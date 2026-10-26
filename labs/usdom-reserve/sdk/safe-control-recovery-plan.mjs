import {
  AbiCoder,
  Interface,
  Signature,
  TypedDataEncoder,
  concat,
  getAddress,
  getBytes,
  isAddress,
  keccak256,
  recoverAddress,
  toUtf8Bytes,
} from 'ethers';
import {BoundedMainnetPreflightProvider} from './mainnet-preflight-rpc.mjs';
import {SAFE_CONTROL_SPECS} from './safe-control-deployment.mjs';
import {
  _safeControlObservationInternals,
  collectRecoverableSafeControlSnapshot,
  validateRecoverableSafeControlBaseline,
} from './safe-control-observation.mjs';
import {validateRpcConsensusEvidence} from './rpc-consensus-evidence.mjs';

export const SAFE_RECOVERY_PLAN_SCHEMA='usdom-safe-recovery-plan/v2';
export const SAFE_RECOVERY_TRANSACTION_PACKAGE_SCHEMA='usdom-safe-recovery-transactions/v2';

const ZERO_ADDRESS='0x0000000000000000000000000000000000000000';
const SENTINEL='0x0000000000000000000000000000000000000001';
const HASH=/^0x[0-9a-f]{64}$/;
const SIGNATURE=/^0x[0-9a-fA-F]{130}$/;
const DOMAIN_TYPEHASH='0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218';
const SAFE_TX_TYPEHASH='0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8';
const coder=AbiCoder.defaultAbiCoder();
const safeInterface=new Interface([
  'function getTransactionHash(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce) view returns (bytes32)',
  'function execTransaction(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address payable refundReceiver,bytes signatures) returns (bool success)',
  'function swapOwner(address prevOwner,address oldOwner,address newOwner)',
]);
const {canonicalJson,documentHash}=_safeControlObservationInternals;

function fail(message) { throw new Error(message); }
function sameAddress(left,right) { return getAddress(left)===getAddress(right); }
function exactKeys(value,keys,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      || canonicalJson(Object.keys(value).sort())!==canonicalJson([...keys].sort())) {
    fail(`${label} schema is invalid`);
  }
}
function normalizedTransitions(packageDocument,value) {
  exactKeys(value,SAFE_CONTROL_SPECS.map(({role})=>role),'recovery transitionsByRole');
  const allCurrent=Object.values(packageDocument.ownersByRole).flat().map(getAddress);
  const replacements=[]; const result={};
  for(const {role} of SAFE_CONTROL_SPECS) {
    exactKeys(value[role],['lostOwner','replacementOwner'],`${role} recovery transition`);
    const lost=getAddress(value[role].lostOwner),replacement=getAddress(value[role].replacementOwner);
    const owners=packageDocument.ownersByRole[role].map(getAddress);
    if(!owners.includes(lost)||allCurrent.includes(replacement)||lost===replacement) {
      fail(`${role} recovery lost/replacement owner policy is invalid`);
    }
    replacements.push(replacement); result[role]={lostOwner:lost,replacementOwner:replacement};
  }
  if(new Set(replacements).size!==replacements.length) fail('replacement owners must be distinct between roles');
  return result;
}

function independentSafeTxHash(safe,transaction) {
  const domain=keccak256(coder.encode(
    ['bytes32','uint256','address'],[DOMAIN_TYPEHASH,1,safe],
  ));
  const struct=keccak256(coder.encode(
    ['bytes32','address','uint256','bytes32','uint8','uint256','uint256','uint256',
      'address','address','uint256'],
    [SAFE_TX_TYPEHASH,transaction.to,transaction.value,keccak256(transaction.data),
      transaction.operation,transaction.safeTxGas,transaction.baseGas,transaction.gasPrice,
      transaction.gasToken,transaction.refundReceiver,transaction.nonce],
  ));
  return keccak256(concat(['0x1901',domain,struct]));
}

function typedData(safe,transaction) {
  return {
    types:{
      EIP712Domain:[
        {name:'chainId',type:'uint256'},
        {name:'verifyingContract',type:'address'},
      ],
      SafeTx:[
        {name:'to',type:'address'},{name:'value',type:'uint256'},
        {name:'data',type:'bytes'},{name:'operation',type:'uint8'},
        {name:'safeTxGas',type:'uint256'},{name:'baseGas',type:'uint256'},
        {name:'gasPrice',type:'uint256'},{name:'gasToken',type:'address'},
        {name:'refundReceiver',type:'address'},{name:'nonce',type:'uint256'},
      ],
    },
    domain:{chainId:'1',verifyingContract:safe},
    primaryType:'SafeTx',
    message:{...transaction},
  };
}

/** Prepare exact EIP-712 payloads for a loss-of-one-key drill; never signs or sends. */
export async function prepareRecoverableSafeRecoveryPlan({
  packageDocument,baselineSnapshot,transitionsByRole,rpcUrl,
  providerFactory=(url)=>new BoundedMainnetPreflightProvider(url),
}={}) {
  validateRecoverableSafeControlBaseline(baselineSnapshot,packageDocument);
  if(typeof rpcUrl!=='string'||rpcUrl.length===0) fail('rpcUrl is required');
  const transitions=normalizedTransitions(packageDocument,transitionsByRole);
  const current=await collectRecoverableSafeControlSnapshot({
    packageDocument,rpcUrl,expectedNonce:'0',providerFactory,
  });
  if(current.packageHash!==baselineSnapshot.packageHash
      || current.roles.some((role,index)=>
        role.configurationHash!==baselineSnapshot.roles[index].configurationHash)) {
    fail('current finalized Safe state no longer matches the recovery baseline');
  }
  const provider=providerFactory(rpcUrl);
  try {
  const network=await provider.getNetwork();
  if(network.chainId!==1n) fail(`expected Ethereum chain ID 1, got ${network.chainId}`);
  const blockTag=Number(current.finalizedBlockNumber);
  for(const {replacementOwner} of Object.values(transitions)) if(await provider.getCode(replacementOwner,blockTag)!=='0x') {
    fail('replacement owner must be a hardware-wallet EOA at the planning snapshot');
  }
  const roles=[];
  for(const role of current.roles) {
    const {lostOwner:lost,replacementOwner:replacement}=transitions[role.role];
    const requiredSigners=packageDocument.ownersByRole[role.role]
      .filter(owner=>!sameAddress(owner,lost)).sort((a,b)=>BigInt(a)<BigInt(b)?-1:1);
    const oldIndex=role.owners.findIndex(owner=>sameAddress(owner,lost));
    if(oldIndex<0) fail(`${role.role} does not contain the lost owner`);
    const previousOwner=oldIndex===0?SENTINEL:role.owners[oldIndex-1];
    const inner=safeInterface.encodeFunctionData('swapOwner',[
      previousOwner,lost,replacement,
    ]).toLowerCase();
    const transaction={
      to:role.address,
      value:'0',
      data:inner,
      operation:'0',
      safeTxGas:'0',
      baseGas:'0',
      gasPrice:'0',
      gasToken:ZERO_ADDRESS,
      refundReceiver:ZERO_ADDRESS,
      nonce:role.nonce,
    };
    const safeTxHash=independentSafeTxHash(role.address,transaction);
    const result=await provider.call({
      to:role.address,
      data:safeInterface.encodeFunctionData('getTransactionHash',Object.values(transaction)),
      blockTag,
    });
    const [observedHash]=safeInterface.decodeFunctionResult('getTransactionHash',result);
    if(observedHash.toLowerCase()!==safeTxHash) {
      fail(`${role.role} Safe transaction hash disagrees with independent EIP-712 derivation`);
    }
    roles.push({
      role:role.role,
      safe:role.address,
      previousOwner,
      oldOwner:lost,
      newOwner:replacement,
      requiredSigners,
      safeTransaction:transaction,
      safeTxHash,
      typedData:typedData(role.address,transaction),
    });
  }
  const ending=await provider.getBlock(blockTag);
  if(!ending||ending.hash!==current.finalizedBlockHash) {
    fail('recovery planning snapshot changed while the plan was built');
  }
  const plan={
    schema:SAFE_RECOVERY_PLAN_SCHEMA,
    ethereumChainId:'1',
    packageHash:current.packageHash,
    baselineSnapshotHash:baselineSnapshot.snapshotHash,
    planningSnapshotHash:current.snapshotHash,
    finalizedBlockNumber:current.finalizedBlockNumber,
    finalizedBlockHash:current.finalizedBlockHash,
    transitionsByRole:transitions,
    roles,
  };
  return {...plan,planHash:documentHash(plan)};
  } finally {
    if(typeof provider?.destroy==='function') await provider.destroy();
  }
}

export function validateRecoverableSafeRecoveryPlan(plan) {
  exactKeys(plan,['schema','ethereumChainId','packageHash','baselineSnapshotHash',
    'planningSnapshotHash','finalizedBlockNumber','finalizedBlockHash','transitionsByRole',
    'roles','rpcConsensus','planHash'],'Safe recovery plan');
  validateRpcConsensusEvidence(plan.rpcConsensus);
  if(plan.schema!==SAFE_RECOVERY_PLAN_SCHEMA||plan.ethereumChainId!=='1'
      || !HASH.test(plan.packageHash)||!HASH.test(plan.baselineSnapshotHash)
      || !HASH.test(plan.planningSnapshotHash)||!HASH.test(plan.finalizedBlockHash)
      || !HASH.test(plan.planHash)
      || !/^(0|[1-9][0-9]*)$/.test(plan.finalizedBlockNumber)) {
    fail('Safe recovery plan identity is invalid');
  }
  const unsigned={...plan}; delete unsigned.planHash;
  if(documentHash(unsigned)!==plan.planHash) fail('Safe recovery plan hash mismatch');
  exactKeys(plan.transitionsByRole,SAFE_CONTROL_SPECS.map(({role})=>role),'plan transitionsByRole');
  if(!Array.isArray(plan.roles)||plan.roles.length!==SAFE_CONTROL_SPECS.length) {
    fail('Safe recovery role plan is invalid');
  }
  const plannedOwners=[]; const plannedReplacements=[];
  for(const [index,role] of plan.roles.entries()) {
    exactKeys(role,['role','safe','previousOwner','oldOwner','newOwner','requiredSigners',
      'safeTransaction','safeTxHash','typedData'],`Safe recovery role ${index}`);
    exactKeys(role.safeTransaction,['to','value','data','operation','safeTxGas','baseGas',
      'gasPrice','gasToken','refundReceiver','nonce'],`${role.role} Safe transaction`);
    let swap;
    try { swap=safeInterface.decodeFunctionData('swapOwner',role.safeTransaction.data); }
    catch { fail(`${role.role} recovery inner call is not swapOwner`); }
    if(role.role!==SAFE_CONTROL_SPECS[index].role||!HASH.test(role.safeTxHash)
        || !sameAddress(role.safe,role.safeTransaction.to)
        || !sameAddress(role.oldOwner,plan.transitionsByRole[role.role]?.lostOwner)
        || !sameAddress(role.newOwner,plan.transitionsByRole[role.role]?.replacementOwner)
        || !sameAddress(swap.prevOwner,role.previousOwner)
        || !sameAddress(swap.oldOwner,role.oldOwner)||!sameAddress(swap.newOwner,role.newOwner)
        || role.safeTransaction.value!=='0'||role.safeTransaction.operation!=='0'
        || role.safeTransaction.safeTxGas!=='0'||role.safeTransaction.baseGas!=='0'
        || role.safeTransaction.gasPrice!=='0'||role.safeTransaction.nonce!=='0'
        || !sameAddress(role.safeTransaction.gasToken,ZERO_ADDRESS)
        || !sameAddress(role.safeTransaction.refundReceiver,ZERO_ADDRESS)) {
      fail(`${role.role} recovery role policy is invalid`);
    }
    if(!Array.isArray(role.requiredSigners)||role.requiredSigners.length!==2
        ||role.requiredSigners.some(value=>!isAddress(value)||sameAddress(value,role.oldOwner))
        ||new Set(role.requiredSigners.map(value=>getAddress(value))).size!==2
        || canonicalJson(role.typedData)!==canonicalJson(typedData(role.safe,role.safeTransaction))) {
      fail(`${role.role} recovery signer or typed-data handoff mismatch`);
    }
    plannedOwners.push(getAddress(role.oldOwner),...role.requiredSigners.map(value=>getAddress(value)));
    plannedReplacements.push(getAddress(role.newOwner));
    const types={...role.typedData.types}; delete types.EIP712Domain;
    const typedHash=TypedDataEncoder.hash(role.typedData.domain,types,role.typedData.message);
    const independent=independentSafeTxHash(role.safe,role.safeTransaction);
    if(typedHash!==role.safeTxHash||independent!==role.safeTxHash) {
      fail(`${role.role} recovery typed data hash mismatch`);
    }
  }
  if(new Set(plan.roles.map(role=>getAddress(role.safe))).size!==plan.roles.length) {
    fail('Safe recovery role addresses must be distinct');
  }
  if(new Set(plannedOwners).size!==plannedOwners.length
      ||new Set(plannedReplacements).size!==plannedReplacements.length
      ||plannedReplacements.some(owner=>plannedOwners.includes(owner))) {
    fail('Safe recovery owners must remain globally separated by role');
  }
  return plan;
}

/** Validate hardware signatures and produce exact execTransaction calldata; never sends. */
export function assembleRecoverableSafeRecoveryTransactions({plan,signatures}={}) {
  validateRecoverableSafeRecoveryPlan(plan);
  exactKeys(signatures,SAFE_CONTROL_SPECS.map(({role})=>role),'Safe recovery signatures');
  const transactions=[];
  for(const role of plan.roles) {
    const entries=signatures[role.role];
    if(!Array.isArray(entries)||entries.length!==2) {
      fail(`${role.role} must contain exactly two hardware signatures`);
    }
    const validated=entries.map((entry,signatureIndex)=>{
      exactKeys(entry,['signature','signer'],`${role.role} signature ${signatureIndex}`);
      if(!isAddress(entry.signer)||typeof entry.signature!=='string'
          || !SIGNATURE.test(entry.signature)) fail(`${role.role} signature encoding is invalid`);
      const rawV=Number.parseInt(entry.signature.slice(-2),16);
      if(rawV!==27&&rawV!==28) {
        fail(`${role.role} signature must be a direct EIP-712 hardware signature`);
      }
      const parsed=Signature.from(entry.signature);
      const recovered=getAddress(recoverAddress(role.safeTxHash,parsed));
      if(!sameAddress(recovered,entry.signer)) fail(`${role.role} signature signer mismatch`);
      return {signer:recovered,signature:parsed.serialized};
    }).sort((left,right)=>BigInt(left.signer)<BigInt(right.signer)?-1:1);
    if(validated.some((entry,signerIndex)=>
      !sameAddress(entry.signer,role.requiredSigners[signerIndex]))) {
      fail(`${role.role} signatures are not exactly the two surviving owners`);
    }
    const joined=concat(validated.map(entry=>entry.signature));
    const data=safeInterface.encodeFunctionData('execTransaction',[
      role.safeTransaction.to,role.safeTransaction.value,role.safeTransaction.data,
      role.safeTransaction.operation,role.safeTransaction.safeTxGas,role.safeTransaction.baseGas,
      role.safeTransaction.gasPrice,role.safeTransaction.gasToken,
      role.safeTransaction.refundReceiver,joined,
    ]).toLowerCase();
    transactions.push({
      role:role.role,
      to:role.safe,
      value:'0',
      data,
      dataHash:keccak256(data),
      safeTxHash:role.safeTxHash,
      signers:validated.map(entry=>entry.signer),
    });
  }
  const result={
    schema:SAFE_RECOVERY_TRANSACTION_PACKAGE_SCHEMA,
    ethereumChainId:'1',
    planHash:plan.planHash,
    transactions,
  };
  const complete={...result,transactionPackageHash:documentHash(result)};
  validateRecoverableSafeRecoveryTransactionPackage(plan,complete);
  return complete;
}

/** Revalidate a persisted assembled package without needing the signature source files. */
export function validateRecoverableSafeRecoveryTransactionPackage(plan,transactionPackage) {
  validateRecoverableSafeRecoveryPlan(plan);
  exactKeys(transactionPackage,['schema','ethereumChainId','planHash','transactions',
    'transactionPackageHash'],'Safe recovery transaction package');
  if(transactionPackage.schema!==SAFE_RECOVERY_TRANSACTION_PACKAGE_SCHEMA
      || transactionPackage.ethereumChainId!=='1'||transactionPackage.planHash!==plan.planHash
      || !HASH.test(transactionPackage.transactionPackageHash)
      || !Array.isArray(transactionPackage.transactions)
      || transactionPackage.transactions.length!==plan.roles.length) {
    fail('Safe recovery transaction package identity is invalid');
  }
  const unsigned={...transactionPackage}; delete unsigned.transactionPackageHash;
  if(documentHash(unsigned)!==transactionPackage.transactionPackageHash) {
    fail('Safe recovery transaction package hash mismatch');
  }
  for(const [index,transaction] of transactionPackage.transactions.entries()) {
    const role=plan.roles[index];
    exactKeys(transaction,['role','to','value','data','dataHash','safeTxHash','signers'],
      `Safe recovery transaction ${index}`);
    if(transaction.role!==role.role||!sameAddress(transaction.to,role.safe)
        || transaction.value!=='0'||transaction.safeTxHash!==role.safeTxHash
        || !HASH.test(transaction.dataHash)||keccak256(transaction.data)!==transaction.dataHash
        || canonicalJson(transaction.signers)!==canonicalJson(role.requiredSigners)) {
      fail(`${role.role} persisted recovery transaction identity mismatch`);
    }
    let outer;
    try { outer=safeInterface.decodeFunctionData('execTransaction',transaction.data); }
    catch { fail(`${role.role} persisted recovery transaction is not execTransaction`); }
    if(!sameAddress(outer.to,role.safeTransaction.to)||outer.value!==0n
        || outer.data.toLowerCase()!==role.safeTransaction.data
        || outer.operation!==0n||outer.safeTxGas!==0n||outer.baseGas!==0n||outer.gasPrice!==0n
        || !sameAddress(outer.gasToken,ZERO_ADDRESS)||!sameAddress(outer.refundReceiver,ZERO_ADDRESS)) {
      fail(`${role.role} persisted recovery transaction fields mismatch`);
    }
    const signatureBytes=getBytes(outer.signatures);
    if(signatureBytes.length!==130) fail(`${role.role} persisted signature length is invalid`);
    const recovered=[];
    for(let offset=0;offset<130;offset+=65) {
      const rawV=signatureBytes[offset+64];
      if(rawV!==27&&rawV!==28) fail(`${role.role} persisted signature type is invalid`);
      const r=`0x${Buffer.from(signatureBytes.slice(offset,offset+32)).toString('hex')}`;
      const s=`0x${Buffer.from(signatureBytes.slice(offset+32,offset+64)).toString('hex')}`;
      recovered.push(getAddress(recoverAddress(role.safeTxHash,Signature.from({r,s,v:rawV}))));
    }
    if(canonicalJson(recovered)!==canonicalJson(role.requiredSigners)) {
      fail(`${role.role} persisted signatures are not the surviving owners`);
    }
  }
  return transactionPackage;
}
