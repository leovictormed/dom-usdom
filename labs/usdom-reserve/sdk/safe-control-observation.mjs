import {
  AbiCoder,
  Interface,
  Signature,
  getAddress,
  getBytes,
  isAddress,
  keccak256,
  recoverAddress,
  toUtf8Bytes,
} from 'ethers';
import {BoundedMainnetPreflightProvider} from './mainnet-preflight-rpc.mjs';
import {
  RECOVERABLE_SAFE_CONTROL_SCHEMA,
  RECOVERABLE_SAFE_OWNER_COUNT,
  RECOVERABLE_SAFE_THRESHOLD,
  SAFE_CONTROL_SPECS,
  SAFE_MAINNET_IDENTITY,
  SAFE_VERSION,
  prepareRecoverableSafeControlDeployments,
  validateRecoverableSafeControlPackage,
} from './safe-control-deployment.mjs';
import {validateRpcConsensusEvidence} from './rpc-consensus-evidence.mjs';

export const SAFE_CONTROL_SNAPSHOT_SCHEMA = 'usdom-safe-controls-finalized-snapshot/v2';
export const SAFE_CONTROL_RECOVERY_SCHEMA = 'usdom-safe-controls-recovery/v3';
export const SAFE_GUARD_STORAGE_SLOT =
  '0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8';
export const SAFE_FALLBACK_HANDLER_STORAGE_SLOT =
  '0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5';

const ZERO_ADDRESS='0x0000000000000000000000000000000000000000';
const SENTINEL='0x0000000000000000000000000000000000000001';
const HASH=/^0x[0-9a-f]{64}$/;
const UINT256=/^(0|[1-9][0-9]{0,77})$/;
const CONFIGURATION_TYPEHASH=keccak256(toUtf8Bytes(
  'SafeControlConfiguration(bytes32 role,address safe,bytes32 runtimeCodeHash,address singleton,address fallbackHandler,address guard,bytes32 ownersHash,uint256 threshold,uint256 nonce,bytes32 packageHash,uint256 chainId)',
));
const coder=AbiCoder.defaultAbiCoder();
const safeInterface=new Interface([
  'function masterCopy() view returns (address)',
  'function VERSION() view returns (string)',
  'function getOwners() view returns (address[])',
  'function getThreshold() view returns (uint256)',
  'function nonce() view returns (uint256)',
  'function getModulesPaginated(address start,uint256 pageSize) view returns (address[] array,address next)',
  'function getTransactionHash(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce) view returns (bytes32)',
  'function execTransaction(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address payable refundReceiver,bytes signatures) returns (bool success)',
  'function swapOwner(address prevOwner,address oldOwner,address newOwner)',
  'event RemovedOwner(address indexed owner)',
  'event AddedOwner(address indexed owner)',
  'event ExecutionSuccess(bytes32 indexed txHash,uint256 payment)',
  'event ExecutionFailure(bytes32 indexed txHash,uint256 payment)',
]);

function fail(message) { throw new Error(message); }
function isReservedSafeOwner(value) {
  // Precompiles answer as code-empty accounts, but cannot be ECDSA owners.
  return BigInt(getAddress(value))<=0x11n;
}
function isPinnedSafeContract(value) {
  const address=getAddress(value);
  return ['factory','singleton','fallbackHandler']
    .some(field=>address===getAddress(SAFE_MAINNET_IDENTITY[field]));
}

function canonicalJson(value) {
  if(Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if(value && typeof value==='object') {
    return `{${Object.keys(value).sort().map(key=>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  const encoded=JSON.stringify(value);
  if(encoded===undefined) fail('undefined is forbidden in canonical JSON');
  return encoded;
}

function documentHash(value) {
  return keccak256(toUtf8Bytes(canonicalJson(value)));
}

function decimal(value,label,bits=256) {
  const text=typeof value==='bigint'?value.toString():value;
  const maximumDigits=bits===64?20:78;
  if(typeof text!=='string'||text.length>maximumDigits||!UINT256.test(text)
      ||BigInt(text)>=(1n<<BigInt(bits))) {
    fail(`${label} must be canonical uint${bits} decimal`);
  }
  return text;
}

function bytes32(value,label) {
  if(typeof value!=='string'||!HASH.test(value)) fail(`${label} must be lowercase bytes32`);
  return value;
}

function blockIdentity(block,label) {
  if(!block||!Number.isSafeInteger(block.number)||block.number<0) fail(`${label} block number is invalid`);
  return {number:String(block.number),hash:bytes32(block.hash,`${label} block hash`)};
}

function storageAddress(word,label) {
  if(typeof word!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(word)
      || !/^0x0{24}/.test(word.toLowerCase())) fail(`${label} storage word is invalid`);
  return getAddress(`0x${word.slice(-40)}`);
}

async function read(provider,to,name,args,blockTag) {
  const result=await provider.call({to,data:safeInterface.encodeFunctionData(name,args),blockTag});
  return safeInterface.decodeFunctionResult(name,result);
}

function sameAddress(left,right) {
  return getAddress(left)===getAddress(right);
}

function exactKeys(value,keys,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      || canonicalJson(Object.keys(value).sort())!==canonicalJson([...keys].sort())) {
    fail(`${label} schema is invalid`);
  }
}

function configurationHash({role,safe,runtimeCodeHash,singleton,fallbackHandler,guard,
  owners,threshold,nonce,packageHash}) {
  const ownersHash=keccak256(coder.encode(['address[]'],[owners]));
  return keccak256(coder.encode(
    ['bytes32','bytes32','address','bytes32','address','address','address','bytes32',
      'uint256','uint256','bytes32','uint256'],
    [CONFIGURATION_TYPEHASH,keccak256(toUtf8Bytes(role)),safe,runtimeCodeHash,singleton,
      fallbackHandler,guard,ownersHash,threshold,nonce,packageHash,1],
  ));
}

export function safeControlConfigurationHash(value) {
  return configurationHash(value);
}

function validatePackageShape(document) {
  validateRecoverableSafeControlPackage(document);
  if(!document||typeof document!=='object'||Array.isArray(document)) fail('Safe package is missing');
  if(document.schema!==RECOVERABLE_SAFE_CONTROL_SCHEMA||document.ethereumChainId!=='1'
      || document.safeVersion!==SAFE_VERSION||document.threshold!==String(RECOVERABLE_SAFE_THRESHOLD)) {
    fail('Safe package policy is invalid');
  }
  const roles=SAFE_CONTROL_SPECS.map(({role})=>role);
  if(!document.ownersByRole||typeof document.ownersByRole!=='object'||Array.isArray(document.ownersByRole)
      ||JSON.stringify(Object.keys(document.ownersByRole).sort())!==JSON.stringify([...roles].sort())) {
    fail('Safe package ownersByRole is invalid');
  }
  for(const role of roles) {
    const owners=document.ownersByRole[role];
    if(!Array.isArray(owners)||owners.length!==RECOVERABLE_SAFE_OWNER_COUNT
        ||owners.some(value=>typeof value!=='string'||!isAddress(value))) fail(`${role} Safe owners are invalid`);
  }
  if(!Array.isArray(document.controls)||document.controls.length!==SAFE_CONTROL_SPECS.length) {
    fail('Safe package controls are invalid');
  }
}

async function observeRole({provider,control,owners,packageHash,blockTag,expectedNonce}) {
  const safe=getAddress(control.safe);
  const code=await provider.getCode(safe,blockTag);
  if(code==='0x') fail(`${control.role} Safe is not deployed at the finalized snapshot`);
  const runtimeCodeHash=keccak256(code);
  const [masterCopy]=await read(provider,safe,'masterCopy',[],blockTag);
  const [version]=await read(provider,safe,'VERSION',[],blockTag);
  const [observedOwners]=await read(provider,safe,'getOwners',[],blockTag);
  const [threshold]=await read(provider,safe,'getThreshold',[],blockTag);
  const [nonce]=await read(provider,safe,'nonce',[],blockTag);
  const [modules,nextModule]=await read(
    provider,safe,'getModulesPaginated',[SENTINEL,1],blockTag,
  );
  const [singletonWord,fallbackWord,guardWord]=await Promise.all([
    provider.getStorage(safe,0,blockTag),
    provider.getStorage(safe,SAFE_FALLBACK_HANDLER_STORAGE_SLOT,blockTag),
    provider.getStorage(safe,SAFE_GUARD_STORAGE_SLOT,blockTag),
  ]);
  const singleton=storageAddress(singletonWord,`${control.role} singleton`);
  const fallbackHandler=storageAddress(fallbackWord,`${control.role} fallback handler`);
  const guard=storageAddress(guardWord,`${control.role} guard`);
  const canonicalOwners=observedOwners.map(getAddress);
  if(!sameAddress(masterCopy,singleton)||!sameAddress(singleton,SAFE_MAINNET_IDENTITY.singleton)) {
    fail(`${control.role} Safe singleton mismatch`);
  }
  if(version!==SAFE_VERSION) fail(`${control.role} Safe version mismatch`);
  if(canonicalOwners.length!==owners.length
      || canonicalOwners.some((value,index)=>!sameAddress(value,owners[index]))) {
    fail(`${control.role} Safe owner set or order mismatch`);
  }
  if(threshold!==BigInt(RECOVERABLE_SAFE_THRESHOLD)) fail(`${control.role} Safe threshold mismatch`);
  if(nonce!==BigInt(expectedNonce)) fail(`${control.role} Safe nonce mismatch`);
  if(!sameAddress(fallbackHandler,SAFE_MAINNET_IDENTITY.fallbackHandler)) {
    fail(`${control.role} Safe fallback handler mismatch`);
  }
  if(!sameAddress(guard,ZERO_ADDRESS)) fail(`${control.role} Safe guard must be empty`);
  if(modules.length!==0||!sameAddress(nextModule,SENTINEL)) {
    fail(`${control.role} Safe modules must be empty`);
  }
  const result={
    role:control.role,
    address:safe,
    runtimeCodeHash,
    singleton,
    fallbackHandler,
    guard,
    owners:canonicalOwners,
    threshold:threshold.toString(),
    nonce:nonce.toString(),
    modules:[],
  };
  return {...result,configurationHash:configurationHash({
    ...result,safe:result.address,packageHash,
  })};
}

async function collectExpectedSnapshot({
  packageDocument,
  expectedOwnersByRole=packageDocument?.ownersByRole,
  rpcUrl,
  expectedNonces,
  providerFactory=(url)=>new BoundedMainnetPreflightProvider(url),
}) {
  validatePackageShape(packageDocument);
  exactKeys(expectedNonces,SAFE_CONTROL_SPECS.map(({role})=>role),'expected Safe nonces');
  for(const role of Object.keys(expectedNonces)) decimal(expectedNonces[role],`${role} expected nonce`);
  if(typeof rpcUrl!=='string'||rpcUrl.length===0) fail('rpcUrl is required');
  const provider=providerFactory(rpcUrl);
  try {
  const network=await provider.getNetwork();
  if(network.chainId!==1n) fail(`expected Ethereum chain ID 1, got ${network.chainId}`);
  const initial=blockIdentity(await provider.getBlock('finalized'),'initial finalized');
  provider.pinFinalizedSnapshot?.(initial.number,initial.hash);
  const blockTag=Number(initial.number);
  const rebuilt=await prepareRecoverableSafeControlDeployments({
    ownersByRole:packageDocument.ownersByRole,rpcUrl,blockTag,providerFactory,
  });
  if(canonicalJson(rebuilt)!==canonicalJson(packageDocument)) {
    fail('Safe package does not match its source-derived finalized reconstruction');
  }
  const packageHash=documentHash(rebuilt);
  const roles=[];
  for(const control of rebuilt.controls) {
    roles.push(await observeRole({
      provider,control,owners:expectedOwnersByRole[control.role],packageHash,blockTag,
      expectedNonce:expectedNonces[control.role],
    }));
  }
  if(new Set(roles.map(role=>role.runtimeCodeHash)).size!==1) {
    fail('Safe proxy runtime code hashes differ across roles');
  }
  if(new Set(roles.map(role=>role.configurationHash)).size!==roles.length) {
    fail('Safe role configuration hashes are not separated');
  }
  const endingAtHeight=blockIdentity(await provider.getBlock(blockTag),'ending canonical');
  const endingFinalized=blockIdentity(await provider.getBlock('finalized'),'ending finalized');
  if(endingAtHeight.hash!==initial.hash||BigInt(endingFinalized.number)<BigInt(initial.number)) {
    fail('finalized Safe snapshot changed while it was collected');
  }
  const report={
    schema:SAFE_CONTROL_SNAPSHOT_SCHEMA,
    ethereumChainId:'1',
    packageHash,
    finalizedBlockNumber:initial.number,
    finalizedBlockHash:initial.hash,
    proxyRuntimeCodeHash:roles[0].runtimeCodeHash,
    roles,
  };
  return {...report,snapshotHash:documentHash(report)};
  } finally {
    if(typeof provider?.destroy==='function') await provider.destroy();
  }
}

/** Collect one immutable finalized-block snapshot of all three production Safes. */
export async function collectRecoverableSafeControlSnapshot({
  packageDocument,
  rpcUrl,
  expectedNonce='0',
  providerFactory=(url)=>new BoundedMainnetPreflightProvider(url),
}={}) {
  decimal(expectedNonce,'expected Safe nonce');
  return collectExpectedSnapshot({
    packageDocument,rpcUrl,
    expectedNonces:Object.fromEntries(SAFE_CONTROL_SPECS.map(({role})=>[role,expectedNonce])),
    providerFactory,
  });
}

/** Verify one still-unrotated role at a finalized snapshot for crash-safe execution resume. */
export async function observeRecoverableSafeControlRoleBeforeRecovery({
  packageDocument,role,rpcUrl,providerFactory=(url)=>new BoundedMainnetPreflightProvider(url),
}={}) {
  validatePackageShape(packageDocument);
  const control=packageDocument.controls.find(value=>value.role===role);
  if(!control) fail('Safe control role is invalid');
  if(typeof rpcUrl!=='string'||rpcUrl.length===0) fail('rpcUrl is required');
  const provider=providerFactory(rpcUrl);
  try {
  const network=await provider.getNetwork();
  if(network.chainId!==1n) fail(`expected Ethereum chain ID 1, got ${network.chainId}`);
  const initial=blockIdentity(await provider.getBlock('finalized'),'initial finalized');
  provider.pinFinalizedSnapshot?.(initial.number,initial.hash);
  const blockTag=Number(initial.number);
  const rebuilt=await prepareRecoverableSafeControlDeployments({
    ownersByRole:packageDocument.ownersByRole,rpcUrl,blockTag,providerFactory,
  });
  if(canonicalJson(rebuilt)!==canonicalJson(packageDocument)) {
    fail('Safe package does not match its source-derived finalized reconstruction');
  }
  const observed=await observeRole({provider,control,owners:rebuilt.ownersByRole[role],
    packageHash:documentHash(rebuilt),blockTag,expectedNonce:'0'});
  const ending=blockIdentity(await provider.getBlock(blockTag),'ending canonical');
  if(ending.hash!==initial.hash) fail('finalized Safe target changed while it was observed');
  return {
    schema:'usdom-safe-control-pre-recovery/v2',
    ethereumChainId:'1',
    finalizedBlockNumber:initial.number,
    finalizedBlockHash:initial.hash,
    ...observed,
  };
  } finally {
    if(typeof provider?.destroy==='function') await provider.destroy();
  }
}

export function validateRecoverableSafeControlBaseline(snapshot,packageDocument) {
  exactKeys(snapshot,['schema','ethereumChainId','packageHash','finalizedBlockNumber',
    'finalizedBlockHash','proxyRuntimeCodeHash','roles','rpcConsensus','snapshotHash'],'baseline snapshot');
  validateRpcConsensusEvidence(snapshot.rpcConsensus);
  if(snapshot.schema!==SAFE_CONTROL_SNAPSHOT_SCHEMA||snapshot.ethereumChainId!=='1'
      || (()=>{ try { decimal(snapshot.finalizedBlockNumber,'finalized block number',64); return false; }
        catch { return true; } })()||!HASH.test(snapshot.finalizedBlockHash)
      || !HASH.test(snapshot.proxyRuntimeCodeHash)||!HASH.test(snapshot.packageHash)
      || !HASH.test(snapshot.snapshotHash)) fail('baseline snapshot identity is invalid');
  if(snapshot.packageHash!==documentHash(packageDocument)) fail('baseline Safe package hash mismatch');
  const unsigned={...snapshot};
  delete unsigned.snapshotHash;
  if(documentHash(unsigned)!==snapshot.snapshotHash) fail('baseline snapshot hash mismatch');
  if(!Array.isArray(snapshot.roles)||snapshot.roles.length!==SAFE_CONTROL_SPECS.length) {
    fail('baseline Safe roles are invalid');
  }
  const controls=new Map(packageDocument.controls.map(control=>[control.role,control]));
  for(const [index,role] of snapshot.roles.entries()) {
    exactKeys(role,['role','address','runtimeCodeHash','singleton','fallbackHandler','guard',
      'owners','threshold','nonce','modules','configurationHash'],`baseline role ${index}`);
    const expectedSpec=SAFE_CONTROL_SPECS[index];
    const control=controls.get(role.role);
    if(role.role!==expectedSpec.role||!control||!sameAddress(role.address,control.safe)
        || role.runtimeCodeHash!==snapshot.proxyRuntimeCodeHash
        || !sameAddress(role.singleton,SAFE_MAINNET_IDENTITY.singleton)
        || !sameAddress(role.fallbackHandler,SAFE_MAINNET_IDENTITY.fallbackHandler)
        || !sameAddress(role.guard,ZERO_ADDRESS)||role.threshold!=='2'||role.nonce!=='0'
        || !Array.isArray(role.modules)||role.modules.length!==0
        || !Array.isArray(role.owners)||role.owners.length!==packageDocument.ownersByRole[role.role].length
        || role.owners.some((owner,ownerIndex)=>
          !sameAddress(owner,packageDocument.ownersByRole[role.role][ownerIndex]))) {
      fail(`${role.role} baseline configuration is invalid`);
    }
    const expectedHash=configurationHash({...role,safe:role.address,packageHash:snapshot.packageHash});
    if(role.configurationHash!==expectedHash) fail(`${role.role} baseline configuration hash mismatch`);
  }
}

function recoverSafeSigners(safeTxHash,signatures) {
  const bytes=getBytes(signatures);
  if(bytes.length!==RECOVERABLE_SAFE_THRESHOLD*65) {
    fail('recovery Safe signatures must contain exactly two canonical ECDSA signatures');
  }
  const signers=[];
  for(let offset=0;offset<bytes.length;offset+=65) {
    const r=`0x${Buffer.from(bytes.slice(offset,offset+32)).toString('hex')}`;
    const s=`0x${Buffer.from(bytes.slice(offset+32,offset+64)).toString('hex')}`;
    const rawV=bytes[offset+64];
    if(rawV!==27&&rawV!==28) {
      fail('recovery requires direct EIP-712 hardware signatures');
    }
    const digest=safeTxHash;
    const signature=Signature.from({r,s,v:rawV});
    const signer=getAddress(recoverAddress(digest,signature));
    if(signers.length&&BigInt(signer)<=BigInt(signers.at(-1))) {
      fail('recovery Safe signers must be distinct and canonically ordered');
    }
    signers.push(signer);
  }
  return signers;
}

async function verifyRecoveryTransaction({provider,transactionHash,role,baselineRole,
  finalizedBlockNumber,lostOwner,replacementOwner}) {
  bytes32(transactionHash,`${role} recovery transaction hash`);
  const [transaction,receipt]=await Promise.all([
    provider.getTransaction(transactionHash),provider.getTransactionReceipt(transactionHash),
  ]);
  if(!transaction||!receipt||transaction.hash.toLowerCase()!==transactionHash
      || receipt.hash.toLowerCase()!==transactionHash||receipt.status!==1
      || !sameAddress(transaction.to,baselineRole.address)
      || !sameAddress(receipt.to,baselineRole.address)||transaction.value!==0n
      || transaction.blockNumber!==receipt.blockNumber||transaction.blockHash!==receipt.blockHash
      || !Number.isSafeInteger(receipt.index)||receipt.index<0
      || !Number.isSafeInteger(transaction.index)||transaction.index!==receipt.index
      || !Number.isSafeInteger(receipt.blockNumber)||receipt.blockNumber<=Number(baselineRole.blockNumber??-1)
      || receipt.blockNumber>finalizedBlockNumber) {
    fail(`${role} recovery transaction is not a successful finalized Safe call`);
  }
  let outer;
  try { outer=safeInterface.decodeFunctionData('execTransaction',transaction.data); }
  catch { fail(`${role} recovery transaction is not Safe execTransaction`); }
  if(!sameAddress(outer.to,baselineRole.address)||outer.value!==0n||outer.operation!==0n
      || outer.safeTxGas!==0n||outer.baseGas!==0n||outer.gasPrice!==0n
      || !sameAddress(outer.gasToken,ZERO_ADDRESS)||!sameAddress(outer.refundReceiver,ZERO_ADDRESS)) {
    fail(`${role} recovery transaction has unsafe execution or payment fields`);
  }
  let swap;
  try { swap=safeInterface.decodeFunctionData('swapOwner',outer.data); }
  catch { fail(`${role} recovery transaction does not contain swapOwner`); }
  const lostIndex=baselineRole.owners.findIndex(owner=>sameAddress(owner,lostOwner));
  const expectedPrevious=lostIndex===0?SENTINEL:baselineRole.owners[lostIndex-1];
  if(lostIndex<0||!sameAddress(swap.prevOwner,expectedPrevious)
      || !sameAddress(swap.oldOwner,lostOwner)||!sameAddress(swap.newOwner,replacementOwner)) {
    fail(`${role} recovery owner transition mismatch`);
  }
  const transactionHashResult=await read(provider,baselineRole.address,'getTransactionHash',[
    outer.to,outer.value,outer.data,outer.operation,outer.safeTxGas,outer.baseGas,outer.gasPrice,
    outer.gasToken,outer.refundReceiver,BigInt(baselineRole.nonce),
  ],finalizedBlockNumber);
  const safeTxHash=transactionHashResult[0].toLowerCase();
  const signers=recoverSafeSigners(safeTxHash,outer.signatures);
  const expectedSigners=baselineRole.owners.filter(owner=>!sameAddress(owner,lostOwner))
    .sort((left,right)=>BigInt(left)<BigInt(right)?-1:1);
  if(signers.length!==expectedSigners.length
      || signers.some((signer,index)=>!sameAddress(signer,expectedSigners[index]))) {
    fail(`${role} recovery was not signed by exactly the two surviving owners`);
  }
  const safeLogs=receipt.logs.filter(log=>sameAddress(log.address,baselineRole.address));
  if(safeLogs.length!==3) fail(`${role} recovery emitted an unexpected Safe log set`);
  const parsed=safeLogs.map(log=>{
    try { return safeInterface.parseLog(log); }
    catch { fail(`${role} recovery emitted an unknown Safe event`); }
  });
  if(parsed[0].name!=='RemovedOwner'||!sameAddress(parsed[0].args.owner,lostOwner)
      || parsed[1].name!=='AddedOwner'||!sameAddress(parsed[1].args.owner,replacementOwner)
      || parsed[2].name!=='ExecutionSuccess'||parsed[2].args.txHash.toLowerCase()!==safeTxHash
      || parsed[2].args.payment!==0n) fail(`${role} recovery Safe events mismatch`);
  const canonicalBlock=blockIdentity(await provider.getBlock(receipt.blockNumber),`${role} recovery`);
  if(canonicalBlock.hash!==receipt.blockHash) fail(`${role} recovery receipt block is no longer canonical`);
  return {
    role,
    safe:baselineRole.address,
    transactionHash,
    blockNumber:String(receipt.blockNumber),
    blockHash:receipt.blockHash,
    transactionIndex:String(receipt.index),
    safeTxHash,
    signers,
    previousNonce:baselineRole.nonce,
    newNonce:(BigInt(baselineRole.nonce)+1n).toString(),
  };
}

function recoveryTransitions(packageDocument,value) {
  exactKeys(value,SAFE_CONTROL_SPECS.map(({role})=>role),'recovery transitionsByRole');
  const existing=Object.values(packageDocument.ownersByRole).flat().map(getAddress);
  const controlSafes=packageDocument.controls.map(control=>getAddress(control.safe));
  const result={},replacements=[];
  for(const {role} of SAFE_CONTROL_SPECS) {
    exactKeys(value[role],['lostOwner','replacementOwner'],`${role} recovery transition`);
    const lostOwner=getAddress(value[role].lostOwner),replacementOwner=getAddress(value[role].replacementOwner);
    const owners=packageDocument.ownersByRole[role].map(getAddress);
    if(!owners.includes(lostOwner)||existing.includes(replacementOwner)
        ||controlSafes.includes(replacementOwner)||lostOwner===replacementOwner
        ||isReservedSafeOwner(replacementOwner)||isPinnedSafeContract(replacementOwner)) {
      fail(`${role} recovery owner transition is invalid`);
    }
    replacements.push(replacementOwner); result[role]={lostOwner,replacementOwner};
  }
  if(new Set(replacements).size!==SAFE_CONTROL_SPECS.length) fail('recovery replacement owners must be globally distinct');
  return result;
}

/** Verify a finalized loss-of-one-key drill across every configured Safe role. */
export async function collectRecoverableSafeControlRecovery({
  packageDocument,baselineSnapshot,transitionsByRole,transactions,rpcUrl,
  providerFactory=(url)=>new BoundedMainnetPreflightProvider(url),
}={}) {
  validatePackageShape(packageDocument);
  validateRecoverableSafeControlBaseline(baselineSnapshot,packageDocument);
  const transitions=recoveryTransitions(packageDocument,transitionsByRole);
  exactKeys(transactions,SAFE_CONTROL_SPECS.map(({role})=>role),'recovery transactions');
  const hashes=Object.values(transactions);
  if(new Set(hashes).size!==hashes.length) fail('recovery transaction hashes must be distinct');
  const provider=providerFactory(rpcUrl);
  try {
  const network=await provider.getNetwork();
  if(network.chainId!==1n) fail(`expected Ethereum chain ID 1, got ${network.chainId}`);
  const baselineBlock=blockIdentity(
    await provider.getBlock(Number(baselineSnapshot.finalizedBlockNumber)),'baseline canonical',
  );
  if(baselineBlock.hash!==baselineSnapshot.finalizedBlockHash) fail('baseline block is no longer canonical');
  for(const {replacementOwner} of Object.values(transitions)) {
    if(await provider.getCode(replacementOwner,'finalized')!=='0x') fail('replacement owner must remain a hardware-wallet EOA');
  }
  const expectedOwnersByRole=Object.fromEntries(baselineSnapshot.roles.map(role=>{
    const transition=transitions[role.role];
    return [role.role,role.owners.map(owner=>sameAddress(owner,transition.lostOwner)
      ?transition.replacementOwner:owner)];
  }));
  const expectedNonces=Object.fromEntries(baselineSnapshot.roles.map(role=>[
    role.role,(BigInt(role.nonce)+1n).toString(),
  ]));
  const afterSnapshot=await collectExpectedSnapshot({
    packageDocument,rpcUrl,expectedOwnersByRole,expectedNonces,providerFactory,
  });
  if(afterSnapshot.packageHash!==baselineSnapshot.packageHash) fail('recovery Safe package changed');
  const recoveries=[];
  for(const baselineRole of baselineSnapshot.roles) {
    const transition=transitions[baselineRole.role];
    recoveries.push(await verifyRecoveryTransaction({
      provider,transactionHash:transactions[baselineRole.role],role:baselineRole.role,
      baselineRole:{...baselineRole,blockNumber:baselineSnapshot.finalizedBlockNumber},
      finalizedBlockNumber:Number(afterSnapshot.finalizedBlockNumber),lostOwner:transition.lostOwner,
      replacementOwner:transition.replacementOwner,
    }));
  }
  const report={
    schema:SAFE_CONTROL_RECOVERY_SCHEMA,
    ethereumChainId:'1',
    packageHash:baselineSnapshot.packageHash,
    baselineSnapshotHash:baselineSnapshot.snapshotHash,
    transitionsByRole:transitions,
    afterSnapshot,
    recoveries,
  };
  return {...report,recoveryHash:documentHash(report)};
  } finally {
    if(typeof provider?.destroy==='function') await provider.destroy();
  }
}

/** Revalidate one persisted collector report without trusting its producer. */
export function validateRecoverableSafeControlRecoveryReport(
  report,baselineSnapshot,packageDocument,
) {
  validatePackageShape(packageDocument);
  validateRecoverableSafeControlBaseline(baselineSnapshot,packageDocument);
  exactKeys(report,['schema','ethereumChainId','packageHash','baselineSnapshotHash',
    'transitionsByRole','afterSnapshot','recoveries','rpcConsensus','recoveryHash'],
  'Safe recovery report');
  validateRpcConsensusEvidence(report.rpcConsensus);
  if(report.schema!==SAFE_CONTROL_RECOVERY_SCHEMA||report.ethereumChainId!=='1'
      || report.packageHash!==baselineSnapshot.packageHash
      || report.baselineSnapshotHash!==baselineSnapshot.snapshotHash
      || !HASH.test(report.recoveryHash)||BigInt(report.recoveryHash)===0n) fail('Safe recovery report identity is invalid');
  const transitions=recoveryTransitions(packageDocument,report.transitionsByRole);
  const unsignedReport={...report}; delete unsignedReport.recoveryHash;
  if(documentHash(unsignedReport)!==report.recoveryHash) fail('Safe recovery report hash mismatch');

  const after=report.afterSnapshot;
  exactKeys(after,['schema','ethereumChainId','packageHash','finalizedBlockNumber',
    'finalizedBlockHash','proxyRuntimeCodeHash','roles','snapshotHash'],'recovery after snapshot');
  decimal(after.finalizedBlockNumber,'recovery finalized block number',64);
  if(after.schema!==SAFE_CONTROL_SNAPSHOT_SCHEMA||after.ethereumChainId!=='1'
      || after.packageHash!==baselineSnapshot.packageHash
      || !HASH.test(after.finalizedBlockHash)||!HASH.test(after.proxyRuntimeCodeHash)
      || !HASH.test(after.snapshotHash)
      ||[after.finalizedBlockHash,after.proxyRuntimeCodeHash,after.snapshotHash]
        .some(value=>BigInt(value)===0n)
      || BigInt(after.finalizedBlockNumber)<BigInt(baselineSnapshot.finalizedBlockNumber)) {
    fail('recovery after snapshot identity is invalid');
  }
  const unsignedAfter={...after}; delete unsignedAfter.snapshotHash;
  if(documentHash(unsignedAfter)!==after.snapshotHash) fail('recovery after snapshot hash mismatch');
  if(!Array.isArray(after.roles)||after.roles.length!==SAFE_CONTROL_SPECS.length) {
    fail('recovery after snapshot roles are invalid');
  }
  for(const [index,role] of after.roles.entries()) {
    const baselineRole=baselineSnapshot.roles[index];
    const transition=transitions[role.role];
    const expectedOwners=packageDocument.ownersByRole[role.role].map(owner=>
      sameAddress(owner,transition.lostOwner)?transition.replacementOwner:getAddress(owner));
    exactKeys(role,['role','address','runtimeCodeHash','singleton','fallbackHandler','guard',
      'owners','threshold','nonce','modules','configurationHash'],`recovery role ${index}`);
    if(role.role!==SAFE_CONTROL_SPECS[index].role||role.role!==baselineRole.role
        || !sameAddress(role.address,baselineRole.address)
        || role.runtimeCodeHash!==baselineRole.runtimeCodeHash
        || role.runtimeCodeHash!==after.proxyRuntimeCodeHash
        || !sameAddress(role.singleton,baselineRole.singleton)
        || !sameAddress(role.fallbackHandler,baselineRole.fallbackHandler)
        || !sameAddress(role.guard,baselineRole.guard)||role.threshold!==baselineRole.threshold
        || role.nonce!==(BigInt(baselineRole.nonce)+1n).toString()
        || !Array.isArray(role.modules)||role.modules.length!==0
        || !Array.isArray(role.owners)||role.owners.length!==expectedOwners.length
        || role.owners.some((owner,ownerIndex)=>!sameAddress(owner,expectedOwners[ownerIndex]))) {
      fail(`${role.role} recovery after-state mismatch`);
    }
    const expectedConfigurationHash=configurationHash({
      ...role,safe:role.address,packageHash:after.packageHash,
    });
    if(role.configurationHash!==expectedConfigurationHash) {
      fail(`${role.role} recovery configuration hash mismatch`);
    }
  }
  if(new Set(after.roles.map(role=>role.configurationHash)).size!==after.roles.length) {
    fail('recovery after-state configurations are not separated');
  }

  if(!Array.isArray(report.recoveries)||report.recoveries.length!==SAFE_CONTROL_SPECS.length) {
    fail('Safe recovery transaction evidence is invalid');
  }
  const transactionHashes=[];
  for(const [index,recovery] of report.recoveries.entries()) {
    const baselineRole=baselineSnapshot.roles[index];
    const transition=transitions[recovery.role];
    const expectedSigners=packageDocument.ownersByRole[recovery.role]
      .filter(owner=>!sameAddress(owner,transition.lostOwner))
      .map(getAddress).sort((left,right)=>BigInt(left)<BigInt(right)?-1:1);
    exactKeys(recovery,['role','safe','transactionHash','blockNumber','blockHash','transactionIndex','safeTxHash',
      'signers','previousNonce','newNonce'],`recovery transaction ${index}`);
    decimal(recovery.blockNumber,`${recovery.role} recovery block number`,64);
    decimal(recovery.transactionIndex,`${recovery.role} recovery transaction index`,64);
    if(recovery.role!==SAFE_CONTROL_SPECS[index].role||recovery.role!==baselineRole.role
        || !sameAddress(recovery.safe,baselineRole.address)
        || !HASH.test(recovery.transactionHash)||!HASH.test(recovery.blockHash)
        || !HASH.test(recovery.safeTxHash)
        ||[recovery.transactionHash,recovery.blockHash,recovery.safeTxHash]
          .some(value=>BigInt(value)===0n)
        || BigInt(recovery.blockNumber)<=BigInt(baselineSnapshot.finalizedBlockNumber)
        || BigInt(recovery.blockNumber)>BigInt(after.finalizedBlockNumber)
        || recovery.previousNonce!==baselineRole.nonce
        || recovery.newNonce!==(BigInt(baselineRole.nonce)+1n).toString()
        || !Array.isArray(recovery.signers)||recovery.signers.length!==expectedSigners.length
        || recovery.signers.some((signer,signerIndex)=>
          !isAddress(signer)||!sameAddress(signer,expectedSigners[signerIndex]))) {
      fail(`${recovery.role} recovery transaction evidence mismatch`);
    }
    transactionHashes.push(recovery.transactionHash);
  }
  if(new Set(transactionHashes).size!==transactionHashes.length) {
    fail('Safe recovery transaction hashes are not distinct');
  }
  for(let index=1;index<report.recoveries.length;index++) {
    const previous=report.recoveries[index-1],current=report.recoveries[index];
    const previousBlock=BigInt(previous.blockNumber),currentBlock=BigInt(current.blockNumber);
    if(currentBlock<previousBlock
        || currentBlock===previousBlock
          && BigInt(current.transactionIndex)<=BigInt(previous.transactionIndex)) {
      fail('Safe recovery transactions are not in strict canonical chain order');
    }
  }
  return report;
}

export const _safeControlObservationInternals=Object.freeze({canonicalJson,documentHash});
