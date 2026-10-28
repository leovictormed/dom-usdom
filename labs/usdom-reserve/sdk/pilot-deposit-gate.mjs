import {AbiCoder,Interface,Signature,TypedDataEncoder,concat,getAddress,getBytes,keccak256,recoverAddress} from 'ethers';
import {pilotFundsSnapshotCommitment,validatePilotFundsAuthorizationState}
  from './pilot-funds-authorization.mjs';

export const PILOT_GATE_PLAN_SCHEMA='usdom-pilot-deposit-gate-plan/v1';
export const PILOT_GATE_TRANSACTION_SCHEMA='usdom-pilot-deposit-gate-transaction/v1';
const ZERO='0x0000000000000000000000000000000000000000';
const HASH=/^0x[0-9a-f]{64}$/; const SIG=/^0x[0-9a-f]{130}$/;
const DOMAIN_TYPEHASH='0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218';
const SAFE_TX_TYPEHASH='0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8';
const coder=AbiCoder.defaultAbiCoder();
const reserveInterface=new Interface([
 'function authorizePilotDeposit(bytes32 snapshotCommitment,address funder,uint64 amount,bytes32 salt,bytes32 receivingCommitment,uint64 validUntil,uint64 expectedGeneration)',
 'function pilotDepositAuthorization(address funder,uint64 amount,bytes32 salt,bytes32 receivingCommitment,uint64 validUntil,uint64 generation) view returns(bytes32)',
 'function cancelPilotDepositAuthorization(bytes32 expectedSnapshotCommitment,uint64 expectedGeneration)',
 'function clearExpiredPilotDepositAuthorization(bytes32 expectedSnapshotCommitment,uint64 expectedGeneration)',
 'function pauseQueueEpoch(uint64 expectedQueueEpoch,uint64 expectedPilotAuthorizationGeneration)',
]);
const safeInterface=new Interface([
 'function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes) returns(bool)',
]);
const exact=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&JSON.stringify(Object.keys(v).sort())===JSON.stringify([...k].sort());
const fail=m=>{throw new Error(m);};
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
const documentHash=v=>keccak256(Buffer.from(JSON.stringify(canonical(v))));
const safeHash=(safe,tx)=>{
 const domain=keccak256(coder.encode(['bytes32','uint256','address'],[DOMAIN_TYPEHASH,1,getAddress(safe)]));
 const structure=keccak256(coder.encode(['bytes32','address','uint256','bytes32','uint8','uint256','uint256','uint256','address','address','uint256'],[SAFE_TX_TYPEHASH,tx.to,tx.value,keccak256(tx.data),tx.operation,tx.safeTxGas,tx.baseGas,tx.gasPrice,tx.gasToken,tx.refundReceiver,tx.nonce]));
 return keccak256(concat(['0x1901',domain,structure]));
};

export function pilotDepositAuthorizationHash({chainId,reserve,funder,amount,salt,receivingCommitment,validUntil,generation}={}) {
 const chain=BigInt(String(chainId)),normalizedReserve=getAddress(reserve),normalizedFunder=getAddress(funder);
 const canonicalUint64=value=>{const text=String(value);if(!/^(0|[1-9][0-9]*)$/.test(text)||BigInt(text)>((1n<<64n)-1n))fail('pilot authorization uint64 is invalid');return text;};
 if(chain<=0n||BigInt(normalizedReserve)===0n||BigInt(normalizedFunder)===0n||!HASH.test(salt??'')||!HASH.test(receivingCommitment??'')) fail('pilot authorization identity is invalid');
 return keccak256(coder.encode(
  ['uint256','address','address','uint64','bytes32','bytes32','uint64','uint64'],
  [chain,normalizedReserve,normalizedFunder,canonicalUint64(amount),salt.toLowerCase(),receivingCommitment.toLowerCase(),canonicalUint64(validUntil),canonicalUint64(generation)],
 ));
}

export function buildPilotDepositGatePlan({snapshot,authorizationState,releaseConfig,safePackage,safeNonce,pilotAuthorizationGeneration,finalizedBlockNumber,finalizedBlockHash,observedAuthorization}={}) {
 const commitment=pilotFundsSnapshotCommitment(snapshot),governance=getAddress(releaseConfig?.governance),reserve=getAddress(releaseConfig?.reserve);
 validatePilotFundsAuthorizationState({state:authorizationState,snapshot,releaseConfig,
  depositAmountBaseUnits:snapshot.pilotDepositBaseUnits});
 const governanceControl=safePackage?.controls?.find(value=>value.role==='governance');
 if(governance!==getAddress(governanceControl?.safe??ZERO)
     ||safePackage?.threshold!=='2') fail('pilot gate governance Safe identity is invalid');
 const owners=safePackage?.ownersByRole?.governance?.map(getAddress);
 if(!Array.isArray(owners)||owners.length!==3||new Set(owners).size!==3) fail('pilot gate requires exact governance 2-of-3 owners');
 if(!/^(0|[1-9][0-9]*)$/.test(String(safeNonce))||!/^(0|[1-9][0-9]*)$/.test(String(finalizedBlockNumber))||!HASH.test(finalizedBlockHash??'')) fail('pilot gate finalized identity is invalid');
 const validUntil=authorizationState?.authorization?.validUntil,generation=String(pilotAuthorizationGeneration??'');
 if(authorizationState?.authorization?.snapshotCommitment?.toLowerCase()!==commitment||!/^([1-9][0-9]*)$/.test(validUntil??'')||!/^(0|[1-9][0-9]*)$/.test(generation)) fail('pilot gate authorization state differs from snapshot');
 const calldata=reserveInterface.encodeFunctionData('authorizePilotDeposit',[commitment,snapshot.funder,snapshot.pilotDepositBaseUnits,snapshot.salt,snapshot.receivingCommitment,validUntil,generation]).toLowerCase();
 const expectedAuthorization=pilotDepositAuthorizationHash({chainId:1,reserve,funder:snapshot.funder,
  amount:snapshot.pilotDepositBaseUnits,salt:snapshot.salt,receivingCommitment:snapshot.receivingCommitment,
  validUntil,generation});
 if(String(observedAuthorization).toLowerCase()!==expectedAuthorization) fail('pilot gate authorization derivation differs from reserve');
 const safeTransaction={to:reserve,value:'0',data:calldata,operation:'0',safeTxGas:'0',baseGas:'0',gasPrice:'0',gasToken:ZERO,refundReceiver:ZERO,nonce:String(safeNonce)};
 const unsigned={schema:PILOT_GATE_PLAN_SCHEMA,chainId:'1',snapshotCommitment:commitment,validUntil,generation,governanceSafe:governance,reserve,authorizedOwners:[...owners].sort((a,b)=>BigInt(a)<BigInt(b)?-1:1),safeTransaction,safeTxHash:safeHash(governance,safeTransaction),expectedAuthorization,finalizedBlockNumber:String(finalizedBlockNumber),finalizedBlockHash:finalizedBlockHash.toLowerCase()};
 return {...unsigned,planHash:documentHash(unsigned)};
}

export function validatePilotDepositGatePlan(plan,{snapshot,authorizationState,releaseConfig,safePackage}={}) {
 if(!exact(plan,['schema','chainId','snapshotCommitment','validUntil','generation','governanceSafe','reserve','authorizedOwners','safeTransaction','safeTxHash','expectedAuthorization','finalizedBlockNumber','finalizedBlockHash','planHash'])||plan.schema!==PILOT_GATE_PLAN_SCHEMA||plan.chainId!=='1'||!HASH.test(plan.safeTxHash)||!HASH.test(plan.expectedAuthorization)||!HASH.test(plan.finalizedBlockHash)||!HASH.test(plan.planHash)) fail('pilot gate plan schema is invalid');
 const rebuilt=buildPilotDepositGatePlan({snapshot,authorizationState,releaseConfig,safePackage,safeNonce:plan.safeTransaction.nonce,pilotAuthorizationGeneration:plan.generation,finalizedBlockNumber:plan.finalizedBlockNumber,finalizedBlockHash:plan.finalizedBlockHash,observedAuthorization:plan.expectedAuthorization});
 if(JSON.stringify(canonical(rebuilt))!==JSON.stringify(canonical(plan))) fail('pilot gate plan differs from exact authorization tuple');
 return plan;
}

export function pilotDepositGateSafeTypedData(plan) {
 if(!plan||!/^usdom-pilot-deposit-gate-(?:plan|cancel-plan)\/v1$/.test(plan.schema??'')
   ||plan.chainId!=='1'||!HASH.test(plan.safeTxHash??'')) fail('pilot gate plan is invalid');
 const domain={chainId:'1',verifyingContract:getAddress(plan.governanceSafe??plan.controlSafe)};
 const types={EIP712Domain:[{name:'chainId',type:'uint256'},{name:'verifyingContract',type:'address'}],SafeTx:[
  {name:'to',type:'address'},{name:'value',type:'uint256'},{name:'data',type:'bytes'},
  {name:'operation',type:'uint8'},{name:'safeTxGas',type:'uint256'},{name:'baseGas',type:'uint256'},
  {name:'gasPrice',type:'uint256'},{name:'gasToken',type:'address'},
  {name:'refundReceiver',type:'address'},{name:'nonce',type:'uint256'},
 ]};
 const message={...plan.safeTransaction};
 const signingTypes={SafeTx:types.SafeTx};
 if(TypedDataEncoder.hash(domain,signingTypes,message)!==plan.safeTxHash) fail('pilot gate Safe typed data differs from plan');
 return Object.freeze({types,primaryType:'SafeTx',domain,message});
}

export function assemblePilotDepositGateTransaction({plan,snapshot,authorizationState,releaseConfig,safePackage,signatures}={}) {
 validatePilotDepositGatePlan(plan,{snapshot,authorizationState,releaseConfig,safePackage});
 if(!Array.isArray(signatures)||signatures.length!==2) fail('pilot gate requires exactly two signatures');
 const entries=signatures.map((entry,index)=>{
  if(!exact(entry,['signer','signature'])||!SIG.test(entry.signature??'')) fail(`pilot gate signature ${index} is invalid`);
  const parsed=Signature.from(entry.signature),signer=getAddress(recoverAddress(plan.safeTxHash,parsed));
  if(parsed.serialized!==entry.signature) fail(`pilot gate signature ${index} is noncanonical`);
  if(signer!==getAddress(entry.signer)||![27,28].includes(parsed.v)) fail(`pilot gate signature ${index} signer mismatch`);
  return {signer,signature:parsed.serialized};
 }).sort((a,b)=>BigInt(a.signer)<BigInt(b.signer)?-1:1);
 if(entries[0].signer===entries[1].signer||entries.some(value=>!plan.authorizedOwners.includes(value.signer))) fail('pilot gate signatures are not an exact governance 2-of-3 quorum');
 const data=safeInterface.encodeFunctionData('execTransaction',[plan.safeTransaction.to,0,plan.safeTransaction.data,0,0,0,0,ZERO,ZERO,concat(entries.map(v=>v.signature))]).toLowerCase();
 const unsigned={schema:PILOT_GATE_TRANSACTION_SCHEMA,chainId:'1',planHash:plan.planHash,to:plan.governanceSafe,value:'0',data,dataHash:keccak256(data),safeTxHash:plan.safeTxHash,signers:entries.map(v=>v.signer)};
 return {...unsigned,transactionPackageHash:documentHash(unsigned)};
}

export const _pilotDepositGateInternals={reserveInterface,safeInterface,safeHash};
