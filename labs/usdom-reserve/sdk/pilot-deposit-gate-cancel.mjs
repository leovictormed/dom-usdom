import {Interface,Signature,concat,getAddress,keccak256,recoverAddress} from 'ethers';
import {_pilotDepositGateInternals} from './pilot-deposit-gate.mjs';
export const PILOT_GATE_CANCEL_PLAN_SCHEMA='usdom-pilot-deposit-gate-cancel-plan/v1',PILOT_GATE_CANCEL_TRANSACTION_SCHEMA='usdom-pilot-deposit-gate-cancel-transaction/v1';
const ZERO='0x0000000000000000000000000000000000000000',HASH=/^0x[0-9a-f]{64}$/,SIG=/^0x[0-9a-f]{130}$/;
const reserveInterface=new Interface(['function cancelPilotDepositAuthorization(bytes32 expectedSnapshotCommitment,uint64 expectedGeneration)']);
const exact=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&JSON.stringify(Object.keys(v).sort())===JSON.stringify([...k].sort()),fail=m=>{throw new Error(m);};
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
const doc=v=>keccak256(Buffer.from(JSON.stringify(canonical(v))));
export function buildPilotGateCancelPlan({gatePlan,releaseConfig,safePackage,role='guardian',safeNonce,finalizedBlockNumber,finalizedBlockHash,observation}={}){
 if(!['guardian','governance'].includes(role)) fail('pilot cancel Safe role is invalid');
 const safe=getAddress(releaseConfig?.[role]),reserve=getAddress(releaseConfig?.reserve),control=safePackage?.controls?.find(v=>v.role===role),owners=safePackage?.ownersByRole?.[role]?.map(getAddress);
 if(safe!==getAddress(control?.safe??ZERO)||safePackage?.threshold!=='2'||!Array.isArray(owners)||owners.length!==3||new Set(owners).size!==3) fail('pilot cancel requires exact 2-of-3 Safe');
 if(!HASH.test(gatePlan?.snapshotCommitment??'')||!HASH.test(gatePlan?.expectedAuthorization??'')||!/^(0|[1-9][0-9]*)$/.test(gatePlan?.generation??'')||!HASH.test(finalizedBlockHash??'')) fail('pilot cancel gate identity is invalid');
 const expected={authorization:gatePlan.expectedAuthorization,snapshot:gatePlan.snapshotCommitment,validUntil:gatePlan.validUntil,generation:gatePlan.generation};
 if(JSON.stringify(observation)!==JSON.stringify(expected)) fail('pilot cancel finalized state differs from exact armed gate');
 const data=reserveInterface.encodeFunctionData('cancelPilotDepositAuthorization',[gatePlan.snapshotCommitment,gatePlan.generation]).toLowerCase(),safeTransaction={to:reserve,value:'0',data,operation:'0',safeTxGas:'0',baseGas:'0',gasPrice:'0',gasToken:ZERO,refundReceiver:ZERO,nonce:String(safeNonce)};
 const unsigned={schema:PILOT_GATE_CANCEL_PLAN_SCHEMA,chainId:'1',role,governanceGatePlanHash:gatePlan.planHash,snapshotCommitment:gatePlan.snapshotCommitment,expectedAuthorization:gatePlan.expectedAuthorization,generation:gatePlan.generation,validUntil:gatePlan.validUntil,controlSafe:safe,reserve,authorizedOwners:[...owners].sort((a,b)=>BigInt(a)<BigInt(b)?-1:1),safeTransaction,safeTxHash:_pilotDepositGateInternals.safeHash(safe,safeTransaction),finalizedBlockNumber:String(finalizedBlockNumber),finalizedBlockHash:finalizedBlockHash.toLowerCase()}; return {...unsigned,planHash:doc(unsigned)};
}
export function assemblePilotGateCancelTransaction({plan,signatures}={}){
 if(!exact(plan,['schema','chainId','role','governanceGatePlanHash','snapshotCommitment','expectedAuthorization','generation','validUntil','controlSafe','reserve','authorizedOwners','safeTransaction','safeTxHash','finalizedBlockNumber','finalizedBlockHash','planHash'])||plan.schema!==PILOT_GATE_CANCEL_PLAN_SCHEMA||doc(Object.fromEntries(Object.entries(plan).filter(([k])=>k!=='planHash')))!==plan.planHash) fail('pilot cancel plan is invalid');
 if(!Array.isArray(signatures)||signatures.length!==2) fail('pilot cancel requires exactly two signatures');
 const entries=signatures.map(v=>{if(!exact(v,['signer','signature'])||!SIG.test(v.signature??''))fail('pilot cancel signature invalid');const sig=Signature.from(v.signature);if(sig.serialized!==v.signature)fail('pilot cancel signature is noncanonical');const signer=getAddress(recoverAddress(plan.safeTxHash,sig));if(![27,28].includes(sig.v)||signer!==getAddress(v.signer)||!plan.authorizedOwners.includes(signer))fail('pilot cancel signer mismatch');return{signer,signature:sig.serialized};}).sort((a,b)=>BigInt(a.signer)<BigInt(b.signer)?-1:1); if(entries[0].signer===entries[1].signer)fail('pilot cancel duplicate signer');
 const data=_pilotDepositGateInternals.safeInterface.encodeFunctionData('execTransaction',[plan.reserve,0,plan.safeTransaction.data,0,0,0,0,ZERO,ZERO,concat(entries.map(v=>v.signature))]).toLowerCase(),unsigned={schema:PILOT_GATE_CANCEL_TRANSACTION_SCHEMA,chainId:'1',planHash:plan.planHash,to:plan.controlSafe,value:'0',data,dataHash:keccak256(data),safeTxHash:plan.safeTxHash,signers:entries.map(v=>v.signer)};return{...unsigned,transactionPackageHash:doc(unsigned)};
}
export const _pilotGateCancelInternals={reserveInterface};
