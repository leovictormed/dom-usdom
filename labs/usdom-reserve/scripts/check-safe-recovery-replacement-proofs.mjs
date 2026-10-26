#!/usr/bin/env node
import {getAddress,verifyTypedData} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const roles=['governance','reserveGuardian','checkpointGuardian'];
const domainTypes=[
  {name:'name',type:'string'},
  {name:'version',type:'string'},
  {name:'chainId',type:'uint256'},
  {name:'verifyingContract',type:'address'},
];
const proofTypes=[
  {name:'role',type:'string'},
  {name:'replacementOwner',type:'address'},
  {name:'planHash',type:'bytes32'},
];

function fail(message){ throw new Error(message); }
function exactKeys(value,keys,label){
  if(value===null||typeof value!=='object'||Array.isArray(value)) fail(`${label} must be an object`);
  const actual=Object.keys(value).sort();
  const expected=[...keys].sort();
  if(JSON.stringify(actual)!==JSON.stringify(expected)) fail(`${label} has unexpected or missing fields`);
}
function address(value,label){
  if(typeof value!=='string'||!/^0x[0-9a-fA-F]{40}$/.test(value)) fail(`${label} is not an address`);
  try { return getAddress(value); } catch { fail(`${label} is not a valid address`); }
}
function equalAddress(a,b,label){
  if(address(a,`${label} left`).toLowerCase()!==address(b,`${label} right`).toLowerCase()) fail(`${label} mismatch`);
}
async function load(path,label){
  if(typeof path!=='string'||path.length===0) fail(`${label} path is required`);
  const bytes=await readDirectFile(path,{minimum:2,maximum:2*1024*1024,label});
  try { return parseStrictJson(bytes.toString('utf8'),{label,maxBytes:2*1024*1024,maxDepth:32}); }
  finally { bytes.fill(0); }
}

try {
  const plan=await load(process.env.USDOM_SAFE_RECOVERY_PLAN,'Safe recovery plan');
  const bundle=await load(process.env.USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS,'Safe recovery replacement proofs');
  if(typeof plan.planHash!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(plan.planHash)) fail('planHash is invalid');
  if(!Array.isArray(plan.roles)||plan.roles.length!==3) fail('plan roles must contain exactly three entries');
  exactKeys(bundle,['schema','ethereumChainId','planHash','proofs'],'proof bundle');
  if(bundle.schema!=='usdom-safe-recovery-replacement-proofs/v2'||bundle.ethereumChainId!=='1') fail('proof bundle identity is invalid');
  if(bundle.planHash!==plan.planHash) fail('proof bundle planHash mismatch');
  if(!Array.isArray(bundle.proofs)||bundle.proofs.length!==3) fail('proof bundle must contain exactly three proofs');
  const replacements=new Set();
  for(let index=0;index<roles.length;index++){
    const role=roles[index];
    const planned=plan.roles.find(entry=>entry?.role===role);
    if(!planned) fail(`plan is missing ${role}`);
    const proof=bundle.proofs[index];
    exactKeys(proof,['role','replacementOwner','safe','typedData','signature'],`${role} proof`);
    if(proof.role!==role) fail(`${role} proof order or role mismatch`);
    equalAddress(proof.replacementOwner,planned.newOwner,`${role} replacement owner`);
    equalAddress(proof.safe,planned.safe,`${role} Safe`);
    const replacement=address(proof.replacementOwner,`${role} replacement owner`).toLowerCase();
    if(replacements.has(replacement)) fail('replacement owners must be globally distinct');
    replacements.add(replacement);
    exactKeys(proof.typedData,['types','primaryType','domain','message'],`${role} typed data`);
    exactKeys(proof.typedData.types,['EIP712Domain','SafeRecoveryReplacementProof'],`${role} typed types`);
    if(JSON.stringify(proof.typedData.types.EIP712Domain)!==JSON.stringify(domainTypes)||
       JSON.stringify(proof.typedData.types.SafeRecoveryReplacementProof)!==JSON.stringify(proofTypes)) fail(`${role} typed data types mismatch`);
    if(proof.typedData.primaryType!=='SafeRecoveryReplacementProof') fail(`${role} primary type mismatch`);
    exactKeys(proof.typedData.domain,['name','version','chainId','verifyingContract'],`${role} domain`);
    if(proof.typedData.domain.name!=='USDOM Safe Recovery Replacement Proof'||proof.typedData.domain.version!=='1'||proof.typedData.domain.chainId!==1) fail(`${role} domain identity mismatch`);
    equalAddress(proof.typedData.domain.verifyingContract,planned.safe,`${role} verifying contract`);
    exactKeys(proof.typedData.message,['role','replacementOwner','planHash'],`${role} message`);
    if(proof.typedData.message.role!==role||proof.typedData.message.planHash!==plan.planHash) fail(`${role} message binding mismatch`);
    equalAddress(proof.typedData.message.replacementOwner,planned.newOwner,`${role} message owner`);
    if(typeof proof.signature!=='string'||!/^0x[0-9a-fA-F]{130}$/.test(proof.signature)) fail(`${role} signature is invalid`);
    const recovered=verifyTypedData(proof.typedData.domain,{SafeRecoveryReplacementProof:proofTypes},proof.typedData.message,proof.signature);
    equalAddress(recovered,planned.newOwner,`${role} recovered signer`);
  }
  process.stdout.write(`${JSON.stringify({schema:'usdom-safe-recovery-replacement-proof-check/v1',valid:true,planHash:plan.planHash,proofCount:3})}\n`);
} catch(error) {
  process.stderr.write(`Safe recovery replacement proof validation failed: ${error instanceof Error?error.message:String(error)}\n`);
  process.exitCode=1;
}
