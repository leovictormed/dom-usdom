#!/usr/bin/env node
import {getAddress,verifyTypedData} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {canonicalOwnersByRole,SAFE_CONTROL_SPECS,RECOVERABLE_SAFE_CONTROL_SCHEMA}
  from '../sdk/safe-control-deployment.mjs';
import {_safeControlObservationInternals} from '../sdk/safe-control-observation.mjs';

const slots=['primary','secondary','recovery'];
const domainTypes=[{name:'name',type:'string'},{name:'version',type:'string'},
  {name:'chainId',type:'uint256'},{name:'verifyingContract',type:'address'}];
const custodyTypes=[{name:'role',type:'string'},{name:'slot',type:'string'},
  {name:'owner',type:'address'},{name:'packageHash',type:'bytes32'}];
function fail(message){throw new Error(message);}
function exact(value,keys,label){
  if(value===null||typeof value!=='object'||Array.isArray(value)
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) fail(`${label} fields are invalid`);
}
function sameAddress(left,right,label){
  try { if(getAddress(left).toLowerCase()!==getAddress(right).toLowerCase()) fail(`${label} mismatch`); }
  catch(error) { fail(`${label} is invalid: ${error instanceof Error?error.message:String(error)}`); }
}
async function load(name,label,maximum){
  const target=process.env[name]; if(typeof target!=='string'||target.length===0) fail(`${name} is required`);
  const bytes=await readDirectFile(target,{minimum:2,maximum,exactMode:0o600,label});
  try{return parseStrictJson(bytes.toString('utf8'),{label,maxBytes:maximum,maxDepth:32});}
  finally{bytes.fill(0);}
}
try{
  const packageDocument=await load('USDOM_SAFE_PACKAGE','Safe package',4*1024*1024);
  const bundle=await load('USDOM_SAFE_HARDWARE_CUSTODY_PROOFS','hardware custody proofs',2*1024*1024);
  if(packageDocument.schema!==RECOVERABLE_SAFE_CONTROL_SCHEMA||packageDocument.ethereumChainId!=='1'
      ||packageDocument.threshold!=='2'||!Array.isArray(packageDocument.controls)||packageDocument.controls.length!==3) fail('Safe package identity is invalid');
  const owners=canonicalOwnersByRole(packageDocument.ownersByRole);
  const packageHash=_safeControlObservationInternals.documentHash(packageDocument);
  exact(bundle,['schema','ethereumChainId','packageHash','ownersByRole','proofs'],'custody proof bundle');
  if(bundle.schema!=='usdom-safe-owner-hardware-custody-proofs/v1'||bundle.ethereumChainId!=='1'||bundle.packageHash!==packageHash) fail('custody proof bundle identity is invalid');
  canonicalOwnersByRole(bundle.ownersByRole);
  for(const {role} of SAFE_CONTROL_SPECS){
    const packageSet=owners[role].map(value=>value.toLowerCase()).sort();
    const proofSet=bundle.ownersByRole[role].map(value=>getAddress(value).toLowerCase()).sort();
    if(JSON.stringify(packageSet)!==JSON.stringify(proofSet)) fail(`${role} custody owner set mismatch`);
  }
  if(!Array.isArray(bundle.proofs)||bundle.proofs.length!==9) fail('custody bundle must contain nine proofs');
  for(let roleIndex=0;roleIndex<SAFE_CONTROL_SPECS.length;roleIndex++){
    const role=SAFE_CONTROL_SPECS[roleIndex].role;
    const control=packageDocument.controls.find(value=>value?.role===role);
    if(!control) fail(`Safe package is missing ${role}`);
    for(let slotIndex=0;slotIndex<slots.length;slotIndex++){
      const slot=slots[slotIndex],owner=bundle.ownersByRole[role][slotIndex];
      const proof=bundle.proofs[roleIndex*3+slotIndex];
      exact(proof,['role','slot','owner','safe','typedData','signature'],`${role}/${slot} proof`);
      if(proof.role!==role||proof.slot!==slot) fail(`${role}/${slot} proof order mismatch`);
      sameAddress(proof.owner,owner,`${role}/${slot} owner`); sameAddress(proof.safe,control.safe,`${role}/${slot} Safe`);
      exact(proof.typedData,['types','primaryType','domain','message'],`${role}/${slot} typed data`);
      exact(proof.typedData.types,['EIP712Domain','SafeOwnerCustodyProof'],`${role}/${slot} types`);
      if(JSON.stringify(proof.typedData.types.EIP712Domain)!==JSON.stringify(domainTypes)
          ||JSON.stringify(proof.typedData.types.SafeOwnerCustodyProof)!==JSON.stringify(custodyTypes)
          ||proof.typedData.primaryType!=='SafeOwnerCustodyProof') fail(`${role}/${slot} typed data type mismatch`);
      exact(proof.typedData.domain,['name','version','chainId','verifyingContract'],`${role}/${slot} domain`);
      if(proof.typedData.domain.name!=='USDOM Safe Owner Custody Proof'||proof.typedData.domain.version!=='1'||proof.typedData.domain.chainId!==1) fail(`${role}/${slot} domain mismatch`);
      sameAddress(proof.typedData.domain.verifyingContract,control.safe,`${role}/${slot} verifying contract`);
      exact(proof.typedData.message,['role','slot','owner','packageHash'],`${role}/${slot} message`);
      if(proof.typedData.message.role!==role||proof.typedData.message.slot!==slot||proof.typedData.message.packageHash!==packageHash) fail(`${role}/${slot} message binding mismatch`);
      sameAddress(proof.typedData.message.owner,owner,`${role}/${slot} message owner`);
      if(typeof proof.signature!=='string'||!/^0x[0-9A-Fa-f]{130}$/.test(proof.signature)) fail(`${role}/${slot} signature is invalid`);
      const recovered=verifyTypedData(proof.typedData.domain,{SafeOwnerCustodyProof:custodyTypes},proof.typedData.message,proof.signature);
      sameAddress(recovered,owner,`${role}/${slot} recovered signer`);
    }
  }
  process.stdout.write(`${JSON.stringify({schema:'usdom-safe-owner-hardware-custody-proof-check/v1',valid:true,packageHash,proofCount:9})}\n`);
}catch(error){process.stderr.write(`Hardware custody proof validation failed: ${error instanceof Error?error.message:String(error)}\n`);process.exitCode=1;}
