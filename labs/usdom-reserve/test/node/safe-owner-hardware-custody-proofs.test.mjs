import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp,writeFile,chmod,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {Wallet} from 'ethers';
import {canonicalOwnersByRole,SAFE_CONTROL_SPECS,RECOVERABLE_SAFE_CONTROL_SCHEMA} from '../../sdk/safe-control-deployment.mjs';
import {_safeControlObservationInternals} from '../../sdk/safe-control-observation.mjs';

const checker=fileURLToPath(new URL('../../scripts/check-safe-owner-hardware-custody-proofs.mjs',import.meta.url));
const slots=['primary','secondary','recovery'];
const safes=['0x1000000000000000000000000000000000000001','0x2000000000000000000000000000000000000002','0x3000000000000000000000000000000000000003'];
const types={SafeOwnerCustodyProof:[{name:'role',type:'string'},{name:'slot',type:'string'},
  {name:'owner',type:'address'},{name:'packageHash',type:'bytes32'}]};
async function fixture(){
  const wallets=Array.from({length:9},(_,index)=>new Wallet(`0x${String(index+1).padStart(64,'0')}`));
  const physical={};
  for(let roleIndex=0;roleIndex<3;roleIndex++) physical[SAFE_CONTROL_SPECS[roleIndex].role]=wallets.slice(roleIndex*3,roleIndex*3+3).reverse().map(value=>value.address);
  const canonical=canonicalOwnersByRole(physical);
  const packageDocument={schema:RECOVERABLE_SAFE_CONTROL_SCHEMA,ethereumChainId:'1',threshold:'2',
    ownersByRole:canonical,controls:SAFE_CONTROL_SPECS.map((value,index)=>({role:value.role,safe:safes[index]}))};
  const packageHash=_safeControlObservationInternals.documentHash(packageDocument),proofs=[];
  for(let roleIndex=0;roleIndex<3;roleIndex++){
    const role=SAFE_CONTROL_SPECS[roleIndex].role,safe=safes[roleIndex];
    for(let slotIndex=0;slotIndex<3;slotIndex++){
      const slot=slots[slotIndex],owner=physical[role][slotIndex];
      const wallet=wallets.find(value=>value.address===owner);
      const domain={name:'USDOM Safe Owner Custody Proof',version:'1',chainId:1,verifyingContract:safe};
      const message={role,slot,owner,packageHash};
      proofs.push({role,slot,owner,safe,typedData:{types:{EIP712Domain:[{name:'name',type:'string'},
        {name:'version',type:'string'},{name:'chainId',type:'uint256'},{name:'verifyingContract',type:'address'}],...types},
        primaryType:'SafeOwnerCustodyProof',domain,message},signature:await wallet.signTypedData(domain,types,message)});
    }
  }
  return {packageDocument,bundle:{schema:'usdom-safe-owner-hardware-custody-proofs/v1',ethereumChainId:'1',packageHash,ownersByRole:physical,proofs}};
}
async function run(value){
  const directory=await mkdtemp(path.join(tmpdir(),'usdom-hardware-custody-')); await chmod(directory,0o700);
  const packagePath=path.join(directory,'package.json'),proofPath=path.join(directory,'proofs.json');
  await writeFile(packagePath,JSON.stringify(value.packageDocument),{mode:0o600});
  await writeFile(proofPath,JSON.stringify(value.bundle),{mode:0o600});
  try{return spawnSync(process.execPath,[checker],{encoding:'utf8',env:{...process.env,USDOM_SAFE_PACKAGE:packagePath,USDOM_SAFE_HARDWARE_CUSTODY_PROOFS:proofPath}});}
  finally{await rm(directory,{recursive:true,force:true});}
}
test('hardware custody proofs preserve physical slot labels while matching canonical Safe owner sets',async()=>{
  const value=await fixture();
  assert.notDeepEqual(value.bundle.ownersByRole,value.packageDocument.ownersByRole);
  const result=await run(value); assert.equal(result.status,0,result.stderr);
  assert.equal(JSON.parse(result.stdout).proofCount,9);
});
test('hardware custody checker rejects slot, owner set, package and signature mutations',async()=>{
  for(const mutate of [
    value=>{value.bundle.proofs[0].slot='secondary';},
    value=>{value.bundle.ownersByRole.governance[0]=value.bundle.ownersByRole.reserveGuardian[0];},
    value=>{value.bundle.packageHash=`0x${'00'.repeat(32)}`;},
    value=>{value.bundle.proofs[4].signature=value.bundle.proofs[5].signature;},
    value=>{value.bundle.proofs[8].extra=true;},
  ]){const value=await fixture();mutate(value);const result=await run(value);assert.notEqual(result.status,0);assert.match(result.stderr,/Hardware custody proof validation failed:/);}
});
