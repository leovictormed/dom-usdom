import assert from 'node:assert/strict';
import test from 'node:test';
import {chmod,link,mkdtemp,readFile,rm,symlink,writeFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {TypedDataEncoder,Wallet} from 'ethers';
import {assembleOneKeySafeSignatures} from '../../scripts/assemble-onekey-safe-signatures.mjs';

const wallets=[new Wallet('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a841b1f6ea2b34be6d0'),
 new Wallet('0x8b3a350cf5c34c9194ca3a545dbea8f3f70a0a8d3b4cc4b2bf7d7d64e3f6f56b')];
const typedData={types:{EIP712Domain:[{name:'name',type:'string'},{name:'version',type:'string'},
 {name:'chainId',type:'uint256'},{name:'verifyingContract',type:'address'}],
 Approval:[{name:'commitment',type:'bytes32'}]},primaryType:'Approval',domain:{name:'USDOM',version:'1',chainId:'1',
 verifyingContract:'0x1111111111111111111111111111111111111111'},message:{commitment:`0x${'11'.repeat(32)}`}};

async function fixture(){const directory=await mkdtemp(join(tmpdir(),'safe-assembler-'));await chmod(directory,0o700);
 const envelopePath=join(directory,'envelope.json'),signature1Path=join(directory,'one.sig'),signature2Path=join(directory,'two.sig'),outputPath=join(directory,'safe.sig');
 const digest=TypedDataEncoder.hash(typedData.domain,{Approval:typedData.types.Approval},typedData.message);
 await writeFile(envelopePath,JSON.stringify({schema:'usdom-onekey-eip712-signing/v1',digest,typedData}),{mode:0o600});
 await writeFile(signature1Path,`${await wallets[0].signTypedData(typedData.domain,{Approval:typedData.types.Approval},typedData.message)}\n`,{mode:0o600});
 await writeFile(signature2Path,`${await wallets[1].signTypedData(typedData.domain,{Approval:typedData.types.Approval},typedData.message)}\n`,{mode:0o600});
 return {directory,envelopePath,signature1Path,signature2Path,outputPath,owner1:wallets[0].address,owner2:wallets[1].address};}

test('assembler verifies owners and creates the canonical Safe payload once',async()=>{const f=await fixture();try{
 await assembleOneKeySafeSignatures(f);assert.match(await readFile(f.outputPath,'ascii'),/^0x[0-9a-f]{260}\n$/);
 await assert.rejects(assembleOneKeySafeSignatures(f),error=>error.exitCode===80);
 }finally{await rm(f.directory,{recursive:true,force:true});}});

test('assembler rejects symlink, hardlink, FIFO, duplicate JSON and oversized inputs',async()=>{
 for(const kind of ['symlink','hardlink','fifo','duplicate','oversize']) {const f=await fixture();try{
  if(kind==='symlink'){const real=f.signature1Path+'.real';await writeFile(real,await readFile(f.signature1Path),{mode:0o600});await rm(f.signature1Path);await symlink(real,f.signature1Path);}
  if(kind==='hardlink'){const alias=f.signature1Path+'.alias';await link(f.signature1Path,alias);}
  if(kind==='fifo'){await rm(f.signature1Path);assert.equal(spawnSync('mkfifo',[f.signature1Path]).status,0);}
  if(kind==='duplicate')await writeFile(f.envelopePath,'{"schema":"x","schema":"y"}',{mode:0o600});
  if(kind==='oversize')await writeFile(f.envelopePath,'x'.repeat(2*1024*1024+1),{mode:0o600});
  await assert.rejects(assembleOneKeySafeSignatures(f),/safe direct regular file|duplicate|size|short|too large/);
 }finally{await rm(f.directory,{recursive:true,force:true});}}
});

test('assembler rejects owner substitution without creating output',async()=>{const f=await fixture();try{
 f.owner1='0x2222222222222222222222222222222222222222';await assert.rejects(assembleOneKeySafeSignatures(f),/owner differs/);
 await assert.rejects(readFile(f.outputPath),error=>error.code==='ENOENT');
 }finally{await rm(f.directory,{recursive:true,force:true});}});
