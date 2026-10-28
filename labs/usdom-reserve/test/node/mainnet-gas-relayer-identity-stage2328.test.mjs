import test from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,rm,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {Wallet} from 'ethers';

const run=promisify(execFile),root=fileURLToPath(new URL('../..',import.meta.url));
const wallet=new Wallet('0x'+'a1'.repeat(32));
const identity={schema:'usdom-mainnet-gas-relayer-public-identity/v1',chainId:'1',
 address:wallet.address,role:'mainnet-deployment-gas-only',encryptedKeystoreSha256:'a2'.repeat(32),
 custodyAuthority:false,tokenCustody:false};
test('deployment relayer identity has no custody role and binds the encrypted keystore',async()=>{
 const dir=await mkdtemp('/dev/shm/usdom-relayer-id-');try{const path=join(dir,'identity.json');
  await writeFile(path,JSON.stringify(identity)+'\n',{mode:0o600,flag:'wx'});
  const {stdout}=await run(process.execPath,['scripts/read-mainnet-gas-relayer-identity.mjs',path],{cwd:root});
  assert.equal(stdout,`${wallet.address}\n`);
 }finally{await rm(dir,{recursive:true,force:true});}
});
test('deployment relayer identity rejects custody authority and extra fields',async()=>{
 const dir=await mkdtemp('/dev/shm/usdom-relayer-id-bad-');try{for(const [name,value] of [['authority',{...identity,custodyAuthority:true}],['extra',{...identity,privateKey:'forbidden'}]]){
  const path=join(dir,`${name}.json`);await writeFile(path,JSON.stringify(value)+'\n',{mode:0o600,flag:'wx'});
  await assert.rejects(run(process.execPath,['scripts/read-mainnet-gas-relayer-identity.mjs',path],{cwd:root}));
 }}finally{await rm(dir,{recursive:true,force:true});}
});
