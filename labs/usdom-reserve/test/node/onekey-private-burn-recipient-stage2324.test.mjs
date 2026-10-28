import test from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {Wallet} from 'ethers';

const run=promisify(execFile),root=fileURLToPath(new URL('../..',import.meta.url));
const wallet=new Wallet('0x'+'91'.repeat(32));
const evidence={schema:'usdom-onekey-ios-hardware-account-evidence/v1',source:'onekey-ios-app',
 deviceId:'classic1s-ios-redemption',firmware:'4.13.0',address:wallet.address,
 appReleaseSha256:'92'.repeat(32),hardwareAddressConfirmed:true,hardwareAccountSelected:true,
 ratified:true,hardwareSigningApproved:false};

test('private burn consumes an exact physical OneKey iPhone recipient evidence file',async()=>{
 const dir=await mkdtemp('/dev/shm/usdom-burn-recipient-');
 try {const path=join(dir,'evidence.json');await writeFile(path,JSON.stringify(evidence)+'\n',{mode:0o600,flag:'wx'});
  const {stdout}=await run(process.execPath,['scripts/read-onekey-ios-hardware-address.mjs',path],{cwd:root});
  assert.equal(stdout,`${wallet.address}\n`);
  const source=await readFile(join(root,'scripts/prepare-closed-mainnet-private-burn.sh'),'utf8');
  assert.doesNotMatch(source,/--ledger|Ledger/u);assert.match(source,/onekey-ios-redemption-account-evidence\.json/u);
 }finally{await rm(dir,{recursive:true,force:true});}
});

test('recipient evidence rejects extra fields and missing hardware confirmation',async()=>{
 const dir=await mkdtemp('/dev/shm/usdom-burn-recipient-bad-');
 try {for(const [name,value] of [['extra',{...evidence,extra:true}],['unconfirmed',{...evidence,hardwareAddressConfirmed:false}]]) {
   const path=join(dir,`${name}.json`);await writeFile(path,JSON.stringify(value)+'\n',{mode:0o600,flag:'wx'});
   await assert.rejects(run(process.execPath,['scripts/read-onekey-ios-hardware-address.mjs',path],{cwd:root}));
  }}finally{await rm(dir,{recursive:true,force:true});}
});
