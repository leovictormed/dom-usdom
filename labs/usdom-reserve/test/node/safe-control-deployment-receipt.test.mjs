import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

const root=path.resolve(new URL('../..',import.meta.url).pathname);
const checker=path.join(root,'scripts/check-safe-control-deployment-receipt.mjs');
const address=value=>`0x${value.repeat(40)}`;
const hash=value=>`0x${value.repeat(64)}`;

function fixture() {
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'safe-receipt-'));
  fs.chmodSync(directory,0o700);
  const packagePath=path.join(directory,'package.json');
  const validationPath=path.join(directory,'validation.json');
  const receiptPath=path.join(directory,'receipt.json');
  const packageDocument={controls:[{role:'governance',safe:address('8'),to:address('2')} ]};
  const validation={schema:'usdom-safe-deployment-raw/v1',role:'governance',
    safe:address('8'),from:address('1'),nonce:'7',to:address('2'),dataHash:hash('9'),
    transactionHash:hash('3'),gasLimit:'200000',maxFeePerGas:'10000000000',rawHash:hash('a')};
  const receipt={transactionHash:hash('3'),blockNumber:'0x10',blockHash:hash('4'),transactionIndex:'0x2',status:'0x1',
    from:address('1'),to:address('2'),logs:[]};
  for(const [file,value] of [[packagePath,packageDocument],[validationPath,validation],[receiptPath,receipt]]) {
    fs.writeFileSync(file,`${JSON.stringify(value)}\n`,{mode:0o600});
  }
  return {directory,packagePath,validationPath,receiptPath,receipt};
}

function run(value) {
  return spawnSync(process.execPath,[checker,'governance',value.receiptPath,value.validationPath],{
    cwd:root,env:{...process.env,USDOM_SAFE_PACKAGE:value.packagePath},encoding:'utf8'});
}

test('Safe deployment receipt is projected and bound to authenticated raw and factory',t=>{
  const value=fixture(); t.after(()=>fs.rmSync(value.directory,{recursive:true,force:true}));
  const result=run(value); assert.equal(result.status,0,result.stderr);
  assert.deepEqual(Object.keys(JSON.parse(result.stdout)).sort(),
    ['schema','role','transactionHash','blockNumber','blockHash','transactionIndex','status','from','to'].sort());
  for(const mutation of [
    receipt=>{receipt.status='0x0';},receipt=>{receipt.transactionHash=hash('5');},
    receipt=>{receipt.from=address('6');},receipt=>{receipt.to=address('7');},
    receipt=>{receipt.blockNumber='0x01';},receipt=>{receipt.blockHash=hash('0');},
    receipt=>{receipt.transactionIndex='0x02';},
  ]) {
    const changed=structuredClone(value.receipt); mutation(changed);
    fs.writeFileSync(value.receiptPath,`${JSON.stringify(changed)}\n`,{mode:0o600});
    assert.notEqual(run(value).status,0);
  }
  const validReceipt=structuredClone(value.receipt);
  fs.writeFileSync(value.receiptPath,`${JSON.stringify(validReceipt)}\n`,{mode:0o600});
  const originalValidation=JSON.parse(fs.readFileSync(value.validationPath,'utf8'));
  for(const mutation of [
    validation=>{validation.extra=true;},validation=>{delete validation.rawHash;},
    validation=>{validation.safe=address('7');},validation=>{validation.to=address('7');},
    validation=>{validation.nonce='07';},validation=>{validation.gasLimit='1000001';},
    validation=>{validation.maxFeePerGas='100000000001';},validation=>{validation.rawHash=hash('0');},
  ]) {
    const changed=structuredClone(originalValidation); mutation(changed);
    fs.writeFileSync(value.validationPath,`${JSON.stringify(changed)}\n`,{mode:0o600});
    assert.notEqual(run(value).status,0);
  }
});
