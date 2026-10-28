import test from 'node:test';
import assert from 'node:assert/strict';
import {chmodSync,mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

const checker=new URL('../../scripts/check-ledger-address-output.mjs',import.meta.url).pathname;
const address='0x1234567890abcdef1234567890abcdef12345678';

test('Ledger address output is one exact bounded identity line',()=>{
  const root=mkdtempSync(join(tmpdir(),'usdom-ledger-address-'));
  chmodSync(root,0o700);
  const file=join(root,'address.txt');
  try {
    for(const valid of [address,`${address}\n`,address.toUpperCase().replace('0X','0x')]) {
      writeFileSync(file,valid,{mode:0o600});
      const result=spawnSync(process.execPath,[checker,file,address],{encoding:'utf8'});
      assert.equal(result.status,0,result.stderr); assert.equal(result.stdout,'');
    }
    for(const invalid of [`${address}\n\n`,`${address}x`,`${address}\r\n`,'0x'+'12'.repeat(21)]) {
      writeFileSync(file,invalid,{mode:0o600});
      const result=spawnSync(process.execPath,[checker,file,address],{encoding:'utf8'});
      assert.notEqual(result.status,0); assert.equal(result.stdout,'');
    }
    writeFileSync(file,address); chmodSync(file,0o644);
    assert.notEqual(spawnSync(process.execPath,[checker,file,address]).status,0);
  } finally { rmSync(root,{recursive:true,force:true}); }
});
