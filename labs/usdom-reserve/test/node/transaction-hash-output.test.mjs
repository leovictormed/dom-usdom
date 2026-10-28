import test from 'node:test';
import assert from 'node:assert/strict';
import {chmodSync,mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

const checker=new URL('../../scripts/check-transaction-hash-output.mjs',import.meta.url).pathname;
const hash='0x'+'12'.repeat(32);

test('publication output is one exact expected transaction hash',()=>{
  const root=mkdtempSync(join(tmpdir(),'usdom-publication-hash-'));
  chmodSync(root,0o700);
  const file=join(root,'hash.txt');
  try {
    for(const valid of [hash,`${hash}\n`]) {
      writeFileSync(file,valid,{mode:0o600});
      const result=spawnSync(process.execPath,[checker,file,hash],{encoding:'utf8'});
      assert.equal(result.status,0,result.stderr); assert.equal(result.stdout,'');
    }
    for(const invalid of [`${hash}\n\n`,`${hash}0`,`${hash}\r\n`,'0x'+'13'.repeat(32)]) {
      writeFileSync(file,invalid,{mode:0o600});
      const result=spawnSync(process.execPath,[checker,file,hash],{encoding:'utf8'});
      assert.notEqual(result.status,0); assert.equal(result.stdout,'');
    }
    writeFileSync(file,hash); chmodSync(file,0o644);
    assert.notEqual(spawnSync(process.execPath,[checker,file,hash]).status,0);
  } finally { rmSync(root,{recursive:true,force:true}); }
});
