import test from 'node:test';
import assert from 'node:assert/strict';
import {chmodSync,linkSync,mkdtempSync,readFileSync,rmSync,symlinkSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {readPrivateRawTransaction} from '../../sdk/private-raw-transaction.mjs';

test('raw transaction reader accepts only owner 0600 single-link regular files',()=>{
  const root=mkdtempSync(join(tmpdir(),'usdom-private-raw-'));
  try {
    const file=join(root,'raw'); writeFileSync(file,'0x0102\n',{mode:0o600});
    assert.equal(readPrivateRawTransaction(file),'0x0102');
    chmodSync(file,0o644); assert.throws(()=>readPrivateRawTransaction(file),/0600/); chmodSync(file,0o600);
    const hard=join(root,'hard'); linkSync(file,hard); assert.throws(()=>readPrivateRawTransaction(file),/single-link/);
    rmSync(hard); const symbolic=join(root,'symbolic'); symlinkSync(file,symbolic);
    assert.throws(()=>readPrivateRawTransaction(symbolic)); rmSync(symbolic);
    writeFileSync(file,'0x0G',{mode:0o600}); assert.throws(()=>readPrivateRawTransaction(file),/malformed/);
  } finally { rmSync(root,{recursive:true,force:true}); }
});

test('publisher rejects credential-bearing RPC before network and never echoes raw',()=>{
  const root=mkdtempSync(join(tmpdir(),'usdom-private-publish-'));
  try {
    const file=join(root,'raw'); writeFileSync(file,'0x0102\n',{mode:0o600});
    const result=spawnSync(process.execPath,[new URL('../../scripts/publish-private-raw-transaction.mjs',import.meta.url).pathname,
      file,'https://user:password@example.invalid'],{encoding:'utf8'});
    assert.notEqual(result.status,0);
    assert.equal(JSON.parse(result.stderr).code,'RELEASE_OPERATION_REJECTED');
    assert.doesNotMatch(`${result.stdout}${result.stderr}`,/0x0102|user:password/);
  } finally { rmSync(root,{recursive:true,force:true}); }
});

test('pilot executors keep raw transactions out of argv, values in env, disk tmp and logs',()=>{
  for(const name of ['deposit','redemption']) {
    const source=readFileSync(new URL(`../../scripts/execute-closed-mainnet-${name}.sh`,import.meta.url),'utf8');
    assert.match(source,/mktemp -d -p \/dev\/shm/);
    assert.match(source,/for abandoned in \/dev\/shm\/usdom-closed-/);
    assert.match(source,/trap 'cleanup \$\?' EXIT/);
    for(const signal of ['HUP','INT','TERM']) assert.match(source,new RegExp(`trap 'cleanup [0-9]+' ${signal}`));
    assert.match(source,/chmod 0600 "\$raw_candidate"/);
    assert.match(source,/publish-private-raw-transaction\.mjs "\$raw_file"/);
    assert.match(source,/rm -f -- "\$raw_file"/);
    assert.match(source,/\[\[ -e \$raw_file && ! -e \$validation \]\]/);
    assert.match(source,/check-pilot-nonce-recovery\.mjs/);
    assert.doesNotMatch(source,/cast publish|RAW=|raw=\$\(cat|raw=\$\(cast mktx/);
  }
});
