import assert from 'node:assert/strict';
import {chmod,mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const checker=new URL('../../scripts/check-release-authorization-signing-request.mjs',
  import.meta.url);

test('release authorization checker rejects ambiguous request bytes',async t=>{
  const temporary=await mkdtemp(path.join(os.tmpdir(),'usdom-release-auth-json-'));
  t.after(()=>rm(temporary,{recursive:true,force:true}));
  await chmod(temporary,0o700);
  const files=['request.json','bundle.json','release.json','evidence.json']
    .map(name=>path.join(temporary,name));
  for(const file of files.slice(1)) await writeFile(file,'{}\n',{mode:0o600});
  for(const bytes of [
    Buffer.from('{"schema":"a","\\u0073chema":"b"}\n'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) {
    await writeFile(files[0],bytes,{mode:0o600}); await chmod(files[0],0o600);
    const result=spawnSync(process.execPath,[checker.pathname,...files],{encoding:'utf8'});
    assert.notEqual(result.status,0);
    assert.equal(JSON.parse(result.stderr).code,'RELEASE_OPERATION_REJECTED');
  }
});

test('release authorization checker uses byte-strict JSON for every input',async()=>{
  const source=await readFile(checker,'utf8');
  assert.match(source,/parseStrictJsonBytes\(bytes/);
  assert.doesNotMatch(source,/bytes\.toString\(['"]utf8['"]\)/);
  assert.match(source,/bytes\.map\(\(value,index\)=>\s*parse\(value,labels\[index\]\)\)/);
});
