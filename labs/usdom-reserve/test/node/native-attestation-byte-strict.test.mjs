import assert from 'node:assert/strict';
import {chmod,mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const checker=new URL('../../scripts/check-native-release-attestation-signing-request.mjs',
  import.meta.url);
const preparer=new URL('../../scripts/prepare-native-release-attestation-requests.mjs',
  import.meta.url);

test('native attestation checker rejects ambiguous request bytes before cargo',async t=>{
  const temporary=await mkdtemp(path.join(os.tmpdir(),'usdom-native-attestation-json-'));
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
    const result=spawnSync(process.execPath,[checker.pathname,...files],{
      encoding:'utf8',env:{...process.env,USDOM_CARGO:'/must-not-run'},
    });
    assert.notEqual(result.status,0);
    assert.equal(JSON.parse(result.stderr).code,'RELEASE_OPERATION_REJECTED');
    assert.doesNotMatch(result.stderr,/must-not-run|ENOENT/);
  }
});

test('native attestation checker uses byte-strict JSON for snapshots and wallet evidence',async()=>{
  const source=await readFile(checker,'utf8');
  assert.match(source,/parseStrictJsonBytes\(bytes/);
  assert.doesNotMatch(source,/bytes\.toString\(['"]utf8['"]\)/);
  assert.match(source,/snapshots\.map\(\(bytes,index\)=>\s*parse\(bytes,labels\[index\]\)\)/);
  assert.match(source,/walletBytes\.map\(\(bytes,index\)=>parse\(bytes/);
});

test('native attestation checker strictly frames authoritative child output',async()=>{
  const source=await readFile(checker,'utf8');
  assert.match(source,/runPinnedExecutable\(cargo,/);
  assert.match(source,/maxBuffer:4\*1024\*1024,timeout:10\*60\*1000/);
  assert.match(source,/checked\.stderr\.length!==0/);
  assert.match(source,/new TextDecoder\('utf-8',\{fatal:true\}\)\.decode\(output\)/);
  assert.match(source,/!text\.endsWith\('\\n'\)/);
  assert.match(source,/text\.endsWith\('\\n\\n'\)/);
  assert.match(source,/text\.includes\('\\r'\)/);
  assert.doesNotMatch(source,/output\.trim\(\)\.split/);
  assert.match(source,/const cargo=await snapshotExecutable\('cargo'\)/);
  assert.doesNotMatch(source,/execFile\(|node:child_process|promisify/);
  assert.doesNotMatch(source,/process\.env\.USDOM_CARGO/);
});

test('native request preparer pins and strictly frames its authoritative child',async()=>{
  const source=await readFile(preparer,'utf8');
  assert.match(source,/parseStrictJsonBytes\(bytes,/);
  assert.doesNotMatch(source,/\.toString\(['"]utf8['"]\)|parseStrictJson\(/);
  assert.match(source,/const cargo=await snapshotExecutable\('cargo'\)/);
  assert.match(source,/runPinnedExecutable\(cargo,/);
  assert.match(source,/maxBuffer:4\*1024\*1024,timeout:10\*60\*1000/);
  assert.doesNotMatch(source,/execFile\(|node:child_process|promisify/);
  assert.match(source,/checked\.stderr\.length!==0/);
  assert.match(source,/new TextDecoder\('utf-8',\{fatal:true\}\)\.decode\(output\)/);
  assert.match(source,/text\.endsWith\('\\n\\n'\)|text\.includes\('\\r'\)/);
  assert.doesNotMatch(source,/process\.env\.USDOM_CARGO|output\.trim\(\)\.split/);
});
