import assert from 'node:assert/strict';
import {chmod,mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {captureMainnetPreflightInputs} from '../../sdk/mainnet-preflight-input-snapshot.mjs';
import {parseStrictJsonBytes} from '../../sdk/strict-json.mjs';

const source=await readFile(new URL(
  '../../scripts/materialize-mainnet-preflight-attestation.mjs',import.meta.url),'utf8');

test('preflight materializer uses one private snapshot through ordered updates',()=>{
  assert.match(source,/captureMainnetPreflightInputs/);
  assert.equal((source.match(/snapshot\.assertOriginsUnchanged\(\)/g)??[]).length,3);
  const evidenceWrite=source.indexOf('writeFileDurable(path.join(root,evidencePath)');
  const requirementsWrite=source.indexOf('writeFileDurable(path.join(root,requirementsPath)');
  assert.ok(evidenceWrite>0&&requirementsWrite>evidenceWrite);
  assert.ok(source.slice(evidenceWrite,requirementsWrite).includes('snapshot.assertOriginsUnchanged()'));
  assert.match(source,/finally \{ await snapshot\.cleanup\(\); \}/);
});

test('preflight materializer uses byte-strict JSON for all five snapshot inputs',()=>{
  assert.match(source,/parseStrictJsonBytes\(bytes/);
  assert.doesNotMatch(source,/bytes\.toString\(['"]utf8['"]\)/);
  for(const input of ['report','release','evidence','requirements','riscZero']) {
    assert.match(source,new RegExp(`json\\(snapshot\\.${input},`));
  }
});

test('preflight JSON boundary rejects duplicate escaped keys and invalid UTF-8',()=>{
  for(const bytes of [
    Buffer.from('{"schema":"a","\\u0073chema":"b"}\n'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) assert.throws(()=>parseStrictJsonBytes(bytes,{label:'preflight',maxBytes:16*1024*1024,
    maxDepth:96}),/duplicate (?:object )?key|invalid UTF-8/);
});

test('preflight input snapshot rejects concurrent source mutation',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'usdom-preflight-snapshot-test-'));
  await chmod(root,0o700);
  const names={report:'report.json',release:'release.json',evidence:'evidence.json',
    requirements:'requirements.json',riscZero:'risc-zero.json'};
  const paths=Object.fromEntries(Object.entries(names).map(([key,name])=>[key,path.join(root,name)]));
  for(const [key,target] of Object.entries(paths)) {
    await writeFile(target,`{"source":"${key}"}\n`,{mode:key==='report'?0o600:0o644});
    await chmod(target,key==='report'?0o600:0o644);
  }
  let snapshot;
  try {
    snapshot=await captureMainnetPreflightInputs(paths,{
      beforeOriginRecheck:()=>writeFile(paths.release,'{"source":"changed"}\n',{mode:0o644}),
    });
    assert.equal(snapshot.release.toString(),'{"source":"release"}\n');
    await assert.rejects(()=>snapshot.assertOriginsUnchanged(),
      /mainnet preflight inputs changed during materialization/);
  } finally { await snapshot?.cleanup(); await rm(root,{recursive:true,force:true}); }
});

test('preflight input snapshot rejects an incomplete catalog',async()=>{
  await assert.rejects(()=>captureMainnetPreflightInputs({}),/fixed absolute catalog/);
});
