import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,readFile,rm,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {captureFinalizedBurnReleaseRun} from '../../sdk/release-run-snapshot.mjs';
import {captureCheckpointCapacityRun} from '../../sdk/checkpoint-run-snapshot.mjs';

async function fixture(files) {
  const root=await mkdtemp(path.join(os.tmpdir(),'usdom-stage968-'));
  const run=path.join(root,'run'); await mkdir(run,{mode:0o700});
  for(const [name,value] of Object.entries(files)) await writeFile(path.join(run,name),value,{mode:0o600});
  return {root,run};
}

for(const [label,capture,files] of [
  ['release',captureFinalizedBurnReleaseRun,{'run-status.json':'status\n','finalized-burn-e2e-report.json':'report\n'}],
  ['checkpoint',captureCheckpointCapacityRun,{'run-status.json':'status\n','capacity-report.json':'report\n'}],
]) test(`${label} snapshot cleanup erases buffers returned to its caller`,async()=>{
  const {root,run}=await fixture(files);
  try {
    const snapshot=await capture(run);
    assert.ok(snapshot.statusBytes.some(byte=>byte!==0));
    assert.ok(snapshot.reportBytes.some(byte=>byte!==0));
    await snapshot.assertOriginsUnchanged();
    await snapshot.cleanup();
    assert.ok(snapshot.statusBytes.every(byte=>byte===0));
    assert.ok(snapshot.reportBytes.every(byte=>byte===0));
  } finally { await rm(root,{recursive:true,force:true}); }
});

test('durable writer erases its owner-only readback capture',async()=>{
  const source=await readFile(new URL('../../sdk/durable-private-file.mjs',import.meta.url),'utf8');
  assert.match(source,/let directoryHandle,file,temporary,stored,temporaryCreated=false/);
  assert.match(source,/finally \{\n    stored\?\.fill\(0\);/);
});
