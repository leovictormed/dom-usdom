import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const checker=fileURLToPath(new URL('../../scripts/check-closed-mainnet-phase-artifacts.mjs',import.meta.url));
const generator=readFileSync(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
const checkerSource=readFileSync(checker,'utf8');
test('generated pilot phases require semantic completion, not inventory success',()=>{
  assert.match(generator,/check-closed-mainnet-phase-artifacts\.mjs require-deposit-complete/);
  assert.match(generator,/check-closed-mainnet-phase-artifacts\.mjs require-pilot-complete/);
});
test('financial baseline objects and hashes come from one exact byte snapshot',()=>{
  assert.match(checkerSource,/function evidenceSnapshot\(/);
  assert.match(checkerSource,/baseline:baselineSnapshot\.value/);
  assert.match(checkerSource,/baselineSha256:baselineSnapshot\.sha256/);
  assert.equal((checkerSource.match(/baselineSha256:baselineSnapshot\.sha256/g)??[]).length,2);
  assert.doesNotMatch(checkerSource,/baselineSha256:sha\(fs\.readFileSync/);
  assert.doesNotMatch(checkerSource,/baselineBytes=fs\.readFileSync\(baselinePath\)/);
});
test('release and verifier values and hashes use cached exact byte snapshots',()=>{
  assert.match(checkerSource,/function localJsonSnapshot\(/);
  assert.match(checkerSource,/const existing=localSnapshots\.get\(target\)/);
  assert.match(checkerSource,/localSnapshots\.set\(target,snapshot\)/);
  assert.equal((checkerSource.match(/releaseSnapshot\.value/g)??[]).length,7);
  assert.equal((checkerSource.match(/releaseSnapshot\.sha256/g)??[]).length,5);
  assert.match(checkerSource,/verifierManifestSha256:verifierSnapshot\.sha256/);
  assert.doesNotMatch(checkerSource,/releaseBytes=fs\.readFileSync/);
  assert.doesNotMatch(checkerSource,/sha\(releaseBytes\)|sha\(verifierBytes\)/);
});
test('DAG checker rejects unknown completion modes and incomplete local pilot',()=>{
  const node='/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node';
  const unknown=spawnSync(node,[checker,'accept-anything'],{encoding:'utf8'});
  assert.equal(unknown.status,64); assert.match(unknown.stderr,/usage:/);
  for(const mode of ['require-deposit-complete','require-pilot-complete']) {
    const result=spawnSync(node,[checker,mode],{encoding:'utf8'});
    assert.equal(result.status,1);
    assert.deepEqual(JSON.parse(result.stderr),{
      schema:'usdom-pilot-safe-diagnostic/v1',ok:false,
      operation:'closed-mainnet-phase-check',code:'PILOT_OPERATION_REJECTED',
    });
    assert.doesNotMatch(result.stderr,/not complete|pilot phases|Error|stack|cause/i);
  }
});
