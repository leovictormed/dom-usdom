import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {
  RISC0_RECURSION_ARTIFACT_BYTES,RISC0_RECURSION_ARTIFACT_SHA256,
  requireRisc0RecursionArtifact,
} from '../../sdk/risc0-recursion-artifact.mjs';

const pinnedIdentity=Object.freeze({
  bytes:RISC0_RECURSION_ARTIFACT_BYTES,sha256:RISC0_RECURSION_ARTIFACT_SHA256,
});

test('recursion preflight binds the exact inspected artifact into a fresh environment',async()=>{
  const environment={HOME:'/home/operator',RECURSION_SRC_PATH:'/evidence/recursion_zkr.zip'};
  let inspected;
  const result=await requireRisc0RecursionArtifact({environment,home:'/home/operator',
    inspectArtifact:async target=>{ inspected=target; return pinnedIdentity; }});
  assert.equal(inspected,environment.RECURSION_SRC_PATH);
  assert.equal(result.path,environment.RECURSION_SRC_PATH);
  assert.deepEqual({bytes:result.bytes,sha256:result.sha256},pinnedIdentity);
  assert.equal(result.environment.RECURSION_SRC_PATH,result.path);
  assert.notEqual(result.environment,environment);
  assert.equal(Object.isFrozen(result.environment),true);
});

test('recursion preflight fails closed for missing, unsafe or corrupt artifacts',async()=>{
  const base={environment:{RECURSION_SRC_PATH:'/evidence/recursion_zkr.zip'},home:'/home/operator'};
  await assert.rejects(()=>requireRisc0RecursionArtifact({...base,inspectArtifact:async()=>{
    const error=new Error('missing'); error.code='ENOENT'; throw error;
  }}),/missing or unsafe direct/);
  for(const identity of [
    {...pinnedIdentity,bytes:RISC0_RECURSION_ARTIFACT_BYTES-1},
    {...pinnedIdentity,sha256:'00'.repeat(32)},
  ]) await assert.rejects(()=>requireRisc0RecursionArtifact({...base,
    inspectArtifact:async()=>identity}),/size or SHA-256 mismatch/);
  await assert.rejects(()=>requireRisc0RecursionArtifact({
    environment:{RECURSION_SRC_PATH:'relative.zip'},home:'/home/operator',
    inspectArtifact:async()=>pinnedIdentity,
  }),/canonical and absolute/);
});

test('all Node proof launchers preflight and propagate the recursion binding',async()=>{
  for(const name of [
    'run-checkpoint-capacity-e2e.mjs','run-finalized-burn-capacity-e2e.mjs',
    'run-finalized-burn-release-e2e.mjs',
  ]) {
    const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
    assert.match(source,/import \{requireRisc0RecursionArtifact\} from '\.\.\/sdk\/risc0-recursion-artifact\.mjs';/);
    assert.match(source,/await requireRisc0RecursionArtifact\(\{/);
    assert.match(source,/\.environment/);
    const preflight=source.indexOf('await requireRisc0RecursionArtifact({');
    const cargo=source.indexOf("await runCommand('cargo'",preflight);
    assert(preflight>=0 && cargo>preflight,`${name} must preflight before spawning Cargo`);
  }
});
