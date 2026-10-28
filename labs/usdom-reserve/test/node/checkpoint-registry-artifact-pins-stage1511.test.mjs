import test from 'node:test';
import assert from 'node:assert/strict';
import {buildCheckpointRegistryArtifactPins,validateCheckpointRegistryArtifactPins} from '../../sdk/checkpoint-registry-artifact-pins.mjs';
import {readFile} from 'node:fs/promises';

const h=n=>'0x'+n.repeat(64),s=n=>n.repeat(64);
const binding={runtimeCodeHash:h('1'),runtimeSize:100,initcodeHash:h('2'),initcodeSize:200,
  checkpointRegistryConfigHash:h('3'),compilerVersion:'0.8.37+commit.f401782d',sourceCount:4};
const artifactBytes=Buffer.from('artifact-a'),releaseConfigBytes=Buffer.from('release-a');
import {createHash} from 'node:crypto';
const sha=value=>createHash('sha256').update(value).digest('hex');
const report=buildCheckpointRegistryArtifactPins({binding,artifactSha256:sha(artifactBytes),releaseConfigSha256:sha(releaseConfigBytes)});

test('registry pins bind current artifact, runtime, initcode and configuration',()=>{
  const authority={binding,artifactBytes,releaseConfigBytes};
  assert.equal(validateCheckpointRegistryArtifactPins(report,authority),report);
  for(const field of ['runtimeCodeHash','initcodeHash','checkpointRegistryConfigHash','artifactSha256','releaseConfigSha256']) {
    const changed={...report,[field]:field.endsWith('Sha256')?s('c'):h('4')};
    assert.throws(()=>validateCheckpointRegistryArtifactPins(changed,authority));
  }
  assert.throws(()=>validateCheckpointRegistryArtifactPins({...report,artifactSha256:sha(Buffer.from('artifact-b'))},authority));
});

test('checkpoint evidence phase materializes create-once registry pins before proofs',async()=>{
  const generator=await readFile(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
  const producer=generator.indexOf('npm run --silent materialize:checkpoint-registry-artifact-pins');
  const proofs=generator.indexOf('npm run --silent export:canonical-checkpoint-source-set',producer);
  assert(producer>0&&proofs>producer);
  const writer=await readFile(new URL('../../scripts/materialize-checkpoint-registry-artifact-pins.mjs',import.meta.url),'utf8');
  assert.match(writer,/deriveCheckpointRegistryArtifactBinding/);
  assert.match(writer,/writePrivateFileDurableNewOrEqual/);
  assert.match(writer,/artifact or release config changed during materialization/);
  assert.match(writer,/source changed during materialization/);
  assert.match(writer,/readDirectProjectFile/);
  assert.match(writer,/maximum:16\*1024\*1024/);
  const readiness=await readFile(new URL('../../scripts/check-mainnet-readiness.mjs',import.meta.url),'utf8');
  assert.match(readiness,/USDOM_CHECKPOINT_REGISTRY_ARTIFACT_PINS/);
  assert.match(readiness,/checkpointRegistryArtifactPinsReport/);
  assert.match(readiness,/binding:compiledCheckpointRegistryBinding/);
});
