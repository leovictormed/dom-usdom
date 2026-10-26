import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {checkpointVerifierConfigHash} from '../../sdk/checkpoint-verifier-config.mjs';
import {buildCheckpointVerifierReproducibleBuildReport,
  serializeCheckpointVerifierReproducibleBuildReport,
  validateCheckpointVerifierReproducibleBuildReport}
  from '../../sdk/checkpoint-verifier-reproducible-build-report.mjs';
import {parseStrictJsonBytes} from '../../sdk/strict-json.mjs';
import {checkpointVerifierConfigFixture} from './checkpoint-verifier-config.test.mjs';

const s=character=>character.repeat(64);
const h=character=>`0x${character.repeat(64)}`;
function fixture() {
  const verifierConfig=checkpointVerifierConfigFixture();
  const computed=checkpointVerifierConfigHash(verifierConfig);
  const releaseEvidence={schema:1,releaseId:'release-1',sourceCommit:'a'.repeat(40),
    sourceTag:'usdom-v1.0.0',checkpointVerifierArtifact:{
      path:'out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json',sha256:s('b')},
    checkpointVerifierConfigManifest:{path:'evidence/checkpoint-verifier-config.json',
      sha256:computed.manifestSha256.slice(2)}};
  const releaseConfig={ethereumChainId:'1',
    checkpointVerifier:'0x0000000000000000000000000000000000000020',
    checkpointVerifierCodeHash:h('c'),checkpointVerifierInitcodeHash:h('d'),
    checkpointVerifierConfigHash:computed.verifierConfigHash};
  const observed=buildId=>({buildId,compilerExecutableSha256:s('d'),compilerVersion:'0.8.37+commit.12345678',
    artifactSha256:s('b'),sourceSetSha256:s('e'),runtimeCodeHash:h('c'),initcodeHash:h('d')});
  return {releaseEvidence,releaseConfig,verifierConfig,
    observations:[observed('isolated-build-a'),observed('isolated-build-b')]};
}

test('requires two identical isolated checkpoint-verifier builds bound to config and release',()=>{
  const context=fixture();
  const report=buildCheckpointVerifierReproducibleBuildReport(context);
  assert.equal(report.status,'reproduced');
  assert.equal(report.checkpointVerifier,context.releaseConfig.checkpointVerifier);
  assert.equal(report.verifierConfigHash,context.releaseConfig.checkpointVerifierConfigHash);
  assert.deepEqual(validateCheckpointVerifierReproducibleBuildReport(report,context),report);
  assert(serializeCheckpointVerifierReproducibleBuildReport(report).equals(
    serializeCheckpointVerifierReproducibleBuildReport(
      buildCheckpointVerifierReproducibleBuildReport(context))));
});

test('rejects release, artifact and configuration drift',()=>{
  for(const mutate of [
    value=>{value.releaseConfig.ethereumChainId='31337';},
    value=>{value.releaseConfig.checkpointVerifierCodeHash=h('f');},
    value=>{value.releaseConfig.checkpointVerifierInitcodeHash=h('f');},
    value=>{value.releaseConfig.checkpointVerifierConfigHash=h('f');},
    value=>{value.releaseEvidence.checkpointVerifierArtifact.sha256=s('f');},
    value=>{value.releaseEvidence.checkpointVerifierConfigManifest.sha256=s('f');},
    value=>{value.verifierConfig.checkpointGuestImageId=h('f');},
    value=>{value.verifierConfig.riscZeroVerifierCodeHash=h('f');},
    value=>{value.verifierConfig.riscZeroVerifierSelector='0xffffffff';},
    value=>{value.verifierConfig.journalSchemaHash=h('f');},
  ]) {
    const value=fixture(); mutate(value);
    assert.throws(()=>buildCheckpointVerifierReproducibleBuildReport(value));
  }
});

test('rejects non-reproducible, failed-identity or non-isolated observations',()=>{
  for(const mutate of [
    value=>{value.observations[1].artifactSha256=s('f');},
    value=>{value.observations[1].sourceSetSha256=s('f');},
    value=>{value.observations[1].runtimeCodeHash=h('f');},
    value=>{value.observations[1].initcodeHash=h('f');},
    value=>{value.observations[1].compilerVersion='0.8.36+commit.12345678';},
    value=>{value.observations[1].buildId='isolated-build-a';},
    value=>{value.observations.pop();},
  ]) {
    const value=fixture(); mutate(value);
    assert.throws(()=>buildCheckpointVerifierReproducibleBuildReport(value));
  }
});

test('rejects a forged report',()=>{
  const context=fixture();
  const report=structuredClone(buildCheckpointVerifierReproducibleBuildReport(context));
  report.observations[1].sourceSetSha256=s('f');
  assert.throws(()=>validateCheckpointVerifierReproducibleBuildReport(report,context));
});

test('preparer performs isolated builds and derives both hashes from sources without observations',async()=>{
  const [prepare,writer]=await Promise.all([
    readFile(new URL('../../scripts/prepare-checkpoint-verifier-reproducible-build-report.mjs',
      import.meta.url),'utf8'),
    readFile(new URL('../../scripts/write-checkpoint-verifier-reproducible-build-report.sh',
      import.meta.url),'utf8'),
  ]);
  assert.match(prepare,/isolatedBuild\('isolated-build-a'/);
  assert.match(prepare,/isolatedBuild\('isolated-build-b'/);
  assert.match(prepare,/deriveCheckpointVerifierArtifactBinding\(\{artifact,verifierConfig,sourceContents,/);
  assert.match(prepare,/expectedConfigHash:releaseConfig\.checkpointVerifierConfigHash/);
  assert.match(prepare,/sourceContents\[source\]=await readDirectProjectFile/);
  assert.equal((prepare.match(/parseStrictJsonBytes\(/g)??[]).length,4);
  assert.doesNotMatch(prepare,/\.toString\(['"]utf8['"]\)/);
  assert.match(prepare,/artifactAfter\.equals\(canonicalArtifact\)/);
  assert.match(prepare,/configAfter\.equals\(verifierConfigBytes\)/);
  assert.match(prepare,/assertArtifactSourcesUnchanged\(root,sourceSnapshot\)/);
  assert.match(prepare,/assertExecutableUnchanged\(forge\)/);
  assert.doesNotMatch(prepare,/reproducible-build-observation/);
  assert.match(writer,/checkpointVerifierReproducibleBuildReport/);
  assert.match(writer,/install-private-file-immutable-stdin/);
});

test('checkpoint verifier build JSON rejects duplicate escaped keys and invalid UTF-8',()=>{
  for(const bytes of [
    Buffer.from('{"metadata":{},"\\u006detadata":{}}\n'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) assert.throws(()=>parseStrictJsonBytes(bytes,{label:'checkpoint verifier artifact',
    maxBytes:64*1024*1024,maxDepth:128}),/duplicate (?:object )?key|invalid UTF-8/);
});
