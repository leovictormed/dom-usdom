import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {assertProductionReleaseStageTransition,classifyProductionReleaseArtifactStage}
  from '../../sdk/production-release-stages.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const hash=byte=>`0x${byte.repeat(64)}`;
const state=(reserve=[null,null],registry=[null,null])=>({
  reserveRuntimeCodeHash:reserve[0],reserveInitcodeHash:reserve[1],
  checkpointRegistryRuntimeCodeHash:registry[0],checkpointRegistryInitcodeHash:registry[1],
});
const bootstrap=state();
const registry=state([null,null],[hash('1'),hash('2')]);
const final=state([hash('3'),hash('4')],[hash('1'),hash('2')]);

test('artifact states are acyclic and permit only adjacent monotonic transitions',()=>{
  assert.equal(classifyProductionReleaseArtifactStage(bootstrap),'bootstrap');
  assert.equal(classifyProductionReleaseArtifactStage(registry),'registry');
  assert.equal(classifyProductionReleaseArtifactStage(final),'final');
  assert.deepEqual(assertProductionReleaseStageTransition(bootstrap,registry),
    {before:'bootstrap',after:'registry'});
  assert.deepEqual(assertProductionReleaseStageTransition(registry,final),
    {before:'registry',after:'final'});
  assert.throws(()=>assertProductionReleaseStageTransition(bootstrap,final),/invalid/);
  assert.throws(()=>assertProductionReleaseStageTransition(final,registry),/invalid/);
});

test('partial hash pairs and impossible reserve-before-registry state fail closed',()=>{
  for(const changed of [
    state([hash('1'),null],[null,null]),state([null,null],[hash('1'),null]),
    state([hash('1'),hash('2')],[null,null]),state([null,hash('2')],[hash('3'),hash('4')]),
    state([null,null],[hash('0'),hash('2')]),
  ]) assert.throws(()=>classifyProductionReleaseArtifactStage(changed),/partial or non-monotonic/);
});

test('generated phase resumes at complete boundaries and validates before advancing',()=>{
  const source=readFileSync(path.join(root,'scripts/generate-closed-mainnet-phase-command.sh'),'utf8');
  const start=source.indexOf('artifact_stage=$(jq -er');
  const registryPins=source.indexOf('materialize:production-release-core -- registry-pins',start);
  const registryCompile=source.indexOf('forge build --offline contracts/DOMCheckpointRegistry.sol',start);
  const reservePins=source.indexOf('materialize:production-release-core -- reserve-pins',start);
  const registryCheck=source.indexOf('check-production-release-staged-state.mjs registry',start);
  const reserveCompile=source.indexOf('forge build --offline contracts/USDOMProofReserve.sol',start);
  const finalPins=source.indexOf('materialize:production-release-core -- final',start);
  const finalCheck=source.indexOf('check-production-release-staged-state.mjs final',start);
  assert.ok(start>=0&&registryPins>start&&registryCompile>registryPins&&reservePins>registryCompile
    &&registryCheck>reservePins&&reserveCompile>registryCheck&&finalPins>reserveCompile
    &&finalCheck>finalPins);
  assert.match(source,/if test "\$artifact_stage" = bootstrap;/);
  assert.match(source,/if test "\$artifact_stage" != final;/);
});

test('staged validator binds current sources and artifacts and rechecks every input',()=>{
  const source=readFileSync(path.join(root,'scripts/check-production-release-staged-state.mjs'),'utf8');
  for(const marker of ['materializeProductionSolidityPins','deriveCheckpointRegistryArtifactBinding',
    'deriveReserveArtifactBinding','checkpoint registry source pins differ','reserve source pins differ',
    'staged release input changed']) assert.ok(source.includes(marker),marker);
});

test('release-core preparer forbids skipping the registry artifact boundary',()=>{
  const source=readFileSync(path.join(root,'scripts/prepare-production-release-core-materialization.mjs'),'utf8');
  assert.match(source,/inputStage!=='registry'&&inputStage!=='final'/);
  assert.match(source,/assertProductionReleaseStageTransition\(releaseConfig,result\)/);
});
