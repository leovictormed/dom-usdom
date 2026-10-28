#!/usr/bin/env node
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {deriveCheckpointRegistryArtifactBinding,deriveReserveArtifactBinding}
  from '../sdk/compiled-runtime.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {materializeProductionSolidityPins} from '../sdk/production-solidity-pins.mjs';
import {classifyProductionReleaseArtifactStage} from '../sdk/production-release-stages.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const requested=process.argv[2];
if(process.argv.length!==3||!['registry','final'].includes(requested)) {
  throw new Error('usage: check-production-release-staged-state.mjs registry|final');
}
const snapshots=new Map();
async function stable(relative) {
  const bytes=await readDirectProjectFile(root,relative,{minimum:1,maximum:16*1024*1024});
  const previous=snapshots.get(relative);
  if(previous&&!previous.equals(bytes)) throw new Error(`staged release input changed: ${relative}`);
  if(!previous) snapshots.set(relative,Buffer.from(bytes));
  return bytes;
}
async function build(relative) {
  const artifact=parseStrictJsonBytes(await stable(relative),{label:relative,maxBytes:16*1024*1024,maxDepth:64});
  const sourceContents=Object.create(null);
  for(const source of Object.keys(artifact?.metadata?.sources??{})) sourceContents[source]=await stable(source);
  return {artifact,sourceContents};
}
const releaseBytes=await stable('config/proof-reserve.unconfigured.json');
const release=parseStrictJsonBytes(releaseBytes,{label:'production release',maxBytes:8*1024*1024,maxDepth:64});
const stage=classifyProductionReleaseArtifactStage(release);
if(stage!==requested) throw new Error(`expected ${requested} artifact stage, found ${stage}`);
const registrySource=await stable('contracts/DOMCheckpointRegistry.sol');
const registryBuild=await build('out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json');
const inertRelease={...release,productionReady:false,realFundsAuthorized:false};
const pinnedRegistry=materializeProductionSolidityPins({releaseConfig:inertRelease,
  reserveSource:'',checkpointRegistrySource:registrySource.toString('utf8'),component:'checkpointRegistry'});
if(pinnedRegistry.checkpointRegistrySource!==registrySource.toString('utf8')) {
  throw new Error('checkpoint registry source pins differ from the staged release');
}
const registry=deriveCheckpointRegistryArtifactBinding({...registryBuild,releaseConfig:release});
for(const [actual,expected,label] of [
  [registry.runtimeCodeHash,release.checkpointRegistryRuntimeCodeHash,'registry runtime'],
  [registry.initcodeHash,release.checkpointRegistryInitcodeHash,'registry initcode'],
  [registry.checkpointRegistryConfigHash,release.checkpointRegistryConfigHash,'registry config'],
]) if(actual.toLowerCase()!==expected.toLowerCase()) throw new Error(`${label} differs from the staged release`);
if(stage==='final') {
  const reserveSource=await stable('contracts/USDOMProofReserve.sol');
  const reserveBuild=await build('out/USDOMProofReserve.sol/USDOMProofReserve.json');
  const pinnedReserve=materializeProductionSolidityPins({releaseConfig:inertRelease,
    reserveSource:reserveSource.toString('utf8'),checkpointRegistrySource:'',component:'reserve'});
  if(pinnedReserve.reserveSource!==reserveSource.toString('utf8')) {
    throw new Error('reserve source pins differ from the final release');
  }
  const reserve=deriveReserveArtifactBinding({...reserveBuild,releaseConfig:release});
  for(const [actual,expected,label] of [
    [reserve.runtimeCodeHash,release.reserveRuntimeCodeHash,'reserve runtime'],
    [reserve.initcodeHash,release.reserveInitcodeHash,'reserve initcode'],
    [reserve.reserveConfigHash,release.reserveConfigHash,'reserve config'],
  ]) if(actual.toLowerCase()!==expected.toLowerCase()) throw new Error(`${label} differs from the final release`);
}
for(const [relative,previous] of snapshots) {
  const current=await readDirectProjectFile(root,relative,{minimum:previous.length,maximum:previous.length});
  if(!current.equals(previous)) throw new Error(`staged release input changed: ${relative}`);
}
process.stdout.write(`${JSON.stringify({ok:true,stage})}\n`);
