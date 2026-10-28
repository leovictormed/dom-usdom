#!/usr/bin/env node
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {deriveCheckpointRegistryArtifactBinding} from '../sdk/compiled-runtime.mjs';
import {buildCheckpointRegistryArtifactPins,checkpointRegistryPinsSha256} from '../sdk/checkpoint-registry-artifact-pins.mjs';
import {writePrivateFileDurableNewOrEqual} from '../sdk/durable-private-file.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
if(process.argv.length!==2) throw new Error('fixed checkpoint registry pin materializer accepts no arguments');
const artifactRelative='out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json';
const releaseRelative='config/proof-reserve.unconfigured.json';
const [artifactBytes,releaseBytes]=await Promise.all([
  readDirectProjectFile(root,artifactRelative,{minimum:2,maximum:16*1024*1024,label:'checkpoint registry artifact'}),
  readDirectProjectFile(root,releaseRelative,{minimum:2,maximum:4*1024*1024,label:'release config'}),
]);
const artifact=parseStrictJsonBytes(artifactBytes,{label:'checkpoint registry artifact',maxBytes:16*1024*1024,maxDepth:64});
const releaseConfig=parseStrictJsonBytes(releaseBytes,{label:'release config',maxBytes:4*1024*1024,maxDepth:64});
const sourceContents={};
const sourceBytes=new Map();
for(const relative of Object.keys(artifact.metadata.sources).sort()) {
  const bytes=await readDirectProjectFile(root,relative,{minimum:1,maximum:4*1024*1024,label:`checkpoint registry source ${relative}`});
  sourceBytes.set(relative,bytes); sourceContents[relative]=bytes.toString('utf8');
}
const binding=deriveCheckpointRegistryArtifactBinding({artifact,releaseConfig,sourceContents});
const report=buildCheckpointRegistryArtifactPins({binding,artifactSha256:checkpointRegistryPinsSha256(artifactBytes),
  releaseConfigSha256:checkpointRegistryPinsSha256(releaseBytes)});
const target=process.env.USDOM_CHECKPOINT_REGISTRY_ARTIFACT_PINS;
if(typeof target!=='string'||!path.isAbsolute(target)) throw new Error('USDOM_CHECKPOINT_REGISTRY_ARTIFACT_PINS must be an absolute private path');
const bytes=Buffer.from(JSON.stringify(report)+'\n');
await writePrivateFileDurableNewOrEqual(target,bytes,{maximum:64*1024});
const [currentArtifact,currentRelease]=await Promise.all([
  readDirectProjectFile(root,artifactRelative,{minimum:2,maximum:16*1024*1024,label:'checkpoint registry artifact'}),
  readDirectProjectFile(root,releaseRelative,{minimum:2,maximum:4*1024*1024,label:'release config'}),
]);
if(!currentArtifact.equals(artifactBytes)||!currentRelease.equals(releaseBytes)) {
  throw new Error('checkpoint registry artifact or release config changed during materialization');
}
for(const [relative,snapshot] of sourceBytes) {
  const current=await readDirectProjectFile(root,relative,{minimum:1,maximum:4*1024*1024,label:`checkpoint registry source ${relative}`});
  if(!current.equals(snapshot)) throw new Error(`checkpoint registry source changed during materialization: ${relative}`);
}
process.stdout.write(`${JSON.stringify({schema:report.schema,path:target,sha256:checkpointRegistryPinsSha256(bytes)})}\n`);
