import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readFile} from 'node:fs/promises';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {deriveCheckpointRegistryArtifactBinding} from '../sdk/compiled-runtime.mjs';
import {buildCheckpointRegistryArtifactPins,checkpointRegistryPinsSha256} from '../sdk/checkpoint-registry-artifact-pins.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
if(process.argv.length!==2) throw new Error('fixed checkpoint registry pin validator accepts no arguments');
const target=process.env.USDOM_CHECKPOINT_REGISTRY_ARTIFACT_PINS;
if(typeof target!=='string'||!path.isAbsolute(target)) throw new Error('USDOM_CHECKPOINT_REGISTRY_ARTIFACT_PINS must be an absolute private path');
const artifactPath=path.join(root,'out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json');
const releasePath=path.join(root,'config/proof-reserve.unconfigured.json');
const [artifactBytes,releaseBytes,publishedBytes]=await Promise.all([
  readFile(artifactPath),readFile(releasePath),readDirectFile(target,{minimum:2,maximum:64*1024,privateMode:true,label:'checkpoint registry artifact pins'}),
]);
const artifact=parseStrictJsonBytes(artifactBytes,{label:'checkpoint registry artifact',maxBytes:16*1024*1024,maxDepth:64});
const releaseConfig=parseStrictJsonBytes(releaseBytes,{label:'release config',maxBytes:4*1024*1024,maxDepth:64});
const sourceContents={};
for(const relative of Object.keys(artifact.metadata.sources).sort()) sourceContents[relative]=await readFile(path.join(root,relative),'utf8');
const binding=deriveCheckpointRegistryArtifactBinding({artifact,releaseConfig,sourceContents});
const expected=Buffer.from(JSON.stringify(buildCheckpointRegistryArtifactPins({binding,
  artifactSha256:checkpointRegistryPinsSha256(artifactBytes),releaseConfigSha256:checkpointRegistryPinsSha256(releaseBytes)}))+'\n');
if(!publishedBytes.equals(expected)) throw new Error('published checkpoint registry pins differ from independently rebuilt artifacts');
process.stdout.write(`${JSON.stringify({status:'verified',sha256:checkpointRegistryPinsSha256(expected)})}\n`);
