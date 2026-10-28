import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {materializeProductionSolidityPins,verifyProductionVerifierBindings}
  from '../sdk/production-solidity-pins.mjs';
import {deriveCheckpointVerifierArtifactBinding,deriveFinalizedBurnVerifierArtifactBinding}
  from '../sdk/compiled-runtime.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {checkpointVerifierConfigHash} from '../sdk/checkpoint-verifier-config.mjs';
import {finalizedBurnVerifierConfigHash} from '../sdk/verifier-config.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const releasePath='config/proof-reserve.unconfigured.json';
const reservePath='contracts/USDOMProofReserve.sol';
const registryPath='contracts/DOMCheckpointRegistry.sol';

async function json(relative) {
  const bytes=await readDirectProjectFile(root,relative);
  return {bytes,value:parseStrictJson(bytes.toString('utf8'),{label:relative,maxBytes:16*1024*1024,maxDepth:64})};
}
async function build(relative) {
  const parsed=await json(relative),sourceContents=Object.create(null);
  for(const source of Object.keys(parsed.value?.metadata?.sources??{})) {
    const absolute=path.resolve(root,source);
    if(absolute!==root&&!absolute.startsWith(root+path.sep)) throw new Error('artifact source escapes project root');
    sourceContents[source]=await readDirectProjectFile(root,source);
  }
  return {artifact:parsed.value,artifactBytes:parsed.bytes,sourceContents};
}

try {
  const component=process.argv[2]??'both';
  if(process.argv.length>3||!['reserve','checkpointRegistry','both'].includes(component)) {
    throw new Error('usage: prepare-production-solidity-pins.mjs [reserve|checkpointRegistry|both]');
  }
  const [releaseBytes,reserveBytes,registryBytes,finalizedConfig,checkpointConfig,
    finalizedBuild,checkpointBuild]=await Promise.all([
    readDirectProjectFile(root,releasePath),readDirectProjectFile(root,reservePath),
    readDirectProjectFile(root,registryPath),
    json('config/finalized-burn-verifier.unconfigured.json'),
    json('config/checkpoint-verifier.unconfigured.json'),
    build('out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json'),
    build('out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json'),
  ]);
  const releaseConfig=parseStrictJson(releaseBytes.toString('utf8'),{label:releasePath});
  const finalizedConfiguration=finalizedBurnVerifierConfigHash(finalizedConfig.value);
  const checkpointConfiguration=checkpointVerifierConfigHash(checkpointConfig.value);
  const finalizedBinding=deriveFinalizedBurnVerifierArtifactBinding({...finalizedBuild,
    verifierConfig:finalizedConfig.value,expectedConfigHash:finalizedConfiguration.verifierConfigHash});
  const checkpointBinding=deriveCheckpointVerifierArtifactBinding({...checkpointBuild,
    verifierConfig:checkpointConfig.value,expectedConfigHash:checkpointConfiguration.verifierConfigHash});
  verifyProductionVerifierBindings({releaseConfig,finalizedBurnVerifier:{
    runtimeCodeHash:finalizedBinding.runtimeCodeHash,initcodeHash:finalizedBinding.initcodeHash,
    configHash:finalizedBinding.verifierConfigHash},checkpointVerifier:{
    runtimeCodeHash:checkpointBinding.runtimeCodeHash,initcodeHash:checkpointBinding.initcodeHash,
    configHash:checkpointBinding.verifierConfigHash}});
  const result=materializeProductionSolidityPins({releaseConfig,
    reserveSource:reserveBytes.toString('utf8'),checkpointRegistrySource:registryBytes.toString('utf8'),component});
  const stableInputs=[[releasePath,releaseBytes],[reservePath,reserveBytes],[registryPath,registryBytes],
    ['config/finalized-burn-verifier.unconfigured.json',finalizedConfig.bytes],
    ['config/checkpoint-verifier.unconfigured.json',checkpointConfig.bytes],
    ['out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json',
      finalizedBuild.artifactBytes],
    ['out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json',checkpointBuild.artifactBytes],
    ...Object.entries(finalizedBuild.sourceContents),...Object.entries(checkpointBuild.sourceContents)];
  for(const [relative,previous] of stableInputs) {
    const current=await readDirectProjectFile(root,relative,{minimum:previous.length,maximum:previous.length});
    if(!current.equals(previous)) throw new Error(`pin input changed during preparation: ${relative}`);
  }
  const sha256=value=>createHash('sha256').update(value).digest('hex');
  process.stdout.write(JSON.stringify({...result,inputSha256:{
    releaseConfig:sha256(releaseBytes),reserveSource:sha256(reserveBytes),
    checkpointRegistrySource:sha256(registryBytes),
    finalizedBurnVerifierConfig:sha256(finalizedConfig.bytes),
    checkpointVerifierConfig:sha256(checkpointConfig.bytes),
    finalizedBurnVerifierArtifact:sha256(finalizedBuild.artifactBytes),
    checkpointVerifierArtifact:sha256(checkpointBuild.artifactBytes),
  }})+'\n');
} catch(error) {
  writeReleaseFailure('prepare-production-solidity-pins',error);
  process.exitCode=1;
}
