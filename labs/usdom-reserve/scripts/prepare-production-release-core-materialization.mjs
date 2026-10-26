import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {checkpointVerifierConfigHash} from '../sdk/checkpoint-verifier-config.mjs';
import {deriveCheckpointVerifierArtifactBinding,deriveFinalizedBurnVerifierArtifactBinding,
  deriveReserveArtifactBinding,deriveCheckpointRegistryArtifactBinding}
  from '../sdk/compiled-runtime.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {materializeProductionReleaseCore} from '../sdk/production-release-core.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {finalizedBurnVerifierConfigHash} from '../sdk/verifier-config.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const snapshots=new Map();
async function stable(relative) {
  const bytes=await readDirectProjectFile(root,relative);
  const previous=snapshots.get(relative);
  if(previous&&!previous.equals(bytes)) throw new Error(`release-core input changed: ${relative}`);
  if(!previous) snapshots.set(relative,Buffer.from(bytes));
  return bytes;
}
async function json(relative) {
  return parseStrictJson((await stable(relative)).toString('utf8'),{label:relative,maxBytes:8*1024*1024,maxDepth:48});
}
async function build(relative) {
  const artifact=await json(relative),sourceContents=Object.create(null);
  for(const source of Object.keys(artifact?.metadata?.sources??{})) {
    const absolute=path.resolve(root,source);
    if(absolute!==root&&!absolute.startsWith(root+path.sep)) throw new Error('artifact source escapes project root');
    sourceContents[source]=await stable(source);
  }
  return {artifact,sourceContents};
}
function equal(left,right,label) {
  if(String(left).toLowerCase()!==String(right).toLowerCase()) throw new Error(`${label} disagrees across sources`);
}

try {
  if(process.argv.length!==2) throw new Error('this fixed release-core materializer accepts no arguments');
  const [releaseConfig,nativeFacts,finalizedConfig,checkpointConfig,finalizedBuild,checkpointBuild,
    reserveBuild,registryBuild]
    =await Promise.all([
      json('config/proof-reserve.unconfigured.json'),json('config/native-release-facts.unconfigured.json'),
      json('config/finalized-burn-verifier.unconfigured.json'),json('config/checkpoint-verifier.unconfigured.json'),
      build('out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json'),
      build('out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json'),
      build('out/USDOMProofReserve.sol/USDOMProofReserve.json'),
      build('out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json'),
    ]);
  const finalized=finalizedBurnVerifierConfigHash(finalizedConfig);
  const checkpoint=checkpointVerifierConfigHash(checkpointConfig);
  for(const field of ['activationScheduleCommitment','domGenesisHash','domNetworkMagic','domChainId',
    'firstV4Height','activationEmptyStateRoot','consensusRulesHash','forkChoiceRulesHash','powRulesHash',
    'ethereumChainId','riscZeroVerifier','riscZeroVerifierCodeHash','riscZeroVerifierSelector',
    'verifyingKeySha256','trustedSetupTranscriptSha256']) equal(finalized[field],checkpoint[field],field);
  for(const [fact,field] of [
    ['activationScheduleCommitment','activationScheduleCommitment'],['checkpointDomNetworkMagic','domNetworkMagic'],
    ['checkpointDomChainId','domChainId'],['checkpointFirstV4Height','firstV4Height'],
    ['checkpointActivationEmptyStateRoot','activationEmptyStateRoot'],
    ['checkpointIntervalBlocks','checkpointInterval'],
    ['checkpointConfirmationDepthBlocks','confirmationDepth'],
    ['checkpointChallengePeriodSeconds','challengePeriod'],
  ]) equal(nativeFacts[fact],checkpoint[field],fact);
  const finalizedBinding=deriveFinalizedBurnVerifierArtifactBinding({...finalizedBuild,
    verifierConfig:finalizedConfig,expectedConfigHash:finalized.verifierConfigHash});
  const checkpointBinding=deriveCheckpointVerifierArtifactBinding({...checkpointBuild,
    verifierConfig:checkpointConfig,expectedConfigHash:checkpoint.verifierConfigHash});
  const verifierInputs={
    finalizedBurnVerifier:{runtimeCodeHash:finalizedBinding.runtimeCodeHash,
      initcodeHash:finalizedBinding.initcodeHash,configHash:finalizedBinding.verifierConfigHash},
    checkpointVerifier:{runtimeCodeHash:checkpointBinding.runtimeCodeHash,
      initcodeHash:checkpointBinding.initcodeHash,configHash:checkpointBinding.verifierConfigHash},
  };
  const pinsUnset=releaseConfig.reserveRuntimeCodeHash===null&&releaseConfig.reserveInitcodeHash===null;
  const registryPinsUnset=releaseConfig.checkpointRegistryRuntimeCodeHash===null
    &&releaseConfig.checkpointRegistryInitcodeHash===null;
  const core=pinsUnset&&registryPinsUnset
    ?materializeProductionReleaseCore({releaseConfig,nativeFacts,...verifierInputs,
      deferReserveArtifact:true,deferCheckpointRegistryArtifact:true})
    :releaseConfig;
  const reserveBinding=deriveReserveArtifactBinding({...reserveBuild,releaseConfig:core});
  const registryBinding=deriveCheckpointRegistryArtifactBinding({...registryBuild,releaseConfig:core});
  const result=materializeProductionReleaseCore({releaseConfig:core,nativeFacts,...verifierInputs,
    reserveArtifact:{runtimeCodeHash:reserveBinding.runtimeCodeHash,
      initcodeHash:reserveBinding.initcodeHash,configHash:reserveBinding.reserveConfigHash},
    checkpointRegistryArtifact:{runtimeCodeHash:registryBinding.runtimeCodeHash,
      initcodeHash:registryBinding.initcodeHash,configHash:registryBinding.checkpointRegistryConfigHash}});
  for(const [relative,previous] of snapshots) {
    const current=await readDirectProjectFile(root,relative,{minimum:previous.length,maximum:previous.length});
    if(!current.equals(previous)) throw new Error(`release-core input changed: ${relative}`);
  }
  process.stdout.write(JSON.stringify(result,null,2)+'\n');
} catch(error) {
  writeReleaseFailure('prepare-production-release-core-materialization',error);
  process.exitCode=1;
}
