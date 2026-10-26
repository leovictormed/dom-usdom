import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  deriveCheckpointRegistryArtifactBinding,
  deriveCheckpointVerifierArtifactBinding,deriveFinalizedBurnVerifierArtifactBinding,
  deriveReserveArtifactBinding,
} from '../sdk/compiled-runtime.mjs';
import {buildMainnetDeploymentPackage} from '../sdk/deployment-package.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {validateMainnetDeploymentIdentityObservation}
  from '../sdk/mainnet-deployment-identity.mjs';
import {auditReserveArtifact} from '../sdk/reserve-artifact-safety.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const inputSnapshots=new Map();
async function readStable(relative,options={}) {
  const bytes=await readDirectProjectFile(root,relative,options);
  const previous=inputSnapshots.get(relative);
  if(previous&&!previous.equals(bytes)) throw new Error(`deployment input changed: ${relative}`);
  if(!previous) inputSnapshots.set(relative,Buffer.from(bytes));
  return bytes;
}
async function loadJson(relative) {
  return parseStrictJson((await readStable(relative)).toString('utf8'),{label:relative});
}

async function loadArtifact(relative) {
  const artifact=await loadJson(relative);
  const sourceContents=Object.create(null);
  for(const source of Object.keys(artifact?.metadata?.sources??{})) {
    const absolute=path.resolve(root,source);
    if(absolute!==root && !absolute.startsWith(root+path.sep)) {
      throw new Error(`artifact source escapes project root: ${source}`);
    }
    sourceContents[source]=await readStable(source,{
      maximum:8*1024*1024,label:'deployment artifact source',
    });
  }
  if(relative==='out/USDOMProofReserve.sol/USDOMProofReserve.json') {
    auditReserveArtifact(artifact,{sourceContents});
  }
  return {artifact,sourceContents};
}

function assertEqual(actual,expected,label) {
  if(typeof expected!=='string' || actual.toLowerCase()!==expected.toLowerCase()) {
    throw new Error(`${label} does not match the exact release`);
  }
}

if(process.argv.length!==2) {
  console.error('Usage: node scripts/prepare-mainnet-deployment.mjs');
  process.exitCode=2;
} else {
  try {
    const observationPath=process.env.USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION;
    const expectedObservationSha=process.env.USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION_SHA256;
    if(typeof observationPath!=='string'||!path.isAbsolute(observationPath)
        ||typeof expectedObservationSha!=='string'||!/^[0-9a-f]{64}$/.test(expectedObservationSha)) {
      throw new Error('absolute deployment identity observation path and SHA-256 are required');
    }
    const observationBytes=await readDirectFile(observationPath,{minimum:1,maximum:4*1024*1024,
      exactMode:0o600,label:'deployment identity observation'});
    const observationSha=createHash('sha256').update(observationBytes).digest('hex');
    if(observationSha!==expectedObservationSha) throw new Error('deployment identity observation SHA-256 mismatch');
    const observation=parseStrictJson(observationBytes.toString('utf8'),{
      label:'deployment identity observation',maxBytes:4*1024*1024,maxDepth:32});
    const releaseBytes=await readStable('config/proof-reserve.unconfigured.json');
    const releaseConfig=parseStrictJson(releaseBytes.toString('utf8'),{
      label:'config/proof-reserve.unconfigured.json',
    });
    validateMainnetDeploymentIdentityObservation({observation,releaseConfigAfter:releaseConfig});
    if(releaseConfig.productionReady!==true || releaseConfig.ethereumChainId!=='1'
        || releaseConfig.deploymentMethod!=='CREATE') {
      throw new Error('the exact Ethereum mainnet CREATE release is not production-ready');
    }
    const [verifierConfig,checkpointVerifierConfig,finalizedBuild,checkpointBuild,registryBuild,reserveBuild]
      =await Promise.all([
        loadJson('config/finalized-burn-verifier.unconfigured.json'),
        loadJson('config/checkpoint-verifier.unconfigured.json'),
        loadArtifact('out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json'),
        loadArtifact('out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json'),
        loadArtifact('out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json'),
        loadArtifact('out/USDOMProofReserve.sol/USDOMProofReserve.json'),
      ]);
    const finalizedBinding=deriveFinalizedBurnVerifierArtifactBinding({...finalizedBuild,verifierConfig,
      expectedConfigHash:releaseConfig.verifierConfigHash});
    const checkpointBinding=deriveCheckpointVerifierArtifactBinding({...checkpointBuild,
      verifierConfig:checkpointVerifierConfig,expectedConfigHash:releaseConfig.checkpointVerifierConfigHash});
    const registryBinding=deriveCheckpointRegistryArtifactBinding({...registryBuild,releaseConfig});
    const reserveBinding=deriveReserveArtifactBinding({...reserveBuild,releaseConfig});
    if(reserveBinding.immutableReferenceCount!==68
        ||reserveBinding.immutablePatchManifest?.length!==23
        ||!/^0x[0-9a-f]{64}$/.test(reserveBinding.immutablePatchManifestHash??'')) {
      throw new Error('reserve immutable patch manifest is incomplete');
    }
    assertEqual(finalizedBinding.runtimeCodeHash,releaseConfig.verifierCodeHash,'finalized-burn verifier runtime');
    assertEqual(finalizedBinding.initcodeHash,releaseConfig.verifierInitcodeHash,
      'finalized-burn verifier initcode');
    assertEqual(checkpointBinding.runtimeCodeHash,releaseConfig.checkpointVerifierCodeHash,
      'checkpoint verifier runtime');
    assertEqual(checkpointBinding.initcodeHash,releaseConfig.checkpointVerifierInitcodeHash,
      'checkpoint verifier initcode');
    assertEqual(registryBinding.initcodeHash,releaseConfig.checkpointRegistryInitcodeHash,
      'checkpoint registry initcode');
    assertEqual(registryBinding.runtimeCodeHash,releaseConfig.checkpointRegistryRuntimeCodeHash,
      'checkpoint registry runtime');
    assertEqual(reserveBinding.initcodeHash,releaseConfig.reserveInitcodeHash,'reserve initcode');
    assertEqual(reserveBinding.runtimeCodeHash,releaseConfig.reserveRuntimeCodeHash,'reserve runtime');
    const packageValue=buildMainnetDeploymentPackage({
      releaseConfigSha256:createHash('sha256').update(releaseBytes).digest('hex'),
      observationDocumentSha256:observationSha,observationHash:observation.observationHash,
      approvedArtifacts:{
        finalizedBurnVerifier:{expectedContract:releaseConfig.verifier,
          expectedInitcodeHash:releaseConfig.verifierInitcodeHash,
          expectedRuntimeCodeHash:releaseConfig.verifierCodeHash},
        checkpointVerifier:{expectedContract:releaseConfig.checkpointVerifier,
          expectedInitcodeHash:releaseConfig.checkpointVerifierInitcodeHash,
          expectedRuntimeCodeHash:releaseConfig.checkpointVerifierCodeHash},
        checkpointRegistry:{expectedContract:releaseConfig.checkpointRegistry,
          expectedInitcodeHash:releaseConfig.checkpointRegistryInitcodeHash,
          expectedRuntimeCodeHash:releaseConfig.checkpointRegistryRuntimeCodeHash},
        reserve:{expectedContract:releaseConfig.reserve,
          expectedInitcodeHash:releaseConfig.reserveInitcodeHash,
          expectedRuntimeCodeHash:releaseConfig.reserveRuntimeCodeHash},
      },
      plans:{
        finalizedBurnVerifier:{from:releaseConfig.verifierDeployer,
          nonce:releaseConfig.verifierDeployerNonce,expectedContract:releaseConfig.verifier,
          expectedInitcodeHash:releaseConfig.verifierInitcodeHash,
          expectedRuntimeCodeHash:releaseConfig.verifierCodeHash,data:finalizedBinding.initcode},
        checkpointVerifier:{from:releaseConfig.checkpointVerifierDeployer,
          nonce:releaseConfig.checkpointVerifierDeployerNonce,expectedContract:releaseConfig.checkpointVerifier,
          expectedInitcodeHash:releaseConfig.checkpointVerifierInitcodeHash,
          expectedRuntimeCodeHash:releaseConfig.checkpointVerifierCodeHash,data:checkpointBinding.initcode},
        checkpointRegistry:{from:releaseConfig.checkpointRegistryDeployer,
          nonce:releaseConfig.checkpointRegistryDeployerNonce,expectedContract:releaseConfig.checkpointRegistry,
          expectedInitcodeHash:releaseConfig.checkpointRegistryInitcodeHash,
          expectedRuntimeCodeHash:releaseConfig.checkpointRegistryRuntimeCodeHash,data:registryBinding.initcode},
        reserve:{from:releaseConfig.deployer,nonce:releaseConfig.deployerNonce,
          expectedContract:releaseConfig.reserve,expectedRuntimeCodeHash:releaseConfig.reserveRuntimeCodeHash,
          expectedInitcodeHash:releaseConfig.reserveInitcodeHash,
          data:reserveBinding.initcode},
      },
    });
    for(const [relative,snapshot] of inputSnapshots) {
      const current=await readDirectProjectFile(root,relative,{minimum:snapshot.length,
        maximum:snapshot.length,label:'deployment input stability check'});
      if(!current.equals(snapshot)) throw new Error(`deployment input changed: ${relative}`);
    }
    const currentObservation=await readDirectFile(observationPath,{minimum:observationBytes.length,
      maximum:observationBytes.length,exactMode:0o600,label:'deployment identity observation'});
    if(!currentObservation.equals(observationBytes)) throw new Error('deployment identity observation changed');
    console.log(JSON.stringify(packageValue,null,2));
  } catch(error) {
    writeReleaseFailure('prepare-mainnet-deployment',error);
    process.exitCode=1;
  }
}
