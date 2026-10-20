import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  deriveCheckpointRegistryInitcodeHash,deriveCheckpointRegistryRuntimeCodeHash,
  deriveCheckpointVerifierInitcodeHash,deriveCheckpointVerifierRuntimeCodeHash,
  deriveFinalizedBurnVerifierInitcodeHash,deriveFinalizedBurnVerifierRuntimeCodeHash,
  deriveReserveInitcodeHash,deriveReserveRuntimeCodeHash,
} from '../sdk/compiled-runtime.mjs';
import {buildMainnetDeploymentPackage} from '../sdk/deployment-package.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
async function loadJson(relative) {
  return parseStrictJson((await readDirectProjectFile(root,relative)).toString('utf8'),{label:relative});
}

async function loadArtifact(relative) {
  const artifact=await loadJson(relative);
  const sourceContents=Object.create(null);
  for(const source of Object.keys(artifact?.metadata?.sources??{})) {
    const absolute=path.resolve(root,source);
    if(absolute!==root && !absolute.startsWith(root+path.sep)) {
      throw new Error(`artifact source escapes project root: ${source}`);
    }
    sourceContents[source]=await readFile(absolute);
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
    const releaseBytes=await readDirectProjectFile(root,'config/proof-reserve.unconfigured.json');
    const releaseConfig=parseStrictJson(releaseBytes.toString('utf8'),{
      label:'config/proof-reserve.unconfigured.json',
    });
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
    const finalizedInit=deriveFinalizedBurnVerifierInitcodeHash({...finalizedBuild,verifierConfig});
    const finalizedRuntime=deriveFinalizedBurnVerifierRuntimeCodeHash({...finalizedBuild,verifierConfig});
    const checkpointInit=deriveCheckpointVerifierInitcodeHash({...checkpointBuild,verifierConfig:checkpointVerifierConfig});
    const checkpointRuntime=deriveCheckpointVerifierRuntimeCodeHash({...checkpointBuild,
      verifierConfig:checkpointVerifierConfig});
    const registryInit=deriveCheckpointRegistryInitcodeHash({...registryBuild,releaseConfig});
    const registryRuntime=deriveCheckpointRegistryRuntimeCodeHash({...registryBuild,releaseConfig});
    const reserveInit=deriveReserveInitcodeHash({...reserveBuild,releaseConfig});
    const reserveRuntime=deriveReserveRuntimeCodeHash({...reserveBuild,releaseConfig});
    assertEqual(finalizedRuntime.runtimeCodeHash,releaseConfig.verifierCodeHash,'finalized-burn verifier runtime');
    assertEqual(checkpointRuntime.runtimeCodeHash,releaseConfig.checkpointVerifierCodeHash,
      'checkpoint verifier runtime');
    assertEqual(registryInit.initcodeHash,releaseConfig.checkpointRegistryInitcodeHash,
      'checkpoint registry initcode');
    assertEqual(registryRuntime.runtimeCodeHash,releaseConfig.checkpointRegistryRuntimeCodeHash,
      'checkpoint registry runtime');
    assertEqual(reserveInit.initcodeHash,releaseConfig.reserveInitcodeHash,'reserve initcode');
    assertEqual(reserveRuntime.runtimeCodeHash,releaseConfig.reserveRuntimeCodeHash,'reserve runtime');
    const packageValue=buildMainnetDeploymentPackage({
      releaseConfigSha256:createHash('sha256').update(releaseBytes).digest('hex'),
      plans:{
        finalizedBurnVerifier:{from:releaseConfig.verifierDeployer,
          nonce:releaseConfig.verifierDeployerNonce,expectedContract:releaseConfig.verifier,
          expectedInitcodeHash:releaseConfig.verifierInitcodeHash,
          expectedRuntimeCodeHash:releaseConfig.verifierCodeHash,data:finalizedInit.initcode},
        checkpointVerifier:{from:releaseConfig.checkpointVerifierDeployer,
          nonce:releaseConfig.checkpointVerifierDeployerNonce,expectedContract:releaseConfig.checkpointVerifier,
          expectedInitcodeHash:releaseConfig.checkpointVerifierInitcodeHash,
          expectedRuntimeCodeHash:releaseConfig.checkpointVerifierCodeHash,data:checkpointInit.initcode},
        checkpointRegistry:{from:releaseConfig.checkpointRegistryDeployer,
          nonce:releaseConfig.checkpointRegistryDeployerNonce,expectedContract:releaseConfig.checkpointRegistry,
          expectedInitcodeHash:releaseConfig.checkpointRegistryInitcodeHash,
          expectedRuntimeCodeHash:releaseConfig.checkpointRegistryRuntimeCodeHash,data:registryInit.initcode},
        reserve:{from:releaseConfig.deployer,nonce:releaseConfig.deployerNonce,
          expectedContract:releaseConfig.reserve,expectedRuntimeCodeHash:releaseConfig.reserveRuntimeCodeHash,
          expectedInitcodeHash:releaseConfig.reserveInitcodeHash,
          data:reserveInit.initcode},
      },
    });
    console.log(JSON.stringify(packageValue,null,2));
  } catch(error) {
    console.error(`Deployment package rejected: ${error.message}`);
    process.exitCode=1;
  }
}
