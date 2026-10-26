import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {checkpointAdapterConfigHash} from '../sdk/checkpoint-verifier-config.mjs';
import {deriveCheckpointAdapterArtifactBinding,deriveFinalizedBurnAdapterArtifactBinding}
  from '../sdk/compiled-runtime.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {materializeProductionPreActivationCore} from '../sdk/production-preactivation-core.mjs';
import {validateRiscZeroMainnetReference} from '../sdk/risc0-verifier-reference.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {finalizedBurnAdapterConfigHash} from '../sdk/verifier-config.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const snapshots=new Map();
async function stable(relative) {
  const bytes=await readDirectProjectFile(root,relative);
  const previous=snapshots.get(relative);
  if(previous&&!previous.equals(bytes)) throw new Error(`pre-activation input changed: ${relative}`);
  if(!previous) snapshots.set(relative,Buffer.from(bytes));
  return bytes;
}
async function json(relative) {
  return parseStrictJson((await stable(relative)).toString('utf8'),
    {label:relative,maxBytes:8*1024*1024,maxDepth:48});
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
function image(requirements,field,label) {
  const value=requirements?.[field];
  if(typeof value!=='string'||!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} ImageID is not pinned by production requirements`);
  }
  return '0x'+value;
}

try {
  if(process.argv.length!==2) throw new Error('this fixed pre-activation materializer accepts no arguments');
  const [releaseConfig,nativeFacts,reference,requirements,burnBuild,checkpointBuild]
    =await Promise.all([
      json('config/proof-reserve.unconfigured.json'),json('config/native-preactivation-facts.unconfigured.json'),
      json('config/risc0-ethereum-mainnet-v3.json'),
      json('config/production-requirements.json'),
      build('out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json'),
      build('out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json'),
    ]);
  const risc0=validateRiscZeroMainnetReference(reference);
  const shared={ethereumChainId:'1',riscZeroVerifier:risc0.verifier_address,
    riscZeroVerifierCodeHash:risc0.observed_runtime_code_hash,
    riscZeroVerifierSelector:risc0.verifier_selector};
  const burnConfig={...shared,finalizedBurnGuestImageId:image(requirements,
    'production_finalized_burn_guest_image_id','finalized-burn guest')};
  const checkpointConfig={...shared,checkpointGuestImageId:image(requirements,
    'production_checkpoint_outer_guest_candidate_image_id','checkpoint guest')};
  const burnIdentity=finalizedBurnAdapterConfigHash(burnConfig);
  const checkpointIdentity=checkpointAdapterConfigHash(checkpointConfig);
  const burnBinding=deriveFinalizedBurnAdapterArtifactBinding({...burnBuild,adapterConfig:burnConfig,
    expectedConfigHash:burnIdentity.verifierConfigHash});
  const checkpointBinding=deriveCheckpointAdapterArtifactBinding({...checkpointBuild,
    adapterConfig:checkpointConfig,expectedConfigHash:checkpointIdentity.verifierConfigHash});
  const result=materializeProductionPreActivationCore({releaseConfig,nativeFacts,
    finalizedBurnVerifier:{runtimeCodeHash:burnBinding.runtimeCodeHash,
      initcodeHash:burnBinding.initcodeHash,
      configHash:burnBinding.verifierConfigHash},
    checkpointVerifier:{runtimeCodeHash:checkpointBinding.runtimeCodeHash,
      initcodeHash:checkpointBinding.initcodeHash,
      configHash:checkpointBinding.verifierConfigHash}});
  for(const [relative,previous] of snapshots) {
    const current=await readDirectProjectFile(root,relative,{minimum:previous.length,maximum:previous.length});
    if(!current.equals(previous)) throw new Error(`pre-activation input changed: ${relative}`);
  }
  process.stdout.write(JSON.stringify(result.releaseConfig,null,2)+'\n');
} catch(error) {
  writeReleaseFailure('prepare-production-preactivation-core-materialization',error);
  process.exitCode=1;
}
