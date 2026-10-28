import path from 'node:path';
import {readDirectFile,readDirectProjectFile} from './direct-project-file.mjs';
import {writeFileDurable} from './durable-private-file.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {deriveFinalizedBurnVerifierArtifactBinding} from './compiled-runtime.mjs';
import {finalizedBurnVerifierConfigHash} from './verifier-config.mjs';
import {verifyProductionVerifierBindings} from './production-solidity-pins.mjs';
import {buildReservePinRatificationProposal,restoreReservePinRatificationBaseline,
  verifyReservePinRatificationProposal}
  from './reserve-pin-ratification.mjs';
import {createHash} from 'node:crypto';

const fixed=Object.freeze({reserve:'contracts/USDOMProofReserve.sol',
  artifact:'out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json',
  manifest:'MANIFEST.sha256',inventory:'config/rebuild-v3-critical-source-inventory.json',
  toolchain:'config/mainnet-toolchain-lock.json'});

/** Re-open all current project inputs, authenticate the adapter artifact against
 * its metadata source graph, and only then derive the review proposal. */
export async function prepareReservePinRatificationFromProject({root,releasePath,verifierConfigPath,proposal}={}) {
  root=path.resolve(root);
  const read=(name,label,maximum)=>readDirectProjectFile(root,name,{minimum:1,maximum,label});
  const [releaseConfigBytes,finalizedBurnVerifierConfigBytes,reserveSourceBytes,
    finalizedBurnVerifierArtifactBytes,sourceManifestBytes,criticalSourceInventoryBytes,
    toolchainLockBytes]=await Promise.all([
      read(releasePath,'release config',4*1024*1024),
      read(verifierConfigPath,'finalized-burn verifier config',4*1024*1024),
      read(fixed.reserve,'reserve source',4*1024*1024),
      read(fixed.artifact,'finalized-burn verifier artifact',32*1024*1024),
      read(fixed.manifest,'source manifest',16*1024*1024),
      read(fixed.inventory,'critical-source inventory',4*1024*1024),
      read(fixed.toolchain,'toolchain lock',1024*1024)]);
  const releaseConfig=parseStrictJsonBytes(releaseConfigBytes,{label:releasePath,maxDepth:64});
  const verifierConfig=parseStrictJsonBytes(finalizedBurnVerifierConfigBytes,
    {label:verifierConfigPath,maxDepth:64});
  const artifact=parseStrictJsonBytes(finalizedBurnVerifierArtifactBytes,
    {label:fixed.artifact,maxBytes:32*1024*1024,maxDepth:128});
  const sourceContents=Object.create(null);
  for(const source of Object.keys(artifact?.metadata?.sources??{})) {
    sourceContents[source]=await read(source,`artifact source ${source}`,16*1024*1024);
  }
  const configured=finalizedBurnVerifierConfigHash(verifierConfig);
  const binding=deriveFinalizedBurnVerifierArtifactBinding({artifact,artifactBytes:finalizedBurnVerifierArtifactBytes,
    sourceContents,verifierConfig,expectedConfigHash:configured.verifierConfigHash});
  verifyProductionVerifierBindings({releaseConfig,finalizedBurnVerifier:{runtimeCodeHash:binding.runtimeCodeHash,
    initcodeHash:binding.initcodeHash,configHash:binding.verifierConfigHash},checkpointVerifier:{
    runtimeCodeHash:releaseConfig.checkpointVerifierCodeHash,
    initcodeHash:releaseConfig.checkpointVerifierInitcodeHash,
    configHash:releaseConfig.checkpointVerifierConfigHash}});
  let proposalSourceBytes=reserveSourceBytes;
  if(proposal!==undefined&&proposal?.inputs?.candidateReserveSourceSha256
      ===createHash('sha256').update(reserveSourceBytes).digest('hex')) {
    proposalSourceBytes=restoreReservePinRatificationBaseline({proposal,
      candidateSourceBytes:reserveSourceBytes});
  }
  const inputs={releaseConfig,releaseConfigBytes,reserveSourceBytes:proposalSourceBytes,
    finalizedBurnVerifierArtifactBytes,
    finalizedBurnVerifierConfigBytes,sourceManifestBytes,criticalSourceInventoryBytes,toolchainLockBytes};
  return proposal===undefined?buildReservePinRatificationProposal(inputs)
    :verifyReservePinRatificationProposal({proposal,...inputs});
}

/** Publish a public review artifact once, or prove an idempotent retry supplied
 * exactly the already-installed bytes. The caller must still revalidate those
 * bytes against current project authority after installation. */
export async function installReservePinRatificationProposal(target,contents) {
  const bytes=Buffer.isBuffer(contents)?contents:Buffer.from(contents);
  if(bytes.length<2||bytes.length>4*1024*1024) throw new Error('ratification proposal size is invalid');
  try {
    await writeFileDurable(target,bytes,{maximum:4*1024*1024,mode:0o644,replace:false});
  } catch(error) {
    if(error?.message!=='durable target already exists') throw error;
  }
  const installed=await readDirectFile(path.resolve(target),{minimum:bytes.length,maximum:bytes.length,
    exactMode:0o644,label:'installed ratification proposal'});
  if(!installed.equals(bytes)) throw new Error('installed ratification proposal differs from requested bytes');
  return installed;
}
