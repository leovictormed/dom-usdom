import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {JsonRpcProvider} from 'ethers';
import {assessMainnetReadiness} from '../sdk/mainnet-readiness.mjs';
import {collectNativeAttestationApprovals} from '../sdk/native-release-attestation.mjs';
import {
  deriveCheckpointRegistryInitcodeHash,
  deriveCheckpointRegistryRuntimeCodeHash,
  deriveCheckpointVerifierInitcodeHash,
  deriveCheckpointVerifierRuntimeCodeHash,
  deriveFinalizedBurnVerifierInitcodeHash,
  deriveFinalizedBurnVerifierRuntimeCodeHash,
  deriveReserveInitcodeHash,
  deriveReserveRuntimeCodeHash,
} from '../sdk/compiled-runtime.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {isCanonicalReleaseTag,parseGitSignatureFingerprint} from '../sdk/git-signature.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const execFileAsync = promisify(execFile);
const mode = process.argv[2] ?? 'closed-mainnet';
function parseNativeRuntimeValidation(output) {
  const result=Object.create(null);
  for(const line of output.trim().split('\n')) {
    const match=/^([a-z0-9_]+): (.+)$/.exec(line);
    if(!match || Object.prototype.hasOwnProperty.call(result,match[1])) {
      throw new Error('native runtime checker returned malformed or duplicate output');
    }
    result[match[1]]=match[2];
  }
  return result;
}
if (process.argv.length > 3) {
  console.error('Usage: node scripts/check-mainnet-readiness.mjs [closed-mainnet|real-funds]');
  process.exitCode = 2;
} else {
  try {
    const forgeBinary=process.env.USDOM_FORGE??'forge';
    await execFileAsync(forgeBinary,[
      'build','contracts/USDOMProofReserve.sol','contracts/DOMCheckpointRegistry.sol',
      'contracts/DOMFinalizedBurnRiscZeroVerifier.sol','contracts/DOMCheckpointRiscZeroVerifier.sol',
      '--force','--ignored-error-codes','6335','-D','warnings',
    ],{cwd:root,encoding:'utf8'});
    const readDirectFile=relative=>readDirectProjectFile(root,relative);
    const readJson = async relative => parseStrictJson(
      (await readDirectFile(relative)).toString('utf8'),{label:relative});
    const readEvidenceFile=readDirectFile;
    const [requirements,operatorIntent,releaseConfig,evidence,riscZeroReference,
      contractSource,checkpointContractSource] = await Promise.all([
      readJson('config/production-requirements.json'),readJson('config/operator-intent.json'),
      readJson('config/proof-reserve.unconfigured.json'),readJson('config/mainnet-release-evidence.unconfigured.json'),
      readJson('config/risc0-ethereum-mainnet-v3.json'),
      readFile(path.join(root, 'contracts/USDOMProofReserve.sol'), 'utf8'),
      readFile(path.join(root, 'contracts/DOMCheckpointRegistry.sol'), 'utf8'),
    ]);
    const evidenceFiles = Object.create(null);
    const documentArray=value=>Array.isArray(value)?value:[];
    const documents = [evidence.reproducibleBuildReport,evidence.verifierReproducibleBuildReport,
      evidence.checkpointRegistryReproducibleBuildReport,evidence.checkpointVerifierReproducibleBuildReport,
      evidence.checkpointBootstrapRatificationReport,evidence.checkpointFinalizedEventReport,
      evidence.realFinalizedEndToEndReport,
      evidence.operationsReviewReport,evidence.mainnetForkRehearsalReport,
      evidence.securityValidationReport,evidence.residualRiskAcceptanceReport,
      evidence.mainnetColdStartAttestationReport,
      evidence.controlPlaneSeparationReport,evidence.controlPlaneRecoveryDrillReport,
      evidence.mainnetPredeploymentAttestationReport,
      evidence.nativePrivacyTrustedSetupAttestationReport,
      evidence.nativeRuntimeManifest,evidence.nativeRuntimeSpendVerifyingKeyArtifact,
      evidence.nativeScheduledRuntimeActivationAttestationReport,
      evidence.nativeWalletCustodyAttestationReport,evidence.nativeWalletRecoveryAttestationReport,
      evidence.reserveArtifact,evidence.verifierArtifact,evidence.verifierConfigManifest,
      evidence.checkpointRegistryArtifact,evidence.checkpointVerifierArtifact,
      evidence.checkpointVerifierConfigManifest,evidence.checkpointVerifyingKeyArtifact,
      evidence.checkpointProvingProgramArtifact,evidence.checkpointProvingProgramSourceManifest,
      evidence.verifyingKeyArtifact,evidence.provingProgramArtifact,evidence.provingProgramSourceManifest,
      ...documentArray(evidence.domConsensusAuditReports),
      ...documentArray(evidence.privacyCircuitAuditReports),
      ...documentArray(evidence.solidityAuditReports),evidence.trustedSetup?.decisionReport,
      evidence.trustedSetup?.transcript,evidence.controlPlane?.governance?.configurationReport,
      evidence.checkpointTrustedSetup?.decisionReport,evidence.checkpointTrustedSetup?.transcript,
      evidence.controlPlane?.guardian?.configurationReport,
      evidence.controlPlane?.checkpointGuardian?.configurationReport].filter(Boolean);
    for (const document of documents) {
      if (typeof document.path !== 'string') continue;
      try {
        evidenceFiles[document.path] = createHash('sha256').update(await readEvidenceFile(document.path)).digest('hex');
      } catch { /* reported by the pure assessment */ }
    }
    let verifierConfig=null;
    if (typeof evidence.verifierConfigManifest?.path === 'string') {
      try {
        verifierConfig=parseStrictJson((await readEvidenceFile(evidence.verifierConfigManifest.path)).toString('utf8'),{
          label:evidence.verifierConfigManifest.path,
        });
      } catch { /* reported by the pure assessment */ }
    }
    let checkpointVerifierConfig=null;
    if (typeof evidence.checkpointVerifierConfigManifest?.path === 'string') {
      try {
        checkpointVerifierConfig=parseStrictJson(
          (await readEvidenceFile(evidence.checkpointVerifierConfigManifest.path)).toString('utf8'),{
            label:evidence.checkpointVerifierConfigManifest.path,
          });
      } catch { /* reported by the pure assessment */ }
    }
    let nativeRuntimeValidation=null;
    const nativeManifest=evidence.nativeRuntimeManifest;
    if(typeof nativeManifest?.path==='string' && typeof nativeManifest.sha256==='string'
        && /^[0-9a-f]{64}$/.test(nativeManifest.sha256)
        && evidenceFiles[nativeManifest.path]===nativeManifest.sha256) {
      try {
        const checked=await execFileAsync(process.env.USDOM_CARGO??'cargo',[
          'run','--quiet','--locked','-p','dom-node','--features','native-usdom-v4-poc',
          '--bin','dom-usdom-manifest-check','--','--manifest-file',
          path.resolve(root,nativeManifest.path),'--manifest-sha256',nativeManifest.sha256,
          '--network','mainnet',
        ],{cwd:path.resolve(root,'../..'),encoding:'utf8'});
        nativeRuntimeValidation=parseNativeRuntimeValidation(checked.stdout);
      } catch { /* the pure assessment reports missing or invalid checker output */ }
    }
    const readAttestation=async document=>{
      if(typeof document?.path!=='string') return null;
      try {
        return parseStrictJson((await readEvidenceFile(document.path)).toString('utf8'),{
          label:document.path,
        });
      } catch { return null; }
    };
    const [predeploymentAttestation,coldStartAttestation,nativePrivacyTrustedSetupAttestation,
      nativeScheduledRuntimeActivationAttestation,nativeWalletCustodyAttestation,
      nativeWalletRecoveryAttestation]=await Promise.all([
      readAttestation(evidence.mainnetPredeploymentAttestationReport),
      readAttestation(evidence.mainnetColdStartAttestationReport),
      readAttestation(evidence.nativePrivacyTrustedSetupAttestationReport),
      readAttestation(evidence.nativeScheduledRuntimeActivationAttestationReport),
      readAttestation(evidence.nativeWalletCustodyAttestationReport),
      readAttestation(evidence.nativeWalletRecoveryAttestationReport),
    ]);
    const requiredNativeAttestations={
      nativePrivacyTrustedSetup:nativePrivacyTrustedSetupAttestation,
      nativeScheduledRuntimeActivation:nativeScheduledRuntimeActivationAttestation,
      ...(mode==='real-funds'?{
        nativeWalletCustody:nativeWalletCustodyAttestation,
        nativeWalletRecovery:nativeWalletRecoveryAttestation,
      }:{}),
    };
    let nativeAttestationApprovalObservation=null;
    if(Object.values(requiredNativeAttestations).every(Boolean) && process.env.ETHEREUM_RPC_URL) {
      const provider=new JsonRpcProvider(process.env.ETHEREUM_RPC_URL);
      try {
        nativeAttestationApprovalObservation=await collectNativeAttestationApprovals({
          provider,releaseConfig,attestations:requiredNativeAttestations,
        });
      } catch { /* the pure assessment reports a missing finalized approval snapshot */ }
      finally { await provider.destroy(); }
    }
    const git = async args => (await execFileAsync('git',['-C',root,...args],{encoding:'utf8'})).stdout.trim();
    const gitSignature = async args => {
      try {
        const result=await execFileAsync('git',['-C',root,...args],{encoding:'utf8'});
        return {verified:true,fingerprint:parseGitSignatureFingerprint(`${result.stdout}\n${result.stderr}`)};
      } catch(error) {
        return {verified:false,
          fingerprint:parseGitSignatureFingerprint(`${error.stdout??''}\n${error.stderr??''}`)};
      }
    };
    const commandVerified = async (command,args) => {
      try { await execFileAsync(command,args,{cwd:root,encoding:'utf8'}); return true; }
      catch { return false; }
    };
    const head = await git(['rev-parse','HEAD']);
    const headParents=(await git(['rev-list','--parents','-n','1','HEAD'])).split(/\s+/).slice(1);
    const releaseIdentities =
      (await git(['show','-s','--format=%an <%ae>%n%cn <%ce>','HEAD'])).split('\n');
    const sourceCommit=/^[0-9a-f]{40}$/.test(evidence.sourceCommit??'')
      ? evidence.sourceCommit:null;
    let sourceIdentities=[];
    let releaseEvidenceChanges=null;
    if(sourceCommit) {
      try {
        sourceIdentities=(await git([
          'show','-s','--format=%an <%ae>%n%cn <%ce>',sourceCommit,
        ])).split('\n');
        const diff=(await execFileAsync('git',[
          '-C',root,'diff-tree','--no-commit-id','--name-status','-r','--no-renames','-z',
          sourceCommit,'HEAD',
        ],{encoding:null})).stdout;
        const fields=diff.toString('utf8').split('\0');
        if(fields.at(-1)==='') fields.pop();
        releaseEvidenceChanges=fields.length%2===0
          ? Array.from({length:fields.length/2},(_,index)=>({
            status:fields[index*2],path:fields[index*2+1],
          }))
          : [{status:'INVALID',path:'INVALID'}];
      } catch { /* the pure assessment reports missing source provenance */ }
    }
    const sourceTag=isCanonicalReleaseTag(evidence.sourceTag)?evidence.sourceTag:null;
    let tagCommit = null;
    if (sourceTag) {
      try { tagCommit = await git(['rev-parse','--verify',`refs/tags/${sourceTag}^{commit}`]); }
      catch { /* reported below */ }
    }
    const [sourceCommitSignature,releaseCommitSignature,tagSignature]=await Promise.all([
      sourceCommit
        ? gitSignature(['verify-commit','--raw',sourceCommit])
        : Promise.resolve({verified:false,fingerprint:null}),
      gitSignature(['verify-commit','--raw','HEAD']),
      sourceTag
        ? gitSignature(['verify-tag','--raw','--',sourceTag])
        : Promise.resolve({verified:false,fingerprint:null}),
    ]);
    const repositoryState = {
      head,dirty:(await git(['status','--porcelain=v1','--untracked-files=all'])).length !== 0,
      sourceCommit,headParents,releaseEvidenceChanges,
      sourceAuthor:sourceIdentities[0] ?? null,sourceCommitter:sourceIdentities[1] ?? null,
      releaseAuthor:releaseIdentities[0] ?? null,releaseCommitter:releaseIdentities[1] ?? null,
      tagCommit,
      sourceCommitSignatureVerified:sourceCommitSignature.verified,
      sourceCommitSignerFingerprint:sourceCommitSignature.fingerprint,
      releaseCommitSignatureVerified:releaseCommitSignature.verified,
      releaseCommitSignerFingerprint:releaseCommitSignature.fingerprint,
      tagSignatureVerified:tagSignature.verified,
      tagSignerFingerprint:tagSignature.fingerprint,
      importProvenanceVerified:await commandVerified('python3',['scripts/verify-import.py']),
      sourceManifestVerified:await commandVerified('python3',['scripts/source-manifest.py']),
      ethereumFinalityPanicBoundaryVerified:await commandVerified(
        'python3',['scripts/check-ethereum-finality-panic-boundary.py']),
      nativeStatePanicBoundaryVerified:await commandVerified(
        'python3',['scripts/check-native-state-panic-boundary.py']),
      nativePrivacyPanicBoundaryVerified:await commandVerified(
        'python3',['scripts/check-native-privacy-panic-boundary.py']),
      proofProgramPanicBoundaryVerified:await commandVerified(
        'python3',['scripts/check-proof-program-panic-boundary.py']),
      nativeWalletPanicBoundaryVerified:await commandVerified(
        'python3',['scripts/check-native-wallet-panic-boundary.py']),
    };
    let compiledReserveRuntimeCodeHash=null,compiledReserveInitcodeHash=null;
    try {
      const artifact=await readJson('out/USDOMProofReserve.sol/USDOMProofReserve.json');
      const sourceContents=Object.create(null);
      for(const source of Object.keys(artifact?.metadata?.sources??{})) {
        const absolute=path.resolve(root,source);
        if (absolute!==root && !absolute.startsWith(root+path.sep)) throw new Error('artifact source escapes project root');
        sourceContents[source]=await readFile(absolute);
      }
      compiledReserveRuntimeCodeHash=deriveReserveRuntimeCodeHash({artifact,releaseConfig,sourceContents}).runtimeCodeHash;
      compiledReserveInitcodeHash=deriveReserveInitcodeHash({artifact,releaseConfig,sourceContents}).initcodeHash;
    } catch { /* reported by the pure assessment */ }
    let compiledCheckpointRegistryRuntimeCodeHash=null,compiledCheckpointRegistryInitcodeHash=null;
    try {
      const artifact=await readJson('out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json');
      const sourceContents=Object.create(null);
      for(const source of Object.keys(artifact?.metadata?.sources??{})) {
        const absolute=path.resolve(root,source);
        if (absolute!==root && !absolute.startsWith(root+path.sep)) throw new Error('artifact source escapes project root');
        sourceContents[source]=await readFile(absolute);
      }
      compiledCheckpointRegistryRuntimeCodeHash=
        deriveCheckpointRegistryRuntimeCodeHash({artifact,releaseConfig,sourceContents}).runtimeCodeHash;
      compiledCheckpointRegistryInitcodeHash=
        deriveCheckpointRegistryInitcodeHash({artifact,releaseConfig,sourceContents}).initcodeHash;
    } catch { /* reported by the pure assessment */ }
    let compiledVerifierRuntimeCodeHash=null,compiledVerifierInitcodeHash=null;
    let compiledCheckpointVerifierRuntimeCodeHash=null,compiledCheckpointVerifierInitcodeHash=null;
    try {
      const artifact=await readJson(
        'out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json',
      );
      const sourceContents=Object.create(null);
      for(const source of Object.keys(artifact?.metadata?.sources??{})) {
        const absolute=path.resolve(root,source);
        if(absolute!==root && !absolute.startsWith(root+path.sep)) {
          throw new Error('artifact source escapes project root');
        }
        sourceContents[source]=await readFile(absolute);
      }
      compiledVerifierRuntimeCodeHash=deriveFinalizedBurnVerifierRuntimeCodeHash({
        artifact,verifierConfig,sourceContents,
      }).runtimeCodeHash;
      compiledVerifierInitcodeHash=deriveFinalizedBurnVerifierInitcodeHash({
        artifact,verifierConfig,sourceContents,
      }).initcodeHash;
    } catch { /* reported by the pure assessment */ }
    try {
      const artifact=await readJson(
        'out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json',
      );
      const sourceContents=Object.create(null);
      for(const source of Object.keys(artifact?.metadata?.sources??{})) {
        const absolute=path.resolve(root,source);
        if(absolute!==root && !absolute.startsWith(root+path.sep)) {
          throw new Error('artifact source escapes project root');
        }
        sourceContents[source]=await readFile(absolute);
      }
      compiledCheckpointVerifierRuntimeCodeHash=deriveCheckpointVerifierRuntimeCodeHash({
        artifact,verifierConfig:checkpointVerifierConfig,sourceContents,
      }).runtimeCodeHash;
      compiledCheckpointVerifierInitcodeHash=deriveCheckpointVerifierInitcodeHash({
        artifact,verifierConfig:checkpointVerifierConfig,sourceContents,
      }).initcodeHash;
    } catch { /* reported by the pure assessment */ }
    const report = assessMainnetReadiness({mode,requirements,operatorIntent,releaseConfig,evidence,evidenceFiles,
      trustedReleaseSigningKeyFingerprint:process.env.USDOM_RELEASE_SIGNING_KEY_FINGERPRINT??null,
      repositoryState,contractSource,checkpointContractSource,compiledReserveRuntimeCodeHash,
      compiledReserveInitcodeHash,compiledCheckpointRegistryRuntimeCodeHash,
      compiledCheckpointRegistryInitcodeHash,verifierConfig,checkpointVerifierConfig,riscZeroReference,
      compiledVerifierRuntimeCodeHash,compiledVerifierInitcodeHash,
      compiledCheckpointVerifierRuntimeCodeHash,compiledCheckpointVerifierInitcodeHash,
      predeploymentAttestation,coldStartAttestation,nativePrivacyTrustedSetupAttestation,
      nativeScheduledRuntimeActivationAttestation,nativeWalletCustodyAttestation,
      nativeWalletRecoveryAttestation,nativeAttestationApprovalObservation,nativeRuntimeValidation});
    console.log(JSON.stringify(report,null,2));
    if (!report.ready) process.exitCode = 1;
  } catch (error) {
    console.error(JSON.stringify({mode,ready:false,error:error.message},null,2));
    process.exitCode = 2;
  }
}
