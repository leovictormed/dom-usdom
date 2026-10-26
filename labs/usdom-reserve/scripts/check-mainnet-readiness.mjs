import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {assessMainnetReadiness} from '../sdk/mainnet-readiness.mjs';
import {collectNativeAttestationApprovalConsensus,collectReleaseAuthorizationApprovalConsensus,
  resolveReleaseAuthorizationRpcSources,
  withReleaseAuthorizationProviders} from '../sdk/release-authorization-rpc.mjs';
import {
  deriveCheckpointRegistryArtifactBinding,
  deriveCheckpointVerifierArtifactBinding,
  deriveFinalizedBurnVerifierArtifactBinding,
  deriveReserveArtifactBinding,
} from '../sdk/compiled-runtime.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {isCanonicalReleaseTag,parseGitSignatureFingerprint} from '../sdk/git-signature.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {assertExecutableUnchanged,snapshotExecutable} from '../sdk/stable-executable.mjs';
import {assertEvidenceByteSnapshotsUnchanged} from '../sdk/evidence-byte-snapshot.mjs';
import {runPinnedExecutable} from '../sdk/pinned-executable-child.mjs';
import {summarizeReadinessBlockers} from '../sdk/readiness-diagnostics.mjs';
import {auditReserveArtifact} from '../sdk/reserve-artifact-safety.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const mode = process.argv[2] ?? 'closed-mainnet';
const diagnosticNoBuild=process.argv[3]==='--diagnostic-no-build';
function parseNativeRuntimeValidation(output) {
  if(!Buffer.isBuffer(output)) throw new Error('native runtime checker output must be bytes');
  let text;
  try { text=new TextDecoder('utf-8',{fatal:true}).decode(output); }
  catch { throw new Error('native runtime checker output is not valid UTF-8'); }
  if(text.length===0||!text.endsWith('\n')||text.endsWith('\n\n')||text.includes('\r')) {
    throw new Error('native runtime checker output framing is invalid');
  }
  const result=Object.create(null);
  for(const line of text.slice(0,-1).split('\n')) {
    const match=/^([a-z0-9_]+): (.+)$/.exec(line);
    if(!match || Object.prototype.hasOwnProperty.call(result,match[1])) {
      throw new Error('native runtime checker returned malformed or duplicate output');
    }
    result[match[1]]=match[2];
  }
  return result;
}
if (process.argv.length > 4 || (process.argv.length===4 && !diagnosticNoBuild)) {
  console.error('Usage: node scripts/check-mainnet-readiness.mjs [closed-mainnet|real-funds] [--diagnostic-no-build]');
  process.exitCode = 2;
} else {
  try {
    // Diagnostic mode consumes existing, source-bound artifacts and intentionally
    // skips compilation.  Do not make that read-only path depend on a tool it
    // never executes; the normal release gate still snapshots, runs and rechecks
    // Forge before trusting freshly compiled artifacts.
    const forgeExecutable=diagnosticNoBuild?null:await snapshotExecutable('forge');
    const gitExecutable=await snapshotExecutable('git');
    const pythonExecutable=await snapshotExecutable('python3');
    if(!diagnosticNoBuild) {
      await runPinnedExecutable(forgeExecutable,[
        'build','contracts/USDOMProofReserve.sol','contracts/DOMCheckpointRegistry.sol',
        'contracts/DOMFinalizedBurnRiscZeroVerifier.sol','contracts/DOMCheckpointRiscZeroVerifier.sol',
        '--force','--ignored-error-codes','6335','-D','warnings',
      ],{cwd:root,encoding:'buffer',maxBuffer:64*1024*1024,timeout:10*60*1000});
      await assertExecutableUnchanged(forgeExecutable);
    }
    const authorityFileBytes=new Map();
    const readRawDirectFile=(relative,options)=>readDirectProjectFile(root,relative,options);
    const readDirectFile=async(relative,options)=>{
      const bytes=await readRawDirectFile(relative,options);
      const previous=authorityFileBytes.get(relative);
      if(previous && !previous.equals(bytes)) {
        throw new Error(`readiness authority changed during collection: ${relative}`);
      }
      if(!previous) authorityFileBytes.set(relative,Buffer.from(bytes));
      return bytes;
    };
    const readJson = async relative => parseStrictJsonBytes(
      await readDirectFile(relative),{label:relative});
    const readEvidenceFile=readDirectFile;
    const [requirementsBytes,sourceManifestBytes,operatorRunbookBytes,residualRiskDraftBytes,
      operatorIntent,releaseConfig,evidence,riscZeroReference,
      contractSource,checkpointContractSource] = await Promise.all([
      readDirectFile('config/production-requirements.json'),readDirectFile('MANIFEST.sha256'),
      readDirectFile('docs/CLOSED-MAINNET-LINUX-RUNBOOK.md'),
      readDirectFile('docs/RESIDUAL-RISK-ACCEPTANCE-DRAFT-ETAPA211-2026-10-20.txt'),
      readJson('config/operator-intent.json'),
      readJson('config/proof-reserve.unconfigured.json'),readJson('config/mainnet-release-evidence.unconfigured.json'),
      readJson('config/risc0-ethereum-mainnet-v3.json'),
      readDirectFile('contracts/USDOMProofReserve.sol').then(value=>value.toString('utf8')),
      readDirectFile('contracts/DOMCheckpointRegistry.sol').then(value=>value.toString('utf8')),
    ]);
    const requirements=parseStrictJsonBytes(requirementsBytes,{
      label:'config/production-requirements.json'});
    const requirementsSha256=createHash('sha256').update(requirementsBytes).digest('hex');
    const sourceManifestSha256=createHash('sha256').update(sourceManifestBytes).digest('hex');
    const operatorRunbookSha256=createHash('sha256').update(operatorRunbookBytes).digest('hex');
    const residualRiskDraftSha256=createHash('sha256').update(residualRiskDraftBytes).digest('hex');
    const evidenceFiles = Object.create(null);
    const evidenceFileBytes = new Map();
    const documentArray=value=>Array.isArray(value)?value:[];
    const documents = [evidence.reproducibleBuildReport,evidence.verifierReproducibleBuildReport,
      evidence.checkpointRegistryReproducibleBuildReport,evidence.checkpointVerifierReproducibleBuildReport,
      evidence.checkpointBootstrapRatificationReport,evidence.checkpointFinalizedEventReport,
      evidence.checkpointProofCapacityReport,
      evidence.realFinalizedEndToEndReport,
      evidence.operationsReviewReport,evidence.mainnetForkRehearsalReport,
      evidence.securityValidationReport,evidence.riscZeroHealthSourceCatalog,
      evidence.residualRiskAcceptanceReport,
      evidence.mainnetColdStartAttestationReport,
      evidence.controlPlaneEvidenceBundle,evidence.controlPlaneSeparationReport,
      evidence.controlPlaneRecoveryDrillReport,
      evidence.safeRecoveryFinalEvidenceBundle,
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
        const bytes=await readEvidenceFile(document.path);
        evidenceFiles[document.path]=createHash('sha256').update(bytes).digest('hex');
        evidenceFileBytes.set(document.path,bytes);
      } catch { /* reported by the pure assessment */ }
    }
    const readOptionalEvidenceJson=async(document,label)=>{
      if(typeof document?.path!=='string') return null;
      const bytes=evidenceFileBytes.get(document.path);
      if(!bytes) return null;
      try {
        return parseStrictJsonBytes(bytes,{
          label,maxBytes:4*1024*1024,maxDepth:48,
        });
      } catch { return null; }
    };
    const readOptionalProjectJson=async(relative,label)=>{
      try {
        return parseStrictJsonBytes(await readEvidenceFile(relative),{
          label,maxBytes:4*1024*1024,maxDepth:48,
        });
      } catch { return null; }
    };
    const [controlPlaneEvidenceBundle,governanceControlReport,guardianControlReport,
      checkpointGuardianControlReport,controlPlaneSeparationReport,
      controlPlaneRecoveryDrillReport,safeRecoveryFinalEvidenceBundle,
      riscZeroHealthSourceCatalog,finalizedBurnE2eReport,
      checkpointProofCapacityReport,securityValidationReport,operationsReviewReport,
      reserveReproducibleBuildReport,verifierReproducibleBuildReport,
      mainnetForkRehearsalReport,checkpointBootstrapRatificationReport,
      ethereumCheckpointConsensus,nativePreactivationFacts,
      checkpointFinalizedEventReport,checkpointVerifierReproducibleBuildReport,
      checkpointRegistryReproducibleBuildReport,residualRiskReport,
      trustedSetupDecisionReport]=await Promise.all([
      readOptionalEvidenceJson(evidence.controlPlaneEvidenceBundle,'control-plane evidence bundle'),
      readOptionalEvidenceJson(evidence.controlPlane?.governance?.configurationReport,
        'governance control report'),
      readOptionalEvidenceJson(evidence.controlPlane?.guardian?.configurationReport,
        'guardian control report'),
      readOptionalEvidenceJson(evidence.controlPlane?.checkpointGuardian?.configurationReport,
        'checkpoint guardian control report'),
      readOptionalEvidenceJson(evidence.controlPlaneSeparationReport,'control-plane separation report'),
      readOptionalEvidenceJson(evidence.controlPlaneRecoveryDrillReport,
        'control-plane recovery drill report'),
      readOptionalEvidenceJson(evidence.safeRecoveryFinalEvidenceBundle,
        'Safe recovery final evidence bundle'),
      readOptionalEvidenceJson(evidence.riscZeroHealthSourceCatalog,
        'RISC Zero health source catalog'),
      readOptionalEvidenceJson(evidence.realFinalizedEndToEndReport,
        'finalized-burn E2E report'),
      readOptionalEvidenceJson(evidence.checkpointProofCapacityReport,
        'checkpoint proof capacity report'),
      readOptionalEvidenceJson(evidence.securityValidationReport,'security validation report'),
      readOptionalEvidenceJson(evidence.operationsReviewReport,'operations review report'),
      readOptionalEvidenceJson(evidence.reproducibleBuildReport,
        'reserve reproducible-build report'),
      readOptionalEvidenceJson(evidence.verifierReproducibleBuildReport,
        'verifier reproducible-build report'),
      readOptionalEvidenceJson(evidence.mainnetForkRehearsalReport,'mainnet fork rehearsal report'),
      readOptionalEvidenceJson(evidence.checkpointBootstrapRatificationReport,
        'checkpoint bootstrap ratification report'),
      readOptionalProjectJson('evidence/native-preactivation/ethereum-checkpoint-consensus.json',
        'Ethereum checkpoint consensus'),
      readOptionalProjectJson('config/native-preactivation-facts.unconfigured.json',
        'native pre-activation facts'),
      readOptionalEvidenceJson(evidence.checkpointFinalizedEventReport,
        'checkpoint finalized event report'),
      readOptionalEvidenceJson(evidence.checkpointVerifierReproducibleBuildReport,
        'checkpoint verifier reproducible-build report'),
      readOptionalEvidenceJson(evidence.checkpointRegistryReproducibleBuildReport,
        'checkpoint registry reproducible-build report'),
      readOptionalEvidenceJson(evidence.residualRiskAcceptanceReport,'residual-risk report'),
      readOptionalEvidenceJson(evidence.trustedSetup?.decisionReport,
        'shared trusted-setup decision report'),
    ]);
    const mainnetForkRehearsalEvidenceFiles=Object.create(null);
    if(Array.isArray(mainnetForkRehearsalReport?.scenarios)) {
      const rawReferences=mainnetForkRehearsalReport.scenarios.flatMap(scenario=>
        [scenario?.faultEvidence?.path,scenario?.recoveryEvidence?.path]);
      for(const relative of rawReferences) {
        if(typeof relative!=='string'
            || !/^evidence\/fork-rehearsal\/raw\/[a-z0-9][a-z0-9._-]{0,127}$/.test(relative)
            || Object.prototype.hasOwnProperty.call(mainnetForkRehearsalEvidenceFiles,relative)) continue;
        try {
          const content=await readEvidenceFile(relative);
          mainnetForkRehearsalEvidenceFiles[relative]={
            sha256:createHash('sha256').update(content).digest('hex'),
            document:parseStrictJsonBytes(content,{
              label:relative,maxBytes:16*1024*1024,maxDepth:16,
            }),
          };
        } catch { /* semantic validation reports missing or malformed raw evidence */ }
      }
    }
    const controlPlaneEvidenceArtifacts={
      bundle:controlPlaneEvidenceBundle,
      roleReports:{
        governance:governanceControlReport,
        guardian:guardianControlReport,
        checkpointGuardian:checkpointGuardianControlReport,
      },
      separationReport:controlPlaneSeparationReport,
      recoveryDrillReport:controlPlaneRecoveryDrillReport,
      finalBundle:safeRecoveryFinalEvidenceBundle,
    };
    let verifierConfig=null;
    if (typeof evidence.verifierConfigManifest?.path === 'string') {
      try {
        const bytes=evidenceFileBytes.get(evidence.verifierConfigManifest.path);
        if(!bytes) throw new Error('verifier config was not snapshotted');
        verifierConfig=parseStrictJsonBytes(bytes,{
          label:evidence.verifierConfigManifest.path,
        });
      } catch { /* reported by the pure assessment */ }
    }
    let checkpointVerifierConfig=null;
    if (typeof evidence.checkpointVerifierConfigManifest?.path === 'string') {
      try {
        const bytes=evidenceFileBytes.get(evidence.checkpointVerifierConfigManifest.path);
        if(!bytes) throw new Error('checkpoint verifier config was not snapshotted');
        checkpointVerifierConfig=parseStrictJsonBytes(bytes,{
            label:evidence.checkpointVerifierConfigManifest.path,
          });
      } catch { /* reported by the pure assessment */ }
    }
    let nativeRuntimeValidation=null;
    const nativeManifest=evidence.nativeRuntimeManifest;
    if(!diagnosticNoBuild && typeof nativeManifest?.path==='string' && typeof nativeManifest.sha256==='string'
        && /^[0-9a-f]{64}$/.test(nativeManifest.sha256)
        && evidenceFiles[nativeManifest.path]===nativeManifest.sha256) {
      try {
        const cargo=await snapshotExecutable('cargo');
        const checked=await runPinnedExecutable(cargo,[
          'run','--quiet','--locked','-p','dom-node','--features','native-usdom-v4-poc',
          '--bin','dom-usdom-manifest-check','--','--manifest-file',
          path.resolve(root,nativeManifest.path),'--manifest-sha256',nativeManifest.sha256,
          '--network','mainnet',
        ],{cwd:path.resolve(root,'../..'),encoding:'buffer',maxBuffer:4*1024*1024,timeout:10*60*1000});
        await assertExecutableUnchanged(cargo);
        if(checked.stderr.length!==0) throw new Error('native runtime checker wrote stderr');
        nativeRuntimeValidation=parseNativeRuntimeValidation(checked.stdout);
      } catch { /* the pure assessment reports missing or invalid checker output */ }
    }
    const readAttestation=async document=>{
      if(typeof document?.path!=='string') return null;
      const bytes=evidenceFileBytes.get(document.path);
      if(!bytes) return null;
      try {
        return parseStrictJsonBytes(bytes,{
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
    let releaseAuthorizationApprovalObservation=null;
    if(Object.hasOwn(process.env,'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES')) {
      throw new Error('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES is forbidden; provide the owner-only file path in USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE');
    }
    if(Object.values(requiredNativeAttestations).every(Boolean)
        && process.env.USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE) {
      try {
        const catalog=await readOptionalProjectJson('config/mainnet-preflight-rpc-catalog.json',
          'mainnet preflight RPC catalog');
        const runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
        const sources=resolveReleaseAuthorizationRpcSources({catalog,runtimeSources});
        nativeAttestationApprovalObservation=await withReleaseAuthorizationProviders(sources,
          providers=>collectNativeAttestationApprovalConsensus({providers,releaseConfig,
            attestations:requiredNativeAttestations,sources}));
      } catch { /* the pure assessment reports a missing finalized approval snapshot */ }
    }
    const releaseAuthorization=operatorIntent.residual_risk_acceptance;
    if(releaseAuthorization?.accepted===true && process.env.USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE) {
      try {
        const catalog=await readOptionalProjectJson('config/mainnet-preflight-rpc-catalog.json',
          'mainnet preflight RPC catalog');
        const runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
        const sources=resolveReleaseAuthorizationRpcSources({catalog,runtimeSources});
        releaseAuthorizationApprovalObservation=await withReleaseAuthorizationProviders(sources,
          providers=>collectReleaseAuthorizationApprovalConsensus({providers,releaseConfig,
            authorization:releaseAuthorization,sources}));
      } catch { /* the pure assessment reports the missing finalized approval snapshot */ }
    }
    const decodeChildText=(bytes,label)=>{
      try { return new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
      catch { throw new Error(`${label} is not valid UTF-8`); }
    };
    const git = async args => {
      const result=await runPinnedExecutable(gitExecutable,['-C',root,...args],{
        maxBuffer:4*1024*1024,timeout:30_000});
      if(result.stderr.length!==0) throw new Error(`git ${args[0]} wrote stderr`);
      const output=decodeChildText(result.stdout,`git ${args[0]} stdout`);
      if(output==='') return '';
      if(!output.endsWith('\n')||output.endsWith('\n\n')||output.includes('\r')) {
        throw new Error(`git ${args[0]} stdout framing is invalid`);
      }
      return output.slice(0,-1);
    };
    const gitSignature = async args => {
      try {
        const result=await runPinnedExecutable(gitExecutable,['-C',root,...args],{
          maxBuffer:4*1024*1024,timeout:30_000});
        return {verified:true,fingerprint:parseGitSignatureFingerprint(
          `${decodeChildText(result.stdout,'git signature stdout')}\n${decodeChildText(result.stderr,'git signature stderr')}`)};
      } catch(error) {
        return {verified:false,
          fingerprint:parseGitSignatureFingerprint(
            `${Buffer.isBuffer(error.stdout)?decodeChildText(error.stdout,'git signature stdout'):''}\n${Buffer.isBuffer(error.stderr)?decodeChildText(error.stderr,'git signature stderr'):''}`)};
      }
    };
    const commandVerified = async args => {
      try {
        await runPinnedExecutable(pythonExecutable,args,{cwd:root,maxBuffer:4*1024*1024,timeout:30_000});
        return true;
      }
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
        const diffResult=await runPinnedExecutable(gitExecutable,[
          '-C',root,'diff-tree','--no-commit-id','--name-status','-r','--no-renames','-z',
          sourceCommit,'HEAD',
        ],{maxBuffer:4*1024*1024,timeout:30_000});
        if(diffResult.stderr.length!==0) throw new Error('git diff-tree wrote stderr');
        const fields=decodeChildText(diffResult.stdout,'git diff-tree stdout').split('\0');
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
      importProvenanceVerified:await commandVerified(['scripts/verify-import.py']),
      sourceManifestVerified:await commandVerified(['scripts/source-manifest.py']),
      ethereumFinalityPanicBoundaryVerified:await commandVerified(
        ['scripts/check-ethereum-finality-panic-boundary.py']),
      nativeStatePanicBoundaryVerified:await commandVerified(
        ['scripts/check-native-state-panic-boundary.py']),
      nativePrivacyPanicBoundaryVerified:await commandVerified(
        ['scripts/check-native-privacy-panic-boundary.py']),
      proofProgramPanicBoundaryVerified:await commandVerified(
        ['scripts/check-proof-program-panic-boundary.py']),
      risc0ProgramBinariesVerified:await commandVerified(
        ['scripts/check-risc0-proof-program-binary.py']),
      nativeWalletPanicBoundaryVerified:await commandVerified(
        ['scripts/check-native-wallet-panic-boundary.py']),
    };
    let compiledReserveRuntimeCodeHash=null,compiledReserveInitcodeHash=null;
    try {
      const artifact=await readJson('out/USDOMProofReserve.sol/USDOMProofReserve.json');
      const sourceContents=Object.create(null);
      for(const source of Object.keys(artifact?.metadata?.sources??{})) {
        const absolute=path.resolve(root,source);
        if (absolute!==root && !absolute.startsWith(root+path.sep)) throw new Error('artifact source escapes project root');
        sourceContents[source]=await readDirectFile(source,{label:'reserve compiled source'});
      }
      auditReserveArtifact(artifact,{sourceContents});
      const binding=deriveReserveArtifactBinding({artifact,releaseConfig,sourceContents});
      compiledReserveRuntimeCodeHash=binding.runtimeCodeHash;
      compiledReserveInitcodeHash=binding.initcodeHash;
    } catch { /* reported by the pure assessment */ }
    let compiledCheckpointRegistryRuntimeCodeHash=null,compiledCheckpointRegistryInitcodeHash=null;
    try {
      const artifact=await readJson('out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json');
      const sourceContents=Object.create(null);
      for(const source of Object.keys(artifact?.metadata?.sources??{})) {
        const absolute=path.resolve(root,source);
        if (absolute!==root && !absolute.startsWith(root+path.sep)) throw new Error('artifact source escapes project root');
        sourceContents[source]=await readDirectFile(source,{
          label:'checkpoint-registry compiled source',
        });
      }
      const binding=deriveCheckpointRegistryArtifactBinding({artifact,releaseConfig,sourceContents});
      compiledCheckpointRegistryRuntimeCodeHash=binding.runtimeCodeHash;
      compiledCheckpointRegistryInitcodeHash=binding.initcodeHash;
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
        sourceContents[source]=await readDirectFile(source,{
          label:'finalized-burn verifier compiled source',
        });
      }
      const binding=deriveFinalizedBurnVerifierArtifactBinding({artifact,verifierConfig,sourceContents,
        expectedConfigHash:releaseConfig.verifierConfigHash});
      compiledVerifierRuntimeCodeHash=binding.runtimeCodeHash;
      compiledVerifierInitcodeHash=binding.initcodeHash;
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
        sourceContents[source]=await readDirectFile(source,{
          label:'checkpoint verifier compiled source',
        });
      }
      const binding=deriveCheckpointVerifierArtifactBinding({artifact,
        verifierConfig:checkpointVerifierConfig,sourceContents,
        expectedConfigHash:releaseConfig.checkpointVerifierConfigHash});
      compiledCheckpointVerifierRuntimeCodeHash=binding.runtimeCodeHash;
      compiledCheckpointVerifierInitcodeHash=binding.initcodeHash;
    } catch { /* reported by the pure assessment */ }
    await Promise.all([
      ...(forgeExecutable===null?[]:[assertExecutableUnchanged(forgeExecutable)]),
      assertExecutableUnchanged(gitExecutable),assertExecutableUnchanged(pythonExecutable),
    ]);
    const report = assessMainnetReadiness({mode,requirements,operatorIntent,releaseConfig,evidence,evidenceFiles,
      trustedReleaseSigningKeyFingerprint:process.env.USDOM_RELEASE_SIGNING_KEY_FINGERPRINT??null,
      repositoryState,contractSource,checkpointContractSource,compiledReserveRuntimeCodeHash,
      compiledReserveInitcodeHash,compiledCheckpointRegistryRuntimeCodeHash,
      compiledCheckpointRegistryInitcodeHash,verifierConfig,checkpointVerifierConfig,riscZeroReference,
      compiledVerifierRuntimeCodeHash,compiledVerifierInitcodeHash,
      compiledCheckpointVerifierRuntimeCodeHash,compiledCheckpointVerifierInitcodeHash,
      predeploymentAttestation,coldStartAttestation,nativePrivacyTrustedSetupAttestation,
      nativeScheduledRuntimeActivationAttestation,nativeWalletCustodyAttestation,
      nativeWalletRecoveryAttestation,nativeAttestationApprovalObservation,
      releaseAuthorizationApprovalObservation,nativeRuntimeValidation,
      controlPlaneEvidenceArtifacts,riscZeroHealthSourceCatalog,finalizedBurnE2eReport,
      checkpointProofCapacityReport,securityValidationReport,requirementsSha256,sourceManifestSha256,
      operationsReviewReport,operatorRunbookSha256,reserveReproducibleBuildReport,
      verifierReproducibleBuildReport,
      mainnetForkRehearsalReport,
      mainnetForkRehearsalEvidenceFiles,checkpointBootstrapRatificationReport,
      ethereumCheckpointConsensus,nativePreactivationFacts,checkpointFinalizedEventReport,
      checkpointVerifierReproducibleBuildReport,checkpointRegistryReproducibleBuildReport,
      residualRiskReport,residualRiskDraftSha256,trustedSetupDecisionReport});
    await assertEvidenceByteSnapshotsUnchanged(authorityFileBytes,readRawDirectFile,
      {label:'readiness authority'});
    const output=diagnosticNoBuild
      ? {...report,diagnostic:summarizeReadinessBlockers(report.blockers,{buildSkipped:true})}
      : report;
    if(diagnosticNoBuild) console.log(JSON.stringify(output,null,2));
    else console.log(JSON.stringify(report,null,2));
    if (!report.ready) process.exitCode = 1;
  } catch (error) {
    writePilotFailure('mainnet-readiness',error);
    process.exitCode = 2;
  }
}
