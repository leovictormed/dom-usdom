import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {lstatSync,realpathSync} from 'node:fs';
import {mkdtemp,rm} from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
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
import {readDirectFile as readDirectAbsoluteFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {assertExecutableUnchanged,snapshotExecutable} from '../sdk/stable-executable.mjs';
import {assertEvidenceByteSnapshotsUnchanged} from '../sdk/evidence-byte-snapshot.mjs';
import {runPinnedExecutable} from '../sdk/pinned-executable-child.mjs';
import {summarizeReadinessBlockers} from '../sdk/readiness-diagnostics.mjs';
import {auditReserveArtifact} from '../sdk/reserve-artifact-safety.mjs';
import {validateCheckpointRegistryArtifactPins} from '../sdk/checkpoint-registry-artifact-pins.mjs';
import {buildCheckpointRandomxImageRatification,
  validateCheckpointRandomxImageRatification} from '../sdk/checkpoint-randomx-image-ratification.mjs';
import {closedMainnetPhaseGenerationIdentity,closedMainnetPhaseSha256,
  validateClosedMainnetExecutionPlan,validateClosedMainnetPhaseGenerationIdentity}
  from '../sdk/closed-mainnet-phase-dependency.mjs';
import {applyOperationalClaimsLedger,operationalClaimsReleaseBinding,
  validateOperationalClaimsLedger} from '../sdk/operational-claims-ledger.mjs';
import {buildAuthenticatedFinalizedBurnSubmission,proofReserveConfigurationFromRelease}
  from '../sdk/finalized-burn-submission.mjs';
import {buildCheckpointCapacityArtifactManifest,collectCheckpointCapacityArtifacts} from '../sdk/checkpoint-capacity-artifact-collector.mjs';
import {buildCheckpointProofCapacityReport} from '../sdk/checkpoint-proof-capacity-report.mjs';
import {CHECKPOINT_CAPACITY_MANIFEST_PATH} from '../sdk/checkpoint-capacity-release-evidence-materialization.mjs';
import {validateFinalizedBurnCapacityReport} from '../sdk/finalized-burn-capacity-report.mjs';
import {buildFinalizedBurnCapacityArtifactManifest} from '../sdk/finalized-burn-capacity-artifact-manifest.mjs';
import {proofArtifacts} from './run-finalized-burn-capacity-e2e.mjs';
import {parseProverResourceMetrics} from '../sdk/prover-resource-metrics.mjs';

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
    const sshKeygenExecutable=await snapshotExecutable('ssh-keygen');
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
    const externalAuthorityFileBytes=new Map();
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
    const readExternalAuthorityFile=async(absolute,options)=>{
      const bytes=await readDirectAbsoluteFile(absolute,options);
      const previous=externalAuthorityFileBytes.get(absolute);
      if(previous&&!previous.equals(bytes)) throw new Error(`readiness authority changed during collection: ${absolute}`);
      if(!previous) externalAuthorityFileBytes.set(absolute,Buffer.from(bytes));
      return bytes;
    };
    const readEvidenceFile=readDirectFile;
    const reconstructReleaseValidation=async report=>{
      const ids=Object.fromEntries(report.runs.map(run=>[run.kind,run.runId]));
      const temporary=await mkdtemp(path.join(os.tmpdir(),'usdom-readiness-release-validation-'));
      try {
        const output=path.join(temporary,'report.json');
        await runPinnedExecutable(pythonExecutable,[
          path.join(root,'scripts/materialize-usdom-release-validation-report.py'),
          '--repository',path.resolve(root,'../..'),
          '--jobs-directory',path.join(os.homedir(),'.config/usdom-proof/jobs'),
          '--state-root',path.join(os.homedir(),'.local/state/usdom-proof'),
          '--release-evidence',path.join(root,'config/mainnet-release-evidence.unconfigured.json'),
          '--output',output,'--checkpoint390-run-id',ids.checkpoint390,
          '--randomxCache-run-id',ids.randomxCache,'--nativePrivacy-run-id',ids.nativePrivacy,
        ],{cwd:root,env:{HOME:os.homedir(),LANG:'C.UTF-8',LC_ALL:'C.UTF-8'},
          maxBuffer:1024*1024,timeout:120_000});
        return await readDirectAbsoluteFile(output,{minimum:2,maximum:4*1024*1024,
          privateMode:true,label:'reconstructed release validation report'});
      } finally { await rm(temporary,{recursive:true,force:true}); }
    };
    const [requirementsBytes,sourceManifestBytes,operatorRunbookBytes,residualRiskDraftBytes,
      operatorIntent,releaseConfig,evidence,riscZeroReference,
      contractSourceBytes,checkpointContractSourceBytes] = await Promise.all([
      readDirectFile('config/production-requirements.json'),readDirectFile('MANIFEST.sha256'),
      readDirectFile('docs/CLOSED-MAINNET-LINUX-RUNBOOK.md'),
      readDirectFile('docs/RESIDUAL-RISK-ACCEPTANCE-DRAFT-ETAPA211-2026-10-20.txt'),
      readJson('config/operator-intent.json'),
      readJson('config/proof-reserve.unconfigured.json'),readJson('config/mainnet-release-evidence.unconfigured.json'),
      readJson('config/risc0-ethereum-mainnet-v3.json'),
      readDirectFile('contracts/USDOMProofReserve.sol'),
      readDirectFile('contracts/DOMCheckpointRegistry.sol'),
    ]);
    const contractSource=contractSourceBytes.toString('utf8');
    const checkpointContractSource=checkpointContractSourceBytes.toString('utf8');
    const contractSourceAuthority={reserveBytes:contractSourceBytes,
      checkpointRegistryBytes:checkpointContractSourceBytes};
    const readinessDocumentAuthority={
      operatorIntentBytes:authorityFileBytes.get('config/operator-intent.json'),
      releaseEvidenceBytes:authorityFileBytes.get('config/mainnet-release-evidence.unconfigured.json'),
    };
    const sourceRequirements=parseStrictJsonBytes(requirementsBytes,{
      label:'config/production-requirements.json'});
    let requirements=sourceRequirements;
    const trustedSetupAuthorityBytes=await readDirectFile(riscZeroReference.trusted_setup_authority_path);
    const trustedSetupAuthoritySha256=createHash('sha256').update(trustedSetupAuthorityBytes).digest('hex');
    if(trustedSetupAuthoritySha256!==riscZeroReference.trusted_setup_authority_sha256) {
      throw new Error('RISC Zero trusted-setup authority differs from the mainnet verifier reference');
    }
    const trustedSetupAuthority=parseStrictJsonBytes(trustedSetupAuthorityBytes,{
      label:riscZeroReference.trusted_setup_authority_path,maxBytes:64*1024,maxDepth:8,
    });
    const requirementsSha256=createHash('sha256').update(requirementsBytes).digest('hex');
    const operationalLedgerPath=path.join('/home/leonardov/usdom-mainnet-private/control-plane',
      'operational-claims-ledger.json');
    let operationalPlanBytes=null;
    let operationalArtifactAuditBytes=null;
    try {
      const ledgerBytes=await readExternalAuthorityFile(operationalLedgerPath,{minimum:2,
        maximum:4*1024*1024,exactMode:0o600,label:'operational claims ledger'});
      const generatedPlan=spawnSync(process.execPath,['scripts/write-open-claims-execution-plan.mjs'],{
        cwd:root,encoding:null,env:{PATH:'/usr/bin:/bin'},maxBuffer:16*1024*1024,
      });
      if(generatedPlan.status!==0||generatedPlan.stderr.length!==0||generatedPlan.stdout.length<2) {
        throw new Error('cannot reproduce operational claims plan');
      }
      const planBytes=generatedPlan.stdout;
      operationalPlanBytes=Buffer.from(planBytes);
      const plan=validateClosedMainnetExecutionPlan(parseStrictJsonBytes(planBytes,{
        label:'operational claims plan',maxBytes:16*1024*1024,maxDepth:64}));
      const controlDirectory='/home/leonardov/usdom-mainnet-private/control-plane';
      const planPath=path.join('/home/leonardov/usdom-mainnet-public',
        `open-claims-execution-plan-v1-${closedMainnetPhaseSha256(planBytes)}.json`);
      const installedPlanBytes=await readExternalAuthorityFile(planPath,{minimum:2,
        maximum:16*1024*1024,exactMode:0o644,label:'published operational claims plan'});
      if(!installedPlanBytes.equals(planBytes)) throw new Error('published operational claims plan differs from current sources');
      const controlStat=lstatSync(controlDirectory,{bigint:true});
      const executionLockStat=lstatSync(path.join(controlDirectory,'phase-execution-lock'),{bigint:true});
      if(!controlStat.isDirectory()||controlStat.uid!==BigInt(process.getuid())
          ||(controlStat.mode&0o777n)!==0o700n||realpathSync(controlDirectory)!==controlDirectory) {
        throw new Error('operational claims evidence directory is unsafe');
      }
      const phaseGenerationPath=path.join(controlDirectory,'.phase-generation.json');
      const phaseGenerationBytes=await readExternalAuthorityFile(phaseGenerationPath,{minimum:2,
        maximum:64*1024,exactMode:0o600,label:'phase generation identity'});
      const phaseGenerationIdentity=parseStrictJsonBytes(phaseGenerationBytes,{
        label:'phase generation identity',maxBytes:64*1024,maxDepth:8});
      validateClosedMainnetPhaseGenerationIdentity(phaseGenerationIdentity,
        closedMainnetPhaseGenerationIdentity({planBytes,plan,evidenceDirectoryStat:controlStat,executionLockStat,planPath}));
      const releaseConfigBytes=authorityFileBytes.get('config/proof-reserve.unconfigured.json');
      const releaseEvidenceBytes=authorityFileBytes.get('config/mainnet-release-evidence.unconfigured.json');
      const phaseArtifactAudit=spawnSync(process.execPath,
        ['scripts/check-closed-mainnet-phase-artifacts.mjs','require-pilot-complete'],{
          cwd:root,encoding:null,env:process.env,maxBuffer:16*1024*1024,
        });
      if(phaseArtifactAudit.status!==0||phaseArtifactAudit.stderr.length!==0
          ||phaseArtifactAudit.stdout.length<2) {
        throw new Error('terminal phase artifacts do not independently validate during readiness');
      }
      parseStrictJsonBytes(phaseArtifactAudit.stdout,{label:'terminal phase artifact audit',
        maxBytes:16*1024*1024,maxDepth:64});
      operationalArtifactAuditBytes=Buffer.from(phaseArtifactAudit.stdout);
      const binding=operationalClaimsReleaseBinding({planBytes,plan,requirementsBytes,
        releaseConfigBytes,releaseEvidenceBytes,phaseGenerationBytes,phaseGenerationIdentity,
        phaseArtifactAuditBytes:phaseArtifactAudit.stdout});
      const completionDirectory=path.join(controlDirectory,'.phase-completions');
      const phaseCompletionBytes=new Map();
      for(const artifact of plan.phaseArtifacts.slice(0,-1)) {
        const name=`${String(artifact.ordinal).padStart(2,'0')}-${artifact.phase}.json`;
        phaseCompletionBytes.set(artifact.phase,await readExternalAuthorityFile(path.join(completionDirectory,name),{
          minimum:2,maximum:1024*1024,exactMode:0o600,label:`${artifact.phase} completion`}));
      }
      const ledger=parseStrictJsonBytes(ledgerBytes,{label:'operational claims ledger',
        maxBytes:4*1024*1024,maxDepth:32});
      validateOperationalClaimsLedger(ledger,{binding,plan,phaseCompletionBytes});
      requirements=applyOperationalClaimsLedger(sourceRequirements,ledger);
    } catch(error) {
      if(error?.code!=='ENOENT') throw error;
    }
    const requirementsAuthority={bytes:Buffer.from(JSON.stringify(requirements))};
    const sourceManifestSha256=createHash('sha256').update(sourceManifestBytes).digest('hex');
    const toolchainLockBytes=await readDirectFile('config/mainnet-toolchain-lock.json');
    const toolchainLock=parseStrictJsonBytes(toolchainLockBytes,{
      label:'config/mainnet-toolchain-lock.json',maxBytes:1024*1024,maxDepth:16,
    });
    const toolchainLockSha256=createHash('sha256').update(toolchainLockBytes).digest('hex');
    const cargoLockSha256=toolchainLock?.files?.find(item=>item?.path==='../../Cargo.lock')?.sha256??null;
    const operatorRunbookSha256=createHash('sha256').update(operatorRunbookBytes).digest('hex');
    const residualRiskDraftSha256=createHash('sha256').update(residualRiskDraftBytes).digest('hex');
    const evidenceFiles = Object.create(null);
    const evidenceFileBytes = new Map();
    const documentArray=value=>Array.isArray(value)?value:[];
    const documents = [evidence.reproducibleBuildReport,evidence.verifierReproducibleBuildReport,
      evidence.checkpointRegistryReproducibleBuildReport,evidence.checkpointVerifierReproducibleBuildReport,
      evidence.checkpointBootstrapRatificationReport,evidence.checkpointFinalizedEventReport,
      evidence.checkpointProofCapacityReport,
      evidence.finalizedBurnCapacityReport,
      evidence.releaseValidationReport,
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
      evidence.controlPlane?.checkpointGuardian?.configurationReport,
      evidence.controlPlane?.usdtCustody?.configurationReport].filter(Boolean);
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
      checkpointGuardianControlReport,usdtCustodyControlReport,controlPlaneSeparationReport,
      controlPlaneRecoveryDrillReport,safeRecoveryFinalEvidenceBundle,
      riscZeroHealthSourceCatalog,finalizedBurnE2eReport,
      checkpointProofCapacityReport,finalizedBurnCapacityReport,releaseValidationReport,securityValidationReport,operationsReviewReport,
      reserveReproducibleBuildReport,verifierReproducibleBuildReport,
      mainnetForkRehearsalReport,checkpointBootstrapRatificationReport,
      ethereumCheckpointConsensus,nativePreactivationFacts,
      checkpointFinalizedEventReport,checkpointVerifierReproducibleBuildReport,
      checkpointRegistryReproducibleBuildReport,residualRiskReport,
      trustedSetupDecisionReport,trustedSetupVerificationReport]=await Promise.all([
      readOptionalEvidenceJson(evidence.controlPlaneEvidenceBundle,'control-plane evidence bundle'),
      readOptionalEvidenceJson(evidence.controlPlane?.governance?.configurationReport,
        'governance control report'),
      readOptionalEvidenceJson(evidence.controlPlane?.guardian?.configurationReport,
        'guardian control report'),
      readOptionalEvidenceJson(evidence.controlPlane?.checkpointGuardian?.configurationReport,
        'checkpoint guardian control report'),
      readOptionalEvidenceJson(evidence.controlPlane?.usdtCustody?.configurationReport,
        'USDT custody control report'),
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
      readOptionalEvidenceJson(evidence.finalizedBurnCapacityReport,'finalized-burn capacity report'),
      readOptionalEvidenceJson(evidence.releaseValidationReport,
        'release validation report'),
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
      readOptionalEvidenceJson(evidence.trustedSetup?.transcript,
        'RISC Zero trusted-setup verification report'),
    ]);
    const finalizedBurnE2eAuthority={
      reportBytes:evidenceFileBytes.get(evidence.realFinalizedEndToEndReport?.path),
    };
    const riscZeroHealthSourceCatalogAuthority={
      catalogBytes:evidenceFileBytes.get(evidence.riscZeroHealthSourceCatalog?.path),
    };
    const releaseAssuranceAuthority={
      securityValidationReportBytes:evidenceFileBytes.get(evidence.securityValidationReport?.path),
      operationsReviewReportBytes:evidenceFileBytes.get(evidence.operationsReviewReport?.path),
      reserveReproducibleBuildReportBytes:evidenceFileBytes.get(evidence.reproducibleBuildReport?.path),
      verifierReproducibleBuildReportBytes:evidenceFileBytes.get(evidence.verifierReproducibleBuildReport?.path),
      mainnetForkRehearsalReportBytes:evidenceFileBytes.get(evidence.mainnetForkRehearsalReport?.path),
      checkpointVerifierReproducibleBuildReportBytes:evidenceFileBytes.get(
        evidence.checkpointVerifierReproducibleBuildReport?.path),
      checkpointRegistryReproducibleBuildReportBytes:evidenceFileBytes.get(
        evidence.checkpointRegistryReproducibleBuildReport?.path),
      residualRiskReportBytes:evidenceFileBytes.get(evidence.residualRiskAcceptanceReport?.path),
    };
    const trustedSetupDecisionReportAuthority={
      reportBytes:evidenceFileBytes.get(evidence.trustedSetup?.decisionReport?.path),
    };
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
        usdtCustody:usdtCustodyControlReport,
      },
      separationReport:controlPlaneSeparationReport,
      recoveryDrillReport:controlPlaneRecoveryDrillReport,
      finalBundle:safeRecoveryFinalEvidenceBundle,
    };
    const controlPlaneEvidenceAuthority={
      bundleBytes:evidenceFileBytes.get(evidence.controlPlaneEvidenceBundle?.path),
      roleReportBytes:Object.fromEntries(['governance','guardian','checkpointGuardian','usdtCustody'].map(role=>
        [role,evidenceFileBytes.get(evidence.controlPlane?.[role]?.configurationReport?.path)])),
      separationReportBytes:evidenceFileBytes.get(evidence.controlPlaneSeparationReport?.path),
      recoveryDrillReportBytes:evidenceFileBytes.get(evidence.controlPlaneRecoveryDrillReport?.path),
      finalBundleBytes:evidenceFileBytes.get(evidence.safeRecoveryFinalEvidenceBundle?.path),
    };
    const checkpointBootstrapRatificationAuthority={
      reportBytes:evidenceFileBytes.get(evidence.checkpointBootstrapRatificationReport?.path),
      consensusBytes:authorityFileBytes.get('evidence/native-preactivation/ethereum-checkpoint-consensus.json'),
      nativeFactsBytes:authorityFileBytes.get('config/native-preactivation-facts.unconfigured.json'),
    };
    const checkpointFinalizedEventAuthority={
      reportBytes:evidenceFileBytes.get(evidence.checkpointFinalizedEventReport?.path),
    };
    const predeploymentAttestationAuthority={
      reportBytes:evidenceFileBytes.get(evidence.mainnetPredeploymentAttestationReport?.path),
    };
    const coldStartAttestationAuthority={
      reportBytes:evidenceFileBytes.get(evidence.mainnetColdStartAttestationReport?.path),
    };
    const configurationAuthority={
      releaseConfigBytes:authorityFileBytes.get('config/proof-reserve.unconfigured.json'),
      nativeRuntimeManifestBytes:evidenceFileBytes.get(evidence.nativeRuntimeManifest?.path),
      scheduledRuntimeAttestationBytes:evidenceFileBytes.get(
        evidence.nativeScheduledRuntimeActivationAttestationReport?.path),
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
    const nativeReleaseAttestationAuthority={
      nativePrivacyTrustedSetupBytes:evidenceFileBytes.get(
        evidence.nativePrivacyTrustedSetupAttestationReport?.path),
      nativeScheduledRuntimeActivationBytes:evidenceFileBytes.get(
        evidence.nativeScheduledRuntimeActivationAttestationReport?.path),
      nativeWalletCustodyBytes:evidenceFileBytes.get(evidence.nativeWalletCustodyAttestationReport?.path),
      nativeWalletRecoveryBytes:evidenceFileBytes.get(evidence.nativeWalletRecoveryAttestationReport?.path),
    };
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
    const approvalAuthority=value=>{
      if(!value) return null;
      const bytes=Buffer.from(JSON.stringify(value));
      return {bytes,sha256:createHash('sha256').update(bytes).digest('hex')};
    };
    const approvalObservationAuthority={
      nativeAttestations:approvalAuthority(nativeAttestationApprovalObservation),
      releaseAuthorization:approvalAuthority(releaseAuthorizationApprovalObservation),
    };
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
        const result=await runPinnedExecutable(gitExecutable,[
          '-c',`gpg.ssh.program=${sshKeygenExecutable.path}`,'-C',root,...args,
        ],{
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
    const repositoryStateAuthority={bytes:Buffer.from(JSON.stringify(repositoryState))};
    const compiledArtifactBindingErrors=Object.create(null);
    const compiledArtifactAuthority=Object.create(null);
    const recordArtifactBindingError=(name,error)=>{
      const message=error instanceof Error?error.message:'non-Error binding failure';
      compiledArtifactBindingErrors[name]=message.replaceAll(root,'<project>').slice(0,512);
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
      compiledArtifactAuthority.reserve={artifactBytes:authorityFileBytes.get(
        'out/USDOMProofReserve.sol/USDOMProofReserve.json'),sourceContents};
      auditReserveArtifact(artifact,{sourceContents});
      const binding=deriveReserveArtifactBinding({artifact,releaseConfig,sourceContents});
      compiledArtifactAuthority.reserve.bindingBytes=Buffer.from(JSON.stringify(binding));
      compiledReserveRuntimeCodeHash=binding.runtimeCodeHash;
      compiledReserveInitcodeHash=binding.initcodeHash;
    } catch(error) { recordArtifactBindingError('reserve',error); }
    let compiledCheckpointRegistryRuntimeCodeHash=null,compiledCheckpointRegistryInitcodeHash=null;
    let compiledCheckpointRegistryBinding=null;
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
      compiledArtifactAuthority.checkpointRegistry={artifactBytes:authorityFileBytes.get(
        'out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json'),sourceContents};
      const binding=deriveCheckpointRegistryArtifactBinding({artifact,releaseConfig,sourceContents});
      compiledArtifactAuthority.checkpointRegistry.bindingBytes=Buffer.from(JSON.stringify(binding));
      compiledCheckpointRegistryBinding=binding;
      compiledCheckpointRegistryRuntimeCodeHash=binding.runtimeCodeHash;
      compiledCheckpointRegistryInitcodeHash=binding.initcodeHash;
    } catch(error) { recordArtifactBindingError('checkpointRegistry',error); }
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
      compiledArtifactAuthority.finalizedBurnVerifier={artifactBytes:authorityFileBytes.get(
        'out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json'),
      sourceContents};
      const binding=deriveFinalizedBurnVerifierArtifactBinding({artifact,verifierConfig,sourceContents,
        expectedConfigHash:releaseConfig.verifierConfigHash});
      compiledArtifactAuthority.finalizedBurnVerifier.bindingBytes=Buffer.from(JSON.stringify(binding));
      compiledVerifierRuntimeCodeHash=binding.runtimeCodeHash;
      compiledVerifierInitcodeHash=binding.initcodeHash;
    } catch(error) { recordArtifactBindingError('finalizedBurnVerifier',error); }
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
      compiledArtifactAuthority.checkpointVerifier={artifactBytes:authorityFileBytes.get(
        'out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json'),sourceContents};
      const binding=deriveCheckpointVerifierArtifactBinding({artifact,
        verifierConfig:checkpointVerifierConfig,sourceContents,
        expectedConfigHash:releaseConfig.checkpointVerifierConfigHash});
      compiledArtifactAuthority.checkpointVerifier.bindingBytes=Buffer.from(JSON.stringify(binding));
      compiledCheckpointVerifierRuntimeCodeHash=binding.runtimeCodeHash;
      compiledCheckpointVerifierInitcodeHash=binding.initcodeHash;
    } catch(error) { recordArtifactBindingError('checkpointVerifier',error); }
    await Promise.all([
      ...(forgeExecutable===null?[]:[assertExecutableUnchanged(forgeExecutable)]),
      assertExecutableUnchanged(gitExecutable),assertExecutableUnchanged(sshKeygenExecutable),
      assertExecutableUnchanged(pythonExecutable),
    ]);
    let checkpointProofCapacityAuthority=null;
    if(checkpointProofCapacityReport!==null) {
      const runRoot=path.join(os.homedir(),'.local/share/dom-usdom/prover-capacity/checkpoint/runs',checkpointProofCapacityReport.runId);
      const labRoot=path.join(runRoot,'work/labs/usdom-reserve');
      const runMetadata=lstatSync(runRoot,{bigint:true});
      if(!runMetadata.isDirectory()||runMetadata.uid!==BigInt(process.getuid())||(runMetadata.mode&0o077n)!==0n
          ||realpathSync(runRoot)!==runRoot) throw new Error('checkpoint capacity run root is unsafe');
      const [manifestBytes,runManifestBytes]=await Promise.all([
        readDirectFile(CHECKPOINT_CAPACITY_MANIFEST_PATH),
        readDirectAbsoluteFile(path.join(runRoot,'artifact-manifest.json'),{minimum:2,maximum:16*1024*1024,privateMode:true,label:'checkpoint capacity run manifest'}),
      ]);
      if(!manifestBytes.equals(runManifestBytes)||createHash('sha256').update(manifestBytes).digest('hex')!==checkpointProofCapacityReport.artifactManifestSha256) throw new Error('checkpoint capacity manifest differs from its authenticated run');
      const regeneratedManifest=await buildCheckpointCapacityArtifactManifest(labRoot,checkpointProofCapacityReport.runId);
      if(!regeneratedManifest.bytes.equals(manifestBytes)) throw new Error('checkpoint capacity manifest differs from the complete run artifact inventory');
      const byName=new Map(checkpointProofCapacityReport.layers.map(layer=>[layer.name,layer]));
      const metric=name=>({provingWallMilliseconds:byName.get(name).provingWallMilliseconds,peakResidentKiB:byName.get(name).peakResidentKiB});
      const collected=await collectCheckpointCapacityArtifacts(labRoot,{checkpointVerifierConfig,metrics:{randomx:metric('randomx'),randomxAggregate:metric('randomx-aggregate'),segment:metric('segment'),outer:metric('outer'),compression:{provingWallMilliseconds:checkpointProofCapacityReport.compressionWallMilliseconds,peakResidentKiB:checkpointProofCapacityReport.compressionPeakResidentKiB}}});
      const {schema,artifactSetCommitmentSchema,outerJournalDigestSha256,layers,...base}=checkpointProofCapacityReport;
      const reconstructedReport=buildCheckpointProofCapacityReport(base,collected.measuredLayers,{evidence,releaseConfig,checkpointVerifierConfig,riscZeroReference});
      checkpointProofCapacityAuthority={reportBytes:evidenceFileBytes.get(evidence.checkpointProofCapacityReport.path),manifestBytes,reconstructedReport};
    }
    let finalizedBurnCapacityAuthority=null;
    if(finalizedBurnCapacityReport!==null) {
      const runRoot=path.join(os.homedir(),'.local/share/dom-usdom/prover-capacity/finalized-burn/evm-runs',finalizedBurnCapacityReport.runId);
      const runMetadata=lstatSync(runRoot,{bigint:true});
      if(!runMetadata.isDirectory()||runMetadata.uid!==BigInt(process.getuid())||(runMetadata.mode&0o077n)!==0n
          ||realpathSync(runRoot)!==runRoot) throw new Error('finalized-burn capacity run root is unsafe');
      const installedManifest=await readDirectFile('evidence/finalized-burn-capacity/finalized-burn-capacity-artifact-manifest.json');
      const [runManifest,runReportBytes,runStatusBytes]=await Promise.all([
        readDirectAbsoluteFile(path.join(runRoot,'artifact-manifest.json'),{minimum:2,maximum:16*1024*1024,privateMode:true,label:'finalized-burn capacity manifest'}),
        readDirectAbsoluteFile(path.join(runRoot,'capacity-report.json'),{minimum:2,maximum:1024*1024,privateMode:true,label:'finalized-burn capacity report'}),
        readDirectAbsoluteFile(path.join(runRoot,'run-status.json'),{minimum:2,maximum:64*1024,privateMode:true,label:'finalized-burn capacity status'}),
      ]);
      const installedReportBytes=evidenceFileBytes.get(evidence.finalizedBurnCapacityReport.path);
      if(!runReportBytes.equals(installedReportBytes)) throw new Error('installed finalized-burn capacity report differs from authenticated run');
      const runStatus=parseStrictJsonBytes(runStatusBytes,{label:'finalized-burn capacity status',maxBytes:64*1024,maxDepth:8});
      if(runStatus.schema!=='usdom-finalized-burn-capacity-run-v1'||runStatus.status!=='succeeded'
          ||runStatus.runId!==finalizedBurnCapacityReport.runId
          ||runStatus.reportSha256!==createHash('sha256').update(runReportBytes).digest('hex')) throw new Error('finalized-burn capacity status does not authenticate report');
      const regenerated=await buildFinalizedBurnCapacityArtifactManifest(runRoot,finalizedBurnCapacityReport.runId);
      if(!installedManifest.equals(runManifest)||!runManifest.equals(regenerated.bytes)
          ||createHash('sha256').update(runManifest).digest('hex')!==finalizedBurnCapacityReport.artifactManifestSha256) throw new Error('finalized-burn capacity manifest differs from complete run graph');
      const workLab=path.join(runRoot,'work/labs/usdom-reserve'),artifacts=await proofArtifacts(workLab);
      const [input,metricsBytes,isolatedReceipt]=await Promise.all([
        readDirectAbsoluteFile(path.join(workLab,'evidence/finalized-burn-source/finalized-burn-input.bin'),{minimum:1,maximum:16*1024*1024,privateMode:true,label:'capacity input'}),
        readDirectAbsoluteFile(path.join(runRoot,'input-snapshots/source-prover-time.log'),{minimum:1,maximum:1024*1024,privateMode:true,label:'capacity metrics'}),
        readDirectAbsoluteFile(path.join(runRoot,'isolated-evm-receipt.json'),{minimum:2,maximum:64*1024,privateMode:true,label:'capacity EVM receipt'}),
      ]),metrics=parseProverResourceMetrics(metricsBytes.toString('utf8'));
      if(createHash('sha256').update(input).digest('hex')!==finalizedBurnCapacityReport.inputSha256
          ||input.length!==finalizedBurnCapacityReport.inputBytes
          ||artifacts.receiptIdentity.sha256!==finalizedBurnCapacityReport.succinctReceiptSha256
          ||String(artifacts.receiptIdentity.bytes)!==finalizedBurnCapacityReport.succinctReceiptBytes
          ||artifacts.groth16Identity.sha256!==finalizedBurnCapacityReport.groth16ReceiptSha256
          ||String(artifacts.groth16Identity.bytes)!==finalizedBurnCapacityReport.groth16ReceiptBytes
          ||createHash('sha256').update(artifacts.seal).digest('hex')!==finalizedBurnCapacityReport.evmSealSha256
          ||String(artifacts.seal.length)!==finalizedBurnCapacityReport.evmSealBytes
          ||metrics.provingWallMilliseconds!==finalizedBurnCapacityReport.provingWallMilliseconds
          ||metrics.peakResidentKiB!==finalizedBurnCapacityReport.peakResidentKiB
          ||createHash('sha256').update(isolatedReceipt).digest('hex')!==finalizedBurnCapacityReport.isolatedEvmReceiptSha256) throw new Error('finalized-burn capacity report differs from preserved graph');
      validateFinalizedBurnCapacityReport(finalizedBurnCapacityReport,{riscZeroReference});
      const finalManifest=await buildFinalizedBurnCapacityArtifactManifest(runRoot,finalizedBurnCapacityReport.runId);
      if(!finalManifest.bytes.equals(runManifest)) throw new Error('finalized-burn capacity graph changed during validation');
      finalizedBurnCapacityAuthority={reportBytes:installedReportBytes,manifestBytes:runManifest,validated:true};
    }
    let checkpointRegistryArtifactPinsReport=null,checkpointRegistryArtifactPinsAuthority=null;
    const registryPinsPath=process.env.USDOM_CHECKPOINT_REGISTRY_ARTIFACT_PINS;
    if(registryPinsPath!==undefined) {
      if(!path.isAbsolute(registryPinsPath)) throw new Error('registry pins report path must be absolute');
      const reportBytes=await readExternalAuthorityFile(registryPinsPath,{
        minimum:2,maximum:64*1024,privateMode:true,label:'checkpoint registry artifact pins report',
      });
      checkpointRegistryArtifactPinsReport=parseStrictJsonBytes(reportBytes,
        {label:'checkpoint registry artifact pins report',maxBytes:64*1024,maxDepth:8});
      const [artifactBytes,releaseBytes]=await Promise.all([
        readDirectFile('out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json'),
        readDirectFile('config/proof-reserve.unconfigured.json'),
      ]);
      checkpointRegistryArtifactPinsAuthority={reportBytes,binding:compiledCheckpointRegistryBinding,
        artifactBytes,releaseConfigBytes:releaseBytes};
      validateCheckpointRegistryArtifactPins(checkpointRegistryArtifactPinsReport,
        checkpointRegistryArtifactPinsAuthority);
    }
    let checkpointRandomxImageRatificationReport=null,checkpointRandomxImageRatificationAuthority=null;
    const randomxRatificationPath=process.env.USDOM_CHECKPOINT_RANDOMX_IMAGE_RATIFICATION;
    if(randomxRatificationPath!==undefined) {
      if(!path.isAbsolute(randomxRatificationPath)) throw new Error('RandomX ratification path must be absolute');
      const reportBytes=await readExternalAuthorityFile(randomxRatificationPath,{
        minimum:2,maximum:64*1024,privateMode:true,label:'RandomX ImageID ratification',
      });
      checkpointRandomxImageRatificationReport=parseStrictJsonBytes(reportBytes,
        {label:'RandomX ImageID ratification',maxBytes:64*1024,maxDepth:8});
      const [iidBytes,indexBytes]=await Promise.all([
        readExternalAuthorityFile(path.resolve(root,'../../crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.iid'),
          {minimum:32,maximum:128,label:'RandomX ImageID file'}),
        readDirectFile('evidence/randomx-receipt-set/randomx-receipt-set-index.json'),
      ]);
      const receiptIndex=parseStrictJsonBytes(indexBytes,{label:'RandomX receipt index',maxBytes:4*1024*1024,maxDepth:32});
      const receiptBytes=[];
      for(const record of receiptIndex.receipts??[]) {
        if(typeof record?.receipt_file!=='string'||!/^[A-Za-z0-9._-]+$/.test(record.receipt_file)) throw new Error('RandomX receipt index path is invalid');
        receiptBytes.push(await readDirectFile(`evidence/randomx-receipt-set/${record.receipt_file}`));
      }
      const imageId=String(checkpointVerifierConfig?.randomxReceiptImageId??'').replace(/^0x/,'').toLowerCase();
      if(iidBytes.toString('ascii')!==`${imageId}\n`) throw new Error('RandomX ImageID file differs from the current checkpoint verifier configuration');
      const rebuilt=buildCheckpointRandomxImageRatification({imageId,
        imageIdFileSha256:createHash('sha256').update(iidBytes).digest('hex'),
        receiptIndexSha256:createHash('sha256').update(indexBytes).digest('hex'),receiptIndex});
      if(JSON.stringify(checkpointRandomxImageRatificationReport)!==JSON.stringify(rebuilt)) {
        throw new Error('RandomX ImageID ratification differs from current receipt artifacts');
      }
      checkpointRandomxImageRatificationAuthority={reportBytes,imageIdBytes:iidBytes,receiptIndexBytes:indexBytes,receiptBytes};
      validateCheckpointRandomxImageRatification(checkpointRandomxImageRatificationReport,
        checkpointRandomxImageRatificationAuthority);
    }
    let checkpointRestartWitnessReport=null,checkpointRestartWitnessAuthority=null;
    const restartReportPath=process.env.USDOM_CHECKPOINT_RESTART_WITNESS_REPORT;
    if(restartReportPath!==undefined) {
      if(!path.isAbsolute(restartReportPath)) throw new Error('restart witness report path must be absolute');
      const reportBytes=await readExternalAuthorityFile(restartReportPath,{
        minimum:2,maximum:64*1024,privateMode:true,label:'checkpoint restart witness report',
      });
      checkpointRestartWitnessReport=parseStrictJsonBytes(reportBytes,
        {label:'checkpoint restart witness report',maxBytes:64*1024,maxDepth:8});
      const manifestBytes=await readDirectFile('evidence/native-runtime/native-usdom-v2.json');
      const manifest=parseStrictJsonBytes(manifestBytes,{label:'native runtime manifest',maxBytes:4*1024*1024,maxDepth:32});
      const witnessName=manifest.restart_checkpoint?.witness_file;
      if(typeof witnessName!=='string'||!/^[A-Za-z0-9._-]+$/.test(witnessName)) throw new Error('native runtime restart witness path is invalid');
      const witnessBytes=await readDirectFile(`evidence/native-runtime/${witnessName}`);
      if(checkpointRestartWitnessReport.manifestSha256!==createHash('sha256').update(manifestBytes).digest('hex')
          ||checkpointRestartWitnessReport.witnessSha256!==createHash('sha256').update(witnessBytes).digest('hex')
          ||manifest.restart_checkpoint?.witness_sha256!==checkpointRestartWitnessReport.witnessSha256) {
        throw new Error('restart witness report differs from current manifest or witness bytes');
      }
      checkpointRestartWitnessAuthority={reportBytes,manifestBytes,witnessBytes};
      validateCheckpointRestartWitnessReport(checkpointRestartWitnessReport,checkpointRestartWitnessAuthority);
    }
    let finalizedBurnRecursiveCompletionReport=null,finalizedBurnRecursiveCompletionAuthority=null;
    const burnCompletionPath=process.env.USDOM_FINALIZED_BURN_RECURSIVE_COMPLETION;
    if(burnCompletionPath!==undefined) {
      if(!path.isAbsolute(burnCompletionPath)) throw new Error('finalized-burn completion path must be absolute');
      const completionBytes=await readExternalAuthorityFile(burnCompletionPath,{
        minimum:2,maximum:64*1024,privateMode:true,label:'finalized-burn recursive completion',
      });
      finalizedBurnRecursiveCompletionReport=parseStrictJsonBytes(completionBytes,
        {label:'finalized-burn recursive completion',maxBytes:64*1024,maxDepth:8});
      const currentPaths={checkpointOuterReceiptSha256:'evidence/checkpoint-outer-receipt-set/checkpoint-outer-receipt.bin',
        checkpointOuterReceiptIndexSha256:'evidence/checkpoint-outer-receipt-set/checkpoint-outer-receipt-set-index.json',
        finalizedBurnReceiptSha256:'evidence/finalized-burn-receipt/finalized-burn-receipt.bin',
        finalizedBurnReceiptIndexSha256:'evidence/finalized-burn-receipt/finalized-burn-receipt-index.json',
        finalizedBurnProofIndexSha256:'evidence/finalized-burn-evm-proof/finalized-burn-evm-proof-index.json',
        finalizedBurnSourceIndexSha256:'evidence/finalized-burn-source/finalized-burn-source-index.json',
        finalizedBurnSourceInputSha256:'evidence/finalized-burn-source/finalized-burn-input.bin',
        finalizedBurnEvmSealSha256:'evidence/finalized-burn-evm-proof/finalized-burn-evm-seal.bin',
        finalizedBurnGroth16ReceiptSha256:'evidence/finalized-burn-evm-proof/finalized-burn-groth16-receipt.bin',
        releaseConfigSha256:'config/proof-reserve.unconfigured.json',
        verifierConfigSha256:'config/finalized-burn-verifier.unconfigured.json'};
      const currentBytes=Object.create(null);
      for(const [field,relative] of Object.entries(currentPaths)) {
        currentBytes[field]=await readDirectFile(relative);
        if(finalizedBurnRecursiveCompletionReport[field]!==createHash('sha256').update(currentBytes[field]).digest('hex')) {
          throw new Error(`finalized-burn recursive completion differs from current bytes: ${relative}`);
        }
      }
      const [outerIndex,burnIndex,burnProofIndex]=[
        parseStrictJsonBytes(currentBytes.checkpointOuterReceiptIndexSha256,{label:'checkpoint outer receipt index',maxBytes:4*1024*1024,maxDepth:32}),
        parseStrictJsonBytes(currentBytes.finalizedBurnReceiptIndexSha256,{label:'finalized-burn receipt index',maxBytes:1024*1024,maxDepth:16}),
        parseStrictJsonBytes(currentBytes.finalizedBurnProofIndexSha256,{label:'finalized-burn EVM proof index',maxBytes:1024*1024,maxDepth:16}),
      ];
      if(outerIndex.receipt_sha256!==finalizedBurnRecursiveCompletionReport.checkpointOuterReceiptSha256
          ||burnIndex.receipt_sha256!==finalizedBurnRecursiveCompletionReport.finalizedBurnReceiptSha256) {
        throw new Error('finalized-burn recursive completion receipt/index binding is stale');
      }
      if(burnProofIndex.groth16_receipt_file!=='finalized-burn-groth16-receipt.bin'
          ||burnProofIndex.groth16_receipt_sha256
            !==finalizedBurnRecursiveCompletionReport.finalizedBurnGroth16ReceiptSha256
          ||burnProofIndex.groth16_receipt_bytes
            !==currentBytes.finalizedBurnGroth16ReceiptSha256.length) {
        throw new Error('finalized-burn recursive completion Groth16 receipt binding is stale');
      }
      buildAuthenticatedFinalizedBurnSubmission({
        reserveConfiguration:proofReserveConfigurationFromRelease(releaseConfig),
        verifierConfiguration:verifierConfig,
        sourceIndex:currentBytes.finalizedBurnSourceIndexSha256,
        sourceInput:currentBytes.finalizedBurnSourceInputSha256,
        receiptIndex:currentBytes.finalizedBurnReceiptIndexSha256,
        proofIndex:currentBytes.finalizedBurnProofIndexSha256,
        evmSeal:currentBytes.finalizedBurnEvmSealSha256,
        releaseConfigSha256:finalizedBurnRecursiveCompletionReport.releaseConfigSha256,
      });
      finalizedBurnRecursiveCompletionAuthority={
        completionBytes,
        checkpointOuterReceipt:currentBytes.checkpointOuterReceiptSha256,
        checkpointOuterReceiptIndex:currentBytes.checkpointOuterReceiptIndexSha256,
        finalizedBurnReceipt:currentBytes.finalizedBurnReceiptSha256,
        finalizedBurnReceiptIndex:currentBytes.finalizedBurnReceiptIndexSha256,
        finalizedBurnProofIndex:currentBytes.finalizedBurnProofIndexSha256,
        finalizedBurnSourceIndex:currentBytes.finalizedBurnSourceIndexSha256,
        finalizedBurnSourceInput:currentBytes.finalizedBurnSourceInputSha256,
        finalizedBurnEvmSeal:currentBytes.finalizedBurnEvmSealSha256,
        finalizedBurnGroth16Receipt:currentBytes.finalizedBurnGroth16ReceiptSha256,
        releaseConfig:currentBytes.releaseConfigSha256,verifierConfig:currentBytes.verifierConfigSha256,
      };
    }
    let pilotFundsSnapshot=null,pilotFundsAuthorizationState=null,pilotFundsAuthority=null;
    try {
      const [snapshotBytes,authorizationStateBytes]=await Promise.all([
        readDirectFile('evidence/authorization/pilot-funds-snapshot.json'),
        readDirectFile('evidence/authorization/pilot-funds-authorization-state.json'),
      ]);
      pilotFundsSnapshot=parseStrictJsonBytes(snapshotBytes,{label:'pilot funds snapshot'});
      pilotFundsAuthorizationState=parseStrictJsonBytes(authorizationStateBytes,
        {label:'pilot funds authorization state'});
      pilotFundsAuthority={snapshotBytes,authorizationStateBytes};
    } catch { /* pure assessment reports the missing/invalid authorization */ }
    let nativePrivacyCeremonyAuthority=null;
    if(requirements?.native_privacy_trusted_setup_ceremony_completed===true
        ||requirements?.native_privacy_production_verifying_key_installed===true) {
      try {
        const ceremonyRoot='/home/leonardov/usdom-mainnet-private/native-privacy-ceremony';
        const installationRoot=path.join(os.homedir(),'.local/share/dom-usdom/mainnet-privacy');
        const [transcriptBytes,circuitBytes,finalProvingKeyBytes,verifyingKeyBytes,
          installationReceiptBytes,installedTranscriptBytes,installedVerifyingKeyBytes,
          installedRuntimeManifestBytes]=await Promise.all([
          readExternalAuthorityFile(path.join(ceremonyRoot,'transcript.json'),{minimum:2,maximum:8*1024*1024,exactMode:0o600,label:'native privacy ceremony transcript'}),
          readExternalAuthorityFile(path.join(ceremonyRoot,'spend-circuit.r1cs'),{minimum:1,maximum:64*1024*1024,exactMode:0o600,label:'native privacy spend circuit'}),
          readExternalAuthorityFile(path.join(ceremonyRoot,'final-proving-key.bin'),{minimum:1,maximum:64*1024*1024,exactMode:0o600,label:'native privacy final proving key'}),
          readExternalAuthorityFile(path.join(ceremonyRoot,'spend-verifying-key.bin'),{minimum:1,maximum:16*1024*1024,exactMode:0o600,label:'native privacy verifying key'}),
          readExternalAuthorityFile(path.join(installationRoot,'installation.json'),{minimum:2,maximum:1024*1024,exactMode:0o600,label:'native privacy installation receipt'}),
          readExternalAuthorityFile(path.join(installationRoot,'ceremony-transcript.json'),{minimum:2,maximum:8*1024*1024,exactMode:0o600,label:'installed native privacy transcript'}),
          readExternalAuthorityFile(path.join(installationRoot,'spend-verifying-key.bin'),{minimum:1,maximum:16*1024*1024,exactMode:0o600,label:'installed native privacy verifying key'}),
          readExternalAuthorityFile(path.join(installationRoot,'native-usdom-v2.json'),{minimum:2,maximum:4*1024*1024,exactMode:0o600,label:'installed native privacy runtime manifest'}),
        ]);
        nativePrivacyCeremonyAuthority={transcriptBytes,circuitBytes,finalProvingKeyBytes,verifyingKeyBytes,
          runtimeManifestBytes:evidenceFileBytes.get(evidence.nativeRuntimeManifest.path),
          installationReceiptBytes,installedTranscriptBytes,installedVerifyingKeyBytes,
          installedRuntimeManifestBytes};
      } catch { /* pure readiness emits the semantic authority blocker */ }
    }
    let productionOperationalGasAuthority=null;
    if(['production_queue_withdrawal_worst_case_gas_measured',
      'production_prune_expired_256_worst_case_gas_measured',
      'production_prune_discardable_256_worst_case_gas_measured',
      'production_safe_admin_overhead_gas_measured'].some(key=>requirements?.[key]===true)) {
      try {
        const controlDirectory='/home/leonardov/usdom-mainnet-private/control-plane';
        const [jobBytes,reportBytes]=await Promise.all([
          readExternalAuthorityFile(path.join(controlDirectory,'production-operational-gas-job.json'),{
            minimum:2,maximum:1024*1024,exactMode:0o600,label:'production operational gas job'}),
          readExternalAuthorityFile(path.join(controlDirectory,'production-operational-gas-evidence.json'),{
            minimum:2,maximum:4*1024*1024,exactMode:0o600,label:'production operational gas evidence'}),
        ]);
        productionOperationalGasAuthority={jobBytes,reportBytes,
          releaseConfigBytes:authorityFileBytes.get('config/proof-reserve.unconfigured.json')};
      } catch { /* pure readiness emits the semantic authority blocker */ }
    }
    let releaseValidationAuthority=null;
    if(releaseValidationReport!==null) {
      try {
        const reportBytes=authorityFileBytes.get(evidence.releaseValidationReport.path);
        const reconstructedReportBytes=await reconstructReleaseValidation(releaseValidationReport);
        releaseValidationAuthority={reportBytes,reconstructedReportBytes,
          reconstructedReport:parseStrictJsonBytes(reconstructedReportBytes,
            {label:'reconstructed release validation report'})};
      } catch { /* pure readiness emits the semantic authority blocker */ }
    }
    let finalizedDepositAuthority=null;
    if(requirements?.native_private_mining_real_finalized_deposit_vector_implemented===true
        ||requirements?.real_finalized_reserve_deposit_native_block_vector_implemented===true) {
      try {
        const controlDirectory='/home/leonardov/usdom-mainnet-private/control-plane';
        const walletPath=path.join(os.homedir(),'.local/share/dom-usdom/mainnet-wallet/public-identity.json');
        const [packageBytes,executionBytes,baselineBytes,walletBytes,
          pilotFundsSnapshotBytes,pilotFundsAuthorizationStateBytes]=await Promise.all([
          readExternalAuthorityFile(path.join(controlDirectory,'closed-mainnet-deposit-package.json'),
            {minimum:2,maximum:4*1024*1024,exactMode:0o600,label:'closed deposit package'}),
          readExternalAuthorityFile(path.join(controlDirectory,'closed-mainnet-deposit-execution.json'),
            {minimum:2,maximum:4*1024*1024,exactMode:0o600,label:'closed deposit execution receipt'}),
          readExternalAuthorityFile(path.join(controlDirectory,'closed-mainnet-deposit-financial-baseline.json'),
            {minimum:2,maximum:4*1024*1024,exactMode:0o600,label:'closed deposit financial baseline'}),
          readExternalAuthorityFile(walletPath,{minimum:2,maximum:64*1024,exactMode:0o600,
            label:'closed deposit wallet observation'}),
          readDirectFile('evidence/authorization/pilot-funds-snapshot.json'),
          readDirectFile('evidence/authorization/pilot-funds-authorization-state.json'),
        ]);
        finalizedDepositAuthority={packageBytes,executionBytes,baselineBytes,walletBytes,
          releaseBytes:authorityFileBytes.get('config/proof-reserve.unconfigured.json'),
          pilotFundsSnapshotBytes,pilotFundsAuthorizationStateBytes};
      } catch { /* pure readiness emits the semantic authority blocker */ }
    }
    const report = assessMainnetReadiness({mode,requirements,requirementsAuthority,operatorIntent,
      releaseConfig,evidence,readinessDocumentAuthority,evidenceFiles,
      trustedReleaseSigningKeyFingerprint:process.env.USDOM_RELEASE_SIGNING_KEY_FINGERPRINT??null,
      repositoryState,repositoryStateAuthority,contractSource,checkpointContractSource,
      contractSourceAuthority,
      compiledReserveRuntimeCodeHash,
      compiledReserveInitcodeHash,compiledCheckpointRegistryRuntimeCodeHash,
      compiledCheckpointRegistryInitcodeHash,verifierConfig,checkpointVerifierConfig,riscZeroReference,
      compiledVerifierRuntimeCodeHash,compiledVerifierInitcodeHash,
      compiledCheckpointVerifierRuntimeCodeHash,compiledCheckpointVerifierInitcodeHash,
      compiledArtifactBindingErrors,compiledArtifactAuthority,
      predeploymentAttestation,predeploymentAttestationAuthority,coldStartAttestation,coldStartAttestationAuthority,
      nativePrivacyTrustedSetupAttestation,
      nativeScheduledRuntimeActivationAttestation,nativeWalletCustodyAttestation,
      nativeWalletRecoveryAttestation,nativeReleaseAttestationAuthority,
      nativeAttestationApprovalObservation,releaseAuthorizationApprovalObservation,
      approvalObservationAuthority,nativeRuntimeValidation,configurationAuthority,
      controlPlaneEvidenceArtifacts,controlPlaneEvidenceAuthority,
      riscZeroHealthSourceCatalog,riscZeroHealthSourceCatalogAuthority,
      finalizedBurnE2eReport,finalizedBurnE2eAuthority,
      checkpointProofCapacityReport,checkpointProofCapacityAuthority,finalizedBurnCapacityReport,finalizedBurnCapacityAuthority,
      productionOperationalGasAuthority,finalizedDepositAuthority,
      releaseValidationReport,releaseValidationAuthority,releaseAssuranceAuthority,
      pilotFundsSnapshot,pilotFundsAuthorizationState,pilotFundsAuthority,
      nativePrivacyCeremonyAuthority,
      toolchainLockSha256,cargoLockSha256,
      securityValidationReport,requirementsSha256,sourceManifestSha256,
      operationsReviewReport,operatorRunbookSha256,reserveReproducibleBuildReport,
      verifierReproducibleBuildReport,
      mainnetForkRehearsalReport,
      mainnetForkRehearsalEvidenceFiles,checkpointBootstrapRatificationReport,
      checkpointBootstrapRatificationAuthority,ethereumCheckpointConsensus,nativePreactivationFacts,
      checkpointFinalizedEventReport,checkpointFinalizedEventAuthority,
      checkpointVerifierReproducibleBuildReport,checkpointRegistryReproducibleBuildReport,
      checkpointRegistryArtifactPinsReport,
      checkpointRegistryArtifactPinsAuthority,
      checkpointRandomxImageRatificationReport,
      checkpointRandomxImageRatificationAuthority,
      checkpointRestartWitnessReport,
      checkpointRestartWitnessAuthority,
      finalizedBurnRecursiveCompletionReport,finalizedBurnRecursiveCompletionAuthority,
      residualRiskReport,residualRiskDraftSha256,trustedSetupDecisionReport,
      trustedSetupVerificationReport,trustedSetupAuthority,trustedSetupAuthoritySha256,
      trustedSetupDecisionReportAuthority});
    await assertEvidenceByteSnapshotsUnchanged(authorityFileBytes,readRawDirectFile,
      {label:'readiness authority'});
    for(const [absolute,snapshot] of externalAuthorityFileBytes) {
      const current=await readDirectAbsoluteFile(absolute,{minimum:1,maximum:4*1024*1024,label:'external readiness authority'});
      if(!current.equals(snapshot)) throw new Error(`readiness authority changed during collection: ${absolute}`);
    }
    if(operationalPlanBytes!==null) {
      const regeneratedPlan=spawnSync(process.execPath,['scripts/write-open-claims-execution-plan.mjs'],{
        cwd:root,encoding:null,env:{PATH:'/usr/bin:/bin'},maxBuffer:16*1024*1024,
      });
      if(regeneratedPlan.status!==0||regeneratedPlan.stderr.length!==0
          ||!regeneratedPlan.stdout.equals(operationalPlanBytes)) {
        throw new Error('operational claims plan changed during readiness');
      }
      const terminalReaudit=spawnSync(process.execPath,
        ['scripts/check-closed-mainnet-phase-artifacts.mjs','require-pilot-complete'],{
          cwd:root,encoding:null,env:process.env,maxBuffer:16*1024*1024,
        });
      if(terminalReaudit.status!==0||terminalReaudit.stderr.length!==0
          ||!terminalReaudit.stdout.equals(operationalArtifactAuditBytes)) {
        throw new Error('terminal phase artifacts failed final readiness revalidation');
      }
    }
    // Always include the non-authorizing category summary. A full release gate
    // can legitimately report many dependency-shaped blockers from one missing
    // ceremony or release configuration; presenting only the flat count makes
    // those dependencies look like independent defects. The summary never
    // clears a blocker and explicitly cannot authorize an operational action.
    const output={...report,diagnostic:summarizeReadinessBlockers(report.blockers,{
      buildSkipped:diagnosticNoBuild,
    })};
    console.log(JSON.stringify(output,null,2));
    if (!report.ready) process.exitCode = 1;
  } catch (error) {
    writePilotFailure('mainnet-readiness',error);
    process.exitCode = 2;
  }
}
