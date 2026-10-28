import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {readFileSync} from 'node:fs';
import {finalizedBurnAuthorityFixture} from './finalized-burn-authority-fixture.mjs';
import {Interface,TypedDataEncoder,Wallet,getAddress,getCreateAddress,id,keccak256,sha256,toUtf8Bytes} from 'ethers';
import {assertNoImpossibleAssuranceRequirements,assessMainnetReadiness,
 isForbiddenImpossibleAssuranceRequirement,readinessRequirementKeys}
 from '../../sdk/mainnet-readiness.mjs';
import {proofReserveDeploymentConfigHash,safeOwnersCommitment} from '../../sdk/configuration.mjs';
import {
 BURN_INTENT_TYPEHASH,BURN_STATEMENT_TYPEHASH,PRIVATE_BURN_ID_TYPEHASH,finalizedBurnStatementHash,
} from '../../sdk/proof-reserve.mjs';
import {
 FINALIZED_BURN_PROOF_ACCEPTED_HASH,FINALIZED_BURN_PROOF_SYSTEM,FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,
 FINALIZED_BURN_RISC0_JOURNAL_SCHEMA_HASH,VERIFIER_CONFIG_SCHEMA,finalizedBurnVerifierConfigHash,
} from '../../sdk/verifier-config.mjs';
import {
 CHECKPOINT_STATEMENT_TYPEHASH,checkpointRegistryConfigHash,checkpointStatementHash,
} from '../../sdk/checkpoint-registry.mjs';
import {activationSchedule} from '../../sdk/activation-schedule.mjs';
import {
 CHECKPOINT_PROOF_ACCEPTED_HASH,CHECKPOINT_PROOF_SYSTEM,CHECKPOINT_RANDOMX_STATEMENT_DOMAIN_HASH,
 CHECKPOINT_RISC0_GROTH16_V3_SELECTOR,CHECKPOINT_RISC0_JOURNAL_SCHEMA_HASH,
 CHECKPOINT_SEGMENT_STATE_DOMAIN_HASH,CHECKPOINT_SEGMENT_TRANSITION_DOMAIN_HASH,
 CHECKPOINT_VERIFIER_CONFIG_SCHEMA,checkpointVerifierConfigHash,
} from '../../sdk/checkpoint-verifier-config.mjs';
import {checkpointRegistryConfigurationFromRelease} from '../../sdk/checkpoint-submission.mjs';
import {PINNED_RISC0_MAINNET_V3} from '../../sdk/risc0-verifier-reference.mjs';
import {
 FINALIZED_BURN_CAPACITY_IMAGE_ID,FINALIZED_BURN_CAPACITY_INPUT_BYTES,
 FINALIZED_BURN_CAPACITY_INPUT_SHA256,FINALIZED_BURN_CAPACITY_PROGRAM_SHA256,
 FINALIZED_BURN_CAPACITY_REPORT_SCHEMA,FINALIZED_BURN_CAPACITY_STATEMENT_HASH,
 finalizedBurnCapacityAdapterConfigHash,finalizedBurnIsolatedEvmReceiptCommitment,
} from '../../sdk/finalized-burn-capacity-report.mjs';
import {rpcConsensusEvidence} from '../../sdk/rpc-consensus-evidence.mjs';
import {buildClosedMainnetDepositPackage} from '../../sdk/closed-mainnet-deposit.mjs';
import {finalizedBurnReleaseEvmReceiptCommitment} from '../../sdk/finalized-burn-e2e-report.mjs';
import {assessMainnetPreflight,EMPTY_CODE_HASH,ETHEREUM_MAINNET_GENESIS_BLOCK_HASH,
 ETHEREUM_MAINNET_USDT_CODE_HASH} from '../../sdk/mainnet-preflight.mjs';
import {
 buildNativeReleaseAttestation,nativeReleaseAttestationDigest,nativeReleaseAttestationTypedData,
 validateNativeReleaseAttestationSigningRequest,
} from '../../sdk/native-release-attestation.mjs';
import {
 releaseAuthorizationDigest,releaseAuthorizationTypedData,releaseEvidenceCommitment,
 validateReleaseAuthorizationSigningRequest,
} from '../../sdk/release-authorization.mjs';
import {
  SAFE_MAINNET_IDENTITY,buildRecoverableSafeControlDeploymentPackage,
} from '../../sdk/safe-control-deployment.mjs';
import {
  SAFE_CONTROL_RECOVERY_SCHEMA,SAFE_CONTROL_SNAPSHOT_SCHEMA,
  _safeControlObservationInternals,safeControlConfigurationHash,
} from '../../sdk/safe-control-observation.mjs';
import {buildRecoverableSafeControlReleaseEvidence} from '../../sdk/safe-control-release-evidence.mjs';
import {createRiscZeroHealthSourceCatalog} from '../../sdk/risc0-health-source-catalog.mjs';
import {PRODUCTION_SOLC_SHA256} from '../../sdk/reproducible-build-environment.mjs';
import {buildProductionOperationalGasEvidence,productionOperationalGasJobCommitment}
 from '../../sdk/production-operational-gas-evidence.mjs';
import {buildNativePrivacyInstallationReceipt,ceremonyContributionMessage,
 ceremonyDestructionMessage,ceremonyFinalizationMessage,ceremonyObjectHash,
 phase1ContributionMessage,phase1DestructionMessage,validateNativePrivacyCeremony}
 from '../../sdk/native-privacy-ceremony.mjs';

const safe141Fixture=JSON.parse(readFileSync(
 new URL('../fixtures/safe-1.4.1-mainnet.json',import.meta.url),'utf8'));
const initialSafeOwnersByRole=()=>{const owners=[101,102,103].map(value=>getAddress(address(value)));return {governance:[...owners],reserveGuardian:[...owners],checkpointGuardian:[...owners],usdtCustody:[...owners]};};
import {
 FINALIZED_BURN_E2E_EVIDENCE_PATH,prepareFinalizedBurnReleaseEvidenceMaterialization,
} from '../../sdk/finalized-burn-release-evidence-materialization.mjs';
import {
 CHECKPOINT_ECONOMIC_BLOCK_IMAGE_ID,CHECKPOINT_ECONOMIC_BLOCK_PROGRAM_SHA256,
 CHECKPOINT_ECONOMIC_CHUNK_IMAGE_ID,CHECKPOINT_ECONOMIC_CHUNK_PROGRAM_SHA256,
 CHECKPOINT_CAPACITY_ARTIFACT_SET_SCHEMA,CHECKPOINT_PROOF_CAPACITY_REPORT_SCHEMA,
 CHECKPOINT_RANDOMX_AGGREGATE_IMAGE_ID,
 CHECKPOINT_RANDOMX_AGGREGATE_PROGRAM_SHA256,CHECKPOINT_RANDOMX_IMAGE_ID,
 CHECKPOINT_RANDOMX_PROGRAM_SHA256,
 CHECKPOINT_SEGMENT_IMAGE_ID,CHECKPOINT_SEGMENT_PROGRAM_SHA256,
 checkpointIsolatedEvmReceiptCommitment,
} from '../../sdk/checkpoint-proof-capacity-report.mjs';
import {deriveDomDomain} from '../../sdk/preactivation-policy.mjs';
import {SECURITY_VALIDATION_CHECKS,buildSecurityValidationReport,
 serializeSecurityValidationReport,
} from '../../sdk/security-validation-report.mjs';
import {buildOperationsReviewReport,serializeOperationsReviewReport,
} from '../../sdk/operations-review-report.mjs';
import {buildReserveReproducibleBuildReport,serializeReserveReproducibleBuildReport,
} from '../../sdk/reserve-reproducible-build-report.mjs';
import {buildVerifierReproducibleBuildReport,serializeVerifierReproducibleBuildReport,
} from '../../sdk/verifier-reproducible-build-report.mjs';
import {buildMainnetForkRehearsalReport,forkRehearsalEvidenceDocumentSha256,
 serializeMainnetForkRehearsalReport,
} from '../../sdk/mainnet-fork-rehearsal-report.mjs';
import {buildCheckpointBootstrapRatificationReport,checkpointBootstrapRatificationDigest,
 serializeCheckpointBootstrapRatificationReport,
} from '../../sdk/checkpoint-bootstrap-ratification-report.mjs';
import {buildCheckpointFinalizedEventReport,serializeCheckpointFinalizedEventReport,
} from '../../sdk/checkpoint-finalized-event-report.mjs';
import {buildCheckpointVerifierReproducibleBuildReport,
 serializeCheckpointVerifierReproducibleBuildReport,
} from '../../sdk/checkpoint-verifier-reproducible-build-report.mjs';
import {buildCheckpointRegistryReproducibleBuildReport,
 serializeCheckpointRegistryReproducibleBuildReport,
} from '../../sdk/checkpoint-registry-reproducible-build-report.mjs';
import {buildResidualRiskReport,serializeResidualRiskReport} from '../../sdk/residual-risk-report.mjs';
import {buildTrustedSetupDecisionReport,serializeTrustedSetupDecisionReport}
 from '../../sdk/trusted-setup-decision-report.mjs';
import {PINNED_SNARKJS_PACKAGE_INTEGRITY,PINNED_SNARKJS_VERSION,
 PINNED_SNARKJS_KNOWN_ADVISORIES,
 RISC0_TRUSTED_SETUP_VERIFICATION_COMMANDS,
 buildRisc0TrustedSetupPodmanPlan,
 serializeRisc0TrustedSetupVerificationReport,
} from '../../sdk/risc0-trusted-setup-verification-report.mjs';
import {buildPilotFundsSnapshot,pilotFundsAuthorizationDigest,pilotFundsReleaseId,pilotFundsSnapshotCommitment}
 from '../../sdk/pilot-funds-authorization.mjs';

const address=n=>'0x'+n.toString(16).padStart(40,'0');
const signingFingerprint='A'.repeat(40);
const documentSha=path=>createHash('sha256').update(path).digest('hex');
const document=path=>({path,sha256:documentSha(path)});
const bytes32=byte=>'0x'+byte.repeat(32);
const nativePrivacyAuthorityFixture=async()=>{
 const digest=value=>createHash('sha256').update(value).digest('hex');
 const circuitBytes=Buffer.from('readiness frozen spend circuit'),finalProvingKeyBytes=Buffer.from('readiness final pk'),verifyingKeyBytes=Buffer.from('readiness canonical vk');
 const wallets=[1,2,3].map(value=>new Wallet(`0x${String(value).padStart(64,'0')}`));
 const base={schema:'usdom-native-privacy-groth16-ceremony-v1',circuitSha256:digest(circuitBytes),r1csFingerprintSha256:'10'.repeat(32),releaseCommitment:'11'.repeat(32),privacyVerifierConfigHash:'22'.repeat(32),participantsRequired:3,initialProvingKeySha256:'12'.repeat(32),initialKeyProvenance:null,ceremonyVerifierBinarySha256:'14'.repeat(32)};
 let phase1Previous='0'.repeat(64),phase1Accumulator='13'.repeat(32);const phase1=[];
 for(let i=0;i<3;i++){const participant=wallets[i].address,record={ordinal:i+1,participant,participantCommitment:digest(Buffer.from(participant)),previousRecordHash:phase1Previous,previousAccumulatorSha256:phase1Accumulator,artifactSha256:String(i+7).repeat(64),accumulatorSha256:String(i+1).repeat(64),signature:'',destruction:null};record.destruction={participant,artifactSha256:record.artifactSha256,method:'isolated volatile entropy erased and independently witnessed',destroyedAt:`2026-10-27T11:0${i}:00.000Z`,signature:''};record.destruction.signature=await wallets[i].signMessage(phase1DestructionMessage(record.destruction));record.signature=await wallets[i].signMessage(phase1ContributionMessage(record));phase1.push(record);phase1Accumulator=record.accumulatorSha256;phase1Previous=ceremonyObjectHash(record);}
 base.initialKeyProvenance={kind:'powers-of-tau-bn254-multiparty-specialization-v1',initialAccumulatorSha256:'13'.repeat(32),finalAccumulatorSha256:phase1Accumulator,specializationSha256:base.initialProvingKeySha256,contributions:phase1};
 let previous='0'.repeat(64);const contributions=[];
 for(let i=0;i<3;i++){const contribution={ordinal:i+1,participant:wallets[i].address,participantCommitment:digest(Buffer.from(wallets[i].address)),previousTranscriptHash:previous,previousProvingKeySha256:i===0?base.initialProvingKeySha256:contributions[i-1].contributionSha256,contributionSha256:String(i+3).repeat(64),phase2ArtifactSha256:String(i+6).repeat(64),circuitSha256:base.circuitSha256,r1csFingerprintSha256:base.r1csFingerprintSha256,releaseCommitment:base.releaseCommitment,signature:'',destruction:null};contribution.signature=await wallets[i].signMessage(ceremonyContributionMessage(contribution));contribution.destruction={participant:contribution.participant,contributionSha256:contribution.contributionSha256,method:'ephemeral isolated host securely erased and independently witnessed',destroyedAt:`2026-10-27T12:0${i}:00.000Z`,signature:''};contribution.destruction.signature=await wallets[i].signMessage(ceremonyDestructionMessage(contribution.destruction));contributions.push(contribution);previous=ceremonyObjectHash(contribution);}
 const transcript={...base,contributions,beacon:'ab'.repeat(64),finalProvingKeySha256:digest(finalProvingKeyBytes),verifyingKeySha256:digest(verifyingKeyBytes),finalTranscriptHash:'',finalizationSignatures:[]};
 transcript.finalTranscriptHash=ceremonyObjectHash({previousTranscriptHash:previous,beacon:transcript.beacon,finalProvingKeySha256:transcript.finalProvingKeySha256,verifyingKeySha256:transcript.verifyingKeySha256,circuitSha256:transcript.circuitSha256,releaseCommitment:transcript.releaseCommitment,privacyVerifierConfigHash:transcript.privacyVerifierConfigHash,r1csFingerprintSha256:transcript.r1csFingerprintSha256,initialProvingKeySha256:transcript.initialProvingKeySha256,initialKeyProvenance:transcript.initialKeyProvenance,ceremonyVerifierBinarySha256:transcript.ceremonyVerifierBinarySha256});
 transcript.finalizationSignatures=await Promise.all(wallets.map(async wallet=>({participant:wallet.address,signature:await wallet.signMessage(ceremonyFinalizationMessage(transcript))})));
 const transcriptBytes=Buffer.from(`${JSON.stringify(transcript)}\n`),runtimeManifestBytes=Buffer.from('{"schema":"native-runtime","generation":1}\n');
 const validated=validateNativePrivacyCeremony(transcript,{circuitBytes,finalProvingKeyBytes,verifyingKeyBytes});
 const receipt=buildNativePrivacyInstallationReceipt(validated,runtimeManifestBytes,transcriptBytes);
 return {transcriptBytes,circuitBytes,finalProvingKeyBytes,verifyingKeyBytes,runtimeManifestBytes,installationReceiptBytes:Buffer.from(`${JSON.stringify(receipt)}\n`),installedTranscriptBytes:transcriptBytes,installedVerifyingKeyBytes:verifyingKeyBytes,installedRuntimeManifestBytes:runtimeManifestBytes,privacyVerifierConfigHash:validated.privacyVerifierConfigHash,verifyingKeySha256:validated.verifyingKeySha256};
};
const nativePrivacyAuthority=await nativePrivacyAuthorityFixture();
const operationalGasAuthority=(releaseConfig,releaseConfigBytes)=>{
 const interfaces=[new Interface(['function queueWithdrawal((bytes32,bytes32,address,uint64,bytes32,uint64,bytes32,bytes32,uint64,uint64),bytes)']),new Interface(['function pruneExpired(uint256)']),new Interface(['function pruneDiscardable(bytes32[])']),new Interface(['function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)','function swapOwner(address,address,address)'])];
 const hash=n=>'0x'+n.toString(16).padStart(64,'0');
 const input=index=>index===0?interfaces[0].encodeFunctionData('queueWithdrawal',[[hash(1),hash(2),address(3),1,hash(4),1,hash(5),hash(6),1,999],`0x${'11'.repeat(260)}`]):index===1?interfaces[1].encodeFunctionData('pruneExpired',[256]):index===2?interfaces[2].encodeFunctionData('pruneDiscardable',[Array.from({length:256},(_,n)=>hash(n+1))]):interfaces[3].encodeFunctionData('execTransaction',[releaseConfig.governance,0,interfaces[3].encodeFunctionData('swapOwner',[address(21),address(22),address(23)]),0,0,0,0,address(0),address(0),'0x']);
 const inputHash=value=>'0x'+createHash('sha256').update(Buffer.from(value.slice(2),'hex')).digest('hex');
 const ids=['queueWithdrawal-worst-case','pruneExpired-256','pruneDiscardable-256','safe-admin-swapOwner-3-owner-2-threshold'];
 const topics=[id('WithdrawalQueued(bytes32,bytes32,bytes32,uint64,uint64)'),id('WithdrawalDiscardedV2(bytes32,bytes32,uint64,uint64)'),id('WithdrawalDiscardedV2(bytes32,bytes32,uint64,uint64)'),id('ExecutionSuccess(bytes32,uint256)')];
 const safeAddresses=[releaseConfig.governance.toLowerCase(),releaseConfig.guardian.toLowerCase()];
 const safeImplementationCodeHashes=[releaseConfig.governanceImplementationCodeHash.toLowerCase(),releaseConfig.guardianImplementationCodeHash.toLowerCase()];
 const safeRuntimeCodeHashes=[releaseConfig.governanceCodeHash.toLowerCase(),releaseConfig.guardianCodeHash.toLowerCase()];
 let job={schema:'usdom-production-operational-gas-measurement-job/v3',ethereumChainId:'1',releaseConfigSha256:'0x'+documentSha(releaseConfigBytes),localBaselineSha256:hash(2),reserve:releaseConfig.reserve.toLowerCase(),reserveRuntimeCodeHash:releaseConfig.reserveRuntimeCodeHash.toLowerCase(),reserveConfigHash:releaseConfig.reserveConfigHash.toLowerCase(),safeAddresses,safeImplementationCodeHashes,safeRuntimeCodeHashes,requiredRuns:2,requiredIndependentRpcSources:2,requiredFinalityTag:'finalized',scenarios:ids.map((name,index)=>({id:name,target:index<3?releaseConfig.reserve.toLowerCase():safeAddresses[0],targetRuntimeCodeHash:index<3?releaseConfig.reserveRuntimeCodeHash.toLowerCase():safeRuntimeCodeHashes[0],maximumGasUsed:'0x100000',runs:[1,2].map(ordinal=>({ordinal,transactionHash:hash(100+index*2+ordinal),calldataSha256:inputHash(input(index))}))})),jobCommitment:hash(0)};
 job.jobCommitment=productionOperationalGasJobCommitment(job);
 const observations=job.scenarios.map((scenario,index)=>({id:scenario.id,runs:scenario.runs.map(run=>({ordinal:run.ordinal,sources:['alpha','beta'].map(sourceId=>({sourceId,chainId:'0x1',runtimeCodeHash:scenario.targetRuntimeCodeHash,implementationCodeHash:index===3?safeImplementationCodeHashes[0]:null,transaction:{hash:run.transactionHash,to:scenario.target,input:input(index)},receipt:{transactionHash:run.transactionHash,status:'0x1',blockNumber:'0x10',blockHash:hash(200+index),gasUsed:'0x5208',logs:Array.from({length:index===1||index===2?256:1},()=>({address:scenario.target,topics:[topics[index]],data:'0x'}))},block:{number:'0x10',hash:hash(200+index)},finalized:{number:'0x20',hash:hash(300+index)}}))}))}));
 return {jobBytes:Buffer.from(JSON.stringify(job)),reportBytes:Buffer.from(JSON.stringify(buildProductionOperationalGasEvidence(job,observations))),releaseConfigBytes};
};
const trustedSetupAuthorityBytes=await readFile(new URL('../../config/risc0-trusted-setup-authority-v1.json',import.meta.url));
const trustedSetupAuthority=JSON.parse(trustedSetupAuthorityBytes);
const trustedSetupAuthoritySha256=createHash('sha256').update(trustedSetupAuthorityBytes).digest('hex');
const trustedSetupContributionWords=Array.from({length:16},(_,index)=>(index+1).toString(16).padStart(8,'0')).join(' ');
const trustedSetupPowersLog='[INFO]  snarkJS: Powers Of tau file OK!\n';
const trustedSetupZkeyLog=`[INFO]  snarkJS: Contribution Hash:\n ${trustedSetupContributionWords}\n[INFO]  snarkJS: ZKey Ok!\n`;
const trustedSetupVerificationEnvironment={schema:'usdom-risc0-trusted-setup-verification-environment/v7',
 containerImageDigest:`sha256:${'77'.repeat(32)}`,networkDisabled:true,nodeVersion:'v24.19.0',
 containerImageReference:`sha256:${'77'.repeat(32)}`,
 containerRuntime:{path:'/usr/bin/podman',sha256:'88'.repeat(32)},
 inputArtifacts:{r1csSha256:trustedSetupAuthority.r1cs_sha256,
  powersOfTauBlake2b512:trustedSetupAuthority.powers_of_tau_blake2b512,zkeySha256:'11'.repeat(32),
  expectedVerificationKeySha256:documentSha('evidence/verifying-key.bin')},
 snarkjsVersion:PINNED_SNARKJS_VERSION,snarkjsPackageIntegrity:PINNED_SNARKJS_PACKAGE_INTEGRITY,
 knownAdvisories:[...PINNED_SNARKJS_KNOWN_ADVISORIES],capabilitiesDropped:['ALL'],
 commands:structuredClone(RISC0_TRUSTED_SETUP_VERIFICATION_COMMANDS),inputMountReadOnly:true,
 noNewPrivileges:true,outputTmpfs:true,rootFilesystemReadOnly:true,runAsUser:'65532:65532'};
const stableTrustedSetup=value=>Array.isArray(value)?value.map(stableTrustedSetup):value&&typeof value==='object'
 ?Object.fromEntries(Object.keys(value).sort().map(key=>[key,stableTrustedSetup(value[key])])):value;
const trustedSetupVerificationEnvironmentSha256=createHash('sha256').update(`${JSON.stringify(
 stableTrustedSetup(trustedSetupVerificationEnvironment),null,2)}\n`).digest('hex');
const trustedSetupPodmanPlan=buildRisc0TrustedSetupPodmanPlan(trustedSetupVerificationEnvironment);
const trustedSetupImageInspectionUtf8=`${JSON.stringify(trustedSetupPodmanPlan.image)}\n`;
const trustedSetupToolchainAttestationUtf8=`${JSON.stringify({nodeVersion:trustedSetupVerificationEnvironment.nodeVersion,
 snarkjsVersion:trustedSetupVerificationEnvironment.snarkjsVersion,
 snarkjsPackageIntegrity:trustedSetupVerificationEnvironment.snarkjsPackageIntegrity})}\n`;
const trustedSetupVerificationReport={schema:'usdom-risc0-groth16-trusted-setup-verification/v6',status:'verified',
 authoritySha256:trustedSetupAuthoritySha256,artifacts:{r1cs:{sha256:trustedSetupAuthority.r1cs_sha256,size:trustedSetupAuthority.r1cs_size},
 powersOfTau:{blake2b512:trustedSetupAuthority.powers_of_tau_blake2b512,power:23,size:trustedSetupAuthority.powers_of_tau_size},
 zkey:{sha256:'11'.repeat(32),size:trustedSetupAuthority.zkey_size,
  verificationKeySha256:documentSha('evidence/verifying-key.bin')}},
 snarkjs:{version:PINNED_SNARKJS_VERSION,packageIntegrity:PINNED_SNARKJS_PACKAGE_INTEGRITY,
  isolated:true,networkDisabled:true,knownAdvisories:[...PINNED_SNARKJS_KNOWN_ADVISORIES],
  powersOfTauVerified:true,zkeyVerified:true},contributionDigests:[trustedSetupContributionWords.replaceAll(' ','')],
 verificationLogs:{powersOfTauSha256:createHash('sha256').update(trustedSetupPowersLog).digest('hex'),
  powersOfTauUtf8:trustedSetupPowersLog,
  zkeySha256:createHash('sha256').update(trustedSetupZkeyLog).digest('hex'),zkeyUtf8:trustedSetupZkeyLog},
 containerExecution:{imageInspectionSha256:createHash('sha256').update(trustedSetupImageInspectionUtf8).digest('hex'),
  imageInspectionUtf8:trustedSetupImageInspectionUtf8,planSha256:createHash('sha256').update(`${JSON.stringify(
   stableTrustedSetup(trustedSetupPodmanPlan),null,2)}\n`).digest('hex'),imageIdentifier:trustedSetupPodmanPlan.image,
  toolchainAttestationSha256:createHash('sha256').update(trustedSetupToolchainAttestationUtf8).digest('hex'),
  toolchainAttestationUtf8:trustedSetupToolchainAttestationUtf8},
 verificationEnvironment:{document:structuredClone(trustedSetupVerificationEnvironment),
  sha256:trustedSetupVerificationEnvironmentSha256}};
const trustedSetupVerificationSha256=createHash('sha256').update(
 serializeRisc0TrustedSetupVerificationReport(trustedSetupVerificationReport)).digest('hex');
function forkRehearsalFixture(releaseEvidence,releaseConfig) {
 const ids=['ethereum-reorganization','dom-reorganization','ethereum-unavailability',
  'dom-unavailability','censorship','recovery'];
 const decisions=['reject-conflicting-ethereum-finality','reject-dom-reorg-below-checkpoint-floor',
  'halt-ethereum-dependent-issuance-and-redemption','halt-checkpoint-advancement-and-redemption',
  'preserve-permissionless-retry-without-bypass','resume-only-after-release-bound-recovery-drill'];
 const evidenceFiles=Object.create(null);
 const generationId='ab'.repeat(32),forkBlockNumber='22000000',forkBlockHash=bytes32('cd');
 const scenarios=ids.map((id,index)=>{
  const startedAtUnix=String(1792492000+index*10),finishedAtUnix=String(1792492009+index*10);
  const preStateCommitment=bytes32((0x40+index).toString(16));
  const postRecoveryStateCommitment=preStateCommitment;
  const faultPath=`evidence/fork-rehearsal/raw/${id}-fault.json`;
  const recoveryPath=`evidence/fork-rehearsal/raw/${id}-recovery.json`;
  const faultDocument={schema:'usdom-mainnet-fork-fault-evidence-v1',scenarioId:id,
   releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
   commandId:`${id}-fault-assertion`,assertionExitCode:'0',observedDecision:decisions[index],
   preStateCommitment,faultStateCommitment:preStateCommitment,unsafeTransitionCount:'0',
   fundLossBaseUnits:'0',generationId,forkBlockNumber,forkBlockHash,capturedAtUnix:startedAtUnix};
  const recoveryDocument={schema:'usdom-mainnet-fork-recovery-evidence-v1',scenarioId:id,
   releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
   commandId:`${id}-recovery-assertion`,assertionExitCode:'0',recoveryObserved:true,
   postRecoveryStateCommitment,generationId,forkBlockNumber,forkBlockHash,capturedAtUnix:finishedAtUnix};
  const faultSha=forkRehearsalEvidenceDocumentSha256(faultDocument);
  const recoverySha=forkRehearsalEvidenceDocumentSha256(recoveryDocument);
  evidenceFiles[faultPath]={sha256:faultSha,document:faultDocument};
  evidenceFiles[recoveryPath]={sha256:recoverySha,document:recoveryDocument};
  return {id,faultObserved:true,decisionObserved:decisions[index],unsafeTransitionCount:'0',
   fundLossBaseUnits:'0',recoveryObserved:true,startedAtUnix,finishedAtUnix,preStateCommitment,
   faultStateCommitment:preStateCommitment,postRecoveryStateCommitment,
   faultEvidence:{path:faultPath,sha256:faultSha},
   recoveryEvidence:{path:recoveryPath,sha256:recoverySha}};
 });
 const observations={schema:'usdom-mainnet-fork-rehearsal-observations-v1',
  releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
  sourceTag:releaseEvidence.sourceTag,ethereumChainId:'1',
  reserveConfigHash:releaseConfig.reserveConfigHash,
  checkpointRegistryConfigHash:releaseConfig.checkpointRegistryConfigHash,
  activationScheduleCommitment:releaseConfig.activationScheduleCommitment,
  generationId,forkBlockNumber,forkBlockHash,rpcSourceIds:['drpc','publicnode'],
  rpcEndpointHashes:['c5b9f7564a09b1b2bbdff2c7145d474bbc2ccd025460d9c5b097a39474b7980c',
   '7b71d04b616d2ce47598465ad04d63da212a14b1317f965044bf325b749a6746'],
  startedAtUnix:'1792492000',finishedAtUnix:'1792492100',scenarios};
 return {report:buildMainnetForkRehearsalReport({observations,releaseEvidence,releaseConfig,
  evidenceFiles}),evidenceFiles};
}
function checkpointRatificationFixture(releaseEvidence,releaseConfig) {
 const checkpointConsensus={schema:'usdom-ethereum-checkpoint-consensus-v1',
  network:'ethereum-mainnet',checkpointEpoch:'500000',checkpointSlot:'16000000',
  checkpointRoot:releaseConfig.nativeEthereumTrustedCheckpoint,sourceCount:'3',
  sourceSetCommitment:bytes32('aa'),observedAtUnix:'1792490000'};
 const nativeFacts={schema:'usdom-native-preactivation-facts-v1',
  nativeEthereumTrustedCheckpoint:releaseConfig.nativeEthereumTrustedCheckpoint,
  domDomain:releaseConfig.domDomain,checkpointDomNetworkMagic:releaseConfig.checkpointDomNetworkMagic,
  checkpointDomChainId:releaseConfig.checkpointDomChainId,
  checkpointFirstV4Height:releaseConfig.checkpointFirstV4Height,
  checkpointIntervalBlocks:releaseConfig.checkpointIntervalBlocks,
  checkpointConfirmationDepthBlocks:releaseConfig.checkpointConfirmationDepthBlocks,
  checkpointChallengePeriodSeconds:releaseConfig.checkpointChallengePeriodSeconds,
  checkpointInitialHeight:releaseConfig.checkpointInitialHeight,
  checkpointInitialBlock:releaseConfig.checkpointInitialBlock,
  checkpointInitialContextHash:releaseConfig.checkpointInitialContextHash,
  checkpointInitialTotalDifficulty:releaseConfig.checkpointInitialTotalDifficulty};
 const ratificationDigest=checkpointBootstrapRatificationDigest({releaseEvidence,releaseConfig,
  checkpointConsensus,nativeFacts});
 const approvals=[1,2].map(index=>({operatorId:`operator-${index}`,
  originKeccak256:bytes32(`b${index}`),snapshotBlockNumber:'22000000',
  snapshotBlockHash:bytes32('bc'),snapshotBlockTimestamp:'1792490100',
  governanceCodeHash:releaseConfig.governanceCodeHash,eip1271MagicValue:'0x1626ba7e',
  observedAtUnix:String(1792490100+index)}));
 const sourceSetCommitment=keccak256(toUtf8Bytes(
  `USDOM_CHECKPOINT_RATIFICATION_RPC_SOURCES_V1\n${approvals.map(value=>
    `${value.operatorId}\u0000${value.originKeccak256}`).join('\n')}`));
 const observation={schema:'usdom-checkpoint-bootstrap-ratification-observation-v1',
  releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
  sourceTag:releaseEvidence.sourceTag,ethereumChainId:'1',governance:releaseConfig.governance,
  ratificationDigest,snapshotBlockNumber:'22000000',snapshotBlockHash:bytes32('bc'),
  snapshotBlockTimestamp:'1792490100',sourceSetCommitment,approvals};
 return {report:buildCheckpointBootstrapRatificationReport({releaseEvidence,releaseConfig,
  checkpointConsensus,nativeFacts,observation}),checkpointConsensus,nativeFacts};
}
function checkpointFinalizedEventFixture(releaseEvidence,releaseConfig) {
 const eventInterface=new Interface([
  'event Checkpoint(bytes32 indexed bridgeDomain,uint32 indexed domNetworkMagic,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 checkpointConfigHash)',
  'event CheckpointFinalizedV2(bytes32 indexed statementHash,bytes32 domContextHash,uint256 domTotalDifficulty,uint128 totalIssued,uint128 totalBurned,bool issuanceClosed,uint256 checkpointCount)',
 ]);
 const encoded=eventInterface.encodeEventLog(eventInterface.getEvent('Checkpoint'),[
  releaseConfig.domDomain,releaseConfig.checkpointDomNetworkMagic,'100360',bytes32('c4'),
  bytes32('c5'),releaseConfig.checkpointRegistryConfigHash]);
 const state={checkpointConfigHash:releaseConfig.checkpointRegistryConfigHash,halted:false,
  gracefullyShutdown:false,latestIssuanceClosed:false,latestHeight:'100360',latestBlock:bytes32('c4'),latestStateRoot:bytes32('c5'),
  latestContextHash:bytes32('c6'),latestTotalDifficulty:'2000000',latestTotalIssued:'100',latestTotalBurned:'20',checkpointCount:'1',
  candidateStatementHash:'0x'+'00'.repeat(32)};
 const finalized=eventInterface.encodeEventLog(eventInterface.getEvent('CheckpointFinalizedV2'),[
  bytes32('ca'),state.latestContextHash,state.latestTotalDifficulty,state.latestTotalIssued,
  state.latestTotalBurned,state.latestIssuanceClosed,state.checkpointCount]);
 const observations=[1,2].map(index=>({operatorId:`operator-${index}`,
  originKeccak256:bytes32(`d${index}`),chainId:'1',transactionHash:bytes32('c7'),
  receiptStatus:'1',blockNumber:'22000000',blockHash:bytes32('c8'),
  blockTimestamp:'1792490200',finalizedHeadNumber:'22000010',finalizedHeadHash:bytes32('c9'),
  snapshotBlockHashAfter:bytes32('c8'),
  registryRuntimeCodeHash:releaseConfig.checkpointRegistryRuntimeCodeHash,
  checkpointEventCount:'1',log:{address:releaseConfig.checkpointRegistry,logIndex:'2',
   transactionIndex:'1',transactionHash:bytes32('c7'),blockNumber:'22000000',
   blockHash:bytes32('c8'),removed:false,
   topics:encoded.topics.map(value=>value.toLowerCase()),data:encoded.data.toLowerCase()},
  finalizationLog:{address:releaseConfig.checkpointRegistry,logIndex:'3',transactionIndex:'1',
   transactionHash:bytes32('c7'),blockNumber:'22000000',blockHash:bytes32('c8'),removed:false,
   topics:finalized.topics.map(value=>value.toLowerCase()),data:finalized.data.toLowerCase()},
  state:{...state}}));
 const sourceSetCommitment=keccak256(toUtf8Bytes(
  `USDOM_CHECKPOINT_FINALIZED_EVENT_RPC_SOURCES_V2\n${observations.map(value=>
    `${value.operatorId}\u0000${value.originKeccak256}`).join('\n')}`));
 const observation={schema:'usdom-checkpoint-finalized-event-observation-v3',
  releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
  sourceTag:releaseEvidence.sourceTag,ethereumChainId:'1',transactionHash:bytes32('c7'),
  statementHash:bytes32('ca'),
  blockNumber:'22000000',blockHash:bytes32('c8'),blockTimestamp:'1792490200',
  sourceSetCommitment,observations};
 return buildCheckpointFinalizedEventReport({releaseEvidence,releaseConfig,observation});
}
const deployment=()=>({
 ethereumChainId:'1',reserve:address(9),token:'0xdAC17F958D2ee523a2206206994597C13D831ec7',
 tokenCodeHash:ETHEREUM_MAINNET_USDT_CODE_HASH,verifier:address(8),verifierCodeHash:'0x'+'20'.repeat(32),
 verifierConfigHash:'0x'+'30'.repeat(32),domDomain:'0x'+'40'.repeat(32),
 activationScheduleCommitment:'0x'+'42'.repeat(32),governance:address(7),
 governanceCodeHash:'0x'+'50'.repeat(32),governanceImplementation:SAFE_MAINNET_IDENTITY.singleton,
 governanceImplementationCodeHash:SAFE_MAINNET_IDENTITY.singletonCodeHash,
 governanceOwnersCommitment:safeOwnersCommitment([104,102,103].map(value=>address(value))),
 guardian:address(6),guardianCodeHash:'0x'+'50'.repeat(32),
 guardianImplementation:SAFE_MAINNET_IDENTITY.singleton,
 guardianImplementationCodeHash:SAFE_MAINNET_IDENTITY.singletonCodeHash,
 guardianOwnersCommitment:safeOwnersCommitment([104,102,103].map(value=>address(value))),
 withdrawalDelaySeconds:'86400',governanceDelaySeconds:'172800',
 maxOutstandingBaseUnits:'100000000000',outflowCapacityBaseUnitsPerDay:'2000000000',
});
function preflightObservation(config,phase) {
 const observation={chainId:'1',genesisBlockHash:ETHEREUM_MAINNET_GENESIS_BLOCK_HASH,
  finalizedBlockNumber:'22000000',finalizedBlockHash:bytes32('70'),
  snapshotBlockHashAfter:bytes32('70'),deployerNonce:config.checkpointRegistryDeployerNonce,
  checkpointRegistryDeployerNonce:config.checkpointRegistryDeployerNonce,
  codeHashes:{reserve:phase==='postdeployment'?config.reserveRuntimeCodeHash
    :'0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
   token:config.tokenCodeHash,verifier:config.verifierCodeHash,governance:config.governanceCodeHash,
   governanceImplementation:config.governanceImplementationCodeHash,
   guardian:config.guardianCodeHash,guardianImplementation:config.guardianImplementationCodeHash,
   checkpointRegistry:phase==='postdeployment'?config.checkpointRegistryRuntimeCodeHash
    :'0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
   checkpointVerifier:config.checkpointVerifierCodeHash,
   checkpointGuardian:config.checkpointGuardianCodeHash,
   checkpointGuardianImplementation:config.checkpointGuardianImplementationCodeHash},
  verifierConfigHash:config.verifierConfigHash,checkpointVerifierConfigHash:config.checkpointVerifierConfigHash,
  verifierProofAccepted:FINALIZED_BURN_PROOF_ACCEPTED_HASH,
  checkpointVerifierProofAccepted:CHECKPOINT_PROOF_ACCEPTED_HASH,
  finalizedBurnVerifier:{address:config.verifier,riscZeroVerifier:PINNED_RISC0_MAINNET_V3.verifier_address,
   riscZeroVerifierCodeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
   verifierSelector:PINNED_RISC0_MAINNET_V3.verifier_selector,imageId:bytes32('91'),deploymentChainId:'1',
   verifierConfigHash:config.verifierConfigHash,proofAccepted:FINALIZED_BURN_PROOF_ACCEPTED_HASH},
  checkpointVerifier:{address:config.checkpointVerifier,riscZeroVerifier:PINNED_RISC0_MAINNET_V3.verifier_address,
   riscZeroVerifierCodeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
   verifierSelector:PINNED_RISC0_MAINNET_V3.verifier_selector,imageId:bytes32('92'),deploymentChainId:'1',
   verifierConfigHash:config.checkpointVerifierConfigHash,proofAccepted:CHECKPOINT_PROOF_ACCEPTED_HASH},
  controlPlaneImplementations:{governance:config.governanceImplementation,
   guardian:config.guardianImplementation,checkpointGuardian:config.checkpointGuardianImplementation},
  controlPlanePolicies:{
   governance:{nonce:'0',threshold:'2',owners:[...config.governanceOwners],
    ownerCodeHashes:[EMPTY_CODE_HASH,EMPTY_CODE_HASH,EMPTY_CODE_HASH],modules:[],modulesNext:address(1),guard:address(0),
    fallbackHandler:SAFE_MAINNET_IDENTITY.fallbackHandler,
    fallbackHandlerCodeHash:SAFE_MAINNET_IDENTITY.fallbackHandlerCodeHash},
   guardian:{nonce:'0',threshold:'2',owners:[...config.guardianOwners],
    ownerCodeHashes:[EMPTY_CODE_HASH,EMPTY_CODE_HASH,EMPTY_CODE_HASH],modules:[],modulesNext:address(1),guard:address(0),
    fallbackHandler:SAFE_MAINNET_IDENTITY.fallbackHandler,
    fallbackHandlerCodeHash:SAFE_MAINNET_IDENTITY.fallbackHandlerCodeHash},
   checkpointGuardian:{nonce:'0',threshold:'2',owners:[...config.checkpointGuardianOwners],modules:[],
    ownerCodeHashes:[EMPTY_CODE_HASH,EMPTY_CODE_HASH,EMPTY_CODE_HASH],modulesNext:address(1),guard:address(0),
    fallbackHandler:SAFE_MAINNET_IDENTITY.fallbackHandler,
    fallbackHandlerCodeHash:SAFE_MAINNET_IDENTITY.fallbackHandlerCodeHash}},
  riscZeroVerifier:{address:PINNED_RISC0_MAINNET_V3.verifier_address,
   codeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
   selector:PINNED_RISC0_MAINNET_V3.verifier_selector,version:PINNED_RISC0_MAINNET_V3.verifier_version},
  riscZeroEmergencyStop:{address:PINNED_RISC0_MAINNET_V3.emergency_stop_wrapper_address,
   codeHash:PINNED_RISC0_MAINNET_V3.emergency_stop_wrapper_runtime_code_hash,
   paused:false,verifier:PINNED_RISC0_MAINNET_V3.verifier_address},
  token:{name:'Tether USD',symbol:'USDT',decimals:'6',totalSupply:'1000000000000',owner:address(77),
   ownerCodeHash:EMPTY_CODE_HASH,paused:false,deprecated:false,upgradedAddress:address(0),
   basisPointsRate:'0',maximumFee:'0',reserveBlacklisted:false,reserveBalance:'0',
   eip1967Implementation:bytes32('00'),eip1967Admin:bytes32('00'),eip1967Beacon:bytes32('00')}};
 observation.finalizedBurnVerifierDeployment={status:true,from:config.verifierDeployer,
  nonce:config.verifierDeployerNonce,creates:config.verifier,derivedCreateAddress:config.verifier,
  blockNumber:'21999996',blockHash:bytes32('75'),
  canonicalBlockHash:bytes32('75'),transactionHash:bytes32('76'),to:null,value:'0',
  inputHash:config.verifierInitcodeHash};
 observation.checkpointVerifierDeployment={status:true,from:config.checkpointVerifierDeployer,
  nonce:config.checkpointVerifierDeployerNonce,creates:config.checkpointVerifier,
  derivedCreateAddress:config.checkpointVerifier,
  blockNumber:'21999997',blockHash:bytes32('77'),canonicalBlockHash:bytes32('77'),
  transactionHash:bytes32('78'),to:null,value:'0',inputHash:config.checkpointVerifierInitcodeHash};
 if(phase==='predeployment') return observation;
 observation.deployment={status:true,from:config.deployer,nonce:config.deployerNonce,creates:config.reserve,
  derivedCreateAddress:config.reserve,
  blockNumber:'21999999',blockHash:bytes32('71'),canonicalBlockHash:bytes32('71'),
  transactionHash:bytes32('73'),to:null,value:'0',
  inputHash:config.reserveInitcodeHash};
 observation.checkpointRegistryDeployment={status:true,from:config.checkpointRegistryDeployer,
  nonce:config.checkpointRegistryDeployerNonce,creates:config.checkpointRegistry,
  derivedCreateAddress:config.checkpointRegistry,
  blockNumber:'21999998',blockHash:bytes32('72'),canonicalBlockHash:bytes32('72'),
  transactionHash:bytes32('74'),to:null,value:'0',
  inputHash:config.checkpointRegistryInitcodeHash,checkpointEventCount:'1',checkpointEvent:{
   address:config.checkpointRegistry,bridgeDomain:config.domDomain,
   domNetworkMagic:config.checkpointDomNetworkMagic,domHeight:config.checkpointInitialHeight,
   domBlock:config.checkpointInitialBlock,domStateRoot:config.checkpointInitialStateRoot,
   checkpointConfigHash:config.checkpointRegistryConfigHash}};
 observation.reserve={token:config.token,tokenCodeHash:config.tokenCodeHash,verifier:config.verifier,
  verifierCodeHash:config.verifierCodeHash,verifierConfigHash:config.verifierConfigHash,
  reserveConfigHash:config.reserveConfigHash,domDomain:config.domDomain,
  activationScheduleCommitment:config.activationScheduleCommitment,governance:config.governance,
  governanceCodeHash:config.governanceCodeHash,guardian:config.guardian,
  governanceImplementation:config.governanceImplementation,
  governanceImplementationCodeHash:config.governanceImplementationCodeHash,
  governanceOwnersCommitment:config.governanceOwnersCommitment,
  guardianCodeHash:config.guardianCodeHash,guardianImplementation:config.guardianImplementation,
  guardianImplementationCodeHash:config.guardianImplementationCodeHash,
  guardianOwnersCommitment:config.guardianOwnersCommitment,
  withdrawalDelay:config.withdrawalDelaySeconds,
  governanceDelay:config.governanceDelaySeconds,maxOutstanding:config.maxOutstandingBaseUnits,
  outflowCapacity:config.outflowCapacityBaseUnitsPerDay,paused:true,pilotRestrictedDeployment:true,
  permissionlessDeposits:false,pilotDepositConsumed:false,authorizedPilotDeposit:bytes32('00'),
  authorizedPilotSnapshot:bytes32('00'),authorizedPilotValidUntil:'0',pilotAuthorizationGeneration:'0',
  permissionlessDepositsReadyAt:'0',depositsClosed:false,
  gracefullyShutdown:false,resumeReadyAt:'0',
  totalDeposited:'0',totalReleased:'0',totalProvedDebtAmount:'0',
  pendingQueue:{epoch:'1',count:'0',amount:'0',firstBurnId:bytes32('00'),lastBurnId:bytes32('00')},
  outstanding:'0',unreservedCollateral:'0',availableOutflow:config.outflowCapacityBaseUnitsPerDay,
  controlPlaneHealthy:true};
 observation.checkpointRegistry={checkpointConfigHash:config.checkpointRegistryConfigHash,
  bridgeDomain:config.domDomain,domNetworkMagic:config.checkpointDomNetworkMagic,
  domChainId:config.checkpointDomChainId,firstV4Height:config.checkpointFirstV4Height,
  activationEmptyStateRoot:config.checkpointActivationEmptyStateRoot,
  activationScheduleCommitment:config.activationScheduleCommitment,verifier:config.checkpointVerifier,
  checkpointInterval:config.checkpointIntervalBlocks,confirmationDepth:config.checkpointConfirmationDepthBlocks,
  challengePeriod:config.checkpointChallengePeriodSeconds,verifierCodeHash:config.checkpointVerifierCodeHash,
  verifierConfigHash:config.checkpointVerifierConfigHash,guardian:config.checkpointGuardian,
  guardianCodeHash:config.checkpointGuardianCodeHash,
  guardianImplementation:config.checkpointGuardianImplementation,
  guardianImplementationCodeHash:config.checkpointGuardianImplementationCodeHash,
  guardianOwnersCommitment:safeOwnersCommitment(config.checkpointGuardianOwners),
  latestHeight:config.checkpointInitialHeight,
  checkpointCount:'1',halted:false,gracefullyShutdown:false,latestIssuanceClosed:false,
  latestBlock:config.checkpointInitialBlock,
  latestStateRoot:config.checkpointInitialStateRoot,latestContextHash:config.checkpointInitialContextHash,
  latestTotalDifficulty:config.checkpointInitialTotalDifficulty,latestTotalIssued:'0',latestTotalBurned:'0',
  previousTotalIssued:'0',previousTotalBurned:'0',guardianControlHealthy:true};
 observation.checkpointRegistryCandidate={statementHash:bytes32('00'),height:'0',readyAt:'0',
  blockHash:bytes32('00'),stateRoot:bytes32('00'),contextHash:bytes32('00'),totalDifficulty:'0',
  totalIssued:'0',totalBurned:'0',issuanceClosed:false,
  confirmationHeight:'0',confirmationBlock:bytes32('00'),confirmationTotalDifficulty:'0',
  confirmationTimestamp:'0'};
 observation.checkpointRegistrySlot0=config.checkpointRegistryConfigHash;
 return observation;
}
const mainnetPreflightRpcCatalog={schema:'usdom-mainnet-preflight-rpc-catalog-v2',sources:[
 {operatorId:'operator-a',providerId:'provider-a',infrastructureId:'infra-a',
  originKeccak256:bytes32('81'),tlsPolicy:'node-default-ca-hostname-expiry-origin-pinned-v1',
  clockPolicy:'utc-wall-clock-sane-v1',clientPolicy:'ethereum-execution-client-stable-v1'},
 {operatorId:'operator-b',providerId:'provider-b',infrastructureId:'infra-b',
  originKeccak256:bytes32('82'),tlsPolicy:'node-default-ca-hostname-expiry-origin-pinned-v1',
  clockPolicy:'utc-wall-clock-sane-v1',clientPolicy:'ethereum-execution-client-stable-v1'},
]};
const preflightRpcConsensus=()=>rpcConsensusEvidence(mainnetPreflightRpcCatalog.sources.map(source=>({
 sourceId:source.operatorId,originKeccak256:source.originKeccak256,
})));
function preflightAttestation(config,phase) {
 const observation=preflightObservation(config,phase);
 return {...assessMainnetPreflight({phase,releaseConfig:config,observation,
  riscZeroReference:{...PINNED_RISC0_MAINNET_V3}}),
  collectionStartedAtMs:1792492800000,collectionCompletedAtMs:1792492801000,
  observation,rpcConsensus:preflightRpcConsensus()};
}
function nativeReleaseAttestation(kind,config,subjectCommitment) {
 return {approvedBy:config.governance,checkpointRegistryConfigHash:config.checkpointRegistryConfigHash,
  completedAt:'1792492800',kind,releaseId:'release-1',reserveConfigHash:config.reserveConfigHash,
  schema:1,signature:'0x1234',sourceCommit:'a'.repeat(40),subjectCommitment};
}
function nativeApprovalObservation(attestations,config) {
 return {approvals:Object.fromEntries(Object.entries(attestations).map(([name,attestation])=>[
   name,{digest:nativeReleaseAttestationDigest(attestation,config),valid:true},
 ])),chainId:'1',finalizedBlockHash:bytes32('70'),finalizedBlockNumber:'22000000',
  finalizedBlockTimestamp:'1792492900',
  governance:config.governance,governanceCodeHash:config.governanceCodeHash,
  rpcConsensus:rpcConsensusEvidence([{sourceId:'operator-a',originKeccak256:bytes32('81')},
   {sourceId:'operator-b',originKeccak256:bytes32('82')}]),snapshotBlockHashAfter:bytes32('70')};
}
function releaseAuthorizationObservation(authorization,config) {
 return {approvals:{releaseAuthorization:{
   digest:releaseAuthorizationDigest(authorization,config),valid:true,
  }},chainId:'1',finalizedBlockHash:bytes32('70'),finalizedBlockNumber:'22000000',
  finalizedBlockTimestamp:'1792492900',governance:config.governance,
  governanceCodeHash:config.governanceCodeHash,
  rpcConsensus:rpcConsensusEvidence([{sourceId:'operator-a',originKeccak256:bytes32('81')},
   {sourceId:'operator-b',originKeccak256:bytes32('82')}]),snapshotBlockHashAfter:bytes32('70')};
}
function controlPlaneEvidenceFixture(config) {
 const ownersByRole=initialSafeOwnersByRole();
 const replacements={governance:getAddress(address(110)),reserveGuardian:getAddress(address(111)),
  checkpointGuardian:getAddress(address(112)),usdtCustody:getAddress(address(113))};
 const packageDocument=buildRecoverableSafeControlDeploymentPackage({ownersByRole,
  proxyCreationCode:safe141Fixture.proxyCreationCode});
 const controls=packageDocument.controls;
 assert.equal(controls[0].safe,getAddress(config.governance));
 assert.equal(controls[1].safe,getAddress(config.guardian));
 assert.equal(controls[2].safe,getAddress(config.checkpointGuardian));
 const packageHash=_safeControlObservationInternals.documentHash(packageDocument);
 const roleState=(control,stateOwners,nonce)=>{
  const role={role:control.role,address:control.safe,runtimeCodeHash:config.governanceCodeHash,
   singleton:SAFE_MAINNET_IDENTITY.singleton,
   fallbackHandler:SAFE_MAINNET_IDENTITY.fallbackHandler,
   guard:address(0),owners:[...stateOwners],threshold:'2',nonce,modules:[]};
  return {...role,configurationHash:safeControlConfigurationHash({
   ...role,safe:role.address,packageHash,
  })};
 };
 const baselineRoles=controls.map(control=>roleState(control,ownersByRole[control.role],'0'));
 const rpcConsensus=rpcConsensusEvidence([
  {sourceId:'operator-a',originKeccak256:bytes32('81')},
  {sourceId:'operator-b',originKeccak256:bytes32('82')},
 ]);
 const baselineUnsigned={schema:SAFE_CONTROL_SNAPSHOT_SCHEMA,ethereumChainId:'1',packageHash,
  finalizedBlockNumber:'21999000',finalizedBlockHash:bytes32('91'),
  proxyRuntimeCodeHash:config.governanceCodeHash,roles:baselineRoles,rpcConsensus};
 const baselineSnapshot={...baselineUnsigned,
  snapshotHash:_safeControlObservationInternals.documentHash(baselineUnsigned)};
 const transitionsByRole=Object.fromEntries(controls.map(control=>[control.role,{
  lostOwner:ownersByRole[control.role][0],replacementOwner:replacements[control.role]}]));
 const afterRoles=controls.map(control=>roleState(control,
  [replacements[control.role],...ownersByRole[control.role].slice(1)],'1'));
 const afterUnsigned={schema:SAFE_CONTROL_SNAPSHOT_SCHEMA,ethereumChainId:'1',packageHash,
  finalizedBlockNumber:'21999010',finalizedBlockHash:bytes32('92'),
  proxyRuntimeCodeHash:config.governanceCodeHash,roles:afterRoles};
 const afterSnapshot={...afterUnsigned,
  snapshotHash:_safeControlObservationInternals.documentHash(afterUnsigned)};
 const recoveries=controls.map((control,index)=>({role:control.role,safe:control.safe,
  transactionHash:`0x${(0xa1+index).toString(16).repeat(32)}`,
  blockNumber:String(21999001+index),blockHash:`0x${(0xb1+index).toString(16).repeat(32)}`,
  transactionIndex:'0',
  safeTxHash:`0x${(0xc1+index).toString(16).repeat(32)}`,
  signers:ownersByRole[control.role].slice(1),previousNonce:'0',newNonce:'1'}));
 const recoveryUnsigned={schema:SAFE_CONTROL_RECOVERY_SCHEMA,ethereumChainId:'1',packageHash,
  baselineSnapshotHash:baselineSnapshot.snapshotHash,transitionsByRole,
  afterSnapshot,recoveries,rpcConsensus};
 const recoveryReport={...recoveryUnsigned,
  recoveryHash:_safeControlObservationInternals.documentHash(recoveryUnsigned)};
 return buildRecoverableSafeControlReleaseEvidence({
  packageDocument,baselineSnapshot,recoveryReport,
 });
}
function verifierManifest(activationScheduleCommitment) {
 return {schema:VERIFIER_CONFIG_SCHEMA,statementVersion:'1',transitionCommitmentVersion:'2',
  burnStateWitnessVersion:'3',finalizedBurnProverInputVersion:'2',publicOutputVersion:'1',
  burnStatementTypeHash:BURN_STATEMENT_TYPEHASH,
  burnIntentTypeHash:BURN_INTENT_TYPEHASH,privateBurnIdTypeHash:PRIVATE_BURN_ID_TYPEHASH,
  activationScheduleCommitment,domGenesisHash:bytes32('01'),domNetworkMagic:'1146047793',
  domChainId:bytes32('02'),firstV4Height:'100000',activationEmptyStateRoot:bytes32('44'),
  consensusRulesHash:bytes32('03'),
  forkChoiceRulesHash:bytes32('04'),powRulesHash:bytes32('05'),nativeAssetId:bytes32('06'),
  noteTreeRulesHash:bytes32('07'),nullifierRulesHash:bytes32('08'),balanceRulesHash:bytes32('09'),
  finalityRulesHash:bytes32('0a'),proofSystem:FINALIZED_BURN_PROOF_SYSTEM,
  verifyingKeySha256:'0x'+documentSha('evidence/verifying-key.bin'),
  trustedSetupRequired:true,
  trustedSetupTranscriptSha256:'0x'+trustedSetupVerificationSha256,
  provingProgramSha256:'0x'+documentSha('evidence/proving-program.bin'),
  sourceManifestSha256:'0x'+documentSha('evidence/proving-program-sources.sha256'),
  verifierArtifactSha256:'0x'+documentSha(
    'out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json'),
  maxProofBytes:'260',minimumFinalityBeaconSlot:'12000000',ethereumChainId:'1',
  riscZeroVerifier:PINNED_RISC0_MAINNET_V3.verifier_address,
  riscZeroVerifierCodeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
  riscZeroVerifierSelector:FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,
  finalizedBurnGuestImageId:bytes32('1d'),journalSchemaHash:FINALIZED_BURN_RISC0_JOURNAL_SCHEMA_HASH};
}
function checkpointVerifierManifest(activationScheduleCommitment) {
 return {schema:CHECKPOINT_VERIFIER_CONFIG_SCHEMA,statementVersion:'6',checkpointProverInputVersion:'4',
  continuationContextVersion:'2',
  transitionCommitmentVersion:'4',activationScheduleVersion:'2',publicOutputVersion:'1',
  publicStatementBytes:'551',continuationContextBytes:'695',checkpointStatementTypeHash:CHECKPOINT_STATEMENT_TYPEHASH,
  segmentStateVersion:'2',segmentTransitionVersion:'4',randomxStatementVersion:'1',
  segmentStateBytes:'1105',segmentTransitionBytes:'2320',randomxStatementBytes:'384',
  segmentStateDomainHash:CHECKPOINT_SEGMENT_STATE_DOMAIN_HASH,
  segmentTransitionDomainHash:CHECKPOINT_SEGMENT_TRANSITION_DOMAIN_HASH,
  randomxStatementDomainHash:CHECKPOINT_RANDOMX_STATEMENT_DOMAIN_HASH,
  randomxReceiptImageId:'0x'+CHECKPOINT_RANDOMX_IMAGE_ID,
  proofAcceptedHash:CHECKPOINT_PROOF_ACCEPTED_HASH,activationScheduleCommitment,
  domGenesisHash:bytes32('01'),domNetworkMagic:'1146047793',domChainId:bytes32('02'),
  firstV4Height:'100000',activationEmptyStateRoot:bytes32('44'),checkpointInterval:'360',
  confirmationDepth:'30',challengePeriod:'172800',maxCheckpointSpan:'390',
  consensusRulesHash:bytes32('11'),forkChoiceRulesHash:bytes32('12'),powRulesHash:bytes32('13'),
  nativeStateRulesHash:bytes32('14'),continuationContextRulesHash:bytes32('19'),
  consensusExtensionWitnessRulesHash:bytes32('15'),
  proofSystem:CHECKPOINT_PROOF_SYSTEM,
  verifyingKeySha256:'0x'+documentSha('evidence/verifying-key.bin'),trustedSetupRequired:true,
  trustedSetupTranscriptSha256:'0x'+trustedSetupVerificationSha256,
  provingProgramSha256:'0x'+documentSha('evidence/checkpoint-proving-program.bin'),
  sourceManifestSha256:'0x'+documentSha('evidence/checkpoint-proving-program-sources.sha256'),
  verifierArtifactSha256:'0x'+documentSha(
    'out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json'),
  maxProofBytes:'260',
  ethereumChainId:'1',riscZeroVerifier:PINNED_RISC0_MAINNET_V3.verifier_address,
  riscZeroVerifierCodeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
  riscZeroVerifierSelector:CHECKPOINT_RISC0_GROTH16_V3_SELECTOR,
  checkpointGuestImageId:bytes32('1c'),journalSchemaHash:CHECKPOINT_RISC0_JOURNAL_SCHEMA_HASH};
}
const checkpointProofRequiredKeys=[
 'production_checkpoint_registry_artifacts_pinned',
 'production_checkpoint_registry_bootstrap_ratified',
 'production_checkpoint_registry_positive_finalized_event_vector',
 'production_checkpoint_consensus_extension_private_input_implemented',
 'production_checkpoint_consensus_extension_guest_compiled',
 'production_checkpoint_registry_risc0_evm_adapter_image_id_pinned',
 'production_checkpoint_recursive_segment_transition_implemented',
 'production_checkpoint_recursive_receipt_aggregation_implemented',
 'production_checkpoint_segment_private_input_covers_all_valid_dom_blocks',
 'production_checkpoint_recursive_economic_witness_covers_all_consensus_valid_blocks',
 'production_checkpoint_recursive_economic_effect_count_consensus_bounded',
 'production_checkpoint_recursive_economic_receipt_exact_block_bound',
 'production_checkpoint_randomx_statement_header_fields_non_substitutable',
 'production_checkpoint_randomx_aggregate_is_component_receipt_only',
 'production_checkpoint_segment_guest_authorizes_bounded_transition_only',
 'production_checkpoint_outer_guest_is_checkpoint_statement_authority',
 'production_checkpoint_randomx_native_reference_prevalidates_all_production_statements',
 'production_checkpoint_randomx_native_reference_is_not_production_authority',
 'production_checkpoint_pow_authority_requires_pinned_randomx_receipt',
 'production_checkpoint_economic_recursive_source_export_implemented',
 'production_checkpoint_economic_receipt_job_planner_implemented',
 'production_checkpoint_economic_local_succinct_prover_implemented',
 'production_checkpoint_authenticated_segment_job_planner_implemented',
 'production_checkpoint_authenticated_segment_local_succinct_prover_implemented',
 'production_checkpoint_authenticated_outer_job_planner_implemented',
 'production_checkpoint_authenticated_outer_local_succinct_prover_implemented',
 'production_checkpoint_outer_groth16_evm_packager_implemented',
 'production_checkpoint_authenticated_submission_package_implemented',
 'production_checkpoint_submission_package_create_once_private',
 'production_checkpoint_submission_inputs_rechecked_before_write',
 'production_checkpoint_authenticated_submission_local_evm_verification_implemented',
 'production_checkpoint_capacity_report_semantically_validated',
 'production_checkpoint_capacity_report_binds_all_six_recursive_layers',
 'production_checkpoint_capacity_report_recomputes_release_statement',
 'production_checkpoint_capacity_report_binds_ordered_artifact_sets',
 'production_checkpoint_capacity_artifact_set_commitment_implemented',
 'production_checkpoint_capacity_report_materializer_implemented',
 'production_checkpoint_capacity_private_run_toctou_rejected',
 'production_checkpoint_capacity_historical_report_create_once',
 'production_checkpoint_capacity_report_measures_groth16_compression',
 'production_checkpoint_capacity_artifact_collector_implemented',
 'production_checkpoint_capacity_collector_binds_groth16_and_evm_seal',
 'production_checkpoint_capacity_e2e_executor_implemented',
 'production_checkpoint_capacity_executor_clean_workspace_enforced',
 'production_checkpoint_capacity_executor_local_evm_verification_implemented',
 'production_checkpoint_isolated_evm_receipt_bound_to_capacity_report',
 'production_checkpoint_finalized_snapshot_observer_implemented',
 'production_checkpoint_candidate_lifecycle_assessment_implemented',
 'production_candidate_monitor_strict_bounded_state_parsing',
 'production_checkpoint_observer_secret_free_rpc_launcher_implemented',
 'production_checkpoint_guest_randomx_relation_implemented',
 'production_checkpoint_canonical_source_export_fail_closed',
 'production_checkpoint_canonical_source_set_export_fail_closed',
 'production_checkpoint_randomx_measurement_plan_fail_closed',
 'production_checkpoint_randomx_measurement_inputs_strict_and_toctou_rejected',
 'production_checkpoint_randomx_authenticated_statement_export_fail_closed',
 'production_checkpoint_randomx_authenticated_statement_set_export_fail_closed',
 'production_checkpoint_randomx_authenticated_receipt_job_plan_fail_closed',
 'production_checkpoint_randomx_proof_receipt_implemented',
 'production_checkpoint_randomx_aggregate_receipt_implemented',
 'production_checkpoint_randomx_authenticated_aggregate_job_plan_fail_closed',
 'production_checkpoint_randomx_image_id_cross_layer_binding_implemented',
 'production_checkpoint_randomx_verified_summary_bound_to_capacity_evidence',
 'production_checkpoint_randomx_resource_transcripts_bound_to_capacity_report',
 'production_checkpoint_risc0_runtime_finalized_observation_bound_to_capacity_report',
 'production_native_runtime_candidate_v2_required_by_release_gate',
 'production_checkpoint_randomx_receipt_image_id_pinned',
];
const checkpointReceiptCompletionRequiredKeys=[
 'production_checkpoint_randomx_complete_guest_positive_receipt_executed',
 'production_checkpoint_randomx_complete_guest_proving_cost_measured',
 'production_checkpoint_economic_chunk_guest_cryptographic_receipt_generated',
 'production_checkpoint_economic_chunk_guest_proving_cost_measured',
 'production_checkpoint_economic_block_guest_positive_receipt_executed',
 'production_checkpoint_economic_block_guest_proving_cost_measured',
 'production_checkpoint_segment_guest_positive_receipt_executed',
 'production_checkpoint_segment_guest_proving_cost_measured',
 'production_checkpoint_outer_guest_positive_receipt_executed',
 'production_checkpoint_outer_guest_proving_cost_measured',
 'production_checkpoint_outer_guest_adapter_binding_implemented',
];
const recoverableControlPlaneRequiredKeys=[
 'production_recoverable_safe_control_unsigned_package_implemented',
 'production_recoverable_safe_control_two_of_three_enforced',
 'production_recoverable_safe_control_independent_hardware_keys_required',
 'production_onekey_classic_1s_model_pinned',
 'production_onekey_official_ble_transport_pinned',
 'production_onekey_ble_pairing_and_permissions_verified',
 'production_onekey_ble_device_identity_and_reconnection_verified',
 'production_onekey_usb_fallback_disabled',
 'production_onekey_ethereum_derivation_path_explicit',
 'production_onekey_address_verified_on_device',
 'production_onekey_sdk_firmware_transport_versions_pinned',
 'production_onekey_eip1559_and_eip712_signing_verified',
 'production_onekey_reject_cancel_disconnect_reconnect_verified',
 'production_onekey_ios_walletconnect_authority_pinned',
 'production_onekey_ios_walletconnect_session_runtime_pinned',
 'production_onekey_ios_exact_eip712_signing_verified',
 'production_onekey_mobile_physical_ceremony_ratified',
 'production_onekey_hardware_signing_approved',
 'production_onekey_ios_relayer_role_separation_verified',
 'production_onekey_ios_relayer_no_token_custody_verified',
 'production_onekey_ios_relayer_signed_safetx_exact_calldata_verified',
 'production_onekey_ios_relayer_economic_caps_verified',
 'production_onekey_ios_relayer_nonce_no_blind_retry_verified',
 'production_onekey_ios_relayer_emergency_rotation_verified',
 'production_onekey_ios_safe_custody_identity_verified',
 'production_onekey_ios_safe_custody_dual_rpc_finality_verified',
 'production_onekey_ios_safe_custody_relayer_no_usdt_verified',
 'production_onekey_ios_safe_custody_approve_eip712_finalized',
 'production_onekey_ios_safe_custody_deposit_eip712_finalized',
 'production_onekey_ios_safe_custody_deposit_event_verified',
 'production_onekey_ios_safe_custody_accounting_verified',
 'production_onekey_ios_safe_custody_operator_ratification_bound',
 'production_ledger_compatibility_disabled',
 'production_recoverable_safe_control_finalized_snapshot_collector_implemented',
 'production_recoverable_safe_control_catalog_bound_multirpc_collection',
 'production_recoverable_safe_control_catalog_bound_multirpc_planning',
 'production_recoverable_safe_control_bounded_multirpc_deployment_planning',
 'production_recoverable_safe_control_broadcast_endpoint_catalog_member_enforced',
 'production_recoverable_safe_control_final_evidence_create_once',
 'production_recoverable_safe_control_catalog_bound_multirpc_recovery_observation',
 'production_recoverable_safe_control_operational_inputs_toctou_rejected',
 'production_recoverable_safe_control_recovery_verifier_implemented',
 'production_recoverable_safe_control_two_survivor_signatures_enforced',
 'production_recoverable_safe_control_recovery_unsigned_plan_implemented',
 'production_recoverable_safe_control_hardware_signature_handoff_implemented',
 'production_recoverable_safe_control_signing_inputs_rechecked_per_onekey_action',
 'production_recoverable_safe_control_signature_outputs_create_once',
 'production_recoverable_safe_control_recovery_transaction_assembly_implemented',
 'production_recoverable_safe_control_recovery_crash_safe_executor_implemented',
 'production_recoverable_safe_control_finalized_dual_rpc_execution_observer_implemented',
 'production_recoverable_safe_control_raw_transaction_journal_before_publish_enforced',
 'production_recoverable_safe_control_dual_rpc_envelope_planner_implemented',
 'production_recoverable_safe_control_eip1559_fee_and_gas_caps_enforced',
 'production_recoverable_safe_control_signed_envelope_revalidation_enforced',
 'production_recoverable_safe_control_release_evidence_reconciliation_implemented',
 'production_recoverable_safe_control_two_commit_materialization_implemented',
 'production_release_provenance_identity_materialization_implemented',
 'production_release_provenance_multi_aggregate_toctou_rejected',
 'production_signed_release_source_commit_ceremony_implemented',
 'production_signed_release_evidence_commit_and_tag_ceremony_implemented',
];
const proofOperationalCapacityRequiredKeys=[
 'production_finalized_burn_proving_capacity_measured',
 'production_finalized_burn_evm_verification_gas_measured',
 'production_checkpoint_outer_evm_verification_gas_measured',
 'production_queue_withdrawal_worst_case_gas_measured',
 'production_prune_expired_256_worst_case_gas_measured',
 'production_prune_discardable_256_worst_case_gas_measured',
 'production_safe_admin_overhead_gas_measured',
];
const productionActivationAndPrivacyRequiredKeys=[
 'native_privacy_trusted_setup_ceremony_completed',
 'native_scheduled_public_runtime_configured',
 'production_native_release_attestation_content_revalidated',
 'production_native_attestation_eip1271_finalized_approval_enforced',
];
const realFundsCustodyRequiredKeys=[
 'native_private_wallet_public_receiving_commitment_export_implemented',
 'native_private_wallet_fixed_receiving_ceremony_command_implemented',
 'production_closed_mainnet_deposit_unsigned_package_implemented',
 'production_closed_mainnet_deposit_inputs_rechecked_before_output',
 'production_closed_mainnet_deposit_fixed_minimal_amount_enforced',
 'production_closed_mainnet_private_burn_offline_command_implemented',
 'native_private_wallet_tpm2_monotonic_authority_implemented',
 'production_closed_mainnet_tpm2_authority_bootstrap_command_implemented',
 'production_closed_mainnet_private_burn_submission_command_implemented',
 'production_closed_mainnet_private_burn_intent_journal_before_submit',
 'production_closed_mainnet_private_burn_inputs_and_binary_pinned',
 'production_closed_mainnet_private_burn_preparation_inputs_and_binary_pinned',
 'native_private_wallet_tpm2_operational_keystore_implemented',
 'native_private_wallet_recovery_and_operational_passwords_separated',
 'production_closed_mainnet_tpm2_keystore_provision_command_implemented',
 'native_private_wallet_verified_checkpoint_disaster_recovery_implemented',
 'production_closed_mainnet_wallet_recovery_drill_command_implemented',
 'production_closed_mainnet_wallet_recovery_inputs_binary_and_output_pinned',
 'native_private_wallet_hardware_or_os_keystore_integrated',
 'native_private_wallet_recovery_ceremony_implemented',
 'production_native_wallet_attestation_content_revalidated',
];
const riscZeroAdapterRequiredKeys=[
 'finalized_burn_risc0_adapter_selector_canonical_abi_enforced',
 'finalized_burn_risc0_adapter_verify_empty_returndata_enforced',
 'checkpoint_risc0_adapter_selector_canonical_abi_enforced',
 'checkpoint_risc0_adapter_verify_empty_returndata_enforced',
 'risc0_adapter_verify_return_bomb_not_copied',
];
const riscZeroGuestInputRequiredKeys=[
 'risc0_guest_host_input_bounded_before_allocation',
];
const finalizedBurnSubmissionRequiredKeys=[
 'production_finalized_burn_groth16_evm_packager_implemented',
 'production_finalized_burn_authenticated_submission_package_implemented',
 'production_finalized_burn_submission_package_create_once_private',
 'production_finalized_burn_submission_inputs_rechecked_before_write',
 'production_finalized_burn_authenticated_submission_local_evm_verification_implemented',
 'production_finalized_burn_e2e_report_content_revalidated',
 'production_finalized_burn_e2e_report_v4_enforced',
 'production_finalized_burn_release_evm_receipt_bound_to_e2e_report',
 'production_finalized_burn_e2e_burn_tuple_recomputed',
 'production_finalized_burn_artifact_collector_implemented',
 'production_finalized_burn_release_e2e_executor_implemented',
 'production_finalized_burn_release_evidence_materializer_implemented',
 'production_finalized_burn_private_run_toctou_rejected',
 'production_finalized_burn_historical_report_create_once',
 'production_finalized_burn_capacity_report_semantically_validated',
 'production_finalized_burn_isolated_evm_receipt_bound_to_capacity_report',
 'production_closed_deposit_queue_redemption_rehearsal_implemented',
];
const ethereumFinalityPanicBoundaryRequiredKeys=[
 'ethereum_finality_untrusted_paths_panic_free',
];
const nativeStatePanicBoundaryRequiredKeys=[
 'native_state_untrusted_decoders_panic_free',
];
const nativePrivacyPanicBoundaryRequiredKeys=[
 'native_privacy_untrusted_decoders_panic_free',
];
const proofProgramBoundaryRequiredKeys=[
 'proof_program_untrusted_paths_panic_free',
 'proof_program_host_inputs_bounded_before_read_to_end',
];
const nativeWalletPanicBoundaryRequiredKeys=[
 'native_wallet_untrusted_paths_panic_free',
];
const preflightSnapshotRequiredKeys=[
 'production_mainnet_preflight_single_finalized_snapshot_enforced',
 'production_mainnet_attestation_content_revalidated',
 'production_mainnet_preflight_canonical_uint_encoding_enforced',
 'production_mainnet_preflight_exact_observation_schema_enforced',
];
const renewableBurnClaimRequiredKeys=[
 'production_irreversible_burn_claim_survives_queue_expiry',
 'production_withdrawal_queue_lease_renewable',
 'production_withdrawal_queue_lease_uses_current_ethereum_time',
 'production_burn_intent_valid_until_is_not_payout_extinguishment',
 'production_finalized_burn_historical_claim_reproof_vector',
 'production_finalized_burn_reproof_binds_fresh_finality_slot',
 'production_finalized_burn_reproof_preserves_original_intent_deadline',
];
const riscZeroConfigRequiredKeys=[
 'production_finalized_burn_risc0_adapter_config_manifest_reconciled',
 'production_finalized_burn_proving_program_config_hash_separated',
 'production_risc0_adapters_same_upstream_identity_required',
 'production_risc0_mainnet_reference_source_pinned',
 'production_risc0_mainnet_reference_release_gate_required',
 'production_risc0_direct_verifier_router_estop_distinguished',
 'production_risc0_upstream_health_monitor_implemented',
 'production_risc0_upstream_estop_preflight_implemented',
 'production_risc0_upstream_incident_response_implemented',
 'production_risc0_unconfirmed_failure_cannot_halt_registry',
 'production_risc0_irreversible_halt_requires_two_release_approved_source_operators',
 'production_risc0_health_source_catalog_validator_implemented',
 'production_risc0_health_source_catalog_release_evidence_bound',
 'production_risc0_catalog_matched_multi_rpc_collector_implemented',
 'production_risc0_rpc_urls_redacted_and_not_persisted',
 'production_risc0_all_endpoint_identities_validated_before_network_access',
 'production_risc0_source_catalog_materializer_implemented',
 'production_risc0_source_catalog_historical_evidence_create_once',
 'production_risc0_source_catalog_aggregate_boundary_toctou_rejected',
 'production_risc0_source_catalog_materializer_fail_closed_atomic_writes',
 'production_risc0_health_single_finalized_snapshot_enforced',
 'production_risc0_health_canonical_identity_types_enforced',
 'production_risc0_health_exact_observation_schema_enforced',
 'production_risc0_upstream_health_response_drill_passed',
 'production_finalized_burn_adapter_runtime_source_derived',
 'production_checkpoint_adapter_runtime_source_derived',
 'production_risc0_adapter_artifact_paths_canonical',
 'production_risc0_adapter_runtime_evm_differential_verified',
];
const requiredKeys=[
 'native_set_witness_bounded_cursor_deserialization',
 'native_consensus_implemented','consensus_proof_implemented','production_block_header_state_commitment_implemented',
 'production_finalized_burn_verifier_implemented',
 'production_finalized_burn_proof_backend_selected','production_finalized_burn_guest_compiled',
 'production_finalized_burn_recursive_checkpoint_relation_implemented',
 'production_finalized_burn_recursive_checkpoint_artifacts_pinned',
 'production_finalized_burn_recursive_checkpoint_receipt_verified',
 'production_finalized_burn_guest_benchmarked','production_finalized_burn_raw_checkpoint_positive_vector',
 'production_finalized_burn_risc0_evm_receipt_verifier_implemented',
 'production_finalized_burn_canonical_replay_slot_enforced',
 'production_finalized_burn_positive_evidence_checker_implemented',
 'production_finalized_burn_authenticated_proof_job_planner_implemented',
 ...finalizedBurnSubmissionRequiredKeys,
 ...proofOperationalCapacityRequiredKeys,
 ...riscZeroAdapterRequiredKeys,
 ...riscZeroGuestInputRequiredKeys,
 ...ethereumFinalityPanicBoundaryRequiredKeys,
 ...nativeStatePanicBoundaryRequiredKeys,
 ...nativePrivacyPanicBoundaryRequiredKeys,
 ...proofProgramBoundaryRequiredKeys,
 ...nativeWalletPanicBoundaryRequiredKeys,
 ...preflightSnapshotRequiredKeys,
 ...renewableBurnClaimRequiredKeys,
 ...riscZeroConfigRequiredKeys,
 'production_checkpoint_registry_contract_implemented','production_checkpoint_registry_verifier_implemented',
 'production_checkpoint_registry_verifier_proves_consensus_extension',
 'production_checkpoint_registry_artifact_pinning_implemented','production_checkpoint_registry_bootstrap_ratified',
 'production_checkpoint_registry_artifacts_pinned',
 'production_checkpoint_registry_positive_finalized_event_vector',
 ...checkpointProofRequiredKeys,
 ...checkpointReceiptCompletionRequiredKeys,
 'verified_ethereum_checkpoint_native_burn_binding_enforces_dom_fork_choice',
 'production_finalized_deposit_readonly_source_collector_implemented',
 'production_finalized_deposit_catalog_bound_multisource',
 'production_finalized_deposit_durable_source_binds_catalog',
 'production_finalized_deposit_source_catalog_toctou_rejected',
 'production_finalized_deposit_authenticated_witness_builder_implemented',
 'production_finalized_deposit_witness_consensus_replay_implemented',
 'production_finalized_deposit_authenticated_issuance_rpc_implemented',
 'production_finalized_deposit_issuance_inputs_rechecked_after_submission',
 'production_finalized_deposit_issuance_intent_journal_before_post',
 'production_finalized_deposit_issuance_strict_bounded_response',
 'production_finalized_deposit_wallet_preregistration_implemented',
 'production_finalized_deposit_wallet_registration_inputs_binary_identity_and_state_pinned',
 'production_finalized_deposit_submission_ceremony_implemented',
 'production_closed_mainnet_isolated_node_ceremony_implemented',
 'production_closed_mainnet_exact_one_block_ceremony_implemented',
 'production_closed_mainnet_node_action_inputs_toctou_rejected',
 'production_closed_mainnet_issuance_block_receipt_create_once',
 'production_closed_mainnet_issuance_block_intent_journal_before_post',
 'production_closed_mainnet_node_rpc_strict_json_identity_stability',
 'production_closed_mainnet_genesis_receipt_create_once',
 'production_closed_mainnet_genesis_intent_journal_before_post',
 'production_finalized_deposit_authenticated_wallet_observation_implemented',
 'production_finalized_deposit_wallet_observation_inputs_binary_identity_and_state_pinned',
 'real_finalized_reserve_deposit_native_block_vector_implemented',
 'native_privacy_production_verifying_key_installed',
 ...productionActivationAndPrivacyRequiredKeys,
 'mainnet_release_two_commit_evidence_provenance_enforced',
 'mainnet_release_metadata_exact_schema_enforced',
 'production_release_config_exact_schema_and_native_timing_enforced',
 'production_native_runtime_manifest_release_bound',
 'production_native_ethereum_policies_release_reconciled',
 'production_native_ethereum_consensus_config_release_bound',
 'production_unsigned_mainnet_deployment_package_source_verified',
 'production_unsigned_deployment_package_initcodes_release_bound',
 'production_deployment_package_rederived_before_broadcast',
 'production_mainnet_deployment_crash_safe_executor_implemented',
 'production_mainnet_deployment_dual_rpc_finalized_observer_implemented',
 'production_mainnet_deployment_catalog_bound_multirpc_executor',
 'production_mainnet_deployment_finalized_receipt_canonicality_enforced',
 'production_mainnet_deployment_final_persistence_input_recheck',
 'production_mainnet_deployment_rpc_url_redaction_enforced',
 'production_mainnet_deployment_per_source_double_receipt_recheck',
 'production_mainnet_deployment_post_wait_finality_revalidated',
 'production_mainnet_deployment_raw_transaction_revalidation_enforced',
 'production_mainnet_deployment_eip1559_fee_and_gas_caps_enforced',
 'production_mainnet_deployment_split_authorization_enforced',
 'production_limited_mainnet_policy_materializer_implemented',
 'production_mainnet_deployment_identity_materializer_implemented',
 'production_mainnet_deployment_identity_rpc_secret_redaction_enforced',
 'production_mainnet_deployment_identity_catalog_bound',
 'production_mainnet_deployment_identity_observation_binds_rpc_origins',
 'production_mainnet_deployment_identity_full_snapshot_recheck_enforced',
 'production_mainnet_deployment_identity_rpc_catalog_toctou_rejected',
 'production_mainnet_deployment_identity_rederived_before_each_persistence',
 'production_safe_control_durable_objects_bind_rpc_consensus',
 'production_deterministic_residual_risk_report_writer_implemented',
 'production_finalized_eip1271_release_authorization_materializer_implemented',
 'production_release_authorization_signing_inputs_rechecked_per_onekey_action',
 'production_release_authorization_signature_bundles_create_once',
 'production_release_authorization_multi_output_toctou_rejected',
 'production_release_authorization_catalog_bound_multirpc',
 'production_release_authorization_double_collection_and_snapshot_recheck',
 'production_release_authorization_rpc_catalog_toctou_rejected',
 'production_release_authorization_request_rpc_catalog_toctou_rejected',
 'production_source_bound_native_attestation_materializer_implemented',
 'production_native_attestation_catalog_bound_multirpc',
 'production_native_attestation_double_collection_and_snapshot_recheck',
 'production_native_attestation_rpc_catalog_toctou_rejected',
 'production_native_attestation_request_rpc_catalog_toctou_rejected',
 'production_safe_control_unsigned_hardware_deployment_package_implemented',
 ...recoverableControlPlaneRequiredKeys,
 'production_safe_control_identity_pins_nonoverridable',
 'production_adapter_deployment_receipts_release_bound',
 'production_predeployment_adapter_receipts_release_bound',
 'production_deployment_receipt_contract_address_observed',
 'native_private_mining_real_finalized_deposit_vector_implemented','production_activation_schedule_implemented',
 'native_private_prover_linked_into_node','native_private_wallet_node_dependency',
 'native_private_wallet_private_burn_random_identifiers',
 'native_private_wallet_private_burn_request_id_pending_collision_rejected',
 'native_private_wallet_private_burn_identifiers_proof_and_consensus_bound',
 'native_private_wallet_authenticated_history_atomic_application',
 'native_private_wallet_authenticated_history_partial_release_forbidden',
 'native_private_wallet_authenticated_history_completed_scan_fields_private',
 'native_private_wallet_authenticated_history_failure_restores_original_tip',
 'verified_native_burn_checkpoint_external_restart_floor_required',
 'production_verified_checkpoint_restart_witness_live_exercised',
 'production_reserve_config_hash_configured','solidity_production_contract_lint_clean',
 'solidity_deep_fuzz_and_invariants_passed','proof_reserve_exact_deployment_commitment_implemented',
 'proof_reserve_mainnet_initial_pause_implemented',
 'production_control_plane_recovery_drill_passed','production_mainnet_predeployment_preflight_passed',
 'native_private_wallet_key_management_implemented',
 'native_private_wallet_production_monotonic_seal_authority_integrated',
 ...realFundsCustodyRequiredKeys,
 'native_private_wallet_remote_historical_deposit_rescan_implemented','native_private_wallet_history_finality_claimed',
 'production_ethereum_checkpoint_source_catalog_materializer_implemented',
 'production_ethereum_checkpoint_consensus_collector_implemented',
 'production_ethereum_checkpoint_light_client_bootstrap_verified',
 'production_security_validation_report_semantically_validated',
 'production_security_validation_report_materializer_implemented',
 'production_operations_review_report_semantically_validated',
 'production_operations_review_report_materializer_implemented',
 'production_release_dom_domain_derivation_enforced',
 'production_mainnet_fork_rehearsal_report_semantically_validated',
 'production_mainnet_fork_rehearsal_raw_bytes_hash_recomputed',
 'production_mainnet_fork_rehearsal_report_materializer_implemented',
 'production_checkpoint_bootstrap_ratification_report_semantically_validated',
 'production_checkpoint_bootstrap_ratification_report_materializer_implemented',
 'production_checkpoint_bootstrap_rpc_catalog_materializer_implemented',
 'production_checkpoint_bootstrap_ratification_live_collector_implemented',
 'production_checkpoint_bootstrap_ratification_collector_input_toctou_rejected',
 'production_checkpoint_bootstrap_ratification_rpc_secrets_not_persisted',
 'production_checkpoint_finalized_event_report_semantically_validated',
 'production_checkpoint_finalized_event_report_materializer_implemented',
 'production_checkpoint_finalized_event_rpc_catalog_materializer_implemented',
 'production_checkpoint_finalized_event_live_collector_implemented',
 'production_checkpoint_finalized_event_collector_input_toctou_rejected',
 'production_checkpoint_finalized_event_rpc_secrets_not_persisted',
 'production_checkpoint_finalized_event_report_input_toctou_rejected',
 'production_mainnet_preflight_rpc_catalog_materializer_implemented',
 'production_mainnet_preflight_bounded_strict_rpc_transport_implemented',
 'production_mainnet_preflight_rpc_secrets_not_persisted',
 'production_mainnet_preflight_fixed_inputs_toctou_rejected',
 'production_mainnet_preflight_materialization_aggregate_boundaries_rechecked',
 'production_mainnet_preflight_durable_report_binds_rpc_consensus',
 'production_finalized_approval_durable_observations_bind_rpc_consensus',
 'production_signing_request_finalized_anchors_bind_rpc_consensus',
 'production_safe_recovery_envelope_binds_rpc_consensus',
 'production_safe_release_bundle_binds_rpc_consensus',
 'production_deployment_package_binds_identity_observation',
 'production_deployment_transaction_handoff_binds_identity_observation',
 'production_safe_recovery_presign_envelope_reobserved',
 'production_mainnet_deployment_presign_network_reobserved',
 'production_safe_recovery_each_signature_network_reobserved',
 'production_release_multisig_each_signature_network_reobserved',
 'production_checkpoint_bootstrap_ratification_signing_ceremony_implemented',
 'production_checkpoint_finalized_transaction_reference_bound',
 'production_safe_recovery_finalized_execution_references_bound',
 'production_mainnet_preflight_deployment_references_bound',
 'production_safe_recovery_owner_transition_derived_from_plan',
 'production_safe_recovery_raw_semantics_derived_from_envelope',
 'production_safe_recovery_observer_role_derived_from_envelope',
 'production_safe_recovery_target_role_derived_from_envelope',
 'production_safe_recovery_signer_owner_transition_derived_from_plan',
 'production_safe_recovery_executor_external_gas_only_relayer_verified',
 'production_deployment_handoff_observation_sha_derived_from_package',
 'production_deployment_executor_package_sha_derived_from_snapshot',
 'production_deployment_executor_observation_snapshotted',
 'production_wallet_registration_manifest_snapshotted',
 'production_private_burn_submission_manifest_snapshotted',
 'production_private_burn_preparation_manifest_snapshotted',
 'production_finalized_deposit_observation_manifest_snapshotted',
 'production_tpm_authority_bootstrap_manifest_snapshotted',
 'production_wallet_recovery_manifest_snapshotted',
 'production_tpm_keystore_provision_manifest_snapshotted',
 'production_finalized_deposit_witness_inputs_snapshotted',
 'production_checkpoint_source_manifest_snapshotted',
 'production_checkpoint_source_set_manifest_snapshotted',
 'production_finalized_burn_source_manifest_snapshotted',
 'production_finalized_burn_source_evidence_snapshotted',
 'production_randomx_statement_private_inputs_snapshotted',
 'production_randomx_statement_set_inputs_snapshotted',
 'production_randomx_proof_plan_inputs_snapshotted',
 'production_randomx_prover_inputs_and_receipts_snapshotted',
 'production_economic_proof_plan_inputs_snapshotted',
 'production_economic_prover_inputs_and_receipts_snapshotted',
 'production_checkpoint_segment_plan_inputs_snapshotted',
 'production_checkpoint_segment_prover_inputs_and_receipts_snapshotted',
 'production_checkpoint_outer_plan_inputs_snapshotted',
 'production_checkpoint_outer_prover_inputs_and_receipts_snapshotted',
 'production_finalized_burn_plan_inputs_snapshotted',
 'production_finalized_burn_prover_inputs_and_receipts_snapshotted',
 'production_checkpoint_capacity_adapter_artifact_snapshotted',
 'production_finalized_burn_evm_package_inputs_and_outputs_snapshotted',
 'production_finalized_burn_release_adapter_artifact_snapshotted',
 'production_finalized_burn_submission_inputs_snapshotted_and_package_reread',
 'production_finalized_burn_capacity_adapter_artifact_snapshotted',
 'production_finalized_burn_artifact_collector_uses_one_revalidated_replica',
 'production_checkpoint_capacity_report_logs_snapshotted_and_origins_rechecked',
 'production_finalized_burn_release_metric_logs_snapshotted_and_origins_rechecked',
 'production_finalized_burn_release_run_pair_snapshotted_and_origins_rechecked',
 'production_finalized_burn_capacity_source_metrics_snapshotted_and_origin_rechecked',
 'production_checkpoint_capacity_materializer_run_pair_snapshotted_and_origins_rechecked',
 'production_mainnet_preflight_materializer_inputs_snapshotted_and_origins_rechecked',
 'production_finalized_burn_capacity_source_receipts_snapshotted_and_origins_rechecked',
 'production_risc0_health_catalog_materializer_inputs_snapshotted_and_origins_rechecked',
 'production_residual_risk_report_semantically_validated',
 'production_shared_trusted_setup_decision_report_semantically_validated',
 'production_shared_trusted_setup_decision_report_materializer_implemented',
 'production_trusted_setup_config_manifest_contents_recomputed',
 'production_authenticated_checkpoint_observer_catalog_bound_multi_rpc',
 'production_authenticated_checkpoint_durable_report_binds_rpc_source_set',
 'production_authenticated_checkpoint_observer_strict_bounded_transport',
 'production_authenticated_checkpoint_observer_private_create_once_evidence',
 'production_authenticated_checkpoint_observer_input_toctou_rejected',
 'production_security_validation_toolchain_hashes_enforced',
 'production_operations_review_input_toctou_rejected',
 'production_operations_review_document_contents_recomputed',
 'production_residual_risk_input_toctou_rejected',
 'production_trusted_setup_content_hash_and_toctou_enforced',
 'production_checkpoint_bootstrap_ratification_input_toctou_rejected',
 'production_mainnet_fork_rehearsal_input_toctou_rejected',
 'production_risc0_health_all_catalog_sources_required',
 'production_risc0_health_bounded_strict_rpc_transport',
 'production_risc0_health_same_snapshot_rechecks_enforced',
 'production_risc0_health_fixed_inputs_toctou_rejected',
 'production_security_validation_final_source_manifest_recheck',
 'production_security_validation_ambient_injection_rejected',
 'production_reserve_reproducible_build_report_semantically_validated',
 'production_reserve_reproducible_build_report_materializer_implemented',
 'production_verifier_reproducible_build_report_semantically_validated',
 'production_verifier_reproducible_build_report_materializer_implemented',
 'production_checkpoint_registry_reproducible_build_report_semantically_validated',
 'production_checkpoint_registry_reproducible_build_report_materializer_implemented',
 'production_checkpoint_verifier_reproducible_build_report_semantically_validated',
 'production_checkpoint_verifier_reproducible_build_report_materializer_implemented',
 'production_reproducible_build_forge_executable_identity_pinned',
 'production_reproducible_build_ambient_environment_rejected',
 'production_reproducible_build_artifact_source_snapshot_rechecked',
 'production_dom_anchor_single_lmdb_snapshot_enforced',
 'production_dom_sync_attestation_format_implemented',
 'production_dom_sync_attestation_atomic_persistence_implemented',
 'production_dom_anchor_requires_quorum_sync_attestation',
];
function recursiveCompletionFixture(releaseConfig) {
 const f=finalizedBurnAuthorityFixture(),receipt=Buffer.from('verified receipt');
 f.reserveConfiguration.reserveConfigHash=
   proofReserveDeploymentConfigHash(f.reserveConfiguration).reserveConfigHash;
 const groth=Buffer.alloc(1024,7),receiptIndex=JSON.parse(f.receiptIndex),proofIndex=JSON.parse(f.proofIndex);
 const digest=value=>createHash('sha256').update(value).digest('hex');
 receiptIndex.receipt_sha256=digest(receipt); receiptIndex.receipt_bytes=receipt.length;
 const receiptIndexBytes=Buffer.from(JSON.stringify(receiptIndex)+'\n');
 proofIndex.receipt_index_sha256=digest(receiptIndexBytes);
 proofIndex.groth16_receipt_sha256=digest(groth); proofIndex.groth16_receipt_bytes=groth.length;
 const proofIndexBytes=Buffer.from(JSON.stringify(proofIndex)+'\n'),outerReceipt=Buffer.from('outer receipt');
 const outerIndexBytes=Buffer.from(JSON.stringify({outer_receipt_verified:true,dev_mode:false,
   receipt_file:'checkpoint-outer-receipt.bin',receipt_sha256:digest(outerReceipt)}));
 const releaseBytes=Buffer.from(JSON.stringify(f.reserveConfiguration));
 const verifierBytes=Buffer.from(JSON.stringify(f.verifierConfiguration));
 const authority={checkpointOuterReceipt:outerReceipt,checkpointOuterReceiptIndex:outerIndexBytes,
   finalizedBurnReceipt:receipt,finalizedBurnReceiptIndex:receiptIndexBytes,
   finalizedBurnProofIndex:proofIndexBytes,finalizedBurnSourceIndex:f.sourceIndex,
   finalizedBurnSourceInput:f.sourceInput,finalizedBurnEvmSeal:f.evmSeal,
   finalizedBurnGroth16Receipt:groth,releaseConfig:releaseBytes,verifierConfig:verifierBytes};
 const report={schema:'usdom-finalized-burn-recursive-completion/v3',
   checkpointOuterReceiptSha256:digest(outerReceipt),checkpointOuterReceiptIndexSha256:digest(outerIndexBytes),
   checkpointOuterReceiptVerified:true,finalizedBurnReceiptSha256:digest(receipt),
   finalizedBurnReceiptIndexSha256:digest(receiptIndexBytes),finalizedBurnReceiptVerified:true,
   finalizedBurnProofIndexSha256:digest(proofIndexBytes),finalizedBurnSourceIndexSha256:digest(f.sourceIndex),
   finalizedBurnSourceInputSha256:digest(f.sourceInput),finalizedBurnEvmSealSha256:digest(f.evmSeal),
   finalizedBurnGroth16ReceiptSha256:digest(groth),releaseConfigSha256:digest(releaseBytes),
   verifierConfigSha256:digest(verifierBytes),evmReceiptVerified:true,
   adapterRuntimeCodeHash:releaseConfig.verifierCodeHash,
   adapterInitcodeHash:releaseConfig.verifierInitcodeHash,adapterConfigHash:releaseConfig.verifierConfigHash};
 authority.completionBytes=Buffer.from(JSON.stringify(report));
 return {report,authority};
}
function readyFixture(mode='closed-mainnet') {
 const base=deployment();
 const safePackage=buildRecoverableSafeControlDeploymentPackage({
  ownersByRole:initialSafeOwnersByRole(),proxyCreationCode:safe141Fixture.proxyCreationCode});
 base.governance=safePackage.controls[0].safe;
 base.guardian=safePackage.controls[1].safe;
 const governanceOwners=[110,102,103].map(value=>getAddress(address(value)));
 const guardianOwners=[111,102,103].map(value=>getAddress(address(value)));
 const checkpointGuardianOwners=[112,102,103].map(value=>getAddress(address(value)));
 const usdtCustodyOwners=[113,102,103].map(value=>getAddress(address(value)));
 base.governanceOwnersCommitment=safeOwnersCommitment(governanceOwners);
 base.guardianOwnersCommitment=safeOwnersCommitment(guardianOwners);
 const schedule=activationSchedule({networkMagic:'1146047793',chainId:bytes32('02'),
  firstV4Height:'100000',emptyStateRoot:bytes32('44')});
 base.activationScheduleCommitment=schedule.commitment;
 const verifierConfig=verifierManifest(base.activationScheduleCommitment);
 const finalizedVerifierConfig=finalizedBurnVerifierConfigHash(verifierConfig);
 base.verifierConfigHash=finalizedVerifierConfig.verifierConfigHash;
 const verifierConfigManifestSha256=finalizedVerifierConfig.manifestSha256.slice(2);
 const checkpointVerifierConfig=checkpointVerifierManifest(base.activationScheduleCommitment);
 const finalizedCheckpointVerifierConfig=checkpointVerifierConfigHash(checkpointVerifierConfig);
 const checkpointVerifierConfigManifestSha256=finalizedCheckpointVerifierConfig.manifestSha256.slice(2);
 const deployer=address(15);
 const verifierDeployer=deployer,verifierDeployerNonce='7';
 base.verifier=getCreateAddress({from:verifierDeployer,nonce:7});
 const checkpointVerifierDeployer=deployer,checkpointVerifierDeployerNonce='8';
 const checkpointVerifier=getCreateAddress({from:checkpointVerifierDeployer,nonce:8});
 const checkpointRegistryDeployer=deployer,checkpointRegistryDeployerNonce='9';
 const checkpointRegistry=getCreateAddress({from:checkpointRegistryDeployer,nonce:9});
 const deployerNonce='10';
 base.reserve=getCreateAddress({from:deployer,nonce:10});
 base.domDomain=deriveDomDomain({domNetworkMagic:'1146047793',
  domChainId:verifierConfig.domChainId,ethereumChainId:base.ethereumChainId,
  reserve:base.reserve,checkpointRegistry});
 const reserveDeployment={...base,checkpointRegistry,
  checkpointRegistryRuntimeCodeHash:'0x'+'93'.repeat(32)};
 Object.assign(base,{checkpointRegistryDeployer,checkpointRegistryDeployerNonce,checkpointRegistry,
  checkpointVerifier,checkpointVerifierCodeHash:'0x'+'21'.repeat(32),
  checkpointVerifierConfigHash:finalizedCheckpointVerifierConfig.verifierConfigHash,
  checkpointGuardian:safePackage.controls[2].safe,
  checkpointGuardianCodeHash:'0x'+'50'.repeat(32),
  checkpointGuardianImplementation:SAFE_MAINNET_IDENTITY.singleton,
  checkpointGuardianImplementationCodeHash:SAFE_MAINNET_IDENTITY.singletonCodeHash,
  checkpointDomNetworkMagic:'1146047793',
  checkpointDomChainId:verifierConfig.domChainId,checkpointFirstV4Height:verifierConfig.firstV4Height,
  checkpointActivationEmptyStateRoot:'0x'+'44'.repeat(32),
  checkpointIntervalBlocks:'360',checkpointConfirmationDepthBlocks:'30',
  checkpointChallengePeriodSeconds:'172800',
  checkpointInitialHeight:'99999',checkpointInitialBlock:'0x'+'43'.repeat(32),
  checkpointInitialStateRoot:'0x'+'44'.repeat(32),checkpointInitialContextHash:'0x'+'45'.repeat(32),
  checkpointInitialTotalDifficulty:'1000000'});
 const checkpointConfig=checkpointRegistryConfigHash({ethereumChainId:base.ethereumChainId,
  registry:base.checkpointRegistry,bridgeDomain:base.domDomain,domNetworkMagic:base.checkpointDomNetworkMagic,
  domChainId:base.checkpointDomChainId,firstV4Height:base.checkpointFirstV4Height,
  activationEmptyStateRoot:base.checkpointActivationEmptyStateRoot,
  activationScheduleCommitment:base.activationScheduleCommitment,
  checkpointInterval:base.checkpointIntervalBlocks,
  confirmationDepth:base.checkpointConfirmationDepthBlocks,
  challengePeriod:base.checkpointChallengePeriodSeconds,verifier:base.checkpointVerifier,
  verifierCodeHash:base.checkpointVerifierCodeHash,verifierConfigHash:base.checkpointVerifierConfigHash,
  guardian:base.checkpointGuardian,guardianCodeHash:base.checkpointGuardianCodeHash,
  guardianImplementation:base.checkpointGuardianImplementation,
  guardianImplementationCodeHash:base.checkpointGuardianImplementationCodeHash,
  guardianOwnersCommitment:safeOwnersCommitment(checkpointGuardianOwners),
  initialHeight:base.checkpointInitialHeight,initialBlock:base.checkpointInitialBlock,
  initialStateRoot:base.checkpointInitialStateRoot,
  initialContextHash:base.checkpointInitialContextHash,
  initialTotalDifficulty:base.checkpointInitialTotalDifficulty});
 Object.assign(base,{checkpointRegistryRuntimeCodeHash:'0x'+'93'.repeat(32),
  checkpointRegistryConfigHash:checkpointConfig.checkpointConfigHash});
 reserveDeployment.checkpointRegistryConfigHash=checkpointConfig.checkpointConfigHash;
 const computed=proofReserveDeploymentConfigHash(reserveDeployment);
 const releaseConfig={productionReady:true,deploymentMethod:'CREATE',deployer,deployerNonce,...base,
  tokenOwner:address(77),tokenOwnerCodeHash:EMPTY_CODE_HASH,
  governanceOwners,guardianOwners,checkpointGuardianOwners,
  reserveRuntimeCodeHash:'0x'+'90'.repeat(32),
  reserveInitcodeHash:'0x'+'92'.repeat(32),
  checkpointRegistryRuntimeCodeHash:'0x'+'93'.repeat(32),
  checkpointRegistryInitcodeHash:'0x'+'94'.repeat(32),
  verifierDeployer,verifierDeployerNonce,verifierInitcodeHash:'0x'+'95'.repeat(32),
  checkpointVerifierDeployer,checkpointVerifierDeployerNonce,
  checkpointVerifierInitcodeHash:'0x'+'96'.repeat(32),
  ethereumGenesisValidatorsRoot:'0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95',
  nativeEthereumTrustedCheckpoint:bytes32('55'),
  checkpointRegistryConfigHash:checkpointConfig.checkpointConfigHash,
  reserveConfigHash:computed.reserveConfigHash,
  // The technical release remains pre-funds in both modes. Real-funds
  // readiness is conferred only by the dedicated pilot EIP-1271 state.
  realFundsAuthorized:false,nativeRelaySafetyMarginSeconds:'3600',
  nativeMaxEthereumAnchorAgeSeconds:'1800',nativeMaxDomClockLeadSeconds:'120'};
 const requirements=Object.fromEntries(requiredKeys.map(key=>[key,true]));
 Object.assign(requirements,{deploy_authorized:true,mainnet_ready:true,real_funds_authorized:true,
  native_burn_state_witness_authorizes_consensus_or_payout:false,
  native_burn_block_prover_input_proves_finality:false,
  native_privacy_policy_hash:'83'.repeat(32),
  production_withdrawal_queue_lease_period_seconds:604800,
  finality_evaluation:{selected_production_mechanism:'ethereum-checkpoint-finality'},
  checkpoint_poc_authorization:{production_mechanism_approved:true}});
 const operatorIntent={schema:1,network:'Ethereum mainnet',chainId:'1',token:{},
  prototype_trust_model:'prototype',production_trust_model:'production',
  local_test_values_not_approved_for_production:{},authority:'operator',native_asset_requirements:{},
  current_phase:'release',release_assurance_policy:{
   external_audit_required_by_gate:false,absolute_zero_risk_required_by_gate:false,
   required_basis:'objective validation and explicit acceptance of documented residual risk',
   authority:'explicit operator release policy',
  },finality_direction:'checkpoint',
  finality_comparison:'docs/FINALITY-COMPARISON.txt',
  checkpoint_poc_authorization:{production_mechanism_approved:true},
  production_approved:true,deploy_authorized:true,real_funds_authorized:true,undefined:[],
  release_signing_key_fingerprint:signingFingerprint,
  residual_risk_acceptance:{accepted:true,releaseId:'release-1',sourceCommit:'a'.repeat(40),
   reserveConfigHash:computed.reserveConfigHash,
   checkpointRegistryConfigHash:checkpointConfig.checkpointConfigHash,
   reportSha256:documentSha('evidence/residual-risk-acceptance.txt'),
   acceptingAuthority:base.governance,acceptedAt:'1792492800',productionApproved:true,
   deployAuthorized:true,realFundsAuthorized:true,signature:'0x1234',rule:'exact release only'}};
 const controlPlaneEvidence=controlPlaneEvidenceFixture(releaseConfig);
 const safeRecoveryFinalBundle={schema:'usdom-safe-recovery-evidence-bundle/v2',
  ethereumChainId:'1',packageDocumentSha256:'1'.repeat(64),
  packageHash:controlPlaneEvidence.packageHash,baselineDocumentSha256:'2'.repeat(64),
  planDocumentSha256:'3'.repeat(64),replacementProofsDocumentSha256:'a'.repeat(64),
  transactionPackageDocumentSha256:'4'.repeat(64),
  rpcCatalogSha256:'5'.repeat(64),executions:controlPlaneEvidence.recoveryDrillReport.roles.map(
   (role,index)=>({role:role.safeRole,documentSha256:String(index+6).repeat(64),
    transactionHash:role.transactionHash})),reportDocumentSha256:'9'.repeat(64),
  recoveryHash:controlPlaneEvidence.recoveryHash};
 const evidence={schema:1,releaseId:'release-1',sourceCommit:'a'.repeat(40),sourceTag:'usdom-v1.0.0',
  releaseValidationReport:document('evidence/release-validation.json'),
  reproducibleBuildReport:document('evidence/build.txt'),
  verifierReproducibleBuildReport:document('evidence/verifier-build.txt'),
  checkpointRegistryReproducibleBuildReport:document('evidence/checkpoint-registry-build.txt'),
  checkpointVerifierReproducibleBuildReport:document('evidence/checkpoint-verifier-build.txt'),
  checkpointBootstrapRatificationReport:document('evidence/checkpoint-bootstrap.txt'),
  checkpointFinalizedEventReport:document('evidence/checkpoint-finalized-event.txt'),
  domConsensusAuditReports:[document('evidence/consensus.txt'),document('evidence/consensus-2.txt')],
  privacyCircuitAuditReports:[document('evidence/privacy.txt'),document('evidence/privacy-2.txt')],
  solidityAuditReports:[document('evidence/solidity.txt'),document('evidence/solidity-2.txt')],
  trustedSetup:{required:true,decisionReport:document('evidence/setup-decision.txt'),
   transcript:{path:'evidence/risc0-groth16-ceremony-verification.json',sha256:trustedSetupVerificationSha256}},
  checkpointTrustedSetup:{required:true,
   decisionReport:document('evidence/checkpoint-setup-decision.txt'),
   transcript:{path:'evidence/risc0-groth16-ceremony-verification.json',sha256:trustedSetupVerificationSha256}},
  checkpointProofCapacityReport:null,
  finalizedBurnCapacityReport:null,
  realFinalizedEndToEndReport:null,
  operationsReviewReport:document('evidence/operations.txt'),
  mainnetForkRehearsalReport:document('evidence/fork.txt'),
  securityValidationReport:document('evidence/security-validation.txt'),
  riscZeroHealthSourceCatalog:document('evidence/risc0-health-sources.json'),
  residualRiskAcceptanceReport:document('evidence/residual-risk-acceptance.txt'),
  mainnetColdStartAttestationReport:document('evidence/cold-start.txt'),
  nativePrivacyTrustedSetupAttestationReport:document('evidence/native-privacy-setup.json'),
  nativeRuntimeManifest:document('evidence/native-runtime-manifest.json'),
  nativeRuntimeSpendVerifyingKeyArtifact:document('evidence/native-spend-verifying-key.bin'),
  nativeScheduledRuntimeActivationAttestationReport:document('evidence/native-runtime-activation.json'),
  nativeWalletCustodyAttestationReport:document('evidence/native-wallet-custody.json'),
  nativeWalletRecoveryAttestationReport:document('evidence/native-wallet-recovery.json'),
  controlPlane:{
   governance:{address:controlPlaneEvidence.roleReports.governance.address,
    runtimeCodeHash:controlPlaneEvidence.roleReports.governance.runtimeCodeHash,
    configurationHash:controlPlaneEvidence.roleReports.governance.configurationHash,
    configurationReport:document('evidence/control-plane/governance-configuration.json')},
   guardian:{address:controlPlaneEvidence.roleReports.guardian.address,
    runtimeCodeHash:controlPlaneEvidence.roleReports.guardian.runtimeCodeHash,
    configurationHash:controlPlaneEvidence.roleReports.guardian.configurationHash,
    configurationReport:document('evidence/control-plane/guardian-configuration.json')},
   checkpointGuardian:{address:controlPlaneEvidence.roleReports.checkpointGuardian.address,
    runtimeCodeHash:controlPlaneEvidence.roleReports.checkpointGuardian.runtimeCodeHash,
    configurationHash:controlPlaneEvidence.roleReports.checkpointGuardian.configurationHash,
    configurationReport:document('evidence/control-plane/checkpoint-guardian-configuration.json')},
   usdtCustody:{address:controlPlaneEvidence.roleReports.usdtCustody.address,
    runtimeCodeHash:controlPlaneEvidence.roleReports.usdtCustody.runtimeCodeHash,
    configurationHash:controlPlaneEvidence.roleReports.usdtCustody.configurationHash,
    configurationReport:document('evidence/control-plane/usdt-custody-configuration.json')},
  },
  controlPlaneEvidenceBundle:document(
    'evidence/control-plane/safe-control-release-evidence-bundle.json'),
  controlPlaneSeparationReport:document('evidence/control-plane/control-plane-separation.json'),
  controlPlaneRecoveryDrillReport:document(
    'evidence/control-plane/control-plane-recovery-drill.json'),
  safeRecoveryFinalEvidenceBundle:document(
    'evidence/control-plane/safe-recovery-finalized-bundle.json'),
  mainnetPredeploymentAttestationReport:document('evidence/predeployment.txt'),
  verifierArtifact:document(
    'out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json'),
  checkpointRegistryArtifact:document('out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json'),
  checkpointVerifierArtifact:document(
    'out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json'),
  verifierConfigManifest:{path:'evidence/verifier-config.json',sha256:verifierConfigManifestSha256},
  checkpointVerifierConfigManifest:{path:'evidence/checkpoint-verifier-config.json',
   sha256:checkpointVerifierConfigManifestSha256},
  verifyingKeyArtifact:document('evidence/verifying-key.bin'),
  provingProgramArtifact:document('evidence/proving-program.bin'),
  provingProgramSourceManifest:document('evidence/proving-program-sources.sha256'),
  checkpointVerifyingKeyArtifact:document('evidence/verifying-key.bin'),
  checkpointProvingProgramArtifact:document('evidence/checkpoint-proving-program.bin'),
  checkpointProvingProgramSourceManifest:document('evidence/checkpoint-proving-program-sources.sha256')};
 evidence.reserveArtifact=document('out/USDOMProofReserve.sol/USDOMProofReserve.json');
 const evidenceFiles=Object.fromEntries([
  'build','verifier-build','checkpoint-registry-build','checkpoint-verifier-build','checkpoint-bootstrap',
  'checkpoint-finalized-event','consensus','consensus-2','privacy','privacy-2','solidity','solidity-2','setup-decision',
  'checkpoint-setup-decision',
  'operations','fork','security-validation','residual-risk-acceptance','cold-start',
  'predeployment',
 ].map(name=>{
  const path=`evidence/${name}.txt`;
  return [path,documentSha(path)];
 }));
 const fixtureBindDocument=(document,value,bytes=Buffer.from(JSON.stringify(value)))=>{
  document.sha256=createHash('sha256').update(bytes).digest('hex');
  evidenceFiles[document.path]=document.sha256;
  return bytes;
 };
 const controlPlaneEvidenceAuthority={
  bundleBytes:fixtureBindDocument(evidence.controlPlaneEvidenceBundle,controlPlaneEvidence),
  roleReportBytes:Object.fromEntries(['governance','guardian','checkpointGuardian','usdtCustody'].map(role=>[role,
   fixtureBindDocument(evidence.controlPlane[role].configurationReport,controlPlaneEvidence.roleReports[role])])),
  separationReportBytes:fixtureBindDocument(evidence.controlPlaneSeparationReport,
   controlPlaneEvidence.separationReport),
  recoveryDrillReportBytes:fixtureBindDocument(evidence.controlPlaneRecoveryDrillReport,
   controlPlaneEvidence.recoveryDrillReport),
  finalBundleBytes:fixtureBindDocument(evidence.safeRecoveryFinalEvidenceBundle,safeRecoveryFinalBundle),
 };
 const predeploymentAttestation=preflightAttestation(releaseConfig,'predeployment');
 const predeploymentAttestationAuthority={reportBytes:fixtureBindDocument(
  evidence.mainnetPredeploymentAttestationReport,predeploymentAttestation)};
 const coldStartAttestation=preflightAttestation(releaseConfig,'postdeployment');
 const coldStartAttestationAuthority={reportBytes:fixtureBindDocument(
  evidence.mainnetColdStartAttestationReport,coldStartAttestation)};
 evidenceFiles['evidence/verifier-config.json']=verifierConfigManifestSha256;
 evidenceFiles['evidence/risc0-groth16-ceremony-verification.json']=trustedSetupVerificationSha256;
 evidenceFiles['evidence/checkpoint-verifier-config.json']=checkpointVerifierConfigManifestSha256;
 evidence.nativeRuntimeManifest.sha256=documentSha(nativePrivacyAuthority.runtimeManifestBytes);
 evidence.nativeRuntimeSpendVerifyingKeyArtifact.sha256=nativePrivacyAuthority.verifyingKeySha256;
 evidenceFiles[evidence.nativeRuntimeManifest.path]=evidence.nativeRuntimeManifest.sha256;
 evidenceFiles[evidence.nativeRuntimeSpendVerifyingKeyArtifact.path]=nativePrivacyAuthority.verifyingKeySha256;
 evidenceFiles['evidence/risc0-health-sources.json']=documentSha('evidence/risc0-health-sources.json');
 const toolchainLockSha256=documentSha('mainnet-toolchain-lock');
 const cargoLockSha256=documentSha('Cargo.lock');
 const vectorKinds=['checkpoint390','randomxCache','nativePrivacy'];
 const releaseValidationReport={schema:'usdom-release-validation-report/v1',status:'passed',
  releaseId:evidence.releaseId,sourceCommit:evidence.sourceCommit,sourceTag:evidence.sourceTag,
  toolchainLockSha256,cargoLockSha256,runs:vectorKinds.map((kind,index)=>({kind,
   runId:documentSha(`vector-command-${index}`),commandManifestSha256:documentSha(`vector-command-${index}`),
   runSha256:documentSha(`vector-run-${index}`),terminalSha256:documentSha(`vector-terminal-${index}`),
   processLogSha256:documentSha(`vector-log-${index}`),eventsSha256:documentSha(`vector-events-${index}`),
   supervisorSha256:documentSha('vector-supervisor'),startedAt:`2026-10-27T${10+index}:00:00Z`,
   finishedAt:`2026-10-27T${11+index}:00:00Z`}))};
 const releaseValidationPath=evidence.releaseValidationReport.path;
 const releaseValidationSha=createHash('sha256').update(JSON.stringify(releaseValidationReport)).digest('hex');
 evidence.releaseValidationReport.sha256=releaseValidationSha;
 evidenceFiles[releaseValidationPath]=releaseValidationSha;
 const releaseValidationReportBytes=Buffer.from(JSON.stringify(releaseValidationReport));
 const releaseValidationAuthority={reportBytes:releaseValidationReportBytes,
  reconstructedReportBytes:Buffer.from(releaseValidationReportBytes),
  reconstructedReport:structuredClone(releaseValidationReport)};
 const finalizedBurnE2eBurn={burnId:bytes32('a1'),requestId:bytes32('a2'),recipient:address(23),
  amount:'1000000',domDomain:releaseConfig.domDomain,height:'100360',blockHash:bytes32('a3'),
  stateRoot:bytes32('a4'),finalityBeaconSlot:'16000010',validUntil:'1800000000'};
 const finalizedBurnE2eStatement=finalizedBurnStatementHash({chainId:'1',reserve:releaseConfig.reserve,
  activationScheduleCommitment:releaseConfig.activationScheduleCommitment,burn:finalizedBurnE2eBurn});
 const finalizedBurnE2eReport={
  schema:'usdom-finalized-burn-e2e-report-v4',releaseId:evidence.releaseId,
  sourceCommit:evidence.sourceCommit,ethereumChainId:'1',reserve:releaseConfig.reserve,
  verifier:releaseConfig.verifier,adapterRuntimeCodeHash:releaseConfig.verifierCodeHash,
  verifierConfigHash:releaseConfig.verifierConfigHash,
  riscZeroVerifier:PINNED_RISC0_MAINNET_V3.verifier_address,
  riscZeroVerifierCodeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
  guestProgramSha256:verifierConfig.provingProgramSha256,
  guestImageId:verifierConfig.finalizedBurnGuestImageId,
  burn:finalizedBurnE2eBurn,inputSha256:'11'.repeat(32),inputBytes:'4096',
  statementHash:finalizedBurnE2eStatement,
  succinctReceiptSha256:'13'.repeat(32),groth16ReceiptSha256:'14'.repeat(32),
  evmSealSha256:'15'.repeat(32),succinctReceiptBytes:'8192',groth16ReceiptBytes:'2048',
  evmSealBytes:'260',sourcePackageSha256:'16'.repeat(32),hostFingerprintSha256:'17'.repeat(32),
  risc0ZkvmVersion:'3.0.6',receiptKind:'groth16',
  prover:'local',rayonWorkers:2,segmentLimitPo2:18,provingWallMilliseconds:'1000',
  peakResidentKiB:'2048',compressionWallMilliseconds:'1000',compressionPeakResidentKiB:'2048',
  evmVerificationGas:'1000000',receiptVerified:true,evmCallAccepted:true,devMode:false,mines:false,
  broadcastAuthorized:false,releaseSpecific:true,startedAt:'1792492600',completedAt:'1792492700',
  finalizedObservationBlockNumber:'1000000',finalizedObservationBlockHash:bytes32('18'),
  observationSourceIds:['drpc','publicnode'],observationEndpointHashes:['19'.repeat(32),'1a'.repeat(32)],
  isolatedEvmTransactionHash:bytes32('1b'),isolatedEvmBlockHash:bytes32('1c'),
  isolatedEvmBlockNumber:'2',isolatedEvmReceiptSha256:'1d'.repeat(32),
 };
 finalizedBurnE2eReport.isolatedEvmReceiptSha256=finalizedBurnReleaseEvmReceiptCommitment({
  transactionHash:finalizedBurnE2eReport.isolatedEvmTransactionHash,
  blockHash:finalizedBurnE2eReport.isolatedEvmBlockHash,
  blockNumber:finalizedBurnE2eReport.isolatedEvmBlockNumber,
  adapter:finalizedBurnE2eReport.verifier,
  adapterRuntimeCodeHash:finalizedBurnE2eReport.adapterRuntimeCodeHash,
  verifierConfigHash:finalizedBurnE2eReport.verifierConfigHash,
  statementHash:finalizedBurnE2eReport.statementHash,
  evmSealSha256:finalizedBurnE2eReport.evmSealSha256,
  evmVerificationGas:finalizedBurnE2eReport.evmVerificationGas,
 }).sha256;
 const e2ePath='evidence/finalized-burn-e2e.json';
 const e2eSha=createHash('sha256').update(JSON.stringify(finalizedBurnE2eReport)).digest('hex');
 evidence.realFinalizedEndToEndReport={path:e2ePath,sha256:e2eSha};
 evidenceFiles[e2ePath]=e2eSha;
 const finalizedBurnE2eAuthority={reportBytes:Buffer.from(JSON.stringify(finalizedBurnE2eReport))};
 const capacityLayer=(name,programSha256,imageId,index,receiptCount)=>({name,programSha256,imageId,
  inputSetSha256:(0x10+index).toString(16).repeat(32),inputBytes:'4096',
  journalSetSha256:(0x20+index).toString(16).repeat(32),journalBytes:String(receiptCount*32),
  journalCount:String(receiptCount),
  receiptSetSha256:(0x30+index).toString(16).repeat(32),receiptBytes:'8192',
  receiptCount:String(receiptCount),
  receiptKind:'succinct',receiptVerified:true,segmentLimitPo2:18,
  provingWallMilliseconds:'1000',peakResidentKiB:'1048576'});
 const capacityCheckpoint={previousHeight:'100000',previousBlock:bytes32('d5'),
  previousStateRoot:bytes32('d6'),previousContextHash:bytes32('d7'),
  previousTotalDifficulty:'1000000',height:'100360',blockHash:bytes32('d8'),
  stateRoot:bytes32('d9'),contextHash:bytes32('da'),totalDifficulty:'2000000',
  totalIssued:'1000000',totalBurned:'250000',issuanceClosed:false,
  confirmationHeight:'100390',confirmationBlock:bytes32('db'),
  confirmationTotalDifficulty:'2100000',confirmationTimestamp:'1792492500'};
 const capacityStatementHash=checkpointStatementHash(
  checkpointRegistryConfigurationFromRelease(releaseConfig),capacityCheckpoint,
 );
 const checkpointProofCapacityReport={schema:CHECKPOINT_PROOF_CAPACITY_REPORT_SCHEMA,
  artifactSetCommitmentSchema:CHECKPOINT_CAPACITY_ARTIFACT_SET_SCHEMA,
  runId:'20261027T120000Z-123',artifactManifestPath:'artifact-manifest.json',artifactManifestSha256:'09'.repeat(32),
  releaseId:evidence.releaseId,sourceCommit:evidence.sourceCommit,ethereumChainId:'1',
  checkpointRegistry:releaseConfig.checkpointRegistry,adapter:releaseConfig.checkpointVerifier,
  adapterRuntimeCodeHash:releaseConfig.checkpointVerifierCodeHash,
  adapterVerifierConfigHash:releaseConfig.checkpointVerifierConfigHash,
  riscZeroVerifier:PINNED_RISC0_MAINNET_V3.verifier_address,
  riscZeroVerifierCodeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
  riscZeroFinalizedBlockNumber:'22000000',riscZeroFinalizedBlockHash:bytes32('e3'),
  riscZeroObservationSourceIds:['drpc','publicnode'],riscZeroObservationEndpointHashes:[
   'c5b9f7564a09b1b2bbdff2c7145d474bbc2ccd025460d9c5b097a39474b7980c',
   '7b71d04b616d2ce47598465ad04d63da212a14b1317f965044bf325b749a6746'],
  riscZeroRuntimeArtifactSha256:'e4'.repeat(32),
  risc0ZkvmVersion:'3.0.6',prover:'local',rayonWorkers:1,devMode:false,mines:false,
  broadcastAuthorized:false,releaseSpecific:true,checkpointStartHeight:'100000',
  checkpointEndHeight:'100360',confirmationHeight:'100390',checkpointSpan:'360',
  confirmationDepth:'30',checkpoint:capacityCheckpoint,statementHash:capacityStatementHash,
  sourcePackageSha256:'d1'.repeat(32),
  randomxProverTranscriptSha256:'e1'.repeat(32),randomxResourceLogSha256:'e2'.repeat(32),
  hostFingerprintSha256:'d2'.repeat(32),logicalCpus:4,memoryTotalKiB:'8388608',layers:[
   capacityLayer('randomx',CHECKPOINT_RANDOMX_PROGRAM_SHA256,CHECKPOINT_RANDOMX_IMAGE_ID,0,390),
   capacityLayer('randomx-aggregate',CHECKPOINT_RANDOMX_AGGREGATE_PROGRAM_SHA256,
    CHECKPOINT_RANDOMX_AGGREGATE_IMAGE_ID,1,2),
   capacityLayer('economic-chunk',CHECKPOINT_ECONOMIC_CHUNK_PROGRAM_SHA256,
    CHECKPOINT_ECONOMIC_CHUNK_IMAGE_ID,2,390),
   capacityLayer('economic-block',CHECKPOINT_ECONOMIC_BLOCK_PROGRAM_SHA256,
    CHECKPOINT_ECONOMIC_BLOCK_IMAGE_ID,3,390),
   capacityLayer('segment',CHECKPOINT_SEGMENT_PROGRAM_SHA256,CHECKPOINT_SEGMENT_IMAGE_ID,4,2),
   capacityLayer('outer',checkpointVerifierConfig.provingProgramSha256.slice(2),
    checkpointVerifierConfig.checkpointGuestImageId.slice(2),5,1),
  ],outerGroth16ReceiptSha256:'d3'.repeat(32),outerGroth16ReceiptBytes:'2048',
  outerJournalDigestSha256:sha256(capacityStatementHash).slice(2),
  evmSealSha256:'d4'.repeat(32),evmSealBytes:'260',adapterCallAccepted:true,
  adapterVerificationGas:'400000',compressionWallMilliseconds:'1000',
  isolatedEvmTransactionHash:bytes32('e5'),isolatedEvmBlockHash:bytes32('e6'),
  isolatedEvmBlockNumber:'2',isolatedEvmReceiptSha256:'e7'.repeat(32),
  compressionPeakResidentKiB:'1048576',startedAt:'1792492600',completedAt:'1792492610'};
 checkpointProofCapacityReport.isolatedEvmReceiptSha256=checkpointIsolatedEvmReceiptCommitment({
  transactionHash:checkpointProofCapacityReport.isolatedEvmTransactionHash,
  blockHash:checkpointProofCapacityReport.isolatedEvmBlockHash,
  blockNumber:checkpointProofCapacityReport.isolatedEvmBlockNumber,
  adapter:checkpointProofCapacityReport.adapter,
  adapterRuntimeCodeHash:checkpointProofCapacityReport.adapterRuntimeCodeHash,
  adapterVerifierConfigHash:checkpointProofCapacityReport.adapterVerifierConfigHash,
  statementHash:checkpointProofCapacityReport.statementHash,
  evmSealSha256:checkpointProofCapacityReport.evmSealSha256,
  adapterVerificationGas:checkpointProofCapacityReport.adapterVerificationGas,
 }).sha256;
 const checkpointCapacityManifestBytes=Buffer.from(JSON.stringify({schema:'usdom-checkpoint-capacity-artifact-manifest/v1',runId:checkpointProofCapacityReport.runId,files:[{path:'evidence/test.bin',sha256:'08'.repeat(32),bytes:1}]},null,2)+'\n');
 checkpointProofCapacityReport.artifactManifestSha256=documentSha(checkpointCapacityManifestBytes);
 const checkpointProofCapacityAuthority={reportBytes:Buffer.from(JSON.stringify(checkpointProofCapacityReport)),manifestBytes:checkpointCapacityManifestBytes,reconstructedReport:structuredClone(checkpointProofCapacityReport)};
 const capacityPath='evidence/checkpoint-proof-capacity.json';
 const capacitySha=createHash('sha256').update(
  JSON.stringify(checkpointProofCapacityReport),
 ).digest('hex');
 evidence.checkpointProofCapacityReport={path:capacityPath,sha256:capacitySha};
 evidenceFiles[capacityPath]=capacitySha;
 const finalizedCapacityManifestBytes=Buffer.from(JSON.stringify({
  schema:'usdom-finalized-burn-capacity-artifact-manifest/v1',runId:'20261027T120000Z-124',
  files:[{path:'work/evidence/test.bin',sha256:'0a'.repeat(32),bytes:1}],
 },null,2)+'\n');
 const finalizedBurnCapacityReport={
  schema:FINALIZED_BURN_CAPACITY_REPORT_SCHEMA,runId:'20261027T120000Z-124',
  artifactManifestPath:'artifact-manifest.json',artifactManifestSha256:documentSha(finalizedCapacityManifestBytes),
  startedAt:'1792643744',completedAt:'1792647344',provingWallMilliseconds:'3540000',
  peakResidentKiB:'2097152',rayonWorkers:1,segmentLimitPo2:18,prover:'local',devMode:false,
  receiptKind:'groth16',receiptVerified:true,risc0ZkvmVersion:'3.0.6',mines:false,
  broadcastAuthorized:false,releaseSpecific:false,ethereumChainId:'1',
  inputSha256:FINALIZED_BURN_CAPACITY_INPUT_SHA256,inputBytes:FINALIZED_BURN_CAPACITY_INPUT_BYTES,
  statementHash:FINALIZED_BURN_CAPACITY_STATEMENT_HASH,
  guestProgramSha256:FINALIZED_BURN_CAPACITY_PROGRAM_SHA256,guestImageId:FINALIZED_BURN_CAPACITY_IMAGE_ID,
  succinctReceiptSha256:'11'.repeat(32),succinctReceiptBytes:'4096',
  groth16ReceiptSha256:'22'.repeat(32),groth16ReceiptBytes:'2048',
  evmSealSha256:'33'.repeat(32),evmSealBytes:'260',
  riscZeroVerifier:PINNED_RISC0_MAINNET_V3.verifier_address,
  riscZeroVerifierCodeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
  finalizedObservationBlockNumber:'26245816',finalizedObservationBlockHash:'0x'+'44'.repeat(32),
  observationSourceIds:['drpc','publicnode'],observationEndpointHashes:['55'.repeat(32),'66'.repeat(32)],
  adapterRuntimeCodeHash:'0x'+'77'.repeat(32),
  adapterVerifierConfigHash:finalizedBurnCapacityAdapterConfigHash(PINNED_RISC0_MAINNET_V3),
  adapterCallAccepted:true,adapterVerificationGas:'400000',
  isolatedEvmAdapter:'0x0000000000000000000000000000000000000002',
  isolatedEvmTransactionHash:'0x'+'88'.repeat(32),isolatedEvmBlockHash:'0x'+'99'.repeat(32),
  isolatedEvmBlockNumber:'2',isolatedEvmReceiptSha256:'aa'.repeat(32),
 };
 finalizedBurnCapacityReport.isolatedEvmReceiptSha256=finalizedBurnIsolatedEvmReceiptCommitment({
  transactionHash:finalizedBurnCapacityReport.isolatedEvmTransactionHash,
  blockHash:finalizedBurnCapacityReport.isolatedEvmBlockHash,
  blockNumber:finalizedBurnCapacityReport.isolatedEvmBlockNumber,
  adapter:finalizedBurnCapacityReport.isolatedEvmAdapter,
  adapterRuntimeCodeHash:finalizedBurnCapacityReport.adapterRuntimeCodeHash,
  adapterVerifierConfigHash:finalizedBurnCapacityReport.adapterVerifierConfigHash,
  statementHash:finalizedBurnCapacityReport.statementHash,evmSealSha256:finalizedBurnCapacityReport.evmSealSha256,
  adapterVerificationGas:finalizedBurnCapacityReport.adapterVerificationGas,
 }).sha256;
 const finalizedCapacityReportBytes=Buffer.from(JSON.stringify(finalizedBurnCapacityReport));
 const finalizedCapacityPath='evidence/finalized-burn-capacity/finalized-burn-capacity-report.json';
 evidence.finalizedBurnCapacityReport={path:finalizedCapacityPath,sha256:documentSha(finalizedCapacityReportBytes)};
 evidenceFiles[finalizedCapacityPath]=evidence.finalizedBurnCapacityReport.sha256;
 for(const path of ['evidence/native-privacy-setup.json','evidence/native-runtime-activation.json',
  'evidence/native-wallet-custody.json','evidence/native-wallet-recovery.json']) {
  evidenceFiles[path]=documentSha(path);
 }
 for(const path of [
  'evidence/control-plane/governance-configuration.json',
  'evidence/control-plane/guardian-configuration.json',
  'evidence/control-plane/checkpoint-guardian-configuration.json',
  'evidence/control-plane/usdt-custody-configuration.json',
  'evidence/control-plane/control-plane-separation.json',
  'evidence/control-plane/control-plane-recovery-drill.json',
  'evidence/control-plane/safe-control-release-evidence-bundle.json',
  'evidence/control-plane/safe-recovery-finalized-bundle.json',
  'evidence/native-runtime-manifest.json','evidence/native-spend-verifying-key.bin',
  'evidence/verifying-key.bin','evidence/proving-program.bin','evidence/proving-program-sources.sha256',
  'evidence/checkpoint-verifying-key.bin','evidence/checkpoint-proving-program.bin',
  'evidence/checkpoint-proving-program-sources.sha256',
  'out/USDOMProofReserve.sol/USDOMProofReserve.json',
  'out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json',
  'out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json',
  'out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json',
 ]) evidenceFiles[path]=documentSha(path);
 for(const [document,bytes] of [
  [evidence.controlPlaneEvidenceBundle,controlPlaneEvidenceAuthority.bundleBytes],
  [evidence.controlPlane.governance.configurationReport,controlPlaneEvidenceAuthority.roleReportBytes.governance],
  [evidence.controlPlane.guardian.configurationReport,controlPlaneEvidenceAuthority.roleReportBytes.guardian],
  [evidence.controlPlane.checkpointGuardian.configurationReport,controlPlaneEvidenceAuthority.roleReportBytes.checkpointGuardian],
  [evidence.controlPlane.usdtCustody.configurationReport,controlPlaneEvidenceAuthority.roleReportBytes.usdtCustody],
  [evidence.controlPlaneSeparationReport,controlPlaneEvidenceAuthority.separationReportBytes],
  [evidence.controlPlaneRecoveryDrillReport,controlPlaneEvidenceAuthority.recoveryDrillReportBytes],
  [evidence.safeRecoveryFinalEvidenceBundle,controlPlaneEvidenceAuthority.finalBundleBytes],
 ]) evidenceFiles[document.path]=createHash('sha256').update(bytes).digest('hex');
 evidenceFiles[evidence.nativeRuntimeManifest.path]=evidence.nativeRuntimeManifest.sha256;
 evidenceFiles[evidence.nativeRuntimeSpendVerifyingKeyArtifact.path]=evidence.nativeRuntimeSpendVerifyingKeyArtifact.sha256;
 const contractSource=`
 bytes32 private constant PRODUCTION_VERIFIER_CODE_HASH = ${base.verifierCodeHash};
 bytes32 private constant PRODUCTION_VERIFIER_CONFIG_HASH = ${base.verifierConfigHash};
 bytes32 private constant PRODUCTION_RESERVE_PREACTIVATION_CONFIG_HASH = ${computed.reservePreActivationConfigHash};`;
 const checkpointContractSource=`
 bytes32 public constant PRODUCTION_VERIFIER_CODE_HASH = ${base.checkpointVerifierCodeHash};
 bytes32 public constant PRODUCTION_VERIFIER_CONFIG_HASH = ${base.checkpointVerifierConfigHash};
 bytes32 public constant PRODUCTION_CHECKPOINT_CONFIG_HASH = ${checkpointConfig.checkpointConfigHash};`;
 const contractSourceAuthority={reserveBytes:Buffer.from(contractSource),
  checkpointRegistryBytes:Buffer.from(checkpointContractSource)};
 const repositoryState={head:'b'.repeat(40),sourceCommit:'a'.repeat(40),
  headParents:['a'.repeat(40)],dirty:false,
  sourceAuthor:'Soren Planck <sorenplanck@tutamail.com>',
  sourceCommitter:'Soren Planck <sorenplanck@tutamail.com>',
  releaseAuthor:'Soren Planck <sorenplanck@tutamail.com>',
  releaseCommitter:'Soren Planck <sorenplanck@tutamail.com>',tagCommit:'b'.repeat(40),
  releaseEvidenceChanges:[
   {status:'M',path:'labs/usdom-reserve/config/mainnet-release-evidence.unconfigured.json'},
   {status:'M',path:'labs/usdom-reserve/config/operator-intent.json'},
  ],
  sourceCommitSignatureVerified:true,sourceCommitSignerFingerprint:signingFingerprint,
  releaseCommitSignatureVerified:true,releaseCommitSignerFingerprint:signingFingerprint,
  tagSignatureVerified:true,tagSignerFingerprint:signingFingerprint,
  importProvenanceVerified:true,sourceManifestVerified:true,
  ethereumFinalityPanicBoundaryVerified:true,nativeStatePanicBoundaryVerified:true,
  nativePrivacyPanicBoundaryVerified:true,proofProgramPanicBoundaryVerified:true,
  risc0ProgramBinariesVerified:true,
  nativeWalletPanicBoundaryVerified:true};
 const repositoryStateAuthority={bytes:Buffer.from(JSON.stringify(repositoryState))};
 const nativeRuntimeValidation={status:'valid',network:'Mainnet',network_magic:'444f4d31',
  manifest_sha256:evidence.nativeRuntimeManifest.sha256,chain_id:base.checkpointDomChainId.slice(2),
  first_v4_height:base.checkpointFirstV4Height,candidate_v2_first_height:'100001',
  checkpoint_interval_blocks:base.checkpointIntervalBlocks,
  checkpoint_confirmation_depth_blocks:base.checkpointConfirmationDepthBlocks,
  randomx_receipt_image_id:CHECKPOINT_RANDOMX_IMAGE_ID,
  empty_state_root:base.checkpointActivationEmptyStateRoot.slice(2),
  activation_schedule_commitment:base.activationScheduleCommitment.slice(2),
  dom_domain:base.domDomain.slice(2),
  ethereum_genesis_validators_root:releaseConfig.ethereumGenesisValidatorsRoot.slice(2),
  ethereum_trusted_checkpoint:releaseConfig.nativeEthereumTrustedCheckpoint.slice(2),
  ethereum_fork_genesis_epoch:'0',ethereum_fork_genesis_version:'00000000',
  ethereum_fork_altair_epoch:'74240',ethereum_fork_altair_version:'01000000',
  ethereum_fork_bellatrix_epoch:'144896',ethereum_fork_bellatrix_version:'02000000',
  ethereum_fork_capella_epoch:'194048',ethereum_fork_capella_version:'03000000',
  ethereum_fork_deneb_epoch:'269568',ethereum_fork_deneb_version:'04000000',
  ethereum_fork_electra_epoch:'364032',ethereum_fork_electra_version:'05000000',
  ethereum_fork_fulu_epoch:'411392',ethereum_fork_fulu_version:'06000000',
  ethereum_fork_gloas_epoch:'18446744073709551615',ethereum_fork_gloas_version:'07000000',
  ethereum_chain_id_uint256:'0'.repeat(63)+'1',reserve:base.reserve.slice(2).toLowerCase(),
  checkpoint_registry:base.checkpointRegistry.slice(2).toLowerCase(),
  checkpoint_runtime_code_hash:releaseConfig.checkpointRegistryRuntimeCodeHash.slice(2),
  checkpoint_config_storage_slot:'0'.repeat(64),
  checkpoint_config_hash:releaseConfig.checkpointRegistryConfigHash.slice(2),
  checkpoint_bridge_domain:base.domDomain.slice(2),
  ethereum_checkpoint_policy_hash:'81'.repeat(32),ethereum_deposit_policy_hash:'82'.repeat(32),
  deposit_reserve:base.reserve.slice(2).toLowerCase(),
  deposit_runtime_code_hash:releaseConfig.reserveRuntimeCodeHash.slice(2),
  deposit_bridge_domain:base.domDomain.slice(2),deposit_max_amount:base.maxOutstandingBaseUnits,
  privacy_policy_hash:'83'.repeat(32),privacy_verifier_config_hash:nativePrivacyAuthority.privacyVerifierConfigHash,
  withdrawal_delay_secs:base.withdrawalDelaySeconds,min_execution_window_secs:'3600',
  max_certificate_lifetime_secs:'604800',relay_safety_margin_secs:'3600',
  max_ethereum_anchor_age_secs:'1800',max_dom_clock_lead_secs:'120',
  spend_verifying_key_sha256:evidence.nativeRuntimeSpendVerifyingKeyArtifact.sha256};
 const nativePrivacyTrustedSetupAttestation=nativeReleaseAttestation(
  'native-privacy-trusted-setup',releaseConfig,`0x${nativeRuntimeValidation.privacy_verifier_config_hash}`);
 const nativeScheduledRuntimeActivationAttestation=nativeReleaseAttestation(
  'native-scheduled-runtime-activation',releaseConfig,`0x${evidence.nativeRuntimeManifest.sha256}`);
 const scheduledRuntimeAttestationBytes=Buffer.from(
  JSON.stringify(nativeScheduledRuntimeActivationAttestation));
 evidence.nativeScheduledRuntimeActivationAttestationReport.sha256=
  createHash('sha256').update(scheduledRuntimeAttestationBytes).digest('hex');
 evidenceFiles[evidence.nativeScheduledRuntimeActivationAttestationReport.path]=
  evidence.nativeScheduledRuntimeActivationAttestationReport.sha256;
 const nativeWalletCustodyAttestation=nativeReleaseAttestation(
  'native-wallet-custody',releaseConfig,bytes32('a2'));
 const nativeWalletRecoveryAttestation=nativeReleaseAttestation(
  'native-wallet-recovery',releaseConfig,bytes32('a2'));
 const nativeReleaseAttestationAuthority={
  nativePrivacyTrustedSetupBytes:fixtureBindDocument(
   evidence.nativePrivacyTrustedSetupAttestationReport,nativePrivacyTrustedSetupAttestation),
  nativeScheduledRuntimeActivationBytes:scheduledRuntimeAttestationBytes,
  nativeWalletCustodyBytes:fixtureBindDocument(
   evidence.nativeWalletCustodyAttestationReport,nativeWalletCustodyAttestation),
  nativeWalletRecoveryBytes:fixtureBindDocument(
   evidence.nativeWalletRecoveryAttestationReport,nativeWalletRecoveryAttestation),
 };
 const requiredNativeAttestations={nativePrivacyTrustedSetup:nativePrivacyTrustedSetupAttestation,
  nativeScheduledRuntimeActivation:nativeScheduledRuntimeActivationAttestation,
  ...(mode==='real-funds'?{nativeWalletCustody:nativeWalletCustodyAttestation,
   nativeWalletRecovery:nativeWalletRecoveryAttestation}:{}),
 };
 const riscZeroHealthSourceCatalog=createRiscZeroHealthSourceCatalog({sources:[
  {sourceId:'rpc-a',operatorId:'operator-a',providerId:'provider-a',
    infrastructureId:'infra-a',endpointHash:bytes32('c1')},
  {sourceId:'rpc-b',operatorId:'operator-b',providerId:'provider-b',
    infrastructureId:'infra-b',endpointHash:bytes32('c2')},
 ]});
 const riscZeroHealthSourceCatalogAuthority={catalogBytes:fixtureBindDocument(
  evidence.riscZeroHealthSourceCatalog,riscZeroHealthSourceCatalog)};
 const requirementsSha256=documentSha('production-requirements');
 const sourceManifestSha256=documentSha('source-manifest');
 const securityValidationReport=buildSecurityValidationReport({releaseEvidence:evidence,
  requirementsSha256,sourceManifestSha256,results:SECURITY_VALIDATION_CHECKS.map(({id,command},index)=>({
   id,command,exitCode:0,stdoutSha256:documentSha(`security-stdout-${index}`),
   stderrSha256:documentSha(`security-stderr-${index}`),toolSha256:documentSha(
    id==='production-solidity-lint'||id==='production-solidity-build'||id==='solidity-regression'
      ||id==='deep-solidity-regression'?'tool-forge':`tool-${id}`),
  }))});
 const securityPath=evidence.securityValidationReport.path;
 const securitySha=createHash('sha256').update(
  serializeSecurityValidationReport(securityValidationReport)).digest('hex');
 // The report validator receives parsed semantics separately; the evidence map
 // still models the exact immutable file hash used by the release gate.
 evidence.securityValidationReport.sha256=securitySha;
 evidenceFiles[securityPath]=securitySha;
 const reserveBuildObservation=buildId=>({buildId,
  compilerExecutableSha256:PRODUCTION_SOLC_SHA256,
  compilerVersion:'0.8.37+commit.f401782d',
  artifactSha256:evidence.reserveArtifact.sha256,sourceSetSha256:documentSha('reserve source set'),
  runtimeCodeHash:releaseConfig.reserveRuntimeCodeHash,
  initcodeHash:releaseConfig.reserveInitcodeHash});
 const reserveReproducibleBuildReport=buildReserveReproducibleBuildReport({
  releaseEvidence:evidence,releaseConfig,observations:[reserveBuildObservation('isolated-build-a'),
   reserveBuildObservation('isolated-build-b')]});
 const reserveBuildPath=evidence.reproducibleBuildReport.path;
 const reserveBuildSha=createHash('sha256').update(
  serializeReserveReproducibleBuildReport(reserveReproducibleBuildReport)).digest('hex');
 evidence.reproducibleBuildReport.sha256=reserveBuildSha;
 evidenceFiles[reserveBuildPath]=reserveBuildSha;
 const verifierBuildObservation=buildId=>({buildId,
  compilerExecutableSha256:PRODUCTION_SOLC_SHA256,
  compilerVersion:'0.8.37+commit.f401782d',
  artifactSha256:evidence.verifierArtifact.sha256,sourceSetSha256:documentSha('verifier source set'),
  runtimeCodeHash:releaseConfig.verifierCodeHash,initcodeHash:releaseConfig.verifierInitcodeHash});
 const verifierReproducibleBuildReport=buildVerifierReproducibleBuildReport({releaseEvidence:evidence,
  releaseConfig,verifierConfig,observations:[verifierBuildObservation('isolated-build-a'),
   verifierBuildObservation('isolated-build-b')]});
 const verifierBuildPath=evidence.verifierReproducibleBuildReport.path;
 const verifierBuildSha=createHash('sha256').update(
  serializeVerifierReproducibleBuildReport(verifierReproducibleBuildReport)).digest('hex');
 evidence.verifierReproducibleBuildReport.sha256=verifierBuildSha;
 evidenceFiles[verifierBuildPath]=verifierBuildSha;
 const checkpointVerifierBuildObservation=buildId=>({buildId,
  compilerExecutableSha256:PRODUCTION_SOLC_SHA256,
  compilerVersion:'0.8.37+commit.f401782d',
  artifactSha256:evidence.checkpointVerifierArtifact.sha256,
  sourceSetSha256:documentSha('checkpoint verifier source set'),
  runtimeCodeHash:releaseConfig.checkpointVerifierCodeHash,
  initcodeHash:releaseConfig.checkpointVerifierInitcodeHash});
 const checkpointVerifierReproducibleBuildReport=
  buildCheckpointVerifierReproducibleBuildReport({releaseEvidence:evidence,releaseConfig,
   verifierConfig:checkpointVerifierConfig,
   observations:[checkpointVerifierBuildObservation('isolated-build-a'),
    checkpointVerifierBuildObservation('isolated-build-b')]});
 const checkpointVerifierBuildPath=evidence.checkpointVerifierReproducibleBuildReport.path;
 const checkpointVerifierBuildSha=createHash('sha256').update(
  serializeCheckpointVerifierReproducibleBuildReport(
   checkpointVerifierReproducibleBuildReport)).digest('hex');
 evidence.checkpointVerifierReproducibleBuildReport.sha256=checkpointVerifierBuildSha;
 evidenceFiles[checkpointVerifierBuildPath]=checkpointVerifierBuildSha;
 const checkpointRegistryBuildObservation=buildId=>({buildId,
  compilerExecutableSha256:PRODUCTION_SOLC_SHA256,
  compilerVersion:'0.8.37+commit.f401782d',
  artifactSha256:evidence.checkpointRegistryArtifact.sha256,
  sourceSetSha256:documentSha('checkpoint registry source set'),
  runtimeCodeHash:releaseConfig.checkpointRegistryRuntimeCodeHash,
  initcodeHash:releaseConfig.checkpointRegistryInitcodeHash});
 const checkpointRegistryReproducibleBuildReport=
  buildCheckpointRegistryReproducibleBuildReport({releaseEvidence:evidence,releaseConfig,
   observations:[checkpointRegistryBuildObservation('isolated-build-a'),
    checkpointRegistryBuildObservation('isolated-build-b')]});
 const checkpointRegistryBuildPath=evidence.checkpointRegistryReproducibleBuildReport.path;
 const checkpointRegistryBuildSha=createHash('sha256').update(
  serializeCheckpointRegistryReproducibleBuildReport(
   checkpointRegistryReproducibleBuildReport)).digest('hex');
 evidence.checkpointRegistryReproducibleBuildReport.sha256=checkpointRegistryBuildSha;
 evidenceFiles[checkpointRegistryBuildPath]=checkpointRegistryBuildSha;
 const operatorRunbookSha256=documentSha('operator-runbook');
 const operationsReviewReport=buildOperationsReviewReport({releaseEvidence:evidence,releaseConfig,
  runbookSha256:operatorRunbookSha256});
 const operationsPath=evidence.operationsReviewReport.path;
 const operationsSha=createHash('sha256').update(
  serializeOperationsReviewReport(operationsReviewReport)).digest('hex');
 evidence.operationsReviewReport.sha256=operationsSha;
 evidenceFiles[operationsPath]=operationsSha;
 const forkRehearsal=forkRehearsalFixture(evidence,releaseConfig);
 const mainnetForkRehearsalReport=forkRehearsal.report;
 const forkPath=evidence.mainnetForkRehearsalReport.path;
 const forkSha=createHash('sha256').update(
  serializeMainnetForkRehearsalReport(mainnetForkRehearsalReport)).digest('hex');
 evidence.mainnetForkRehearsalReport.sha256=forkSha;
 evidenceFiles[forkPath]=forkSha;
 const checkpointRatification=checkpointRatificationFixture(evidence,releaseConfig);
 const checkpointBootstrapRatificationReport=checkpointRatification.report;
 const ratificationPath=evidence.checkpointBootstrapRatificationReport.path;
 const ratificationSha=createHash('sha256').update(
  serializeCheckpointBootstrapRatificationReport(checkpointBootstrapRatificationReport)).digest('hex');
 evidence.checkpointBootstrapRatificationReport.sha256=ratificationSha;
 evidenceFiles[ratificationPath]=ratificationSha;
 const checkpointFinalizedEventReport=checkpointFinalizedEventFixture(evidence,releaseConfig);
 const finalizedEventPath=evidence.checkpointFinalizedEventReport.path;
 const finalizedEventSha=createHash('sha256').update(
  serializeCheckpointFinalizedEventReport(checkpointFinalizedEventReport)).digest('hex');
 evidence.checkpointFinalizedEventReport.sha256=finalizedEventSha;
 evidenceFiles[finalizedEventPath]=finalizedEventSha;
 evidence.checkpointTrustedSetup.decisionReport={...evidence.trustedSetup.decisionReport};
 const trustedSetupDecisionReport=buildTrustedSetupDecisionReport({releaseEvidence:evidence,
  releaseConfig,verifierConfig,checkpointVerifierConfig,trustedSetupVerificationReport,
  trustedSetupAuthority,trustedSetupAuthoritySha256});
 const trustedSetupDecisionPath=evidence.trustedSetup.decisionReport.path;
 const trustedSetupDecisionSha=createHash('sha256').update(
  serializeTrustedSetupDecisionReport(trustedSetupDecisionReport)).digest('hex');
 evidence.trustedSetup.decisionReport.sha256=trustedSetupDecisionSha;
 evidence.checkpointTrustedSetup.decisionReport={...evidence.trustedSetup.decisionReport};
 evidenceFiles[trustedSetupDecisionPath]=trustedSetupDecisionSha;
 const trustedSetupDecisionReportAuthority={reportBytes:Buffer.from(
  serializeTrustedSetupDecisionReport(trustedSetupDecisionReport))};
 const residualRiskDraftSha256=documentSha('residual-risk-draft');
 const residualRiskReport=buildResidualRiskReport({releaseEvidence:evidence,releaseConfig,
  requirements,draftSha256:residualRiskDraftSha256});
 const residualRiskPath=evidence.residualRiskAcceptanceReport.path;
 const residualRiskSha=createHash('sha256').update(
  serializeResidualRiskReport(residualRiskReport)).digest('hex');
 evidence.residualRiskAcceptanceReport.sha256=residualRiskSha;
 evidenceFiles[residualRiskPath]=residualRiskSha;
 operatorIntent.residual_risk_acceptance.reportSha256=residualRiskSha;
 operatorIntent.residual_risk_acceptance.sourceTag=evidence.sourceTag;
 operatorIntent.residual_risk_acceptance.releaseEvidenceCommitment=releaseEvidenceCommitment(evidence);
 const pilotReleaseBytes=Buffer.from(JSON.stringify(releaseConfig));
 const pilotReleaseSha256=createHash('sha256').update(pilotReleaseBytes).digest('hex');
 const pilotFundsSnapshot=buildPilotFundsSnapshot({releaseConfig,
  releaseConfigSha256:pilotReleaseSha256,
  deploymentPackageSha256:documentSha('pilot-deployment-package'),
  safeControlBundleSha256:documentSha('pilot-safe-control-bundle'),
  nativePrivacyInstallationSha256:documentSha('pilot-native-privacy-installation'),
  checkpointCapacityEvidenceSha256:documentSha('pilot-checkpoint-capacity'),
  finalizedBurnCapacityEvidenceSha256:documentSha('pilot-finalized-burn-capacity'),
  operationalGasEvidenceSha256:documentSha('pilot-operational-gas'),
  residualRiskDraftSha256,releaseValidationReportSha256:documentSha('pilot-release-validation'),
  planSha256:documentSha('pilot-plan'),phaseCatalogSha256:documentSha('pilot-phase-catalog'),
  pilotDepositBaseUnits:'1000000',funder:address(60),salt:bytes32('61'),receivingCommitment:bytes32('03')});
 const pilotSnapshotCommitment=pilotFundsSnapshotCommitment(pilotFundsSnapshot);
 const pilotFundsAuthorization={schema:'usdom-pilot-funds-authorization/v1',
  snapshotCommitment:pilotSnapshotCommitment,releaseId:pilotFundsReleaseId(pilotSnapshotCommitment),
  validAfter:'1000',validUntil:'2000',governance:releaseConfig.governance,
  pilotDepositBaseUnits:pilotFundsSnapshot.pilotDepositBaseUnits,funder:pilotFundsSnapshot.funder,
  salt:pilotFundsSnapshot.salt,receivingCommitment:pilotFundsSnapshot.receivingCommitment,
  nonce:bytes32('64'),signature:'0x1234'};
 const pilotFundsDigest=pilotFundsAuthorizationDigest(pilotFundsAuthorization,releaseConfig);
 const pilotFundsAuthorizationState={schema:'usdom-pilot-funds-authorization-state/v1',
  authorization:pilotFundsAuthorization,digest:pilotFundsDigest,consumed:false,
  finalizedObservation:{chainId:'1',governance:releaseConfig.governance,
   governanceCodeHash:releaseConfig.governanceCodeHash,finalizedBlockHash:bytes32('65'),
   finalizedBlockNumber:'99',snapshotBlockHashAfter:bytes32('65'),finalizedBlockTimestamp:'1500',
   rpcConsensus:rpcConsensusEvidence([{sourceId:'pilot-a',originKeccak256:bytes32('66')},
    {sourceId:'pilot-b',originKeccak256:bytes32('67')}]),
   approvals:{pilotFundsAuthorization:{digest:pilotFundsDigest,valid:true}}}};
 const recursiveCompletion=recursiveCompletionFixture(releaseConfig);
 const registryArtifactBytes=Buffer.from('registry-artifact'),registryReleaseBytes=Buffer.from('registry-release');
 const randomxImageId=checkpointVerifierConfig.randomxReceiptImageId.slice(2);
 const randomxImageIdBytes=Buffer.from(`${randomxImageId}\n`),randomxReceiptBytes=Buffer.from('randomx-receipt');
 const randomxIndexBytes=Buffer.from(JSON.stringify({schema:'usdom-randomx-receipt-set-v1',
  randomx_receipt_image_id:randomxImageId,randomx_relations_executed:true,receipts_verified:true,
  dev_mode:false,generates_proofs:true,mines:false,receipt_count:1,receipts:[{index:0,
   receipt_file:'randomx-receipt-0000.bin',receipt_sha256:documentSha(randomxReceiptBytes),receipt_bytes:randomxReceiptBytes.length}]}));
 const restartWitnessBytes=Buffer.from('restart-witness');
 const restartManifestBytes=Buffer.from(JSON.stringify({restart_checkpoint:{witness_file:'restart-witness.bin',witness_sha256:documentSha(restartWitnessBytes)}}));
 const checkpointRegistryArtifactPinsReport={schema:'usdom-checkpoint-registry-artifact-pins/v1',
  artifactPath:'out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json',artifactSha256:documentSha(registryArtifactBytes),
  releaseConfigPath:'config/proof-reserve.unconfigured.json',releaseConfigSha256:documentSha(registryReleaseBytes),
  runtimeCodeHash:releaseConfig.checkpointRegistryRuntimeCodeHash,runtimeSize:1,
  initcodeHash:releaseConfig.checkpointRegistryInitcodeHash,initcodeSize:1,
  checkpointRegistryConfigHash:releaseConfig.checkpointRegistryConfigHash,
  compilerVersion:'solc-test',sourceCount:1};
 const checkpointRandomxImageRatificationReport={schema:'usdom-checkpoint-randomx-image-ratification/v1',
  imageId:randomxImageId,
  imageIdPath:'../../crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.iid',
  imageIdFileSha256:documentSha(randomxImageIdBytes),receiptIndexPath:'evidence/randomx-receipt-set/randomx-receipt-set-index.json',
  receiptIndexSha256:documentSha(randomxIndexBytes),receiptCount:1,randomxRelationsExecuted:true,receiptsVerified:true};
 const checkpointRestartWitnessReport={schema:'usdom-checkpoint-restart-witness-live-exercise/v1',
  manifestSha256:documentSha(restartManifestBytes),witnessSha256:documentSha(restartWitnessBytes),firstProcessPid:100,secondProcessPid:101,
  firstStartupAccepted:true,secondStartupAccepted:true,sameDataDirectory:true,checkpointWitnessRequired:true};
 const releaseConfigBytes=pilotReleaseBytes;
 const wallet={schema:'usdom-native-receiving-wallet-public-v1',domDomain:releaseConfig.domDomain,
  privacyPolicyHash:`0x${requirements.native_privacy_policy_hash}`,chainScalar:bytes32('02'),
  receivingCommitment:pilotFundsSnapshot.receivingCommitment,
  recipientAddress:Buffer.concat([Buffer.from('USDADR01'),Buffer.from(bytes32('02').slice(2),'hex'),
   Buffer.from(pilotFundsSnapshot.receivingCommitment.slice(2),'hex'),Buffer.from('69'.repeat(32),'hex')]).toString('hex')};
 const walletBytes=Buffer.from(JSON.stringify(wallet));
 const walletSha256=createHash('sha256').update(walletBytes).digest('hex');
 const pilotSnapshotBytes=Buffer.from(JSON.stringify(pilotFundsSnapshot));
 const pilotAuthorizationBytes=Buffer.from(JSON.stringify(pilotFundsAuthorizationState));
 const pilotFundsAuthority={snapshotBytes:pilotSnapshotBytes,
  authorizationStateBytes:pilotAuthorizationBytes};
 const depositPackage=buildClosedMainnetDepositPackage({release:releaseConfig,wallet,
  funder:pilotFundsSnapshot.funder,salt:pilotFundsSnapshot.salt,
  releaseConfigSha256:pilotReleaseSha256,walletIdentitySha256:walletSha256,
  expectedPrivacyPolicyHash:wallet.privacyPolicyHash,pilotFundsSnapshot,pilotFundsAuthorizationState});
 const depositPackageBytes=Buffer.from(JSON.stringify(depositPackage));
 const depositPackageSha256=createHash('sha256').update(depositPackageBytes).digest('hex');
 const depositBaseline={schema:'usdom-closed-mainnet-deposit-financial-baseline-v2',chainId:'1',
  packageSha256:depositPackageSha256,funder:depositPackage.funder,token:depositPackage.token,
  reserve:depositPackage.reserve,funderBalanceBaseUnits:'5000000',reserveBalanceBaseUnits:'7000000',
  totalDepositedBaseUnits:'6000000',outstandingBaseUnits:'4000000',allowanceBaseUnits:'0',
  observedAt:'finalized',rpcCount:2,snapshotBlockNumber:'19000000',snapshotBlockHash:bytes32('73')};
 const depositBaselineBytes=Buffer.from(JSON.stringify(depositBaseline));
 const depositBaselineSha256=createHash('sha256').update(depositBaselineBytes).digest('hex');
 const depositFinality={schema:'usdom-closed-mainnet-deposit-finality-v2',transactionHash:bytes32('72'),
  blockNumber:'19000032',blockHash:bytes32('74'),transactionIndex:'2',finalizedRpcCount:2,
  gasUsed:'100000',effectiveGasPrice:'2000000000',actualCost:'200000000000000',maximumCost:'300000000000000'};
 const depositFinalityBytes=Buffer.from(JSON.stringify(depositFinality));
 const depositFinalitySha256=createHash('sha256').update(depositFinalityBytes).digest('hex');
 const depositExecution={schema:'usdom-closed-mainnet-deposit-execution-v3',
  packageSha256:depositPackageSha256,chainId:'1',steps:3,amountBaseUnits:'1000000',
  financialBaselineSha256:depositBaselineSha256,depositFinalitySha256,
  snapshotBlockNumber:'19000064',snapshotBlockHash:bytes32('75'),funderBalanceBefore:'5000000',
  funderBalanceAfter:'4000000',reserveBalanceBefore:'7000000',reserveBalanceAfter:'8000000',
  totalDepositedBefore:'6000000',totalDepositedAfter:'7000000',outstandingBefore:'4000000',
  outstandingAfter:'5000000',allowanceBefore:'0',allowanceAfter:'0',outputLast:true,
  transactionHashes:[bytes32('70'),bytes32('71'),bytes32('72')]};
 const finalizedDepositAuthority={packageBytes:depositPackageBytes,
  executionBytes:Buffer.from(JSON.stringify(depositExecution)),baselineBytes:depositBaselineBytes,
  depositFinalityBytes,
  releaseBytes:releaseConfigBytes,walletBytes,pilotFundsSnapshotBytes:pilotSnapshotBytes,
  pilotFundsAuthorizationStateBytes:pilotAuthorizationBytes};
 const configurationAuthority={releaseConfigBytes,
  nativeRuntimeManifestBytes:nativePrivacyAuthority.runtimeManifestBytes,
  scheduledRuntimeAttestationBytes};
 const releaseAssuranceAuthority={
  securityValidationReportBytes:Buffer.from(serializeSecurityValidationReport(securityValidationReport)),
  operationsReviewReportBytes:Buffer.from(serializeOperationsReviewReport(operationsReviewReport)),
  reserveReproducibleBuildReportBytes:Buffer.from(serializeReserveReproducibleBuildReport(reserveReproducibleBuildReport)),
  verifierReproducibleBuildReportBytes:Buffer.from(serializeVerifierReproducibleBuildReport(verifierReproducibleBuildReport)),
  mainnetForkRehearsalReportBytes:Buffer.from(serializeMainnetForkRehearsalReport(mainnetForkRehearsalReport)),
  checkpointVerifierReproducibleBuildReportBytes:Buffer.from(serializeCheckpointVerifierReproducibleBuildReport(checkpointVerifierReproducibleBuildReport)),
  checkpointRegistryReproducibleBuildReportBytes:Buffer.from(serializeCheckpointRegistryReproducibleBuildReport(checkpointRegistryReproducibleBuildReport)),
  residualRiskReportBytes:Buffer.from(serializeResidualRiskReport(residualRiskReport)),
 };
 const checkpointBootstrapRatificationAuthority={
  reportBytes:fixtureBindDocument(evidence.checkpointBootstrapRatificationReport,
    checkpointBootstrapRatificationReport,
    serializeCheckpointBootstrapRatificationReport(checkpointBootstrapRatificationReport)),
  consensusBytes:Buffer.from(JSON.stringify(checkpointRatification.checkpointConsensus)),
  nativeFactsBytes:Buffer.from(JSON.stringify(checkpointRatification.nativeFacts)),
 };
 const checkpointFinalizedEventAuthority={reportBytes:fixtureBindDocument(
  evidence.checkpointFinalizedEventReport,checkpointFinalizedEventReport,
  serializeCheckpointFinalizedEventReport(checkpointFinalizedEventReport))};
 const nativeAttestationApprovalObservation=nativeApprovalObservation(requiredNativeAttestations,releaseConfig);
 const releaseAuthorizationApprovalObservation=releaseAuthorizationObservation(
  operatorIntent.residual_risk_acceptance,releaseConfig);
 const approvalAuthority=value=>{
  const bytes=Buffer.from(JSON.stringify(value));
  return {bytes,sha256:createHash('sha256').update(bytes).digest('hex')};
 };
 const approvalObservationAuthority={
  nativeAttestations:approvalAuthority(nativeAttestationApprovalObservation),
  releaseAuthorization:approvalAuthority(releaseAuthorizationApprovalObservation),
 };
 const requirementsAuthority={bytes:Buffer.from(JSON.stringify(requirements))};
 const readinessDocumentAuthority={operatorIntentBytes:Buffer.from(JSON.stringify(operatorIntent)),
  releaseEvidenceBytes:Buffer.from(JSON.stringify(evidence))};
 const compiledBinding=(runtimeCodeHash,initcodeHash)=>({bindingBytes:Buffer.from(JSON.stringify(
  {runtimeCodeHash,initcodeHash}))});
 const compiledArtifactAuthority={
  reserve:compiledBinding(releaseConfig.reserveRuntimeCodeHash,releaseConfig.reserveInitcodeHash),
  checkpointRegistry:compiledBinding(releaseConfig.checkpointRegistryRuntimeCodeHash,
   releaseConfig.checkpointRegistryInitcodeHash),
  finalizedBurnVerifier:compiledBinding(releaseConfig.verifierCodeHash,
   releaseConfig.verifierInitcodeHash),
  checkpointVerifier:compiledBinding(releaseConfig.checkpointVerifierCodeHash,
   releaseConfig.checkpointVerifierInitcodeHash),
 };
 return {mode,requirements,requirementsAuthority,operatorIntent,releaseConfig,evidence,evidenceFiles,
  readinessDocumentAuthority,repositoryState,
  repositoryStateAuthority,contractSource,contractSourceAuthority,
  trustedReleaseSigningKeyFingerprint:signingFingerprint,
  checkpointContractSource,verifierConfig,checkpointVerifierConfig,
  riscZeroReference:{...PINNED_RISC0_MAINNET_V3},
  compiledReserveRuntimeCodeHash:releaseConfig.reserveRuntimeCodeHash,
  compiledReserveInitcodeHash:releaseConfig.reserveInitcodeHash,
  compiledCheckpointRegistryRuntimeCodeHash:releaseConfig.checkpointRegistryRuntimeCodeHash,
  compiledCheckpointRegistryInitcodeHash:releaseConfig.checkpointRegistryInitcodeHash,
  compiledVerifierRuntimeCodeHash:releaseConfig.verifierCodeHash,
  compiledVerifierInitcodeHash:releaseConfig.verifierInitcodeHash,
  compiledCheckpointVerifierRuntimeCodeHash:releaseConfig.checkpointVerifierCodeHash,
  compiledCheckpointVerifierInitcodeHash:releaseConfig.checkpointVerifierInitcodeHash,
  compiledArtifactAuthority,
  predeploymentAttestation,predeploymentAttestationAuthority,
  coldStartAttestation,coldStartAttestationAuthority,
  nativePrivacyTrustedSetupAttestation,nativeScheduledRuntimeActivationAttestation,
  nativeWalletCustodyAttestation,nativeWalletRecoveryAttestation,nativeReleaseAttestationAuthority,
  nativeAttestationApprovalObservation,releaseAuthorizationApprovalObservation,
  approvalObservationAuthority,
  nativeRuntimeValidation,configurationAuthority,
  riscZeroHealthSourceCatalog,riscZeroHealthSourceCatalogAuthority,
  finalizedBurnE2eReport,finalizedBurnE2eAuthority,
  checkpointProofCapacityReport,checkpointProofCapacityAuthority,
  finalizedBurnCapacityReport,finalizedBurnCapacityAuthority:{reportBytes:finalizedCapacityReportBytes,
   manifestBytes:finalizedCapacityManifestBytes,validated:true},
  productionOperationalGasAuthority:operationalGasAuthority(releaseConfig,releaseConfigBytes),
  finalizedDepositAuthority,
  releaseValidationReport,releaseValidationAuthority,releaseAssuranceAuthority,
  toolchainLockSha256,cargoLockSha256,
  securityValidationReport,requirementsSha256,sourceManifestSha256,
  operationsReviewReport,operatorRunbookSha256,
  reserveReproducibleBuildReport,verifierReproducibleBuildReport,
  mainnetForkRehearsalReport,mainnetForkRehearsalEvidenceFiles:forkRehearsal.evidenceFiles,
  checkpointBootstrapRatificationReport,checkpointBootstrapRatificationAuthority,
  ethereumCheckpointConsensus:checkpointRatification.checkpointConsensus,
  nativePreactivationFacts:checkpointRatification.nativeFacts,
  checkpointFinalizedEventReport,checkpointFinalizedEventAuthority,
  pilotFundsSnapshot,pilotFundsAuthorizationState,pilotFundsAuthority,
  checkpointVerifierReproducibleBuildReport,
  checkpointRegistryReproducibleBuildReport,
  checkpointRegistryArtifactPinsReport,
  checkpointRegistryArtifactPinsAuthority:{reportBytes:Buffer.from(JSON.stringify(checkpointRegistryArtifactPinsReport)),artifactBytes:registryArtifactBytes,releaseConfigBytes:registryReleaseBytes,
   binding:{runtimeCodeHash:releaseConfig.checkpointRegistryRuntimeCodeHash,runtimeSize:1,
    initcodeHash:releaseConfig.checkpointRegistryInitcodeHash,initcodeSize:1,
    checkpointRegistryConfigHash:releaseConfig.checkpointRegistryConfigHash,compilerVersion:'solc-test',sourceCount:1}},
  checkpointRandomxImageRatificationReport,
  checkpointRandomxImageRatificationAuthority:{reportBytes:Buffer.from(JSON.stringify(checkpointRandomxImageRatificationReport)),imageIdBytes:randomxImageIdBytes,receiptIndexBytes:randomxIndexBytes,receiptBytes:[randomxReceiptBytes]},
  checkpointRestartWitnessReport,
  checkpointRestartWitnessAuthority:{reportBytes:Buffer.from(JSON.stringify(checkpointRestartWitnessReport)),manifestBytes:restartManifestBytes,witnessBytes:restartWitnessBytes},
  finalizedBurnRecursiveCompletionReport:recursiveCompletion.report,
  finalizedBurnRecursiveCompletionAuthority:recursiveCompletion.authority,
  residualRiskReport,residualRiskDraftSha256,
  trustedSetupDecisionReport,trustedSetupVerificationReport,trustedSetupAuthority,
  trustedSetupAuthoritySha256,trustedSetupDecisionReportAuthority,
  controlPlaneEvidenceArtifacts:{bundle:controlPlaneEvidence,
   roleReports:structuredClone(controlPlaneEvidence.roleReports),
   separationReport:structuredClone(controlPlaneEvidence.separationReport),
   recoveryDrillReport:structuredClone(controlPlaneEvidence.recoveryDrillReport),
   finalBundle:safeRecoveryFinalBundle},controlPlaneEvidenceAuthority,
  nativePrivacyCeremonyAuthority:nativePrivacyAuthority};
}

function rebindRepositoryState(fixture) {
 fixture.repositoryStateAuthority={bytes:Buffer.from(JSON.stringify(fixture.repositoryState))};
}
function rebindRequirements(fixture) {
 fixture.requirementsAuthority={bytes:Buffer.from(JSON.stringify(fixture.requirements))};
}
function rebindReadinessDocuments(fixture) {
 fixture.readinessDocumentAuthority={
  operatorIntentBytes:Buffer.from(JSON.stringify(fixture.operatorIntent)),
  releaseEvidenceBytes:Buffer.from(JSON.stringify(fixture.evidence)),
 };
}

test('configured hash-addressed evidence can satisfy both fail-closed release modes',()=>{
 for(const mode of ['closed-mainnet','real-funds']) {
  const report=assessMainnetReadiness(readyFixture(mode));
  assert.equal(report.ready,true,JSON.stringify(report.blockers));
  assert.equal(report.blockerCount,0);
 }
});
test('release validation requires descriptor-bound raw reconstruction',()=>{
 for(const mutate of [
  fixture=>{ fixture.releaseValidationAuthority=null; },
  fixture=>{ fixture.releaseValidationAuthority.reconstructedReportBytes=Buffer.from('{}'); },
  fixture=>{
   const substituted=structuredClone(fixture.releaseValidationReport);
   substituted.runs[0].processLogSha256=documentSha('substituted-process-log');
   const bytes=Buffer.from(JSON.stringify(substituted));
   fixture.releaseValidationReport=substituted;
   fixture.releaseValidationAuthority.reportBytes=bytes;
   fixture.evidence.releaseValidationReport.sha256=createHash('sha256').update(bytes).digest('hex');
   fixture.evidenceFiles[fixture.evidence.releaseValidationReport.path]=
    fixture.evidence.releaseValidationReport.sha256;
  },
 ]) {
  const fixture=readyFixture();
  mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert.ok(report.blockers.some(({code})=>code==='release_validation_report_invalid'));
 }
});
test('finalized-deposit claims require package, execution receipt and upstream byte authority',()=>{
 for(const mutate of [
  fixture=>{ fixture.finalizedDepositAuthority=null; },
  fixture=>{ fixture.finalizedDepositAuthority.packageBytes=Buffer.from('{'); },
  fixture=>{ fixture.finalizedDepositAuthority.depositFinalityBytes=Buffer.from('{'); },
  fixture=>{
   const receipt=JSON.parse(fixture.finalizedDepositAuthority.executionBytes.toString());
   receipt.packageSha256='ab'.repeat(32);
   fixture.finalizedDepositAuthority.executionBytes=Buffer.from(JSON.stringify(receipt));
  },
 ]) {
  const fixture=readyFixture('real-funds');
  mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert.ok(report.blockers.some(({code})=>code==='finalized_deposit_authority_invalid'));
 }
});
test('terminal readiness objects cannot substitute coordinated B semantics under authority bytes A',()=>{
 const cases=[
  [fixture=>{
    fixture.checkpointBootstrapRatificationReport=structuredClone(fixture.checkpointBootstrapRatificationReport);
    fixture.checkpointBootstrapRatificationReport.snapshotBlockNumber='1000001';
    for(const approval of fixture.checkpointBootstrapRatificationReport.approvals) {
      approval.snapshotBlockNumber='1000001';
    }
   },'checkpoint_bootstrap_ratification_report_invalid'],
  [fixture=>{
    fixture.checkpointFinalizedEventReport=structuredClone(fixture.checkpointFinalizedEventReport);
    fixture.checkpointFinalizedEventReport.blockTimestamp='1792492999';
    for(const observation of fixture.checkpointFinalizedEventReport.observations) {
      observation.blockTimestamp='1792492999';
    }
   },'checkpoint_finalized_event_report_invalid'],
  [fixture=>{
    fixture.controlPlaneEvidenceArtifacts=structuredClone(fixture.controlPlaneEvidenceArtifacts);
    fixture.controlPlaneEvidenceArtifacts.bundle.roleReports.governance.configurationHash=bytes32('98');
    fixture.controlPlaneEvidenceArtifacts.roleReports.governance.configurationHash=bytes32('98');
   },'control_plane_evidence_content_invalid'],
  [fixture=>{
    fixture.predeploymentAttestation=structuredClone(fixture.predeploymentAttestation);
    fixture.predeploymentAttestation.collectionCompletedAtMs++;
   },'predeployment_attestation_authority_invalid'],
  [fixture=>{
    fixture.coldStartAttestation=structuredClone(fixture.coldStartAttestation);
    fixture.coldStartAttestation.collectionStartedAtMs++;
    fixture.coldStartAttestationAuthority={reportBytes:
      Buffer.from(JSON.stringify(fixture.coldStartAttestation))};
   },'cold_start_attestation_authority_invalid'],
 ];
 for(const [mutate,code] of cases) {
  const fixture=readyFixture('real-funds'); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert.ok(report.blockers.some(blocker=>blocker.code===code),code);
 }
});
test('production configuration claims require release, native manifest and scheduled-attestation bytes',()=>{
 for(const mutate of [
  fixture=>{ fixture.configurationAuthority=null; },
  fixture=>{
   fixture.releaseConfig=structuredClone(fixture.releaseConfig);
   fixture.releaseConfig.maxOutstandingBaseUnits='2000000';
  },
  fixture=>{
   fixture.nativeScheduledRuntimeActivationAttestation=
    structuredClone(fixture.nativeScheduledRuntimeActivationAttestation);
   fixture.nativeScheduledRuntimeActivationAttestation.completedAt='1792492801';
  },
  fixture=>{ fixture.nativeRuntimeValidation={...fixture.nativeRuntimeValidation,
    manifest_sha256:'ab'.repeat(32)}; },
 ]) {
  const fixture=readyFixture('real-funds'); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert.ok(report.blockers.some(({code})=>code==='production_configuration_authority_invalid'));
 }
});
test('release assurance reports require their exact descriptor-bound bytes',()=>{
 const missingCases=[
  ['securityValidationReportBytes','security_validation_report_invalid'],
  ['operationsReviewReportBytes','operations_review_report_invalid'],
  ['reserveReproducibleBuildReportBytes','reserve_reproducible_build_report_invalid'],
  ['verifierReproducibleBuildReportBytes','verifier_reproducible_build_report_invalid'],
  ['mainnetForkRehearsalReportBytes','mainnet_fork_rehearsal_report_invalid'],
  ['checkpointVerifierReproducibleBuildReportBytes','checkpoint_verifier_reproducible_build_report_invalid'],
  ['checkpointRegistryReproducibleBuildReportBytes','checkpoint_registry_reproducible_build_report_invalid'],
  ['residualRiskReportBytes','residual_risk_report_invalid'],
 ];
 for(const [field,code] of missingCases) {
  const fixture=readyFixture(); fixture.releaseAssuranceAuthority[field]=null;
  const report=assessMainnetReadiness(fixture);
  assert(report.blockers.some(blocker=>blocker.code===code),field);
 }
 const substituted=readyFixture();
 substituted.securityValidationReport=structuredClone(substituted.securityValidationReport);
 substituted.securityValidationReport.checks[0].stdoutSha256='ab'.repeat(32);
 substituted.releaseAssuranceAuthority.securityValidationReportBytes=Buffer.from(
  serializeSecurityValidationReport(substituted.securityValidationReport));
 const report=assessMainnetReadiness(substituted);
 assert(report.blockers.some(({code})=>code==='security_validation_report_invalid'));
});
test('finalized-burn capacity requires the preserved run graph and rejects a report from another graph',()=>{
 const missing=readyFixture('closed-mainnet');
 missing.finalizedBurnCapacityAuthority=null;
 let report=assessMainnetReadiness(missing);
 assert(report.blockers.some(blocker=>blocker.code==='finalized_burn_capacity_authority_invalid'));
 const substituted=readyFixture('closed-mainnet');
 substituted.finalizedBurnCapacityReport={...substituted.finalizedBurnCapacityReport,
  peakResidentKiB:'2097153'};
 report=assessMainnetReadiness(substituted);
 assert(report.blockers.some(blocker=>blocker.code==='finalized_burn_capacity_authority_invalid'));
});
test('capacity claims reject coordinated report B bytes under release descriptor A',()=>{
 const checkpoint=readyFixture('closed-mainnet');
 checkpoint.checkpointProofCapacityReport={...checkpoint.checkpointProofCapacityReport,
  compressionPeakResidentKiB:'1048575'};
 checkpoint.checkpointProofCapacityAuthority={...checkpoint.checkpointProofCapacityAuthority,
  reportBytes:Buffer.from(JSON.stringify(checkpoint.checkpointProofCapacityReport)),
  reconstructedReport:structuredClone(checkpoint.checkpointProofCapacityReport)};
 let report=assessMainnetReadiness(checkpoint);
 assert(report.blockers.some(blocker=>blocker.code==='checkpoint_proof_capacity_report_invalid'));

 const finalized=readyFixture('closed-mainnet');
 finalized.finalizedBurnCapacityReport={...finalized.finalizedBurnCapacityReport,
  peakResidentKiB:'2097151'};
 finalized.finalizedBurnCapacityAuthority={...finalized.finalizedBurnCapacityAuthority,
  reportBytes:Buffer.from(JSON.stringify(finalized.finalizedBurnCapacityReport))};
 report=assessMainnetReadiness(finalized);
 assert(report.blockers.some(blocker=>blocker.code==='finalized_burn_capacity_authority_invalid'));
});
test('operational gas claims require live job and report bytes after ledger completion',()=>{
 for(const mutate of [
  fixture=>{fixture.productionOperationalGasAuthority=null;},
  fixture=>{fixture.productionOperationalGasAuthority.reportBytes=Buffer.from('{}');},
  fixture=>{fixture.productionOperationalGasAuthority.jobBytes=Buffer.from('{}');},
 ]) {
  const fixture=readyFixture('closed-mainnet');mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert(report.blockers.some(blocker=>blocker.code==='production_operational_gas_authority_invalid'));
 }
});
test('native privacy ceremony claims require the preserved ceremony and exact installed copies',()=>{
 for(const mutate of [
  fixture=>{fixture.nativePrivacyCeremonyAuthority=null;},
  fixture=>{fixture.nativePrivacyCeremonyAuthority.transcriptBytes=Buffer.from('{}');},
  fixture=>{const receipt=JSON.parse(fixture.nativePrivacyCeremonyAuthority.installationReceiptBytes);
   receipt.nativeRuntimeManifestSha256='ff'.repeat(32);
   fixture.nativePrivacyCeremonyAuthority.installationReceiptBytes=Buffer.from(`${JSON.stringify(receipt)}\n`);},
  fixture=>{fixture.nativePrivacyCeremonyAuthority.installedVerifyingKeyBytes=Buffer.from('foreign vk');},
 ]) {
  const fixture=readyFixture('closed-mainnet');
  fixture.nativePrivacyCeremonyAuthority={...fixture.nativePrivacyCeremonyAuthority};mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert(report.blockers.some(blocker=>blocker.code==='native_privacy_ceremony_authority_invalid'));
 }
});
test('recursive burn completion rejects zero digests even with the real adapter pins',()=>{
 const fixture=readyFixture('closed-mainnet');
 for(const field of Object.keys(fixture.finalizedBurnRecursiveCompletionReport)) {
  if(field.endsWith('Sha256')) fixture.finalizedBurnRecursiveCompletionReport[field]='0'.repeat(64);
 }
 const report=assessMainnetReadiness(fixture);
 for(const claim of ['production_finalized_burn_recursive_checkpoint_artifacts_pinned',
  'production_finalized_burn_recursive_checkpoint_receipt_verified',
  'production_finalized_burn_risc0_evm_receipt_verifier_implemented']) {
  assert.ok(report.blockers.some(blocker=>blocker.code===`${claim}_completion_invalid`));
 }
});

test('real-funds readiness rejects a consumed pilot authorization fixture',()=>{
 const fixture=readyFixture('real-funds');
 fixture.pilotFundsAuthorizationState.consumed=true;
 fixture.pilotFundsAuthority.authorizationStateBytes=
  Buffer.from(JSON.stringify(fixture.pilotFundsAuthorizationState));
 const report=assessMainnetReadiness(fixture);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>blocker.code==='pilot_funds_authorization_invalid'));
});

test('pilot funds readiness derives snapshot and authorization state from authority bytes',()=>{
 for(const mutate of [
  fixture=>{fixture.pilotFundsSnapshot={...fixture.pilotFundsSnapshot,pilotDepositBaseUnits:'2'};},
  fixture=>{fixture.pilotFundsAuthorizationState.consumed=true;},
  fixture=>{fixture.pilotFundsAuthority.snapshotBytes=Buffer.from(JSON.stringify(
   {...fixture.pilotFundsSnapshot,pilotDepositBaseUnits:'2'}));},
  fixture=>{fixture.pilotFundsAuthority.authorizationStateBytes=Buffer.from(JSON.stringify(
   {...fixture.pilotFundsAuthorizationState,consumed:true}));},
 ]) {
  const fixture=readyFixture('real-funds'); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>blocker.code==='pilot_funds_authorization_invalid'));
 }
});

test('release gate enforces the deterministic production DOM domain',()=>{
 const fixture=readyFixture();
 fixture.releaseConfig.domDomain=bytes32('99');
 const report=assessMainnetReadiness(fixture);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>blocker.code==='release_dom_domain_derivation_mismatch'));
});

test('absent DOM-domain inputs keep exact missing blockers without a derivative invalid blocker',()=>{
 const fixture=readyFixture();
 for(const field of ['checkpointDomNetworkMagic','checkpointDomChainId','reserve',
  'checkpointRegistry','domDomain']) fixture.releaseConfig[field]=null;
 const report=assessMainnetReadiness(fixture);
 for(const field of ['checkpointDomNetworkMagic','checkpointDomChainId','reserve',
  'checkpointRegistry','domDomain']) {
  assert(report.blockers.some(blocker=>blocker.code===`release_${field}_missing`));
 }
 assert(!report.blockers.some(blocker=>blocker.code==='release_dom_domain_derivation_invalid'));
 assert(!report.blockers.some(blocker=>blocker.code==='release_dom_domain_derivation_mismatch'));
});

test('absent CREATE plan fields keep exact missing blockers without derivative invalid plans',()=>{
 const fixture=readyFixture();
 const plans=[
  ['deployer','deployerNonce','reserve','release_deployment_plan_invalid'],
  ['checkpointRegistryDeployer','checkpointRegistryDeployerNonce','checkpointRegistry',
    'release_checkpoint_registry_deployment_plan_invalid'],
  ['verifierDeployer','verifierDeployerNonce','verifier','release_verifier_deployment_plan_invalid'],
  ['checkpointVerifierDeployer','checkpointVerifierDeployerNonce','checkpointVerifier',
    'release_checkpoint_verifier_deployment_plan_invalid'],
 ];
 for(const [deployer,nonce,addressField] of plans) {
  fixture.releaseConfig[deployer]=null; fixture.releaseConfig[nonce]=null;
  fixture.releaseConfig[addressField]=null;
 }
 const report=assessMainnetReadiness(fixture);
 for(const [deployer,nonce,addressField,derived] of plans) {
  for(const field of [deployer,nonce,addressField]) {
   assert(report.blockers.some(blocker=>blocker.code===`release_${field}_missing`));
  }
  assert(!report.blockers.some(blocker=>blocker.code===derived));
 }
 for(const [deployer,,,derived] of plans) {
  const malformed=readyFixture(); malformed.releaseConfig[deployer]=address(0);
  assert(assessMainnetReadiness(malformed).blockers.some(blocker=>blocker.code===derived));
 }
});

test('incomplete CREATE topology keeps field blockers without a derivative topology blocker',()=>{
 const fixture=readyFixture();
 fixture.releaseConfig.verifierDeployer=null;
 fixture.releaseConfig.verifierDeployerNonce=null;
 fixture.releaseConfig.verifier=null;
 let report=assessMainnetReadiness(fixture);
 for(const field of ['verifierDeployer','verifierDeployerNonce','verifier']) {
  assert(report.blockers.some(blocker=>blocker.code===`release_${field}_missing`));
 }
 assert(!report.blockers.some(blocker=>blocker.code==='release_deployment_topology_invalid'));
 const inconsistent=readyFixture(); inconsistent.releaseConfig.verifierDeployerNonce='9';
 report=assessMainnetReadiness(inconsistent);
 assert(report.blockers.some(blocker=>blocker.code==='release_deployment_topology_invalid'));
});

test('absent contract roles keep missing blockers without claiming an identity collision',()=>{
 const fixture=readyFixture(); fixture.releaseConfig.reserve=null;
 let report=assessMainnetReadiness(fixture);
 assert(report.blockers.some(blocker=>blocker.code==='release_reserve_missing'));
 assert(!report.blockers.some(blocker=>blocker.code==='release_contract_identity_collision'));
 const duplicate=readyFixture(); duplicate.releaseConfig.reserve=duplicate.releaseConfig.verifier;
 report=assessMainnetReadiness(duplicate);
 assert(report.blockers.some(blocker=>blocker.code==='release_contract_identity_collision'));
 const malformed=readyFixture(); malformed.releaseConfig.reserve='not-an-address';
 report=assessMainnetReadiness(malformed);
 assert(report.blockers.some(blocker=>blocker.code==='release_contract_identity_collision'));
});

test('absent owner sets keep missing blockers without invalid or reuse derivatives',()=>{
 const fixture=readyFixture();
 for(const role of ['governance','guardian','checkpointGuardian']) {
  fixture.releaseConfig[`${role}Owners`]=null;
 }
 let report=assessMainnetReadiness(fixture);
 for(const role of ['governance','guardian','checkpointGuardian']) {
  assert(report.blockers.some(blocker=>blocker.code===`release_${role}Owners_missing`));
  assert(!report.blockers.some(blocker=>blocker.code===`release_${role}_owners_invalid`));
 }
 assert(!report.blockers.some(blocker=>blocker.code==='release_control_plane_owner_reuse'));
 const malformed=readyFixture(); malformed.releaseConfig.governanceOwners=[];
 report=assessMainnetReadiness(malformed);
 assert(report.blockers.some(blocker=>blocker.code==='release_governance_owners_invalid'));
 const reused=readyFixture(); reused.releaseConfig.checkpointGuardianOwners[0]=
  reused.releaseConfig.governanceOwners[0];
 report=assessMainnetReadiness(reused);
 assert(!report.blockers.some(blocker=>blocker.code==='release_control_plane_owner_reuse'));
});

test('absent source commit keeps its blocker without impossible parent and diff diagnostics',()=>{
 const fixture=readyFixture(); fixture.evidence.sourceCommit=null;
 fixture.repositoryState.sourceCommit=null;
 fixture.repositoryState.headParents=[];
 fixture.repositoryState.releaseEvidenceChanges=null;
 fixture.readinessDocumentAuthority.releaseEvidenceBytes=Buffer.from(JSON.stringify(fixture.evidence));
 fixture.repositoryStateAuthority.bytes=Buffer.from(JSON.stringify(fixture.repositoryState));
 let report=assessMainnetReadiness(fixture);
 assert(report.blockers.some(blocker=>blocker.code==='source_commit_missing'));
 assert(!report.blockers.some(blocker=>blocker.code==='release_evidence_parent_mismatch'));
 assert(!report.blockers.some(blocker=>blocker.code==='release_evidence_diff_missing'));
 assert(!report.blockers.some(blocker=>blocker.code==='source_tag_signature_unverified'));
 assert(!report.blockers.some(blocker=>blocker.code==='source_tag_mismatch'));
 const invalidParent=readyFixture(); invalidParent.repositoryState.headParents=[];
 invalidParent.repositoryStateAuthority.bytes=Buffer.from(JSON.stringify(invalidParent.repositoryState));
 report=assessMainnetReadiness(invalidParent);
 assert(report.blockers.some(blocker=>blocker.code==='release_evidence_parent_mismatch'));
 const missingDiff=readyFixture(); missingDiff.repositoryState.releaseEvidenceChanges=null;
 missingDiff.repositoryStateAuthority.bytes=Buffer.from(JSON.stringify(missingDiff.repositoryState));
 report=assessMainnetReadiness(missingDiff);
 assert(report.blockers.some(blocker=>blocker.code==='release_evidence_diff_missing'));
});

test('absent source commit does not claim signature or identity failures for a nonexistent object',()=>{
 const fixture=readyFixture(); fixture.evidence.sourceCommit=null;
 fixture.readinessDocumentAuthority.releaseEvidenceBytes=Buffer.from(JSON.stringify(fixture.evidence));
 Object.assign(fixture.repositoryState,{sourceCommit:null,sourceCommitSignatureVerified:false,
  releaseCommitSignatureVerified:false,sourceAuthor:null,sourceCommitter:null,
  releaseAuthor:'Wrong <wrong@example.test>',releaseCommitter:'Wrong <wrong@example.test>',
  sourceCommitSignerFingerprint:'B'.repeat(40),releaseCommitSignerFingerprint:'B'.repeat(40)});
 fixture.repositoryStateAuthority.bytes=Buffer.from(JSON.stringify(fixture.repositoryState));
 let report=assessMainnetReadiness(fixture);
 assert(report.blockers.some(blocker=>blocker.code==='source_commit_missing'));
 for(const code of ['source_commit_signature_unverified','source_author_mismatch',
  'source_committer_mismatch','release_evidence_commit_signature_unverified',
  'release_evidence_author_mismatch','release_evidence_committer_mismatch',
  'source_commit_signer_mismatch','release_evidence_commit_signer_mismatch']) {
  assert(!report.blockers.some(blocker=>blocker.code===code));
 }
 const present=readyFixture(); Object.assign(present.repositoryState,
  {sourceCommitSignatureVerified:false,releaseCommitSignatureVerified:false,
   sourceAuthor:'Wrong <wrong@example.test>',
   sourceCommitter:'Wrong <wrong@example.test>',releaseAuthor:'Wrong <wrong@example.test>',
   releaseCommitter:'Wrong <wrong@example.test>',sourceCommitSignerFingerprint:'B'.repeat(40)});
 present.repositoryState.releaseCommitSignerFingerprint='B'.repeat(40);
 present.repositoryStateAuthority.bytes=Buffer.from(JSON.stringify(present.repositoryState));
 report=assessMainnetReadiness(present);
 for(const code of ['source_commit_signature_unverified','source_author_mismatch',
  'source_committer_mismatch','release_evidence_commit_signature_unverified',
  'release_evidence_author_mismatch','release_evidence_committer_mismatch',
  'source_commit_signer_mismatch','release_evidence_commit_signer_mismatch']) {
  assert(report.blockers.some(blocker=>blocker.code===code));
 }
});

test('uninspected source commit does not claim signature or identity failures for another object',()=>{
 const absent=readyFixture(); absent.repositoryState.sourceCommit=null;
 absent.repositoryState.sourceCommitSignatureVerified=false;
 absent.repositoryState.sourceAuthor='Wrong <wrong@example.test>';
 absent.repositoryState.sourceCommitter='Wrong <wrong@example.test>';
 absent.repositoryState.sourceCommitSignerFingerprint='B'.repeat(40);
 absent.repositoryStateAuthority.bytes=Buffer.from(JSON.stringify(absent.repositoryState));
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='source_commit_mismatch'));
 assert(!report.blockers.some(blocker=>blocker.code==='source_commit_signature_unverified'));
 assert(!report.blockers.some(blocker=>blocker.code==='source_author_mismatch'));
 assert(!report.blockers.some(blocker=>blocker.code==='source_committer_mismatch'));
 assert(!report.blockers.some(blocker=>blocker.code==='source_commit_signer_mismatch'));

 const present=readyFixture(); present.repositoryState.sourceCommitSignatureVerified=false;
 present.repositoryState.sourceAuthor='Wrong <wrong@example.test>';
 present.repositoryState.sourceCommitter='Wrong <wrong@example.test>';
 present.repositoryState.sourceCommitSignerFingerprint='B'.repeat(40);
 present.repositoryStateAuthority.bytes=Buffer.from(JSON.stringify(present.repositoryState));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>blocker.code==='source_commit_signature_unverified'));
 assert(report.blockers.some(blocker=>blocker.code==='source_author_mismatch'));
 assert(report.blockers.some(blocker=>blocker.code==='source_committer_mismatch'));
 assert(report.blockers.some(blocker=>blocker.code==='source_commit_signer_mismatch'));
});

test('absent release-evidence commit does not claim signature or identity failures for source HEAD',()=>{
 const absent=readyFixture();
 absent.repositoryState.head=absent.evidence.sourceCommit;
 absent.repositoryState.headParents=[];
 absent.repositoryState.releaseEvidenceChanges=null;
 absent.repositoryState.releaseCommitSignatureVerified=false;
 absent.repositoryState.releaseAuthor='Wrong <wrong@example.test>';
 absent.repositoryState.releaseCommitter='Wrong <wrong@example.test>';
 absent.repositoryState.releaseCommitSignerFingerprint='B'.repeat(40);
 absent.repositoryState.tagSignatureVerified=false;
 absent.repositoryState.tagSignerFingerprint='B'.repeat(40);
 absent.repositoryStateAuthority.bytes=Buffer.from(JSON.stringify(absent.repositoryState));
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_evidence_commit_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='release_evidence_commit_signature_unverified'));
 assert(!report.blockers.some(blocker=>blocker.code==='release_evidence_author_mismatch'));
 assert(!report.blockers.some(blocker=>blocker.code==='release_evidence_committer_mismatch'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='release_evidence_commit_signer_mismatch'));
 assert(!report.blockers.some(blocker=>blocker.code==='release_evidence_parent_mismatch'));
 assert(!report.blockers.some(blocker=>blocker.code==='release_evidence_diff_missing'));
 assert(!report.blockers.some(blocker=>blocker.code==='source_tag_signature_unverified'));
 assert(!report.blockers.some(blocker=>blocker.code==='source_tag_signer_mismatch'));

 const present=readyFixture(); present.repositoryState.releaseCommitSignatureVerified=false;
 present.repositoryState.headParents=[];
 present.repositoryState.releaseEvidenceChanges=null;
 present.repositoryState.tagCommit=present.evidence.sourceCommit;
 present.repositoryState.tagSignatureVerified=false;
 present.repositoryState.releaseAuthor='Wrong <wrong@example.test>';
 present.repositoryState.releaseCommitter='Wrong <wrong@example.test>';
 present.repositoryState.releaseCommitSignerFingerprint='B'.repeat(40);
 present.repositoryState.tagSignerFingerprint='B'.repeat(40);
 present.repositoryStateAuthority.bytes=Buffer.from(JSON.stringify(present.repositoryState));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_evidence_commit_signature_unverified'));
 assert(report.blockers.some(blocker=>blocker.code==='release_evidence_author_mismatch'));
 assert(report.blockers.some(blocker=>blocker.code==='release_evidence_committer_mismatch'));
 assert(report.blockers.some(blocker=>
  blocker.code==='release_evidence_commit_signer_mismatch'));
 assert(report.blockers.some(blocker=>blocker.code==='release_evidence_parent_mismatch'));
 assert(report.blockers.some(blocker=>blocker.code==='release_evidence_diff_missing'));
 assert(report.blockers.some(blocker=>blocker.code==='source_tag_mismatch'));
 assert(report.blockers.some(blocker=>blocker.code==='source_tag_signature_unverified'));
 assert(report.blockers.some(blocker=>blocker.code==='source_tag_signer_mismatch'));
});

test('absent or noncanonical source tag does not claim a signature failure for no Git ref',()=>{
 for(const sourceTag of [null,'latest']) {
  const fixture=readyFixture(); fixture.evidence.sourceTag=sourceTag;
  fixture.readinessDocumentAuthority.releaseEvidenceBytes=Buffer.from(JSON.stringify(fixture.evidence));
  fixture.repositoryState.tagCommit=null; fixture.repositoryState.tagSignatureVerified=false;
  fixture.repositoryState.tagSignerFingerprint='B'.repeat(40);
  fixture.repositoryStateAuthority.bytes=Buffer.from(JSON.stringify(fixture.repositoryState));
  const report=assessMainnetReadiness(fixture);
  assert(report.blockers.some(blocker=>blocker.code===(sourceTag===null
    ?'source_tag_missing':'source_tag_invalid')));
  assert(!report.blockers.some(blocker=>blocker.code==='source_tag_signature_unverified'));
  assert(!report.blockers.some(blocker=>blocker.code==='source_tag_signer_mismatch'));
 }
 const present=readyFixture(); present.repositoryState.tagSignatureVerified=false;
 present.repositoryState.tagSignerFingerprint='B'.repeat(40);
 present.repositoryStateAuthority.bytes=Buffer.from(JSON.stringify(present.repositoryState));
 const report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>blocker.code==='source_tag_signature_unverified'));
 assert(report.blockers.some(blocker=>blocker.code==='source_tag_signer_mismatch'));
});

test('release gate semantically validates the security report against immutable source inputs',()=>{
 for(const mutate of [
  fixture=>{fixture.securityValidationReport.checks[0].exitCode=1;},
  fixture=>{fixture.securityValidationReport.sourceCommit='b'.repeat(40);},
  fixture=>{fixture.requirementsSha256=documentSha('substituted requirements');},
  fixture=>{fixture.sourceManifestSha256=documentSha('substituted manifest');},
 ]) {
  const fixture=readyFixture(); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>blocker.code==='security_validation_report_invalid'));
 }
});

test('release gate semantically validates the operations review and exact runbook',()=>{
 for(const mutate of [
  fixture=>{fixture.operationsReviewReport.reviewAssertions.nativeRuntimeActivationReviewed=false;},
  fixture=>{fixture.operationsReviewReport.operationalEvidence.riscZeroHealthSourceCatalog.sha256=
    documentSha('substituted health catalog');},
  fixture=>{fixture.operationsReviewReport.reserve=address(999);},
  fixture=>{fixture.operatorRunbookSha256=documentSha('substituted runbook');},
 ]) {
  const fixture=readyFixture(); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>blocker.code==='operations_review_report_invalid'));
 }
});

test('release gate semantically validates two isolated reserve builds',()=>{
 for(const mutate of [
  fixture=>{fixture.reserveReproducibleBuildReport.observations[1].artifactSha256=
    documentSha('substituted artifact');},
  fixture=>{fixture.reserveReproducibleBuildReport.observations[1].runtimeCodeHash=bytes32('99');},
  fixture=>{fixture.reserveReproducibleBuildReport.observations[1].compilerVersion=
    '0.8.36+commit.00000000';},
  fixture=>{fixture.reserveReproducibleBuildReport.reserve=address(999);},
 ]) {
  const fixture=readyFixture(); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>blocker.code==='reserve_reproducible_build_report_invalid'));
 }
});

test('release gate semantically validates two isolated verifier builds',()=>{
 for(const mutate of [
  fixture=>{fixture.verifierReproducibleBuildReport.observations[1].artifactSha256=
    documentSha('substituted verifier artifact');},
  fixture=>{fixture.verifierReproducibleBuildReport.observations[1].runtimeCodeHash=bytes32('99');},
  fixture=>{fixture.verifierReproducibleBuildReport.observations[1].compilerVersion=
    '0.8.36+commit.00000000';},
  fixture=>{fixture.verifierReproducibleBuildReport.verifierConfigHash=bytes32('98');},
  fixture=>{fixture.verifierReproducibleBuildReport.verifier=address(999);},
 ]) {
  const fixture=readyFixture(); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>blocker.code==='verifier_reproducible_build_report_invalid'));
 }
});

test('release gate semantically validates fork rehearsal outcomes and raw evidence',()=>{
 for(const mutate of [
  fixture=>{fixture.mainnetForkRehearsalReport.scenarios[0].unsafeTransitionCount='1';},
  fixture=>{fixture.mainnetForkRehearsalReport.reserveConfigHash=bytes32('99');},
  fixture=>{delete fixture.mainnetForkRehearsalEvidenceFiles[
   fixture.mainnetForkRehearsalReport.scenarios[0].faultEvidence.path];},
  fixture=>{fixture.mainnetForkRehearsalEvidenceFiles[
   fixture.mainnetForkRehearsalReport.scenarios[0].recoveryEvidence.path].document.recoveryObserved=false;},
  fixture=>{fixture.mainnetForkRehearsalEvidenceFiles[
   fixture.mainnetForkRehearsalReport.scenarios[0].faultEvidence.path].document.capturedAtUnix='1792492001';},
 ]) {
  const fixture=readyFixture();
  fixture.mainnetForkRehearsalReport=structuredClone(fixture.mainnetForkRehearsalReport);
  mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>blocker.code==='mainnet_fork_rehearsal_report_invalid'));
 }
});

test('release gate semantically validates checkpoint bootstrap ratification',()=>{
 for(const mutate of [
  fixture=>{fixture.checkpointBootstrapRatificationReport.approvals[0].eip1271MagicValue='0xffffffff';},
  fixture=>{fixture.checkpointBootstrapRatificationReport.ethereumCheckpointRoot=bytes32('99');},
  fixture=>{fixture.ethereumCheckpointConsensus.checkpointRoot=bytes32('99');},
  fixture=>{fixture.nativePreactivationFacts.checkpointInitialHeight='999';},
 ]) {
  const fixture=readyFixture();
  fixture.checkpointBootstrapRatificationReport=
   structuredClone(fixture.checkpointBootstrapRatificationReport);
  mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>
   blocker.code==='checkpoint_bootstrap_ratification_report_invalid'));
 }
});

test('release gate semantically validates the finalized checkpoint event',()=>{
 for(const mutate of [
  fixture=>{fixture.checkpointFinalizedEventReport.observations[0].receiptStatus='0';},
  fixture=>{fixture.checkpointFinalizedEventReport.registryRuntimeCodeHash=bytes32('99');},
  fixture=>{fixture.checkpointFinalizedEventReport.registryState.candidateStatementHash=bytes32('99');},
 ]) {
  const fixture=readyFixture();
  fixture.checkpointFinalizedEventReport=structuredClone(fixture.checkpointFinalizedEventReport);
  mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>blocker.code==='checkpoint_finalized_event_report_invalid'));
 }
});

test('release gate semantically validates the checkpoint verifier reproducible build',()=>{
 for(const mutate of [
  fixture=>{fixture.checkpointVerifierReproducibleBuildReport.observations[1].artifactSha256=
   documentSha('substituted artifact');},
  fixture=>{fixture.checkpointVerifierReproducibleBuildReport.verifierConfigHash=bytes32('99');},
  fixture=>{fixture.checkpointVerifierConfig.checkpointGuestImageId=bytes32('99');},
 ]) {
  const fixture=readyFixture();
  fixture.checkpointVerifierReproducibleBuildReport=
   structuredClone(fixture.checkpointVerifierReproducibleBuildReport);
  mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>
   blocker.code==='checkpoint_verifier_reproducible_build_report_invalid'));
 }
});

test('release readiness rejects a shared burn and checkpoint guest ImageID',()=>{
 const fixture=readyFixture();
 fixture.checkpointVerifierConfig.checkpointGuestImageId=
  fixture.verifierConfig.finalizedBurnGuestImageId;
 const report=assessMainnetReadiness(fixture);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>
  blocker.code==='risc0_adapter_image_capability_collision'));
});

test('release gate semantically validates the checkpoint registry reproducible build',()=>{
 for(const mutate of [
  fixture=>{fixture.checkpointRegistryReproducibleBuildReport.observations[1].artifactSha256=
   documentSha('substituted registry artifact');},
  fixture=>{fixture.checkpointRegistryReproducibleBuildReport.checkpointRegistryConfigHash=
   bytes32('99');},
  fixture=>{fixture.releaseConfig.checkpointInitialHeight='99998';},
 ]) {
  const fixture=readyFixture();
  fixture.checkpointRegistryReproducibleBuildReport=
   structuredClone(fixture.checkpointRegistryReproducibleBuildReport);
  mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>
   blocker.code==='checkpoint_registry_reproducible_build_report_invalid'));
 }
});

test('release gate semantically validates the residual-risk presentation separately from acceptance',()=>{
 for(const mutate of [
  fixture=>{fixture.residualRiskReport.risks[0].accepted=true;},
  fixture=>{fixture.residualRiskReport.realFundsAuthorized=
   !fixture.residualRiskReport.realFundsAuthorized;},
  fixture=>{fixture.residualRiskDraftSha256=documentSha('substituted risk draft');},
 ]) {
  const fixture=readyFixture();
  fixture.residualRiskReport=structuredClone(fixture.residualRiskReport);
  mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>blocker.code==='residual_risk_report_invalid'));
 }
});

test('release gate semantically validates the shared trusted-setup decision',()=>{
 for(const mutate of [
  fixture=>{fixture.trustedSetupDecisionReport.decision='not-required';},
  fixture=>{fixture.trustedSetupDecisionReport.finalizedBurnVerifier.verifyingKeySha256=
   bytes32('99');},
  fixture=>{fixture.trustedSetupVerificationReport.snarkjs.zkeyVerified=false;},
  fixture=>{fixture.trustedSetupVerificationReport.artifacts.zkey.verificationKeySha256='99'.repeat(32);},
  fixture=>{fixture.trustedSetupAuthoritySha256='88'.repeat(32);},
  fixture=>{const decision=fixture.evidence.checkpointTrustedSetup.decisionReport;
   fixture.evidence.checkpointTrustedSetup.decisionReport={...decision,
    path:'evidence/other-decision.txt'};
   fixture.evidenceFiles['evidence/other-decision.txt']=decision.sha256;},
 ]) {
  const fixture=readyFixture();
  fixture.trustedSetupDecisionReport=structuredClone(fixture.trustedSetupDecisionReport);
  fixture.trustedSetupVerificationReport=structuredClone(fixture.trustedSetupVerificationReport);
  mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>blocker.code==='trusted_setup_decision_report_invalid'));
 }
});
test('trusted-setup decision rejects coordinated object B and bytes B under descriptor A',()=>{
 const fixture=readyFixture();
 fixture.trustedSetupDecisionReport={...fixture.trustedSetupDecisionReport,decision:'not-required'};
 fixture.trustedSetupDecisionReportAuthority={reportBytes:Buffer.from(
  serializeTrustedSetupDecisionReport(fixture.trustedSetupDecisionReport))};
 const report=assessMainnetReadiness(fixture);
 assert(report.blockers.some(({code})=>code==='trusted_setup_decision_report_invalid'));
});

test('offline release signer rederives the exact owner-bound EIP-712 request',()=>{
 const fixture=readyFixture();
 const bundleBytes=Buffer.from(JSON.stringify(fixture.controlPlaneEvidenceArtifacts.bundle));
 const bundleSha256=createHash('sha256').update(bundleBytes).digest('hex');
 fixture.evidence.controlPlaneEvidenceBundle.sha256=bundleSha256;
 const authorization={...fixture.operatorIntent.residual_risk_acceptance,
  releaseEvidenceCommitment:releaseEvidenceCommitment(fixture.evidence),signature:null};
 const typed=releaseAuthorizationTypedData(authorization,fixture.releaseConfig);
 const request={schema:'usdom-release-authorization-request/v2',
  releaseId:fixture.evidence.releaseId,sourceCommit:fixture.evidence.sourceCommit,
  finalizedAnchor:{blockNumber:'22000000',blockHash:bytes32('70'),
   blockTimestamp:authorization.acceptedAt,governance:fixture.releaseConfig.governance,
   governanceCodeHash:fixture.releaseConfig.governanceCodeHash,
   rpcConsensus:rpcConsensusEvidence([{sourceId:'operator-a',originKeccak256:bytes32('81')},
    {sourceId:'operator-b',originKeccak256:bytes32('82')}])},authorization,
  digest:releaseAuthorizationDigest(authorization,fixture.releaseConfig),
  typedData:TypedDataEncoder.getPayload(typed.domain,typed.types,typed.message)};
 const inputs={request,bundle:fixture.controlPlaneEvidenceArtifacts.bundle,
  bundleBytes,bundleSha256,
  releaseConfig:fixture.releaseConfig,releaseEvidence:fixture.evidence};
 assert.equal(validateReleaseAuthorizationSigningRequest(inputs).digest,request.digest);
 const mutations=[
  value=>{value.request.digest=bytes32('99');},
  value=>{value.request.typedData.message.governanceOwnersHash=bytes32('99');},
  value=>{value.request.authorization.reserveConfigHash=bytes32('99');},
  value=>{value.request.sourceCommit='b'.repeat(40);},
  value=>{value.request.finalizedAnchor.governanceCodeHash=bytes32('99');},
  value=>{value.request.finalizedAnchor.blockNumber='022000000';},
  value=>{value.request.finalizedAnchor.blockHash='0x12';},
  value=>{value.request.finalizedAnchor.rpcConsensus.sources.pop();},
  value=>{value.bundleSha256='9'.repeat(64);},
  value=>{value.releaseEvidence.controlPlaneEvidenceBundle.path='evidence/other.json';},
  value=>{value.releaseEvidence.controlPlaneEvidenceBundle.sha256='9'.repeat(64);},
  value=>{value.releaseEvidence.reserveArtifact.sha256='8'.repeat(64);},
  value=>{value.request.authorization.sourceTag='usdom-v9.9.9';},
  value=>{value.bundle.ethereumChainId='2';},
  value=>{value.releaseConfig.governanceOwners.reverse();},
  value=>{value.bundle.roleReports.governance.ownersAfter.reverse();},
 ];
 for(const mutate of mutations) {
  const changed=structuredClone(inputs); mutate(changed);
  changed.bundleBytes=bundleBytes;
  assert.throws(()=>validateReleaseAuthorizationSigningRequest(changed));
 }
 const detached=structuredClone(inputs); detached.bundle.ethereumChainId='2';
 detached.bundleBytes=bundleBytes;
 assert.throws(()=>validateReleaseAuthorizationSigningRequest(detached),/bytes differ from parsed authority/);
});

test('offline native signer independently derives all four artifact-bound requests',()=>{
 const fixture=readyFixture('real-funds');
 const bundleBytes=Buffer.from(JSON.stringify(fixture.controlPlaneEvidenceArtifacts.bundle));
 const bundleSha256=createHash('sha256').update(bundleBytes).digest('hex');
 fixture.evidence.controlPlaneEvidenceBundle.sha256=bundleSha256;
 const subjects={nativePrivacyTrustedSetup:`0x${fixture.nativeRuntimeValidation.privacy_verifier_config_hash}`,
  nativeScheduledRuntimeActivation:`0x${fixture.evidence.nativeRuntimeManifest.sha256}`,
  nativeWalletCustody:bytes32('a3'),nativeWalletRecovery:bytes32('a4'),
  walletPublicIdentitySha256:'a2'.repeat(32),walletCustodyEvidenceSha256:'a3'.repeat(32),
  walletRecoveryEvidenceSha256:'a4'.repeat(32)};
 const kinds={nativePrivacyTrustedSetup:'native-privacy-trusted-setup',
  nativeScheduledRuntimeActivation:'native-scheduled-runtime-activation',
  nativeWalletCustody:'native-wallet-custody',nativeWalletRecovery:'native-wallet-recovery'};
 const requests=Object.fromEntries(Object.entries(kinds).map(([name,kind])=>{
  const built=buildNativeReleaseAttestation({kind,releaseEvidence:fixture.evidence,
   releaseConfig:fixture.releaseConfig,completedAt:'1792492800',subjectCommitment:subjects[name]});
  const typed=nativeReleaseAttestationTypedData(built.attestation,fixture.releaseConfig);
  return [name,{attestation:built.attestation,digest:built.digest,
   typedData:TypedDataEncoder.getPayload(typed.domain,typed.types,typed.message)}];
 }));
 const request={schema:'usdom-native-release-attestation-requests/v3',
  releaseId:fixture.evidence.releaseId,sourceCommit:fixture.evidence.sourceCommit,
  finalizedAnchor:{blockNumber:'22000000',blockHash:bytes32('70'),blockTimestamp:'1792492800',
   governance:fixture.releaseConfig.governance,
   governanceCodeHash:fixture.releaseConfig.governanceCodeHash,
   rpcConsensus:rpcConsensusEvidence([{sourceId:'operator-a',originKeccak256:bytes32('81')},
    {sourceId:'operator-b',originKeccak256:bytes32('82')}])},subjects,requests};
 const inputs={request,bundle:fixture.controlPlaneEvidenceArtifacts.bundle,
  bundleBytes,bundleSha256,
  releaseConfig:fixture.releaseConfig,releaseEvidence:fixture.evidence,
  privacyVerifierConfigHash:fixture.nativeRuntimeValidation.privacy_verifier_config_hash,
  nativeRuntimeManifestSha256:fixture.evidence.nativeRuntimeManifest.sha256,
  walletPublicIdentitySha256:'a2'.repeat(32),walletCustodyEvidenceSha256:'a3'.repeat(32),
  walletRecoveryEvidenceSha256:'a4'.repeat(32)};
 assert.equal(Object.keys(validateNativeReleaseAttestationSigningRequest(inputs).digests).length,4);
 const mutations=[
  value=>{value.request.requests.nativeWalletCustody.digest=bytes32('99');},
  value=>{value.request.requests.nativePrivacyTrustedSetup.typedData.message.subjectCommitment=bytes32('99');},
  value=>{value.request.subjects.nativeWalletRecovery=bytes32('99');},
  value=>{value.walletPublicIdentitySha256='9'.repeat(64);},
  value=>{value.walletCustodyEvidenceSha256='9'.repeat(64);},
  value=>{value.walletRecoveryEvidenceSha256='9'.repeat(64);},
  value=>{value.nativeRuntimeManifestSha256='9'.repeat(64);},
  value=>{value.privacyVerifierConfigHash='9'.repeat(64);},
  value=>{value.bundleSha256='9'.repeat(64);},
  value=>{value.request.finalizedAnchor.blockNumber='022000000';},
  value=>{value.request.finalizedAnchor.rpcConsensus.sourceSetCommitment=bytes32('99');},
  value=>{value.releaseConfig.governanceOwners.reverse();},
 ];
 for(const mutate of mutations) {
  const changed=structuredClone(inputs); mutate(changed);
  changed.bundleBytes=bundleBytes;
  assert.throws(()=>validateNativeReleaseAttestationSigningRequest(changed));
 }
 const detached=structuredClone(inputs); detached.bundle.ethereumChainId='2';
 detached.bundleBytes=bundleBytes;
 assert.throws(()=>validateNativeReleaseAttestationSigningRequest(detached),
  /bytes differ from parsed authority/);
});

test('finalized-burn E2E evidence is semantically bound to proof, verifier and release',()=>{
 const cases=[
  fixture=>{fixture.finalizedBurnE2eReport=null;},
  fixture=>{fixture.finalizedBurnE2eReport.devMode=true;},
  fixture=>{fixture.finalizedBurnE2eReport.receiptVerified=false;},
  fixture=>{fixture.finalizedBurnE2eReport.evmCallAccepted=false;},
  fixture=>{fixture.finalizedBurnE2eReport.evmVerificationGas='5000001';},
  fixture=>{fixture.finalizedBurnE2eReport.broadcastAuthorized=true;},
  fixture=>{fixture.finalizedBurnE2eReport.mines=true;},
  fixture=>{fixture.finalizedBurnE2eReport.releaseSpecific=false;},
  fixture=>{fixture.finalizedBurnE2eReport.evmSealBytes='0';},
  fixture=>{fixture.finalizedBurnE2eReport.compressionWallMilliseconds='0';},
  fixture=>{fixture.finalizedBurnE2eReport.startedAt='1792492800';},
  fixture=>{fixture.finalizedBurnE2eReport.observationSourceIds=['drpc','drpc'];},
  fixture=>{fixture.finalizedBurnE2eReport.finalizedObservationBlockHash=bytes32('00');},
  fixture=>{fixture.finalizedBurnE2eReport.isolatedEvmTransactionHash=bytes32('99');},
  fixture=>{fixture.finalizedBurnE2eReport.isolatedEvmBlockHash=bytes32('99');},
  fixture=>{fixture.finalizedBurnE2eReport.isolatedEvmBlockNumber='0';},
  fixture=>{fixture.finalizedBurnE2eReport.isolatedEvmReceiptSha256='99'.repeat(32);},
  fixture=>{fixture.finalizedBurnE2eReport.burn.amount='1000001';},
  fixture=>{fixture.finalizedBurnE2eReport.guestImageId=bytes32('99');},
  fixture=>{fixture.finalizedBurnE2eReport.releaseId='another-release';},
  fixture=>{fixture.finalizedBurnE2eReport.sourceCommit='b'.repeat(40);},
  fixture=>{fixture.finalizedBurnE2eReport.unexpected=true;},
 ];
 for(const mutate of cases) {
  const fixture=readyFixture(); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,JSON.stringify(report.blockers));
  assert(report.blockers.some(blocker=>blocker.code==='finalized_burn_e2e_report_invalid'),
    JSON.stringify(report.blockers));
 }
});

test('finalized-burn E2E rejects coordinated report B bytes under release descriptor A',()=>{
 const fixture=readyFixture();
 fixture.finalizedBurnE2eReport={...fixture.finalizedBurnE2eReport,peakResidentKiB:'2047'};
 fixture.finalizedBurnE2eAuthority={reportBytes:Buffer.from(JSON.stringify(fixture.finalizedBurnE2eReport))};
 const report=assessMainnetReadiness(fixture);
 assert.equal(report.ready,false);
 assert(report.blockers.some(({code})=>code==='finalized_burn_e2e_report_invalid'));
});

test('finalized-burn E2E materialization is fixed, canonical and evidence-only',()=>{
 const fixture=readyFixture();
 fixture.evidence.realFinalizedEndToEndReport=null;
 const prepared=prepareFinalizedBurnReleaseEvidenceMaterialization({
  report:fixture.finalizedBurnE2eReport,evidence:fixture.evidence,
  releaseConfig:fixture.releaseConfig,verifierConfig:fixture.verifierConfig,
  riscZeroReference:fixture.riscZeroReference,
 });
 assert.equal(prepared.evidence.realFinalizedEndToEndReport.path,
  FINALIZED_BURN_E2E_EVIDENCE_PATH);
 assert.equal(prepared.evidence.realFinalizedEndToEndReport.sha256,prepared.sha256);
 assert.deepEqual(JSON.parse(prepared.reportContent),fixture.finalizedBurnE2eReport);
 assert.deepEqual(JSON.parse(prepared.evidenceContent),prepared.evidence);
 const collision=readyFixture();
 collision.evidence.realFinalizedEndToEndReport=null;
 collision.evidence.operationsReviewReport={path:FINALIZED_BURN_E2E_EVIDENCE_PATH,
  sha256:'ab'.repeat(32)};
 assert.throws(()=>prepareFinalizedBurnReleaseEvidenceMaterialization({
  report:collision.finalizedBurnE2eReport,evidence:collision.evidence,
  releaseConfig:collision.releaseConfig,verifierConfig:collision.verifierConfig,
  riscZeroReference:collision.riscZeroReference,
 }));
 const stale=readyFixture();
 stale.evidence.realFinalizedEndToEndReport={
  path:'evidence/finalized-burn-e2e/stale-report.json',sha256:'ab'.repeat(32),
 };
 assert.throws(()=>prepareFinalizedBurnReleaseEvidenceMaterialization({
  report:stale.finalizedBurnE2eReport,evidence:stale.evidence,
  releaseConfig:stale.releaseConfig,verifierConfig:stale.verifierConfig,
  riscZeroReference:stale.riscZeroReference,
 }),/already binds a different finalized-burn E2E report/);
 const substituted=readyFixture(); substituted.finalizedBurnE2eReport.releaseSpecific=false;
 assert.throws(()=>prepareFinalizedBurnReleaseEvidenceMaterialization({
  report:substituted.finalizedBurnE2eReport,evidence:substituted.evidence,
  releaseConfig:substituted.releaseConfig,verifierConfig:substituted.verifierConfig,
  riscZeroReference:substituted.riscZeroReference,
 }));
});

test('checkpoint capacity evidence is semantically bound to every proof layer and release',()=>{
 const cases=[
  fixture=>{fixture.checkpointProofCapacityReport=null;},
  fixture=>{fixture.checkpointProofCapacityReport.devMode=true;},
  fixture=>{fixture.checkpointProofCapacityReport.layers[0].receiptVerified=false;},
  fixture=>{fixture.checkpointProofCapacityReport.layers[3].imageId='99'.repeat(32);},
  fixture=>{fixture.checkpointProofCapacityReport.checkpoint.blockHash=bytes32('99');},
  fixture=>{fixture.checkpointProofCapacityReport.outerJournalDigestSha256='99'.repeat(32);},
  fixture=>{fixture.checkpointProofCapacityReport.adapterCallAccepted=false;},
  fixture=>{fixture.checkpointProofCapacityReport.adapterVerificationGas='5000001';},
  fixture=>{fixture.checkpointProofCapacityReport.releaseId='another-release';},
  fixture=>{fixture.checkpointProofCapacityReport.sourceCommit='b'.repeat(40);},
  fixture=>{fixture.checkpointProofCapacityReport.unexpected=true;},
 ];
 for(const mutate of cases) {
  const fixture=readyFixture(); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,JSON.stringify(report.blockers));
  assert(report.blockers.some(blocker=>blocker.code==='checkpoint_proof_capacity_report_invalid'),
    JSON.stringify(report.blockers));
 }
});

test('control-plane evidence content is parsed and cross-reconciled',()=>{
 const mutations=[
  fixture=>{fixture.controlPlaneEvidenceArtifacts.bundle=null;},
  fixture=>{fixture.controlPlaneEvidenceArtifacts.bundle.roleReports.guardian.ownersAfter.reverse();},
  fixture=>{fixture.controlPlaneEvidenceArtifacts.roleReports.governance.configurationHash=
    bytes32('99');},
  fixture=>{fixture.controlPlaneEvidenceArtifacts.separationReport.roles.reverse();},
  fixture=>{fixture.controlPlaneEvidenceArtifacts.recoveryDrillReport.roles[0].signers.reverse();},
  fixture=>{fixture.controlPlaneEvidenceArtifacts.finalBundle=null;},
  fixture=>{fixture.controlPlaneEvidenceArtifacts.finalBundle.extra=true;},
  fixture=>{fixture.controlPlaneEvidenceArtifacts.finalBundle.executions[1].transactionHash=
    bytes32('99');},
 ];
 for(const mutate of mutations) {
  const fixture=readyFixture(); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert.ok(report.blockers.some(blocker=>blocker.code==='control_plane_evidence_content_invalid'));
 }
});

test('absent control-plane evidence does not cascade into a semantic-content blocker',()=>{
 const fixture=readyFixture();
 const documents=[
  fixture.evidence.controlPlaneEvidenceBundle,
  ...['governance','guardian','checkpointGuardian'].map(role=>
   fixture.evidence.controlPlane[role].configurationReport),
  fixture.evidence.controlPlaneSeparationReport,
  fixture.evidence.controlPlaneRecoveryDrillReport,
  fixture.evidence.safeRecoveryFinalEvidenceBundle,
 ];
 for(const document of documents) {
  delete fixture.evidenceFiles[document.path];
  document.sha256='';
 }
 fixture.controlPlaneEvidenceArtifacts=null;
 fixture.controlPlaneEvidenceAuthority=null;
 const report=assessMainnetReadiness(fixture);
 assert.equal(report.ready,false);
 assert.ok(report.blockers.some(blocker=>
  blocker.code==='evidence_controlPlaneEvidenceBundle_missing'));
 assert.ok(!report.blockers.some(blocker=>
  blocker.code==='control_plane_evidence_content_invalid'));
});

test('partial control-plane semantic authority remains fail-closed',()=>{
 const fixture=readyFixture();
 fixture.controlPlaneEvidenceArtifacts=null;
 fixture.controlPlaneEvidenceAuthority={bundleBytes:Buffer.from('{}')};
 const report=assessMainnetReadiness(fixture);
 assert.equal(report.ready,false);
 assert.ok(report.blockers.some(blocker=>
  blocker.code==='control_plane_evidence_content_invalid'));
});

test('external audits and a zero-risk guarantee are not release requirements',()=>{
 for(const mode of ['closed-mainnet','real-funds']) {
  const fixture=readyFixture(mode);
  fixture.evidence.domConsensusAuditReports=[];
  fixture.evidence.privacyCircuitAuditReports=[];
  fixture.evidence.solidityAuditReports=[];
  Object.assign(fixture.requirements,{
   production_checkpoint_registry_independently_audited:false,
   issuance_commitment_relation_independently_reviewed:false,
   native_privacy_circuit_independently_audited:false,
   production_control_plane_configuration_independently_reviewed:false,
   absolute_zero_risk_guaranteed:false,
  });
  rebindRequirements(fixture);
  fixture.residualRiskReport=buildResidualRiskReport({
   releaseEvidence:fixture.evidence,releaseConfig:fixture.releaseConfig,
   requirements:fixture.requirements,draftSha256:fixture.residualRiskDraftSha256,
  });
  const residualRiskSha=createHash('sha256').update(
   serializeResidualRiskReport(fixture.residualRiskReport)).digest('hex');
  fixture.evidence.residualRiskAcceptanceReport.sha256=residualRiskSha;
  fixture.evidenceFiles[fixture.evidence.residualRiskAcceptanceReport.path]=residualRiskSha;
  fixture.releaseAssuranceAuthority.residualRiskReportBytes=
   Buffer.from(serializeResidualRiskReport(fixture.residualRiskReport));
  fixture.operatorIntent.residual_risk_acceptance.reportSha256=residualRiskSha;
  fixture.operatorIntent.residual_risk_acceptance.releaseEvidenceCommitment=
   releaseEvidenceCommitment(fixture.evidence);
  fixture.releaseAuthorizationApprovalObservation=releaseAuthorizationObservation(
   fixture.operatorIntent.residual_risk_acceptance,fixture.releaseConfig);
  const approvalBytes=Buffer.from(JSON.stringify(fixture.releaseAuthorizationApprovalObservation));
  fixture.approvalObservationAuthority.releaseAuthorization={bytes:approvalBytes,
   sha256:createHash('sha256').update(approvalBytes).digest('hex')};
  rebindReadinessDocuments(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,true,JSON.stringify(report.blockers));
  assert.equal(report.blockerCount,0);
 }
});

test('external assurance claims cannot re-enter readiness requirement lists or subgroups',()=>{
 const forbidden=/audit|audited|independently_reviewed|zero_risk/i;
 const forbiddenKnown=new Set([
  'production_checkpoint_registry_independently_audited',
  'issuance_commitment_relation_independently_reviewed',
  'native_privacy_circuit_independently_audited',
  'production_control_plane_configuration_independently_reviewed',
  'absolute_zero_risk_guaranteed',
 ]);
 const subgroups=[checkpointProofRequiredKeys,checkpointReceiptCompletionRequiredKeys,
  recoverableControlPlaneRequiredKeys,proofOperationalCapacityRequiredKeys,
  productionActivationAndPrivacyRequiredKeys,realFundsCustodyRequiredKeys,
  riscZeroAdapterRequiredKeys,riscZeroGuestInputRequiredKeys,finalizedBurnSubmissionRequiredKeys,
  ethereumFinalityPanicBoundaryRequiredKeys,nativeStatePanicBoundaryRequiredKeys,
  nativePrivacyPanicBoundaryRequiredKeys,proofProgramBoundaryRequiredKeys,
  nativeWalletPanicBoundaryRequiredKeys,preflightSnapshotRequiredKeys,
  renewableBurnClaimRequiredKeys,riscZeroConfigRequiredKeys];
 for(const keys of [readinessRequirementKeys('closed-mainnet'),
  readinessRequirementKeys('real-funds'),requiredKeys,...subgroups]) {
  assert.deepEqual(keys.filter(key=>forbiddenKnown.has(key)),[]);
  assert.deepEqual(keys.filter(key=>forbidden.test(key)),[]);
 }
 assert.throws(()=>readinessRequirementKeys('unsupported'),/mode/);
});

test('external-audit and zero-risk aliases cannot be reintroduced as readiness gates',()=>{
 const aliases=[
  'third_party_security_review_required','mandatory_independent_assurance',
  'external_security_assessment_must_pass','risk_free_release_guaranteed',
  'no_residual_risk_required','absolute_safety_risk_requirement',
 ];
 for(const alias of aliases) assert.equal(isForbiddenImpossibleAssuranceRequirement(alias),true,alias);
 assert.throws(()=>assertNoImpossibleAssuranceRequirements(['technical_gate',...aliases]),
  /impossible assurance requirement reintroduced/);
 for(const allowed of ['objective_security_validation_required_by_release_gate',
  'documented_residual_risk_acceptance_required_by_release_gate']) {
  assert.equal(isForbiddenImpossibleAssuranceRequirement(allowed),false,allowed);
 }
});

test('release policy explicitly keeps impossible assurances optional and residual risk accepted',()=>{
 for(const mutate of [
  fixture=>{fixture.operatorIntent.release_assurance_policy.external_audit_required_by_gate=true;},
  fixture=>{fixture.operatorIntent.release_assurance_policy.absolute_zero_risk_required_by_gate=true;},
  fixture=>{delete fixture.operatorIntent.release_assurance_policy.required_basis;},
 ]) {
  const fixture=readyFixture(); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(({code})=>code==='operator_release_assurance_policy_invalid'));
 }
});

test('checkpoint registry assurance booleans cannot replace their semantic evidence',()=>{
 const noBootstrap=readyFixture();
 noBootstrap.evidence.checkpointBootstrapRatificationReport=null;
 let report=assessMainnetReadiness(noBootstrap);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>
  blocker.code==='evidence_checkpointBootstrapRatificationReport_missing'));

 const noFinalizedEvent=readyFixture();
 noFinalizedEvent.evidence.checkpointFinalizedEventReport=null;
 report=assessMainnetReadiness(noFinalizedEvent);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>
  blocker.code==='evidence_checkpointFinalizedEventReport_missing'));

});

test('source, release-evidence commit and tag signatures use the operator-pinned key',()=>{
 const changes=[
  fixture=>{fixture.trustedReleaseSigningKeyFingerprint=null;},
  fixture=>{fixture.trustedReleaseSigningKeyFingerprint='a'.repeat(40);},
  fixture=>{fixture.trustedReleaseSigningKeyFingerprint='SHA256:short';},
  fixture=>{fixture.operatorIntent.release_signing_key_fingerprint='B'.repeat(40);},
  fixture=>{fixture.repositoryState.sourceCommitSignerFingerprint='B'.repeat(40);},
  fixture=>{fixture.repositoryState.releaseCommitSignerFingerprint='B'.repeat(40);},
  fixture=>{fixture.repositoryState.tagSignerFingerprint='B'.repeat(40);},
 ];
 for(const change of changes) {
  const fixture=readyFixture(); change(fixture);
  rebindRepositoryState(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,JSON.stringify(report.blockers));
  assert(report.blockers.some(blocker=>
   blocker.code==='trusted_release_signing_key_unconfigured'
    || blocker.code==='operator_release_signing_key_mismatch'
    || blocker.code==='source_commit_signer_mismatch'
    || blocker.code==='release_evidence_commit_signer_mismatch'
    || blocker.code==='source_tag_signer_mismatch'),JSON.stringify(report.blockers));
 }
});

test('a self-signed repository cannot replace the out-of-repository trust anchor',()=>{
 const fixture=readyFixture();
 const attacker='B'.repeat(40);
 fixture.operatorIntent.release_signing_key_fingerprint=attacker;
 fixture.repositoryState.sourceCommitSignerFingerprint=attacker;
 fixture.repositoryState.releaseCommitSignerFingerprint=attacker;
 fixture.repositoryState.tagSignerFingerprint=attacker;
 rebindRepositoryState(fixture);
 const report=assessMainnetReadiness(fixture);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>blocker.code==='operator_release_signing_key_mismatch'));
});

test('repository provenance is derived from the exact checker snapshot bytes',()=>{
 for(const mutate of [
  fixture=>{fixture.repositoryState.dirty=true;},
  fixture=>{fixture.repositoryStateAuthority.bytes=Buffer.from(JSON.stringify(
   {...fixture.repositoryState,dirty:true}));},
  fixture=>{fixture.repositoryStateAuthority=null;},
 ]) {
  const fixture=readyFixture(); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>blocker.code==='repository_state_authority_invalid'));
 }
});

test('production pin constants are derived from the exact contract source bytes',()=>{
 for(const mutate of [
  fixture=>{fixture.contractSource+='\n// substituted object\n';},
  fixture=>{fixture.contractSourceAuthority.reserveBytes=Buffer.concat([
   fixture.contractSourceAuthority.reserveBytes,Buffer.from('\n// substituted bytes\n')]);},
  fixture=>{fixture.checkpointContractSource+='\n// substituted object\n';},
  fixture=>{fixture.contractSourceAuthority.checkpointRegistryBytes=Buffer.concat([
   fixture.contractSourceAuthority.checkpointRegistryBytes,Buffer.from('\n// substituted bytes\n')]);},
  fixture=>{fixture.contractSourceAuthority=null;},
 ]) {
  const fixture=readyFixture(); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>blocker.code==='contract_source_authority_invalid'));
 }
});

test('compiled hash summaries are derived from exact artifact binding bytes',()=>{
 const cases=[
  ['reserve','compiledReserveRuntimeCodeHash'],
  ['checkpointRegistry','compiledCheckpointRegistryRuntimeCodeHash'],
  ['finalizedBurnVerifier','compiledVerifierRuntimeCodeHash'],
  ['checkpointVerifier','compiledCheckpointVerifierRuntimeCodeHash'],
 ];
 for(const [name,field] of cases) {
  const objectB=readyFixture(); objectB[field]=bytes32('ab');
  let report=assessMainnetReadiness(objectB);
  assert(report.blockers.some(blocker=>blocker.code==='compiled_artifact_authority_invalid'),name);
  const bytesB=readyFixture();
  const binding=JSON.parse(bytesB.compiledArtifactAuthority[name].bindingBytes.toString('utf8'));
  binding.runtimeCodeHash=bytes32('ab');
  bytesB.compiledArtifactAuthority[name].bindingBytes=Buffer.from(JSON.stringify(binding));
  report=assessMainnetReadiness(bytesB);
  assert(report.blockers.some(blocker=>blocker.code==='compiled_artifact_authority_invalid'),name);
 }
 const missing=readyFixture(); missing.compiledArtifactAuthority=null;
 const report=assessMainnetReadiness(missing);
 assert(report.blockers.some(blocker=>blocker.code==='compiled_artifact_authority_invalid'));
});

test('unconfigured artifact bindings retain component blockers without a false authority blocker',()=>{
 const fixture=readyFixture();
 fixture.compiledArtifactAuthority={};
 fixture.compiledArtifactBindingErrors={};
 for(const [name,runtime,initcode] of [
  ['reserve','compiledReserveRuntimeCodeHash','compiledReserveInitcodeHash'],
  ['checkpointRegistry','compiledCheckpointRegistryRuntimeCodeHash','compiledCheckpointRegistryInitcodeHash'],
  ['finalizedBurnVerifier','compiledVerifierRuntimeCodeHash','compiledVerifierInitcodeHash'],
  ['checkpointVerifier','compiledCheckpointVerifierRuntimeCodeHash','compiledCheckpointVerifierInitcodeHash'],
 ]) {
  fixture[runtime]=null; fixture[initcode]=null;
  fixture.compiledArtifactBindingErrors[name]='release constructor inputs are not configured';
 }
 const report=assessMainnetReadiness(fixture);
 assert(!report.blockers.some(blocker=>blocker.code==='compiled_artifact_authority_invalid'));
 for(const component of ['reserve','checkpoint_registry','verifier','checkpoint_verifier']) {
  assert(report.blockers.some(blocker=>blocker.code===`compiled_${component}_runtime_unavailable`));
  assert(report.blockers.some(blocker=>blocker.code===`compiled_${component}_initcode_unavailable`));
 }
});

test('effective production requirements are derived from their exact snapshot bytes',()=>{
 for(const mutate of [
  fixture=>{fixture.requirements.consensus_proof_implemented=false;},
  fixture=>{fixture.requirementsAuthority.bytes=Buffer.from(JSON.stringify(
   {...fixture.requirements,consensus_proof_implemented:false}));},
  fixture=>{fixture.requirementsAuthority=null;},
 ]) {
  const fixture=readyFixture(); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>blocker.code==='requirements_authority_invalid'));
 }
});

test('operator intent and release evidence are derived from their exact document bytes',()=>{
 for(const mutate of [
  fixture=>{fixture.operatorIntent.deploy_authorized=false;},
  fixture=>{fixture.readinessDocumentAuthority.operatorIntentBytes=Buffer.from(JSON.stringify(
   {...fixture.operatorIntent,deploy_authorized:false}));},
  fixture=>{fixture.evidence.releaseId='substituted-release';},
  fixture=>{fixture.readinessDocumentAuthority.releaseEvidenceBytes=Buffer.from(JSON.stringify(
   {...fixture.evidence,releaseId:'substituted-release'}));},
  fixture=>{fixture.readinessDocumentAuthority=null;},
 ]) {
  const fixture=readyFixture(); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>blocker.code==='readiness_document_authority_invalid'));
 }
});

test('release evidence rejects noncanonical or option-like source tags',()=>{
 for(const sourceTag of ['--raw','v1.0.0','../usdom-v1.0.0','usdom-v01.0.0','usdom-v1.0.0^{}']) {
  const fixture=readyFixture(); fixture.evidence.sourceTag=sourceTag;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,sourceTag);
  assert(report.blockers.some(blocker=>blocker.code==='source_tag_invalid'),sourceTag);
 }
});

test('release provenance requires a direct signed evidence-only child commit',()=>{
 const cases=[
  [fixture=>{fixture.repositoryState.sourceCommit='c'.repeat(40);},'source_commit_mismatch'],
  [fixture=>{fixture.repositoryState.head=fixture.evidence.sourceCommit;},
   'release_evidence_commit_missing'],
  [fixture=>{fixture.repositoryState.headParents=[];},'release_evidence_parent_mismatch'],
  [fixture=>{fixture.repositoryState.headParents=['a'.repeat(40),'c'.repeat(40)];},
   'release_evidence_parent_mismatch'],
  [fixture=>{fixture.repositoryState.headParents=['c'.repeat(40)];},
   'release_evidence_parent_mismatch'],
  [fixture=>{fixture.repositoryState.releaseEvidenceChanges=null;},
   'release_evidence_diff_missing'],
  [fixture=>{fixture.repositoryState.releaseEvidenceChanges.splice(0,1);},
   'release_evidence_metadata_diff_missing'],
  [fixture=>{fixture.repositoryState.releaseEvidenceChanges[0].status='A';},
   'release_evidence_diff_forbidden'],
  [fixture=>{fixture.repositoryState.releaseEvidenceChanges.push(
    {status:'M',path:'labs/usdom-reserve/contracts/USDOMProofReserve.sol'});},
   'release_evidence_diff_forbidden'],
  [fixture=>{fixture.repositoryState.releaseEvidenceChanges.push(
    {status:'D',path:'labs/usdom-reserve/evidence/report.txt'});},
   'release_evidence_diff_forbidden'],
  [fixture=>{fixture.repositoryState.releaseEvidenceChanges.push(
    {...fixture.repositoryState.releaseEvidenceChanges[0]});},
   'release_evidence_diff_forbidden'],
  [fixture=>{fixture.repositoryState.sourceCommitSignatureVerified=false;},
   'source_commit_signature_unverified'],
  [fixture=>{fixture.repositoryState.releaseCommitSignatureVerified=false;},
   'release_evidence_commit_signature_unverified'],
  [fixture=>{fixture.repositoryState.sourceAuthor='Other <other@example.com>';},
   'source_author_mismatch'],
  [fixture=>{fixture.repositoryState.sourceCommitter='Other <other@example.com>';},
   'source_committer_mismatch'],
  [fixture=>{fixture.repositoryState.releaseAuthor='Other <other@example.com>';},
   'release_evidence_author_mismatch'],
  [fixture=>{fixture.repositoryState.releaseCommitter='Other <other@example.com>';},
   'release_evidence_committer_mismatch'],
  [fixture=>{fixture.repositoryState.tagCommit=fixture.evidence.sourceCommit;},
   'source_tag_mismatch'],
 ];
 for(const [mutate,expected] of cases) {
  const fixture=readyFixture(); mutate(fixture);
  rebindRepositoryState(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,expected);
  assert(report.blockers.some(blocker=>blocker.code===expected),JSON.stringify(report.blockers));
 }
 const allowed=readyFixture();
 allowed.repositoryState.releaseEvidenceChanges.push(
  {status:'A',path:'labs/usdom-reserve/evidence/new-attestation.json'},
  {status:'M',path:'labs/usdom-reserve/evidence/existing-report.txt'});
 rebindRepositoryState(allowed);
 assert.equal(assessMainnetReadiness(allowed).ready,true);
});

test('release evidence and operator intent use exact unambiguous schemas',()=>{
 const cases=[
  [fixture=>{fixture.evidence.unexpected=true;},'release_evidence_schema_invalid'],
  [fixture=>{delete fixture.evidence.solidityAuditReports;},'release_evidence_schema_invalid'],
  [fixture=>{fixture.operatorIntent.unexpected=true;},'operator_intent_schema_invalid'],
  [fixture=>{delete fixture.operatorIntent.schema;},'operator_intent_schema_invalid'],
  [fixture=>{fixture.operatorIntent.undefined='none';},'operator_parameters_undefined_invalid'],
  [fixture=>{fixture.operatorIntent.undefined=[1];},'operator_parameters_undefined_invalid'],
  [fixture=>{fixture.operatorIntent.undefined=[''];},'operator_parameters_undefined_invalid'],
  [fixture=>{fixture.operatorIntent.undefined=['role','role'];},
   'operator_parameters_undefined_invalid'],
  [fixture=>{fixture.operatorIntent.residual_risk_acceptance.unexpected=true;},
   'operator_residual_risk_schema_invalid'],
  [fixture=>{fixture.evidence.reproducibleBuildReport.unexpected=true;},
   'evidence_reproducibleBuildReport_missing'],
  [fixture=>{fixture.evidence.trustedSetup.unexpected=true;},'trusted_setup_schema_invalid'],
  [fixture=>{fixture.evidence.checkpointTrustedSetup.unexpected=true;},
   'checkpoint_trusted_setup_schema_invalid'],
  [fixture=>{fixture.evidence.controlPlane.unexpected=true;},'control_plane_schema_invalid'],
  [fixture=>{fixture.evidence.controlPlane.governance.unexpected=true;},
   'control_plane_governance_schema_invalid'],
 ];
 for(const [mutate,expected] of cases) {
  const fixture=readyFixture(); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,expected);
  assert(report.blockers.some(blocker=>blocker.code===expected),JSON.stringify(report.blockers));
 }
});

test('production release config uses the exact schema and native timing policy',()=>{
 const cases=[
  [fixture=>{fixture.releaseConfig.unexpected=true;},'release_config_schema_invalid'],
  [fixture=>{delete fixture.releaseConfig.ethereumGenesisValidatorsRoot;},
   'release_config_schema_invalid'],
  [fixture=>{fixture.releaseConfig.ethereumChainId=1;},'release_wrong_chain'],
  [fixture=>{fixture.releaseConfig.ethereumGenesisValidatorsRoot=bytes32('99');},
   'release_ethereum_genesis_validators_root_invalid'],
  [fixture=>{fixture.releaseConfig.nativeEthereumTrustedCheckpoint=bytes32('00');},
   'release_native_ethereum_trusted_checkpoint_invalid'],
  [fixture=>{fixture.releaseConfig.realFundsAuthorized='false';},
   'release_real_funds_authorization_invalid'],
  [fixture=>{fixture.releaseConfig.governanceOwners=null;},
   'release_governanceOwners_missing'],
  [fixture=>{fixture.releaseConfig.governanceOwners[2]=fixture.releaseConfig.governanceOwners[1];},
   'release_governance_owners_invalid'],
  [fixture=>{fixture.releaseConfig.governanceOwners[0]=
    '0x0000000000000000000000000000000000000011';},
   'release_governance_owners_invalid'],
  [fixture=>{fixture.releaseConfig.checkpointGuardianOwners[0]=fixture.releaseConfig.governance;},
   'release_checkpointGuardian_owners_invalid'],
  [fixture=>{fixture.releaseConfig.guardianOwners[0]=fixture.releaseConfig.governanceImplementation;},
   'release_guardian_owners_invalid'],
  [fixture=>{fixture.releaseConfig.checkpointGuardianOwners[0]=SAFE_MAINNET_IDENTITY.fallbackHandler;},
   'release_checkpointGuardian_owners_invalid'],
  [fixture=>{fixture.releaseConfig.checkpointVerifier=fixture.releaseConfig.verifier;},
   'release_contract_identity_collision'],
  [fixture=>{fixture.releaseConfig.guardianImplementation=address(99);},
   'release_safe_implementation_identity_invalid'],
  [fixture=>{fixture.releaseConfig.guardianImplementationCodeHash=bytes32('99');},
   'release_safe_implementation_identity_invalid'],
  [fixture=>{fixture.releaseConfig.nativeRelaySafetyMarginSeconds=3600;},
   'release_native_burn_timing_invalid'],
  [fixture=>{fixture.releaseConfig.nativeRelaySafetyMarginSeconds='03600';},
   'release_native_burn_timing_invalid'],
  [fixture=>{fixture.releaseConfig.nativeRelaySafetyMarginSeconds='1799';},
   'release_native_burn_timing_invalid'],
  [fixture=>{fixture.releaseConfig.nativeMaxEthereumAnchorAgeSeconds='0';},
   'release_native_burn_timing_invalid'],
  [fixture=>{fixture.releaseConfig.nativeMaxDomClockLeadSeconds='119';},
   'release_native_burn_timing_invalid'],
  [fixture=>{fixture.releaseConfig.nativeRelaySafetyMarginSeconds='600000';},
   'release_native_burn_timing_invalid'],
  [fixture=>{fixture.releaseConfig.nativeMaxDomClockLeadSeconds=(1n<<64n).toString();},
   'release_native_burn_timing_invalid'],
 ];
 for(const [mutate,expected] of cases) {
  const fixture=readyFixture(); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,expected);
  assert(report.blockers.some(blocker=>blocker.code===expected),JSON.stringify(report.blockers));
 }
});

test('Safe proxies share the pinned singleton without allowing an operational-role collision',()=>{
 const fixture=readyFixture();
 assert.equal(fixture.releaseConfig.governanceImplementation,SAFE_MAINNET_IDENTITY.singleton);
 assert.equal(fixture.releaseConfig.guardianImplementation,SAFE_MAINNET_IDENTITY.singleton);
 assert.equal(fixture.releaseConfig.checkpointGuardianImplementation,SAFE_MAINNET_IDENTITY.singleton);
 assert.equal(assessMainnetReadiness(fixture).ready,true);
 fixture.releaseConfig.verifier=SAFE_MAINNET_IDENTITY.singleton;
 const report=assessMainnetReadiness(fixture);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>blocker.code==='release_contract_identity_collision'));
});

test('native runtime manifest, checker output, key and attestations form one release identity',()=>{
 const cases=[
  [fixture=>{fixture.evidence.nativeRuntimeManifest=null;},
   'evidence_nativeRuntimeManifest_missing'],
  [fixture=>{fixture.evidence.nativeRuntimeSpendVerifyingKeyArtifact=null;},
   'evidence_nativeRuntimeSpendVerifyingKeyArtifact_missing'],
  [fixture=>{fixture.nativeRuntimeValidation=null;},'native_runtime_manifest_validation_missing'],
  [fixture=>{fixture.nativeRuntimeValidation.extra='value';},
   'native_runtime_manifest_validation_missing'],
  [fixture=>{fixture.nativeRuntimeValidation.manifest_sha256='99'.repeat(32);},
   'native_runtime_manifest_hash_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.network='Testnet';},
   'native_runtime_manifest_network_invalid'],
  [fixture=>{fixture.nativeRuntimeValidation.network_magic='00000000';},
   'native_runtime_network_magic_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.activation_schedule_commitment='99'.repeat(32);},
   'native_runtime_activation_schedule_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.ethereum_checkpoint_policy_hash='00'.repeat(32);},
   'native_runtime_ethereum_checkpoint_policy_hash_invalid'],
  [fixture=>{fixture.nativeRuntimeValidation.ethereum_trusted_checkpoint='99'.repeat(32);},
   'native_runtime_ethereum_trusted_checkpoint_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.ethereum_fork_fulu_epoch='411391';},
   'native_runtime_ethereum_fork_fulu_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.ethereum_fork_electra_version='99000000';},
   'native_runtime_ethereum_fork_electra_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.checkpoint_registry=address(99).slice(2).toLowerCase();},
   'native_runtime_checkpoint_registry_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.checkpoint_runtime_code_hash='99'.repeat(32);},
   'native_runtime_checkpoint_codehash_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.checkpoint_config_storage_slot='01'.repeat(32);},
   'native_runtime_checkpoint_config_slot_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.checkpoint_config_hash='99'.repeat(32);},
   'native_runtime_checkpoint_config_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.checkpoint_bridge_domain='99'.repeat(32);},
   'native_runtime_checkpoint_domain_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.deposit_reserve=address(98).slice(2).toLowerCase();},
   'native_runtime_deposit_reserve_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.deposit_runtime_code_hash='98'.repeat(32);},
   'native_runtime_deposit_codehash_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.deposit_bridge_domain='98'.repeat(32);},
   'native_runtime_deposit_domain_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.deposit_max_amount='1';},
   'native_runtime_deposit_max_amount_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.withdrawal_delay_secs='1';},
   'native_runtime_withdrawal_delay_secs_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.min_execution_window_secs='3599';},
   'native_runtime_certificate_window_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.spend_verifying_key_sha256='99'.repeat(32);},
   'native_runtime_spend_verifying_key_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.randomx_receipt_image_id='99'.repeat(32);},
   'native_runtime_checkpoint_randomx_image_id_mismatch'],
  [fixture=>{fixture.nativeRuntimeValidation.randomx_receipt_image_id='00'.repeat(32);},
   'native_runtime_randomx_receipt_image_id_invalid'],
  [fixture=>{
    fixture.nativeRuntimeValidation.candidate_v2_first_height='disabled';
    fixture.nativeRuntimeValidation.checkpoint_interval_blocks='disabled';
    fixture.nativeRuntimeValidation.checkpoint_confirmation_depth_blocks='disabled';
    fixture.nativeRuntimeValidation.randomx_receipt_image_id='disabled';
  },'native_runtime_candidate_v2_required'],
  [fixture=>{fixture.nativeRuntimeValidation.checkpoint_interval_blocks='359';},
   'native_runtime_checkpoint_schedule_mismatch'],
  [fixture=>{fixture.nativePrivacyTrustedSetupAttestation.subjectCommitment=bytes32('a1');},
   'native_privacy_trusted_setup_subject_mismatch'],
 ];
 for(const [mutate,expected] of cases) {
  const fixture=readyFixture(); mutate(fixture);
  const attestationBytes=Buffer.from(JSON.stringify(fixture.nativePrivacyTrustedSetupAttestation));
  fixture.nativeReleaseAttestationAuthority.nativePrivacyTrustedSetupBytes=attestationBytes;
  fixture.evidence.nativePrivacyTrustedSetupAttestationReport.sha256=
   createHash('sha256').update(attestationBytes).digest('hex');
  fixture.evidenceFiles[fixture.evidence.nativePrivacyTrustedSetupAttestationReport.path]=
   fixture.evidence.nativePrivacyTrustedSetupAttestationReport.sha256;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,expected);
  assert(report.blockers.some(blocker=>blocker.code===expected),JSON.stringify(report.blockers));
 }
});

test('residual-risk acceptance is explicit and bound to the exact release',()=>{
 const changes=[
  fixture=>{delete fixture.operatorIntent.residual_risk_acceptance;},
  fixture=>{fixture.operatorIntent.residual_risk_acceptance.accepted=false;},
  fixture=>{fixture.operatorIntent.residual_risk_acceptance.releaseId='release-2';},
  fixture=>{fixture.operatorIntent.residual_risk_acceptance.sourceCommit='b'.repeat(40);},
  fixture=>{fixture.operatorIntent.residual_risk_acceptance.reserveConfigHash=bytes32('99');},
  fixture=>{fixture.operatorIntent.residual_risk_acceptance.checkpointRegistryConfigHash=bytes32('99');},
  fixture=>{fixture.operatorIntent.residual_risk_acceptance.reportSha256='2'.repeat(64);},
  fixture=>{fixture.operatorIntent.residual_risk_acceptance.acceptingAuthority=address(5);},
  fixture=>{fixture.operatorIntent.residual_risk_acceptance.acceptingAuthority='invalid';},
  fixture=>{fixture.operatorIntent.residual_risk_acceptance.acceptedAt='0';},
  fixture=>{fixture.operatorIntent.residual_risk_acceptance.acceptedAt='01';},
  fixture=>{fixture.operatorIntent.residual_risk_acceptance.acceptedAt=(1n<<64n).toString();},
  fixture=>{fixture.operatorIntent.residual_risk_acceptance.acceptedAt='9'.repeat(100000);},
 ];
 for(const change of changes) {
  const fixture=readyFixture(); change(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,JSON.stringify(report.blockers));
  assert(report.blockers.some(blocker=>blocker.code.startsWith('operator_residual_risk_')),
   JSON.stringify(report.blockers));
 }
});

test('production authorization requires one exact finalized governance approval',()=>{
 const cases=[
  [fixture=>{fixture.operatorIntent.residual_risk_acceptance.productionApproved=false;},
   'operator_release_authorization_scope_mismatch'],
  [fixture=>{fixture.operatorIntent.residual_risk_acceptance.deployAuthorized=false;},
   'operator_release_authorization_scope_mismatch'],
  [fixture=>{fixture.operatorIntent.residual_risk_acceptance.realFundsAuthorized=false;},
   'operator_release_authorization_scope_mismatch'],
  [fixture=>{fixture.operatorIntent.residual_risk_acceptance.signature='0x';},
   'operator_release_authorization_signature_invalid'],
  [fixture=>{fixture.releaseAuthorizationApprovalObservation=null;},
   'release_authorization_approval_snapshot_missing'],
  [fixture=>{fixture.releaseAuthorizationApprovalObservation.chainId='2';},
   'release_authorization_approval_chain_mismatch'],
  [fixture=>{fixture.releaseAuthorizationApprovalObservation.finalizedBlockNumber='9'.repeat(100000);},
   'release_authorization_approval_block_invalid'],
  [fixture=>{fixture.releaseAuthorizationApprovalObservation.snapshotBlockHashAfter=bytes32('71');},
   'release_authorization_approval_snapshot_changed'],
  [fixture=>{fixture.releaseAuthorizationApprovalObservation.governance=address(5);},
   'release_authorization_approval_governance_mismatch'],
  [fixture=>{fixture.releaseAuthorizationApprovalObservation.governanceCodeHash=bytes32('51');},
   'release_authorization_approval_governance_codehash_mismatch'],
  [fixture=>{fixture.releaseAuthorizationApprovalObservation.rpcConsensus.sourceSetCommitment=bytes32('51');},
   'release_authorization_approval_rpc_consensus_invalid'],
  [fixture=>{fixture.releaseAuthorizationApprovalObservation.approvals.releaseAuthorization.digest=
    bytes32('01');},'release_authorization_digest_mismatch'],
  [fixture=>{fixture.releaseAuthorizationApprovalObservation.approvals.releaseAuthorization.valid=false;},
   'release_authorization_eip1271_rejected'],
  [fixture=>{fixture.releaseAuthorizationApprovalObservation.finalizedBlockTimestamp=
    (BigInt(fixture.operatorIntent.residual_risk_acceptance.acceptedAt)+86401n).toString();},
   'release_authorization_stale'],
  [fixture=>{fixture.operatorIntent.residual_risk_acceptance.acceptedAt='1792492901';
    fixture.releaseAuthorizationApprovalObservation.approvals.releaseAuthorization.digest=
      releaseAuthorizationDigest(fixture.operatorIntent.residual_risk_acceptance,
        fixture.releaseConfig);},'release_authorization_after_finalized_snapshot'],
 ];
 for(const [mutate,code] of cases) {
  const fixture=readyFixture(); mutate(fixture);
  const bytes=Buffer.from(JSON.stringify(fixture.releaseAuthorizationApprovalObservation));
  fixture.approvalObservationAuthority.releaseAuthorization={bytes,
   sha256:createHash('sha256').update(bytes).digest('hex')};
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,code);
  assert(report.blockers.some(blocker=>blocker.code===code),JSON.stringify(report.blockers));
 }
});
test('EIP-1271 approval snapshots reject objects and bytes detached from their descriptors',()=>{
 for(const [objectField,authorityField,code] of [
  ['releaseAuthorizationApprovalObservation','releaseAuthorization',
   'release_authorization_approval_snapshot_authority_invalid'],
  ['nativeAttestationApprovalObservation','nativeAttestations',
   'native_attestation_approval_snapshot_authority_invalid'],
 ]) {
  const objectOnly=readyFixture();
  objectOnly[objectField]={...objectOnly[objectField],finalizedBlockNumber:'22000001'};
  let report=assessMainnetReadiness(objectOnly);
  assert(report.blockers.some(blocker=>blocker.code===code),`${objectField} object B`);

  const bytesOnly=readyFixture();
  bytesOnly[objectField]={...bytesOnly[objectField],finalizedBlockNumber:'22000001'};
  bytesOnly.approvalObservationAuthority[authorityField]={
   ...bytesOnly.approvalObservationAuthority[authorityField],
   bytes:Buffer.from(JSON.stringify(bytesOnly[objectField])),
  };
  report=assessMainnetReadiness(bytesOnly);
  assert(report.blockers.some(blocker=>blocker.code===code),`${objectField} bytes B`);
 }
});

test('independent evidence slots reject duplicate paths and duplicate file content',()=>{
 const duplicatePath=readyFixture();
 duplicatePath.evidence.operationsReviewReport={...duplicatePath.evidence.mainnetForkRehearsalReport};
 let report=assessMainnetReadiness(duplicatePath);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>blocker.code==='duplicate_evidence_document'));

 const duplicateContent=readyFixture();
 const duplicateHash=duplicateContent.evidence.mainnetForkRehearsalReport.sha256;
 duplicateContent.evidence.operationsReviewReport.sha256=duplicateHash;
 duplicateContent.evidenceFiles[duplicateContent.evidence.operationsReviewReport.path]=duplicateHash;
 report=assessMainnetReadiness(duplicateContent);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>blocker.code==='duplicate_evidence_content'));
});

test('release evidence documents reject the reserved all-zero SHA-256 sentinel',()=>{
 const fixture=readyFixture();
 const target=fixture.evidence.operationsReviewReport;
 target.sha256='0'.repeat(64);
 fixture.evidenceFiles[target.path]=target.sha256;
 const report=assessMainnetReadiness(fixture);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>blocker.code==='evidence_operationsReviewReport_missing'));
});

test('both RISC Zero adapters bind the same upstream ceremony evidence',()=>{
 const fixture=readyFixture();
 fixture.evidence.checkpointTrustedSetup.transcript={
  path:'evidence/other-risc0-ceremony.txt',sha256:documentSha('evidence/other-risc0-ceremony.txt'),
 };
 fixture.evidenceFiles['evidence/other-risc0-ceremony.txt']=
  fixture.evidence.checkpointTrustedSetup.transcript.sha256;
 const report=assessMainnetReadiness(fixture);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>blocker.code==='risc0_trusted_setup_evidence_mismatch'));
});

test('both RISC Zero adapters may reference the same canonical verifying-key artifact',()=>{
 const fixture=readyFixture();
 assert.deepEqual(fixture.evidence.checkpointVerifyingKeyArtifact,
  fixture.evidence.verifyingKeyArtifact);
 assert.equal(assessMainnetReadiness(fixture).ready,true);
 const substituted=readyFixture();
 substituted.evidence.checkpointVerifyingKeyArtifact={
  path:'evidence/checkpoint-verifying-key.bin',
  sha256:documentSha('evidence/checkpoint-verifying-key.bin'),
 };
 substituted.evidenceFiles['evidence/checkpoint-verifying-key.bin']=
  substituted.evidence.checkpointVerifyingKeyArtifact.sha256;
 const report=assessMainnetReadiness(substituted);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>
  blocker.code==='checkpoint_verifier_config_checkpointVerifyingKeyArtifact_mismatch'));
});

test('release evidence accepts only canonical relative POSIX paths',()=>{
 for(const path of [
  '/evidence/build.txt','../evidence/build.txt','evidence/../build.txt',
  'evidence/./build.txt','evidence//build.txt','evidence\\build.txt','',
 ]) {
  const fixture=readyFixture();
  fixture.evidence.reproducibleBuildReport.path=path;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,JSON.stringify(report.blockers));
  assert(report.blockers.some(blocker=>blocker.code==='evidence_reproducibleBuildReport_missing'),path);
 }
});

test('malformed optional review collections fail closed without throwing',()=>{
 for(const field of ['domConsensusAuditReports','privacyCircuitAuditReports','solidityAuditReports']) {
  for(const value of [{invalid:true},'not-an-array',42]) {
   const fixture=readyFixture(); fixture.evidence[field]=value;
   const report=assessMainnetReadiness(fixture);
   assert.equal(report.ready,false,field);
   assert(report.blockers.some(blocker=>blocker.code===`evidence_${field}_invalid`),field);
  }
 }
});

test('every checkpoint proof completion requirement independently fails closed',()=>{
 for(const key of checkpointProofRequiredKeys) {
  const fixture=readyFixture();
  fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
});

test('every authoritative checkpoint receipt and capacity boundary independently fails closed',()=>{
 for(const key of checkpointReceiptCompletionRequiredKeys) {
  const fixture=readyFixture();
  fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
});

test('a positive guest execution cannot replace EVM receipt verification',()=>{
 const fixture=readyFixture();
 fixture.requirements.production_finalized_burn_risc0_evm_receipt_verifier_implemented=false;
 const report=assessMainnetReadiness(fixture);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>
  blocker.code==='requirement_production_finalized_burn_risc0_evm_receipt_verifier_implemented'));
});

test('every finalized-burn EVM handoff and closed lifecycle requirement independently fails closed',()=>{
 for(const key of finalizedBurnSubmissionRequiredKeys) {
  const fixture=readyFixture(); fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
});

test('every end-to-end proof capacity and EVM gas boundary independently fails closed',()=>{
 for(const key of proofOperationalCapacityRequiredKeys) {
  const fixture=readyFixture(); fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
});

test('every production activation and privacy-key ceremony boundary independently fails closed',()=>{
 for(const key of productionActivationAndPrivacyRequiredKeys) {
  const fixture=readyFixture(); fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
});

test('every real-funds wallet custody and recovery boundary independently fails closed',()=>{
 for(const key of realFundsCustodyRequiredKeys) {
  const fixture=readyFixture('real-funds'); fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
});

test('every recoverable production control-plane package boundary independently fails closed',()=>{
 for(const key of recoverableControlPlaneRequiredKeys) {
  const fixture=readyFixture();
  fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
});

test('native privacy and scheduled-runtime attestations are exact and release-bound',()=>{
 const mutations=[
  [fixture=>{fixture.evidence.nativePrivacyTrustedSetupAttestationReport=null;},
   'evidence_nativePrivacyTrustedSetupAttestationReport_missing'],
  [fixture=>{fixture.nativePrivacyTrustedSetupAttestation=null;},
   'native_privacy_trusted_setup_attestation_unreadable'],
  [fixture=>{fixture.nativePrivacyTrustedSetupAttestation.extra=true;},
   'native_privacy_trusted_setup_attestation_unreadable'],
  [fixture=>{fixture.nativePrivacyTrustedSetupAttestation.schema=2;},
   'native_privacy_trusted_setup_schema_invalid'],
  [fixture=>{fixture.nativePrivacyTrustedSetupAttestation.kind='wrong';},
   'native_privacy_trusted_setup_kind_mismatch'],
  [fixture=>{fixture.nativePrivacyTrustedSetupAttestation.releaseId='other';},
   'native_privacy_trusted_setup_release_mismatch'],
  [fixture=>{fixture.nativePrivacyTrustedSetupAttestation.sourceCommit='b'.repeat(40);},
   'native_privacy_trusted_setup_commit_mismatch'],
  [fixture=>{fixture.nativePrivacyTrustedSetupAttestation.reserveConfigHash=bytes32('b1');},
   'native_privacy_trusted_setup_reserveConfigHash_mismatch'],
  [fixture=>{fixture.nativePrivacyTrustedSetupAttestation.checkpointRegistryConfigHash=bytes32('b2');},
   'native_privacy_trusted_setup_checkpointRegistryConfigHash_mismatch'],
  [fixture=>{fixture.nativePrivacyTrustedSetupAttestation.completedAt='01';},
   'native_privacy_trusted_setup_completed_at_invalid'],
  [fixture=>{fixture.nativePrivacyTrustedSetupAttestation.approvedBy=address(5);},
   'native_privacy_trusted_setup_approver_mismatch'],
  [fixture=>{fixture.nativePrivacyTrustedSetupAttestation.signature='0x';},
   'native_privacy_trusted_setup_signature_invalid'],
  [fixture=>{fixture.nativePrivacyTrustedSetupAttestation.subjectCommitment=bytes32('00');},
   'native_privacy_trusted_setup_subject_invalid'],
  [fixture=>{fixture.nativeScheduledRuntimeActivationAttestation.subjectCommitment=bytes32('b3');},
   'native_scheduled_runtime_activation_subject_mismatch'],
 ];
 for(const [mutate,code] of mutations) {
  const fixture=readyFixture(); mutate(fixture);
  for(const [objectField,bytesField,evidenceField] of [
   ['nativePrivacyTrustedSetupAttestation','nativePrivacyTrustedSetupBytes',
    'nativePrivacyTrustedSetupAttestationReport'],
   ['nativeScheduledRuntimeActivationAttestation','nativeScheduledRuntimeActivationBytes',
    'nativeScheduledRuntimeActivationAttestationReport'],
  ]) {
   const document=fixture.evidence[evidenceField];
   if(!document) continue;
   const bytes=Buffer.from(JSON.stringify(fixture[objectField]));
   fixture.nativeReleaseAttestationAuthority[bytesField]=bytes;
   document.sha256=createHash('sha256').update(bytes).digest('hex');
   fixture.evidenceFiles[document.path]=document.sha256;
  }
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,code);
  assert(report.blockers.some(blocker=>blocker.code===code),code);
 }
});

test('native release attestations reject coordinated object B and bytes B under descriptor A',()=>{
 const cases=[
  ['nativePrivacyTrustedSetupAttestation','nativePrivacyTrustedSetupBytes',
   'native_privacy_trusted_setup_attestation_authority_invalid','closed-mainnet'],
  ['nativeScheduledRuntimeActivationAttestation','nativeScheduledRuntimeActivationBytes',
   'native_scheduled_runtime_activation_attestation_authority_invalid','closed-mainnet'],
  ['nativeWalletCustodyAttestation','nativeWalletCustodyBytes',
   'native_wallet_custody_attestation_authority_invalid','real-funds'],
  ['nativeWalletRecoveryAttestation','nativeWalletRecoveryBytes',
   'native_wallet_recovery_attestation_authority_invalid','real-funds'],
 ];
 for(const [field,bytesField,code,mode] of cases) {
  const fixture=readyFixture(mode);
  fixture[field]={...fixture[field],completedAt:String(BigInt(fixture[field].completedAt)+1n)};
  fixture.nativeReleaseAttestationAuthority[bytesField]=Buffer.from(JSON.stringify(fixture[field]));
  const report=assessMainnetReadiness(fixture);
  assert(report.blockers.some(blocker=>blocker.code===code),code);
 }
});

test('native attestation approvals require one exact finalized EIP-1271 snapshot',()=>{
 const mutations=[
  [fixture=>{fixture.nativeAttestationApprovalObservation=null;},
   'native_attestation_approval_snapshot_missing'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.extra=true;},
   'native_attestation_approval_snapshot_missing'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.chainId=1;},
   'native_attestation_approval_chain_mismatch'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.finalizedBlockNumber='022000000';},
   'native_attestation_approval_block_number_invalid'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.finalizedBlockTimestamp='01792492900';},
   'native_attestation_approval_block_timestamp_invalid'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.finalizedBlockTimestamp='9'.repeat(100000);},
   'native_attestation_approval_block_timestamp_invalid'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.finalizedBlockHash=bytes32('00');},
   'native_attestation_approval_block_hash_invalid'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.snapshotBlockHashAfter=bytes32('71');},
   'native_attestation_approval_snapshot_changed'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.governance=address(5);},
   'native_attestation_approval_governance_mismatch'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.governanceCodeHash=bytes32('51');},
   'native_attestation_approval_governance_codehash_mismatch'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.rpcConsensus.sources.pop();},
   'native_attestation_approval_rpc_consensus_invalid'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.approvals.extra={digest:bytes32('01'),valid:true};},
   'native_attestation_approval_set_mismatch'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.approvals.nativePrivacyTrustedSetup.extra=true;},
   'native_attestation_nativePrivacyTrustedSetup_approval_invalid'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.approvals.nativePrivacyTrustedSetup.digest=bytes32('01');},
   'native_attestation_nativePrivacyTrustedSetup_digest_mismatch'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.approvals.nativePrivacyTrustedSetup.valid=false;},
   'native_attestation_nativePrivacyTrustedSetup_eip1271_rejected'],
  [fixture=>{fixture.nativePrivacyTrustedSetupAttestation.subjectCommitment=bytes32('a4');},
   'native_attestation_nativePrivacyTrustedSetup_digest_mismatch'],
  [fixture=>{fixture.nativePrivacyTrustedSetupAttestation.completedAt='1792492901';
    fixture.nativeAttestationApprovalObservation.approvals.nativePrivacyTrustedSetup.digest=
      nativeReleaseAttestationDigest(fixture.nativePrivacyTrustedSetupAttestation,fixture.releaseConfig);},
   'native_attestation_nativePrivacyTrustedSetup_completed_after_finalized_snapshot'],
  [fixture=>{fixture.nativePrivacyTrustedSetupAttestation.completedAt='9'.repeat(100000);},
   'native_privacy_trusted_setup_completed_at_invalid'],
 ];
 for(const [mutate,code] of mutations) {
  const fixture=readyFixture(); mutate(fixture);
  const attestationBytes=Buffer.from(JSON.stringify(fixture.nativePrivacyTrustedSetupAttestation));
  fixture.nativeReleaseAttestationAuthority.nativePrivacyTrustedSetupBytes=attestationBytes;
  fixture.evidence.nativePrivacyTrustedSetupAttestationReport.sha256=
   createHash('sha256').update(attestationBytes).digest('hex');
  fixture.evidenceFiles[fixture.evidence.nativePrivacyTrustedSetupAttestationReport.path]=
   fixture.evidence.nativePrivacyTrustedSetupAttestationReport.sha256;
  const bytes=Buffer.from(JSON.stringify(fixture.nativeAttestationApprovalObservation));
  fixture.approvalObservationAuthority.nativeAttestations={bytes,
   sha256:createHash('sha256').update(bytes).digest('hex')};
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,code);
  assert(report.blockers.some(blocker=>blocker.code===code),code);
 }
});

test('absent release config hash pins do not claim native attestation mismatches',()=>{
 const absent=readyFixture(); absent.releaseConfig.reserveConfigHash=null;
 absent.releaseConfig.checkpointRegistryConfigHash=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_reserveConfigHash_missing'));
 assert(report.blockers.some(blocker=>
  blocker.code==='release_checkpointRegistryConfigHash_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code.startsWith('native_')&&(blocker.code.endsWith('_reserveConfigHash_mismatch')
   ||blocker.code.endsWith('_checkpointRegistryConfigHash_mismatch'))),JSON.stringify(report.blockers));

 const present=readyFixture();
 present.nativePrivacyTrustedSetupAttestation.reserveConfigHash=bytes32('99');
 const bytes=Buffer.from(JSON.stringify(present.nativePrivacyTrustedSetupAttestation));
 present.nativeReleaseAttestationAuthority.nativePrivacyTrustedSetupBytes=bytes;
 const descriptor=present.evidence.nativePrivacyTrustedSetupAttestationReport;
 descriptor.sha256=createHash('sha256').update(bytes).digest('hex');
 present.evidenceFiles[descriptor.path]=descriptor.sha256;
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='native_privacy_trusted_setup_reserveConfigHash_mismatch'));
});

test('absent release config hash pins do not claim residual-risk mismatches',()=>{
 const absent=readyFixture(); absent.releaseConfig.reserveConfigHash=null;
 absent.releaseConfig.checkpointRegistryConfigHash=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_reserveConfigHash_missing'));
 assert(report.blockers.some(blocker=>
  blocker.code==='release_checkpointRegistryConfigHash_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_reserveConfigHash_mismatch'
   ||blocker.code==='operator_residual_risk_checkpointRegistryConfigHash_mismatch'));

 const present=readyFixture();
 present.operatorIntent.residual_risk_acceptance.reserveConfigHash=bytes32('99');
 present.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(present.operatorIntent));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_reserveConfigHash_mismatch'));
});

test('absent governance pin does not claim residual-risk authority failure',()=>{
 const absent=readyFixture(); absent.releaseConfig.governance=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_governance_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_authority_mismatch'
   ||blocker.code==='operator_residual_risk_authority_invalid'));

 const present=readyFixture();
 present.operatorIntent.residual_risk_acceptance.acceptingAuthority=address(5);
 present.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(present.operatorIntent));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_authority_mismatch'));
});

test('absent release ID does not claim residual-risk release mismatch',()=>{
 const absent=readyFixture(); absent.evidence.releaseId=null;
 absent.readinessDocumentAuthority.releaseEvidenceBytes=Buffer.from(JSON.stringify(absent.evidence));
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_evidence_unconfigured'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_release_mismatch'));

 const present=readyFixture();
 present.operatorIntent.residual_risk_acceptance.releaseId='another-release';
 present.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(present.operatorIntent));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_release_mismatch'));
});

test('absent source commit does not claim residual-risk commit mismatch',()=>{
 const absent=readyFixture(); absent.evidence.sourceCommit=null;
 absent.readinessDocumentAuthority.releaseEvidenceBytes=Buffer.from(JSON.stringify(absent.evidence));
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='source_commit_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_commit_mismatch'));

 const present=readyFixture();
 present.operatorIntent.residual_risk_acceptance.sourceCommit='b'.repeat(40);
 present.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(present.operatorIntent));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_commit_mismatch'));
});

test('absent source tag does not claim residual-risk tag mismatch',()=>{
 const absent=readyFixture(); absent.evidence.sourceTag=null;
 absent.readinessDocumentAuthority.releaseEvidenceBytes=Buffer.from(JSON.stringify(absent.evidence));
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='source_tag_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_tag_mismatch'));

 const present=readyFixture();
 present.operatorIntent.residual_risk_acceptance.sourceTag='usdom-v9.9.9';
 present.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(present.operatorIntent));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_tag_mismatch'));
});

test('absent release evidence base does not claim residual-risk commitment mismatch',()=>{
 const absent=readyFixture(); absent.evidence.sourceTag=null;
 absent.readinessDocumentAuthority.releaseEvidenceBytes=Buffer.from(JSON.stringify(absent.evidence));
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='source_tag_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_evidence_commitment_mismatch'));

 const present=readyFixture();
 present.operatorIntent.residual_risk_acceptance.releaseEvidenceCommitment=bytes32('99');
 present.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(present.operatorIntent));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_evidence_commitment_mismatch'));
});

test('absent residual-risk report does not claim acceptance report mismatch',()=>{
 const absent=readyFixture(); absent.evidence.residualRiskAcceptanceReport=null;
 absent.readinessDocumentAuthority.releaseEvidenceBytes=Buffer.from(JSON.stringify(absent.evidence));
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='evidence_residualRiskAcceptanceReport_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_report_mismatch'));

 const present=readyFixture();
 present.operatorIntent.residual_risk_acceptance.reportSha256='2'.repeat(64);
 present.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(present.operatorIntent));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_report_mismatch'));
});

test('noncanonical residual-risk acceptance does not run derived authorization checks',()=>{
 const invalid=readyFixture(); delete invalid.operatorIntent.residual_risk_acceptance.reportSha256;
 invalid.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(invalid.operatorIntent));
 const report=assessMainnetReadiness(invalid);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_schema_invalid'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_report_mismatch'
   ||blocker.code==='operator_release_authorization_invalid'));

 const present=readyFixture();
 present.operatorIntent.residual_risk_acceptance.reportSha256='2'.repeat(64);
 present.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(present.operatorIntent));
 const divergent=assessMainnetReadiness(present);
 assert(divergent.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_report_mismatch'));
});

test('noncanonical operator intent does not run derived acceptance checks',()=>{
 const invalid=readyFixture(); delete invalid.operatorIntent.production_approved;
 invalid.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(invalid.operatorIntent));
 let report=assessMainnetReadiness(invalid);
 assert(report.blockers.some(blocker=>blocker.code==='operator_intent_schema_invalid'));
 assert(report.blockers.some(blocker=>blocker.code==='operator_production_approval_invalid'));
 assert(!report.blockers.some(blocker=>blocker.code==='operator_production_unapproved'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='operator_release_authorization_scope_mismatch'));

 const present=readyFixture(); present.operatorIntent.production_approved=false;
 present.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(present.operatorIntent));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>blocker.code==='operator_production_unapproved'));
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_release_authorization_scope_mismatch'));
});

test('noncanonical release config does not run derived acceptance checks',()=>{
 const invalid=readyFixture(); delete invalid.releaseConfig.governance;
 let report=assessMainnetReadiness(invalid);
 assert(report.blockers.some(blocker=>blocker.code==='release_config_schema_invalid'));
 assert(report.blockers.some(blocker=>blocker.code==='release_governance_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='operator_release_authorization_invalid'));

 const present=readyFixture(); present.releaseConfig.governance=null;
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>blocker.code==='release_governance_missing'));
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_release_authorization_invalid'));
});

test('noncanonical release evidence does not run derived acceptance checks',()=>{
 const invalid=readyFixture(); invalid.evidence.unexpected=true;
 invalid.operatorIntent.residual_risk_acceptance.reportSha256='2'.repeat(64);
 invalid.readinessDocumentAuthority.releaseEvidenceBytes=
  Buffer.from(JSON.stringify(invalid.evidence));
 invalid.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(invalid.operatorIntent));
 let report=assessMainnetReadiness(invalid);
 assert(report.blockers.some(blocker=>blocker.code==='release_evidence_schema_invalid'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_report_mismatch'));

 const present=readyFixture();
 present.operatorIntent.residual_risk_acceptance.reportSha256='2'.repeat(64);
 present.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(present.operatorIntent));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_residual_risk_report_mismatch'));
});

test('absent release chain ID does not claim a wrong chain',()=>{
 const absent=readyFixture(); delete absent.releaseConfig.ethereumChainId;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_config_schema_invalid'));
 assert(report.blockers.some(blocker=>blocker.code==='release_ethereumChainId_missing'));
 assert(!report.blockers.some(blocker=>blocker.code==='release_wrong_chain'));

 const present=readyFixture(); present.releaseConfig.ethereumChainId='2';
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>blocker.code==='release_wrong_chain'));
});

test('absent deployment method does not claim an invalid method',()=>{
 const absent=readyFixture(); delete absent.releaseConfig.deploymentMethod;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_config_schema_invalid'));
 assert(report.blockers.some(blocker=>blocker.code==='release_deploymentMethod_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='release_deployment_method_invalid'));

 const present=readyFixture(); present.releaseConfig.deploymentMethod='CREATE2';
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_deployment_method_invalid'));
});

test('absent release token does not claim an invalid token address',()=>{
 const absent=readyFixture(); delete absent.releaseConfig.token;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_config_schema_invalid'));
 assert(report.blockers.some(blocker=>blocker.code==='release_token_missing'));
 assert(!report.blockers.some(blocker=>blocker.code==='release_invalid_token'));

 const present=readyFixture(); present.releaseConfig.token='invalid';
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>blocker.code==='release_invalid_token'));
});

test('absent native burn timing field does not claim an invalid timing policy',()=>{
 const absent=readyFixture(); delete absent.releaseConfig.withdrawalDelaySeconds;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_config_schema_invalid'));
 assert(report.blockers.some(blocker=>
  blocker.code==='release_withdrawalDelaySeconds_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='release_native_burn_timing_invalid'));

 const present=readyFixture(); present.releaseConfig.withdrawalDelaySeconds='invalid';
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_native_burn_timing_invalid'));
});

test('absent reserve commitment field does not claim an invalid config',()=>{
 const absent=readyFixture(); absent.releaseConfig.governanceCodeHash='';
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_governanceCodeHash_missing'));
 assert(!report.blockers.some(blocker=>blocker.code==='release_config_invalid'));

 const present=readyFixture(); present.releaseConfig.governanceCodeHash='invalid';
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>blocker.code==='release_config_invalid'));
});

test('absent checkpoint commitment field does not claim an invalid config',()=>{
 const absent=readyFixture(); absent.releaseConfig.checkpointGuardianCodeHash='';
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_checkpointGuardianCodeHash_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='release_checkpoint_registry_config_invalid'));

 const present=readyFixture(); present.releaseConfig.checkpointGuardianCodeHash='invalid';
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_checkpoint_registry_config_invalid'));
});

test('absent bytecode hash does not claim an invalid hash',()=>{
 const absent=readyFixture(); absent.releaseConfig.reserveRuntimeCodeHash='';
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_reserveRuntimeCodeHash_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='release_reserve_runtime_codehash_invalid'));

 const present=readyFixture(); present.releaseConfig.reserveRuntimeCodeHash='invalid';
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_reserve_runtime_codehash_invalid'));
});

test('absent Ethereum anchor fields do not claim invalid values',()=>{
 const absent=readyFixture();
 absent.releaseConfig.ethereumGenesisValidatorsRoot='';
 absent.releaseConfig.nativeEthereumTrustedCheckpoint='';
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_ethereumGenesisValidatorsRoot_missing'));
 assert(report.blockers.some(blocker=>
  blocker.code==='release_nativeEthereumTrustedCheckpoint_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='release_ethereum_genesis_validators_root_invalid'
   ||blocker.code==='release_native_ethereum_trusted_checkpoint_invalid'));

 const present=readyFixture();
 present.releaseConfig.ethereumGenesisValidatorsRoot=bytes32('99');
 present.releaseConfig.nativeEthereumTrustedCheckpoint='invalid';
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_ethereum_genesis_validators_root_invalid'));
 assert(report.blockers.some(blocker=>
  blocker.code==='release_native_ethereum_trusted_checkpoint_invalid'));
});

test('absent control-plane address pin does not claim snapshot address failure',()=>{
 const absent=readyFixture(); absent.releaseConfig.guardian=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_guardian_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='control_plane_guardian_address_invalid'
   ||blocker.code==='control_plane_guardian_address_mismatch'));

 const present=readyFixture(); present.evidence.controlPlane.guardian.address='invalid';
 present.readinessDocumentAuthority.releaseEvidenceBytes=
  Buffer.from(JSON.stringify(present.evidence));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='control_plane_guardian_address_invalid'));
});

test('absent control-plane codehash pin does not claim snapshot mismatch',()=>{
 const absent=readyFixture(); absent.releaseConfig.guardianCodeHash=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_guardianCodeHash_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='control_plane_guardian_codehash_mismatch'));

 const present=readyFixture();
 present.evidence.controlPlane.guardian.runtimeCodeHash='invalid';
 present.readinessDocumentAuthority.releaseEvidenceBytes=
  Buffer.from(JSON.stringify(present.evidence));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='control_plane_guardian_codehash_mismatch'));
});

test('absent control-plane owner set does not claim semantic mismatch',()=>{
 const absent=readyFixture(); absent.releaseConfig.guardianOwners=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_guardianOwners_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='control_plane_evidence_content_invalid'));

 const present=readyFixture();
 present.releaseConfig.guardianOwners=[address(31),...present.releaseConfig.guardianOwners.slice(1)];
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='control_plane_evidence_content_invalid'));
});

test('absent control-plane snapshot does not claim semantic mismatch',()=>{
 const absent=readyFixture(); absent.evidence.controlPlane.guardian=null;
 absent.readinessDocumentAuthority.releaseEvidenceBytes=
  Buffer.from(JSON.stringify(absent.evidence));
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='control_plane_guardian_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='control_plane_evidence_content_invalid'),JSON.stringify(report.blockers));

 const present=readyFixture(); present.evidence.controlPlane.guardian.address=address(31);
 present.readinessDocumentAuthority.releaseEvidenceBytes=
  Buffer.from(JSON.stringify(present.evidence));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='control_plane_evidence_content_invalid'));
});

test('absent control-plane document does not claim semantic mismatch',()=>{
 const absent=readyFixture();
 absent.evidence.controlPlane.guardian.configurationReport=null;
 absent.readinessDocumentAuthority.releaseEvidenceBytes=
  Buffer.from(JSON.stringify(absent.evidence));
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='control_plane_guardian_report_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='control_plane_evidence_content_invalid'));

 const present=readyFixture(); present.evidence.controlPlane.guardian.address=address(31);
 present.readinessDocumentAuthority.releaseEvidenceBytes=
  Buffer.from(JSON.stringify(present.evidence));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='control_plane_evidence_content_invalid'));
});

test('invalid real-funds flag does not claim manual promotion',()=>{
 const absent=readyFixture('real-funds'); absent.releaseConfig.realFundsAuthorized=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_real_funds_authorization_invalid'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='release_real_funds_manual_flag'
   ||blocker.code==='pilot_funds_authorization_invalid'));

 const present=readyFixture('real-funds'); present.releaseConfig.realFundsAuthorized=true;
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_real_funds_manual_flag'));
});

test('invalid production-ready flag does not claim an explicit not-ready decision',()=>{
 const invalid=readyFixture(); invalid.releaseConfig.productionReady=null;
 let report=assessMainnetReadiness(invalid);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_production_ready_invalid'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='release_not_production_ready'));

 const present=readyFixture(); present.releaseConfig.productionReady=false;
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_not_production_ready'));
});

test('invalid operator deployment flag does not claim explicit denial',()=>{
 const invalid=readyFixture(); delete invalid.operatorIntent.deploy_authorized;
 invalid.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(invalid.operatorIntent));
 let report=assessMainnetReadiness(invalid);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_deploy_authorization_invalid'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='operator_deploy_unauthorized'));

 const present=readyFixture(); present.operatorIntent.deploy_authorized=false;
 present.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(present.operatorIntent));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_deploy_unauthorized'));
});

test('invalid operator real-funds flag does not claim explicit denial',()=>{
 const invalid=readyFixture('real-funds');
 delete invalid.operatorIntent.real_funds_authorized;
 invalid.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(invalid.operatorIntent));
 let report=assessMainnetReadiness(invalid);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_real_funds_authorization_invalid'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='operator_real_funds_unauthorized'));

 const present=readyFixture('real-funds');
 present.operatorIntent.real_funds_authorized=false;
 present.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(present.operatorIntent));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_real_funds_unauthorized'));
});

test('invalid requirements deployment flag does not claim explicit denial',()=>{
 const invalid=readyFixture(); delete invalid.requirements.deploy_authorized;
 invalid.requirementsAuthority.bytes=Buffer.from(JSON.stringify(invalid.requirements));
 let report=assessMainnetReadiness(invalid);
 assert(report.blockers.some(blocker=>
  blocker.code==='requirements_deploy_authorization_invalid'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='requirements_deploy_unauthorized'));

 const present=readyFixture(); present.requirements.deploy_authorized=false;
 present.requirementsAuthority.bytes=Buffer.from(JSON.stringify(present.requirements));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='requirements_deploy_unauthorized'));
});

test('invalid requirements mainnet-ready flag does not claim explicit denial',()=>{
 const invalid=readyFixture('real-funds'); delete invalid.requirements.mainnet_ready;
 invalid.requirementsAuthority.bytes=Buffer.from(JSON.stringify(invalid.requirements));
 let report=assessMainnetReadiness(invalid);
 assert(report.blockers.some(blocker=>
  blocker.code==='requirements_mainnet_ready_invalid'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='requirements_mainnet_not_ready'));

 const present=readyFixture('real-funds'); present.requirements.mainnet_ready=false;
 present.requirementsAuthority.bytes=Buffer.from(JSON.stringify(present.requirements));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='requirements_mainnet_not_ready'));
});

test('invalid requirements real-funds flag does not claim explicit denial',()=>{
 const invalid=readyFixture('real-funds');
 delete invalid.requirements.real_funds_authorized;
 invalid.requirementsAuthority.bytes=Buffer.from(JSON.stringify(invalid.requirements));
 let report=assessMainnetReadiness(invalid);
 assert(report.blockers.some(blocker=>
  blocker.code==='requirements_real_funds_authorization_invalid'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='requirements_real_funds_unauthorized'));

 const present=readyFixture('real-funds');
 present.requirements.real_funds_authorized=false;
 present.requirementsAuthority.bytes=Buffer.from(JSON.stringify(present.requirements));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='requirements_real_funds_unauthorized'));
});

test('invalid requirements finality approval does not claim explicit denial',()=>{
 const invalid=readyFixture();
 delete invalid.requirements.checkpoint_poc_authorization.production_mechanism_approved;
 invalid.requirementsAuthority.bytes=Buffer.from(JSON.stringify(invalid.requirements));
 let report=assessMainnetReadiness(invalid);
 assert(report.blockers.some(blocker=>
  blocker.code==='production_finality_approval_invalid'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='production_finality_unapproved'));

 const present=readyFixture();
 present.requirements.checkpoint_poc_authorization.production_mechanism_approved=false;
 present.requirementsAuthority.bytes=Buffer.from(JSON.stringify(present.requirements));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='production_finality_unapproved'));
});

test('absent owner commitment does not claim a derived mismatch',()=>{
 const absent=readyFixture(); absent.releaseConfig.governanceOwnersCommitment=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_governanceOwnersCommitment_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='release_governance_owners_commitment_mismatch'));

 const present=readyFixture();
 present.releaseConfig.governanceOwnersCommitment='0x'+'99'.repeat(32);
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_governance_owners_commitment_mismatch'));
});

test('absent release pin does not claim a contract-source mismatch',()=>{
 const absent=readyFixture(); absent.releaseConfig.verifierCodeHash=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_verifierCodeHash_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='contract_PRODUCTION_VERIFIER_CODE_HASH_mismatch'));

 const present=readyFixture(); present.releaseConfig.verifierCodeHash='0x'+'99'.repeat(32);
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='contract_PRODUCTION_VERIFIER_CODE_HASH_mismatch'));
});

test('invalid authorization flag does not claim a derived scope mismatch',()=>{
 const invalid=readyFixture(); invalid.operatorIntent.deploy_authorized=null;
 invalid.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(invalid.operatorIntent));
 let report=assessMainnetReadiness(invalid);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_deploy_authorization_invalid'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='operator_release_authorization_scope_mismatch'));

 const present=readyFixture(); present.operatorIntent.deploy_authorized=false;
 present.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(present.operatorIntent));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_release_authorization_scope_mismatch'));
});

test('absent operator signing fingerprint does not claim a mismatch',()=>{
 const absent=readyFixture(); delete absent.operatorIntent.release_signing_key_fingerprint;
 absent.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(absent.operatorIntent));
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='operator_intent_schema_invalid'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='operator_release_signing_key_mismatch'));

 const present=readyFixture();
 present.operatorIntent.release_signing_key_fingerprint='B'.repeat(40);
 present.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(present.operatorIntent));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_release_signing_key_mismatch'));
});

test('absent checkpoint guardian owners do not run config derivation',()=>{
 const absent=readyFixture(); absent.releaseConfig.checkpointGuardianOwners=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_checkpointGuardianOwners_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='release_checkpoint_registry_config_invalid'));

 const present=readyFixture(); present.releaseConfig.checkpointGuardianOwners=[];
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_checkpointGuardian_owners_invalid'));
 assert(report.blockers.some(blocker=>
  blocker.code==='release_checkpoint_registry_config_invalid'));
});

test('absent network-magic pin does not claim native runtime mismatch',()=>{
 const absent=readyFixture(); absent.releaseConfig.checkpointDomNetworkMagic=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_checkpointDomNetworkMagic_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='native_runtime_network_magic_mismatch'));

 const present=readyFixture(); present.releaseConfig.checkpointDomNetworkMagic='3735928559';
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='native_runtime_network_magic_mismatch'));
});

test('absent release hash pin does not claim native runtime mismatch',()=>{
 const absent=readyFixture(); absent.releaseConfig.checkpointDomChainId=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_checkpointDomChainId_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='native_runtime_chain_id_mismatch'));

 const present=readyFixture(); present.releaseConfig.checkpointDomChainId='0x'+'99'.repeat(32);
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='native_runtime_chain_id_mismatch'));
});

test('absent trusted-checkpoint pin does not claim native runtime mismatch',()=>{
 const absent=readyFixture(); absent.releaseConfig.nativeEthereumTrustedCheckpoint=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_nativeEthereumTrustedCheckpoint_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='native_runtime_ethereum_trusted_checkpoint_mismatch'));

 const present=readyFixture();
 present.releaseConfig.nativeEthereumTrustedCheckpoint='0x'+'99'.repeat(32);
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='native_runtime_ethereum_trusted_checkpoint_mismatch'));
});

test('absent V4 activation-height pin does not claim native runtime mismatch',()=>{
 const absent=readyFixture(); absent.releaseConfig.checkpointFirstV4Height=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_checkpointFirstV4Height_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='native_runtime_first_v4_height_mismatch'));

 const present=readyFixture(); present.releaseConfig.checkpointFirstV4Height='999';
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='native_runtime_first_v4_height_mismatch'));
});

test('absent Ethereum chain pin does not claim native runtime mismatch',()=>{
 const absent=readyFixture(); absent.releaseConfig.ethereumChainId=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_ethereumChainId_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='native_runtime_ethereum_chain_id_mismatch'));

 const present=readyFixture(); present.releaseConfig.ethereumChainId='2';
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='native_runtime_ethereum_chain_id_mismatch'));
});

test('absent address pin does not claim native runtime mismatch',()=>{
 const absent=readyFixture(); absent.releaseConfig.reserve=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_reserve_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='native_runtime_reserve_mismatch'
   ||blocker.code==='native_runtime_deposit_reserve_mismatch'));

 const present=readyFixture(); present.releaseConfig.reserve=address(77);
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='native_runtime_reserve_mismatch'));
 assert(report.blockers.some(blocker=>
  blocker.code==='native_runtime_deposit_reserve_mismatch'));
});

test('absent operational hash pin does not claim native runtime mismatch',()=>{
 const absent=readyFixture(); absent.releaseConfig.reserveRuntimeCodeHash=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_reserveRuntimeCodeHash_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='native_runtime_deposit_codehash_mismatch'));

 const present=readyFixture(); present.releaseConfig.reserveRuntimeCodeHash='0x'+'99'.repeat(32);
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='native_runtime_deposit_codehash_mismatch'));
});

test('invalid operator finality approval does not claim explicit denial',()=>{
 const invalid=readyFixture();
 delete invalid.operatorIntent.checkpoint_poc_authorization.production_mechanism_approved;
 invalid.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(invalid.operatorIntent));
 let report=assessMainnetReadiness(invalid);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_production_finality_approval_invalid'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='operator_production_finality_unapproved'));

 const present=readyFixture();
 present.operatorIntent.checkpoint_poc_authorization.production_mechanism_approved=false;
 present.readinessDocumentAuthority.operatorIntentBytes=
  Buffer.from(JSON.stringify(present.operatorIntent));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='operator_production_finality_unapproved'));
});

test('absent native approval finalized hash does not claim the snapshot changed',()=>{
 const assess=fixture=>{
  const bytes=Buffer.from(JSON.stringify(fixture.nativeAttestationApprovalObservation));
  fixture.approvalObservationAuthority.nativeAttestations={bytes,
   sha256:createHash('sha256').update(bytes).digest('hex')};
  return assessMainnetReadiness(fixture);
 };
 const absent=readyFixture(); absent.nativeAttestationApprovalObservation.finalizedBlockHash=null;
 let report=assess(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='native_attestation_approval_block_hash_invalid'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='native_attestation_approval_snapshot_changed'));

 const present=readyFixture();
 present.nativeAttestationApprovalObservation.snapshotBlockHashAfter=bytes32('71');
 report=assess(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='native_attestation_approval_snapshot_changed'));
});

test('absent governance codehash pin does not claim native approval mismatch',()=>{
 const absent=readyFixture(); absent.releaseConfig.governanceCodeHash=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_governanceCodeHash_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='native_attestation_approval_governance_codehash_mismatch'));

 const present=readyFixture();
 present.nativeAttestationApprovalObservation.governanceCodeHash=bytes32('51');
 const bytes=Buffer.from(JSON.stringify(present.nativeAttestationApprovalObservation));
 present.approvalObservationAuthority.nativeAttestations={bytes,
  sha256:createHash('sha256').update(bytes).digest('hex')};
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='native_attestation_approval_governance_codehash_mismatch'));
});

test('absent governance address pin does not claim native approval identity failure',()=>{
 const absent=readyFixture(); absent.releaseConfig.governance=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_governance_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='native_attestation_approval_governance_mismatch'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='native_attestation_approval_governance_invalid'));

 const present=readyFixture(); present.nativeAttestationApprovalObservation.governance=address(5);
 const bytes=Buffer.from(JSON.stringify(present.nativeAttestationApprovalObservation));
 present.approvalObservationAuthority.nativeAttestations={bytes,
  sha256:createHash('sha256').update(bytes).digest('hex')};
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='native_attestation_approval_governance_mismatch'));
});

test('absent chain ID pin does not claim native approval chain mismatch',()=>{
 const absent=readyFixture(); absent.releaseConfig.ethereumChainId=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_ethereumChainId_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='native_attestation_approval_chain_mismatch'));

 const present=readyFixture(); present.nativeAttestationApprovalObservation.chainId='2';
 const bytes=Buffer.from(JSON.stringify(present.nativeAttestationApprovalObservation));
 present.approvalObservationAuthority.nativeAttestations={bytes,
  sha256:createHash('sha256').update(bytes).digest('hex')};
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='native_attestation_approval_chain_mismatch'));
});

test('absent chain ID pin does not claim release approval chain mismatch',()=>{
 const absent=readyFixture(); absent.releaseConfig.ethereumChainId=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_ethereumChainId_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='release_authorization_approval_chain_mismatch'));

 const present=readyFixture(); present.releaseAuthorizationApprovalObservation.chainId='2';
 const bytes=Buffer.from(JSON.stringify(present.releaseAuthorizationApprovalObservation));
 present.approvalObservationAuthority.releaseAuthorization={bytes,
  sha256:createHash('sha256').update(bytes).digest('hex')};
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_authorization_approval_chain_mismatch'));
});

test('absent governance address pin does not claim release approval identity failure',()=>{
 const absent=readyFixture(); absent.releaseConfig.governance=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_governance_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='release_authorization_approval_governance_mismatch'));

 const present=readyFixture();
 present.releaseAuthorizationApprovalObservation.governance=address(5);
 const bytes=Buffer.from(JSON.stringify(present.releaseAuthorizationApprovalObservation));
 present.approvalObservationAuthority.releaseAuthorization={bytes,
  sha256:createHash('sha256').update(bytes).digest('hex')};
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_authorization_approval_governance_mismatch'));
});

test('absent governance codehash pin does not claim release approval mismatch',()=>{
 const absent=readyFixture(); absent.releaseConfig.governanceCodeHash=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_governanceCodeHash_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='release_authorization_approval_governance_codehash_mismatch'));

 const present=readyFixture();
 present.releaseAuthorizationApprovalObservation.governanceCodeHash=bytes32('51');
 const bytes=Buffer.from(JSON.stringify(present.releaseAuthorizationApprovalObservation));
 present.approvalObservationAuthority.releaseAuthorization={bytes,
  sha256:createHash('sha256').update(bytes).digest('hex')};
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_authorization_approval_governance_codehash_mismatch'));
});

test('real-funds custody and recovery attestations bind the same wallet identity',()=>{
 const mutations=[
  [fixture=>{fixture.evidence.nativeWalletCustodyAttestationReport=null;},
   'evidence_nativeWalletCustodyAttestationReport_missing'],
  [fixture=>{fixture.nativeWalletCustodyAttestation.kind='wrong';},
   'native_wallet_custody_kind_mismatch'],
  [fixture=>{fixture.nativeWalletRecoveryAttestation.completedAt='0';},
   'native_wallet_recovery_completed_at_invalid'],
  [fixture=>{fixture.nativeWalletRecoveryAttestation.subjectCommitment=bytes32('a3');},
   'native_wallet_recovery_identity_mismatch'],
 ];
 for(const [mutate,code] of mutations) {
  const fixture=readyFixture('real-funds'); mutate(fixture);
  for(const [objectField,bytesField,evidenceField] of [
   ['nativeWalletCustodyAttestation','nativeWalletCustodyBytes','nativeWalletCustodyAttestationReport'],
   ['nativeWalletRecoveryAttestation','nativeWalletRecoveryBytes','nativeWalletRecoveryAttestationReport'],
  ]) {
   const document=fixture.evidence[evidenceField];
   if(!document) continue;
   const bytes=Buffer.from(JSON.stringify(fixture[objectField]));
   fixture.nativeReleaseAttestationAuthority[bytesField]=bytes;
   document.sha256=createHash('sha256').update(bytes).digest('hex');
   fixture.evidenceFiles[document.path]=document.sha256;
  }
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,code);
  assert(report.blockers.some(blocker=>blocker.code===code),code);
 }
});

test('every RISC Zero adapter ABI hardening requirement independently fails closed',()=>{
 for(const key of riscZeroAdapterRequiredKeys) {
  const fixture=readyFixture();
  fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
});

test('every RISC Zero guest input-boundary requirement independently fails closed',()=>{
 for(const key of riscZeroGuestInputRequiredKeys) {
  const fixture=readyFixture();
  fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
});

test('every Ethereum finality panic-boundary requirement independently fails closed',()=>{
 for(const key of ethereumFinalityPanicBoundaryRequiredKeys) {
  const fixture=readyFixture();
  fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
});

test('every native state panic-boundary requirement independently fails closed',()=>{
 for(const key of nativeStatePanicBoundaryRequiredKeys) {
  const fixture=readyFixture();
  fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
});

test('every native privacy panic-boundary requirement independently fails closed',()=>{
 for(const key of nativePrivacyPanicBoundaryRequiredKeys) {
  const fixture=readyFixture();
  fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
});

test('every proof-program boundary requirement independently fails closed',()=>{
 for(const key of proofProgramBoundaryRequiredKeys) {
  const fixture=readyFixture(); fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
});

test('every native wallet panic-boundary requirement independently fails closed',()=>{
 for(const key of nativeWalletPanicBoundaryRequiredKeys) {
  const fixture=readyFixture(); fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
});

test('every finalized-snapshot preflight requirement independently fails closed',()=>{
 for(const key of preflightSnapshotRequiredKeys) {
  const fixture=readyFixture(); fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
});

test('every reconciled RISC Zero configuration requirement independently fails closed',()=>{
 for(const key of riscZeroConfigRequiredKeys) {
  const fixture=readyFixture(); fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
});

test('finalized-burn and checkpoint adapters must bind one chain and upstream verifier identity',()=>{
 const wrongChain=readyFixture();
 wrongChain.verifierConfig.ethereumChainId='2';
 let report=assessMainnetReadiness(wrongChain);
 assert(report.blockers.some(blocker=>blocker.code==='verifier_ethereumChainId_release_mismatch'));
 const fields=['riscZeroVerifier','riscZeroVerifierCodeHash'];
 for(const field of fields) {
  const fixture=readyFixture();
  fixture.verifierConfig[field]=field==='riscZeroVerifier' ? address(17) : bytes32('2b');
  fixture.checkpointVerifierConfig[field]=field==='riscZeroVerifier' ? address(18) : bytes32('2c');
  report=assessMainnetReadiness(fixture);
  assert(report.blockers.some(blocker=>blocker.code==='verifier_config_manifest_invalid'),field);
  assert(report.blockers.some(blocker=>blocker.code==='checkpoint_verifier_config_manifest_invalid'),field);
 }
});

test('repository manifests cannot replace the reviewed RISC Zero mainnet verifier pin',()=>{
 const changedReference=readyFixture();
 changedReference.riscZeroReference.observed_runtime_code_hash=bytes32('99');
 let report=assessMainnetReadiness(changedReference);
 assert(report.blockers.some(blocker=>blocker.code==='risc0_mainnet_reference_invalid'));

 const attacker=readyFixture();
 attacker.riscZeroReference.verifier_address=address(99);
 attacker.verifierConfig.riscZeroVerifier=address(99);
 attacker.checkpointVerifierConfig.riscZeroVerifier=address(99);
 report=assessMainnetReadiness(attacker);
 assert(report.blockers.some(blocker=>blocker.code==='risc0_mainnet_reference_invalid'));

 const untrustedManifest=readyFixture();
 untrustedManifest.verifierConfig.riscZeroVerifier=address(99);
 report=assessMainnetReadiness(untrustedManifest);
 assert(report.blockers.some(blocker=>blocker.code==='verifier_config_manifest_invalid'));
});

test('RISC Zero incident source catalog is hash-addressed release evidence',()=>{
 const changedIdentity=readyFixture();
 changedIdentity.riscZeroHealthSourceCatalog.sources[1].operatorId='operator-a';
 let report=assessMainnetReadiness(changedIdentity);
 assert(report.blockers.some(({code})=>code==='risc0_health_source_catalog_invalid'));
 const changedHash=readyFixture();
 changedHash.riscZeroHealthSourceCatalog.catalogHash=bytes32('ff');
 report=assessMainnetReadiness(changedHash);
 assert(report.blockers.some(({code})=>code==='risc0_health_source_catalog_invalid'));
 const missingEvidence=readyFixture();
 delete missingEvidence.evidenceFiles[missingEvidence.evidence.riscZeroHealthSourceCatalog.path];
 report=assessMainnetReadiness(missingEvidence);
 assert(report.blockers.some(({code})=>code==='evidence_riscZeroHealthSourceCatalog_missing'));
 const substituted=readyFixture();
 substituted.riscZeroHealthSourceCatalog=createRiscZeroHealthSourceCatalog({sources:[
  {sourceId:'rpc-a',operatorId:'operator-a',providerId:'provider-a',
   infrastructureId:'infra-a',endpointHash:bytes32('c3')},
  {sourceId:'rpc-b',operatorId:'operator-b',providerId:'provider-b',
   infrastructureId:'infra-b',endpointHash:bytes32('c4')},
 ]});
 substituted.riscZeroHealthSourceCatalogAuthority={catalogBytes:
  Buffer.from(JSON.stringify(substituted.riscZeroHealthSourceCatalog))};
 report=assessMainnetReadiness(substituted);
 assert(report.blockers.some(({code})=>code==='risc0_health_source_catalog_invalid'));
});

test('machine predeployment and cold-start attestations are independently recomputed',()=>{
 const predeploymentChanges=[
  fixture=>{fixture.predeploymentAttestation=null;},
  fixture=>{fixture.predeploymentAttestation.phase='postdeployment';},
  fixture=>{fixture.predeploymentAttestation.ready=false;},
  fixture=>{fixture.predeploymentAttestation.blockerCount=1;},
  fixture=>{fixture.predeploymentAttestation.blockers=[{code:'forged',detail:'forged'}];},
  fixture=>{fixture.predeploymentAttestation.finalizedBlockHash=bytes32('99');},
  fixture=>{fixture.predeploymentAttestation.observation.codeHashes.verifier=bytes32('98');},
  fixture=>{fixture.predeploymentAttestation.observation.finalizedBurnVerifierDeployment.inputHash=bytes32('98');},
  fixture=>{fixture.predeploymentAttestation.observation.finalizedBurnVerifierDeployment
    .derivedCreateAddress=address(99);},
  fixture=>{delete fixture.predeploymentAttestation.observation.checkpointVerifierDeployment.transactionHash;},
  fixture=>{fixture.predeploymentAttestation.observation.token.maximumFee=null;},
  fixture=>{fixture.predeploymentAttestation.observation.token.extra=true;},
  fixture=>{fixture.predeploymentAttestation.rpcConsensus.sources.pop();},
  fixture=>{fixture.predeploymentAttestation.rpcConsensus.sourceSetCommitment=bytes32('99');},
  fixture=>{delete fixture.predeploymentAttestation.collectionStartedAtMs;},
  fixture=>{fixture.predeploymentAttestation.collectionCompletedAtMs=
    fixture.predeploymentAttestation.collectionStartedAtMs+10*60*1000+1;},
  fixture=>{fixture.predeploymentAttestation.extra=true;},
 ];
 for(const change of predeploymentChanges) {
  const fixture=readyFixture(); change(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,JSON.stringify(change));
  assert(report.blockers.some(blocker=>blocker.code.startsWith('predeployment_attestation_')),
   JSON.stringify(report.blockers));
 }
 const coldStartChanges=[
  fixture=>{fixture.coldStartAttestation=null;},
  fixture=>{fixture.coldStartAttestation.phase='predeployment';},
  fixture=>{fixture.coldStartAttestation.ready=false;},
  fixture=>{fixture.coldStartAttestation.finalizedBlockNumber='21999999';},
  fixture=>{fixture.coldStartAttestation.observation.reserve.paused=false;},
  fixture=>{fixture.coldStartAttestation.observation.reserve.resumeReadyAt=false;},
  fixture=>{delete fixture.coldStartAttestation.observation.deployment.transactionHash;},
  fixture=>{fixture.coldStartAttestation.observation.finalizedBurnVerifierDeployment.inputHash=bytes32('99');},
  fixture=>{fixture.coldStartAttestation.observation.deployment.derivedCreateAddress=address(99);},
  fixture=>{delete fixture.coldStartAttestation.observation.checkpointVerifierDeployment.transactionHash;},
  fixture=>{fixture.coldStartAttestation.observation.checkpointRegistryCandidate.extra=true;},
  fixture=>{delete fixture.coldStartAttestation.observation.snapshotBlockHashAfter;},
  fixture=>{fixture.coldStartAttestation.rpcConsensus.sources.pop();},
  fixture=>{fixture.coldStartAttestation.rpcConsensus.sourceSetCommitment=bytes32('99');},
  fixture=>{fixture.coldStartAttestation.collectionStartedAtMs='1792492800000';},
  fixture=>{fixture.coldStartAttestation.collectionStartedAtMs=
    fixture.coldStartAttestation.collectionCompletedAtMs+1;},
 ];
 for(const change of coldStartChanges) {
  const fixture=readyFixture('real-funds'); change(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,JSON.stringify(change));
  assert(report.blockers.some(blocker=>blocker.code.startsWith('cold_start_attestation_')),
   JSON.stringify(report.blockers));
 }
});

test('every renewable irreversible-burn claim requirement independently fails closed',()=>{
 for(const key of renewableBurnClaimRequiredKeys) {
  const fixture=readyFixture(); fixture.requirements[key]=false;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,key);
  assert(report.blockers.some(blocker=>blocker.code===`requirement_${key}`),key);
 }
 for(const period of [undefined,0,604799,604801,'604800']) {
  const fixture=readyFixture();
  fixture.requirements.production_withdrawal_queue_lease_period_seconds=period;
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,String(period));
  assert(report.blockers.some(blocker=>
   blocker.code==='requirement_production_withdrawal_queue_lease_period_seconds'),String(period));
 }
});

test('the checked-in candidate is rejected with explicit nonduplicated blockers',async()=>{
 const [requirements,operatorIntent,releaseConfig,contractSource,checkpointContractSource,evidence]=await Promise.all([
  readFile(new URL('../../config/production-requirements.json',import.meta.url),'utf8').then(JSON.parse),
  readFile(new URL('../../config/operator-intent.json',import.meta.url),'utf8').then(JSON.parse),
  readFile(new URL('../../config/proof-reserve.unconfigured.json',import.meta.url),'utf8').then(JSON.parse),
  readFile(new URL('../../contracts/USDOMProofReserve.sol',import.meta.url),'utf8'),
  readFile(new URL('../../contracts/DOMCheckpointRegistry.sol',import.meta.url),'utf8'),
  readFile(new URL('../../config/mainnet-release-evidence.unconfigured.json',import.meta.url),'utf8').then(JSON.parse),
 ]);
 const report=assessMainnetReadiness({mode:'closed-mainnet',requirements,operatorIntent,releaseConfig,
  requirementsAuthority:{bytes:Buffer.from(JSON.stringify(requirements))},
  readinessDocumentAuthority:{operatorIntentBytes:Buffer.from(JSON.stringify(operatorIntent)),
   releaseEvidenceBytes:Buffer.from(JSON.stringify(evidence))},
  evidence,evidenceFiles:{},contractSource,checkpointContractSource,
  contractSourceAuthority:{reserveBytes:Buffer.from(contractSource),
   checkpointRegistryBytes:Buffer.from(checkpointContractSource)}});
 assert.equal(report.ready,false);
 const codes=report.blockers.map(blocker=>blocker.code);
 assert.equal(new Set(codes).size,codes.length);
 for(const code of ['requirement_production_finalized_burn_risc0_evm_receipt_verifier_implemented','production_finality_unselected',
  'operator_deploy_unauthorized','release_reserve_missing','contract_PRODUCTION_VERIFIER_CODE_HASH_zero',
  'release_evidence_unconfigured']) assert(codes.includes(code),code);
 assert.match(operatorIntent.production_trust_model,/quorum restricted to prototype/i);
 assert(!operatorIntent.undefined.some(parameter=>/notary|threshold|testnet token/i.test(parameter)),
  'proof-authorized mainnet release must not require prototype quorum or unrelated testnet parameters');
});

test('production finality selection accepts only the implemented checkpoint mechanism',()=>{
 const fixture=readyFixture();
 assert.equal(assessMainnetReadiness(fixture).ready,true);
 fixture.requirements.finality_evaluation.selected_production_mechanism='operator-defined-finality';
 const report=assessMainnetReadiness(fixture);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>blocker.code==='production_finality_unsupported'));
 assert(!report.blockers.some(blocker=>blocker.code==='production_finality_unselected'));
});

test('absent production finality selection does not claim an approval decision failed',()=>{
 const fixture=readyFixture();
 fixture.requirements.finality_evaluation.selected_production_mechanism='';
 fixture.requirements.checkpoint_poc_authorization.production_mechanism_approved=false;
 fixture.operatorIntent.checkpoint_poc_authorization.production_mechanism_approved=false;
 fixture.operatorIntent.finality_direction='decision-pending';
 let report=assessMainnetReadiness(fixture);
 assert(report.blockers.some(blocker=>blocker.code==='production_finality_unselected'));
 assert(!report.blockers.some(blocker=>blocker.code==='production_finality_unapproved'));
 assert(!report.blockers.some(blocker=>blocker.code==='operator_production_finality_unapproved'));
 assert(!report.blockers.some(blocker=>blocker.code==='operator_finality_direction_invalid'));
 assert(!report.blockers.some(blocker=>blocker.code==='operator_finality_direction_invalid'));

 fixture.requirements.finality_evaluation.selected_production_mechanism='checkpoint';
 report=assessMainnetReadiness(fixture);
 assert(!report.blockers.some(blocker=>blocker.code==='production_finality_unselected'));
 assert(report.blockers.some(blocker=>blocker.code==='production_finality_unapproved'));
 assert(report.blockers.some(blocker=>blocker.code==='operator_production_finality_unapproved'));
 assert(report.blockers.some(blocker=>blocker.code==='operator_finality_direction_invalid'));
});

test('production finality requires an independent matching operator decision',()=>{
 for(const [mutate,code] of [
  [fixture=>{fixture.operatorIntent.checkpoint_poc_authorization.production_mechanism_approved=false;},
   'operator_production_finality_unapproved'],
  [fixture=>{fixture.operatorIntent.checkpoint_poc_authorization={};},
   'operator_production_finality_approval_invalid'],
  [fixture=>{fixture.operatorIntent.finality_direction='probabilistic-pow';},
   'operator_finality_direction_invalid'],
  [fixture=>{fixture.operatorIntent.finality_comparison='docs/OTHER.txt';},
   'operator_finality_comparison_invalid'],
 ]) {
  const fixture=readyFixture();
  mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,code);
  assert(report.blockers.some(blocker=>blocker.code===code),code);
 }
});

test('absent operator intent does not claim its finality fields are invalid',()=>{
 const absent=readyFixture(); absent.operatorIntent=null;
 absent.readinessDocumentAuthority.operatorIntentBytes=Buffer.from('null');
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='operator_intent_missing'));
 assert(!report.blockers.some(blocker=>blocker.code==='operator_finality_comparison_invalid'));
 assert(!report.blockers.some(blocker=>blocker.code==='operator_production_finality_unapproved'));

 const present=readyFixture(); present.operatorIntent.finality_comparison='docs/OTHER.txt';
 present.operatorIntent.checkpoint_poc_authorization.production_mechanism_approved=false;
 present.operatorIntent.finality_direction='probabilistic-pow';
 present.readinessDocumentAuthority.operatorIntentBytes=Buffer.from(JSON.stringify(present.operatorIntent));
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>blocker.code==='operator_finality_comparison_invalid'));
 assert(report.blockers.some(blocker=>blocker.code==='operator_production_finality_unapproved'));
 assert(report.blockers.some(blocker=>blocker.code==='operator_finality_direction_invalid'));
});

test('absent reserve artifact pins do not claim compiled hash mismatches',()=>{
 const absent=readyFixture(); absent.releaseConfig.reserveRuntimeCodeHash=null;
 absent.releaseConfig.reserveInitcodeHash=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_reserveRuntimeCodeHash_missing'));
 assert(!report.blockers.some(blocker=>blocker.code==='compiled_reserve_runtime_mismatch'));
 assert(report.blockers.some(blocker=>blocker.code==='release_reserveInitcodeHash_missing'));
 assert(!report.blockers.some(blocker=>blocker.code==='compiled_reserve_initcode_mismatch'));

 const present=readyFixture(); present.releaseConfig.reserveRuntimeCodeHash=bytes32('99');
 present.releaseConfig.reserveInitcodeHash=bytes32('98');
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>blocker.code==='compiled_reserve_runtime_mismatch'));
 assert(report.blockers.some(blocker=>blocker.code==='compiled_reserve_initcode_mismatch'));
});

test('absent checkpoint registry pins do not claim compiled hash mismatches',()=>{
 const absent=readyFixture(); absent.releaseConfig.checkpointRegistryRuntimeCodeHash=null;
 absent.releaseConfig.checkpointRegistryInitcodeHash=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_checkpointRegistryRuntimeCodeHash_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='compiled_checkpoint_registry_runtime_mismatch'));
 assert(report.blockers.some(blocker=>
  blocker.code==='release_checkpointRegistryInitcodeHash_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='compiled_checkpoint_registry_initcode_mismatch'));

 const present=readyFixture();
 present.releaseConfig.checkpointRegistryRuntimeCodeHash=bytes32('99');
 present.releaseConfig.checkpointRegistryInitcodeHash=bytes32('98');
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='compiled_checkpoint_registry_runtime_mismatch'));
 assert(report.blockers.some(blocker=>
  blocker.code==='compiled_checkpoint_registry_initcode_mismatch'));
});

test('absent finalized-burn verifier pins do not claim compiled hash mismatches',()=>{
 const absent=readyFixture(); absent.releaseConfig.verifierCodeHash=null;
 absent.releaseConfig.verifierInitcodeHash=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>blocker.code==='release_verifierCodeHash_missing'));
 assert(!report.blockers.some(blocker=>blocker.code==='compiled_verifier_runtime_mismatch'));
 assert(report.blockers.some(blocker=>blocker.code==='release_verifierInitcodeHash_missing'));
 assert(!report.blockers.some(blocker=>blocker.code==='compiled_verifier_initcode_mismatch'));

 const present=readyFixture(); present.releaseConfig.verifierCodeHash=bytes32('99');
 present.releaseConfig.verifierInitcodeHash=bytes32('98');
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>blocker.code==='compiled_verifier_runtime_mismatch'));
 assert(report.blockers.some(blocker=>blocker.code==='compiled_verifier_initcode_mismatch'));
});

test('absent checkpoint verifier pins do not claim compiled hash mismatches',()=>{
 const absent=readyFixture(); absent.releaseConfig.checkpointVerifierCodeHash=null;
 absent.releaseConfig.checkpointVerifierInitcodeHash=null;
 let report=assessMainnetReadiness(absent);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_checkpointVerifierCodeHash_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='compiled_checkpoint_verifier_runtime_mismatch'));
 assert(report.blockers.some(blocker=>
  blocker.code==='release_checkpointVerifierInitcodeHash_missing'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='compiled_checkpoint_verifier_initcode_mismatch'));

 const present=readyFixture(); present.releaseConfig.checkpointVerifierCodeHash=bytes32('99');
 present.releaseConfig.checkpointVerifierInitcodeHash=bytes32('98');
 report=assessMainnetReadiness(present);
 assert(report.blockers.some(blocker=>
  blocker.code==='compiled_checkpoint_verifier_runtime_mismatch'));
 assert(report.blockers.some(blocker=>
  blocker.code==='compiled_checkpoint_verifier_initcode_mismatch'));
});

test('an intermediate burn-state witness can never claim consensus or payout authority',()=>{
 const fixture=readyFixture();
 assert.equal(assessMainnetReadiness(fixture).ready,true);
 fixture.requirements.native_burn_state_witness_authorizes_consensus_or_payout=true;
 const report=assessMainnetReadiness(fixture);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>
  blocker.code==='requirement_native_burn_state_witness_scope_invalid'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='requirement_native_burn_state_witness_authorizes_consensus_or_payout'));
});

test('the block-bound burn transport can never claim independent finality',()=>{
 const fixture=readyFixture();
 assert.equal(fixture.requirements.native_burn_block_prover_input_proves_finality,false);
 assert.equal(assessMainnetReadiness(fixture).ready,true);
 fixture.requirements.native_burn_block_prover_input_proves_finality=true;
 const report=assessMainnetReadiness(fixture);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>
  blocker.code==='requirement_native_burn_block_prover_input_scope_invalid'));
 assert(!report.blockers.some(blocker=>
  blocker.code==='requirement_native_burn_block_prover_input_proves_finality'));
});

test('a substituted config, compiled pin, evidence hash or authorization fails closed',()=>{
 const changes=[
  fixture=>{fixture.releaseConfig.reserveConfigHash='0x'+'99'.repeat(32);},
  fixture=>{fixture.releaseConfig.deployerNonce='8';},
  fixture=>{fixture.releaseConfig.deployer=address(0);},
  fixture=>{fixture.releaseConfig.deploymentMethod='CREATE2';},
  fixture=>{fixture.releaseConfig.reserveRuntimeCodeHash='0x'+'00'.repeat(32);},
  fixture=>{fixture.compiledReserveRuntimeCodeHash='0x'+'91'.repeat(32);},
  fixture=>{fixture.compiledVerifierRuntimeCodeHash='0x'+'97'.repeat(32);},
  fixture=>{fixture.compiledVerifierInitcodeHash='0x'+'97'.repeat(32);},
  fixture=>{fixture.compiledCheckpointVerifierRuntimeCodeHash='0x'+'98'.repeat(32);},
  fixture=>{fixture.compiledCheckpointVerifierInitcodeHash='0x'+'98'.repeat(32);},
  fixture=>{fixture.releaseConfig.verifierDeployerNonce='3';},
  fixture=>{fixture.releaseConfig.checkpointVerifierDeployerNonce='4';},
  fixture=>{fixture.releaseConfig.reserveInitcodeHash='0x'+'00'.repeat(32);},
  fixture=>{fixture.compiledReserveInitcodeHash='0x'+'93'.repeat(32);},
  fixture=>{fixture.contractSource=fixture.contractSource.replace('0x'+'20'.repeat(32),'0x'+'21'.repeat(32));},
  fixture=>{fixture.releaseConfig.checkpointRegistryConfigHash='0x'+'98'.repeat(32);},
  fixture=>{fixture.releaseConfig.checkpointRegistryDeployerNonce='5';},
  fixture=>{fixture.releaseConfig.checkpointRegistryRuntimeCodeHash='0x'+'00'.repeat(32);},
  fixture=>{fixture.compiledCheckpointRegistryRuntimeCodeHash='0x'+'95'.repeat(32);},
  fixture=>{fixture.releaseConfig.checkpointRegistryInitcodeHash='0x'+'00'.repeat(32);},
  fixture=>{fixture.compiledCheckpointRegistryInitcodeHash='0x'+'96'.repeat(32);},
  fixture=>{fixture.releaseConfig.checkpointDomChainId='0x'+'98'.repeat(32);},
  fixture=>{fixture.releaseConfig.checkpointFirstV4Height='100001';},
  fixture=>{fixture.releaseConfig.checkpointActivationEmptyStateRoot='0x'+'98'.repeat(32);},
  fixture=>{fixture.releaseConfig.checkpointIntervalBlocks='359';},
  fixture=>{fixture.releaseConfig.checkpointConfirmationDepthBlocks='29';},
  fixture=>{fixture.releaseConfig.checkpointChallengePeriodSeconds='172801';},
  fixture=>{fixture.releaseConfig.checkpointInitialTotalDifficulty='1000001';},
  fixture=>{fixture.checkpointContractSource=fixture.checkpointContractSource
    .replace(fixture.releaseConfig.checkpointVerifierCodeHash,'0x'+'22'.repeat(32));},
  fixture=>{fixture.evidence.checkpointBootstrapRatificationReport=null;},
  fixture=>{fixture.evidence.checkpointRegistryArtifact.path='evidence/wrong-checkpoint-artifact.json';},
  fixture=>{fixture.evidence.controlPlane.checkpointGuardian.configurationHash=
    fixture.evidence.controlPlane.guardian.configurationHash;},
  fixture=>{fixture.evidenceFiles['evidence/build.txt']='2'.repeat(64);},
  fixture=>{fixture.verifierConfig.activationScheduleCommitment='0x'+'99'.repeat(32);},
  fixture=>{fixture.verifierConfig.verifyingKeySha256='0x'+'99'.repeat(32);},
  fixture=>{fixture.checkpointVerifierConfig.powRulesHash='0x'+'99'.repeat(32);},
  fixture=>{fixture.checkpointVerifierConfig.checkpointInterval='359';
    fixture.checkpointVerifierConfig.maxCheckpointSpan='389';},
  fixture=>{fixture.evidenceFiles['evidence/checkpoint-verifier-config.json']='2'.repeat(64);},
  fixture=>{fixture.evidenceFiles['evidence/checkpoint-proving-program.bin']='2'.repeat(64);},
  fixture=>{fixture.evidenceFiles['evidence/verifier-config.json']='2'.repeat(64);},
  fixture=>{fixture.evidenceFiles['evidence/proving-program.bin']='2'.repeat(64);},
  fixture=>{fixture.evidence.domConsensusAuditReports=[{path:'evidence/bad.txt',sha256:'not-a-hash'}];},
  fixture=>{fixture.evidence.securityValidationReport=null;},
  fixture=>{fixture.evidence.residualRiskAcceptanceReport=null;},
  fixture=>{fixture.evidence.controlPlane.governance.address=address(5);},
  fixture=>{fixture.evidence.controlPlane.guardian.runtimeCodeHash='0x'+'61'.repeat(32);},
  fixture=>{fixture.evidence.controlPlane.governance.configurationHash='0x'+'00'.repeat(32);},
  fixture=>{fixture.evidence.controlPlane.guardian.configurationHash=fixture.evidence.controlPlane.governance.configurationHash;},
  fixture=>{fixture.evidenceFiles['evidence/control-plane/governance-configuration.json']=
    '2'.repeat(64);},
  fixture=>{fixture.evidence.controlPlaneSeparationReport=null;},
  fixture=>{fixture.evidence.mainnetPredeploymentAttestationReport=null;},
  fixture=>{fixture.evidence.reserveArtifact.path='evidence/wrong-artifact.json';},
  fixture=>{fixture.evidence.verifierArtifact.path='out/wrong-finalized-burn-adapter.json';},
  fixture=>{fixture.evidence.checkpointVerifierArtifact.path='out/wrong-checkpoint-adapter.json';},
  fixture=>{fixture.operatorIntent.deploy_authorized=false;},
  fixture=>{fixture.requirements.consensus_proof_implemented=false;},
  fixture=>{fixture.requirements.native_set_witness_bounded_cursor_deserialization=false;},
  fixture=>{fixture.requirements.native_private_prover_linked_into_node=false;},
  fixture=>{fixture.requirements.native_private_wallet_node_dependency=false;},
  fixture=>{fixture.requirements.native_private_wallet_private_burn_random_identifiers=false;},
  fixture=>{fixture.requirements.native_private_wallet_private_burn_request_id_pending_collision_rejected=false;},
  fixture=>{fixture.requirements.native_private_wallet_private_burn_identifiers_proof_and_consensus_bound=false;},
  fixture=>{fixture.requirements.native_private_wallet_authenticated_history_atomic_application=false;},
  fixture=>{fixture.requirements.native_private_wallet_authenticated_history_partial_release_forbidden=false;},
  fixture=>{fixture.requirements.native_private_wallet_authenticated_history_completed_scan_fields_private=false;},
  fixture=>{fixture.requirements.native_private_wallet_authenticated_history_failure_restores_original_tip=false;},
  fixture=>{fixture.requirements.native_burn_state_witness_authorizes_consensus_or_payout=true;},
  fixture=>{fixture.requirements.native_burn_block_prover_input_proves_finality=true;},
  fixture=>{fixture.requirements.verified_native_burn_checkpoint_external_restart_floor_required=false;},
  fixture=>{fixture.requirements.production_verified_checkpoint_restart_witness_live_exercised=false;},
  fixture=>{fixture.repositoryState.dirty=true;},
  fixture=>{fixture.repositoryState.head='c'.repeat(40);},
  fixture=>{fixture.repositoryState.tagSignatureVerified=false;},
  fixture=>{fixture.repositoryState.importProvenanceVerified=false;},
  fixture=>{fixture.repositoryState.sourceManifestVerified=false;},
  fixture=>{fixture.repositoryState.ethereumFinalityPanicBoundaryVerified=false;},
  fixture=>{fixture.repositoryState.nativeStatePanicBoundaryVerified=false;},
  fixture=>{fixture.repositoryState.nativePrivacyPanicBoundaryVerified=false;},
  fixture=>{fixture.repositoryState.proofProgramPanicBoundaryVerified=false;},
  fixture=>{fixture.repositoryState.risc0ProgramBinariesVerified=false;},
  fixture=>{fixture.repositoryState.nativeWalletPanicBoundaryVerified=false;},
 ];
 for(const change of changes) {
  const fixture=readyFixture(); change(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  const codes=report.blockers.map(blocker=>blocker.code);
  assert.equal(new Set(codes).size,codes.length,JSON.stringify(report.blockers));
 }
 assert.throws(()=>assessMainnetReadiness({...readyFixture(),mode:'invalid'}),/mode/);
 const realFunds=readyFixture('real-funds'); realFunds.evidence.mainnetColdStartAttestationReport=null;
 assert.equal(assessMainnetReadiness(realFunds).ready,false);
});

test('checkpoint registry artifact declaration cannot replace compiled release bindings',()=>{
 const missingRuntime=readyFixture();
 assert.equal(missingRuntime.requirements.production_checkpoint_registry_artifacts_pinned,true);
 missingRuntime.compiledCheckpointRegistryRuntimeCodeHash=null;
 let report=assessMainnetReadiness(missingRuntime);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>
  blocker.code==='compiled_checkpoint_registry_runtime_unavailable'));

 const changedInitcode=readyFixture();
 assert.equal(changedInitcode.requirements.production_checkpoint_registry_artifacts_pinned,true);
 changedInitcode.compiledCheckpointRegistryInitcodeHash='0x'+'98'.repeat(32);
 report=assessMainnetReadiness(changedInitcode);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>
  blocker.code==='compiled_checkpoint_registry_initcode_mismatch'));

 const changedConfig=readyFixture();
 assert.equal(changedConfig.requirements.production_checkpoint_registry_artifacts_pinned,true);
 changedConfig.releaseConfig.checkpointRegistryConfigHash='0x'+'98'.repeat(32);
 report=assessMainnetReadiness(changedConfig);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>
  blocker.code==='release_checkpoint_registry_config_hash_mismatch'));
});

test('checkpoint ledger reports reject coordinated semantic B under report bytes A',()=>{
 const registry=readyFixture();
 registry.checkpointRegistryArtifactPinsReport={...registry.checkpointRegistryArtifactPinsReport,
  compilerVersion:'solc-test-b'};
 registry.checkpointRegistryArtifactPinsAuthority={...registry.checkpointRegistryArtifactPinsAuthority,
  binding:{...registry.checkpointRegistryArtifactPinsAuthority.binding,compilerVersion:'solc-test-b'}};
 let report=assessMainnetReadiness(registry);
 assert(report.blockers.some(({code})=>code==='checkpoint_registry_artifact_pins_report_invalid'));

 const randomx=readyFixture();
 const receiptBytes=randomx.checkpointRandomxImageRatificationAuthority.receiptBytes[0];
 const index={...JSON.parse(randomx.checkpointRandomxImageRatificationAuthority.receiptIndexBytes),
  receipt_count:2,receipts:[
   {index:0,receipt_file:'randomx-receipt-0000.bin',receipt_sha256:documentSha(receiptBytes),receipt_bytes:receiptBytes.length},
   {index:1,receipt_file:'randomx-receipt-0001.bin',receipt_sha256:documentSha(receiptBytes),receipt_bytes:receiptBytes.length},
  ]};
 const indexBytes=Buffer.from(JSON.stringify(index));
 randomx.checkpointRandomxImageRatificationReport={...randomx.checkpointRandomxImageRatificationReport,
  receiptIndexSha256:documentSha(indexBytes),receiptCount:2};
 randomx.checkpointRandomxImageRatificationAuthority={...randomx.checkpointRandomxImageRatificationAuthority,
  receiptIndexBytes:indexBytes,receiptBytes:[receiptBytes,receiptBytes]};
 report=assessMainnetReadiness(randomx);
 assert(report.blockers.some(({code})=>code==='checkpoint_randomx_image_ratification_invalid'));

 const restart=readyFixture();
 restart.checkpointRestartWitnessReport={...restart.checkpointRestartWitnessReport,
  firstProcessPid:102,secondProcessPid:103};
 report=assessMainnetReadiness(restart);
 assert(report.blockers.some(({code})=>code==='checkpoint_restart_witness_report_invalid'));
});

test('compiled artifact failures retain their actionable local validation cause',()=>{
 const fixture=readyFixture();
 fixture.compiledReserveRuntimeCodeHash=null;
 fixture.compiledReserveInitcodeHash=null;
 fixture.compiledArtifactBindingErrors={reserve:'invalid address in release configuration'};
 const report=assessMainnetReadiness(fixture);
 for(const code of ['compiled_reserve_runtime_unavailable','compiled_reserve_initcode_unavailable']) {
  const blocker=report.blockers.find(value=>value.code===code);
  assert.ok(blocker,code);
  assert.match(blocker.detail,/binding failure: invalid address in release configuration$/);
 }

 fixture.compiledArtifactBindingErrors.reserve='invalid\nmultiline diagnostic';
 const sanitized=assessMainnetReadiness(fixture);
 assert.doesNotMatch(sanitized.blockers.find(value=>
  value.code==='compiled_reserve_runtime_unavailable').detail,/multiline/);
});
