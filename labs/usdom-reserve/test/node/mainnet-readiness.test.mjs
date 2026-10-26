import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {Interface,TypedDataEncoder,getAddress,getCreateAddress,keccak256,sha256,toUtf8Bytes} from 'ethers';
import {assessMainnetReadiness} from '../../sdk/mainnet-readiness.mjs';
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
import {rpcConsensusEvidence} from '../../sdk/rpc-consensus-evidence.mjs';
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
  RECOVERABLE_SAFE_CONTROL_SCHEMA,SAFE_MAINNET_IDENTITY,SAFE_VERSION,
} from '../../sdk/safe-control-deployment.mjs';
import {
  SAFE_CONTROL_RECOVERY_SCHEMA,SAFE_CONTROL_SNAPSHOT_SCHEMA,
  _safeControlObservationInternals,safeControlConfigurationHash,
} from '../../sdk/safe-control-observation.mjs';
import {buildRecoverableSafeControlReleaseEvidence} from '../../sdk/safe-control-release-evidence.mjs';
import {createRiscZeroHealthSourceCatalog} from '../../sdk/risc0-health-source-catalog.mjs';
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

const address=n=>'0x'+n.toString(16).padStart(40,'0');
const signingFingerprint='A'.repeat(40);
const documentSha=path=>createHash('sha256').update(path).digest('hex');
const document=path=>({path,sha256:documentSha(path)});
const bytes32=byte=>'0x'+byte.repeat(32);
function forkRehearsalFixture(releaseEvidence,releaseConfig) {
 const ids=['ethereum-reorganization','dom-reorganization','ethereum-unavailability',
  'dom-unavailability','censorship','recovery'];
 const decisions=['reject-conflicting-ethereum-finality','reject-dom-reorg-below-checkpoint-floor',
  'halt-ethereum-dependent-issuance-and-redemption','halt-checkpoint-advancement-and-redemption',
  'preserve-permissionless-retry-without-bypass','resume-only-after-release-bound-recovery-drill'];
 const evidenceFiles=Object.create(null);
 const scenarios=ids.map((id,index)=>{
  const startedAtUnix=String(1792492000+index*10),finishedAtUnix=String(1792492009+index*10);
  const preStateCommitment=bytes32((0x40+index).toString(16));
  const postRecoveryStateCommitment=bytes32((0x60+index).toString(16));
  const faultPath=`evidence/fork-rehearsal/raw/${id}-fault.json`;
  const recoveryPath=`evidence/fork-rehearsal/raw/${id}-recovery.json`;
  const faultDocument={schema:'usdom-mainnet-fork-fault-evidence-v1',scenarioId:id,
   releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
   commandId:`${id}-fault-assertion`,assertionExitCode:'0',observedDecision:decisions[index],
   preStateCommitment,faultStateCommitment:preStateCommitment,unsafeTransitionCount:'0',
   fundLossBaseUnits:'0',capturedAtUnix:startedAtUnix};
  const recoveryDocument={schema:'usdom-mainnet-fork-recovery-evidence-v1',scenarioId:id,
   releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
   commandId:`${id}-recovery-assertion`,assertionExitCode:'0',recoveryObserved:true,
   postRecoveryStateCommitment,capturedAtUnix:finishedAtUnix};
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
 ]);
 const encoded=eventInterface.encodeEventLog(eventInterface.getEvent('Checkpoint'),[
  releaseConfig.domDomain,releaseConfig.checkpointDomNetworkMagic,'100360',bytes32('c4'),
  bytes32('c5'),releaseConfig.checkpointRegistryConfigHash]);
 const state={checkpointConfigHash:releaseConfig.checkpointRegistryConfigHash,halted:false,
  gracefullyShutdown:false,latestIssuanceClosed:false,latestHeight:'100360',latestBlock:bytes32('c4'),latestStateRoot:bytes32('c5'),
  latestContextHash:bytes32('c6'),latestTotalDifficulty:'2000000',latestTotalIssued:'100',latestTotalBurned:'20',checkpointCount:'1',
  candidateStatementHash:'0x'+'00'.repeat(32)};
 const observations=[1,2].map(index=>({operatorId:`operator-${index}`,
  originKeccak256:bytes32(`d${index}`),chainId:'1',transactionHash:bytes32('c7'),
  receiptStatus:'1',blockNumber:'22000000',blockHash:bytes32('c8'),
  blockTimestamp:'1792490200',finalizedHeadNumber:'22000010',finalizedHeadHash:bytes32('c9'),
  snapshotBlockHashAfter:bytes32('c8'),
  registryRuntimeCodeHash:releaseConfig.checkpointRegistryRuntimeCodeHash,
  checkpointEventCount:'1',log:{address:releaseConfig.checkpointRegistry,logIndex:'2',
   topics:encoded.topics.map(value=>value.toLowerCase()),data:encoded.data.toLowerCase()},
  state:{...state}}));
 const sourceSetCommitment=keccak256(toUtf8Bytes(
  `USDOM_CHECKPOINT_FINALIZED_EVENT_RPC_SOURCES_V2\n${observations.map(value=>
    `${value.operatorId}\u0000${value.originKeccak256}`).join('\n')}`));
 const observation={schema:'usdom-checkpoint-finalized-event-observation-v2',
  releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
  sourceTag:releaseEvidence.sourceTag,ethereumChainId:'1',transactionHash:bytes32('c7'),
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
  snapshotBlockHashAfter:bytes32('70'),deployerNonce:config.deployerNonce,
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
  blockNumber:'21999997',blockHash:bytes32('75'),
  canonicalBlockHash:bytes32('75'),transactionHash:bytes32('76'),to:null,value:'0',
  inputHash:config.verifierInitcodeHash};
 observation.checkpointVerifierDeployment={status:true,from:config.checkpointVerifierDeployer,
  nonce:config.checkpointVerifierDeployerNonce,creates:config.checkpointVerifier,
  derivedCreateAddress:config.checkpointVerifier,
  blockNumber:'21999996',blockHash:bytes32('77'),canonicalBlockHash:bytes32('77'),
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
  outflowCapacity:config.outflowCapacityBaseUnitsPerDay,paused:true,depositsClosed:false,
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
function preflightAttestation(config,phase) {
 const observation=preflightObservation(config,phase);
 return {...assessMainnetPreflight({phase,releaseConfig:config,observation,
  riscZeroReference:{...PINNED_RISC0_MAINNET_V3}}),observation,
  rpcConsensus:rpcConsensusEvidence([
   {sourceId:'operator-a',originKeccak256:bytes32('81')},
   {sourceId:'operator-b',originKeccak256:bytes32('82')},
  ])};
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
 const ownersByRole={governance:[101,102,103].map(value=>getAddress(address(value))),
  reserveGuardian:[104,105,106].map(value=>getAddress(address(value))),
  checkpointGuardian:[107,108,109].map(value=>getAddress(address(value)))};
 const replacements={governance:getAddress(address(110)),reserveGuardian:getAddress(address(111)),
  checkpointGuardian:getAddress(address(112))};
 const controls=[
  {role:'governance',safe:getAddress(config.governance)},
  {role:'reserveGuardian',safe:getAddress(config.guardian)},
  {role:'checkpointGuardian',safe:getAddress(config.checkpointGuardian)},
 ];
 const packageDocument={schema:RECOVERABLE_SAFE_CONTROL_SCHEMA,ethereumChainId:'1',
  safeVersion:SAFE_VERSION,threshold:'2',ownersByRole,controls};
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
  trustedSetupTranscriptSha256:'0x'+documentSha('evidence/risc0-groth16-ceremony-transcript.txt'),
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
  trustedSetupTranscriptSha256:'0x'+documentSha('evidence/risc0-groth16-ceremony-transcript.txt'),
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
 'production_recoverable_safe_control_signing_inputs_rechecked_per_ledger_action',
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
 'production_release_authorization_signing_inputs_rechecked_per_ledger_action',
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
 'production_safe_recovery_executor_relayer_derived_from_ledger',
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
function readyFixture(mode='closed-mainnet') {
 const base=deployment();
 const governanceOwners=[110,102,103].map(value=>getAddress(address(value)));
 const guardianOwners=[111,105,106].map(value=>getAddress(address(value)));
 const checkpointGuardianOwners=[112,108,109].map(value=>getAddress(address(value)));
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
 const verifierDeployer=address(16),verifierDeployerNonce='2';
 base.verifier=getCreateAddress({from:verifierDeployer,nonce:2});
 const deployer=address(15),deployerNonce='7';
 base.reserve=getCreateAddress({from:deployer,nonce:7});
 const checkpointVerifierDeployer=address(17),checkpointVerifierDeployerNonce='3';
 const checkpointVerifier=getCreateAddress({from:checkpointVerifierDeployer,nonce:3});
 const checkpointRegistryDeployer=address(14),checkpointRegistryDeployerNonce='4';
 const checkpointRegistry=getCreateAddress({from:checkpointRegistryDeployer,nonce:4});
 base.domDomain=deriveDomDomain({domNetworkMagic:'1146047793',
  domChainId:verifierConfig.domChainId,ethereumChainId:base.ethereumChainId,
  reserve:base.reserve,checkpointRegistry});
 const reserveDeployment={...base,checkpointRegistry,
  checkpointRegistryRuntimeCodeHash:'0x'+'93'.repeat(32)};
 Object.assign(base,{checkpointRegistryDeployer,checkpointRegistryDeployerNonce,checkpointRegistry,
  checkpointVerifier,checkpointVerifierCodeHash:'0x'+'21'.repeat(32),
  checkpointVerifierConfigHash:finalizedCheckpointVerifierConfig.verifierConfigHash,
  checkpointGuardian:address(12),
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
  realFundsAuthorized:mode==='real-funds',nativeRelaySafetyMarginSeconds:'3600',
  nativeMaxEthereumAnchorAgeSeconds:'1800',nativeMaxDomClockLeadSeconds:'120'};
 const requirements=Object.fromEntries(requiredKeys.map(key=>[key,true]));
 Object.assign(requirements,{deploy_authorized:true,mainnet_ready:true,real_funds_authorized:true,
  native_burn_state_witness_authorizes_consensus_or_payout:false,
  native_burn_block_prover_input_proves_finality:false,
  production_withdrawal_queue_lease_period_seconds:604800,
  finality_evaluation:{selected_production_mechanism:'ethereum-checkpoint-finality'},
  checkpoint_poc_authorization:{production_mechanism_approved:true}});
 const operatorIntent={schema:1,network:'Ethereum mainnet',chainId:'1',token:{},
  prototype_trust_model:'prototype',production_trust_model:'production',
  local_test_values_not_approved_for_production:{},authority:'operator',native_asset_requirements:{},
  current_phase:'release',release_assurance_policy:{},finality_direction:'checkpoint',
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
 const safeRecoveryFinalBundle={schema:'usdom-safe-recovery-evidence-bundle/v1',
  ethereumChainId:'1',packageDocumentSha256:'1'.repeat(64),
  packageHash:controlPlaneEvidence.packageHash,baselineDocumentSha256:'2'.repeat(64),
  planDocumentSha256:'3'.repeat(64),transactionPackageDocumentSha256:'4'.repeat(64),
  rpcCatalogSha256:'5'.repeat(64),executions:controlPlaneEvidence.recoveryDrillReport.roles.map(
   (role,index)=>({role:role.safeRole,documentSha256:String(index+6).repeat(64),
    transactionHash:role.transactionHash})),reportDocumentSha256:'9'.repeat(64),
  recoveryHash:controlPlaneEvidence.recoveryHash};
 const evidence={schema:1,releaseId:'release-1',sourceCommit:'a'.repeat(40),sourceTag:'usdom-v1.0.0',
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
   transcript:document('evidence/risc0-groth16-ceremony-transcript.txt')},
  checkpointTrustedSetup:{required:true,
   decisionReport:document('evidence/checkpoint-setup-decision.txt'),
   transcript:document('evidence/risc0-groth16-ceremony-transcript.txt')},
  checkpointProofCapacityReport:null,
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
  'checkpoint-setup-decision','risc0-groth16-ceremony-transcript',
  'operations','fork','security-validation','residual-risk-acceptance','cold-start',
  'predeployment',
 ].map(name=>{
  const path=`evidence/${name}.txt`;
  return [path,documentSha(path)];
 }));
 evidenceFiles['evidence/verifier-config.json']=verifierConfigManifestSha256;
 evidenceFiles['evidence/checkpoint-verifier-config.json']=checkpointVerifierConfigManifestSha256;
 evidenceFiles['evidence/risc0-health-sources.json']=documentSha('evidence/risc0-health-sources.json');
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
 const capacityLayer=(name,programSha256,imageId,index)=>({name,programSha256,imageId,
  inputSetSha256:(0x10+index).toString(16).repeat(32),inputBytes:'4096',
  journalSetSha256:(0x20+index).toString(16).repeat(32),journalBytes:'32',journalCount:'1',
  receiptSetSha256:(0x30+index).toString(16).repeat(32),receiptBytes:'8192',receiptCount:'1',
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
   capacityLayer('randomx',CHECKPOINT_RANDOMX_PROGRAM_SHA256,CHECKPOINT_RANDOMX_IMAGE_ID,0),
   capacityLayer('randomx-aggregate',CHECKPOINT_RANDOMX_AGGREGATE_PROGRAM_SHA256,
    CHECKPOINT_RANDOMX_AGGREGATE_IMAGE_ID,1),
   capacityLayer('economic-chunk',CHECKPOINT_ECONOMIC_CHUNK_PROGRAM_SHA256,
    CHECKPOINT_ECONOMIC_CHUNK_IMAGE_ID,2),
   capacityLayer('economic-block',CHECKPOINT_ECONOMIC_BLOCK_PROGRAM_SHA256,
    CHECKPOINT_ECONOMIC_BLOCK_IMAGE_ID,3),
   capacityLayer('segment',CHECKPOINT_SEGMENT_PROGRAM_SHA256,CHECKPOINT_SEGMENT_IMAGE_ID,4),
   capacityLayer('outer',checkpointVerifierConfig.provingProgramSha256.slice(2),
    checkpointVerifierConfig.checkpointGuestImageId.slice(2),5),
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
 const capacityPath='evidence/checkpoint-proof-capacity.json';
 const capacitySha=createHash('sha256').update(
  JSON.stringify(checkpointProofCapacityReport),
 ).digest('hex');
 evidence.checkpointProofCapacityReport={path:capacityPath,sha256:capacitySha};
 evidenceFiles[capacityPath]=capacitySha;
 for(const path of ['evidence/native-privacy-setup.json','evidence/native-runtime-activation.json',
  'evidence/native-wallet-custody.json','evidence/native-wallet-recovery.json']) {
  evidenceFiles[path]=documentSha(path);
 }
 for(const path of [
  'evidence/control-plane/governance-configuration.json',
  'evidence/control-plane/guardian-configuration.json',
  'evidence/control-plane/checkpoint-guardian-configuration.json',
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
 const contractSource=`
 bytes32 public constant PRODUCTION_VERIFIER_CODE_HASH = ${base.verifierCodeHash};
 bytes32 public constant PRODUCTION_VERIFIER_CONFIG_HASH = ${base.verifierConfigHash};
 bytes32 public constant PRODUCTION_RESERVE_PREACTIVATION_CONFIG_HASH = ${computed.reservePreActivationConfigHash};`;
 const checkpointContractSource=`
 bytes32 public constant PRODUCTION_VERIFIER_CODE_HASH = ${base.checkpointVerifierCodeHash};
 bytes32 public constant PRODUCTION_VERIFIER_CONFIG_HASH = ${base.checkpointVerifierConfigHash};
 bytes32 public constant PRODUCTION_CHECKPOINT_CONFIG_HASH = ${checkpointConfig.checkpointConfigHash};`;
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
  privacy_policy_hash:'83'.repeat(32),privacy_verifier_config_hash:'84'.repeat(32),
  withdrawal_delay_secs:base.withdrawalDelaySeconds,min_execution_window_secs:'3600',
  max_certificate_lifetime_secs:'604800',relay_safety_margin_secs:'3600',
  max_ethereum_anchor_age_secs:'1800',max_dom_clock_lead_secs:'120',
  spend_verifying_key_sha256:evidence.nativeRuntimeSpendVerifyingKeyArtifact.sha256};
 const nativePrivacyTrustedSetupAttestation=nativeReleaseAttestation(
  'native-privacy-trusted-setup',releaseConfig,`0x${nativeRuntimeValidation.privacy_verifier_config_hash}`);
 const nativeScheduledRuntimeActivationAttestation=nativeReleaseAttestation(
  'native-scheduled-runtime-activation',releaseConfig,`0x${evidence.nativeRuntimeManifest.sha256}`);
 const nativeWalletCustodyAttestation=nativeReleaseAttestation(
  'native-wallet-custody',releaseConfig,bytes32('a2'));
 const nativeWalletRecoveryAttestation=nativeReleaseAttestation(
  'native-wallet-recovery',releaseConfig,bytes32('a2'));
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
  compilerExecutableSha256:documentSha('solc compiler executable'),
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
  compilerExecutableSha256:documentSha('solc compiler executable'),
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
  compilerExecutableSha256:documentSha('solc compiler executable'),
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
  compilerExecutableSha256:documentSha('solc compiler executable'),
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
  releaseConfig,verifierConfig,checkpointVerifierConfig});
 const trustedSetupDecisionPath=evidence.trustedSetup.decisionReport.path;
 const trustedSetupDecisionSha=createHash('sha256').update(
  serializeTrustedSetupDecisionReport(trustedSetupDecisionReport)).digest('hex');
 evidence.trustedSetup.decisionReport.sha256=trustedSetupDecisionSha;
 evidence.checkpointTrustedSetup.decisionReport={...evidence.trustedSetup.decisionReport};
 evidenceFiles[trustedSetupDecisionPath]=trustedSetupDecisionSha;
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
 return {mode,requirements,operatorIntent,releaseConfig,evidence,evidenceFiles,repositoryState,contractSource,
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
  predeploymentAttestation:preflightAttestation(releaseConfig,'predeployment'),
  coldStartAttestation:preflightAttestation(releaseConfig,'postdeployment'),
  nativePrivacyTrustedSetupAttestation,nativeScheduledRuntimeActivationAttestation,
  nativeWalletCustodyAttestation,nativeWalletRecoveryAttestation,
  nativeAttestationApprovalObservation:nativeApprovalObservation(requiredNativeAttestations,releaseConfig),
  releaseAuthorizationApprovalObservation:releaseAuthorizationObservation(
    operatorIntent.residual_risk_acceptance,releaseConfig),
  nativeRuntimeValidation,
  riscZeroHealthSourceCatalog,finalizedBurnE2eReport,checkpointProofCapacityReport,
  securityValidationReport,requirementsSha256,sourceManifestSha256,
  operationsReviewReport,operatorRunbookSha256,
  reserveReproducibleBuildReport,verifierReproducibleBuildReport,
  mainnetForkRehearsalReport,mainnetForkRehearsalEvidenceFiles:forkRehearsal.evidenceFiles,
  checkpointBootstrapRatificationReport,
  ethereumCheckpointConsensus:checkpointRatification.checkpointConsensus,
  nativePreactivationFacts:checkpointRatification.nativeFacts,
  checkpointFinalizedEventReport,
  checkpointVerifierReproducibleBuildReport,
  checkpointRegistryReproducibleBuildReport,
  residualRiskReport,residualRiskDraftSha256,
  trustedSetupDecisionReport,
  controlPlaneEvidenceArtifacts:{bundle:controlPlaneEvidence,
   roleReports:structuredClone(controlPlaneEvidence.roleReports),
   separationReport:structuredClone(controlPlaneEvidence.separationReport),
   recoveryDrillReport:structuredClone(controlPlaneEvidence.recoveryDrillReport),
   finalBundle:safeRecoveryFinalBundle}};
}

test('configured hash-addressed evidence can satisfy both fail-closed release modes',()=>{
 for(const mode of ['closed-mainnet','real-funds']) {
  const report=assessMainnetReadiness(readyFixture(mode));
  assert.equal(report.ready,true,JSON.stringify(report.blockers));
  assert.equal(report.blockerCount,0);
 }
});

test('release gate enforces the deterministic production DOM domain',()=>{
 const fixture=readyFixture();
 fixture.releaseConfig.domDomain=bytes32('99');
 const report=assessMainnetReadiness(fixture);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>blocker.code==='release_dom_domain_derivation_mismatch'));
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
  fixture=>{const decision=fixture.evidence.checkpointTrustedSetup.decisionReport;
   fixture.evidence.checkpointTrustedSetup.decisionReport={...decision,
    path:'evidence/other-decision.txt'};
   fixture.evidenceFiles['evidence/other-decision.txt']=decision.sha256;},
 ]) {
  const fixture=readyFixture();
  fixture.trustedSetupDecisionReport=structuredClone(fixture.trustedSetupDecisionReport);
  mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false);
  assert(report.blockers.some(blocker=>blocker.code==='trusted_setup_decision_report_invalid'));
 }
});

test('offline release signer rederives the exact owner-bound EIP-712 request',()=>{
 const fixture=readyFixture();
 const authorization={...fixture.operatorIntent.residual_risk_acceptance,signature:null};
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
  bundleSha256:fixture.evidence.controlPlaneEvidenceBundle.sha256,
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
  assert.throws(()=>validateReleaseAuthorizationSigningRequest(changed));
 }
});

test('offline native signer independently derives all four artifact-bound requests',()=>{
 const fixture=readyFixture('real-funds');
 const subjects={nativePrivacyTrustedSetup:`0x${fixture.nativeRuntimeValidation.privacy_verifier_config_hash}`,
  nativeScheduledRuntimeActivation:`0x${fixture.evidence.nativeRuntimeManifest.sha256}`,
  nativeWalletCustody:bytes32('a2'),nativeWalletRecovery:bytes32('a2'),
  walletPublicIdentitySha256:'a2'.repeat(32)};
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
 const request={schema:'usdom-native-release-attestation-requests/v2',
  releaseId:fixture.evidence.releaseId,sourceCommit:fixture.evidence.sourceCommit,
  finalizedAnchor:{blockNumber:'22000000',blockHash:bytes32('70'),blockTimestamp:'1792492800',
   governance:fixture.releaseConfig.governance,
   governanceCodeHash:fixture.releaseConfig.governanceCodeHash,
   rpcConsensus:rpcConsensusEvidence([{sourceId:'operator-a',originKeccak256:bytes32('81')},
    {sourceId:'operator-b',originKeccak256:bytes32('82')}])},subjects,requests};
 const inputs={request,bundle:fixture.controlPlaneEvidenceArtifacts.bundle,
  bundleSha256:fixture.evidence.controlPlaneEvidenceBundle.sha256,
  releaseConfig:fixture.releaseConfig,releaseEvidence:fixture.evidence,
  privacyVerifierConfigHash:fixture.nativeRuntimeValidation.privacy_verifier_config_hash,
  nativeRuntimeManifestSha256:fixture.evidence.nativeRuntimeManifest.sha256,
  walletPublicIdentitySha256:'a2'.repeat(32)};
 assert.equal(Object.keys(validateNativeReleaseAttestationSigningRequest(inputs).digests).length,4);
 const mutations=[
  value=>{value.request.requests.nativeWalletCustody.digest=bytes32('99');},
  value=>{value.request.requests.nativePrivacyTrustedSetup.typedData.message.subjectCommitment=bytes32('99');},
  value=>{value.request.subjects.nativeWalletRecovery=bytes32('99');},
  value=>{value.walletPublicIdentitySha256='9'.repeat(64);},
  value=>{value.nativeRuntimeManifestSha256='9'.repeat(64);},
  value=>{value.privacyVerifierConfigHash='9'.repeat(64);},
  value=>{value.bundleSha256='9'.repeat(64);},
  value=>{value.request.finalizedAnchor.blockNumber='022000000';},
  value=>{value.request.finalizedAnchor.rpcConsensus.sourceSetCommitment=bytes32('99');},
  value=>{value.releaseConfig.governanceOwners.reverse();},
 ];
 for(const mutate of mutations) {
  const changed=structuredClone(inputs); mutate(changed);
  assert.throws(()=>validateNativeReleaseAttestationSigningRequest(changed));
 }
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

test('finalized-burn E2E materialization is fixed, canonical and evidence-only',()=>{
 const fixture=readyFixture();
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
 collision.evidence.operationsReviewReport={path:FINALIZED_BURN_E2E_EVIDENCE_PATH,
  sha256:'ab'.repeat(32)};
 assert.throws(()=>prepareFinalizedBurnReleaseEvidenceMaterialization({
  report:collision.finalizedBurnE2eReport,evidence:collision.evidence,
  releaseConfig:collision.releaseConfig,verifierConfig:collision.verifierConfig,
  riscZeroReference:collision.riscZeroReference,
 }));
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
  fixture.residualRiskReport=buildResidualRiskReport({
   releaseEvidence:fixture.evidence,releaseConfig:fixture.releaseConfig,
   requirements:fixture.requirements,draftSha256:fixture.residualRiskDraftSha256,
  });
  const residualRiskSha=createHash('sha256').update(
   serializeResidualRiskReport(fixture.residualRiskReport)).digest('hex');
  fixture.evidence.residualRiskAcceptanceReport.sha256=residualRiskSha;
  fixture.evidenceFiles[fixture.evidence.residualRiskAcceptanceReport.path]=residualRiskSha;
  fixture.operatorIntent.residual_risk_acceptance.reportSha256=residualRiskSha;
  fixture.operatorIntent.residual_risk_acceptance.releaseEvidenceCommitment=
   releaseEvidenceCommitment(fixture.evidence);
  fixture.releaseAuthorizationApprovalObservation=releaseAuthorizationObservation(
   fixture.operatorIntent.residual_risk_acceptance,fixture.releaseConfig);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,true,JSON.stringify(report.blockers));
  assert.equal(report.blockerCount,0);
 }
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
 const report=assessMainnetReadiness(fixture);
 assert.equal(report.ready,false);
 assert(report.blockers.some(blocker=>blocker.code==='operator_release_signing_key_mismatch'));
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
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,expected);
  assert(report.blockers.some(blocker=>blocker.code===expected),JSON.stringify(report.blockers));
 }
 const allowed=readyFixture();
 allowed.repositoryState.releaseEvidenceChanges.push(
  {status:'A',path:'labs/usdom-reserve/evidence/new-attestation.json'},
  {status:'M',path:'labs/usdom-reserve/evidence/existing-report.txt'});
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
   'release_governance_owners_invalid'],
  [fixture=>{fixture.releaseConfig.governanceOwners[2]=fixture.releaseConfig.governanceOwners[1];},
   'release_governance_owners_invalid'],
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
  [fixture=>{fixture.operatorIntent.residual_risk_acceptance.acceptedAt='1792492901';
    fixture.releaseAuthorizationApprovalObservation.approvals.releaseAuthorization.digest=
      releaseAuthorizationDigest(fixture.operatorIntent.residual_risk_acceptance,
        fixture.releaseConfig);},'release_authorization_after_finalized_snapshot'],
 ];
 for(const [mutate,code] of cases) {
  const fixture=readyFixture(); mutate(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,code);
  assert(report.blockers.some(blocker=>blocker.code===code),JSON.stringify(report.blockers));
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
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,code);
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
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,code);
  assert(report.blockers.some(blocker=>blocker.code===code),code);
 }
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
  assert(report.blockers.some(blocker=>blocker.code===`risc0_${field}_adapter_mismatch`),field);
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
 assert(report.blockers.some(blocker=>blocker.code==='risc0_finalized_burn_riscZeroVerifier_untrusted'));
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
  evidence,evidenceFiles:{},contractSource,checkpointContractSource});
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
