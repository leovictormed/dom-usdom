import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {getCreateAddress} from 'ethers';
import {assessMainnetReadiness} from '../../sdk/mainnet-readiness.mjs';
import {proofReserveDeploymentConfigHash} from '../../sdk/configuration.mjs';
import {BURN_INTENT_TYPEHASH,BURN_STATEMENT_TYPEHASH,PRIVATE_BURN_ID_TYPEHASH} from '../../sdk/proof-reserve.mjs';
import {
 FINALIZED_BURN_PROOF_SYSTEM,FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,
 FINALIZED_BURN_RISC0_JOURNAL_SCHEMA_HASH,VERIFIER_CONFIG_SCHEMA,finalizedBurnVerifierConfigHash,
} from '../../sdk/verifier-config.mjs';
import {checkpointRegistryConfigHash} from '../../sdk/checkpoint-registry.mjs';
import {activationSchedule} from '../../sdk/activation-schedule.mjs';
import {
 CHECKPOINT_PROOF_ACCEPTED_HASH,CHECKPOINT_PROOF_SYSTEM,CHECKPOINT_RANDOMX_STATEMENT_DOMAIN_HASH,
 CHECKPOINT_RISC0_GROTH16_V3_SELECTOR,CHECKPOINT_RISC0_JOURNAL_SCHEMA_HASH,
 CHECKPOINT_SEGMENT_STATE_DOMAIN_HASH,CHECKPOINT_SEGMENT_TRANSITION_DOMAIN_HASH,
 CHECKPOINT_VERIFIER_CONFIG_SCHEMA,checkpointVerifierConfigHash,
} from '../../sdk/checkpoint-verifier-config.mjs';
import {CHECKPOINT_STATEMENT_TYPEHASH} from '../../sdk/checkpoint-registry.mjs';
import {PINNED_RISC0_MAINNET_V3} from '../../sdk/risc0-verifier-reference.mjs';
import {assessMainnetPreflight} from '../../sdk/mainnet-preflight.mjs';
import {nativeReleaseAttestationDigest} from '../../sdk/native-release-attestation.mjs';

const address=n=>'0x'+n.toString(16).padStart(40,'0');
const signingFingerprint='A'.repeat(40);
const documentSha=path=>createHash('sha256').update(path).digest('hex');
const document=path=>({path,sha256:documentSha(path)});
const bytes32=byte=>'0x'+byte.repeat(32);
const deployment=()=>({
 ethereumChainId:'1',reserve:address(9),token:'0xdAC17F958D2ee523a2206206994597C13D831ec7',
 tokenCodeHash:'0x'+'10'.repeat(32),verifier:address(8),verifierCodeHash:'0x'+'20'.repeat(32),
 verifierConfigHash:'0x'+'30'.repeat(32),domDomain:'0x'+'40'.repeat(32),
 activationScheduleCommitment:'0x'+'42'.repeat(32),governance:address(7),
 governanceCodeHash:'0x'+'50'.repeat(32),guardian:address(6),guardianCodeHash:'0x'+'60'.repeat(32),
 withdrawalDelaySeconds:'86400',governanceDelaySeconds:'172800',
 maxOutstandingBaseUnits:'100000000000',outflowCapacityBaseUnitsPerDay:'2000000000',
});
function preflightObservation(config,phase) {
 const observation={chainId:'1',finalizedBlockNumber:'22000000',finalizedBlockHash:bytes32('70'),
  snapshotBlockHashAfter:bytes32('70'),deployerNonce:config.deployerNonce,
  checkpointRegistryDeployerNonce:config.checkpointRegistryDeployerNonce,
  codeHashes:{reserve:phase==='postdeployment'?config.reserveRuntimeCodeHash
    :'0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
   token:config.tokenCodeHash,verifier:config.verifierCodeHash,governance:config.governanceCodeHash,
   guardian:config.guardianCodeHash,
   checkpointRegistry:phase==='postdeployment'?config.checkpointRegistryRuntimeCodeHash
    :'0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
   checkpointVerifier:config.checkpointVerifierCodeHash,
   checkpointGuardian:config.checkpointGuardianCodeHash},
  verifierConfigHash:config.verifierConfigHash,checkpointVerifierConfigHash:config.checkpointVerifierConfigHash,
  riscZeroVerifier:{address:PINNED_RISC0_MAINNET_V3.verifier_address,
   codeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
   selector:PINNED_RISC0_MAINNET_V3.verifier_selector,version:PINNED_RISC0_MAINNET_V3.verifier_version},
  riscZeroEmergencyStop:{address:PINNED_RISC0_MAINNET_V3.emergency_stop_wrapper_address,
   codeHash:PINNED_RISC0_MAINNET_V3.emergency_stop_wrapper_runtime_code_hash,
   paused:false,verifier:PINNED_RISC0_MAINNET_V3.verifier_address},
  token:{decimals:'6',paused:false,deprecated:false,basisPointsRate:'0',maximumFee:'0',
   reserveBlacklisted:false,reserveBalance:'0'}};
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
  guardianCodeHash:config.guardianCodeHash,withdrawalDelay:config.withdrawalDelaySeconds,
  governanceDelay:config.governanceDelaySeconds,maxOutstanding:config.maxOutstandingBaseUnits,
  outflowCapacity:config.outflowCapacityBaseUnitsPerDay,paused:true,queueEpoch:'1',resumeReadyAt:'0',
  totalDeposited:'0',totalReleased:'0',totalPendingAmount:'0',pendingCount:'0'};
 observation.checkpointRegistry={checkpointConfigHash:config.checkpointRegistryConfigHash,
  bridgeDomain:config.domDomain,domNetworkMagic:config.checkpointDomNetworkMagic,
  domChainId:config.checkpointDomChainId,firstV4Height:config.checkpointFirstV4Height,
  activationEmptyStateRoot:config.checkpointActivationEmptyStateRoot,
  activationScheduleCommitment:config.activationScheduleCommitment,verifier:config.checkpointVerifier,
  checkpointInterval:config.checkpointIntervalBlocks,confirmationDepth:config.checkpointConfirmationDepthBlocks,
  challengePeriod:config.checkpointChallengePeriodSeconds,verifierCodeHash:config.checkpointVerifierCodeHash,
  verifierConfigHash:config.checkpointVerifierConfigHash,guardian:config.checkpointGuardian,
  guardianCodeHash:config.checkpointGuardianCodeHash,latestHeight:config.checkpointInitialHeight,
  checkpointCount:'1',halted:false,latestBlock:config.checkpointInitialBlock,
  latestStateRoot:config.checkpointInitialStateRoot,latestContextHash:config.checkpointInitialContextHash,
  latestTotalDifficulty:config.checkpointInitialTotalDifficulty};
 observation.checkpointRegistryCandidate={statementHash:bytes32('00'),height:'0',readyAt:'0',
  blockHash:bytes32('00'),stateRoot:bytes32('00'),contextHash:bytes32('00'),totalDifficulty:'0',
  confirmationHeight:'0',confirmationBlock:bytes32('00'),confirmationTotalDifficulty:'0',
  confirmationTimestamp:'0'};
 observation.checkpointRegistrySlot0=config.checkpointRegistryConfigHash;
 return observation;
}
function preflightAttestation(config,phase) {
 const observation=preflightObservation(config,phase);
 return {...assessMainnetPreflight({phase,releaseConfig:config,observation,
  riscZeroReference:{...PINNED_RISC0_MAINNET_V3}}),observation};
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
  snapshotBlockHashAfter:bytes32('70')};
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
  trustedSetupRequired:false,trustedSetupTranscriptSha256:bytes32('00'),
  provingProgramSha256:'0x'+documentSha('evidence/proving-program.bin'),
  sourceManifestSha256:'0x'+documentSha('evidence/proving-program-sources.sha256'),
  verifierArtifactSha256:'0x'+documentSha(
    'out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json'),
  maxProofBytes:'65536',minimumFinalityBeaconSlot:'12000000',ethereumChainId:'1',
  riscZeroVerifier:PINNED_RISC0_MAINNET_V3.verifier_address,
  riscZeroVerifierCodeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
  riscZeroVerifierSelector:FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,
  finalizedBurnGuestImageId:bytes32('1d'),journalSchemaHash:FINALIZED_BURN_RISC0_JOURNAL_SCHEMA_HASH};
}
function checkpointVerifierManifest(activationScheduleCommitment) {
 return {schema:CHECKPOINT_VERIFIER_CONFIG_SCHEMA,statementVersion:'4',checkpointProverInputVersion:'4',
  continuationContextVersion:'2',
  transitionCommitmentVersion:'3',activationScheduleVersion:'2',publicOutputVersion:'1',
  publicStatementBytes:'518',continuationContextBytes:'695',checkpointStatementTypeHash:CHECKPOINT_STATEMENT_TYPEHASH,
  segmentStateVersion:'2',segmentTransitionVersion:'2',randomxStatementVersion:'1',
  segmentStateBytes:'1105',segmentTransitionBytes:'2254',randomxStatementBytes:'384',
  segmentStateDomainHash:CHECKPOINT_SEGMENT_STATE_DOMAIN_HASH,
  segmentTransitionDomainHash:CHECKPOINT_SEGMENT_TRANSITION_DOMAIN_HASH,
  randomxStatementDomainHash:CHECKPOINT_RANDOMX_STATEMENT_DOMAIN_HASH,
  randomxReceiptImageId:bytes32('1a'),
  proofAcceptedHash:CHECKPOINT_PROOF_ACCEPTED_HASH,activationScheduleCommitment,
  domGenesisHash:bytes32('01'),domNetworkMagic:'1146047793',domChainId:bytes32('02'),
  firstV4Height:'100000',activationEmptyStateRoot:bytes32('44'),checkpointInterval:'360',
  confirmationDepth:'30',challengePeriod:'172800',maxCheckpointSpan:'390',
  consensusRulesHash:bytes32('11'),forkChoiceRulesHash:bytes32('12'),powRulesHash:bytes32('13'),
  nativeStateRulesHash:bytes32('14'),continuationContextRulesHash:bytes32('19'),
  consensusExtensionWitnessRulesHash:bytes32('15'),
  proofSystem:CHECKPOINT_PROOF_SYSTEM,
  verifyingKeySha256:'0x'+documentSha('evidence/checkpoint-verifying-key.bin'),trustedSetupRequired:false,
  trustedSetupTranscriptSha256:bytes32('00'),
  provingProgramSha256:'0x'+documentSha('evidence/checkpoint-proving-program.bin'),
  sourceManifestSha256:'0x'+documentSha('evidence/checkpoint-proving-program-sources.sha256'),
  verifierArtifactSha256:'0x'+documentSha(
    'out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json'),
  maxProofBytes:'65536',
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
 'production_checkpoint_guest_randomx_relation_implemented',
 'production_checkpoint_randomx_proof_receipt_implemented',
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
 'production_checkpoint_outer_guest_adapter_configured',
];
const proofOperationalCapacityRequiredKeys=[
 'production_finalized_burn_proving_capacity_measured',
 'production_finalized_burn_evm_verification_gas_measured',
 'production_checkpoint_outer_evm_verification_gas_measured',
];
const productionActivationAndPrivacyRequiredKeys=[
 'native_privacy_trusted_setup_ceremony_completed',
 'native_scheduled_public_runtime_configured',
 'production_native_release_attestation_content_revalidated',
 'production_native_attestation_eip1271_finalized_approval_enforced',
];
const realFundsCustodyRequiredKeys=[
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
 'native_consensus_implemented','consensus_proof_implemented','production_block_header_state_commitment_implemented',
 'production_finalized_burn_verifier_implemented',
 'production_finalized_burn_proof_backend_selected','production_finalized_burn_guest_compiled',
 'production_finalized_burn_guest_benchmarked','production_finalized_burn_raw_checkpoint_positive_vector',
 'production_finalized_burn_risc0_evm_receipt_verifier_implemented',
 'production_finalized_burn_canonical_replay_slot_enforced',
 'production_finalized_burn_positive_evidence_checker_implemented',
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
 'production_checkpoint_registry_artifacts_pinned','production_checkpoint_registry_bootstrap_ratified',
 'production_checkpoint_registry_positive_finalized_event_vector',
 ...checkpointProofRequiredKeys,
 ...checkpointReceiptCompletionRequiredKeys,
 'verified_ethereum_checkpoint_native_burn_binding_enforces_dom_fork_choice',
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
 'production_safe_control_unsigned_hardware_deployment_package_implemented',
 'production_adapter_deployment_receipts_release_bound',
 'production_predeployment_adapter_receipts_release_bound',
 'production_deployment_receipt_contract_address_observed',
 'native_private_mining_real_finalized_deposit_vector_implemented','production_activation_schedule_implemented',
 'production_reserve_config_hash_configured','solidity_production_contract_lint_clean',
 'solidity_deep_fuzz_and_invariants_passed','proof_reserve_exact_deployment_commitment_implemented',
 'proof_reserve_mainnet_initial_pause_implemented',
 'production_control_plane_recovery_drill_passed','production_mainnet_predeployment_preflight_passed',
 'native_private_wallet_key_management_implemented',
 'native_private_wallet_production_monotonic_seal_authority_integrated',
 ...realFundsCustodyRequiredKeys,
 'native_private_wallet_remote_historical_deposit_rescan_implemented','native_private_wallet_history_finality_claimed',
];
function readyFixture(mode='closed-mainnet') {
 const base=deployment();
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
 const computed=proofReserveDeploymentConfigHash(base);
 const checkpointVerifierDeployer=address(17),checkpointVerifierDeployerNonce='3';
 const checkpointVerifier=getCreateAddress({from:checkpointVerifierDeployer,nonce:3});
 const checkpointRegistryDeployer=address(14),checkpointRegistryDeployerNonce='4';
 const checkpointRegistry=getCreateAddress({from:checkpointRegistryDeployer,nonce:4});
 Object.assign(base,{checkpointRegistryDeployer,checkpointRegistryDeployerNonce,checkpointRegistry,
  checkpointVerifier,checkpointVerifierCodeHash:'0x'+'21'.repeat(32),
  checkpointVerifierConfigHash:finalizedCheckpointVerifierConfig.verifierConfigHash,
  checkpointGuardian:address(12),
  checkpointGuardianCodeHash:'0x'+'61'.repeat(32),checkpointDomNetworkMagic:'1146047793',
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
  initialHeight:base.checkpointInitialHeight,initialBlock:base.checkpointInitialBlock,
  initialStateRoot:base.checkpointInitialStateRoot,
  initialContextHash:base.checkpointInitialContextHash,
  initialTotalDifficulty:base.checkpointInitialTotalDifficulty});
 const releaseConfig={productionReady:true,deploymentMethod:'CREATE',deployer,deployerNonce,...base,
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
   acceptingAuthority:base.governance,acceptedAt:'1792492800',rule:'exact release only'}};
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
  trustedSetup:{required:false,decisionReport:document('evidence/setup-decision.txt'),transcript:null},
  checkpointTrustedSetup:{required:false,
   decisionReport:document('evidence/checkpoint-setup-decision.txt'),transcript:null},
  realFinalizedEndToEndReport:document('evidence/e2e.txt'),
  operationsReviewReport:document('evidence/operations.txt'),
  mainnetForkRehearsalReport:document('evidence/fork.txt'),
  securityValidationReport:document('evidence/security-validation.txt'),
  residualRiskAcceptanceReport:document('evidence/residual-risk-acceptance.txt'),
  mainnetColdStartAttestationReport:document('evidence/cold-start.txt'),
  nativePrivacyTrustedSetupAttestationReport:document('evidence/native-privacy-setup.json'),
  nativeRuntimeManifest:document('evidence/native-runtime-manifest.json'),
  nativeRuntimeSpendVerifyingKeyArtifact:document('evidence/native-spend-verifying-key.bin'),
  nativeScheduledRuntimeActivationAttestationReport:document('evidence/native-runtime-activation.json'),
  nativeWalletCustodyAttestationReport:document('evidence/native-wallet-custody.json'),
  nativeWalletRecoveryAttestationReport:document('evidence/native-wallet-recovery.json'),
  controlPlane:{
   governance:{address:base.governance,runtimeCodeHash:base.governanceCodeHash,
    configurationHash:'0x'+'70'.repeat(32),configurationReport:document('evidence/governance-config.txt')},
   guardian:{address:base.guardian,runtimeCodeHash:base.guardianCodeHash,
    configurationHash:'0x'+'71'.repeat(32),configurationReport:document('evidence/guardian-config.txt')},
   checkpointGuardian:{address:base.checkpointGuardian,runtimeCodeHash:base.checkpointGuardianCodeHash,
    configurationHash:'0x'+'72'.repeat(32),configurationReport:document('evidence/checkpoint-guardian-config.txt')},
  },
  controlPlaneSeparationReport:document('evidence/control-plane-separation.txt'),
  controlPlaneRecoveryDrillReport:document('evidence/control-plane-recovery.txt'),
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
  checkpointVerifyingKeyArtifact:document('evidence/checkpoint-verifying-key.bin'),
  checkpointProvingProgramArtifact:document('evidence/checkpoint-proving-program.bin'),
  checkpointProvingProgramSourceManifest:document('evidence/checkpoint-proving-program-sources.sha256')};
 evidence.reserveArtifact=document('out/USDOMProofReserve.sol/USDOMProofReserve.json');
 const evidenceFiles=Object.fromEntries([
  'build','verifier-build','checkpoint-registry-build','checkpoint-verifier-build','checkpoint-bootstrap',
  'checkpoint-finalized-event','consensus','consensus-2','privacy','privacy-2','solidity','solidity-2','setup-decision',
  'checkpoint-setup-decision',
  'e2e','operations','fork','security-validation','residual-risk-acceptance','cold-start',
  'governance-config','guardian-config','control-plane-separation',
  'checkpoint-guardian-config','control-plane-recovery','predeployment',
 ].map(name=>{
  const path=`evidence/${name}.txt`;
  return [path,documentSha(path)];
 }));
 evidenceFiles['evidence/verifier-config.json']=verifierConfigManifestSha256;
 evidenceFiles['evidence/checkpoint-verifier-config.json']=checkpointVerifierConfigManifestSha256;
 for(const path of ['evidence/native-privacy-setup.json','evidence/native-runtime-activation.json',
  'evidence/native-wallet-custody.json','evidence/native-wallet-recovery.json']) {
  evidenceFiles[path]=documentSha(path);
 }
 for(const path of [
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
 bytes32 public constant PRODUCTION_RESERVE_CONFIG_HASH = ${computed.reserveConfigHash};`;
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
  nativeWalletPanicBoundaryVerified:true};
 const nativeRuntimeValidation={status:'valid',network:'Mainnet',network_magic:'444f4d31',
  manifest_sha256:evidence.nativeRuntimeManifest.sha256,chain_id:base.checkpointDomChainId.slice(2),
  first_v4_height:base.checkpointFirstV4Height,candidate_v2_first_height:'disabled',
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
  nativeRuntimeValidation};
}

test('configured hash-addressed evidence can satisfy both fail-closed release modes',()=>{
 for(const mode of ['closed-mainnet','real-funds']) {
  const report=assessMainnetReadiness(readyFixture(mode));
  assert.equal(report.ready,true,JSON.stringify(report.blockers));
  assert.equal(report.blockerCount,0);
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
 ];
 for(const change of changes) {
  const fixture=readyFixture(); change(fixture);
  const report=assessMainnetReadiness(fixture);
  assert.equal(report.ready,false,JSON.stringify(report.blockers));
  assert(report.blockers.some(blocker=>blocker.code.startsWith('operator_residual_risk_')),
   JSON.stringify(report.blockers));
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
  [fixture=>{fixture.nativeAttestationApprovalObservation.finalizedBlockHash=bytes32('00');},
   'native_attestation_approval_block_hash_invalid'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.snapshotBlockHashAfter=bytes32('71');},
   'native_attestation_approval_snapshot_changed'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.governance=address(5);},
   'native_attestation_approval_governance_mismatch'],
  [fixture=>{fixture.nativeAttestationApprovalObservation.governanceCodeHash=bytes32('51');},
   'native_attestation_approval_governance_codehash_mismatch'],
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
 for(const code of ['requirement_native_consensus_implemented','production_finality_unselected',
  'operator_deploy_unauthorized','release_reserve_missing','contract_PRODUCTION_RESERVE_CONFIG_HASH_zero',
  'release_evidence_unconfigured']) assert(codes.includes(code),code);
 assert.match(operatorIntent.production_trust_model,/quorum restricted to prototype/i);
 assert(!operatorIntent.undefined.some(parameter=>/notary|threshold|testnet token/i.test(parameter)),
  'proof-authorized mainnet release must not require prototype quorum or unrelated testnet parameters');
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
  fixture=>{fixture.evidenceFiles['evidence/governance-config.txt']='2'.repeat(64);},
  fixture=>{fixture.evidence.controlPlaneSeparationReport=null;},
  fixture=>{fixture.evidence.mainnetPredeploymentAttestationReport=null;},
  fixture=>{fixture.evidence.reserveArtifact.path='evidence/wrong-artifact.json';},
  fixture=>{fixture.evidence.verifierArtifact.path='out/wrong-finalized-burn-adapter.json';},
  fixture=>{fixture.evidence.checkpointVerifierArtifact.path='out/wrong-checkpoint-adapter.json';},
  fixture=>{fixture.operatorIntent.deploy_authorized=false;},
  fixture=>{fixture.requirements.consensus_proof_implemented=false;},
  fixture=>{fixture.repositoryState.dirty=true;},
  fixture=>{fixture.repositoryState.head='c'.repeat(40);},
  fixture=>{fixture.repositoryState.tagSignatureVerified=false;},
  fixture=>{fixture.repositoryState.importProvenanceVerified=false;},
  fixture=>{fixture.repositoryState.sourceManifestVerified=false;},
  fixture=>{fixture.repositoryState.ethereumFinalityPanicBoundaryVerified=false;},
  fixture=>{fixture.repositoryState.nativeStatePanicBoundaryVerified=false;},
  fixture=>{fixture.repositoryState.nativePrivacyPanicBoundaryVerified=false;},
  fixture=>{fixture.repositoryState.proofProgramPanicBoundaryVerified=false;},
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
