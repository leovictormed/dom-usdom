import {getAddress,getCreateAddress} from 'ethers';
import {proofReserveDeploymentConfigHash} from './configuration.mjs';
import {uint} from './reserve.mjs';
import {finalizedBurnVerifierConfigHash} from './verifier-config.mjs';
import {checkpointRegistryConfigHash} from './checkpoint-registry.mjs';
import {activationSchedule} from './activation-schedule.mjs';
import {checkpointVerifierConfigHash} from './checkpoint-verifier-config.mjs';
import {isCanonicalGitSigningKeyFingerprint,isCanonicalReleaseTag} from './git-signature.mjs';
import {validateRiscZeroMainnetReference} from './risc0-verifier-reference.mjs';
import {assessMainnetPreflight} from './mainnet-preflight.mjs';
import {
  nativeReleaseAttestationDigest,validNativeAttestationSignature,
} from './native-release-attestation.mjs';

const zeroHash = '0x' + '00'.repeat(32);
const sha256Pattern = /^[0-9a-f]{64}$/;
const bytes32Pattern = /^0x[0-9a-fA-F]{64}$/;
const mainnetUsdt = getAddress('0xdAC17F958D2ee523a2206206994597C13D831ec7');
const ethereumMainnetGenesisValidatorsRoot =
  '0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95';
const ethereumMainnetForkSchedule = Object.freeze({
  genesis:{epoch:'0',version:'00000000'},
  altair:{epoch:'74240',version:'01000000'},
  bellatrix:{epoch:'144896',version:'02000000'},
  capella:{epoch:'194048',version:'03000000'},
  deneb:{epoch:'269568',version:'04000000'},
  electra:{epoch:'364032',version:'05000000'},
  fulu:{epoch:'411392',version:'06000000'},
  gloas:{epoch:'18446744073709551615',version:'07000000'},
});
const domMaxFutureBlockTimeSeconds = 120n;
const reserveMinExecutionWindowSeconds = 3600n;
const reserveMaxCertificateLifetimeSeconds = 7n*24n*60n*60n;
const expectedReleaseIdentity = 'Soren Planck <sorenplanck@tutamail.com>';
const releaseEvidenceConfigPath =
  'labs/usdom-reserve/config/mainnet-release-evidence.unconfigured.json';
const operatorIntentPath = 'labs/usdom-reserve/config/operator-intent.json';
const releaseEvidencePathPrefix = 'labs/usdom-reserve/evidence/';
const releaseEvidenceKeys = [
  'checkpointBootstrapRatificationReport','checkpointFinalizedEventReport',
  'checkpointProvingProgramArtifact','checkpointProvingProgramSourceManifest',
  'checkpointRegistryArtifact','checkpointRegistryReproducibleBuildReport','checkpointTrustedSetup',
  'checkpointVerifierArtifact','checkpointVerifierConfigManifest',
  'checkpointVerifierReproducibleBuildReport','checkpointVerifyingKeyArtifact','controlPlane',
  'controlPlaneRecoveryDrillReport','controlPlaneSeparationReport','domConsensusAuditReports',
  'mainnetColdStartAttestationReport','mainnetForkRehearsalReport',
  'mainnetPredeploymentAttestationReport','nativePrivacyTrustedSetupAttestationReport',
  'nativeRuntimeManifest','nativeRuntimeSpendVerifyingKeyArtifact',
  'nativeScheduledRuntimeActivationAttestationReport','nativeWalletCustodyAttestationReport',
  'nativeWalletRecoveryAttestationReport','operationsReviewReport','privacyCircuitAuditReports',
  'provingProgramArtifact','provingProgramSourceManifest','realFinalizedEndToEndReport','releaseId',
  'reproducibleBuildReport','reserveArtifact','residualRiskAcceptanceReport','schema',
  'securityValidationReport','solidityAuditReports','sourceCommit','sourceTag','trustedSetup',
  'verifierArtifact','verifierConfigManifest','verifierReproducibleBuildReport',
  'verifyingKeyArtifact',
];
const operatorIntentKeys = [
  'authority','chainId','checkpoint_poc_authorization','current_phase','deploy_authorized',
  'finality_comparison','finality_direction','local_test_values_not_approved_for_production',
  'native_asset_requirements','network','production_approved','production_trust_model',
  'prototype_trust_model','real_funds_authorized','release_assurance_policy',
  'release_signing_key_fingerprint','residual_risk_acceptance','schema','token','undefined',
];
const residualRiskAcceptanceKeys = [
  'accepted','acceptedAt','acceptingAuthority','checkpointRegistryConfigHash','releaseId',
  'reportSha256','reserveConfigHash','rule','sourceCommit',
];

const closedMainnetRequirements = [
  'native_consensus_implemented',
  'consensus_proof_implemented',
  'production_finalized_burn_verifier_implemented',
  'production_finalized_burn_proof_backend_selected',
  'production_finalized_burn_guest_compiled',
  'production_finalized_burn_guest_benchmarked',
  'production_finalized_burn_raw_checkpoint_positive_vector',
  'production_finalized_burn_risc0_evm_receipt_verifier_implemented',
  'production_finalized_burn_proving_capacity_measured',
  'production_finalized_burn_evm_verification_gas_measured',
  'production_finalized_burn_canonical_replay_slot_enforced',
  'production_finalized_burn_positive_evidence_checker_implemented',
  'finalized_burn_risc0_adapter_selector_canonical_abi_enforced',
  'finalized_burn_risc0_adapter_verify_empty_returndata_enforced',
  'checkpoint_risc0_adapter_selector_canonical_abi_enforced',
  'checkpoint_risc0_adapter_verify_empty_returndata_enforced',
  'risc0_adapter_verify_return_bomb_not_copied',
  'risc0_guest_host_input_bounded_before_allocation',
  'ethereum_finality_untrusted_paths_panic_free',
  'native_state_untrusted_decoders_panic_free',
  'native_privacy_untrusted_decoders_panic_free',
  'proof_program_untrusted_paths_panic_free',
  'proof_program_host_inputs_bounded_before_read_to_end',
  'native_wallet_untrusted_paths_panic_free',
  'production_irreversible_burn_claim_survives_queue_expiry',
  'production_withdrawal_queue_lease_renewable',
  'production_withdrawal_queue_lease_uses_current_ethereum_time',
  'production_burn_intent_valid_until_is_not_payout_extinguishment',
  'production_finalized_burn_historical_claim_reproof_vector',
  'production_finalized_burn_reproof_binds_fresh_finality_slot',
  'production_finalized_burn_reproof_preserves_original_intent_deadline',
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
  'production_checkpoint_registry_contract_implemented',
  'production_checkpoint_registry_verifier_implemented',
  'production_checkpoint_registry_verifier_proves_consensus_extension',
  'production_checkpoint_registry_artifacts_pinned',
  'production_checkpoint_registry_bootstrap_ratified',
  'production_checkpoint_registry_positive_finalized_event_vector',
  'production_checkpoint_consensus_extension_private_input_implemented',
  'production_checkpoint_consensus_extension_guest_compiled',
  'production_checkpoint_registry_risc0_evm_adapter_image_id_pinned',
  'production_checkpoint_recursive_segment_transition_implemented',
  'production_checkpoint_recursive_receipt_aggregation_implemented',
  'production_checkpoint_segment_private_input_covers_all_valid_dom_blocks',
  'production_checkpoint_guest_randomx_relation_implemented',
  'production_checkpoint_randomx_proof_receipt_implemented',
  'production_checkpoint_randomx_receipt_image_id_pinned',
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
  'production_checkpoint_outer_evm_verification_gas_measured',
  'production_block_header_state_commitment_implemented',
  'verified_ethereum_checkpoint_native_burn_binding_enforces_dom_fork_choice',
  'real_finalized_reserve_deposit_native_block_vector_implemented',
  'native_privacy_production_verifying_key_installed',
  'native_privacy_trusted_setup_ceremony_completed',
  'native_private_mining_real_finalized_deposit_vector_implemented',
  'native_scheduled_public_runtime_configured',
  'production_native_release_attestation_content_revalidated',
  'production_native_attestation_eip1271_finalized_approval_enforced',
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
  'production_activation_schedule_implemented',
  'production_reserve_config_hash_configured',
  'solidity_production_contract_lint_clean',
  'solidity_deep_fuzz_and_invariants_passed',
  'proof_reserve_exact_deployment_commitment_implemented',
  'proof_reserve_mainnet_initial_pause_implemented',
  'production_control_plane_recovery_drill_passed',
  'production_mainnet_predeployment_preflight_passed',
  'production_mainnet_preflight_single_finalized_snapshot_enforced',
  'production_mainnet_attestation_content_revalidated',
  'production_mainnet_preflight_canonical_uint_encoding_enforced',
  'production_mainnet_preflight_exact_observation_schema_enforced',
];

const realFundsRequirements = [
  'native_private_wallet_key_management_implemented',
  'native_private_wallet_production_monotonic_seal_authority_integrated',
  'native_private_wallet_hardware_or_os_keystore_integrated',
  'native_private_wallet_recovery_ceremony_implemented',
  'production_native_wallet_attestation_content_revalidated',
  'native_private_wallet_remote_historical_deposit_rescan_implemented',
  'native_private_wallet_history_finality_claimed',
];

const releaseFields = [
  'ethereumChainId','deploymentMethod','deployer','deployerNonce','reserve','token','tokenCodeHash',
  'reserveRuntimeCodeHash','reserveInitcodeHash',
  'verifierDeployer','verifierDeployerNonce','verifier','verifierCodeHash','verifierInitcodeHash',
  'verifierConfigHash',
  'reserveConfigHash','domDomain','activationScheduleCommitment',
  'checkpointRegistryDeployer','checkpointRegistryDeployerNonce','checkpointRegistry',
  'checkpointRegistryRuntimeCodeHash','checkpointRegistryInitcodeHash','checkpointRegistryConfigHash',
  'checkpointVerifierDeployer','checkpointVerifierDeployerNonce','checkpointVerifier',
  'checkpointVerifierCodeHash','checkpointVerifierInitcodeHash','checkpointVerifierConfigHash',
  'checkpointGuardian','checkpointGuardianCodeHash','checkpointDomNetworkMagic',
  'checkpointDomChainId','checkpointFirstV4Height','checkpointActivationEmptyStateRoot',
  'checkpointIntervalBlocks','checkpointConfirmationDepthBlocks','checkpointChallengePeriodSeconds',
  'checkpointInitialHeight','checkpointInitialBlock','checkpointInitialStateRoot','checkpointInitialContextHash',
  'checkpointInitialTotalDifficulty',
  'governance','governanceCodeHash','guardian','guardianCodeHash',
  'withdrawalDelaySeconds','governanceDelaySeconds',
  'maxOutstandingBaseUnits','outflowCapacityBaseUnitsPerDay','nativeRelaySafetyMarginSeconds',
  'nativeMaxEthereumAnchorAgeSeconds','nativeMaxDomClockLeadSeconds',
];
const releaseConfigKeys = [
  ...releaseFields,'ethereumGenesisValidatorsRoot','nativeEthereumTrustedCheckpoint',
  'productionReady','realFundsAuthorized',
];

const evidenceDocuments = [
  'reproducibleBuildReport','verifierReproducibleBuildReport','realFinalizedEndToEndReport',
  'checkpointRegistryReproducibleBuildReport','checkpointVerifierReproducibleBuildReport',
  'checkpointBootstrapRatificationReport','checkpointFinalizedEventReport',
  'operationsReviewReport','mainnetForkRehearsalReport',
  'securityValidationReport','residualRiskAcceptanceReport',
  'controlPlaneSeparationReport','controlPlaneRecoveryDrillReport',
  'mainnetPredeploymentAttestationReport',
  'nativePrivacyTrustedSetupAttestationReport','nativeScheduledRuntimeActivationAttestationReport',
  'nativeRuntimeManifest','nativeRuntimeSpendVerifyingKeyArtifact',
  'reserveArtifact','verifierArtifact','verifierConfigManifest','verifyingKeyArtifact',
  'checkpointRegistryArtifact','checkpointVerifierArtifact',
  'checkpointVerifierConfigManifest','checkpointVerifyingKeyArtifact',
  'checkpointProvingProgramArtifact','checkpointProvingProgramSourceManifest',
  'provingProgramArtifact','provingProgramSourceManifest',
];

const realFundsEvidenceDocuments = [
  'mainnetColdStartAttestationReport','nativeWalletCustodyAttestationReport',
  'nativeWalletRecoveryAttestationReport',
];

function add(blockers, code, detail) {
  blockers.push({code, detail});
}

function exactObject(value,keys) {
  return value && typeof value==='object' && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
}

function documentArray(value) {
  return Array.isArray(value) ? value : [];
}

function readProductionConstant(source, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const expression = new RegExp(
    `bytes32\\s+public\\s+constant\\s+${escaped}\\s*=\\s*(?:bytes32\\(\\s*(0|0x[0-9a-fA-F]{64})\\s*\\)|(0x[0-9a-fA-F]{64}))\\s*;`,
  );
  const match = source.match(expression);
  if (!match) return null;
  const value = match[1] ?? match[2];
  return value === '0' ? zeroHash : value.toLowerCase();
}

function validDocument(document, evidenceFiles) {
  return exactObject(document,['path','sha256'])
    && canonicalEvidencePath(document.path)
    && typeof document.sha256 === 'string' && sha256Pattern.test(document.sha256)
    && Object.prototype.hasOwnProperty.call(evidenceFiles ?? {}, document.path)
    && evidenceFiles[document.path] === document.sha256;
}

function canonicalEvidencePath(value) {
  if (typeof value!=='string' || value.length===0 || value.startsWith('/')
      || value.includes('\\') || value.includes('\0')) return false;
  const parts=value.split('/');
  return parts.every(part=>part.length>0 && part!=='.' && part!=='..');
}

function requireControlPlaneRole(blockers, evidence, evidenceFiles, releaseConfig, role) {
  const snapshot = evidence?.controlPlane?.[role];
  if (!snapshot || typeof snapshot!=='object' || Array.isArray(snapshot)) {
    add(blockers, `control_plane_${role}_missing`, `${role} control-plane snapshot is required`);
    return [];
  }
  if (!exactObject(snapshot,['address','configurationHash','configurationReport','runtimeCodeHash'])) {
    add(blockers,`control_plane_${role}_schema_invalid`,
      `${role} control-plane snapshot must use the exact supported schema`);
    return [];
  }
  try {
    if (getAddress(snapshot.address) !== getAddress(releaseConfig?.[role])) {
      add(blockers, `control_plane_${role}_address_mismatch`, `${role} snapshot address does not match the release`);
    }
  } catch {
    add(blockers, `control_plane_${role}_address_invalid`, `${role} snapshot or release address is invalid`);
  }
  const expectedCodeHash = releaseConfig?.[`${role}CodeHash`];
  if (!bytes32Pattern.test(snapshot.runtimeCodeHash ?? '')
      || !bytes32Pattern.test(expectedCodeHash ?? '')
      || snapshot.runtimeCodeHash.toLowerCase() !== expectedCodeHash.toLowerCase()) {
    add(blockers, `control_plane_${role}_codehash_mismatch`, `${role} runtime code hash does not match the release`);
  }
  if (!bytes32Pattern.test(snapshot.configurationHash ?? '')
      || snapshot.configurationHash.toLowerCase() === zeroHash) {
    add(blockers, `control_plane_${role}_configuration_hash_invalid`, `${role} configuration hash must be nonzero bytes32`);
  }
  if (!validDocument(snapshot.configurationReport, evidenceFiles)) {
    add(blockers, `control_plane_${role}_report_missing`, `${role} configuration report is absent or hash-mismatched`);
  }
  return snapshot.configurationReport && typeof snapshot.configurationReport.path === 'string'
    ? [snapshot.configurationReport] : [];
}

function requireDocuments(blockers, evidence, evidenceFiles, mode, releaseConfig) {
  if (!exactObject(evidence,releaseEvidenceKeys)) {
    add(blockers,'release_evidence_schema_invalid',
      'release evidence must use the exact supported top-level schema');
  }
  if (!evidence || evidence.schema !== 1 || typeof evidence.releaseId !== 'string' || !evidence.releaseId) {
    add(blockers, 'release_evidence_unconfigured', 'release evidence schema and releaseId are required');
  }
  for (const name of evidenceDocuments) {
    if (!validDocument(evidence?.[name], evidenceFiles)) {
      add(blockers, `evidence_${name}_missing`, `${name} must reference a present file with an exact SHA-256`);
    }
  }
  if (evidence?.reserveArtifact?.path!==undefined
      && evidence.reserveArtifact.path!=='out/USDOMProofReserve.sol/USDOMProofReserve.json') {
    add(blockers, 'evidence_reserveArtifact_path_invalid', 'reserveArtifact must use the canonical Foundry artifact path');
  }
  if (evidence?.checkpointRegistryArtifact?.path!==undefined
      && evidence.checkpointRegistryArtifact.path!=='out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json') {
    add(blockers,'evidence_checkpointRegistryArtifact_path_invalid',
      'checkpointRegistryArtifact must use the canonical Foundry artifact path');
  }
  if(evidence?.verifierArtifact?.path!==undefined
      && evidence.verifierArtifact.path
        !=='out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json') {
    add(blockers,'evidence_verifierArtifact_path_invalid',
      'verifierArtifact must use the canonical finalized-burn RISC Zero adapter artifact path');
  }
  if(evidence?.checkpointVerifierArtifact?.path!==undefined
      && evidence.checkpointVerifierArtifact.path
        !=='out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json') {
    add(blockers,'evidence_checkpointVerifierArtifact_path_invalid',
      'checkpointVerifierArtifact must use the canonical checkpoint RISC Zero adapter artifact path');
  }
  if (mode === 'real-funds') {
    for (const name of realFundsEvidenceDocuments) {
      if (!validDocument(evidence?.[name], evidenceFiles)) {
        add(blockers, `evidence_${name}_missing`, `${name} must reference a present file with an exact SHA-256`);
      }
    }
  }
  // External reviews are optional evidence. Their absence is not a release
  // blocker; present reports must still be real, hash-addressed documents.
  for (const name of ['domConsensusAuditReports','privacyCircuitAuditReports','solidityAuditReports']) {
    const reports = evidence?.[name];
    if (reports !== undefined
        && (!Array.isArray(reports) || reports.some(report => !validDocument(report, evidenceFiles)))) {
      add(blockers, `evidence_${name}_invalid`, `${name} contains an invalid or hash-mismatched report`);
    }
  }
  const setup = evidence?.trustedSetup;
  if (setup && typeof setup==='object' && !Array.isArray(setup)
      && !exactObject(setup,['decisionReport','required','transcript'])) {
    add(blockers,'trusted_setup_schema_invalid','trustedSetup must use the exact supported schema');
  }
  if (!setup || typeof setup.required !== 'boolean') {
    add(blockers, 'trusted_setup_decision_missing', 'trustedSetup.required must be explicitly true or false');
  } else {
    if (!validDocument(setup.decisionReport, evidenceFiles)) {
      add(blockers, 'trusted_setup_decision_evidence_missing', 'the trusted-setup decision report is absent or hash-mismatched');
    }
    if (setup.required && !validDocument(setup.transcript, evidenceFiles)) {
      add(blockers, 'trusted_setup_transcript_missing', 'the required trusted-setup transcript is absent or hash-mismatched');
    }
  }
  const checkpointSetup=evidence?.checkpointTrustedSetup;
  if (checkpointSetup && typeof checkpointSetup==='object' && !Array.isArray(checkpointSetup)
      && !exactObject(checkpointSetup,['decisionReport','required','transcript'])) {
    add(blockers,'checkpoint_trusted_setup_schema_invalid',
      'checkpointTrustedSetup must use the exact supported schema');
  }
  if (!checkpointSetup || typeof checkpointSetup.required !== 'boolean') {
    add(blockers,'checkpoint_trusted_setup_decision_missing',
      'checkpoint verifier trustedSetup.required must be explicitly true or false');
  } else {
    if (!validDocument(checkpointSetup.decisionReport,evidenceFiles)) {
      add(blockers,'checkpoint_trusted_setup_decision_evidence_missing',
        'the checkpoint verifier trusted-setup decision report is absent or hash-mismatched');
    }
    if (checkpointSetup.required && !validDocument(checkpointSetup.transcript,evidenceFiles)) {
      add(blockers,'checkpoint_trusted_setup_transcript_missing',
        'the required checkpoint verifier trusted-setup transcript is absent or hash-mismatched');
    }
  }
  if(!exactObject(evidence?.controlPlane,['checkpointGuardian','governance','guardian'])) {
    add(blockers,'control_plane_schema_invalid','controlPlane must use the exact three-role schema');
  }
  const governanceReports = requireControlPlaneRole(blockers, evidence, evidenceFiles, releaseConfig, 'governance');
  const guardianReports = requireControlPlaneRole(blockers, evidence, evidenceFiles, releaseConfig, 'guardian');
  const checkpointGuardianReports =
    requireControlPlaneRole(blockers,evidence,evidenceFiles,releaseConfig,'checkpointGuardian');
  const governanceConfigurationHash = evidence?.controlPlane?.governance?.configurationHash;
  const guardianConfigurationHash = evidence?.controlPlane?.guardian?.configurationHash;
  const checkpointGuardianConfigurationHash=evidence?.controlPlane?.checkpointGuardian?.configurationHash;
  const controlHashes=[governanceConfigurationHash,guardianConfigurationHash,checkpointGuardianConfigurationHash]
    .filter(value=>bytes32Pattern.test(value??'')).map(value=>value.toLowerCase());
  if (new Set(controlHashes).size!==controlHashes.length) {
    add(blockers,'control_plane_configuration_not_separated',
      'governance, reserve guardian and checkpoint guardian configuration hashes must differ');
  }
  const allDocuments = [
    ...evidenceDocuments.map(name => evidence?.[name]),
    ...(mode === 'real-funds' ? realFundsEvidenceDocuments.map(name => evidence?.[name]) : []),
    ...documentArray(evidence?.domConsensusAuditReports),
    ...documentArray(evidence?.privacyCircuitAuditReports),
    ...documentArray(evidence?.solidityAuditReports),
    setup?.decisionReport,...(setup?.required ? [setup.transcript] : []),
    checkpointSetup?.decisionReport,...(checkpointSetup?.required ? [checkpointSetup.transcript] : []),
    ...governanceReports,...guardianReports,...checkpointGuardianReports,
  ].filter(document => document && typeof document.path === 'string');
  const paths = allDocuments.map(document => document.path);
  if (new Set(paths).size !== paths.length) {
    add(blockers, 'duplicate_evidence_document', 'independent evidence slots cannot reuse the same file path');
  }
  const hashes=allDocuments.filter(document=>validDocument(document,evidenceFiles))
    .map(document=>document.sha256);
  if (new Set(hashes).size!==hashes.length) {
    add(blockers,'duplicate_evidence_content',
      'independent evidence slots cannot use byte-identical files under different paths');
  }
}

function requirePreflightAttestation(
  blockers,{name,phase,document,evidenceFiles,attestation,releaseConfig,riscZeroReference},
) {
  if(!validDocument(document,evidenceFiles)) return;
  const expectedKeys=['blockerCount','blockers','finalizedBlockHash','finalizedBlockNumber',
    'observation','phase','ready'];
  if(!attestation || typeof attestation!=='object' || Array.isArray(attestation)
      || JSON.stringify(Object.keys(attestation).sort())!==JSON.stringify(expectedKeys)) {
    add(blockers,`${name}_attestation_unreadable`,
      `${name} attestation must be the exact parsed preflight report schema`);
    return;
  }
  if(attestation.phase!==phase || attestation.ready!==true || attestation.blockerCount!==0
      || !Array.isArray(attestation.blockers) || attestation.blockers.length!==0) {
    add(blockers,`${name}_attestation_not_ready`,
      `${name} attestation must report the expected phase with zero blockers`);
  }
  let recomputed;
  try {
    recomputed=assessMainnetPreflight({phase,releaseConfig,
      observation:attestation.observation,riscZeroReference});
  } catch(error) {
    add(blockers,`${name}_attestation_invalid`,`${name} attestation cannot be assessed: ${error.message}`);
    return;
  }
  if(!recomputed.ready) {
    add(blockers,`${name}_attestation_observation_rejected`,
      `${name} observation fails current preflight: ${recomputed.blockers.map(value=>value.code).join(',')}`);
  }
  if(attestation.finalizedBlockNumber!==recomputed.finalizedBlockNumber
      || String(attestation.finalizedBlockHash).toLowerCase()
        !==String(recomputed.finalizedBlockHash).toLowerCase()
      || attestation.blockerCount!==recomputed.blockerCount || attestation.ready!==recomputed.ready) {
    add(blockers,`${name}_attestation_report_mismatch`,
      `${name} reported result differs from the independently recomputed preflight`);
  }
}

function requireNativeReleaseAttestation(
  blockers,{name,kind,document,evidenceFiles,attestation,evidence,releaseConfig,expectedSubjectCommitment},
) {
  if(!validDocument(document,evidenceFiles)) return null;
  const expectedKeys=['approvedBy','checkpointRegistryConfigHash','completedAt','kind','releaseId',
    'reserveConfigHash','schema','signature','sourceCommit','subjectCommitment'];
  if(!attestation || typeof attestation!=='object' || Array.isArray(attestation)
      || JSON.stringify(Object.keys(attestation).sort())!==JSON.stringify(expectedKeys)) {
    add(blockers,`${name}_attestation_unreadable`,
      `${name} must use the exact release-bound native attestation schema`);
    return null;
  }
  if(attestation.schema!==1) add(blockers,`${name}_schema_invalid`,`${name} schema must be 1`);
  if(attestation.kind!==kind) add(blockers,`${name}_kind_mismatch`,`${name} kind does not match its evidence slot`);
  if(attestation.releaseId!==evidence?.releaseId) {
    add(blockers,`${name}_release_mismatch`,`${name} releaseId does not match the release evidence`);
  }
  if(attestation.sourceCommit!==evidence?.sourceCommit) {
    add(blockers,`${name}_commit_mismatch`,`${name} sourceCommit does not match the release evidence`);
  }
  for(const [field,expected] of [
    ['reserveConfigHash',releaseConfig?.reserveConfigHash],
    ['checkpointRegistryConfigHash',releaseConfig?.checkpointRegistryConfigHash],
  ]) {
    const value=attestation[field];
    if(!bytes32Pattern.test(value??'') || !bytes32Pattern.test(expected??'')
        || value.toLowerCase()!==expected.toLowerCase()) {
      add(blockers,`${name}_${field}_mismatch`,`${name} ${field} does not match the exact release`);
    }
  }
  if(typeof attestation.completedAt!=='string' || !/^[1-9][0-9]*$/.test(attestation.completedAt)) {
    add(blockers,`${name}_completed_at_invalid`,`${name} completedAt must be a nonzero canonical uint64 string`);
  } else {
    try { uint(attestation.completedAt,64); }
    catch { add(blockers,`${name}_completed_at_invalid`,`${name} completedAt must fit uint64`); }
  }
  try {
    if(getAddress(attestation.approvedBy)!==getAddress(releaseConfig?.governance)) {
      add(blockers,`${name}_approver_mismatch`,`${name} approver does not match release governance`);
    }
  } catch {
    add(blockers,`${name}_approver_invalid`,`${name} approvedBy is not a valid address`);
  }
  if(!validNativeAttestationSignature(attestation.signature)) {
    add(blockers,`${name}_signature_invalid`,`${name} signature must be nonempty, canonical and bounded`);
  }
  const subject=attestation.subjectCommitment;
  if(!bytes32Pattern.test(subject??'') || subject.toLowerCase()===zeroHash) {
    add(blockers,`${name}_subject_invalid`,`${name} subjectCommitment must be nonzero bytes32`);
    return null;
  }
  if(expectedSubjectCommitment!==undefined
      && (!bytes32Pattern.test(expectedSubjectCommitment??'')
        || subject.toLowerCase()!==expectedSubjectCommitment.toLowerCase())) {
    add(blockers,`${name}_subject_mismatch`,`${name} subjectCommitment does not match the release`);
  }
  return subject.toLowerCase();
}

const nativeRuntimeValidationKeys = [
  'activation_schedule_commitment','candidate_v2_first_height','chain_id','dom_domain',
  'checkpoint_bridge_domain','checkpoint_config_hash','checkpoint_config_storage_slot',
  'checkpoint_registry','checkpoint_runtime_code_hash','deposit_bridge_domain','deposit_max_amount',
  'deposit_reserve','deposit_runtime_code_hash','empty_state_root','ethereum_chain_id_uint256','ethereum_deposit_policy_hash',
  'ethereum_genesis_validators_root','ethereum_trusted_checkpoint',
  'ethereum_fork_genesis_epoch','ethereum_fork_genesis_version',
  'ethereum_fork_altair_epoch','ethereum_fork_altair_version',
  'ethereum_fork_bellatrix_epoch','ethereum_fork_bellatrix_version',
  'ethereum_fork_capella_epoch','ethereum_fork_capella_version',
  'ethereum_fork_deneb_epoch','ethereum_fork_deneb_version',
  'ethereum_fork_electra_epoch','ethereum_fork_electra_version',
  'ethereum_fork_fulu_epoch','ethereum_fork_fulu_version',
  'ethereum_fork_gloas_epoch','ethereum_fork_gloas_version',
  'ethereum_checkpoint_policy_hash','first_v4_height',
  'manifest_sha256','max_certificate_lifetime_secs','max_dom_clock_lead_secs',
  'max_ethereum_anchor_age_secs','min_execution_window_secs','network','network_magic',
  'privacy_policy_hash','privacy_verifier_config_hash','relay_safety_margin_secs','reserve',
  'spend_verifying_key_sha256','status','withdrawal_delay_secs',
];

function requireNativeRuntimeManifest(
  blockers,{evidence,evidenceFiles,releaseConfig,nativeRuntimeValidation},
) {
  const manifest=evidence?.nativeRuntimeManifest;
  const spendKey=evidence?.nativeRuntimeSpendVerifyingKeyArtifact;
  if(!validDocument(manifest,evidenceFiles) || !validDocument(spendKey,evidenceFiles)) return null;
  if(!exactObject(nativeRuntimeValidation,nativeRuntimeValidationKeys)
      || nativeRuntimeValidationKeys.some(key=>typeof nativeRuntimeValidation[key]!=='string')) {
    add(blockers,'native_runtime_manifest_validation_missing',
      'the exact native runtime manifest was not accepted by the source-built Rust checker');
    return null;
  }
  const validation=nativeRuntimeValidation;
  const rawHash=value=>typeof value==='string' && /^[0-9a-f]{64}$/.test(value);
  const rawAddress=value=>typeof value==='string' && /^[0-9a-f]{40}$/.test(value);
  if(validation.status!=='valid' || validation.network!=='Mainnet') {
    add(blockers,'native_runtime_manifest_network_invalid',
      'the native runtime checker did not validate an Ethereum/DOM mainnet manifest');
  }
  if(validation.manifest_sha256!==manifest.sha256) {
    add(blockers,'native_runtime_manifest_hash_mismatch',
      'the Rust-validated native runtime manifest differs from the release evidence');
  }
  let expectedNetworkMagic=null;
  try { expectedNetworkMagic=uint(releaseConfig?.checkpointDomNetworkMagic,32).toString(16).padStart(8,'0'); }
  catch { /* the release-config validator reports the invalid value */ }
  if(!expectedNetworkMagic || validation.network_magic!==expectedNetworkMagic) {
    add(blockers,'native_runtime_network_magic_mismatch',
      'the native runtime network magic differs from the checkpoint release');
  }
  for(const [observed,expected,code,detail] of [
    [validation.chain_id,releaseConfig?.checkpointDomChainId,'native_runtime_chain_id_mismatch',
      'native runtime chain ID differs from the checkpoint release'],
    [validation.empty_state_root,releaseConfig?.checkpointActivationEmptyStateRoot,
      'native_runtime_empty_state_root_mismatch','native runtime empty state differs from the checkpoint release'],
    [validation.activation_schedule_commitment,releaseConfig?.activationScheduleCommitment,
      'native_runtime_activation_schedule_mismatch','native runtime activation schedule differs from the release'],
    [validation.dom_domain,releaseConfig?.domDomain,'native_runtime_dom_domain_mismatch',
      'native runtime DOM domain differs from the reserve release'],
    [validation.ethereum_genesis_validators_root,releaseConfig?.ethereumGenesisValidatorsRoot,
      'native_runtime_ethereum_genesis_mismatch','native runtime Ethereum genesis root differs from the release'],
  ]) {
    if(!rawHash(observed) || !bytes32Pattern.test(expected??'')
        || observed!==expected.slice(2).toLowerCase()) add(blockers,code,detail);
  }
  if(!rawHash(validation.ethereum_trusted_checkpoint)
      || !bytes32Pattern.test(releaseConfig?.nativeEthereumTrustedCheckpoint??'')
      || validation.ethereum_trusted_checkpoint
        !==releaseConfig.nativeEthereumTrustedCheckpoint.slice(2).toLowerCase()) {
    add(blockers,'native_runtime_ethereum_trusted_checkpoint_mismatch',
      'native runtime trusted checkpoint differs from the exact release');
  }
  for(const [name,expected] of Object.entries(ethereumMainnetForkSchedule)) {
    if(validation[`ethereum_fork_${name}_epoch`]!==expected.epoch
        || validation[`ethereum_fork_${name}_version`]!==expected.version) {
      add(blockers,`native_runtime_ethereum_fork_${name}_mismatch`,
        `native runtime ${name} fork differs from the supported Ethereum mainnet schedule`);
    }
  }
  if(validation.first_v4_height!==releaseConfig?.checkpointFirstV4Height) {
    add(blockers,'native_runtime_first_v4_height_mismatch',
      'native runtime activation height differs from the checkpoint release');
  }
  if(!rawHash(validation.ethereum_chain_id_uint256)
      || BigInt(`0x${validation.ethereum_chain_id_uint256}`).toString()!==releaseConfig?.ethereumChainId) {
    add(blockers,'native_runtime_ethereum_chain_id_mismatch',
      'native runtime Ethereum chain ID differs from the release');
  }
  if(!rawAddress(validation.reserve) || !/^0x[0-9a-fA-F]{40}$/.test(releaseConfig?.reserve??'')
      || validation.reserve!==releaseConfig.reserve.slice(2).toLowerCase()) {
    add(blockers,'native_runtime_reserve_mismatch','native runtime reserve differs from the release');
  }
  for(const [observed,expected,code,detail] of [
    [validation.checkpoint_registry,releaseConfig?.checkpointRegistry,
      'native_runtime_checkpoint_registry_mismatch','native checkpoint registry differs from the release'],
    [validation.deposit_reserve,releaseConfig?.reserve,
      'native_runtime_deposit_reserve_mismatch','native deposit reserve differs from the release'],
  ]) {
    if(!rawAddress(observed) || !/^0x[0-9a-fA-F]{40}$/.test(expected??'')
        || observed!==expected.slice(2).toLowerCase()) add(blockers,code,detail);
  }
  for(const [observed,expected,code,detail] of [
    [validation.checkpoint_runtime_code_hash,releaseConfig?.checkpointRegistryRuntimeCodeHash,
      'native_runtime_checkpoint_codehash_mismatch','native checkpoint runtime differs from the release'],
    [validation.checkpoint_config_hash,releaseConfig?.checkpointRegistryConfigHash,
      'native_runtime_checkpoint_config_mismatch','native checkpoint configuration differs from the release'],
    [validation.checkpoint_bridge_domain,releaseConfig?.domDomain,
      'native_runtime_checkpoint_domain_mismatch','native checkpoint domain differs from the release'],
    [validation.deposit_runtime_code_hash,releaseConfig?.reserveRuntimeCodeHash,
      'native_runtime_deposit_codehash_mismatch','native deposit runtime differs from the release'],
    [validation.deposit_bridge_domain,releaseConfig?.domDomain,
      'native_runtime_deposit_domain_mismatch','native deposit domain differs from the release'],
  ]) {
    if(!rawHash(observed) || !bytes32Pattern.test(expected??'')
        || observed!==expected.slice(2).toLowerCase()) add(blockers,code,detail);
  }
  if(validation.checkpoint_config_storage_slot!=='0'.repeat(64)) {
    add(blockers,'native_runtime_checkpoint_config_slot_mismatch',
      'native checkpoint verification must authenticate checkpointConfigHash at slot zero');
  }
  if(validation.deposit_max_amount!==releaseConfig?.maxOutstandingBaseUnits) {
    add(blockers,'native_runtime_deposit_max_amount_mismatch',
      'native deposit ceiling differs from the reserve exposure limit');
  }
  for(const [field,releaseField] of [
    ['withdrawal_delay_secs','withdrawalDelaySeconds'],
    ['relay_safety_margin_secs','nativeRelaySafetyMarginSeconds'],
    ['max_ethereum_anchor_age_secs','nativeMaxEthereumAnchorAgeSeconds'],
    ['max_dom_clock_lead_secs','nativeMaxDomClockLeadSeconds'],
  ]) {
    if(validation[field]!==releaseConfig?.[releaseField]) {
      add(blockers,`native_runtime_${field}_mismatch`,`${field} differs from the release`);
    }
  }
  if(validation.min_execution_window_secs!==reserveMinExecutionWindowSeconds.toString()
      || validation.max_certificate_lifetime_secs!==reserveMaxCertificateLifetimeSeconds.toString()) {
    add(blockers,'native_runtime_certificate_window_mismatch',
      'native runtime certificate constants differ from the immutable reserve policy');
  }
  if(!rawHash(validation.spend_verifying_key_sha256)
      || validation.spend_verifying_key_sha256!==spendKey.sha256) {
    add(blockers,'native_runtime_spend_verifying_key_mismatch',
      'the native runtime spend-verifying key differs from its release artifact');
  }
  for(const field of ['ethereum_checkpoint_policy_hash','ethereum_deposit_policy_hash',
    'privacy_policy_hash','privacy_verifier_config_hash']) {
    if(!rawHash(validation[field]) || validation[field]==='0'.repeat(64)) {
      add(blockers,`native_runtime_${field}_invalid`,`${field} must be a nonzero checker-derived hash`);
    }
  }
  if(validation.candidate_v2_first_height!=='disabled') {
    try {
      const candidate=uint(validation.candidate_v2_first_height,64);
      const first=uint(validation.first_v4_height,64);
      if(candidate<=first) throw new Error('candidate activation is not later');
    } catch {
      add(blockers,'native_runtime_candidate_v2_height_invalid',
        'candidate V2 activation must be disabled or a canonical later uint64 height');
    }
  }
  return {manifestSubject:`0x${manifest.sha256}`,
    privacyVerifierSubject:rawHash(validation.privacy_verifier_config_hash)
      ? `0x${validation.privacy_verifier_config_hash}`:undefined};
}

function requireNativeAttestationApprovalSnapshot(
  blockers,{observation,attestations,releaseConfig},
) {
  const expectedKeys=['approvals','chainId','finalizedBlockHash','finalizedBlockNumber',
    'finalizedBlockTimestamp','governance','governanceCodeHash','snapshotBlockHashAfter'];
  if(!observation || typeof observation!=='object' || Array.isArray(observation)
      || JSON.stringify(Object.keys(observation).sort())!==JSON.stringify(expectedKeys)) {
    add(blockers,'native_attestation_approval_snapshot_missing',
      'native attestations require an exact finalized EIP-1271 approval snapshot');
    return;
  }
  if(observation.chainId!==releaseConfig?.ethereumChainId || observation.chainId!=='1') {
    add(blockers,'native_attestation_approval_chain_mismatch',
      'native attestation approvals were not checked on the release Ethereum chain');
  }
  if(typeof observation.finalizedBlockNumber!=='string'
      || !/^[1-9][0-9]*$/.test(observation.finalizedBlockNumber)) {
    add(blockers,'native_attestation_approval_block_number_invalid',
      'native attestation approval block number must be a nonzero canonical integer string');
  }
  if(typeof observation.finalizedBlockTimestamp!=='string'
      || !/^[1-9][0-9]*$/.test(observation.finalizedBlockTimestamp)) {
    add(blockers,'native_attestation_approval_block_timestamp_invalid',
      'native attestation approval block timestamp must be a nonzero canonical integer string');
  }
  if(!bytes32Pattern.test(observation.finalizedBlockHash??'')
      || observation.finalizedBlockHash.toLowerCase()===zeroHash) {
    add(blockers,'native_attestation_approval_block_hash_invalid',
      'native attestation approvals require a nonzero finalized block hash');
  }
  if(!bytes32Pattern.test(observation.snapshotBlockHashAfter??'')
      || !bytes32Pattern.test(observation.finalizedBlockHash??'')
      || observation.snapshotBlockHashAfter.toLowerCase()
        !==observation.finalizedBlockHash.toLowerCase()) {
    add(blockers,'native_attestation_approval_snapshot_changed',
      'the finalized block hash changed while native approvals were checked');
  }
  try {
    if(getAddress(observation.governance)!==getAddress(releaseConfig?.governance)) {
      add(blockers,'native_attestation_approval_governance_mismatch',
        'the EIP-1271 verifier differs from release governance');
    }
  } catch {
    add(blockers,'native_attestation_approval_governance_invalid',
      'the EIP-1271 governance verifier is invalid');
  }
  if(!bytes32Pattern.test(observation.governanceCodeHash??'')
      || !bytes32Pattern.test(releaseConfig?.governanceCodeHash??'')
      || observation.governanceCodeHash.toLowerCase()
        !==releaseConfig.governanceCodeHash.toLowerCase()) {
    add(blockers,'native_attestation_approval_governance_codehash_mismatch',
      'the EIP-1271 verifier code differs from the release');
  }
  const approvals=observation.approvals;
  const names=Object.keys(attestations).sort();
  if(!approvals || typeof approvals!=='object' || Array.isArray(approvals)
      || JSON.stringify(Object.keys(approvals).sort())!==JSON.stringify(names)) {
    add(blockers,'native_attestation_approval_set_mismatch',
      'the finalized approval snapshot does not contain exactly the required native attestations');
    return;
  }
  for(const name of names) {
    const approval=approvals[name];
    if(!approval || typeof approval!=='object' || Array.isArray(approval)
        || JSON.stringify(Object.keys(approval).sort())!==JSON.stringify(['digest','valid'])) {
      add(blockers,`native_attestation_${name}_approval_invalid`,
        `${name} approval must contain only its EIP-712 digest and EIP-1271 result`);
      continue;
    }
    let digest=null;
    try { digest=nativeReleaseAttestationDigest(attestations[name],releaseConfig); }
    catch { /* the content validator emits the field-specific blocker */ }
    if(!bytes32Pattern.test(approval.digest??'') || !digest
        || approval.digest.toLowerCase()!==digest.toLowerCase()) {
      add(blockers,`native_attestation_${name}_digest_mismatch`,
        `${name} EIP-1271 approval does not bind the current EIP-712 attestation`);
    }
    if(approval.valid!==true) {
      add(blockers,`native_attestation_${name}_eip1271_rejected`,
        `${name} was not accepted by release governance through EIP-1271`);
    }
    if(typeof observation.finalizedBlockTimestamp==='string'
        && /^[1-9][0-9]*$/.test(observation.finalizedBlockTimestamp)
        && typeof attestations[name]?.completedAt==='string'
        && /^[1-9][0-9]*$/.test(attestations[name].completedAt)
        && BigInt(attestations[name].completedAt)>BigInt(observation.finalizedBlockTimestamp)) {
      add(blockers,`native_attestation_${name}_completed_after_finalized_snapshot`,
        `${name} completion time is later than the finalized approval snapshot`);
    }
  }
}

function requireCheckpointVerifierConfiguration(
  blockers,evidence,evidenceFiles,releaseConfig,checkpointVerifierConfig,
) {
  if (!validDocument(evidence?.checkpointVerifierConfigManifest,evidenceFiles)) return null;
  if (!checkpointVerifierConfig || typeof checkpointVerifierConfig!=='object'
      || Array.isArray(checkpointVerifierConfig)) {
    add(blockers,'checkpoint_verifier_config_manifest_unreadable',
      'the hash-verified checkpoint verifier configuration manifest was not parsed');
    return null;
  }
  let computed;
  try {
    computed=checkpointVerifierConfigHash(checkpointVerifierConfig);
  } catch(error) {
    add(blockers,'checkpoint_verifier_config_manifest_invalid',error.message);
    return null;
  }
  if(computed.manifestSha256.slice(2)!==evidence.checkpointVerifierConfigManifest.sha256) {
    add(blockers,'checkpoint_verifier_config_manifest_noncanonical',
      'checkpoint verifier configuration file is not the canonical manifest encoding');
  }
  if(!bytes32Pattern.test(releaseConfig?.checkpointVerifierConfigHash??'')
      || computed.verifierConfigHash!==releaseConfig.checkpointVerifierConfigHash.toLowerCase()) {
    add(blockers,'checkpoint_verifier_config_hash_mismatch',
      'checkpointVerifierConfigHash does not match its canonical manifest');
  }
  for(const [manifestField,releaseField] of [
    ['ethereumChainId','ethereumChainId'],
    ['activationScheduleCommitment','activationScheduleCommitment'],
    ['domNetworkMagic','checkpointDomNetworkMagic'],['domChainId','checkpointDomChainId'],
    ['firstV4Height','checkpointFirstV4Height'],
    ['activationEmptyStateRoot','checkpointActivationEmptyStateRoot'],
    ['checkpointInterval','checkpointIntervalBlocks'],
    ['confirmationDepth','checkpointConfirmationDepthBlocks'],
    ['challengePeriod','checkpointChallengePeriodSeconds'],
  ]) {
    if(String(computed[manifestField]).toLowerCase()!==String(releaseConfig?.[releaseField]).toLowerCase()) {
      add(blockers,`checkpoint_verifier_${manifestField}_release_mismatch`,
        `${manifestField} differs between checkpoint verifier manifest and release`);
    }
  }
  for(const [documentName,configName] of [
    ['checkpointVerifyingKeyArtifact','verifyingKeySha256'],
    ['checkpointProvingProgramArtifact','provingProgramSha256'],
    ['checkpointProvingProgramSourceManifest','sourceManifestSha256'],
    ['checkpointVerifierArtifact','verifierArtifactSha256'],
  ]) {
    const document=evidence?.[documentName];
    if(validDocument(document,evidenceFiles) && computed[configName].slice(2)!==document.sha256) {
      add(blockers,`checkpoint_verifier_config_${documentName}_mismatch`,
        `${documentName} differs from the checkpoint verifier manifest`);
    }
  }
  const setup=evidence?.checkpointTrustedSetup;
  if(typeof setup?.required==='boolean' && setup.required!==computed.trustedSetupRequired) {
    add(blockers,'checkpoint_verifier_config_trusted_setup_mismatch',
      'checkpoint trusted-setup decision differs from its verifier manifest');
  }
  if(setup?.required && validDocument(setup.transcript,evidenceFiles)
      && computed.trustedSetupTranscriptSha256.slice(2)!==setup.transcript.sha256) {
    add(blockers,'checkpoint_verifier_config_trusted_setup_transcript_mismatch',
      'checkpoint trusted-setup transcript differs from its verifier manifest');
  }
  return computed;
}

function requireVerifierConfiguration(blockers, evidence, evidenceFiles, releaseConfig, verifierConfig) {
  if (!validDocument(evidence?.verifierConfigManifest, evidenceFiles)) return null;
  if (!verifierConfig || typeof verifierConfig !== 'object' || Array.isArray(verifierConfig)) {
    add(blockers, 'verifier_config_manifest_unreadable', 'the hash-verified verifier configuration manifest was not parsed');
    return null;
  }
  let computed;
  try {
    computed=finalizedBurnVerifierConfigHash(verifierConfig);
  } catch (error) {
    add(blockers, 'verifier_config_manifest_invalid', error.message);
    return null;
  }
  if (computed.manifestSha256.slice(2) !== evidence.verifierConfigManifest.sha256) {
    add(blockers, 'verifier_config_manifest_noncanonical', 'verifier configuration file is not the canonical manifest encoding');
  }
  if (!bytes32Pattern.test(releaseConfig?.verifierConfigHash ?? '')
      || computed.verifierConfigHash !== releaseConfig.verifierConfigHash.toLowerCase()) {
    add(blockers, 'verifier_config_hash_mismatch', 'verifierConfigHash does not match the canonical verifier manifest');
  }
  if (!bytes32Pattern.test(releaseConfig?.activationScheduleCommitment ?? '')
      || computed.activationScheduleCommitment !== releaseConfig.activationScheduleCommitment.toLowerCase()) {
    add(blockers, 'verifier_activation_schedule_mismatch', 'verifier manifest uses another DOM activation schedule');
  }
  if(String(computed.ethereumChainId)!==String(releaseConfig?.ethereumChainId)) {
    add(blockers,'verifier_ethereumChainId_release_mismatch',
      'finalized-burn verifier manifest uses another Ethereum chain');
  }
  const artifactBindings = [
    ['verifyingKeyArtifact','verifyingKeySha256'],
    ['provingProgramArtifact','provingProgramSha256'],
    ['provingProgramSourceManifest','sourceManifestSha256'],
    ['verifierArtifact','verifierArtifactSha256'],
  ];
  for (const [documentName, configName] of artifactBindings) {
    const document=evidence?.[documentName];
    if (validDocument(document,evidenceFiles)
        && computed[configName].slice(2) !== document.sha256) {
      add(blockers, `verifier_config_${documentName}_mismatch`, `${documentName} differs from the verifier manifest`);
    }
  }
  const setup=evidence?.trustedSetup;
  if (typeof setup?.required === 'boolean' && setup.required !== computed.trustedSetupRequired) {
    add(blockers, 'verifier_config_trusted_setup_mismatch', 'trusted-setup decision differs from the verifier manifest');
  }
  if (setup?.required && validDocument(setup.transcript,evidenceFiles)
      && computed.trustedSetupTranscriptSha256.slice(2) !== setup.transcript.sha256) {
    add(blockers, 'verifier_config_trusted_setup_transcript_mismatch', 'trusted-setup transcript differs from the verifier manifest');
  }
  return computed;
}

function requireRepositoryProvenance(blockers, evidence, repositoryState) {
  if (!repositoryState || typeof repositoryState !== 'object') {
    add(blockers, 'repository_state_missing', 'the actual Git repository state was not inspected');
    return;
  }
  if (repositoryState.importProvenanceVerified !== true) {
    add(blockers, 'source_import_provenance_unverified', 'the imported-source provenance check must pass');
  }
  if (repositoryState.sourceManifestVerified !== true) {
    add(blockers, 'source_manifest_unverified', 'the complete deterministic source manifest check must pass');
  }
  if (repositoryState.ethereumFinalityPanicBoundaryVerified !== true) {
    add(blockers, 'ethereum_finality_panic_boundary_unverified',
      'the Ethereum finality panic boundary and its complete manifest must pass');
  }
  if (repositoryState.nativeStatePanicBoundaryVerified !== true) {
    add(blockers, 'native_state_panic_boundary_unverified',
      'the native USDOM state panic boundary and its complete manifest must pass');
  }
  if (repositoryState.nativePrivacyPanicBoundaryVerified !== true) {
    add(blockers, 'native_privacy_panic_boundary_unverified',
      'the native USDOM privacy panic boundary and its complete manifest must pass');
  }
  if (repositoryState.proofProgramPanicBoundaryVerified !== true) {
    add(blockers, 'proof_program_panic_boundary_unverified',
      'proof-program panic, host-input and source-manifest boundaries must pass');
  }
  if (repositoryState.nativeWalletPanicBoundaryVerified !== true) {
    add(blockers, 'native_wallet_panic_boundary_unverified',
      'the native USDOM wallet panic boundary and its complete manifest must pass');
  }
  if (repositoryState.dirty !== false) add(blockers, 'repository_dirty', 'the release source tree must be clean');
  if (typeof evidence?.sourceCommit !== 'string' || !/^[0-9a-f]{40}$/.test(evidence.sourceCommit)) {
    add(blockers, 'source_commit_missing', 'the release manifest requires an exact lowercase Git commit');
  } else if (repositoryState.sourceCommit !== evidence.sourceCommit) {
    add(blockers, 'source_commit_mismatch',
      'the release manifest sourceCommit does not equal the inspected immutable source commit');
  }
  if (typeof repositoryState.head !== 'string' || !/^[0-9a-f]{40}$/.test(repositoryState.head)
      || repositoryState.head === evidence?.sourceCommit) {
    add(blockers, 'release_evidence_commit_missing',
      'HEAD must be a distinct signed release-evidence commit after the immutable source commit');
  }
  if (!Array.isArray(repositoryState.headParents)
      || repositoryState.headParents.length !== 1
      || repositoryState.headParents[0] !== evidence?.sourceCommit) {
    add(blockers, 'release_evidence_parent_mismatch',
      'the release-evidence commit must have the exact sourceCommit as its sole parent');
  }
  const changes=repositoryState.releaseEvidenceChanges;
  if (!Array.isArray(changes)) {
    add(blockers,'release_evidence_diff_missing',
      'the exact source-to-release-evidence commit diff was not inspected');
  } else {
    let malformed=false;
    const seen=new Set();
    let releaseConfigModified=false;
    let operatorIntentModified=false;
    for(const change of changes) {
      if(!change || typeof change!=='object' || Array.isArray(change)
          || Object.keys(change).sort().join(',')!=='path,status'
          || typeof change.path!=='string' || typeof change.status!=='string'
          || seen.has(change.path)) {
        malformed=true;
        continue;
      }
      seen.add(change.path);
      if(change.path===releaseEvidenceConfigPath) {
        releaseConfigModified ||= change.status==='M';
        malformed ||= change.status!=='M';
      } else if(change.path===operatorIntentPath) {
        operatorIntentModified ||= change.status==='M';
        malformed ||= change.status!=='M';
      } else if(change.path.startsWith(releaseEvidencePathPrefix)
          && change.path.length>releaseEvidencePathPrefix.length) {
        malformed ||= !['A','M'].includes(change.status);
      } else {
        malformed=true;
      }
    }
    if(!releaseConfigModified || !operatorIntentModified) {
      add(blockers,'release_evidence_metadata_diff_missing',
        'the evidence commit must modify both release evidence and operator intent metadata');
    }
    if(malformed) {
      add(blockers,'release_evidence_diff_forbidden',
        'the evidence commit contains a malformed, duplicate, deleted or non-evidence path');
    }
  }
  if (typeof evidence?.sourceTag !== 'string' || !evidence.sourceTag) {
    add(blockers, 'source_tag_missing', 'the release manifest requires an annotated signed source tag');
  } else if (!isCanonicalReleaseTag(evidence.sourceTag)) {
    add(blockers,'source_tag_invalid','sourceTag must use canonical usdom-v<semver> release syntax');
  } else if (repositoryState.tagCommit !== repositoryState.head) {
    add(blockers, 'source_tag_mismatch', 'the declared source tag does not resolve to the inspected HEAD');
  }
  if (repositoryState.sourceCommitSignatureVerified !== true) {
    add(blockers, 'source_commit_signature_unverified',
      'git verify-commit must authenticate the immutable source commit');
  }
  if (repositoryState.releaseCommitSignatureVerified !== true) {
    add(blockers, 'release_evidence_commit_signature_unverified',
      'git verify-commit must authenticate the release-evidence HEAD');
  }
  if (repositoryState.tagSignatureVerified !== true) {
    add(blockers, 'source_tag_signature_unverified', 'git verify-tag must authenticate the declared tag');
  }
  if (repositoryState.sourceAuthor !== expectedReleaseIdentity) {
    add(blockers, 'source_author_mismatch', 'source author identity is not the required identity');
  }
  if (repositoryState.sourceCommitter !== expectedReleaseIdentity) {
    add(blockers, 'source_committer_mismatch', 'source committer identity is not the required identity');
  }
  if (repositoryState.releaseAuthor !== expectedReleaseIdentity) {
    add(blockers, 'release_evidence_author_mismatch',
      'release-evidence author identity is not the required identity');
  }
  if (repositoryState.releaseCommitter !== expectedReleaseIdentity) {
    add(blockers, 'release_evidence_committer_mismatch',
      'release-evidence committer identity is not the required identity');
  }
}

/**
 * Fail-closed, offline release assessment. A passing result proves only that
 * the reviewed repository contains every declared gate and hash-addressed
 * evidence file. Reviewers must still authenticate report authors and execute
 * the deployment runbook against finalized Ethereum state.
 */
export function assessMainnetReadiness({
  mode = 'closed-mainnet', requirements, operatorIntent, releaseConfig, evidence, evidenceFiles, repositoryState,
  trustedReleaseSigningKeyFingerprint,
  contractSource, checkpointContractSource,
  compiledReserveRuntimeCodeHash, compiledReserveInitcodeHash,
  compiledCheckpointRegistryRuntimeCodeHash, compiledCheckpointRegistryInitcodeHash, verifierConfig,
  checkpointVerifierConfig,riscZeroReference,compiledVerifierRuntimeCodeHash,
  compiledVerifierInitcodeHash,compiledCheckpointVerifierRuntimeCodeHash,
  compiledCheckpointVerifierInitcodeHash,predeploymentAttestation,coldStartAttestation,
  nativePrivacyTrustedSetupAttestation,nativeScheduledRuntimeActivationAttestation,
  nativeWalletCustodyAttestation,nativeWalletRecoveryAttestation,
  nativeAttestationApprovalObservation,nativeRuntimeValidation,
}) {
  if (!['closed-mainnet','real-funds'].includes(mode)) throw new Error('mode must be closed-mainnet or real-funds');
  const blockers = [];
  if (!requirements || typeof requirements !== 'object') add(blockers, 'requirements_missing', 'production requirements are missing');
  else {
    for (const key of closedMainnetRequirements) {
      if (requirements[key] !== true) add(blockers, `requirement_${key}`, `${key} must be true`);
    }
    if (requirements.production_withdrawal_queue_lease_period_seconds !== 7 * 24 * 60 * 60) {
      add(blockers, 'requirement_production_withdrawal_queue_lease_period_seconds',
        'production_withdrawal_queue_lease_period_seconds must be exactly 604800');
    }
    const finality = requirements.finality_evaluation;
    if (!finality || typeof finality.selected_production_mechanism !== 'string' || !finality.selected_production_mechanism) {
      add(blockers, 'production_finality_unselected', 'a production finality mechanism must be selected');
    }
    if (requirements.checkpoint_poc_authorization?.production_mechanism_approved !== true) {
      add(blockers, 'production_finality_unapproved', 'the selected production finality mechanism must be approved');
    }
    if (requirements.deploy_authorized !== true) add(blockers, 'requirements_deploy_unauthorized', 'deployment authorization is absent');
    if (mode === 'real-funds') {
      for (const key of realFundsRequirements) {
        if (requirements[key] !== true) add(blockers, `requirement_${key}`, `${key} must be true`);
      }
      if (requirements.mainnet_ready !== true) add(blockers, 'requirements_mainnet_not_ready', 'mainnet_ready must be true');
      if (requirements.real_funds_authorized !== true) add(blockers, 'requirements_real_funds_unauthorized', 'real-funds authorization is absent');
    }
  }

  if (!operatorIntent || typeof operatorIntent !== 'object') add(blockers, 'operator_intent_missing', 'operator intent is missing');
  else {
    if(operatorIntent.schema!==1 || !exactObject(operatorIntent,operatorIntentKeys)) {
      add(blockers,'operator_intent_schema_invalid',
        'operator intent must use schema 1 with the exact supported top-level fields');
    }
    if (operatorIntent.production_approved !== true) add(blockers, 'operator_production_unapproved', 'production approval is absent');
    if (operatorIntent.deploy_authorized !== true) add(blockers, 'operator_deploy_unauthorized', 'operator deployment authorization is absent');
    if (!Array.isArray(operatorIntent.undefined)
        || operatorIntent.undefined.some(value=>typeof value!=='string' || value.length===0)
        || new Set(operatorIntent.undefined).size!==operatorIntent.undefined.length) {
      add(blockers,'operator_parameters_undefined_invalid',
        'undefined production parameters must be a unique array of nonempty strings');
    } else if (operatorIntent.undefined.length) {
      add(blockers, 'operator_parameters_undefined', `undefined production parameters: ${operatorIntent.undefined.join(', ')}`);
    }
    if (mode === 'real-funds' && operatorIntent.real_funds_authorized !== true) {
      add(blockers, 'operator_real_funds_unauthorized', 'operator real-funds authorization is absent');
    }
    const signingFingerprint=trustedReleaseSigningKeyFingerprint;
    if (!isCanonicalGitSigningKeyFingerprint(signingFingerprint)) {
      add(blockers,'trusted_release_signing_key_unconfigured',
        'an out-of-repository canonical release-signing fingerprint is not configured');
    } else {
      if (operatorIntent.release_signing_key_fingerprint!==signingFingerprint) {
        add(blockers,'operator_release_signing_key_mismatch',
          'the repository declaration differs from the out-of-repository release trust anchor');
      }
      if (repositoryState?.sourceCommitSignerFingerprint!==signingFingerprint) {
        add(blockers,'source_commit_signer_mismatch',
          'the immutable source commit was not signed by the operator-pinned key');
      }
      if (repositoryState?.releaseCommitSignerFingerprint!==signingFingerprint) {
        add(blockers,'release_evidence_commit_signer_mismatch',
          'the release-evidence commit was not signed by the operator-pinned key');
      }
      if (repositoryState?.tagSignerFingerprint!==signingFingerprint) {
        add(blockers,'source_tag_signer_mismatch',
          'the release tag was not signed by the operator-pinned key');
      }
    }
    const acceptance=operatorIntent.residual_risk_acceptance;
    if(acceptance && typeof acceptance==='object' && !Array.isArray(acceptance)
        && !exactObject(acceptance,residualRiskAcceptanceKeys)) {
      add(blockers,'operator_residual_risk_schema_invalid',
        'residual-risk acceptance must use the exact supported schema');
    }
    if (!acceptance || typeof acceptance!=='object' || Array.isArray(acceptance)
        || acceptance.accepted!==true) {
      add(blockers,'operator_residual_risk_unaccepted',
        'documented residual risk must be explicitly accepted for the exact release');
    } else {
      if (acceptance.releaseId!==evidence?.releaseId) {
        add(blockers,'operator_residual_risk_release_mismatch',
          'residual-risk acceptance releaseId does not match the evidence release');
      }
      if (acceptance.sourceCommit!==evidence?.sourceCommit) {
        add(blockers,'operator_residual_risk_commit_mismatch',
          'residual-risk acceptance sourceCommit does not match the evidence release');
      }
      for (const [field,expected] of [
        ['reserveConfigHash',releaseConfig?.reserveConfigHash],
        ['checkpointRegistryConfigHash',releaseConfig?.checkpointRegistryConfigHash],
      ]) {
        const value=acceptance[field];
        if (!bytes32Pattern.test(value??'') || !bytes32Pattern.test(expected??'')
            || value.toLowerCase()!==expected.toLowerCase()) {
          add(blockers,`operator_residual_risk_${field}_mismatch`,
            `residual-risk acceptance ${field} does not match the release`);
        }
      }
      const reportSha=evidence?.residualRiskAcceptanceReport?.sha256;
      if (!sha256Pattern.test(acceptance.reportSha256??'') || acceptance.reportSha256!==reportSha) {
        add(blockers,'operator_residual_risk_report_mismatch',
          'residual-risk acceptance does not bind the exact report SHA-256');
      }
      try {
        if (getAddress(acceptance.acceptingAuthority)!==getAddress(releaseConfig?.governance)) {
          add(blockers,'operator_residual_risk_authority_mismatch',
            'residual-risk acceptance authority does not match release governance');
        }
      } catch {
        add(blockers,'operator_residual_risk_authority_invalid',
          'residual-risk acceptance authority is not a valid address');
      }
      if (typeof acceptance.acceptedAt!=='string' || !/^[1-9][0-9]*$/.test(acceptance.acceptedAt)) {
        add(blockers,'operator_residual_risk_timestamp_invalid',
          'residual-risk acceptance timestamp must be a nonzero canonical integer string');
      } else {
        try { uint(acceptance.acceptedAt,64); }
        catch {
          add(blockers,'operator_residual_risk_timestamp_invalid',
            'residual-risk acceptance timestamp must fit uint64');
        }
      }
    }
  }

  let computed;
  let computedCheckpoint;
  if (!releaseConfig || typeof releaseConfig !== 'object') add(blockers, 'release_config_missing', 'proof-reserve release config is missing');
  else {
    if(!exactObject(releaseConfig,releaseConfigKeys)) {
      add(blockers,'release_config_schema_invalid',
        'proof-reserve release config must use the exact supported 59-field schema');
    }
    for (const key of releaseFields) {
      if (releaseConfig[key] === null || releaseConfig[key] === undefined || releaseConfig[key] === '') {
        add(blockers, `release_${key}_missing`, `${key} is not configured`);
      }
    }
    if (releaseConfig.productionReady !== true) add(blockers, 'release_not_production_ready', 'productionReady must be true');
    if(typeof releaseConfig.realFundsAuthorized!=='boolean') {
      add(blockers,'release_real_funds_authorization_invalid','realFundsAuthorized must be boolean');
    }
    if (releaseConfig.ethereumChainId !== '1') {
      add(blockers, 'release_wrong_chain', 'Ethereum chain ID must be the exact string 1');
    }
    if(releaseConfig.ethereumGenesisValidatorsRoot!==ethereumMainnetGenesisValidatorsRoot) {
      add(blockers,'release_ethereum_genesis_validators_root_invalid',
        'ethereumGenesisValidatorsRoot must be the canonical Ethereum mainnet root');
    }
    if(!bytes32Pattern.test(releaseConfig.nativeEthereumTrustedCheckpoint??'')
        || releaseConfig.nativeEthereumTrustedCheckpoint.toLowerCase()===zeroHash) {
      add(blockers,'release_native_ethereum_trusted_checkpoint_invalid',
        'nativeEthereumTrustedCheckpoint must be a nonzero bytes32 value');
    }
    try {
      const withdrawalDelay=uint(releaseConfig.withdrawalDelaySeconds,64);
      const relayMargin=uint(releaseConfig.nativeRelaySafetyMarginSeconds,64);
      const anchorAge=uint(releaseConfig.nativeMaxEthereumAnchorAgeSeconds,64);
      const clockLead=uint(releaseConfig.nativeMaxDomClockLeadSeconds,64);
      const minimum=withdrawalDelay+reserveMinExecutionWindowSeconds+relayMargin;
      if(relayMargin===0n || anchorAge===0n || clockLead===0n
          || clockLead<domMaxFutureBlockTimeSeconds || relayMargin<anchorAge
          || clockLead>=reserveMaxCertificateLifetimeSeconds
          || minimum>reserveMaxCertificateLifetimeSeconds-clockLead) {
        throw new Error('native burn timing policy is incompatible with reserve certificate windows');
      }
    } catch(error) {
      add(blockers,'release_native_burn_timing_invalid',error.message);
    }
    if (releaseConfig.reserveRuntimeCodeHash !== null && releaseConfig.reserveRuntimeCodeHash !== undefined
        && (!bytes32Pattern.test(releaseConfig.reserveRuntimeCodeHash)
          || releaseConfig.reserveRuntimeCodeHash.toLowerCase() === zeroHash)) {
      add(blockers, 'release_reserve_runtime_codehash_invalid', 'reserveRuntimeCodeHash must be nonzero bytes32');
    }
    if (releaseConfig.reserveInitcodeHash !== null && releaseConfig.reserveInitcodeHash !== undefined
        && (!bytes32Pattern.test(releaseConfig.reserveInitcodeHash)
          || releaseConfig.reserveInitcodeHash.toLowerCase()===zeroHash)) {
      add(blockers, 'release_reserve_initcode_hash_invalid', 'reserveInitcodeHash must be nonzero bytes32');
    }
    for (const [field,code] of [
      ['checkpointRegistryRuntimeCodeHash','checkpoint_registry_runtime_codehash'],
      ['checkpointRegistryInitcodeHash','checkpoint_registry_initcode_hash'],
      ['verifierInitcodeHash','verifier_initcode_hash'],
      ['checkpointVerifierInitcodeHash','checkpoint_verifier_initcode_hash'],
    ]) {
      const value=releaseConfig[field];
      if (value!==null && value!==undefined
          && (!bytes32Pattern.test(value) || value.toLowerCase()===zeroHash)) {
        add(blockers,`release_${code}_invalid`,`${field} must be nonzero bytes32`);
      }
    }
    if (releaseConfig.deploymentMethod !== 'CREATE') {
      add(blockers, 'release_deployment_method_invalid', 'the committed-address release supports only CREATE');
    } else {
      try {
        const deployer = getAddress(releaseConfig.deployer);
        if (BigInt(deployer) === 0n) throw new Error('deployer must not be zero');
        const nonce = uint(releaseConfig.deployerNonce, 64);
        const expectedReserve = getCreateAddress({from:deployer,nonce});
        if (getAddress(releaseConfig.reserve) !== expectedReserve) {
          add(blockers, 'release_reserve_address_mismatch', 'reserve does not match the approved deployer and nonce');
        }
      } catch (error) {
        add(blockers, 'release_deployment_plan_invalid', `invalid CREATE deployment plan: ${error.message}`);
      }
    }
    if (releaseConfig.deploymentMethod === 'CREATE') {
      try {
        const deployer=getAddress(releaseConfig.checkpointRegistryDeployer);
        if (BigInt(deployer)===0n) throw new Error('checkpoint registry deployer must not be zero');
        const nonce=uint(releaseConfig.checkpointRegistryDeployerNonce,64);
        const expectedRegistry=getCreateAddress({from:deployer,nonce});
        if (getAddress(releaseConfig.checkpointRegistry)!==expectedRegistry) {
          add(blockers,'release_checkpoint_registry_address_mismatch',
            'checkpointRegistry does not match the approved deployer and nonce');
        }
      } catch (error) {
        add(blockers,'release_checkpoint_registry_deployment_plan_invalid',
          `invalid checkpoint registry CREATE plan: ${error.message}`);
      }
    }
    if (releaseConfig.deploymentMethod === 'CREATE') {
      for(const [prefix,deployerField,nonceField,addressField] of [
        ['verifier','verifierDeployer','verifierDeployerNonce','verifier'],
        ['checkpoint_verifier','checkpointVerifierDeployer','checkpointVerifierDeployerNonce',
          'checkpointVerifier'],
      ]) {
        try {
          const deployer=getAddress(releaseConfig[deployerField]);
          if(BigInt(deployer)===0n) throw new Error(`${prefix} deployer must not be zero`);
          const nonce=uint(releaseConfig[nonceField],64);
          if(getAddress(releaseConfig[addressField])!==getCreateAddress({from:deployer,nonce})) {
            add(blockers,`release_${prefix}_address_mismatch`,
              `${addressField} does not match the approved deployer and nonce`);
          }
        } catch(error) {
          add(blockers,`release_${prefix}_deployment_plan_invalid`,
            `invalid ${prefix} CREATE plan: ${error.message}`);
        }
      }
    }
    try {
      if (getAddress(releaseConfig.token) !== mainnetUsdt) add(blockers, 'release_wrong_token', 'token is not Ethereum mainnet USDT');
    } catch {
      add(blockers, 'release_invalid_token', 'token is not a valid address');
    }
    if (mode === 'real-funds' && releaseConfig.realFundsAuthorized !== true) {
      add(blockers, 'release_real_funds_unauthorized', 'release manifest does not authorize real funds');
    }
    const commitmentFields = ['ethereumChainId','reserve','token','tokenCodeHash','verifier','verifierCodeHash',
      'verifierConfigHash','domDomain','activationScheduleCommitment',
      'governance','governanceCodeHash','guardian','guardianCodeHash',
      'withdrawalDelaySeconds','governanceDelaySeconds',
      'maxOutstandingBaseUnits','outflowCapacityBaseUnitsPerDay'];
    if (commitmentFields.every(key => releaseConfig[key] !== null && releaseConfig[key] !== undefined)) {
      try {
        computed = proofReserveDeploymentConfigHash({
          ethereumChainId:releaseConfig.ethereumChainId,reserve:releaseConfig.reserve,token:releaseConfig.token,
          tokenCodeHash:releaseConfig.tokenCodeHash,verifier:releaseConfig.verifier,
          verifierCodeHash:releaseConfig.verifierCodeHash,verifierConfigHash:releaseConfig.verifierConfigHash,
          domDomain:releaseConfig.domDomain,activationScheduleCommitment:releaseConfig.activationScheduleCommitment,
          governance:releaseConfig.governance,
          governanceCodeHash:releaseConfig.governanceCodeHash,guardian:releaseConfig.guardian,
          guardianCodeHash:releaseConfig.guardianCodeHash,
          withdrawalDelaySeconds:releaseConfig.withdrawalDelaySeconds,
          governanceDelaySeconds:releaseConfig.governanceDelaySeconds,
          maxOutstandingBaseUnits:releaseConfig.maxOutstandingBaseUnits,
          outflowCapacityBaseUnitsPerDay:releaseConfig.outflowCapacityBaseUnitsPerDay,
        });
        if (typeof releaseConfig.reserveConfigHash !== 'string'
            || releaseConfig.reserveConfigHash.toLowerCase() !== computed.reserveConfigHash) {
          add(blockers, 'release_config_hash_mismatch', 'reserveConfigHash does not match the exact release fields');
        }
      } catch (error) {
        add(blockers, 'release_config_invalid', error.message);
      }
    }
    const checkpointCommitmentFields=['ethereumChainId','checkpointRegistry','domDomain',
      'checkpointDomNetworkMagic','checkpointDomChainId','checkpointFirstV4Height',
      'checkpointActivationEmptyStateRoot','activationScheduleCommitment','checkpointVerifier',
      'checkpointVerifierCodeHash','checkpointVerifierConfigHash','checkpointGuardian',
      'checkpointGuardianCodeHash','checkpointIntervalBlocks','checkpointConfirmationDepthBlocks',
      'checkpointChallengePeriodSeconds','checkpointInitialHeight','checkpointInitialBlock',
      'checkpointInitialStateRoot','checkpointInitialContextHash','checkpointInitialTotalDifficulty'];
    if (checkpointCommitmentFields.every(key => releaseConfig[key] !== null && releaseConfig[key] !== undefined)) {
      try {
        const schedule=activationSchedule({networkMagic:releaseConfig.checkpointDomNetworkMagic,
          chainId:releaseConfig.checkpointDomChainId,firstV4Height:releaseConfig.checkpointFirstV4Height,
          emptyStateRoot:releaseConfig.checkpointActivationEmptyStateRoot});
        if (schedule.commitment!==releaseConfig.activationScheduleCommitment.toLowerCase()) {
          add(blockers,'release_checkpoint_activation_schedule_mismatch',
            'checkpoint activation fields do not produce activationScheduleCommitment');
        }
        computedCheckpoint=checkpointRegistryConfigHash({
          ethereumChainId:releaseConfig.ethereumChainId,registry:releaseConfig.checkpointRegistry,
          bridgeDomain:releaseConfig.domDomain,domNetworkMagic:releaseConfig.checkpointDomNetworkMagic,
          domChainId:releaseConfig.checkpointDomChainId,
          firstV4Height:releaseConfig.checkpointFirstV4Height,
          activationEmptyStateRoot:releaseConfig.checkpointActivationEmptyStateRoot,
          activationScheduleCommitment:releaseConfig.activationScheduleCommitment,
          checkpointInterval:releaseConfig.checkpointIntervalBlocks,
          confirmationDepth:releaseConfig.checkpointConfirmationDepthBlocks,
          challengePeriod:releaseConfig.checkpointChallengePeriodSeconds,
          verifier:releaseConfig.checkpointVerifier,
          verifierCodeHash:releaseConfig.checkpointVerifierCodeHash,
          verifierConfigHash:releaseConfig.checkpointVerifierConfigHash,
          guardian:releaseConfig.checkpointGuardian,
          guardianCodeHash:releaseConfig.checkpointGuardianCodeHash,
          initialHeight:releaseConfig.checkpointInitialHeight,
          initialBlock:releaseConfig.checkpointInitialBlock,
          initialStateRoot:releaseConfig.checkpointInitialStateRoot,
          initialContextHash:releaseConfig.checkpointInitialContextHash,
          initialTotalDifficulty:releaseConfig.checkpointInitialTotalDifficulty,
        });
        if (typeof releaseConfig.checkpointRegistryConfigHash !== 'string'
            || releaseConfig.checkpointRegistryConfigHash.toLowerCase()
              !== computedCheckpoint.checkpointConfigHash) {
          add(blockers,'release_checkpoint_registry_config_hash_mismatch',
            'checkpointRegistryConfigHash does not match the exact release fields');
        }
      } catch (error) {
        add(blockers,'release_checkpoint_registry_config_invalid',error.message);
      }
    }
  }

  if (typeof contractSource !== 'string') add(blockers, 'contract_source_missing', 'USDOMProofReserve source is missing');
  else {
    const pins = {
      PRODUCTION_VERIFIER_CODE_HASH: releaseConfig?.verifierCodeHash,
      PRODUCTION_VERIFIER_CONFIG_HASH: releaseConfig?.verifierConfigHash,
      PRODUCTION_RESERVE_CONFIG_HASH: computed?.reserveConfigHash,
    };
    for (const [name, expected] of Object.entries(pins)) {
      const actual = readProductionConstant(contractSource, name);
      if (!actual) add(blockers, `contract_${name}_unreadable`, `${name} is absent or not a canonical bytes32 literal`);
      else if (actual === zeroHash) add(blockers, `contract_${name}_zero`, `${name} remains fail-closed zero`);
      else if (!bytes32Pattern.test(expected ?? '') || actual !== expected.toLowerCase()) {
        add(blockers, `contract_${name}_mismatch`, `${name} does not match the release manifest`);
      }
    }
  }

  if (typeof checkpointContractSource !== 'string') {
    add(blockers,'checkpoint_contract_source_missing','DOMCheckpointRegistry source is missing');
  } else {
    const pins={
      PRODUCTION_VERIFIER_CODE_HASH:releaseConfig?.checkpointVerifierCodeHash,
      PRODUCTION_VERIFIER_CONFIG_HASH:releaseConfig?.checkpointVerifierConfigHash,
      PRODUCTION_CHECKPOINT_CONFIG_HASH:computedCheckpoint?.checkpointConfigHash,
    };
    for (const [name,expected] of Object.entries(pins)) {
      const actual=readProductionConstant(checkpointContractSource,name);
      if (!actual) add(blockers,`checkpoint_contract_${name}_unreadable`,`${name} is absent or not canonical`);
      else if (actual===zeroHash) add(blockers,`checkpoint_contract_${name}_zero`,`${name} remains fail-closed zero`);
      else if (!bytes32Pattern.test(expected??'') || actual!==expected.toLowerCase()) {
        add(blockers,`checkpoint_contract_${name}_mismatch`,`${name} does not match the release manifest`);
      }
    }
  }

  if (!bytes32Pattern.test(compiledReserveRuntimeCodeHash ?? '')
      || compiledReserveRuntimeCodeHash.toLowerCase() === zeroHash) {
    add(blockers, 'compiled_reserve_runtime_unavailable', 'the source-verified compiled reserve runtime hash is unavailable');
  } else if (!bytes32Pattern.test(releaseConfig?.reserveRuntimeCodeHash ?? '')
      || compiledReserveRuntimeCodeHash.toLowerCase() !== releaseConfig.reserveRuntimeCodeHash.toLowerCase()) {
    add(blockers, 'compiled_reserve_runtime_mismatch', 'compiled reserve runtime hash differs from the release manifest');
  }
  if (!bytes32Pattern.test(compiledReserveInitcodeHash ?? '') || compiledReserveInitcodeHash.toLowerCase()===zeroHash) {
    add(blockers, 'compiled_reserve_initcode_unavailable', 'the source-verified compiled reserve initcode hash is unavailable');
  } else if (!bytes32Pattern.test(releaseConfig?.reserveInitcodeHash ?? '')
      || compiledReserveInitcodeHash.toLowerCase()!==releaseConfig.reserveInitcodeHash.toLowerCase()) {
    add(blockers, 'compiled_reserve_initcode_mismatch', 'compiled reserve initcode hash differs from the release manifest');
  }
  if (!bytes32Pattern.test(compiledCheckpointRegistryRuntimeCodeHash??'')
      || compiledCheckpointRegistryRuntimeCodeHash.toLowerCase()===zeroHash) {
    add(blockers,'compiled_checkpoint_registry_runtime_unavailable',
      'the source-verified compiled checkpoint registry runtime hash is unavailable');
  } else if (!bytes32Pattern.test(releaseConfig?.checkpointRegistryRuntimeCodeHash??'')
      || compiledCheckpointRegistryRuntimeCodeHash.toLowerCase()
        !== releaseConfig.checkpointRegistryRuntimeCodeHash.toLowerCase()) {
    add(blockers,'compiled_checkpoint_registry_runtime_mismatch',
      'compiled checkpoint registry runtime hash differs from the release manifest');
  }
  if (!bytes32Pattern.test(compiledCheckpointRegistryInitcodeHash??'')
      || compiledCheckpointRegistryInitcodeHash.toLowerCase()===zeroHash) {
    add(blockers,'compiled_checkpoint_registry_initcode_unavailable',
      'the source-verified compiled checkpoint registry initcode hash is unavailable');
  } else if (!bytes32Pattern.test(releaseConfig?.checkpointRegistryInitcodeHash??'')
      || compiledCheckpointRegistryInitcodeHash.toLowerCase()
        !== releaseConfig.checkpointRegistryInitcodeHash.toLowerCase()) {
    add(blockers,'compiled_checkpoint_registry_initcode_mismatch',
      'compiled checkpoint registry initcode hash differs from the release manifest');
  }
  if(!bytes32Pattern.test(compiledVerifierRuntimeCodeHash??'')
      || compiledVerifierRuntimeCodeHash.toLowerCase()===zeroHash) {
    add(blockers,'compiled_verifier_runtime_unavailable',
      'the source-verified finalized-burn adapter runtime hash is unavailable');
  } else if(!bytes32Pattern.test(releaseConfig?.verifierCodeHash??'')
      || compiledVerifierRuntimeCodeHash.toLowerCase()!==releaseConfig.verifierCodeHash.toLowerCase()) {
    add(blockers,'compiled_verifier_runtime_mismatch',
      'compiled finalized-burn adapter runtime hash differs from the release manifest');
  }
  if(!bytes32Pattern.test(compiledVerifierInitcodeHash??'')
      || compiledVerifierInitcodeHash.toLowerCase()===zeroHash) {
    add(blockers,'compiled_verifier_initcode_unavailable',
      'the source-verified finalized-burn adapter initcode hash is unavailable');
  } else if(!bytes32Pattern.test(releaseConfig?.verifierInitcodeHash??'')
      || compiledVerifierInitcodeHash.toLowerCase()!==releaseConfig.verifierInitcodeHash.toLowerCase()) {
    add(blockers,'compiled_verifier_initcode_mismatch',
      'compiled finalized-burn adapter initcode hash differs from the release manifest');
  }
  if(!bytes32Pattern.test(compiledCheckpointVerifierRuntimeCodeHash??'')
      || compiledCheckpointVerifierRuntimeCodeHash.toLowerCase()===zeroHash) {
    add(blockers,'compiled_checkpoint_verifier_runtime_unavailable',
      'the source-verified checkpoint adapter runtime hash is unavailable');
  } else if(!bytes32Pattern.test(releaseConfig?.checkpointVerifierCodeHash??'')
      || compiledCheckpointVerifierRuntimeCodeHash.toLowerCase()
        !==releaseConfig.checkpointVerifierCodeHash.toLowerCase()) {
    add(blockers,'compiled_checkpoint_verifier_runtime_mismatch',
      'compiled checkpoint adapter runtime hash differs from the release manifest');
  }
  if(!bytes32Pattern.test(compiledCheckpointVerifierInitcodeHash??'')
      || compiledCheckpointVerifierInitcodeHash.toLowerCase()===zeroHash) {
    add(blockers,'compiled_checkpoint_verifier_initcode_unavailable',
      'the source-verified checkpoint adapter initcode hash is unavailable');
  } else if(!bytes32Pattern.test(releaseConfig?.checkpointVerifierInitcodeHash??'')
      || compiledCheckpointVerifierInitcodeHash.toLowerCase()
        !==releaseConfig.checkpointVerifierInitcodeHash.toLowerCase()) {
    add(blockers,'compiled_checkpoint_verifier_initcode_mismatch',
      'compiled checkpoint adapter initcode hash differs from the release manifest');
  }

  requireDocuments(blockers, evidence, evidenceFiles, mode, releaseConfig);
  const nativeRuntime=requireNativeRuntimeManifest(blockers,{
    evidence,evidenceFiles,releaseConfig,nativeRuntimeValidation,
  });
  requireNativeReleaseAttestation(blockers,{
    name:'native_privacy_trusted_setup',kind:'native-privacy-trusted-setup',
    document:evidence?.nativePrivacyTrustedSetupAttestationReport,evidenceFiles,
    attestation:nativePrivacyTrustedSetupAttestation,evidence,releaseConfig,
    expectedSubjectCommitment:nativeRuntime?.privacyVerifierSubject,
  });
  requireNativeReleaseAttestation(blockers,{
    name:'native_scheduled_runtime_activation',kind:'native-scheduled-runtime-activation',
    document:evidence?.nativeScheduledRuntimeActivationAttestationReport,evidenceFiles,
    attestation:nativeScheduledRuntimeActivationAttestation,evidence,releaseConfig,
    expectedSubjectCommitment:nativeRuntime?.manifestSubject,
  });
  if(mode==='real-funds') {
    const custodySubject=requireNativeReleaseAttestation(blockers,{
      name:'native_wallet_custody',kind:'native-wallet-custody',
      document:evidence?.nativeWalletCustodyAttestationReport,evidenceFiles,
      attestation:nativeWalletCustodyAttestation,evidence,releaseConfig,
    });
    const recoverySubject=requireNativeReleaseAttestation(blockers,{
      name:'native_wallet_recovery',kind:'native-wallet-recovery',
      document:evidence?.nativeWalletRecoveryAttestationReport,evidenceFiles,
      attestation:nativeWalletRecoveryAttestation,evidence,releaseConfig,
    });
    if(custodySubject && recoverySubject && custodySubject!==recoverySubject) {
      add(blockers,'native_wallet_recovery_identity_mismatch',
        'wallet custody and recovery attestations must bind the same wallet identity commitment');
    }
  }
  const nativeAttestations={
    nativePrivacyTrustedSetup:nativePrivacyTrustedSetupAttestation,
    nativeScheduledRuntimeActivation:nativeScheduledRuntimeActivationAttestation,
    ...(mode==='real-funds'?{
      nativeWalletCustody:nativeWalletCustodyAttestation,
      nativeWalletRecovery:nativeWalletRecoveryAttestation,
    }:{}),
  };
  const nativeAttestationDocuments=[
    evidence?.nativePrivacyTrustedSetupAttestationReport,
    evidence?.nativeScheduledRuntimeActivationAttestationReport,
    ...(mode==='real-funds'?[
      evidence?.nativeWalletCustodyAttestationReport,
      evidence?.nativeWalletRecoveryAttestationReport,
    ]:[]),
  ];
  if(nativeAttestationDocuments.every(document=>validDocument(document,evidenceFiles))) {
    requireNativeAttestationApprovalSnapshot(blockers,{
      observation:nativeAttestationApprovalObservation,attestations:nativeAttestations,releaseConfig,
    });
  }
  const computedVerifierConfig=requireVerifierConfiguration(
    blockers,evidence,evidenceFiles,releaseConfig,verifierConfig,
  );
  if (computedVerifierConfig) {
    for (const [manifestField,releaseField] of [
      ['domNetworkMagic','checkpointDomNetworkMagic'],['domChainId','checkpointDomChainId'],
      ['firstV4Height','checkpointFirstV4Height'],
      ['activationEmptyStateRoot','checkpointActivationEmptyStateRoot'],
    ]) {
      const left=String(computedVerifierConfig[manifestField]).toLowerCase();
      const right=String(releaseConfig?.[releaseField]).toLowerCase();
      if (left!==right) add(blockers,`verifier_${manifestField}_checkpoint_mismatch`,
        `${manifestField} differs between verifier manifest and checkpoint registry release`);
    }
  }
  const computedCheckpointVerifierConfig=requireCheckpointVerifierConfiguration(
    blockers,evidence,evidenceFiles,releaseConfig,checkpointVerifierConfig,
  );
  let trustedRiscZeroReference=null;
  try {
    trustedRiscZeroReference=validateRiscZeroMainnetReference(riscZeroReference);
  } catch(error) {
    add(blockers,'risc0_mainnet_reference_invalid',error.message);
  }
  if(trustedRiscZeroReference) {
    requirePreflightAttestation(blockers,{name:'predeployment',phase:'predeployment',
      document:evidence?.mainnetPredeploymentAttestationReport,evidenceFiles,
      attestation:predeploymentAttestation,releaseConfig,riscZeroReference:trustedRiscZeroReference});
    if(mode==='real-funds') {
      requirePreflightAttestation(blockers,{name:'cold_start',phase:'postdeployment',
        document:evidence?.mainnetColdStartAttestationReport,evidenceFiles,
        attestation:coldStartAttestation,releaseConfig,riscZeroReference:trustedRiscZeroReference});
    }
  }
  if(trustedRiscZeroReference) {
    for(const [computed,prefix] of [
      [computedVerifierConfig,'finalized_burn'],[computedCheckpointVerifierConfig,'checkpoint'],
    ]) {
      if(!computed) continue;
      for(const [field,referenceField] of [
        ['ethereumChainId','chain_id'],['riscZeroVerifier','verifier_address'],
        ['riscZeroVerifierCodeHash','observed_runtime_code_hash'],
        ['riscZeroVerifierSelector','verifier_selector'],
      ]) {
        if(String(computed[field]).toLowerCase()
            !==String(trustedRiscZeroReference[referenceField]).toLowerCase()) {
          add(blockers,`risc0_${prefix}_${field}_untrusted`,
            `${prefix} adapter ${field} differs from the reviewed RISC Zero mainnet pin`);
        }
      }
    }
  }
  if(computedVerifierConfig && computedCheckpointVerifierConfig) {
    for(const field of ['riscZeroVerifier','riscZeroVerifierCodeHash','riscZeroVerifierSelector']) {
      if(String(computedVerifierConfig[field]).toLowerCase()
          !==String(computedCheckpointVerifierConfig[field]).toLowerCase()) {
        add(blockers,`risc0_${field}_adapter_mismatch`,
          `finalized-burn and checkpoint adapters use different ${field}`);
      }
    }
  }
  requireRepositoryProvenance(blockers, evidence, repositoryState);
  return {mode, ready:blockers.length === 0, blockerCount:blockers.length, blockers,
    reserveConfigHash:computed?.reserveConfigHash ?? null,
    checkpointRegistryConfigHash:computedCheckpoint?.checkpointConfigHash ?? null,
    verifierConfigHash:computedVerifierConfig?.verifierConfigHash ?? null,
    checkpointVerifierConfigHash:computedCheckpointVerifierConfig?.verifierConfigHash ?? null};
}
