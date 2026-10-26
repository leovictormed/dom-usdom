import {getAddress,getCreateAddress} from 'ethers';
import {proofReserveDeploymentConfigHash,safeOwnersCommitment} from './configuration.mjs';
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
import {releaseAuthorizationDigest,releaseEvidenceCommitment} from './release-authorization.mjs';
import {validEip1271Signature} from './finalized-eip1271-approval.mjs';
import {validateRpcConsensusEvidence} from './rpc-consensus-evidence.mjs';
import {validateRecoverableSafeControlReleaseArtifactSet} from './safe-control-release-evidence.mjs';
import {validateSafeRecoveryEvidenceBundleShape} from './safe-recovery-evidence-bundle.mjs';
import {validateRiscZeroHealthSourceCatalog} from './risc0-health-source-catalog.mjs';
import {validateFinalizedBurnE2eReport} from './finalized-burn-e2e-report.mjs';
import {validateCheckpointProofCapacityReport} from './checkpoint-proof-capacity-report.mjs';
import {isExactReleaseEvidenceShape} from './release-evidence-schema.mjs';
import {deriveDomDomain} from './preactivation-policy.mjs';
import {validateSecurityValidationReport} from './security-validation-report.mjs';
import {validateOperationsReviewReport} from './operations-review-report.mjs';
import {validateReserveReproducibleBuildReport} from './reserve-reproducible-build-report.mjs';
import {validateVerifierReproducibleBuildReport} from './verifier-reproducible-build-report.mjs';
import {validateMainnetForkRehearsalReport} from './mainnet-fork-rehearsal-report.mjs';
import {validateCheckpointBootstrapRatificationReport}
  from './checkpoint-bootstrap-ratification-report.mjs';
import {validateCheckpointFinalizedEventReport} from './checkpoint-finalized-event-report.mjs';
import {validateCheckpointVerifierReproducibleBuildReport}
  from './checkpoint-verifier-reproducible-build-report.mjs';
import {validateCheckpointRegistryReproducibleBuildReport}
  from './checkpoint-registry-reproducible-build-report.mjs';
import {validateResidualRiskReport} from './residual-risk-report.mjs';
import {validateTrustedSetupDecisionReport} from './trusted-setup-decision-report.mjs';
import {isCanonicalReleaseEvidenceDocumentPath}
  from './release-evidence-document-paths.mjs';
export {isCanonicalReleaseEvidenceDocumentPath}
  from './release-evidence-document-paths.mjs';

const zeroHash = '0x' + '00'.repeat(32);
const sha256Pattern = /^[0-9a-f]{64}$/;
const bytes32Pattern = /^0x[0-9a-fA-F]{64}$/;
const nonzeroUint64Pattern = /^[1-9][0-9]{0,19}$/;

function isCanonicalNonzeroUint64(value) {
  if(typeof value!=='string'||!nonzeroUint64Pattern.test(value)) return false;
  return BigInt(value)<(1n<<64n);
}
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
const operatorIntentKeys = [
  'authority','chainId','checkpoint_poc_authorization','current_phase','deploy_authorized',
  'finality_comparison','finality_direction','local_test_values_not_approved_for_production',
  'native_asset_requirements','network','production_approved','production_trust_model',
  'prototype_trust_model','real_funds_authorized','release_assurance_policy',
  'release_signing_key_fingerprint','residual_risk_acceptance','schema','token','undefined',
];
const residualRiskAcceptanceKeys = [
  'accepted','acceptedAt','acceptingAuthority','checkpointRegistryConfigHash','releaseId',
  'reportSha256','reserveConfigHash','releaseEvidenceCommitment','rule','sourceCommit','sourceTag','productionApproved',
  'deployAuthorized','realFundsAuthorized','signature',
];

const closedMainnetRequirements = [
  'native_consensus_implemented',
  'native_set_witness_bounded_cursor_deserialization',
  'consensus_proof_implemented',
  'native_private_prover_linked_into_node',
  'native_private_wallet_node_dependency',
  'native_private_wallet_private_burn_random_identifiers',
  'native_private_wallet_private_burn_request_id_pending_collision_rejected',
  'native_private_wallet_private_burn_identifiers_proof_and_consensus_bound',
  'native_private_wallet_authenticated_history_atomic_application',
  'native_private_wallet_authenticated_history_partial_release_forbidden',
  'native_private_wallet_authenticated_history_completed_scan_fields_private',
  'native_private_wallet_authenticated_history_failure_restores_original_tip',
  'verified_native_burn_checkpoint_external_restart_floor_required',
  'production_verified_checkpoint_restart_witness_live_exercised',
  'production_finalized_burn_verifier_implemented',
  'production_finalized_burn_proof_backend_selected',
  'production_finalized_burn_guest_compiled',
  'production_finalized_burn_recursive_checkpoint_relation_implemented',
  'production_finalized_burn_recursive_checkpoint_artifacts_pinned',
  'production_finalized_burn_recursive_checkpoint_receipt_verified',
  'production_finalized_burn_guest_benchmarked',
  'production_finalized_burn_raw_checkpoint_positive_vector',
  'production_finalized_burn_risc0_evm_receipt_verifier_implemented',
  'production_finalized_burn_proving_capacity_measured',
  'production_finalized_burn_evm_verification_gas_measured',
  'production_queue_withdrawal_worst_case_gas_measured',
  'production_prune_expired_256_worst_case_gas_measured',
  'production_prune_discardable_256_worst_case_gas_measured',
  'production_safe_admin_overhead_gas_measured',
  'production_finalized_burn_canonical_replay_slot_enforced',
  'production_finalized_burn_positive_evidence_checker_implemented',
  'production_finalized_burn_authenticated_proof_job_planner_implemented',
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
  'production_checkpoint_registry_contract_implemented',
  'production_checkpoint_registry_verifier_implemented',
  'production_checkpoint_registry_verifier_proves_consensus_extension',
  'production_checkpoint_registry_artifact_pinning_implemented',
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
  'production_checkpoint_outer_evm_verification_gas_measured',
  'production_block_header_state_commitment_implemented',
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
  'production_safe_control_unsigned_hardware_deployment_package_implemented',
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
  'production_safe_control_identity_pins_nonoverridable',
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

const realFundsRequirements = [
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
  'tokenOwner','tokenOwnerCodeHash',
  'reserveRuntimeCodeHash','reserveInitcodeHash',
  'verifierDeployer','verifierDeployerNonce','verifier','verifierCodeHash','verifierInitcodeHash',
  'verifierConfigHash',
  'reserveConfigHash','domDomain','activationScheduleCommitment',
  'checkpointRegistryDeployer','checkpointRegistryDeployerNonce','checkpointRegistry',
  'checkpointRegistryRuntimeCodeHash','checkpointRegistryInitcodeHash','checkpointRegistryConfigHash',
  'checkpointVerifierDeployer','checkpointVerifierDeployerNonce','checkpointVerifier',
  'checkpointVerifierCodeHash','checkpointVerifierInitcodeHash','checkpointVerifierConfigHash',
  'checkpointGuardian','checkpointGuardianCodeHash','checkpointGuardianImplementation',
  'checkpointGuardianImplementationCodeHash','checkpointDomNetworkMagic',
  'checkpointDomChainId','checkpointFirstV4Height','checkpointActivationEmptyStateRoot',
  'checkpointIntervalBlocks','checkpointConfirmationDepthBlocks','checkpointChallengePeriodSeconds',
  'checkpointInitialHeight','checkpointInitialBlock','checkpointInitialStateRoot','checkpointInitialContextHash',
  'checkpointInitialTotalDifficulty',
  'governance','governanceCodeHash','governanceImplementation','governanceImplementationCodeHash',
  'governanceOwnersCommitment','guardian','guardianCodeHash','guardianImplementation',
  'guardianImplementationCodeHash','guardianOwnersCommitment',
  'governanceOwners','guardianOwners','checkpointGuardianOwners',
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
  'checkpointProofCapacityReport',
  'checkpointRegistryReproducibleBuildReport','checkpointVerifierReproducibleBuildReport',
  'checkpointBootstrapRatificationReport','checkpointFinalizedEventReport',
  'operationsReviewReport','mainnetForkRehearsalReport',
  'securityValidationReport','residualRiskAcceptanceReport',
  'controlPlaneEvidenceBundle','controlPlaneSeparationReport','controlPlaneRecoveryDrillReport',
  'safeRecoveryFinalEvidenceBundle',
  'mainnetPredeploymentAttestationReport',
  'nativePrivacyTrustedSetupAttestationReport','nativeScheduledRuntimeActivationAttestationReport',
  'nativeRuntimeManifest','nativeRuntimeSpendVerifyingKeyArtifact',
  'reserveArtifact','verifierArtifact','verifierConfigManifest','verifyingKeyArtifact',
  'checkpointRegistryArtifact','checkpointVerifierArtifact',
  'checkpointVerifierConfigManifest','checkpointVerifyingKeyArtifact',
  'checkpointProvingProgramArtifact','checkpointProvingProgramSourceManifest',
  'riscZeroHealthSourceCatalog',
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
    && isCanonicalReleaseEvidenceDocumentPath(document.path)
    && typeof document.sha256 === 'string' && sha256Pattern.test(document.sha256)
    && Object.prototype.hasOwnProperty.call(evidenceFiles ?? {}, document.path)
    && evidenceFiles[document.path] === document.sha256;
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

function requireControlPlaneSemanticEvidence(blockers,evidence,releaseConfig,controlPlaneEvidenceArtifacts) {
  try {
    const bundle=validateRecoverableSafeControlReleaseArtifactSet(
      controlPlaneEvidenceArtifacts,
    );
    const finalBundle=validateSafeRecoveryEvidenceBundleShape(
      controlPlaneEvidenceArtifacts.finalBundle,
    );
    if(finalBundle.packageHash!==bundle.packageHash||finalBundle.recoveryHash!==bundle.recoveryHash
        ||finalBundle.executions.length!==bundle.recoveryDrillReport.roles.length
        ||finalBundle.executions.some((execution,index)=>
          execution.role!==bundle.recoveryDrillReport.roles[index].safeRole
          ||execution.transactionHash!==bundle.recoveryDrillReport.roles[index].transactionHash)) {
      throw new Error('output-last Safe recovery bundle disagrees with release evidence');
    }
    for(const role of ['governance','guardian','checkpointGuardian']) {
      const declared=evidence?.controlPlane?.[role];
      const observed=bundle.roleReports[role];
      if(!declared||getAddress(declared.address)!==getAddress(observed.address)
          || declared.runtimeCodeHash.toLowerCase()!==observed.runtimeCodeHash
          || declared.configurationHash.toLowerCase()!==observed.configurationHash) {
        throw new Error(`${role} release snapshot disagrees with semantic Safe evidence`);
      }
      const configuredOwners=releaseConfig?.[`${role}Owners`];
      if(!Array.isArray(configuredOwners)
          || configuredOwners.length!==observed.ownersAfter.length
          || observed.ownersAfter.some((owner,index)=>
            getAddress(owner)!==getAddress(configuredOwners[index]))) {
        throw new Error(`${role} owners disagree with the exact release`);
      }
    }
  } catch(error) {
    add(blockers,'control_plane_evidence_content_invalid',
      `control-plane evidence is missing, malformed or cross-inconsistent: ${error.message}`);
  }
}

function requireDocuments(blockers, evidence, evidenceFiles, mode, releaseConfig) {
  if (!isExactReleaseEvidenceShape(evidence)) {
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
  const sharedRiscZeroTranscript=setup?.required===true && checkpointSetup?.required===true
    && typeof setup.transcript?.path==='string'
    && setup.transcript.path===checkpointSetup.transcript?.path
    && setup.transcript.sha256===checkpointSetup.transcript?.sha256;
  if(setup?.required===true && checkpointSetup?.required===true && !sharedRiscZeroTranscript) {
    add(blockers,'risc0_trusted_setup_evidence_mismatch',
      'both risc0-groth16-v3 adapters must share the same trusted-setup transcript evidence');
  }
  const sharedTrustedSetupDecision=setup?.required===true && checkpointSetup?.required===true
    &&typeof setup.decisionReport?.path==='string'
    &&setup.decisionReport.path===checkpointSetup.decisionReport?.path
    &&setup.decisionReport.sha256===checkpointSetup.decisionReport?.sha256;
  const sharedRiscZeroVerifyingKey=
    typeof evidence?.verifyingKeyArtifact?.path==='string'
    && evidence.verifyingKeyArtifact.path===evidence?.checkpointVerifyingKeyArtifact?.path
    && evidence.verifyingKeyArtifact.sha256===evidence.checkpointVerifyingKeyArtifact?.sha256;
  const allDocuments = [
    ...evidenceDocuments
      .filter(name=>name!=='checkpointVerifyingKeyArtifact'||!sharedRiscZeroVerifyingKey)
      .map(name => evidence?.[name]),
    ...(mode === 'real-funds' ? realFundsEvidenceDocuments.map(name => evidence?.[name]) : []),
    ...documentArray(evidence?.domConsensusAuditReports),
    ...documentArray(evidence?.privacyCircuitAuditReports),
    ...documentArray(evidence?.solidityAuditReports),
    setup?.decisionReport,...(setup?.required ? [setup.transcript] : []),
    ...(!sharedTrustedSetupDecision ? [checkpointSetup?.decisionReport] : []),
    ...(checkpointSetup?.required && !sharedRiscZeroTranscript ? [checkpointSetup.transcript] : []),
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
    'observation','phase','ready','rpcConsensus'];
  if(!attestation || typeof attestation!=='object' || Array.isArray(attestation)
      || JSON.stringify(Object.keys(attestation).sort())!==JSON.stringify(expectedKeys)) {
    add(blockers,`${name}_attestation_unreadable`,
      `${name} attestation must be the exact parsed preflight report schema`);
    return;
  }
  try { validateRpcConsensusEvidence(attestation.rpcConsensus); }
  catch(error) {
    add(blockers,`${name}_attestation_rpc_consensus_invalid`,
      `${name} RPC consensus evidence is invalid: ${error.message}`);
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
  if(!isCanonicalNonzeroUint64(attestation.completedAt)) {
    add(blockers,`${name}_completed_at_invalid`,`${name} completedAt must be a nonzero canonical uint64 string`);
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
  'checkpoint_confirmation_depth_blocks','checkpoint_interval_blocks',
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
  'randomx_receipt_image_id','spend_verifying_key_sha256','status','withdrawal_delay_secs',
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
    if(!rawHash(validation.randomx_receipt_image_id)
        || validation.randomx_receipt_image_id==='0'.repeat(64)) {
      add(blockers,'native_runtime_randomx_receipt_image_id_invalid',
        'candidate V2 activation requires a nonzero manifest-pinned RandomX receipt ImageID');
    }
    if(validation.checkpoint_interval_blocks!==releaseConfig?.checkpointIntervalBlocks
        || validation.checkpoint_confirmation_depth_blocks
          !==releaseConfig?.checkpointConfirmationDepthBlocks) {
      add(blockers,'native_runtime_checkpoint_schedule_mismatch',
        'candidate V2 checkpoint interval and confirmation depth must match the release');
    }
  } else {
    add(blockers,'native_runtime_candidate_v2_required',
      'production mainnet releases require the candidate-V2 checkpoint runtime to be scheduled');
    if(validation.randomx_receipt_image_id!=='disabled') {
      add(blockers,'native_runtime_randomx_receipt_image_id_unexpected',
        'a legacy V1 runtime cannot select a RandomX receipt ImageID');
    }
    if(validation.checkpoint_interval_blocks!=='disabled'
        || validation.checkpoint_confirmation_depth_blocks!=='disabled') {
      add(blockers,'native_runtime_checkpoint_schedule_unexpected',
        'a legacy V1 runtime cannot select a candidate checkpoint schedule');
    }
  }
  return {manifestSubject:`0x${manifest.sha256}`,
    randomxReceiptImageId:validation.candidate_v2_first_height==='disabled'
      ? null:`0x${validation.randomx_receipt_image_id}`,
    privacyVerifierSubject:rawHash(validation.privacy_verifier_config_hash)
      ? `0x${validation.privacy_verifier_config_hash}`:undefined};
}

function requireNativeAttestationApprovalSnapshot(
  blockers,{observation,attestations,releaseConfig},
) {
  const expectedKeys=['approvals','chainId','finalizedBlockHash','finalizedBlockNumber',
    'finalizedBlockTimestamp','governance','governanceCodeHash','rpcConsensus','snapshotBlockHashAfter'];
  if(!observation || typeof observation!=='object' || Array.isArray(observation)
      || JSON.stringify(Object.keys(observation).sort())!==JSON.stringify(expectedKeys)) {
    add(blockers,'native_attestation_approval_snapshot_missing',
      'native attestations require an exact finalized EIP-1271 approval snapshot');
    return;
  }
  try { validateRpcConsensusEvidence(observation.rpcConsensus); }
  catch(error) { add(blockers,'native_attestation_approval_rpc_consensus_invalid',error.message); }
  if(observation.chainId!==releaseConfig?.ethereumChainId || observation.chainId!=='1') {
    add(blockers,'native_attestation_approval_chain_mismatch',
      'native attestation approvals were not checked on the release Ethereum chain');
  }
  if(!isCanonicalNonzeroUint64(observation.finalizedBlockNumber)) {
    add(blockers,'native_attestation_approval_block_number_invalid',
      'native attestation approval block number must be a nonzero canonical integer string');
  }
  if(!isCanonicalNonzeroUint64(observation.finalizedBlockTimestamp)) {
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
    try {
      if(isCanonicalNonzeroUint64(attestations[name]?.completedAt))
        digest=nativeReleaseAttestationDigest(attestations[name],releaseConfig);
    }
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
    if(isCanonicalNonzeroUint64(observation.finalizedBlockTimestamp)
        && isCanonicalNonzeroUint64(attestations[name]?.completedAt)
        && BigInt(attestations[name].completedAt)>BigInt(observation.finalizedBlockTimestamp)) {
      add(blockers,`native_attestation_${name}_completed_after_finalized_snapshot`,
        `${name} completion time is later than the finalized approval snapshot`);
    }
  }
}

function requireReleaseAuthorizationApprovalSnapshot(
  blockers,{observation,authorization,releaseConfig},
) {
  const expectedKeys=['approvals','chainId','finalizedBlockHash','finalizedBlockNumber',
    'finalizedBlockTimestamp','governance','governanceCodeHash','rpcConsensus','snapshotBlockHashAfter'];
  if(!observation||typeof observation!=='object'||Array.isArray(observation)
      || JSON.stringify(Object.keys(observation).sort())!==JSON.stringify(expectedKeys)) {
    add(blockers,'release_authorization_approval_snapshot_missing',
      'release authorization requires an exact finalized EIP-1271 approval snapshot');
    return;
  }
  try { validateRpcConsensusEvidence(observation.rpcConsensus); }
  catch(error) { add(blockers,'release_authorization_approval_rpc_consensus_invalid',error.message); }
  if(observation.chainId!==releaseConfig?.ethereumChainId||observation.chainId!=='1') {
    add(blockers,'release_authorization_approval_chain_mismatch',
      'release authorization was not checked on the release Ethereum chain');
  }
  if(!isCanonicalNonzeroUint64(observation.finalizedBlockNumber)
      || !isCanonicalNonzeroUint64(observation.finalizedBlockTimestamp)) {
    add(blockers,'release_authorization_approval_block_invalid',
      'release authorization requires a canonical finalized block number and timestamp');
  }
  if(!bytes32Pattern.test(observation.finalizedBlockHash??'')
      || observation.finalizedBlockHash.toLowerCase()===zeroHash
      || !bytes32Pattern.test(observation.snapshotBlockHashAfter??'')
      || observation.snapshotBlockHashAfter.toLowerCase()
        !==String(observation.finalizedBlockHash).toLowerCase()) {
    add(blockers,'release_authorization_approval_snapshot_changed',
      'the finalized block identity changed during release-authorization verification');
  }
  try {
    if(getAddress(observation.governance)!==getAddress(releaseConfig?.governance)) throw new Error();
  } catch {
    add(blockers,'release_authorization_approval_governance_mismatch',
      'release authorization was not verified by the release governance');
  }
  if(!bytes32Pattern.test(observation.governanceCodeHash??'')
      || !bytes32Pattern.test(releaseConfig?.governanceCodeHash??'')
      || observation.governanceCodeHash.toLowerCase()
        !==releaseConfig.governanceCodeHash.toLowerCase()) {
    add(blockers,'release_authorization_approval_governance_codehash_mismatch',
      'release-authorization governance code differs from the release');
  }
  const approvals=observation.approvals;
  const approval=approvals?.releaseAuthorization;
  if(!approvals||typeof approvals!=='object'||Array.isArray(approvals)
      || JSON.stringify(Object.keys(approvals))!==JSON.stringify(['releaseAuthorization'])
      || !approval||typeof approval!=='object'||Array.isArray(approval)
      || JSON.stringify(Object.keys(approval).sort())!==JSON.stringify(['digest','valid'])) {
    add(blockers,'release_authorization_approval_invalid',
      'release authorization approval must contain only its EIP-712 digest and EIP-1271 result');
    return;
  }
  let digest=null;
  try {
    if(isCanonicalNonzeroUint64(authorization?.acceptedAt))
      digest=releaseAuthorizationDigest(authorization,releaseConfig);
  }
  catch { /* field-specific validation emits the release authorization blocker */ }
  if(!bytes32Pattern.test(approval.digest??'')||!digest
      || approval.digest.toLowerCase()!==digest.toLowerCase()) {
    add(blockers,'release_authorization_digest_mismatch',
      'EIP-1271 approval does not bind the current release authorization');
  }
  if(approval.valid!==true) add(blockers,'release_authorization_eip1271_rejected',
    'release governance rejected the release authorization');
  if(isCanonicalNonzeroUint64(observation.finalizedBlockTimestamp)
      && isCanonicalNonzeroUint64(authorization?.acceptedAt)
      && BigInt(authorization.acceptedAt)>BigInt(observation.finalizedBlockTimestamp)) {
    add(blockers,'release_authorization_after_finalized_snapshot',
      'release authorization claims a time later than its finalized approval snapshot');
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
  if (repositoryState.risc0ProgramBinariesVerified !== true) {
    add(blockers, 'risc0_program_binaries_unverified',
      'every proof ProgramBinary must decode canonically and match its pinned ImageID');
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
  nativeAttestationApprovalObservation,releaseAuthorizationApprovalObservation,
  nativeRuntimeValidation,controlPlaneEvidenceArtifacts,
  riscZeroHealthSourceCatalog,finalizedBurnE2eReport,checkpointProofCapacityReport,
  securityValidationReport,requirementsSha256,sourceManifestSha256,
  operationsReviewReport,operatorRunbookSha256,
  reserveReproducibleBuildReport,verifierReproducibleBuildReport,
  mainnetForkRehearsalReport,mainnetForkRehearsalEvidenceFiles,
  checkpointBootstrapRatificationReport,ethereumCheckpointConsensus,nativePreactivationFacts,
  checkpointFinalizedEventReport,
  checkpointVerifierReproducibleBuildReport,
  checkpointRegistryReproducibleBuildReport,
  residualRiskReport,residualRiskDraftSha256,
  trustedSetupDecisionReport,
}) {
  if (!['closed-mainnet','real-funds'].includes(mode)) throw new Error('mode must be closed-mainnet or real-funds');
  const blockers = [];
  if (!requirements || typeof requirements !== 'object') add(blockers, 'requirements_missing', 'production requirements are missing');
  else {
    for (const key of closedMainnetRequirements) {
      if (requirements[key] !== true) add(blockers, `requirement_${key}`, `${key} must be true`);
    }
    if (requirements.native_burn_state_witness_authorizes_consensus_or_payout !== false) {
      add(blockers,'requirement_native_burn_state_witness_scope_invalid',
        'the intermediate burn-state witness must not independently authorize consensus or payout');
    }
    if (requirements.native_burn_block_prover_input_proves_finality !== false) {
      add(blockers,'requirement_native_burn_block_prover_input_scope_invalid',
        'the block-bound burn transport must not independently claim finality');
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
      if (acceptance.sourceTag!==evidence?.sourceTag) {
        add(blockers,'operator_residual_risk_tag_mismatch',
          'residual-risk acceptance sourceTag does not match the evidence release');
      }
      try {
        if(String(acceptance.releaseEvidenceCommitment).toLowerCase()
            !==releaseEvidenceCommitment(evidence).toLowerCase()) throw new Error();
      } catch {
        add(blockers,'operator_residual_risk_evidence_commitment_mismatch',
          'residual-risk acceptance does not bind the complete release evidence and artifact hashes');
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
      if (!isCanonicalNonzeroUint64(acceptance.acceptedAt)) {
        add(blockers,'operator_residual_risk_timestamp_invalid',
          'residual-risk acceptance timestamp must be a nonzero canonical integer string');
      }
      if(acceptance.productionApproved!==true||acceptance.deployAuthorized!==true
          || acceptance.realFundsAuthorized!==true
          || acceptance.productionApproved!==operatorIntent.production_approved
          || acceptance.deployAuthorized!==operatorIntent.deploy_authorized
          || acceptance.realFundsAuthorized!==operatorIntent.real_funds_authorized) {
        add(blockers,'operator_release_authorization_scope_mismatch',
          'governance authorization must exactly approve production, deployment and real funds');
      }
      try { releaseAuthorizationDigest(acceptance,releaseConfig); }
      catch(error) {
        add(blockers,'operator_release_authorization_invalid',
          `release authorization is invalid: ${error.message}`);
      }
      if(!validEip1271Signature(acceptance.signature)) {
        add(blockers,'operator_release_authorization_signature_invalid',
          'release authorization requires a nonempty canonical bounded EIP-1271 signature');
      }
      requireReleaseAuthorizationApprovalSnapshot(blockers,{observation:
        releaseAuthorizationApprovalObservation,authorization:acceptance,releaseConfig});
    }
  }

  try {
    const expectedDomDomain=deriveDomDomain({domNetworkMagic:releaseConfig?.checkpointDomNetworkMagic,
      domChainId:releaseConfig?.checkpointDomChainId,ethereumChainId:releaseConfig?.ethereumChainId,
      reserve:releaseConfig?.reserve,checkpointRegistry:releaseConfig?.checkpointRegistry});
    if(!bytes32Pattern.test(releaseConfig?.domDomain??'')
        || releaseConfig.domDomain.toLowerCase()!==expectedDomDomain) {
      add(blockers,'release_dom_domain_derivation_mismatch',
        'domDomain does not match the deterministic production chain and deployment identity');
    }
  } catch(error) {
    add(blockers,'release_dom_domain_derivation_invalid',
      `the deterministic production domain could not be derived: ${error.message}`);
  }

  let computed;
  let computedCheckpoint;
  if (!releaseConfig || typeof releaseConfig !== 'object') add(blockers, 'release_config_missing', 'proof-reserve release config is missing');
  else {
    if(!exactObject(releaseConfig,releaseConfigKeys)) {
      add(blockers,'release_config_schema_invalid',
        'proof-reserve release config must use the exact supported schema');
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
    const allOwners=[];
    for(const role of ['governance','guardian','checkpointGuardian']) {
      const owners=[];
      for(const value of releaseConfig[`${role}Owners`]??[]) try { owners.push(getAddress(value)); } catch {}
      if(owners.length!==3||new Set(owners).size!==3) add(blockers,`release_${role}_owners_invalid`,
        `${role}Owners must contain exactly three distinct owners`);
      else allOwners.push(...owners);
      if(role!=='checkpointGuardian'&&owners.length===3&&new Set(owners).size===3) {
        const declared=releaseConfig[`${role}OwnersCommitment`];
        if(!bytes32Pattern.test(declared??'')||declared.toLowerCase()!==safeOwnersCommitment(owners)) {
          add(blockers,`release_${role}_owners_commitment_mismatch`,`${role} owner commitment mismatch`);
        }
      }
    }
    if(allOwners.length!==9||new Set(allOwners).size!==9) add(blockers,'release_control_plane_owner_reuse',
      'control-plane owner addresses must be globally distinct');
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
      'verifierConfigHash','checkpointRegistry','checkpointRegistryRuntimeCodeHash',
      'checkpointRegistryConfigHash','domDomain','activationScheduleCommitment',
      'governance','governanceCodeHash','governanceImplementation','governanceImplementationCodeHash',
      'governanceOwnersCommitment','guardian','guardianCodeHash','guardianImplementation',
      'guardianImplementationCodeHash','guardianOwnersCommitment',
      'withdrawalDelaySeconds','governanceDelaySeconds',
      'maxOutstandingBaseUnits','outflowCapacityBaseUnitsPerDay'];
    if (commitmentFields.every(key => releaseConfig[key] !== null && releaseConfig[key] !== undefined)) {
      try {
        computed = proofReserveDeploymentConfigHash({
          ethereumChainId:releaseConfig.ethereumChainId,reserve:releaseConfig.reserve,token:releaseConfig.token,
          tokenCodeHash:releaseConfig.tokenCodeHash,verifier:releaseConfig.verifier,
          verifierCodeHash:releaseConfig.verifierCodeHash,verifierConfigHash:releaseConfig.verifierConfigHash,
          checkpointRegistry:releaseConfig.checkpointRegistry,
          checkpointRegistryRuntimeCodeHash:releaseConfig.checkpointRegistryRuntimeCodeHash,
          checkpointRegistryConfigHash:releaseConfig.checkpointRegistryConfigHash,
          domDomain:releaseConfig.domDomain,activationScheduleCommitment:releaseConfig.activationScheduleCommitment,
          governance:releaseConfig.governance,
          governanceCodeHash:releaseConfig.governanceCodeHash,
          governanceImplementation:releaseConfig.governanceImplementation,
          governanceImplementationCodeHash:releaseConfig.governanceImplementationCodeHash,
          governanceOwnersCommitment:releaseConfig.governanceOwnersCommitment,
          guardian:releaseConfig.guardian,
          guardianCodeHash:releaseConfig.guardianCodeHash,
          guardianImplementation:releaseConfig.guardianImplementation,
          guardianImplementationCodeHash:releaseConfig.guardianImplementationCodeHash,
          guardianOwnersCommitment:releaseConfig.guardianOwnersCommitment,
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
      'checkpointGuardianCodeHash','checkpointGuardianImplementation',
      'checkpointGuardianImplementationCodeHash','checkpointIntervalBlocks','checkpointConfirmationDepthBlocks',
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
          guardianImplementation:releaseConfig.checkpointGuardianImplementation,
          guardianImplementationCodeHash:releaseConfig.checkpointGuardianImplementationCodeHash,
          guardianOwnersCommitment:safeOwnersCommitment(releaseConfig.checkpointGuardianOwners),
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
      PRODUCTION_RESERVE_PREACTIVATION_CONFIG_HASH:computed?.reservePreActivationConfigHash,
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
  if(validDocument(evidence?.securityValidationReport,evidenceFiles)) {
    try {
      validateSecurityValidationReport(securityValidationReport,{releaseEvidence:evidence,
        requirementsSha256,sourceManifestSha256});
    } catch(error) {
      add(blockers,'security_validation_report_invalid',
        `security validation report is invalid: ${error.message}`);
    }
  }
  if(validDocument(evidence?.operationsReviewReport,evidenceFiles)) {
    try {
      validateOperationsReviewReport(operationsReviewReport,{releaseEvidence:evidence,releaseConfig,
        runbookSha256:operatorRunbookSha256});
    } catch(error) {
      add(blockers,'operations_review_report_invalid',
        `operations review report is invalid: ${error.message}`);
    }
  }
  if(validDocument(evidence?.reproducibleBuildReport,evidenceFiles)) {
    try {
      validateReserveReproducibleBuildReport(reserveReproducibleBuildReport,{
        releaseEvidence:evidence,releaseConfig});
    } catch(error) {
      add(blockers,'reserve_reproducible_build_report_invalid',
        `reserve reproducible-build report is invalid: ${error.message}`);
    }
  }
  if(validDocument(evidence?.verifierReproducibleBuildReport,evidenceFiles)) {
    try {
      validateVerifierReproducibleBuildReport(verifierReproducibleBuildReport,{
        releaseEvidence:evidence,releaseConfig,verifierConfig});
    } catch(error) {
      add(blockers,'verifier_reproducible_build_report_invalid',
        `verifier reproducible-build report is invalid: ${error.message}`);
    }
  }
  if(validDocument(evidence?.mainnetForkRehearsalReport,evidenceFiles)) {
    try {
      validateMainnetForkRehearsalReport({report:mainnetForkRehearsalReport,
        releaseEvidence:evidence,releaseConfig,evidenceFiles:mainnetForkRehearsalEvidenceFiles});
    } catch(error) {
      add(blockers,'mainnet_fork_rehearsal_report_invalid',
        `mainnet fork rehearsal report is invalid: ${error.message}`);
    }
  }
  if(validDocument(evidence?.checkpointBootstrapRatificationReport,evidenceFiles)) {
    try {
      validateCheckpointBootstrapRatificationReport({report:checkpointBootstrapRatificationReport,
        releaseEvidence:evidence,releaseConfig,checkpointConsensus:ethereumCheckpointConsensus,
        nativeFacts:nativePreactivationFacts});
    } catch(error) {
      add(blockers,'checkpoint_bootstrap_ratification_report_invalid',
        `checkpoint bootstrap ratification report is invalid: ${error.message}`);
    }
  }
  if(validDocument(evidence?.checkpointFinalizedEventReport,evidenceFiles)) {
    try {
      validateCheckpointFinalizedEventReport({report:checkpointFinalizedEventReport,
        releaseEvidence:evidence,releaseConfig});
    } catch(error) {
      add(blockers,'checkpoint_finalized_event_report_invalid',
        `checkpoint finalized event report is invalid: ${error.message}`);
    }
  }
  if(validDocument(evidence?.checkpointVerifierReproducibleBuildReport,evidenceFiles)) {
    try {
      validateCheckpointVerifierReproducibleBuildReport(checkpointVerifierReproducibleBuildReport,
        {releaseEvidence:evidence,releaseConfig,verifierConfig:checkpointVerifierConfig});
    } catch(error) {
      add(blockers,'checkpoint_verifier_reproducible_build_report_invalid',
        `checkpoint verifier reproducible-build report is invalid: ${error.message}`);
    }
  }
  if(validDocument(evidence?.checkpointRegistryReproducibleBuildReport,evidenceFiles)) {
    try {
      validateCheckpointRegistryReproducibleBuildReport(
        checkpointRegistryReproducibleBuildReport,{releaseEvidence:evidence,releaseConfig});
    } catch(error) {
      add(blockers,'checkpoint_registry_reproducible_build_report_invalid',
        `checkpoint registry reproducible-build report is invalid: ${error.message}`);
    }
  }
  if(validDocument(evidence?.residualRiskAcceptanceReport,evidenceFiles)) {
    try {
      validateResidualRiskReport(residualRiskReport,{releaseEvidence:evidence,releaseConfig,
        requirements,draftSha256:residualRiskDraftSha256});
    } catch(error) {
      add(blockers,'residual_risk_report_invalid',
        `residual-risk report is invalid: ${error.message}`);
    }
  }
  if(validDocument(evidence?.trustedSetup?.decisionReport,evidenceFiles)
      &&validDocument(evidence?.checkpointTrustedSetup?.decisionReport,evidenceFiles)) {
    try {
      if(JSON.stringify(evidence.trustedSetup.decisionReport)
          !==JSON.stringify(evidence.checkpointTrustedSetup.decisionReport)) {
        throw new Error('both verifier decision slots must reference the same immutable report');
      }
      validateTrustedSetupDecisionReport(trustedSetupDecisionReport,{releaseEvidence:evidence,
        releaseConfig,verifierConfig,checkpointVerifierConfig});
    } catch(error) {
      add(blockers,'trusted_setup_decision_report_invalid',
        `trusted-setup decision report is invalid: ${error.message}`);
    }
  }
  if(validDocument(evidence?.realFinalizedEndToEndReport,evidenceFiles)) {
    try {
      validateFinalizedBurnE2eReport(finalizedBurnE2eReport,{
        evidence,releaseConfig,verifierConfig,riscZeroReference,
      });
    } catch(error) {
      add(blockers,'finalized_burn_e2e_report_invalid',
        `finalized-burn E2E report is invalid: ${error.message}`);
    }
  }
  if(validDocument(evidence?.checkpointProofCapacityReport,evidenceFiles)) {
    try {
      validateCheckpointProofCapacityReport(checkpointProofCapacityReport,{
        evidence,releaseConfig,checkpointVerifierConfig,riscZeroReference,
      });
    } catch(error) {
      add(blockers,'checkpoint_proof_capacity_report_invalid',
        `checkpoint proof capacity report is invalid: ${error.message}`);
    }
  }
  if(validDocument(evidence?.riscZeroHealthSourceCatalog,evidenceFiles)) {
    try { validateRiscZeroHealthSourceCatalog(riscZeroHealthSourceCatalog); }
    catch(error) {
      add(blockers,'risc0_health_source_catalog_invalid',
        `RISC Zero health source catalog is invalid: ${error.message}`);
    }
  }
  requireControlPlaneSemanticEvidence(blockers,evidence,releaseConfig,controlPlaneEvidenceArtifacts);
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
  if(nativeRuntime?.randomxReceiptImageId && computedCheckpointVerifierConfig
      && nativeRuntime.randomxReceiptImageId
        !==computedCheckpointVerifierConfig.randomxReceiptImageId) {
    add(blockers,'native_runtime_checkpoint_randomx_image_id_mismatch',
      'the native candidate runtime and checkpoint verifier manifest select different per-block RandomX receipt ImageIDs');
  }
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
    for(const field of ['riscZeroVerifier','riscZeroVerifierCodeHash','riscZeroVerifierSelector',
      'verifyingKeySha256','trustedSetupTranscriptSha256']) {
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
