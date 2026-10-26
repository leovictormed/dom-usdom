/**
 * Concrete implementation facts that must remain true before a broad
 * production implementation claim can be asserted in the release ledger.
 *
 * Operational evidence (live receipts, ceremonies, configuration and
 * authorization) deliberately remains outside these groups. Those facts have
 * independent fail-closed release requirements.
 */
export const productionImplementationClaims=Object.freeze({
  native_consensus_implemented:Object.freeze([
    'native_state_core_implemented',
    'native_state_atomic_persistence_implemented',
    'native_set_witness_bounded_cursor_deserialization',
    'native_transition_batch_commitment_implemented',
    'native_transition_batch_lmdb_rollback_implemented',
    'native_checkpoint_transition_implemented',
    'native_burn_state_witness_implemented',
    'issuerless_deterministic_native_issuance_implemented',
    'native_transfer_proof_verifier_implemented',
    'native_burn_privacy_proof_verifier_implemented',
    'block_header_state_commitment_implemented',
    'production_block_header_state_commitment_implemented',
    'native_scheduled_direct_extension_chainstate_ingress_implemented',
    'native_scheduled_public_side_branch_retention_implemented',
    'native_scheduled_public_reorg_promotion_implemented',
    'native_scheduled_public_unified_package_ingress_implemented',
    'native_scheduled_public_ibd_ingress_implemented',
    'native_scheduled_node_constructor_implemented',
    'native_scheduled_public_mining_template_implemented',
    'verified_ethereum_checkpoint_native_burn_binding_enforces_dom_fork_choice',
  ]),
  consensus_proof_implemented:Object.freeze([
    'production_checkpoint_registry_contract_implemented',
    'production_checkpoint_registry_verifier_implemented',
    'production_checkpoint_registry_verifier_proves_consensus_extension',
    'production_checkpoint_consensus_extension_private_input_implemented',
    'production_checkpoint_consensus_extension_guest_compiled',
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
    'production_checkpoint_guest_randomx_relation_implemented',
    'production_checkpoint_randomx_proof_receipt_implemented',
    'production_checkpoint_portable_bulletproof_verifier_implemented',
    'production_checkpoint_segment_native_state_opening_implemented',
    'production_checkpoint_segment_portable_execution_implemented',
    'production_checkpoint_outer_recursive_chain_implemented',
    'production_checkpoint_outer_statement_binding_implemented',
    'production_checkpoint_proof_launchers_clear_remote_prover_endpoints',
    'production_checkpoint_proof_launchers_single_worker',
    'production_checkpoint_prover_libraries_reject_remote_endpoints',
    'production_prover_libraries_reject_unpinned_risc0_runtime_controls',
    'production_proof_artifacts_owner_only',
    'production_checkpoint_fixed_binaries_reject_arguments',
    'production_checkpoint_capacity_report_semantically_validated',
    'production_checkpoint_capacity_report_binds_all_six_recursive_layers',
    'production_checkpoint_capacity_report_recomputes_release_statement',
    'production_checkpoint_capacity_report_binds_ordered_artifact_sets',
    'production_checkpoint_capacity_artifact_set_commitment_implemented',
    'production_checkpoint_capacity_report_materializer_implemented',
    'production_checkpoint_capacity_report_measures_groth16_compression',
    'production_checkpoint_capacity_artifact_collector_implemented',
    'production_checkpoint_capacity_collector_binds_groth16_and_evm_seal',
    'production_checkpoint_capacity_e2e_executor_implemented',
    'production_checkpoint_capacity_executor_clean_workspace_enforced',
    'production_checkpoint_capacity_executor_local_evm_verification_implemented',
  ]),
  production_finalized_burn_verifier_implemented:Object.freeze([
    'native_finalized_burn_statement_derivation_implemented',
    'native_finalized_burn_statement_cross_stack_known_answer_tested',
    'finalized_burn_checkpoint_state_inclusion_composition_implemented',
    'production_finalized_burn_proof_backend_selected',
    'production_finalized_burn_guest_compiled',
    'production_finalized_burn_guest_reproducibly_compiled',
    'production_finalized_burn_guest_positive_raw_witness_executed',
    'production_finalized_burn_raw_checkpoint_positive_vector',
    'production_finalized_burn_prover_library_rejects_remote_endpoints',
    'production_prover_libraries_reject_unpinned_risc0_runtime_controls',
    'production_proof_artifacts_owner_only',
    'production_finalized_burn_fixed_binaries_reject_arguments',
    'production_finalized_burn_risc0_evm_adapter_implemented',
    'production_finalized_burn_authenticated_proof_job_planner_implemented',
    'production_finalized_burn_groth16_evm_packager_implemented',
    'production_finalized_burn_authenticated_submission_package_implemented',
    'production_finalized_burn_authenticated_submission_local_evm_verification_implemented',
    'production_finalized_burn_e2e_report_v4_enforced',
    'production_finalized_burn_e2e_burn_tuple_recomputed',
    'production_finalized_burn_artifact_collector_implemented',
    'production_finalized_burn_release_e2e_executor_implemented',
    'production_finalized_burn_release_evidence_materializer_implemented',
  ]),
  native_private_wallet_key_management_implemented:Object.freeze([
    'native_private_wallet_passphrase_type_implemented',
    'native_private_wallet_recovery_seed_implemented',
    'native_private_wallet_recovery_backup_encrypted',
    'native_private_wallet_durable_storage_implemented',
    'native_private_wallet_two_phase_seal_protocol_implemented',
    'native_private_wallet_tpm2_monotonic_authority_implemented',
    'native_private_wallet_tpm2_operational_keystore_implemented',
    'native_private_wallet_recovery_and_operational_passwords_separated',
  ]),
  native_private_wallet_production_monotonic_seal_authority_integrated:Object.freeze([
    'native_private_wallet_external_monotonic_seal_required',
    'native_private_wallet_two_phase_seal_protocol_implemented',
    'native_private_wallet_tpm2_monotonic_authority_implemented',
    'production_closed_mainnet_tpm2_authority_bootstrap_command_implemented',
    'production_closed_mainnet_private_burn_submission_command_implemented',
  ]),
  native_private_wallet_hardware_or_os_keystore_integrated:Object.freeze([
    'native_private_wallet_tpm2_operational_keystore_implemented',
    'native_private_wallet_recovery_and_operational_passwords_separated',
    'production_closed_mainnet_tpm2_keystore_provision_command_implemented',
  ]),
  native_private_wallet_recovery_ceremony_implemented:Object.freeze([
    'native_private_wallet_recovery_seed_implemented',
    'native_private_wallet_recovery_cli_implemented',
    'native_private_wallet_verified_checkpoint_disaster_recovery_implemented',
    'production_closed_mainnet_wallet_recovery_drill_command_implemented',
  ]),
});

export function productionImplementationClaimFailures(requirements,{requireClaims=false}={}) {
  if(requirements===null || typeof requirements!=='object' || Array.isArray(requirements)) {
    throw new TypeError('production requirements must be an object');
  }
  const failures=[];
  for(const [claim,dependencies] of Object.entries(productionImplementationClaims)) {
    if(requirements[claim]!==true) {
      if(requireClaims) failures.push({claim,reason:'claim_not_true',dependencies:[]});
      continue;
    }
    const missing=dependencies.filter(dependency=>requirements[dependency]!==true);
    if(missing.length!==0) failures.push({claim,reason:'dependency_not_true',dependencies:missing});
  }
  return failures;
}
