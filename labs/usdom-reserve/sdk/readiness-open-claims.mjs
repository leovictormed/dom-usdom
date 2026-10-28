import {isForbiddenImpossibleAssuranceRequirement,readinessRequirementKeys}
  from './mainnet-readiness.mjs';

const configurationClaims=new Set([
  'production_checkpoint_registry_artifacts_pinned',
  'production_checkpoint_registry_bootstrap_ratified',
  'production_checkpoint_randomx_receipt_image_id_pinned',
  'native_privacy_production_verifying_key_installed',
  'native_scheduled_public_runtime_configured',
  'production_reserve_config_hash_configured',
]);

/**
 * Classify every currently false blocking claim without treating a missing
 * operational artifact as missing implementation. A newly false requirement
 * is deliberately returned as `unclassified` and must be reviewed.
 */
export function classifyOpenReadinessClaims(requirements) {
  const keys=new Set(readinessRequirementKeys('real-funds'));
  const operational=new Set([
    'production_verified_checkpoint_restart_witness_live_exercised',
    'production_finalized_burn_recursive_checkpoint_artifacts_pinned',
    'production_finalized_burn_recursive_checkpoint_receipt_verified',
    'production_finalized_burn_risc0_evm_receipt_verifier_implemented',
    'production_finalized_burn_proving_capacity_measured',
    'production_finalized_burn_evm_verification_gas_measured',
    'production_queue_withdrawal_worst_case_gas_measured',
    'production_prune_expired_256_worst_case_gas_measured',
    'production_prune_discardable_256_worst_case_gas_measured',
    'production_safe_admin_overhead_gas_measured',
    'production_checkpoint_registry_positive_finalized_event_vector',
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
    'production_checkpoint_outer_evm_verification_gas_measured',
    'real_finalized_reserve_deposit_native_block_vector_implemented',
    'native_privacy_trusted_setup_ceremony_completed',
    'native_private_mining_real_finalized_deposit_vector_implemented',
    'production_control_plane_recovery_drill_passed',
    'production_mainnet_predeployment_preflight_passed',
    'production_onekey_classic_1s_model_pinned',
    'production_onekey_ethereum_derivation_path_explicit',
    'production_onekey_address_verified_on_device',
    'production_onekey_sdk_firmware_transport_versions_pinned',
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
  ]);
  return Object.freeze([...keys].filter(key=>requirements?.[key]!==true).sort().map(key=>Object.freeze({
    key,category:configurationClaims.has(key)?'configuration':operational.has(key)?'operational-evidence':'unclassified',
  })));
}

export function assertClassifiedOpenReadinessClaims(requirements) {
  const claims=classifyOpenReadinessClaims(requirements);
  const unknown=claims.filter(({category})=>category==='unclassified');
  if(unknown.length!==0) {
    throw new Error(`unclassified false readiness claims: ${unknown.map(({key})=>key).join(',')}`);
  }
  const forbidden=readinessRequirementKeys('real-funds')
    .filter(isForbiddenImpossibleAssuranceRequirement);
  if(forbidden.length!==0) {
    throw new Error(`external assurance claim is release-blocking: ${forbidden.join(',')}`);
  }
  return claims;
}
