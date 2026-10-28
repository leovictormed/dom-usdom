const capacityLayers=Object.freeze({
  production_checkpoint_randomx_complete_guest_proving_cost_measured:'randomx',
  production_checkpoint_economic_chunk_guest_proving_cost_measured:'economic-chunk',
  production_checkpoint_economic_block_guest_proving_cost_measured:'economic-block',
  production_checkpoint_segment_guest_proving_cost_measured:'segment',
  production_checkpoint_outer_guest_proving_cost_measured:'outer',
});
const operationalScenarios=Object.freeze({
  production_queue_withdrawal_worst_case_gas_measured:'queueWithdrawal-worst-case',
  production_prune_expired_256_worst_case_gas_measured:'pruneExpired-256',
  production_prune_discardable_256_worst_case_gas_measured:'pruneDiscardable-256',
  production_safe_admin_overhead_gas_measured:'safe-admin-swapOwner-3-owner-2-threshold',
});

const exact=Object.freeze({
  native_privacy_production_verifying_key_installed:{
    id:'native-privacy-vk-installation-v1',file:'sdk/native-privacy-ceremony.mjs',
    anchors:['validateNativePrivacyInstallationReceipt','nativeRuntimeManifestSha256','verifyingKeySha256'],
  },
  native_privacy_trusted_setup_ceremony_completed:{
    id:'native-privacy-multiparty-transcript-v1',file:'sdk/native-privacy-ceremony.mjs',
    anchors:['validateNativePrivacyCeremony','contributions','finalizationSignatures'],
  },
  native_private_mining_real_finalized_deposit_vector_implemented:{
    id:'native-finalized-deposit-vector-v1',file:'sdk/native-deposit-vector.mjs',
    anchors:['validateNativeFinalizedDepositVector','validateFinalizedDepositSource',
      'parseStrictJsonBytes(sourceBytes','source.transactionHash!==index.source_transaction_hash',
      'releaseConfig.reserve.toLowerCase()!==source.reserve.toLowerCase()',
      'validatePersistedIssuanceBlock','historyAuthenticated:true'],
  },
  real_finalized_reserve_deposit_native_block_vector_implemented:{
    id:'native-finalized-deposit-vector-v1',file:'sdk/native-deposit-vector.mjs',
    anchors:['validateNativeFinalizedDepositVector','validateFinalizedDepositSource',
      'parseStrictJsonBytes(sourceBytes','source.transactionHash!==index.source_transaction_hash',
      'releaseConfig.reserve.toLowerCase()!==source.reserve.toLowerCase()',
      'validatePersistedIssuanceBlock','historyAuthenticated:true'],
  },
  native_scheduled_public_runtime_configured:{
    id:'native-scheduled-release-configuration-v1',file:'sdk/production-release-core.mjs',
    anchors:['activationScheduleCommitment','checkpointInitialHeight','reserveConfigHash','pilotRestrictedDeployment'],
  },
  production_reserve_config_hash_configured:{
    id:'reserve-config-hash-materialization-v1',file:'sdk/production-release-core.mjs',
    anchors:['reserveConfigHash','compiledReserve.configHash','reserve.reserveConfigHash','pilotRestrictedDeployment'],
  },
  production_control_plane_recovery_drill_passed:{
    id:'safe-recovery-common-roster-finalized-liveness-v3',file:'scripts/check-safe-recovery-roster-v3-completion.mjs',
    anchors:['nextRecoveryOrdinal','finalizedStepCount:12','replacementProofCount:3',"liveness:'2-of-3-common-roster'"],
  },
  production_mainnet_predeployment_preflight_passed:{
    id:'mainnet-predeployment-finalized-consensus-v1',file:'scripts/check-mainnet-preflight.mjs',
    anchors:['assessMainnetPreflight','rpcConsensusEvidence',"phase==='postdeployment'?4:2"],
  },
  production_finalized_burn_proving_capacity_measured:{
    id:'finalized-burn-proving-capacity-v2',file:'sdk/finalized-burn-capacity-report.mjs',
    anchors:['provingWallMilliseconds','peakResidentKiB','receiptVerified!==true'],
  },
  production_finalized_burn_evm_verification_gas_measured:{
    id:'finalized-burn-isolated-evm-gas-v1',file:'sdk/finalized-burn-capacity-report.mjs',
    anchors:['finalizedBurnIsolatedEvmReceiptCommitment','adapterVerificationGas','adapterCallAccepted!==true'],
  },
  production_checkpoint_outer_evm_verification_gas_measured:{
    id:'checkpoint-isolated-evm-gas-v1',file:'sdk/checkpoint-proof-capacity-report.mjs',
    anchors:['checkpointIsolatedEvmReceiptCommitment','adapterVerificationGas','adapterCallAccepted!==true'],
  },
  production_verified_checkpoint_restart_witness_live_exercised:{
    id:'checkpoint-restart-live-witness-v1',file:'scripts/exercise-checkpoint-restart-witness.mjs',
    anchors:['restart witness','witnessSha256','checkpoint-restart-witness-live-exercise'],
  },
  production_checkpoint_registry_artifacts_pinned:{
    id:'checkpoint-registry-artifact-pins-v1',file:'sdk/checkpoint-registry-artifact-pins.mjs',
    anchors:['releaseConfigSha256','artifactSha256','runtimeCodeHash'],
  },
  production_checkpoint_registry_bootstrap_ratified:{
    id:'checkpoint-bootstrap-ratification-v1',file:'sdk/checkpoint-bootstrap-ratification-report.mjs',
    anchors:['validateCheckpointBootstrapRatificationReport','activationScheduleCommitment','ethereumSourceSetCommitment'],
  },
  production_checkpoint_registry_positive_finalized_event_vector:{
    id:'checkpoint-finalized-event-v1',file:'sdk/checkpoint-finalized-event-report.mjs',
    anchors:['validateCheckpointFinalizedEventReport','transactionHash','finalized'],
  },
  production_checkpoint_randomx_receipt_image_id_pinned:{
    id:'checkpoint-randomx-image-ratification-v1',file:'sdk/checkpoint-randomx-image-ratification.mjs',
    anchors:['randomx_receipt_image_id','randomxRelationsExecuted','receiptsVerified'],
  },
  production_checkpoint_randomx_complete_guest_positive_receipt_executed:{
    id:'checkpoint-randomx-complete-positive-receipt-v1',file:'scripts/plan-authenticated-checkpoint-segment-set.sh',
    anchors:['randomx-receipt-set','checkpoint-segment-proof-job-index.json','dom-usdom-plan-checkpoint-segment-set'],
  },
  production_checkpoint_economic_chunk_guest_cryptographic_receipt_generated:{
    id:'checkpoint-economic-chunk-positive-receipt-v1',file:'scripts/plan-authenticated-checkpoint-segment-set.sh',
    anchors:['economic-receipt-set','checkpoint-segment-proof-job-index.json','dom-usdom-plan-checkpoint-segment-set'],
  },
  production_checkpoint_economic_block_guest_positive_receipt_executed:{
    id:'checkpoint-economic-block-positive-receipt-v1',file:'scripts/plan-authenticated-checkpoint-segment-set.sh',
    anchors:['economic-receipt-set','checkpoint-segment-proof-job-index.json','dom-usdom-plan-checkpoint-segment-set'],
  },
  production_checkpoint_segment_guest_positive_receipt_executed:{
    id:'checkpoint-segment-positive-receipt-v1',file:'scripts/plan-authenticated-checkpoint-outer.sh',
    anchors:['checkpoint-segment-receipt-set','checkpoint-outer-proof-job','dom-usdom-plan-checkpoint-outer'],
  },
  production_checkpoint_outer_guest_positive_receipt_executed:{
    id:'checkpoint-outer-positive-receipt-v1',file:'scripts/package-authenticated-checkpoint-outer-evm-proof.sh',
    anchors:['checkpoint-outer-receipt-set-index.json','checkpoint-outer-groth16-receipt.bin','checkpoint-outer-evm-seal.bin'],
  },
  production_finalized_burn_recursive_checkpoint_artifacts_pinned:{
    id:'finalized-burn-recursive-artifact-pins-v1',file:'sdk/finalized-burn-recursive-completion.mjs',
    anchors:['checkpointOuterReceiptSha256','adapterRuntimeCodeHash','adapterInitcodeHash'],
  },
  production_finalized_burn_recursive_checkpoint_receipt_verified:{
    id:'finalized-burn-recursive-receipt-verification-v1',file:'sdk/finalized-burn-recursive-completion.mjs',
    anchors:['checkpointOuterReceiptVerified','finalizedBurnReceiptVerified','finalizedBurnReceiptIndexSha256'],
  },
  production_finalized_burn_risc0_evm_receipt_verifier_implemented:{
    id:'finalized-burn-evm-proof-package-v1',file:'sdk/finalized-burn-recursive-completion.mjs',
    anchors:['evmReceiptVerified','adapterConfigHash','adapterRuntimeCodeHash'],
  },
});

export function openClaimSemanticContract(claim) {
  if(claim.startsWith('production_onekey_ios_safe_custody_')) return Object.freeze({
    id:`${claim.replaceAll('_','-')}-v1`,file:'sdk/onekey-ios-safe-usdt-custody.mjs',
    anchors:Object.freeze(['validateSafeUsdtCustodyEvidence','dual RPC observations diverge','post-deposit accounting invariant rejected']),
  });
  if(claim.startsWith('production_onekey_ios_relayer_')) return Object.freeze({
    id:`${claim.replaceAll('_','-')}-v1`,file:'sdk/onekey-ios-safe-relayer.mjs',
    anchors:Object.freeze(['validateOneKeyIosSafeRelayer','relayerRoleSeparationVerified','relayerNonceAndNoBlindRetryVerified']),
  });
  if(claim.startsWith('production_onekey_')) return Object.freeze({
    id:`${claim.replaceAll('_','-')}-v1`,file:'scripts/check-safe-owner-hardware-custody-proofs.mjs',
    anchors:Object.freeze(['custody bundle must contain twelve proofs','SafeOwnerCustodyProof','verifyTypedData']),
  });
  if(capacityLayers[claim]) return Object.freeze({
    id:`checkpoint-${capacityLayers[claim]}-proving-cost-v1`,
    file:'sdk/checkpoint-proof-capacity-report.mjs',
    anchors:[`name:'${capacityLayers[claim]}'`,'provingWallMilliseconds','receiptVerified'],
  });
  if(operationalScenarios[claim]) return Object.freeze({
    id:`operational-gas-${operationalScenarios[claim]}-v1`,
    file:'sdk/production-operational-gas-evidence.mjs',
    anchors:[operationalScenarios[claim],'maximumGasUsed','gasUsed'],
  });
  const value=exact[claim];
  if(!value) throw new Error(`open claim has no semantic evidence contract: ${claim}`);
  return Object.freeze({...value,anchors:Object.freeze([...value.anchors])});
}

export function assertSemanticContractSource(contract,source) {
  if(!contract||typeof contract.id!=='string'||typeof contract.file!=='string'
      ||!Array.isArray(contract.anchors)||contract.anchors.length<3) {
    throw new Error('semantic evidence contract is malformed');
  }
  for(const anchor of contract.anchors) {
    if(typeof anchor!=='string'||anchor.length===0||!source.includes(anchor)) {
      throw new Error(`semantic evidence contract ${contract.id} lacks implementation anchor: ${anchor}`);
    }
  }
}
