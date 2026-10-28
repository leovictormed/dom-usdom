function requirePattern(failures, source, pattern, code) {
  if (!pattern.test(source)) failures.push(code);
}

function section(source, start, end) {
  const first = source.indexOf(start);
  if (first === -1) return '';
  const last = source.indexOf(end, first + start.length);
  return last === -1 ? '' : source.slice(first, last);
}

/**
 * Audit the source boundaries that prevent one authenticated USDOM artifact
 * from being reused for another chain, deployment, protocol generation or
 * reserve. This is deliberately a source gate: behavioral hash vectors cover
 * the encoders, while this gate ensures the consuming consensus/contracts do
 * not silently drop one of those identities later.
 */
export function validateCrossDomainReplayBindings({
  reserveContract, checkpointContract, preactivationPolicy, checkpointStatement,
  nativeState, nativeChain, finalizedBurnProgram, depositFinality, proofReserveSdk, checkpointRegistrySdk,
}) {
  for (const [name, value] of Object.entries({
    reserveContract, checkpointContract, preactivationPolicy, checkpointStatement,
    nativeState, nativeChain, finalizedBurnProgram, depositFinality, proofReserveSdk, checkpointRegistrySdk,
  })) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new TypeError(`${name} source is required`);
    }
  }

  const failures = [];
  const burnIntentType='BurnIntent(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 validUntil,uint256 ethereumChainId,address reserve)';
  const finalizedBurnType='FinalizedBurn(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 finalityBeaconSlot,uint64 validUntil,uint256 ethereumChainId,address reserve,bytes32 activationScheduleCommitment)';
  const checkpointType='DOMCheckpointV4(bytes32 bridgeDomain,uint32 domNetworkMagic,uint16 nativeStateVersion,uint16 transitionBatchVersion,uint64 previousHeight,bytes32 previousBlock,bytes32 previousStateRoot,bytes32 previousContextHash,uint256 previousTotalDifficulty,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 domContextHash,uint256 domTotalDifficulty,uint128 totalIssued,uint128 totalBurned,bool issuanceClosed,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp,uint256 ethereumChainId,address registry,bytes32 activationScheduleCommitment,bytes32 checkpointConfigHash)';
  for(const [source,type,code] of [
    [nativeState,burnIntentType,'rust_burn_intent_type_drift'],
    [proofReserveSdk,burnIntentType,'sdk_burn_intent_type_drift'],
    [reserveContract,finalizedBurnType,'solidity_finalized_burn_type_drift'],
    [nativeChain,finalizedBurnType,'rust_finalized_burn_type_drift'],
    [proofReserveSdk,finalizedBurnType,'sdk_finalized_burn_type_drift'],
    [checkpointContract,checkpointType,'solidity_checkpoint_type_drift'],
    [checkpointStatement,checkpointType,'rust_checkpoint_type_drift'],
    [checkpointRegistrySdk,checkpointType,'sdk_checkpoint_type_drift'],
  ]) if(!source.includes(type)) failures.push(code);
  const depositId = section(reserveContract, 'function depositId', 'function burnStatementHash');
  const burnStatement = section(reserveContract, 'function burnStatementHash', 'function burnDebtHash');
  const burnEncoder = section(reserveContract, 'function _burnHash', 'function deposit(');
  const checkpointHash = section(
    checkpointContract, 'function checkpointStatementHash', 'function guardianControlHealthy',
  );
  const issuance = section(nativeState, 'pub fn ethereum_deposit_transition', 'pub fn private_transfer_transition');
  const applyIssuance = section(nativeState, 'fn apply_issuance', 'fn apply_ethereum_checkpoint');
  const finalizedBurn = section(
    finalizedBurnProgram, 'fn finalized_burn_statement', 'pub fn execute_with_checkpoint_assumption',
  );
  const checkpointV6Hash = section(
    checkpointStatement, 'impl CheckpointStatementV6', '/// Decode the exact public statement',
  );

  requirePattern(failures, depositId,
    /function depositId[\s\S]*?keccak256\(abi\.encode\(deploymentChainId, address\(this\), funder, salt\)\)/,
    'deposit_id_missing_chain_or_reserve');
  requirePattern(failures, `${burnStatement}\n${burnEncoder}`,
    /_burnHash\(burn, 0\)[\s\S]*?encoded\[5\] = burn\.domDomain[\s\S]*?format == 0[\s\S]*?encoded\[10\] = bytes32\(uint256\(burn\.validUntil\)\)[\s\S]*?encoded\[11\] = bytes32\(deploymentChainId\)[\s\S]*?encoded\[12\] = bytes32\(uint256\(uint160\(address\(this\)\)\)\)[\s\S]*?encoded\[13\] = activationScheduleCommitment/,
    'finalized_burn_statement_missing_domain');
  requirePattern(failures,nativeState,
    /encoded\.extend_from_slice\(&type_hash\);[\s\S]*?&self\.burn_id[\s\S]*?&self\.request_id[\s\S]*?&self\.recipient[\s\S]*?self\.amount\.to_be_bytes[\s\S]*?&dom_domain[\s\S]*?self\.valid_until\.to_be_bytes[\s\S]*?&self\.ethereum_chain_id[\s\S]*?&self\.reserve/,
    'rust_burn_intent_field_order_drift');
  requirePattern(failures,proofReserveSdk,
    /BURN_INTENT_TYPEHASH, normalized\.burnId, normalized\.requestId, normalized\.recipient, normalized\.amount,[\s\S]*?normalized\.domDomain, normalized\.validUntil, idValue, reserveAddress/,
    'sdk_burn_intent_field_order_drift');
  requirePattern(failures,nativeChain,
    /FINALIZED_BURN_STATEMENT_TYPE[\s\S]*?encoded\.extend_from_slice\(&type_hash\);[\s\S]*?self\.burn_id[\s\S]*?self\.request_id[\s\S]*?self\.recipient[\s\S]*?self\.amount\.to_be_bytes[\s\S]*?self\.dom_domain[\s\S]*?self\.height\.to_be_bytes[\s\S]*?self\.block_hash[\s\S]*?self\.state_root[\s\S]*?self\.finality_beacon_slot\.to_be_bytes[\s\S]*?self\.valid_until\.to_be_bytes[\s\S]*?self\.ethereum_chain_id[\s\S]*?self\.reserve[\s\S]*?self\.activation_schedule_commitment/,
    'rust_finalized_burn_field_order_drift');
  requirePattern(failures,proofReserveSdk,
    /BURN_STATEMENT_TYPEHASH, \.\.\.finalizedBurnFields\.map\(field => normalized\[field\.name\]\), idValue,[\s\S]*?reserveAddress,schedule/,
    'sdk_finalized_burn_field_order_drift');

  requirePattern(failures, preactivationPolicy,
    /USDOMDomain\(uint32 domNetworkMagic,bytes32 domChainId,uint256 ethereumChainId,address reserve,address checkpointRegistry\)/,
    'dom_domain_schema_incomplete');
  requirePattern(failures, checkpointHash,
    /CHECKPOINT_STATEMENT_TYPEHASH[\s\S]*?bridgeDomain[\s\S]*?domNetworkMagic[\s\S]*?NATIVE_STATE_VERSION[\s\S]*?TRANSITION_BATCH_VERSION[\s\S]*?checkpoint\.totalIssued[\s\S]*?checkpoint\.totalBurned[\s\S]*?checkpoint\.issuanceClosed[\s\S]*?deploymentChainId,[\s\S]*?address\(this\),[\s\S]*?activationScheduleCommitment,[\s\S]*?checkpointConfigHash/,
    'checkpoint_statement_missing_generation_or_deployment');
  requirePattern(failures, checkpointStatement,
    /V6_TYPE_STRING[\s\S]*?total_issued[\s\S]*?total_burned[\s\S]*?issuance_closed[\s\S]*?ethereum_chain_id[\s\S]*?registry[\s\S]*?activation_schedule_commitment[\s\S]*?checkpoint_config_hash/,
    'native_checkpoint_hash_missing_domain');
  requirePattern(failures,checkpointV6Hash,
    /encoded\[\.\.32\][\s\S]*?bridge_domain[\s\S]*?dom_network_magic[\s\S]*?CHECKPOINT_NATIVE_STATE_V6_VERSION[\s\S]*?CHECKPOINT_TRANSITION_BATCH_V5_VERSION[\s\S]*?previous_height[\s\S]*?previous_block[\s\S]*?previous_state_root[\s\S]*?previous_context_hash[\s\S]*?previous_total_difficulty[\s\S]*?v\.height[\s\S]*?v\.block[\s\S]*?v\.state_root[\s\S]*?v\.context_hash[\s\S]*?v\.total_difficulty[\s\S]*?self\.total_issued[\s\S]*?self\.total_burned[\s\S]*?self\.issuance_closed[\s\S]*?v\.confirmation_height[\s\S]*?v\.confirmation_block[\s\S]*?v\.confirmation_total_difficulty[\s\S]*?v\.confirmation_timestamp[\s\S]*?v\.ethereum_chain_id[\s\S]*?v\.registry[\s\S]*?v\.activation_schedule_commitment[\s\S]*?v\.checkpoint_config_hash/,
    'rust_checkpoint_field_order_drift');

  requirePattern(failures, depositFinality,
    /event_location\.genesis_validators_root == policy\.ethereum_genesis_validators_root[\s\S]*?event\.emitter\(\) == policy\.reserve[\s\S]*?code\.code_hash\(\) == policy\.runtime_code_hash/,
    'deposit_proof_missing_chain_reserve_or_runtime');
  requirePattern(failures, issuance,
    /deposit\.bridge_domain\(\)\.as_slice\(\) != bridge\.dom_domain[\s\S]*?deposit\.reserve\(\)\.as_slice\(\) != bridge\.reserve[\s\S]*?deposit\.locator\(\)\.genesis_validators_root\.as_slice\(\)[\s\S]*?bridge\.ethereum_genesis_validators_root[\s\S]*?deposit\.trust_policy_hash\(\)\.as_slice\(\) != bridge\.ethereum_deposit_policy_hash/,
    'native_issuance_missing_bridge_policy');
  requirePattern(failures, applyIssuance,
    /self\.consumed_deposits\.contains_key\(&value\.deposit_id\)/,
    'native_issuance_missing_replay_set');
  requirePattern(failures, nativeState,
    /PrivateBurnId\(bytes32 domDomain,bytes32 privacyPolicyHash,bytes32 verifierConfigHash,uint256 ethereumChainId,address reserve,address recipient,uint64 amount,uint64 validUntil,bytes32 nullifier0,bytes32 nullifier1\)/,
    'private_burn_id_schema_incomplete');
  requirePattern(failures, finalizedBurn,
    /burn\.ethereum_chain_id != state\.ethereum_chain_id[\s\S]*?burn\.reserve != state\.reserve/,
    'finalized_burn_missing_target_binding');
  requirePattern(failures, finalizedBurn,
    /consensus\.ethereum_chain_id != state\.ethereum_chain_id[\s\S]*?consensus\.registry != registry[\s\S]*?consensus\.activation_schedule_commitment != \*activation_schedule\.commitment\(\)\.as_bytes\(\)[\s\S]*?consensus\.checkpoint_config_hash\.as_slice\(\) != &record\[321\.\.353\]/,
    'finalized_burn_missing_checkpoint_target_binding');
  return failures;
}
