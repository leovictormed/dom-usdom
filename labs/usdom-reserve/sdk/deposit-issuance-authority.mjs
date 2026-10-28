function requirePattern(failures,source,pattern,code) {
  if(!pattern.test(source)) failures.push(code);
}

/** Static composition gate for the one Ethereum deposit -> one native issuance relation. */
export function validateDepositIssuanceAuthority({reserve,finality,state,chain}) {
  for(const [name,source] of Object.entries({reserve,finality,state,chain})) {
    if(typeof source!=='string'||source.length===0) throw new TypeError(`${name} source is required`);
  }
  const failures=[];
  requirePattern(failures,reserve,
    /uint256 public immutable deploymentChainId[\s\S]*?deploymentChainId = block\.chainid[\s\S]*?function depositId[\s\S]*?abi\.encode\(deploymentChainId, address\(this\), funder, salt\)/,
    'deposit_id_not_deployment_bound');
  requirePattern(failures,reserve,
    /deposits\[id\] = Deposit\(msg\.sender, amount, receivingCommitment\)[\s\S]*?totalDeposited \+= amount[\s\S]*?_tokenBalanceOf\(address\(this\)\) != reserveBefore \+ amount[\s\S]*?emit Deposited\(id, msg\.sender, amount, receivingCommitment\)/,
    'deposit_event_not_postcondition_bound');
  requirePattern(failures,finality,
    /verify_receipt_at[\s\S]*?verify_account_at[\s\S]*?finish_verified_reserve_deposit/,
    'deposit_missing_receipt_account_composition');
  requirePattern(failures,finality,
    /event_location\.genesis_validators_root == policy\.ethereum_genesis_validators_root[\s\S]*?event\.emitter\(\) == policy\.reserve[\s\S]*?code\.code_hash\(\) == policy\.runtime_code_hash[\s\S]*?code_location\.block_hash == event_location\.block_hash/,
    'deposit_missing_chain_reserve_runtime_identity');
  requirePattern(failures,finality,
    /topics\[0\] == keccak256\(DEPOSIT_EVENT\)[\s\S]*?deposit_id = topics\[1\][\s\S]*?funder = Address::from_slice[\s\S]*?amount = read_u64_be[\s\S]*?receiving_commitment = B256::from_slice/,
    'deposit_event_fields_not_canonical');
  requirePattern(failures,finality,
    /restore_transcript_bounded[\s\S]*?verify_reserve_deposit[\s\S]*?deposit\.trust_policy_hash = deposit_trust_policy_hash\(policy\)/,
    'deposit_not_finality_policy_bound');
  requirePattern(failures,state,
    /deposit\.bridge_domain\(\)\.as_slice\(\) != bridge\.dom_domain[\s\S]*?deposit\.reserve\(\)\.as_slice\(\) != bridge\.reserve[\s\S]*?deposit\.trust_policy_hash\(\)\.as_slice\(\) != bridge\.ethereum_deposit_policy_hash/,
    'issuance_missing_bridge_config_binding');
  requirePattern(failures,state,
    /EthereumDepositOccurrence \{[\s\S]*?genesis_validators_root:[\s\S]*?block_hash:[\s\S]*?block_number:[\s\S]*?transaction_index:[\s\S]*?receipt_log_index:[\s\S]*?deposit_id:[\s\S]*?funder:[\s\S]*?amount:[\s\S]*?receiving_commitment: deposit\.receiving_commitment\(\)\.into\(\)/,
    'issuance_note_missing_deposit_fields');
  requirePattern(failures,state,
    /fn apply_issuance[\s\S]*?consumed_deposits\.contains_key\(&value\.deposit_id\)[\s\S]*?sparse_deposit_set[\s\S]*?\.insert\(value\.deposit_id, sparse_issuance_leaf\(issuance\)\)[\s\S]*?consumed_deposits\.insert\(value\.deposit_id, issuance\)[\s\S]*?total_issued[\s\S]*?checked_add/,
    'issuance_missing_atomic_replay_accounting');
  requirePattern(failures,state,
    /deposit_root: issuance_set_root\(&self\.consumed_deposits\)[\s\S]*?deposit_count: self\.consumed_deposits\.len\(\) as u64/,
    'state_root_missing_consumed_deposit_set');
  requirePattern(failures,state,
    /suffix\.strip_prefix\(b"deposit\/"\)[\s\S]*?consumed_deposits[\s\S]*?state\.rebuild_sparse_set_caches\(\)[\s\S]*?computed_issued[\s\S]*?computed_issued != total_issued/,
    'restart_missing_deposit_reconstruction');
  requirePattern(failures,state,
    /inserted_deposit:[\s\S]*?after[\s\S]*?consumed_deposits[\s\S]*?if let Some\(deposit\) = undo\.inserted_deposit[\s\S]*?candidate[\s\S]*?\.consumed_deposits[\s\S]*?\.remove\(&deposit\)/,
    'undo_missing_consumed_deposit_removal');
  requirePattern(failures,chain,
    /apply_v2_transition_batch_with_receipt[\s\S]*?previous_state[\s\S]*?next_state[\s\S]*?receipt/,
    'block_persistence_missing_state_transition_binding');
  return failures;
}
