function requirePattern(failures,source,pattern,code) {
  if(!pattern.test(source)) failures.push(code);
}

/**
 * Verify the source-level identifier construction boundary used by private
 * burns. The release source manifest authenticates these exact inputs; this
 * checker prevents the requirements ledger from asserting a broader property
 * than the implementation provides.
 */
export function validateNativePrivateBurnIdentifiers({walletBurnBuilder,privacy,state}) {
  for(const [name,value] of Object.entries({walletBurnBuilder,privacy,state})) {
    if(typeof value!=='string' || value.length===0) throw new TypeError(`${name} source is required`);
  }
  const failures=[];
  requirePattern(failures,walletBurnBuilder,
    /fn fresh_request_identifier<R, I>[\s\S]*?R: RngCore \+ CryptoRng/,
    'request_identifier_not_csprng_generic');
  requirePattern(failures,walletBurnBuilder,
    /const REQUEST_IDENTIFIER_ATTEMPTS: usize = 128;/,
    'request_identifier_retry_budget_missing');
  requirePattern(failures,walletBurnBuilder,
    /value != \[0; 32\] && value != burn_id && !existing\.contains\(&value\)/,
    'request_identifier_collision_checks_missing');
  requirePattern(failures,walletBurnBuilder,
    /self\.pending_burns[\s\S]*?pending\.record\.request_id/,
    'pending_request_identifiers_not_checked');
  requirePattern(failures,walletBurnBuilder,
    /let burn_id = derive_private_burn_id\(bridge, &nullifiers, recipient, amount, valid_until\)\?/,
    'burn_identifier_not_derived_from_exact_obligation');
  requirePattern(failures,walletBurnBuilder,
    /statement_nullifiers\[slot\] = nullifier;/,
    'nullifiers_not_bound_into_spend_statement');
  requirePattern(failures,walletBurnBuilder,
    /encode_private_burn_payload\([\s\S]*?&nullifiers,[\s\S]*?record,[\s\S]*?&proof/,
    'identifiers_not_bound_into_proof_payload');
  requirePattern(failures,privacy,
    /pub fn nullifier\(&self, owner_secret: Scalar\)[\s\S]*?poseidon_hash\([\s\S]*?NULLIFIER_DOMAIN,[\s\S]*?self\.chain, owner_secret, self\.commitment\(\)\?/,
    'nullifier_not_owner_note_and_chain_bound');
  requirePattern(failures,state,
    /if derive_private_burn_id\([\s\S]*?&value\.nullifiers,[\s\S]*?\)\? != value\.record\.burn_id/,
    'consensus_does_not_rederive_burn_identifier');
  requirePattern(failures,state,
    /if self\.burn_request_ids\.contains\(&value\.record\.request_id\)/,
    'consensus_does_not_reject_request_replay');
  return failures;
}
