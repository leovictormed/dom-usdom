function need(failures,source,pattern,code) {
  if(!pattern.test(source)) failures.push(code);
}

export function validateCheckpointEconomicCoverage({library,chunks,portable}) {
  for(const [name,value] of Object.entries({library,chunks,portable})) {
    if(typeof value!=='string' || value.length===0) throw new TypeError(`${name} source is required`);
  }
  const failures=[];
  need(failures,library,
    /MAX_ECONOMIC_BLOCK_CHUNKS: usize =\s*\(dom_core::MAX_BLOCK_WEIGHT as usize\)\.div_ceil\(MAX_ECONOMIC_CHUNK_KEYS\) \+ 1;/,
    'chunk_count_not_derived_from_consensus_weight');
  need(failures,chunks,
    /total > dom_core::MAX_BLOCK_WEIGHT/,
    'economic_effect_count_not_consensus_bounded');
  need(failures,chunks,
    /while cursor < total \{[\s\S]*?EconomicChunkWitness::from_state[\s\S]*?cursor = transition\.next_cursor;[\s\S]*?roots = transition\.next_roots;/,
    'host_does_not_cover_every_effect');
  need(failures,chunks,
    /if proving_state != expected_final \{\s*return Err\(EconomicStateError::InvalidProof\);/,
    'chunk_execution_not_compared_to_full_consensus_state');
  need(failures,portable,
    /EconomicBlockTransition::from_bytes\(block_input\.economic_witness_bytes\(\)\)[\s\S]*?claim\.package_commitment[\s\S]*?claim\.block_hash[\s\S]*?claim\.block_height[\s\S]*?claim\.utxo_effects[\s\S]*?claim\.kernel_effects[\s\S]*?claim\.previous_roots != economic_roots/,
    'recursive_economic_claim_not_bound_to_exact_block');
  need(failures,portable,
    /verify_checkpoint_economic_block_receipts_in_guest\([\s\S]*?risc0_zkvm::guest::env::verify\(/,
    'economic_receipts_not_recursively_verified');
  need(failures,library,
    /checkpoint_randomx_statement_for_header\([\s\S]*?block_height: header\.height\.0,[\s\S]*?pow_preimage,[\s\S]*?randomx_hash: \*header\.pow\.randomx_hash\.as_bytes\(\),[\s\S]*?target: header/,
    'randomx_statement_fields_not_derived_from_header');
  need(failures,library,
    /let statement = header\s*\.randomx_statement\([\s\S]*?transition\.previous\.network_magic,[\s\S]*?transition\.previous\.chain_id,[\s\S]*?seed_hash/,
    'segment_randomx_statement_not_derived_from_parsed_header');
  return failures;
}
