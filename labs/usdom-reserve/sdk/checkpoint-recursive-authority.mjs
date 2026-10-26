function need(failures,source,pattern,code) {
  if(!pattern.test(source)) failures.push(code);
}

export function validateCheckpointRecursiveAuthority({aggregateGuest,segmentGuest,outerGuest,outerProgram}) {
  for(const [name,value] of Object.entries({aggregateGuest,segmentGuest,outerGuest,outerProgram})) {
    if(typeof value!=='string'||value.length===0) throw new TypeError(`${name} source is required`);
  }
  const failures=[];
  need(failures,aggregateGuest,
    /verify_checkpoint_segment_randomx_bindings_in_guest\(&bindings\)[\s\S]*?commit_slice\(&aggregate\.commitment\(\)/,
    'randomx_aggregate_not_limited_to_component_commitment');
  need(failures,segmentGuest,
    /execute_checkpoint_segment_portable[\s\S]*?verify_checkpoint_segment_randomx_bindings_in_guest\(executed\.randomx_bindings\(\)\)[\s\S]*?verify_checkpoint_economic_block_receipts_in_guest\([\s\S]*?executed\.economic_block_bindings\(\)[\s\S]*?commit_slice\(&executed\.transition_commitment\(\)\)/,
    'segment_guest_not_limited_to_complete_transition');
  need(failures,outerGuest,
    /const SEGMENT_IMAGE_ID: \[u8; 32\][\s\S]*?validate_checkpoint_outer_chain\(&statement, &chain, &policy, &opening, SEGMENT_IMAGE_ID\)[\s\S]*?verify_checkpoint_segment_receipts_in_guest\(executed\.segment_receipts\(\)\)[\s\S]*?commit_slice\(&executed\.statement_hash\(\)\)/,
    'outer_guest_not_authoritative_for_statement');
  need(failures,outerProgram,
    /transition\.previous != current[\s\S]*?current\.height != public\.confirmation_height/,
    'outer_chain_does_not_bind_ordered_confirmation_span');
  need(failures,outerProgram,
    /target\.block_hash != public\.block[\s\S]*?target\.native_state_root != public\.state_root/,
    'outer_chain_does_not_bind_target_state');
  need(failures,outerProgram,
    /current\.block_hash != public\.confirmation_block[\s\S]*?statement\s*\.statement_hash\(\)/,
    'outer_chain_does_not_bind_confirmation_and_statement');
  need(failures,outerProgram,
    /verify_checkpoint_segment_receipts_in_guest[\s\S]*?for assumption in assumptions[\s\S]*?guest::env::verify/,
    'outer_guest_does_not_verify_pinned_segment_receipts');
  return failures;
}
