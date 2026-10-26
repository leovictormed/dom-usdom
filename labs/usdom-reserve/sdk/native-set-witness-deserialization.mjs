function need(failures,source,pattern,code) {
  if(!pattern.test(source)) failures.push(code);
}

export function validateNativeSetWitnessDeserialization(source) {
  if(typeof source!=='string'||source.length===0) throw new TypeError('source is required');
  const failures=[];
  need(failures,source,
    /struct SetWitnessReader<'a>[\s\S]*?cursor\s*\.checked_add\(length\)[\s\S]*?bytes\s*\.get\(self\.cursor\.\.end\)[\s\S]*?self\.cursor = end/,
    'set_witness_cursor_not_bounds_checked');
  need(failures,source,
    /NativeSetTransitionWitness[\s\S]*?from_bytes\(bytes: &\[u8\]\)[\s\S]*?SetWitnessReader::new\(bytes\)[\s\S]*?reader\.u16\(\)[\s\S]*?reader\.take\(length\)[\s\S]*?proofs\.push\(proof\);[\s\S]*?if !reader\.is_empty\(\) \{[\s\S]*?let witness = Self \{ proofs, existing \};/,
    'set_witness_parser_bypasses_bounded_cursor');
  need(failures,source,
    /length == 0 \|\| length > MAX_SPARSE_PROOF_BYTES/,
    'set_witness_nested_proof_length_unbounded');
  need(failures,source,
    /for end in 0\.\.bytes\.len\(\)[\s\S]*?accepted UDNSET01 truncation[\s\S]*?oversized_first_proof\[10\.\.12\]/,
    'set_witness_adversarial_corpus_missing');
  return failures;
}
