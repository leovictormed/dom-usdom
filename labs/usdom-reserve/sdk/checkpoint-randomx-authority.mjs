function need(failures,source,pattern,code) {
  if(!pattern.test(source)) failures.push(code);
}

/** Validate the two separate RandomX trust boundaries.
 * Native RandomX is mandatory fail-fast differential validation. Production
 * consensus authority comes only from a receipt for the pinned zkVM image and
 * exact statement commitment.
 */
export function validateCheckpointRandomxAuthority({singleExporter,setExporter,proofHost,guest}) {
  for(const [name,value] of Object.entries({singleExporter,setExporter,proofHost,guest})) {
    if(typeof value!=='string'||value.length===0) throw new TypeError(`${name} source is required`);
  }
  const failures=[];
  need(failures,singleExporter,
    /execute_checkpoint_randomx_reference\(&statement\)[\s\S]*?"randomxRelationExecuted\\": true/,
    'single_statement_not_native_prevalidated');
  need(failures,setExporter,
    /for \(block_index, binding\)[\s\S]*?execute_checkpoint_randomx_reference\(&statement\)[\s\S]*?"randomx_relations_executed": true/,
    'statement_set_not_fully_native_prevalidated');
  need(failures,setExporter,
    /"native_reference_commitment": hex\(&native_reference_commitment\)/,
    'native_reference_result_not_bound_to_record');
  need(failures,proofHost,
    /\|\| !source\.randomx_relations_executed/,
    'proof_host_accepts_unprevalidated_source');
  need(failures,proofHost,
    /source\.randomx_receipt_image_id != EXPECTED_IMAGE_ID[\s\S]*?validate_artifact\(paths\.elf,[\s\S]*?EXPECTED_ELF_SHA256[\s\S]*?validate_artifact\(paths\.image_id,[\s\S]*?EXPECTED_IMAGE_ID_FILE_SHA256/,
    'proof_host_does_not_pin_guest_identity');
  need(failures,proofHost,
    /receipt\s*\.verify\(Risc0Digest::from\(image_id\)\)[\s\S]*?receipt\.journal\.bytes\.as_slice\(\) != expected_journal/,
    'receipt_not_verified_against_image_and_exact_journal');
  need(failures,guest,
    /calculate_randomx_light_hash\(&statement\.pow_preimage,[\s\S]*?assert_eq!\(\s*actual, statement\.randomx_hash,[\s\S]*?env::commit_slice\(&journal\)/,
    'guest_does_not_authorize_exact_randomx_relation');
  return failures;
}

/** Audit the complete release-time ImageID chain without selecting a release.
 * The concrete ImageID is derived from the checked-in guest artifact and must
 * agree with both proof-host and capacity-evidence pins. The native manifest
 * remains release-specific; readiness must reconcile its checker output with
 * the canonical checkpoint verifier manifest before activation.
 */
export function validateCheckpointRandomxImageIdBinding({
  nativeConfig,checkpointProgram,segmentGuest,proofHost,checkpointConfig,readiness,capacity,
  imageIdArtifact,
}) {
  const sources={nativeConfig,checkpointProgram,segmentGuest,proofHost,checkpointConfig,
    readiness,capacity};
  for(const [name,value] of Object.entries(sources)) {
    if(typeof value!=='string'||value.length===0) throw new TypeError(`${name} source is required`);
  }
  if(typeof imageIdArtifact!=='string') throw new TypeError('imageIdArtifact is required');
  const failures=[];
  need(failures,nativeConfig,
    /CANDIDATE_V2_SCHEMA_VERSION \| ISSUANCE_CLOSURE_SCHEMA_VERSION, Some\(value\)[\s\S]*?decode_hex_array::<32>\(value, "RandomX receipt ImageID"\)[\s\S]*?image_id == \[0; 32\][\s\S]*?Some\(image_id\)/,
    'native_manifest_does_not_pin_nonzero_image_id');
  need(failures,checkpointProgram,
    /pub randomx_receipt_image_id: \[u8; 32\][\s\S]*?self\.previous\.randomx_receipt_image_id != self\.next\.randomx_receipt_image_id/,
    'checkpoint_state_does_not_preserve_image_id');
  need(failures,checkpointProgram,
    /let journal = statement[\s\S]*?\.commitment\(\)[\s\S]*?image_id: state\.randomx_receipt_image_id,[\s\S]*?journal/,
    'checkpoint_assumption_not_derived_from_state_and_statement');
  need(failures,segmentGuest,
    /verify_checkpoint_segment_randomx_bindings_in_guest\(executed\.randomx_bindings\(\)\)/,
    'segment_guest_does_not_verify_state_pinned_randomx_receipts');
  need(failures,checkpointConfig,
    /randomxReceiptImageId[\s\S]*?CHECKPOINT_VERIFIER_PROTOCOL_TYPEHASH[\s\S]*?c\.randomxReceiptImageId/,
    'checkpoint_manifest_hash_omits_randomx_image_id');
  need(failures,readiness,
    /nativeRuntime\.randomxReceiptImageId[\s\S]*?computedCheckpointVerifierConfig\.randomxReceiptImageId[\s\S]*?native_runtime_checkpoint_randomx_image_id_mismatch/,
    'release_gate_does_not_reconcile_native_and_checkpoint_image_ids');
  need(failures,capacity,
    /randomxReceiptImageId[\s\S]*?!==['"]0x['"]\+CHECKPOINT_RANDOMX_IMAGE_ID[\s\S]*?per-block RandomX receipt ImageID/,
    'capacity_report_does_not_require_per_block_image_id');

  const host=proofHost.match(/const EXPECTED_IMAGE_ID: &str = "([0-9a-f]{64})";/)?.[1];
  const report=capacity.match(/export const CHECKPOINT_RANDOMX_IMAGE_ID=\s*\n?\s*'([0-9a-f]{64})';/)?.[1];
  const artifact=imageIdArtifact.trim();
  if(!host || !report || !/^[0-9a-f]{64}$/.test(artifact)
      || host!==report || host!==artifact) {
    failures.push('guest_artifact_host_and_evidence_image_ids_disagree');
  }
  return failures;
}
