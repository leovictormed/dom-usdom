//! Export every `UDCRXST1` statement from an authenticated checkpoint source set.

#![deny(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use dom_node::private_staging_directory::PrivateDirectoryAuthority;
use dom_usdom_checkpoint_program::{
    execute_checkpoint_randomx_reference, execute_checkpoint_segment_portable,
    CheckpointSegmentNativeStateOpening, CheckpointSegmentPolicyInput,
    CheckpointSegmentPrivateInput, CheckpointSegmentTransition, CHECKPOINT_RANDOMX_STATEMENT_BYTES,
    CHECKPOINT_SEGMENT_TRANSITION_BYTES, MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES,
    MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES, MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
};
use dom_wallet_crypto::read_captured_bytes;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const OUTPUT_INDEX_NAME: &str = "randomx-statement-set-index.json";
const MAX_SOURCE_INDEX_BYTES: usize = 512 * 1024;
const MAX_SEGMENTS: usize = 32;
const MAX_STATEMENTS: usize = 720;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceIndex {
    schema: String,
    manifest_sha256: String,
    randomx_receipt_image_id: String,
    checkpoint_interval_blocks: u32,
    checkpoint_confirmation_depth_blocks: u32,
    previous_height: u64,
    target_height: u64,
    confirmation_height: u64,
    segment_count: usize,
    segments: Vec<SourceSegment>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceSegment {
    index: usize,
    previous_height: u64,
    next_height: u64,
    block_count: u16,
    transition_file: String,
    transition_sha256: String,
    private_input_file: String,
    private_input_sha256: String,
    policy_input_file: String,
    policy_input_sha256: String,
    native_state_opening_file: String,
    native_state_opening_sha256: String,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn ensure_direct_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "required directory {} is unavailable: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "required directory {} must be a direct directory",
            path.display()
        ));
    }
    Ok(())
}

fn read_direct_regular_file(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    read_captured_bytes(path, maximum)
        .map_err(|error| format!("cannot capture {}: {error}", path.display()))
}

fn expected_source_name(index: usize, suffix: &str) -> String {
    format!("checkpoint-segment-{index:04}-{suffix}")
}

fn statement_name(index: usize) -> String {
    format!("randomx-statement-{index:04}.bin")
}

fn is_output_name(name: &str) -> bool {
    if name == OUTPUT_INDEX_NAME {
        return true;
    }
    let Some(value) = name
        .strip_prefix("randomx-statement-")
        .and_then(|value| value.strip_suffix(".bin"))
    else {
        return false;
    };
    value.len() == 4 && value.as_bytes().iter().all(u8::is_ascii_digit)
}

fn invalidate_outputs(output_directory: &Path) -> Result<(), String> {
    PrivateDirectoryAuthority::open(output_directory)
        .and_then(|authority| authority.invalidate_where(is_output_name))
        .map_err(|error| error.to_string())
}

fn atomic_publish(output_directory: &Path, files: &[(String, Vec<u8>)]) -> Result<(), String> {
    PrivateDirectoryAuthority::open(output_directory)
        .and_then(|authority| authority.replace_files(files, &[OUTPUT_INDEX_NAME]))
        .map_err(|error| error.to_string())
}

fn read_component(
    source_directory: &Path,
    actual_name: &str,
    expected_name: &str,
    expected_hash: &str,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    if actual_name != expected_name || !canonical_sha256(expected_hash) {
        return Err(format!(
            "source component identity mismatch: {expected_name}"
        ));
    }
    let bytes = read_direct_regular_file(&source_directory.join(actual_name), maximum)?;
    if sha256(&bytes) != expected_hash {
        return Err(format!("source component hash mismatch: {expected_name}"));
    }
    Ok(bytes)
}

fn evidence_directory() -> Result<PathBuf, String> {
    let mut arguments = env::args_os().skip(1);
    match arguments.next() {
        None => Ok(PathBuf::from("evidence")),
        Some(flag) if flag == "--evidence-dir" => {
            let directory = arguments
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "--evidence-dir requires an absolute path".to_owned())?;
            if arguments.next().is_some() || !directory.is_absolute() {
                return Err("--evidence-dir requires exactly one absolute path".into());
            }
            Ok(directory)
        }
        Some(_) => Err("only optional --evidence-dir ABS is accepted".into()),
    }
}

fn run() -> Result<(), String> {
    let evidence_directory = evidence_directory()?;
    let source_directory = evidence_directory.join("checkpoint-source-set");
    let source_index_path = source_directory.join("checkpoint-source-set-index.json");
    let output_directory = evidence_directory.join("randomx-statement-set");
    ensure_direct_directory(&evidence_directory)?;
    ensure_direct_directory(&source_directory)?;
    ensure_direct_directory(&output_directory)?;
    invalidate_outputs(&output_directory)?;

    let source_index_bytes = read_direct_regular_file(&source_index_path, MAX_SOURCE_INDEX_BYTES)?;
    let source: SourceIndex = serde_json::from_slice(&source_index_bytes)
        .map_err(|error| format!("invalid source-set index: {error}"))?;
    if source.schema != "usdom-canonical-checkpoint-source-set-v1"
        || !canonical_sha256(&source.manifest_sha256)
        || !canonical_sha256(&source.randomx_receipt_image_id)
        || source.randomx_receipt_image_id == "0".repeat(64)
        || source.checkpoint_interval_blocks == 0
        || source.checkpoint_confirmation_depth_blocks == 0
        || source.checkpoint_confirmation_depth_blocks > source.checkpoint_interval_blocks
        || source.segment_count == 0
        || source.segment_count > MAX_SEGMENTS
        || source.segment_count != source.segments.len()
        || source.previous_height >= source.target_height
        || source.target_height >= source.confirmation_height
        || source.target_height - source.previous_height
            != u64::from(source.checkpoint_interval_blocks)
        || source.confirmation_height - source.target_height
            != u64::from(source.checkpoint_confirmation_depth_blocks)
    {
        return Err("source-set index identity or cadence is invalid".into());
    }

    let mut expected_previous = source.previous_height;
    let mut target_boundary_seen = false;
    let mut statements = Vec::new();
    let mut statement_records = Vec::new();
    for (expected_index, segment) in source.segments.iter().enumerate() {
        if segment.index != expected_index
            || segment.previous_height != expected_previous
            || segment.next_height <= segment.previous_height
            || segment.next_height > source.confirmation_height
            || u64::from(segment.block_count) != segment.next_height - segment.previous_height
            || segment.block_count == 0
            || segment.block_count > 32
            || (segment.previous_height < source.target_height
                && segment.next_height > source.target_height)
        {
            return Err("source segment order or checkpoint boundary is invalid".into());
        }
        if segment.next_height == source.target_height {
            if target_boundary_seen {
                return Err("checkpoint target boundary is duplicated".into());
            }
            target_boundary_seen = true;
        }
        let transition_bytes = read_component(
            &source_directory,
            &segment.transition_file,
            &expected_source_name(expected_index, "transition.bin"),
            &segment.transition_sha256,
            CHECKPOINT_SEGMENT_TRANSITION_BYTES,
        )?;
        if transition_bytes.len() != CHECKPOINT_SEGMENT_TRANSITION_BYTES {
            return Err("checkpoint transition has the wrong exact length".into());
        }
        let private_input_bytes = read_component(
            &source_directory,
            &segment.private_input_file,
            &expected_source_name(expected_index, "private-input.bin"),
            &segment.private_input_sha256,
            MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
        )?;
        let policy_input_bytes = read_component(
            &source_directory,
            &segment.policy_input_file,
            &expected_source_name(expected_index, "policy-input.bin"),
            &segment.policy_input_sha256,
            MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES,
        )?;
        let native_opening_bytes = read_component(
            &source_directory,
            &segment.native_state_opening_file,
            &expected_source_name(expected_index, "native-state-opening.bin"),
            &segment.native_state_opening_sha256,
            MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES,
        )?;
        let transition = CheckpointSegmentTransition::from_bytes(&transition_bytes)
            .map_err(|error| format!("invalid checkpoint transition: {error}"))?;
        if transition.previous.height != segment.previous_height
            || transition.next.height != segment.next_height
            || transition.block_count != segment.block_count
            || hex(&transition.previous.randomx_receipt_image_id) != source.randomx_receipt_image_id
            || transition.next.randomx_receipt_image_id
                != transition.previous.randomx_receipt_image_id
        {
            return Err("source index and transition disagree".into());
        }
        let private_input = CheckpointSegmentPrivateInput::from_bytes(&private_input_bytes)
            .map_err(|error| format!("invalid checkpoint private input: {error}"))?;
        let policy_input = CheckpointSegmentPolicyInput::from_bytes(&policy_input_bytes)
            .map_err(|error| format!("invalid checkpoint policy input: {error}"))?;
        let native_opening = CheckpointSegmentNativeStateOpening::from_bytes(&native_opening_bytes)
            .map_err(|error| format!("invalid checkpoint native opening: {error}"))?;
        let execution = execute_checkpoint_segment_portable(
            &transition,
            &private_input,
            &policy_input,
            &native_opening,
        )
        .map_err(|error| format!("checkpoint segment execution rejected source: {error}"))?;
        if execution.randomx_bindings().len() != usize::from(segment.block_count) {
            return Err("portable execution returned the wrong RandomX binding count".into());
        }
        let transition_commitment = transition
            .commitment()
            .map_err(|error| format!("cannot commit transition: {error}"))?;
        for (block_index, binding) in execution.randomx_bindings().iter().enumerate() {
            let global_index = statements.len();
            if global_index >= MAX_STATEMENTS {
                return Err("statement set exceeds its production bound".into());
            }
            let statement = binding
                .statement()
                .to_bytes()
                .map_err(|error| format!("cannot encode RandomX statement: {error}"))?;
            let height_offset = u64::try_from(block_index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| "RandomX statement height offset overflow".to_string())?;
            let expected_height = segment
                .previous_height
                .checked_add(height_offset)
                .ok_or_else(|| "RandomX statement height overflow".to_string())?;
            if statement.len() != CHECKPOINT_RANDOMX_STATEMENT_BYTES
                || binding.statement().block_height != expected_height
            {
                return Err("portable execution returned a noncanonical statement".into());
            }
            let native_reference_commitment = execute_checkpoint_randomx_reference(&statement)
                .map_err(|error| format!("native RandomX reference rejected statement: {error}"))?;
            let name = statement_name(global_index);
            let statement_hash = sha256(&statement);
            let statement_commitment = binding
                .statement()
                .commitment()
                .map_err(|error| format!("cannot commit statement: {error}"))?;
            statement_records.push(serde_json::json!({
                "index": global_index,
                "segment_index": expected_index,
                "block_index": block_index,
                "block_height": binding.statement().block_height,
                "block_hash": hex(binding.block_hash()),
                "transition_commitment": hex(&transition_commitment),
                "statement_file": name,
                "statement_sha256": statement_hash,
                "statement_commitment": hex(&statement_commitment),
                "native_reference_commitment": hex(&native_reference_commitment)
            }));
            statements.push((name, statement.to_vec()));
        }
        expected_previous = segment.next_height;
    }
    if !target_boundary_seen
        || expected_previous != source.confirmation_height
        || statements.len()
            != usize::try_from(source.confirmation_height - source.previous_height)
                .map_err(|_| "statement count does not fit memory bounds".to_string())?
    {
        return Err("source set does not cover the exact checkpoint span".into());
    }

    let output_index = serde_json::json!({
        "schema": "usdom-authenticated-randomx-statement-set-v1",
        "source_index_path": "evidence/checkpoint-source-set/checkpoint-source-set-index.json",
        "source_index_sha256": sha256(&source_index_bytes),
        "manifest_sha256": source.manifest_sha256,
        "randomx_receipt_image_id": source.randomx_receipt_image_id,
        "previous_height": source.previous_height,
        "target_height": source.target_height,
        "confirmation_height": source.confirmation_height,
        "segment_count": source.segment_count,
        "statement_count": statements.len(),
        "portable_segments_executed": true,
        "randomx_relations_executed": true,
        "generates_proofs": false,
        "mines": false,
        "statements": statement_records
    });
    let mut output_index_bytes = serde_json::to_vec_pretty(&output_index)
        .map_err(|error| format!("cannot encode statement-set index: {error}"))?;
    output_index_bytes.push(b'\n');
    statements.push((OUTPUT_INDEX_NAME.to_owned(), output_index_bytes));
    atomic_publish(&output_directory, &statements)?;
    println!("status: exported");
    println!("segment_count: {}", source.segment_count);
    println!("statement_count: {}", statements.len() - 1);
    println!("source_index_sha256: {}", sha256(&source_index_bytes));
    Ok(())
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("authenticated RandomX statement-set export failed");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{canonical_sha256, is_output_name, statement_name};

    #[test]
    fn output_names_and_hashes_are_exact() {
        assert_eq!(statement_name(7), "randomx-statement-0007.bin");
        assert!(is_output_name("randomx-statement-0007.bin"));
        assert!(is_output_name("randomx-statement-set-index.json"));
        assert!(!is_output_name("randomx-statement-007.bin"));
        assert!(!is_output_name("randomx-statement-0007.bin.bak"));
        assert!(canonical_sha256(&"ab".repeat(32)));
        assert!(!canonical_sha256(&"AB".repeat(32)));
    }
}
