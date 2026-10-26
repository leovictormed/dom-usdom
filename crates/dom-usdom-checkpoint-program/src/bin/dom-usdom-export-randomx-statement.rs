//! Export one terminal `UDCRXST1` statement from a fully executed segment.

#![deny(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use dom_usdom_checkpoint_program::{
    execute_checkpoint_randomx_reference, execute_checkpoint_segment_portable,
    CheckpointSegmentNativeStateOpening, CheckpointSegmentPolicyInput,
    CheckpointSegmentPrivateInput, CheckpointSegmentTransition, CHECKPOINT_RANDOMX_STATEMENT_BYTES,
    CHECKPOINT_SEGMENT_TRANSITION_BYTES, MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES,
    MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES, MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
};
use dom_wallet_crypto::{read_captured_bytes, save_private_bytes};

const SOURCE_DIRECTORY: &str = "evidence/randomx-source";
const TRANSITION_PATH: &str = "evidence/randomx-source/checkpoint-segment-transition.bin";
const PRIVATE_INPUT_PATH: &str = "evidence/randomx-source/checkpoint-segment-private-input.bin";
const POLICY_INPUT_PATH: &str = "evidence/randomx-source/checkpoint-segment-policy-input.bin";
const NATIVE_OPENING_PATH: &str =
    "evidence/randomx-source/checkpoint-segment-native-state-opening.bin";
const OUTPUT_PATH: &str = "evidence/randomx-canonical-statement.bin";
const REPORT_PATH: &str = "evidence/randomx-canonical-statement-export.json";

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
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

fn invalidate_output(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(format!(
            "statement output {} is not a direct regular file",
            path.display()
        )),
        Ok(_) => {
            fs::remove_file(path)
                .map_err(|error| format!("cannot invalidate stale {}: {error}", path.display()))?;
            let parent = path
                .parent()
                .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("cannot sync {}: {error}", parent.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot inspect statement output {}: {error}",
            path.display()
        )),
    }
}

fn read_direct_regular_file(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    read_captured_bytes(path, maximum)
        .map_err(|error| format!("cannot capture {}: {error}", path.display()))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    save_private_bytes(path, bytes)
        .map_err(|error| format!("cannot publish {}: {error}", path.display()))
}

fn run() -> Result<(), String> {
    if env::args_os().len() != 1 {
        return Err("this exporter accepts no arguments or field overrides".into());
    }
    ensure_direct_directory(Path::new("evidence"))?;
    ensure_direct_directory(Path::new(SOURCE_DIRECTORY))?;
    let output = PathBuf::from(OUTPUT_PATH);
    let report_path = PathBuf::from(REPORT_PATH);
    invalidate_output(&output)?;
    invalidate_output(&report_path)?;

    let transition_bytes = read_direct_regular_file(
        Path::new(TRANSITION_PATH),
        CHECKPOINT_SEGMENT_TRANSITION_BYTES,
    )?;
    if transition_bytes.len() != CHECKPOINT_SEGMENT_TRANSITION_BYTES {
        return Err("checkpoint transition has the wrong exact length".into());
    }
    let private_input_bytes = read_direct_regular_file(
        Path::new(PRIVATE_INPUT_PATH),
        MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
    )?;
    let policy_input_bytes = read_direct_regular_file(
        Path::new(POLICY_INPUT_PATH),
        MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES,
    )?;
    let native_opening_bytes = read_direct_regular_file(
        Path::new(NATIVE_OPENING_PATH),
        MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES,
    )?;

    let transition = CheckpointSegmentTransition::from_bytes(&transition_bytes)
        .map_err(|error| format!("invalid checkpoint transition: {error}"))?;
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
    .map_err(|error| format!("checkpoint segment execution rejected source evidence: {error}"))?;
    let selected_index = execution
        .randomx_bindings()
        .len()
        .checked_sub(1)
        .ok_or_else(|| "checkpoint execution returned no RandomX binding".to_string())?;
    let binding = &execution.randomx_bindings()[selected_index];
    let statement = binding
        .statement()
        .to_bytes()
        .map_err(|error| format!("cannot encode canonical RandomX statement: {error}"))?;
    if statement.len() != CHECKPOINT_RANDOMX_STATEMENT_BYTES {
        return Err("canonical RandomX statement has an impossible length".into());
    }
    let native_reference_commitment = execute_checkpoint_randomx_reference(&statement)
        .map_err(|error| format!("native RandomX reference rejected statement: {error}"))?;
    let transition_commitment = transition
        .commitment()
        .map_err(|error| format!("cannot commit transition: {error}"))?;
    let private_input_commitment = private_input
        .commitment()
        .map_err(|error| format!("cannot commit private input: {error}"))?;
    let policy_input_commitment = policy_input
        .commitment()
        .map_err(|error| format!("cannot commit policy input: {error}"))?;
    let native_opening_commitment = native_opening
        .commitment()
        .map_err(|error| format!("cannot commit native opening: {error}"))?;
    let statement_commitment = binding
        .statement()
        .commitment()
        .map_err(|error| format!("cannot commit statement: {error}"))?;
    let report = format!(
        concat!(
            "{{\n",
            "  \"schema\": \"usdom-authenticated-randomx-statement-export-v1\",\n",
            "  \"portableSegmentExecuted\": true,\n",
            "  \"randomxRelationExecuted\": true,\n",
            "  \"generatesProof\": false,\n",
            "  \"mines\": false,\n",
            "  \"sourceBlockCount\": {},\n",
            "  \"selectedBlockIndex\": {},\n",
            "  \"blockHeight\": \"{}\",\n",
            "  \"blockHash\": \"0x{}\",\n",
            "  \"transitionCommitment\": \"0x{}\",\n",
            "  \"privateInputCommitment\": \"0x{}\",\n",
            "  \"policyInputCommitment\": \"0x{}\",\n",
            "  \"nativeOpeningCommitment\": \"0x{}\",\n",
            "  \"statementCommitment\": \"0x{}\",\n",
            "  \"nativeReferenceCommitment\": \"0x{}\",\n",
            "  \"statementPath\": \"{}\",\n",
            "  \"reportPath\": \"{}\"\n",
            "}}"
        ),
        execution.randomx_bindings().len(),
        selected_index,
        binding.statement().block_height,
        hex(binding.block_hash()),
        hex(&transition_commitment),
        hex(&private_input_commitment),
        hex(&policy_input_commitment),
        hex(&native_opening_commitment),
        hex(&statement_commitment),
        hex(&native_reference_commitment),
        OUTPUT_PATH,
        REPORT_PATH,
    );
    atomic_write(&output, &statement)?;
    if let Err(error) = atomic_write(&report_path, report.as_bytes()) {
        let _ = invalidate_output(&output);
        return Err(error);
    }
    println!("{report}");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("authenticated RandomX statement export failed: {error}");
        std::process::exit(1);
    }
}
