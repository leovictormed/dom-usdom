//! Authenticated, deterministic planning for recursive economic proof jobs.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::fs;
#[cfg(feature = "prove")]
use std::fs::File;
use std::path::Path;

use dom_usdom_checkpoint_program::{
    execute_economic_chunk_portable, CheckpointSegmentPrivateInput, EconomicBlockTransition,
    EconomicChunkTransition, EconomicChunkWitness, ECONOMIC_BLOCK_TRANSITION_BYTES,
    ECONOMIC_CHUNK_TRANSITION_BYTES, MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
    MAX_ECONOMIC_CHUNK_WITNESS_BYTES,
};
use dom_usdom_economic_block_program::{
    validate_economic_block_chain, EconomicChunkChain, MAX_ECONOMIC_CHUNK_CHAIN_BYTES,
};
use dom_wallet_crypto::{read_captured_bytes, save_private_bytes};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const SOURCE_SCHEMA: &str = "usdom-canonical-checkpoint-source-set-v1";
const ECONOMIC_SOURCE_SCHEMA: &str = "usdom-economic-proof-source-set-v1";
const JOB_SCHEMA: &str = "usdom-economic-proof-job-set-v1";
const SOURCE_INDEX_LOGICAL_PATH: &str =
    "evidence/checkpoint-source-set/checkpoint-source-set-index.json";
const ECONOMIC_INDEX_LOGICAL_PATH: &str =
    "evidence/checkpoint-source-set/checkpoint-economic-source-set-index.json";
const SOURCE_DIRECTORY_LOGICAL_PATH: &str = "evidence/checkpoint-source-set";
const CHUNK_ELF_LOGICAL_PATH: &str =
    "../../crates/dom-usdom-economic-chunk-risc0-guest/elfs/usdom-economic-chunk.elf";
const CHUNK_PROGRAM_LOGICAL_PATH: &str =
    "../../crates/dom-usdom-economic-chunk-risc0-guest/elfs/usdom-economic-chunk.bin";
const CHUNK_IMAGE_ID_LOGICAL_PATH: &str =
    "../../crates/dom-usdom-economic-chunk-risc0-guest/elfs/usdom-economic-chunk.iid";
const BLOCK_ELF_LOGICAL_PATH: &str =
    "../../crates/dom-usdom-economic-block-risc0-guest/elfs/usdom-economic-block.elf";
const BLOCK_PROGRAM_LOGICAL_PATH: &str =
    "../../crates/dom-usdom-economic-block-risc0-guest/elfs/usdom-economic-block.bin";
const BLOCK_IMAGE_ID_LOGICAL_PATH: &str =
    "../../crates/dom-usdom-economic-block-risc0-guest/elfs/usdom-economic-block.iid";
const EXPECTED_CHUNK_ELF_SHA256: &str =
    "eb4091a118e19205ae4ff6d776e18e811aa2a80063695e768be2a26be45fb3a0";
const EXPECTED_CHUNK_PROGRAM_SHA256: &str =
    "5e7bc30f65ab4eae7c8b19a8c1c386cd023cd648c85f64008be2bd4729231842";
const EXPECTED_CHUNK_IMAGE_ID: &str =
    "67d286e04444b52305ec409de3c0d22b2131a42f2aa6706f087ace253048e350";
const EXPECTED_CHUNK_IMAGE_ID_FILE_SHA256: &str =
    "c9bedc4dcf7919389a8e9d3fbeebadc7bbcfc75dcaa6f12681ba316787e2d123";
const EXPECTED_BLOCK_ELF_SHA256: &str =
    "e863f8ddc042a0692f8ceebc8d0c074e6812087bc9c06a5cd1710ac0c7bfda2f";
const EXPECTED_BLOCK_PROGRAM_SHA256: &str =
    "e16e6aea7d470baad85bec45578e0960c02c2d47bce267e26141a2f3fa4a6c1f";
const EXPECTED_BLOCK_IMAGE_ID: &str =
    "03dc111fee3c42a772f142c80d4a921a19bde10f932f86c888606503a28c22a7";
const EXPECTED_BLOCK_IMAGE_ID_FILE_SHA256: &str =
    "c83ba9f5809f8dc388d01ddb0b75baf98e22e5703cefc8cc349e535b2c796419";
const RISC0_VERSION: &str = "3.0.6";
const RECEIPT_KIND: &str = "succinct";
const JOB_INDEX_NAME: &str = "economic-proof-job-index.json";
#[cfg(feature = "prove")]
const RECEIPT_INDEX_NAME: &str = "economic-receipt-set-index.json";
#[cfg(feature = "prove")]
const JOB_INDEX_LOGICAL_PATH: &str = "evidence/economic-proof-jobs/economic-proof-job-index.json";
const MAX_SOURCE_INDEX_BYTES: usize = 4 * 1024 * 1024;
const MAX_ECONOMIC_INDEX_BYTES: usize = 64 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: usize = 512 * 1024 * 1024;
const MAX_BLOCKS: usize = 720;

#[cfg(feature = "prove")]
fn require_local_prover_environment(context: &str) -> Result<(), String> {
    if std::env::var("RISC0_PROVER").ok().as_deref() != Some("local")
        || std::env::var("RISC0_DEV_MODE").ok().as_deref() != Some("0")
    {
        return Err(format!(
            "{context} requires exact RISC0_PROVER=local and RISC0_DEV_MODE=0"
        ));
    }
    for variable in [
        "BONSAI_API_URL",
        "BONSAI_API_KEY",
        "RISC0_SERVER_PATH",
        "RISC0_SERVER_ADDR",
        "RISC0_EXECUTOR",
        "RISC0_PPROF_OUT",
        "RISC0_PPROF_ENABLE_INLINE_FUNCTIONS",
        "RISC0_KECCAK_PO2",
        "RISC0_DEFAULT_PROVER_NUM_GPUS",
        "RISC0_INFO",
        "RISC0_REDIS_CHANNEL_SIZE",
        "BONSAI_POLL_INTERVAL_MS",
    ] {
        if std::env::var_os(variable).is_some() {
            return Err(format!(
                "{context} rejects inherited remote prover variable {variable}"
            ));
        }
    }
    Ok(())
}

#[cfg(any(feature = "prove", test))]
fn parse_linux_peak_resident_kib(status: &str) -> Result<u64, String> {
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .ok_or_else(|| "prover memory status has no VmHWM".to_owned())?;
    let mut fields = line.split_ascii_whitespace();
    let value = fields
        .next()
        .ok_or_else(|| "prover VmHWM value is absent".to_owned())?
        .parse::<u64>()
        .map_err(|error| format!("prover VmHWM is invalid: {error}"))?;
    if fields.next() != Some("kB")
        || fields.next().is_some()
        || value == 0
        || value > 64 * 1024 * 1024
    {
        return Err("prover VmHWM is outside its canonical bound".into());
    }
    Ok(value)
}

#[cfg(feature = "prove")]
fn linux_peak_resident_kib() -> Result<u64, String> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("cannot read prover memory status: {error}"))?;
    parse_linux_peak_resident_kib(&status)
}
#[cfg(feature = "prove")]
const MAX_RECEIPT_BYTES: usize = 256 * 1024 * 1024;

/// Fixed authenticated inputs and output directory for non-proving planning.
pub struct PlanPaths<'a> {
    /// Canonical checkpoint source-set index.
    pub checkpoint_source_index: &'a Path,
    /// Separate hash-bound economic proof source index.
    pub economic_source_index: &'a Path,
    /// Directory containing checkpoint and economic source files.
    pub source_directory: &'a Path,
    /// Pinned economic chunk guest ELF.
    pub chunk_elf: &'a Path,
    /// Pinned packaged economic chunk program.
    pub chunk_program: &'a Path,
    /// Pinned economic chunk ImageID file.
    pub chunk_image_id: &'a Path,
    /// Pinned economic block guest ELF.
    pub block_elf: &'a Path,
    /// Pinned packaged economic block program.
    pub block_program: &'a Path,
    /// Pinned economic block ImageID file.
    pub block_image_id: &'a Path,
    /// Direct directory receiving the deterministic job index.
    pub output_directory: &'a Path,
}

impl PlanPaths<'static> {
    /// Production paths relative to the USDOM reserve laboratory root.
    pub fn production() -> Self {
        Self {
            checkpoint_source_index: Path::new(SOURCE_INDEX_LOGICAL_PATH),
            economic_source_index: Path::new(ECONOMIC_INDEX_LOGICAL_PATH),
            source_directory: Path::new(SOURCE_DIRECTORY_LOGICAL_PATH),
            chunk_elf: Path::new(CHUNK_ELF_LOGICAL_PATH),
            chunk_program: Path::new(CHUNK_PROGRAM_LOGICAL_PATH),
            chunk_image_id: Path::new(CHUNK_IMAGE_ID_LOGICAL_PATH),
            block_elf: Path::new(BLOCK_ELF_LOGICAL_PATH),
            block_program: Path::new(BLOCK_PROGRAM_LOGICAL_PATH),
            block_image_id: Path::new(BLOCK_IMAGE_ID_LOGICAL_PATH),
            output_directory: Path::new("evidence/economic-proof-jobs"),
        }
    }
}

/// Fixed inputs and output for an explicitly authorized local proving run.
#[cfg(feature = "prove")]
pub struct ProofPaths<'a> {
    /// Inputs used to rebuild the exact authenticated plan.
    pub plan: PlanPaths<'a>,
    /// Published job index, which must equal the rebuilt plan byte for byte.
    pub job_index: &'a Path,
    /// Direct directory receiving verified chunk/block receipts and final index.
    pub output_directory: &'a Path,
}

#[cfg(feature = "prove")]
impl ProofPaths<'static> {
    /// Production paths relative to the reserve laboratory root.
    pub fn production() -> Self {
        Self {
            plan: PlanPaths::production(),
            job_index: Path::new("evidence/economic-proof-jobs/economic-proof-job-index.json"),
            output_directory: Path::new("evidence/economic-receipt-set"),
        }
    }
}

/// Observable deterministic planning result.
pub struct PlanSummary {
    /// Number of bounded economic chunk jobs.
    pub chunk_job_count: usize,
    /// Number of recursive economic block jobs.
    pub block_job_count: usize,
    /// SHA-256 of the consumed economic source index.
    pub economic_source_index_sha256: String,
    /// SHA-256 of the published economic job index.
    pub job_index_sha256: String,
}

/// Observable result after every economic receipt has been proved and verified.
#[cfg(feature = "prove")]
pub struct ProofSummary {
    /// Number of verified bounded chunk receipts.
    pub chunk_receipt_count: usize,
    /// Number of verified recursive block receipts.
    pub block_receipt_count: usize,
    /// SHA-256 of the exact consumed job index.
    pub job_index_sha256: String,
    /// SHA-256 of the published receipt-set index.
    pub receipt_index_sha256: String,
}

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
    segments: Vec<SegmentRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentRecord {
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EconomicSourceIndex {
    schema: String,
    checkpoint_source_index_path: String,
    checkpoint_source_index_sha256: String,
    block_count: usize,
    blocks: Vec<EconomicBlockRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EconomicBlockRecord {
    segment_index: usize,
    block_index: usize,
    block_transition_file: String,
    block_transition_sha256: String,
    chunk_count: usize,
    chunks: Vec<EconomicChunkRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EconomicChunkRecord {
    index: usize,
    transition_file: String,
    transition_sha256: String,
    witness_file: String,
    witness_sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EconomicProofJobIndex {
    schema: String,
    checkpoint_source_index_path: String,
    checkpoint_source_index_sha256: String,
    economic_source_index_path: String,
    economic_source_index_sha256: String,
    manifest_sha256: String,
    chunk_user_elf_path: String,
    chunk_user_elf_sha256: String,
    chunk_program_path: String,
    chunk_program_sha256: String,
    chunk_image_id_path: String,
    chunk_image_id_file_sha256: String,
    chunk_image_id: String,
    block_user_elf_path: String,
    block_user_elf_sha256: String,
    block_program_path: String,
    block_program_sha256: String,
    block_image_id_path: String,
    block_image_id_file_sha256: String,
    block_image_id: String,
    risc0_zkvm_version: String,
    receipt_kind: String,
    previous_height: u64,
    target_height: u64,
    confirmation_height: u64,
    segment_count: usize,
    chunk_job_count: usize,
    block_job_count: usize,
    executes_guests: bool,
    generates_proofs: bool,
    mines: bool,
    chunk_jobs: Vec<ChunkJob>,
    block_jobs: Vec<BlockJob>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ChunkJob {
    index: usize,
    segment_index: usize,
    block_index: usize,
    chunk_index: usize,
    block_height: u64,
    block_hash: String,
    package_source_file: String,
    package_sha256: String,
    transition_file: String,
    transition_sha256: String,
    witness_file: String,
    witness_sha256: String,
    expected_journal: String,
    receipt_file: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BlockJob {
    index: usize,
    segment_index: usize,
    block_index: usize,
    block_height: u64,
    block_hash: String,
    transition_file: String,
    transition_sha256: String,
    expected_journal: String,
    chunk_count: usize,
    chunk_receipts: Vec<BlockChunkReceipt>,
    receipt_file: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BlockChunkReceipt {
    chunk_index: usize,
    expected_journal: String,
    receipt_file: String,
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

fn canonical_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn canonical_nonzero_hash(value: &str) -> bool {
    canonical_hash(value) && value != "0".repeat(64)
}

fn direct_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{} must be a direct directory", path.display()));
    }
    Ok(())
}

fn read_direct(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    read_captured_bytes(path, maximum)
        .map_err(|error| format!("cannot capture {}: {error}", path.display()))
}

fn checked_source(
    directory: &Path,
    name: &str,
    expected_name: &str,
    expected_hash: &str,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    if name != expected_name || !canonical_hash(expected_hash) {
        return Err(format!("noncanonical source record {name:?}"));
    }
    let bytes = read_direct(&directory.join(name), maximum)?;
    if sha256(&bytes) != expected_hash {
        return Err(format!("source hash mismatch for {name}"));
    }
    Ok(bytes)
}

fn checked_artifact(path: &Path, expected_hash: &str) -> Result<(), String> {
    let bytes = read_direct(path, MAX_ARTIFACT_BYTES)?;
    if sha256(&bytes) != expected_hash {
        return Err(format!("pinned artifact hash mismatch: {}", path.display()));
    }
    Ok(())
}

fn checked_image_id(path: &Path, expected_hash: &str, expected_id: &str) -> Result<(), String> {
    let bytes = read_direct(path, 128)?;
    if sha256(&bytes) != expected_hash || bytes != format!("{expected_id}\n").as_bytes() {
        return Err(format!("pinned ImageID mismatch: {}", path.display()));
    }
    Ok(())
}

fn atomic_publish(path: &Path, bytes: &[u8]) -> Result<(), String> {
    save_private_bytes(path, bytes)
        .map_err(|error| format!("cannot publish {}: {error}", path.display()))
}

fn chunk_transition_name(segment: usize, block: usize, chunk: usize) -> String {
    format!(
        "checkpoint-segment-{segment:04}-economic-block-{block:04}-chunk-{chunk:04}-transition.bin"
    )
}

fn chunk_witness_name(segment: usize, block: usize, chunk: usize) -> String {
    format!(
        "checkpoint-segment-{segment:04}-economic-block-{block:04}-chunk-{chunk:04}-witness.bin"
    )
}

fn block_transition_name(segment: usize, block: usize) -> String {
    format!("checkpoint-segment-{segment:04}-economic-block-{block:04}-transition.bin")
}

fn source_path(name: &str) -> String {
    format!("{SOURCE_DIRECTORY_LOGICAL_PATH}/{name}")
}

fn build_plan(paths: &PlanPaths<'_>) -> Result<(EconomicProofJobIndex, Vec<u8>, String), String> {
    direct_directory(paths.source_directory)?;
    checked_artifact(paths.chunk_elf, EXPECTED_CHUNK_ELF_SHA256)?;
    checked_artifact(paths.chunk_program, EXPECTED_CHUNK_PROGRAM_SHA256)?;
    checked_image_id(
        paths.chunk_image_id,
        EXPECTED_CHUNK_IMAGE_ID_FILE_SHA256,
        EXPECTED_CHUNK_IMAGE_ID,
    )?;
    checked_artifact(paths.block_elf, EXPECTED_BLOCK_ELF_SHA256)?;
    checked_artifact(paths.block_program, EXPECTED_BLOCK_PROGRAM_SHA256)?;
    checked_image_id(
        paths.block_image_id,
        EXPECTED_BLOCK_IMAGE_ID_FILE_SHA256,
        EXPECTED_BLOCK_IMAGE_ID,
    )?;

    let source_bytes = read_direct(paths.checkpoint_source_index, MAX_SOURCE_INDEX_BYTES)?;
    let source: SourceIndex = serde_json::from_slice(&source_bytes)
        .map_err(|error| format!("invalid checkpoint source index: {error}"))?;
    let economic_bytes = read_direct(paths.economic_source_index, MAX_ECONOMIC_INDEX_BYTES)?;
    let economic: EconomicSourceIndex = serde_json::from_slice(&economic_bytes)
        .map_err(|error| format!("invalid economic source index: {error}"))?;
    if source.schema != SOURCE_SCHEMA
        || economic.schema != ECONOMIC_SOURCE_SCHEMA
        || economic.checkpoint_source_index_path != SOURCE_INDEX_LOGICAL_PATH
        || economic.checkpoint_source_index_sha256 != sha256(&source_bytes)
        || source.segment_count == 0
        || source.segment_count > MAX_BLOCKS
        || source.segment_count != source.segments.len()
        || economic.block_count == 0
        || economic.block_count != economic.blocks.len()
        || economic.block_count > MAX_BLOCKS
        || !canonical_nonzero_hash(&source.manifest_sha256)
        || !canonical_nonzero_hash(&source.randomx_receipt_image_id)
        || source.checkpoint_interval_blocks == 0
        || source.checkpoint_confirmation_depth_blocks == 0
        || source.target_height <= source.previous_height
        || source.confirmation_height <= source.target_height
        || source.target_height.checked_sub(source.previous_height)
            != Some(u64::from(source.checkpoint_interval_blocks))
        || source.confirmation_height.checked_sub(source.target_height)
            != Some(u64::from(source.checkpoint_confirmation_depth_blocks))
    {
        return Err("economic and checkpoint source indexes are inconsistent".into());
    }

    let mut chunk_jobs = Vec::new();
    let mut block_jobs = Vec::with_capacity(economic.block_count);
    let mut economic_cursor = 0usize;
    let mut expected_height = source.previous_height;
    let mut expected_roots = None;
    for (segment_index, segment) in source.segments.iter().enumerate() {
        let expected_private_name =
            format!("checkpoint-segment-{segment_index:04}-private-input.bin");
        if segment.index != segment_index
            || segment.previous_height != expected_height
            || segment.next_height <= segment.previous_height
            || segment.next_height - segment.previous_height != u64::from(segment.block_count)
            || segment.transition_file
                != format!("checkpoint-segment-{segment_index:04}-transition.bin")
            || !canonical_hash(&segment.transition_sha256)
            || segment.policy_input_file
                != format!("checkpoint-segment-{segment_index:04}-policy-input.bin")
            || !canonical_hash(&segment.policy_input_sha256)
            || segment.native_state_opening_file
                != format!("checkpoint-segment-{segment_index:04}-native-state-opening.bin")
            || !canonical_hash(&segment.native_state_opening_sha256)
        {
            return Err(format!("invalid checkpoint segment record {segment_index}"));
        }
        let private_bytes = Zeroizing::new(checked_source(
            paths.source_directory,
            &segment.private_input_file,
            &expected_private_name,
            &segment.private_input_sha256,
            MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
        )?);
        let private = CheckpointSegmentPrivateInput::from_bytes(&private_bytes)
            .map_err(|error| format!("invalid segment {segment_index} private input: {error}"))?;
        if private.blocks().len() != usize::from(segment.block_count) {
            return Err(format!("segment {segment_index} block count mismatch"));
        }
        for (block_index, input) in private.blocks().iter().enumerate() {
            let record = economic
                .blocks
                .get(economic_cursor)
                .ok_or_else(|| "economic source index ends before checkpoint blocks".to_string())?;
            if record.segment_index != segment_index
                || record.block_index != block_index
                || record.chunk_count == 0
                || record.chunk_count != record.chunks.len()
            {
                return Err(format!("invalid economic block record {economic_cursor}"));
            }
            let block_name = block_transition_name(segment_index, block_index);
            let block_bytes = checked_source(
                paths.source_directory,
                &record.block_transition_file,
                &block_name,
                &record.block_transition_sha256,
                ECONOMIC_BLOCK_TRANSITION_BYTES,
            )?;
            if input.economic_witness_bytes() != block_bytes {
                return Err(format!(
                    "segment {segment_index} block {block_index} claim mismatch"
                ));
            }
            let block = EconomicBlockTransition::from_bytes(&block_bytes)
                .map_err(|error| format!("invalid economic block transition: {error}"))?;
            expected_height = expected_height
                .checked_add(1)
                .ok_or_else(|| "block height overflow".to_string())?;
            if block.block_height != expected_height
                || expected_roots.is_some_and(|roots| roots != block.previous_roots)
            {
                return Err(format!(
                    "economic block continuity failed at height {expected_height}"
                ));
            }
            let package_hash = sha256(input.package_bytes());
            let mut transitions = Vec::with_capacity(record.chunk_count);
            let mut block_receipts = Vec::with_capacity(record.chunk_count);
            for (chunk_index, chunk) in record.chunks.iter().enumerate() {
                if chunk.index != chunk_index {
                    return Err(format!(
                        "noncanonical chunk index at block {economic_cursor}"
                    ));
                }
                let transition_name =
                    chunk_transition_name(segment_index, block_index, chunk_index);
                let witness_name = chunk_witness_name(segment_index, block_index, chunk_index);
                let transition_bytes = checked_source(
                    paths.source_directory,
                    &chunk.transition_file,
                    &transition_name,
                    &chunk.transition_sha256,
                    ECONOMIC_CHUNK_TRANSITION_BYTES,
                )?;
                let witness_bytes = Zeroizing::new(checked_source(
                    paths.source_directory,
                    &chunk.witness_file,
                    &witness_name,
                    &chunk.witness_sha256,
                    MAX_ECONOMIC_CHUNK_WITNESS_BYTES,
                )?);
                let transition = EconomicChunkTransition::from_bytes(&transition_bytes)
                    .map_err(|error| format!("invalid economic chunk transition: {error}"))?;
                let witness = EconomicChunkWitness::from_bytes(&witness_bytes)
                    .map_err(|error| format!("invalid economic chunk witness: {error}"))?;
                let executed = execute_economic_chunk_portable(
                    input.package_bytes(),
                    &witness,
                    transition.network_magic,
                    transition.previous_roots,
                )
                .map_err(|error| format!("economic chunk execution failed: {error}"))?;
                if executed != transition {
                    return Err(format!(
                        "economic chunk statement mismatch at job {}",
                        chunk_jobs.len()
                    ));
                }
                let journal = hex(&transition
                    .commitment()
                    .map_err(|error| format!("economic chunk commitment failed: {error}"))?);
                let receipt_file = format!("economic-chunk-receipt-{:04}.bin", chunk_jobs.len());
                block_receipts.push(BlockChunkReceipt {
                    chunk_index,
                    expected_journal: journal.clone(),
                    receipt_file: receipt_file.clone(),
                });
                chunk_jobs.push(ChunkJob {
                    index: chunk_jobs.len(),
                    segment_index,
                    block_index,
                    chunk_index,
                    block_height: block.block_height,
                    block_hash: hex(&block.block_hash),
                    package_source_file: source_path(&expected_private_name),
                    package_sha256: package_hash.clone(),
                    transition_file: source_path(&transition_name),
                    transition_sha256: chunk.transition_sha256.clone(),
                    witness_file: source_path(&witness_name),
                    witness_sha256: chunk.witness_sha256.clone(),
                    expected_journal: journal,
                    receipt_file,
                });
                transitions.push(transition);
            }
            let chain = EconomicChunkChain::new(transitions)
                .map_err(|error| format!("invalid economic chunk chain: {error}"))?;
            let chain_bytes = chain
                .to_bytes()
                .map_err(|error| format!("cannot encode economic chunk chain: {error}"))?;
            if chain_bytes.len() > MAX_ECONOMIC_CHUNK_CHAIN_BYTES {
                return Err("economic chunk chain exceeds guest bound".into());
            }
            let execution = validate_economic_block_chain(
                &block,
                &chain,
                decode_hash(EXPECTED_CHUNK_IMAGE_ID)?,
            )
            .map_err(|error| format!("economic block composition failed: {error}"))?;
            block_jobs.push(BlockJob {
                index: block_jobs.len(),
                segment_index,
                block_index,
                block_height: block.block_height,
                block_hash: hex(&block.block_hash),
                transition_file: source_path(&block_name),
                transition_sha256: record.block_transition_sha256.clone(),
                expected_journal: hex(&execution.block_commitment()),
                chunk_count: block_receipts.len(),
                chunk_receipts: block_receipts,
                receipt_file: format!("economic-block-receipt-{:04}.bin", block_jobs.len()),
            });
            expected_roots = Some(block.next_roots);
            economic_cursor += 1;
        }
        if expected_height != segment.next_height {
            return Err(format!("segment {segment_index} height coverage mismatch"));
        }
    }
    if economic_cursor != economic.blocks.len()
        || expected_height != source.confirmation_height
        || source.segments.last().map(|segment| segment.next_height)
            != Some(source.confirmation_height)
    {
        return Err("economic jobs do not cover the full checkpoint source".into());
    }

    let plan = EconomicProofJobIndex {
        schema: JOB_SCHEMA.into(),
        checkpoint_source_index_path: SOURCE_INDEX_LOGICAL_PATH.into(),
        checkpoint_source_index_sha256: sha256(&source_bytes),
        economic_source_index_path: ECONOMIC_INDEX_LOGICAL_PATH.into(),
        economic_source_index_sha256: sha256(&economic_bytes),
        manifest_sha256: source.manifest_sha256,
        chunk_user_elf_path: CHUNK_ELF_LOGICAL_PATH.into(),
        chunk_user_elf_sha256: EXPECTED_CHUNK_ELF_SHA256.into(),
        chunk_program_path: CHUNK_PROGRAM_LOGICAL_PATH.into(),
        chunk_program_sha256: EXPECTED_CHUNK_PROGRAM_SHA256.into(),
        chunk_image_id_path: CHUNK_IMAGE_ID_LOGICAL_PATH.into(),
        chunk_image_id_file_sha256: EXPECTED_CHUNK_IMAGE_ID_FILE_SHA256.into(),
        chunk_image_id: EXPECTED_CHUNK_IMAGE_ID.into(),
        block_user_elf_path: BLOCK_ELF_LOGICAL_PATH.into(),
        block_user_elf_sha256: EXPECTED_BLOCK_ELF_SHA256.into(),
        block_program_path: BLOCK_PROGRAM_LOGICAL_PATH.into(),
        block_program_sha256: EXPECTED_BLOCK_PROGRAM_SHA256.into(),
        block_image_id_path: BLOCK_IMAGE_ID_LOGICAL_PATH.into(),
        block_image_id_file_sha256: EXPECTED_BLOCK_IMAGE_ID_FILE_SHA256.into(),
        block_image_id: EXPECTED_BLOCK_IMAGE_ID.into(),
        risc0_zkvm_version: RISC0_VERSION.into(),
        receipt_kind: RECEIPT_KIND.into(),
        previous_height: source.previous_height,
        target_height: source.target_height,
        confirmation_height: source.confirmation_height,
        segment_count: source.segment_count,
        chunk_job_count: chunk_jobs.len(),
        block_job_count: block_jobs.len(),
        executes_guests: false,
        generates_proofs: false,
        mines: false,
        chunk_jobs,
        block_jobs,
    };
    let mut bytes = serde_json::to_vec_pretty(&plan)
        .map_err(|error| format!("cannot encode economic job index: {error}"))?;
    bytes.push(b'\n');
    Ok((plan, bytes, sha256(&economic_bytes)))
}

fn decode_hash(value: &str) -> Result<[u8; 32], String> {
    if !canonical_hash(value) {
        return Err("invalid canonical hash".into());
    }
    let mut output = [0u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        output[index] = (digit(pair[0]).ok_or_else(|| "invalid hex".to_string())? << 4)
            | digit(pair[1]).ok_or_else(|| "invalid hex".to_string())?;
    }
    Ok(output)
}

/// Validate every source and pinned guest, then atomically publish the job index.
pub fn publish_plan(paths: &PlanPaths<'_>) -> Result<PlanSummary, String> {
    direct_directory(paths.output_directory)?;
    let (plan, bytes, economic_source_index_sha256) = build_plan(paths)?;
    let job_index_sha256 = sha256(&bytes);
    atomic_publish(&paths.output_directory.join(JOB_INDEX_NAME), &bytes)?;
    Ok(PlanSummary {
        chunk_job_count: plan.chunk_job_count,
        block_job_count: plan.block_job_count,
        economic_source_index_sha256,
        job_index_sha256,
    })
}

#[cfg(feature = "prove")]
fn source_logical_file(directory: &Path, logical: &str) -> Result<std::path::PathBuf, String> {
    let prefix = format!("{SOURCE_DIRECTORY_LOGICAL_PATH}/");
    let name = logical
        .strip_prefix(&prefix)
        .ok_or_else(|| format!("source path is outside the fixed directory: {logical}"))?;
    if name.is_empty() || name.contains('/') || name.contains('\\') || name == "." || name == ".." {
        return Err(format!(
            "source path is not one canonical filename: {logical}"
        ));
    }
    Ok(directory.join(name))
}

#[cfg(feature = "prove")]
fn verify_receipt(
    bytes: &[u8],
    image_id: [u8; 32],
    expected_journal: [u8; 32],
) -> Result<risc0_zkvm::Receipt, String> {
    use bincode::Options;
    use risc0_zkvm::{sha::Digest as Risc0Digest, InnerReceipt, Receipt};

    if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
        return Err("receipt byte length is outside the accepted bounds".into());
    }
    let receipt: Receipt = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_RECEIPT_BYTES as u64)
        .deserialize(bytes)
        .map_err(|error| format!("cannot decode RISC Zero receipt: {error}"))?;
    if bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&receipt)
        .map_err(|error| format!("cannot canonically encode RISC Zero receipt: {error}"))?
        != bytes
    {
        return Err("receipt is not canonically encoded".into());
    }
    if !matches!(receipt.inner, InnerReceipt::Succinct(_)) {
        return Err("receipt is not a succinct cryptographic receipt".into());
    }
    if receipt.journal.bytes.as_slice() != expected_journal {
        return Err("receipt journal differs from the exact planned commitment".into());
    }
    receipt
        .verify(Risc0Digest::from(image_id))
        .map_err(|error| format!("receipt verification failed: {error}"))?;
    Ok(receipt)
}

#[cfg(feature = "prove")]
fn remove_direct_file(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{} is not a direct regular file", path.display()));
    }
    fs::remove_file(path).map_err(|error| format!("cannot remove {}: {error}", path.display()))?;
    let parent = path
        .parent()
        .ok_or_else(|| "file has no parent".to_string())?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync {}: {error}", parent.display()))
}

#[cfg(feature = "prove")]
fn existing_verified_receipt(
    path: &Path,
    image_id: [u8; 32],
    journal: [u8; 32],
) -> Result<Option<Vec<u8>>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!("{} is not a direct receipt file", path.display()));
            }
            let bytes = read_direct(path, MAX_RECEIPT_BYTES)?;
            if verify_receipt(&bytes, image_id, journal).is_ok() {
                Ok(Some(bytes))
            } else {
                remove_direct_file(path)?;
                Ok(None)
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot inspect {}: {error}", path.display())),
    }
}

/// Prove missing chunk jobs, compose verified block jobs and publish one receipt index.
///
/// This function performs expensive cryptographic proving and must only be called through
/// the separate operator command after explicit authorization.
#[cfg(feature = "prove")]
pub fn prove_receipt_set(paths: &ProofPaths<'_>) -> Result<ProofSummary, String> {
    use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, Prover, ProverOpts};

    require_local_prover_environment("economic proving")?;
    direct_directory(paths.output_directory)?;
    let (plan, rebuilt, _) = build_plan(&paths.plan)?;
    let published = read_direct(paths.job_index, MAX_ECONOMIC_INDEX_BYTES)?;
    if published != rebuilt {
        return Err("published economic job index differs from its exact rebuilt plan".into());
    }
    let decoded: EconomicProofJobIndex = serde_json::from_slice(&published)
        .map_err(|error| format!("invalid published economic job index: {error}"))?;
    if decoded.chunk_job_count != plan.chunk_job_count
        || decoded.block_job_count != plan.block_job_count
    {
        return Err("published economic job counts differ from rebuilt plan".into());
    }
    let chunk_program = read_direct(paths.plan.chunk_program, MAX_ARTIFACT_BYTES)?;
    let block_program = read_direct(paths.plan.block_program, MAX_ARTIFACT_BYTES)?;
    if sha256(&chunk_program) != EXPECTED_CHUNK_PROGRAM_SHA256
        || sha256(&block_program) != EXPECTED_BLOCK_PROGRAM_SHA256
    {
        return Err("economic packaged guest program changed after plan rebuild".into());
    }
    let chunk_image_id = decode_hash(EXPECTED_CHUNK_IMAGE_ID)?;
    let block_image_id = decode_hash(EXPECTED_BLOCK_IMAGE_ID)?;
    let prover = default_prover();
    if prover.get_name() != "local" {
        return Err("selected economic prover is not the fixed local prover".into());
    }
    let options = ProverOpts::succinct().with_dev_mode(false);
    let final_index = paths.output_directory.join(RECEIPT_INDEX_NAME);
    match fs::symlink_metadata(&final_index) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("economic receipt-set index is not a direct regular file".into());
            }
            remove_direct_file(&final_index)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "cannot inspect economic receipt-set index: {error}"
            ))
        }
    }

    let chunk_started = std::time::Instant::now();
    let mut chunk_records = Vec::with_capacity(plan.chunk_job_count);
    for job in &plan.chunk_jobs {
        let journal = decode_hash(&job.expected_journal)?;
        let receipt_path = paths.output_directory.join(&job.receipt_file);
        let encoded = if let Some(bytes) =
            existing_verified_receipt(&receipt_path, chunk_image_id, journal)?
        {
            bytes
        } else {
            let private_path =
                source_logical_file(paths.plan.source_directory, &job.package_source_file)?;
            let private_bytes = Zeroizing::new(read_direct(
                &private_path,
                MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
            )?);
            let private =
                CheckpointSegmentPrivateInput::from_bytes(&private_bytes).map_err(|error| {
                    format!("cannot decode job {} package source: {error}", job.index)
                })?;
            let package = private
                .blocks()
                .get(job.block_index)
                .ok_or_else(|| format!("job {} package block is absent", job.index))?
                .package_bytes();
            if sha256(package) != job.package_sha256 {
                return Err(format!("job {} package changed after planning", job.index));
            }
            let transition = read_direct(
                &source_logical_file(paths.plan.source_directory, &job.transition_file)?,
                ECONOMIC_CHUNK_TRANSITION_BYTES,
            )?;
            let witness = Zeroizing::new(read_direct(
                &source_logical_file(paths.plan.source_directory, &job.witness_file)?,
                MAX_ECONOMIC_CHUNK_WITNESS_BYTES,
            )?);
            if sha256(&transition) != job.transition_sha256
                || sha256(&witness) != job.witness_sha256
            {
                return Err(format!("job {} source changed after planning", job.index));
            }
            let package_length = u32::try_from(package.len())
                .map_err(|_| format!("job {} package length exceeds u32", job.index))?;
            let witness_length = u32::try_from(witness.len())
                .map_err(|_| format!("job {} witness length exceeds u32", job.index))?;
            let mut builder = ExecutorEnv::builder();
            builder.write_slice(&transition);
            builder.write(&package_length).map_err(|error| {
                format!("cannot encode job {} package length: {error}", job.index)
            })?;
            builder.write_slice(package);
            builder.write(&witness_length).map_err(|error| {
                format!("cannot encode job {} witness length: {error}", job.index)
            })?;
            builder.write_slice(&witness);
            let environment = builder
                .build()
                .map_err(|error| format!("cannot build chunk job {}: {error}", job.index))?;
            let proof = prover
                .prove_with_opts(environment, &chunk_program, &options)
                .map_err(|error| format!("economic chunk proof {} failed: {error}", job.index))?;
            if !matches!(proof.receipt.inner, InnerReceipt::Succinct(_)) {
                return Err(format!("chunk proof {} is not succinct", job.index));
            }
            let bytes = bincode::serialize(&proof.receipt)
                .map_err(|error| format!("cannot encode chunk receipt {}: {error}", job.index))?;
            if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
                return Err(format!("chunk receipt {} exceeds its bound", job.index));
            }
            verify_receipt(&bytes, chunk_image_id, journal)?;
            atomic_publish(&receipt_path, &bytes)?;
            bytes
        };
        chunk_records.push(serde_json::json!({
            "index": job.index,
            "segment_index": job.segment_index,
            "block_index": job.block_index,
            "chunk_index": job.chunk_index,
            "block_height": job.block_height,
            "expected_journal": job.expected_journal,
            "receipt_file": job.receipt_file,
            "receipt_sha256": sha256(&encoded),
            "receipt_bytes": encoded.len()
        }));
    }

    let chunk_proving_wall_milliseconds = u64::try_from(chunk_started.elapsed().as_millis().max(1))
        .map_err(|_| "economic chunk proving time exceeds u64".to_owned())?;
    let chunk_peak_resident_kib = linux_peak_resident_kib()?;
    let block_started = std::time::Instant::now();
    let mut block_records = Vec::with_capacity(plan.block_job_count);
    for job in &plan.block_jobs {
        let journal = decode_hash(&job.expected_journal)?;
        let receipt_path = paths.output_directory.join(&job.receipt_file);
        let encoded = if let Some(bytes) =
            existing_verified_receipt(&receipt_path, block_image_id, journal)?
        {
            bytes
        } else {
            let transition = read_direct(
                &source_logical_file(paths.plan.source_directory, &job.transition_file)?,
                ECONOMIC_BLOCK_TRANSITION_BYTES,
            )?;
            if sha256(&transition) != job.transition_sha256 {
                return Err(format!("block job {} transition changed", job.index));
            }
            let first_chunk = plan
                .chunk_jobs
                .iter()
                .position(|chunk| {
                    chunk.segment_index == job.segment_index && chunk.block_index == job.block_index
                })
                .ok_or_else(|| format!("block job {} has no chunks", job.index))?;
            let chunk_end = first_chunk
                .checked_add(job.chunk_count)
                .ok_or_else(|| format!("block job {} chunk range overflow", job.index))?;
            let chunks = plan
                .chunk_jobs
                .get(first_chunk..chunk_end)
                .ok_or_else(|| format!("block job {} chunk range is absent", job.index))?;
            let mut transitions = Vec::with_capacity(chunks.len());
            let mut assumptions = Vec::with_capacity(chunks.len());
            for (expected_index, chunk) in chunks.iter().enumerate() {
                if chunk.segment_index != job.segment_index
                    || chunk.block_index != job.block_index
                    || chunk.chunk_index != expected_index
                {
                    return Err(format!("block job {} chunk order mismatch", job.index));
                }
                let bytes = read_direct(
                    &source_logical_file(paths.plan.source_directory, &chunk.transition_file)?,
                    ECONOMIC_CHUNK_TRANSITION_BYTES,
                )?;
                transitions.push(
                    EconomicChunkTransition::from_bytes(&bytes)
                        .map_err(|error| format!("invalid block job chunk: {error}"))?,
                );
                let receipt_bytes = read_direct(
                    &paths.output_directory.join(&chunk.receipt_file),
                    MAX_RECEIPT_BYTES,
                )?;
                assumptions.push(verify_receipt(
                    &receipt_bytes,
                    chunk_image_id,
                    decode_hash(&chunk.expected_journal)?,
                )?);
            }
            let chain = EconomicChunkChain::new(transitions)
                .map_err(|error| format!("invalid block job {} chain: {error}", job.index))?
                .to_bytes()
                .map_err(|error| format!("cannot encode block job {} chain: {error}", job.index))?;
            let chain_length = u32::try_from(chain.len())
                .map_err(|_| format!("block job {} chain length exceeds u32", job.index))?;
            let mut builder = ExecutorEnv::builder();
            builder.write_slice(&transition);
            builder.write(&chain_length).map_err(|error| {
                format!(
                    "cannot encode block job {} chain length: {error}",
                    job.index
                )
            })?;
            builder.write_slice(&chain);
            for receipt in assumptions {
                builder.add_assumption(receipt);
            }
            let environment = builder
                .build()
                .map_err(|error| format!("cannot build block job {}: {error}", job.index))?;
            let proof = prover
                .prove_with_opts(environment, &block_program, &options)
                .map_err(|error| format!("economic block proof {} failed: {error}", job.index))?;
            if !matches!(proof.receipt.inner, InnerReceipt::Succinct(_)) {
                return Err(format!("block proof {} is not succinct", job.index));
            }
            let bytes = bincode::serialize(&proof.receipt)
                .map_err(|error| format!("cannot encode block receipt {}: {error}", job.index))?;
            if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
                return Err(format!("block receipt {} exceeds its bound", job.index));
            }
            verify_receipt(&bytes, block_image_id, journal)?;
            atomic_publish(&receipt_path, &bytes)?;
            bytes
        };
        block_records.push(serde_json::json!({
            "index": job.index,
            "segment_index": job.segment_index,
            "block_index": job.block_index,
            "block_height": job.block_height,
            "expected_journal": job.expected_journal,
            "receipt_file": job.receipt_file,
            "receipt_sha256": sha256(&encoded),
            "receipt_bytes": encoded.len()
        }));
    }
    let block_proving_wall_milliseconds = u64::try_from(block_started.elapsed().as_millis().max(1))
        .map_err(|_| "economic block proving time exceeds u64".to_owned())?;
    let block_peak_resident_kib = linux_peak_resident_kib()?;
    let output = serde_json::json!({
        "schema": "usdom-economic-receipt-set-v1",
        "proof_job_index_path": JOB_INDEX_LOGICAL_PATH,
        "proof_job_index_sha256": sha256(&published),
        "chunk_image_id": EXPECTED_CHUNK_IMAGE_ID,
        "block_image_id": EXPECTED_BLOCK_IMAGE_ID,
        "risc0_zkvm_version": RISC0_VERSION,
        "receipt_kind": RECEIPT_KIND,
        "chunk_receipt_count": chunk_records.len(),
        "block_receipt_count": block_records.len(),
        "chunk_proving_wall_milliseconds": chunk_proving_wall_milliseconds,
        "chunk_peak_resident_kib": chunk_peak_resident_kib,
        "block_proving_wall_milliseconds": block_proving_wall_milliseconds,
        "block_peak_resident_kib": block_peak_resident_kib,
        "chunk_receipts_verified": true,
        "block_receipts_verified": true,
        "dev_mode": false,
        "generates_proofs": true,
        "mines": false,
        "chunk_receipts": chunk_records,
        "block_receipts": block_records
    });
    let mut output_bytes = serde_json::to_vec_pretty(&output)
        .map_err(|error| format!("cannot encode economic receipt index: {error}"))?;
    output_bytes.push(b'\n');
    let receipt_index_sha256 = sha256(&output_bytes);
    atomic_publish(&final_index, &output_bytes)?;
    Ok(ProofSummary {
        chunk_receipt_count: plan.chunk_job_count,
        block_receipt_count: plan.block_job_count,
        job_index_sha256: sha256(&published),
        receipt_index_sha256,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use dom_chain::{UsdomV4BlockPackage, UsdomV4ProofEnvelope};
    use dom_consensus::block::ProofOfWork;
    use dom_consensus::{
        Block, BlockHeader, CoinbaseKernel, CoinbaseTransaction, TransactionOutput,
    };
    use dom_core::{BlockHeight, Hash256, Timestamp};
    use dom_crypto::{pedersen::Commitment, BlindingFactor};
    use dom_pow::CompactTarget;
    use dom_usdom_checkpoint_program::{
        build_economic_block_proof_source, CheckpointSegmentBlockInput,
        CheckpointSegmentPrivateInput, EconomicState,
    };
    use primitive_types::U256;
    use tempfile::tempdir;

    use super::{parse_linux_peak_resident_kib, publish_plan, sha256, PlanPaths};

    #[test]
    fn peak_resident_parser_rejects_missing_units_zero_and_trailing_fields() {
        assert_eq!(
            parse_linux_peak_resident_kib("Name:\tprover\nVmHWM:\t2097152 kB\n")
                .expect("valid peak memory"),
            2_097_152
        );
        for invalid in [
            "Name:\tprover\n",
            "VmHWM:\t0 kB\n",
            "VmHWM:\t2097152 MB\n",
            "VmHWM:\t2097152 kB extra\n",
            "VmHWM:\tnot-a-number kB\n",
        ] {
            assert!(parse_linux_peak_resident_kib(invalid).is_err());
        }
    }

    fn commitment(seed: u8) -> Commitment {
        let mut scalar = [0u8; 32];
        scalar[31] = seed;
        Commitment::commit(0, &BlindingFactor::from_bytes(scalar).expect("test scalar"))
    }

    fn block(height: u64, seed: u8) -> Block {
        Block {
            header: BlockHeader {
                version: 4,
                height: BlockHeight(height),
                prev_hash: Hash256::from_bytes([seed; 32]),
                timestamp: Timestamp(1_700_000_000 + height),
                output_root: Hash256::from_bytes([2; 32]),
                kernel_root: Hash256::from_bytes([3; 32]),
                rangeproof_root: Hash256::from_bytes([4; 32]),
                total_kernel_offset: [0; 32],
                target: CompactTarget(0x207f_ffff),
                total_difficulty: U256::from(height),
                pow: ProofOfWork {
                    nonce: 0,
                    randomx_hash: Hash256::from_bytes([5; 32]),
                },
            },
            coinbase: CoinbaseTransaction {
                output: TransactionOutput {
                    commitment: commitment(seed),
                    proof: Vec::new(),
                },
                kernel: CoinbaseKernel {
                    features: 1,
                    explicit_value: 0,
                    excess: commitment(seed + 32),
                    excess_signature: [0; 65],
                },
                offset: [0; 32],
            },
            transactions: Vec::new(),
        }
    }

    fn artifact(crate_root: &Path, guest: &str, name: &str) -> PathBuf {
        crate_root
            .parent()
            .expect("crates directory")
            .join(guest)
            .join("elfs")
            .join(name)
    }

    #[test]
    fn deterministic_plan_reexecutes_chunks_and_rejects_tampering() {
        let temporary = tempdir().expect("temporary directory");
        let sources = temporary.path().join("sources");
        let jobs = temporary.path().join("jobs");
        fs::create_dir(&sources).expect("source directory");
        fs::create_dir(&jobs).expect("job directory");

        let mut state = EconomicState::default();
        let mut block_inputs = Vec::new();
        let mut economic_records = Vec::new();
        for (block_index, height) in [15u64, 16].into_iter().enumerate() {
            let candidate = block(height, 10 + block_index as u8);
            let package =
                UsdomV4BlockPackage::new(candidate.clone(), UsdomV4ProofEnvelope::empty())
                    .expect("package")
                    .to_bytes()
                    .expect("package bytes");
            let source = build_economic_block_proof_source(
                &state,
                &candidate,
                &package,
                dom_core::NETWORK_MAGIC_REGTEST,
                10,
            )
            .expect("economic source");
            let block_name =
                format!("checkpoint-segment-0000-economic-block-{block_index:04}-transition.bin");
            fs::write(sources.join(&block_name), source.transition_bytes())
                .expect("block transition");
            let mut chunks = Vec::new();
            for (chunk_index, chunk) in source.chunks().iter().enumerate() {
                let transition_name = format!(
                    "checkpoint-segment-0000-economic-block-{block_index:04}-chunk-{chunk_index:04}-transition.bin"
                );
                let witness_name = format!(
                    "checkpoint-segment-0000-economic-block-{block_index:04}-chunk-{chunk_index:04}-witness.bin"
                );
                fs::write(sources.join(&transition_name), chunk.transition_bytes())
                    .expect("chunk transition");
                fs::write(sources.join(&witness_name), chunk.witness_bytes())
                    .expect("chunk witness");
                chunks.push(serde_json::json!({
                    "index": chunk_index,
                    "transition_file": transition_name,
                    "transition_sha256": sha256(chunk.transition_bytes()),
                    "witness_file": witness_name,
                    "witness_sha256": sha256(chunk.witness_bytes())
                }));
            }
            economic_records.push(serde_json::json!({
                "segment_index": 0,
                "block_index": block_index,
                "block_transition_file": block_name,
                "block_transition_sha256": sha256(source.transition_bytes()),
                "chunk_count": chunks.len(),
                "chunks": chunks
            }));
            block_inputs.push(
                CheckpointSegmentBlockInput::new(
                    package,
                    vec![1],
                    source.transition_bytes().to_vec(),
                )
                .expect("block input"),
            );
            state.apply_block(&candidate, 10).expect("advance state");
        }
        let private = CheckpointSegmentPrivateInput::new(block_inputs)
            .expect("private input")
            .to_bytes()
            .expect("private bytes");
        let private_name = "checkpoint-segment-0000-private-input.bin";
        fs::write(sources.join(private_name), &private).expect("private input file");

        let source_index = serde_json::json!({
            "schema": "usdom-canonical-checkpoint-source-set-v1",
            "manifest_sha256": "11".repeat(32),
            "randomx_receipt_image_id": "22".repeat(32),
            "checkpoint_interval_blocks": 1,
            "checkpoint_confirmation_depth_blocks": 1,
            "previous_height": 14,
            "target_height": 15,
            "confirmation_height": 16,
            "segment_count": 1,
            "segments": [{
                "index": 0,
                "previous_height": 14,
                "next_height": 16,
                "block_count": 2,
                "transition_file": "checkpoint-segment-0000-transition.bin",
                "transition_sha256": "33".repeat(32),
                "private_input_file": private_name,
                "private_input_sha256": sha256(&private),
                "policy_input_file": "checkpoint-segment-0000-policy-input.bin",
                "policy_input_sha256": "44".repeat(32),
                "native_state_opening_file": "checkpoint-segment-0000-native-state-opening.bin",
                "native_state_opening_sha256": "55".repeat(32)
            }]
        });
        let mut source_index_bytes =
            serde_json::to_vec_pretty(&source_index).expect("source index");
        source_index_bytes.push(b'\n');
        let source_index_path = sources.join("checkpoint-source-set-index.json");
        fs::write(&source_index_path, &source_index_bytes).expect("source index file");
        let economic_index = serde_json::json!({
            "schema": "usdom-economic-proof-source-set-v1",
            "checkpoint_source_index_path": "evidence/checkpoint-source-set/checkpoint-source-set-index.json",
            "checkpoint_source_index_sha256": sha256(&source_index_bytes),
            "block_count": economic_records.len(),
            "blocks": economic_records
        });
        let mut economic_index_bytes =
            serde_json::to_vec_pretty(&economic_index).expect("economic index");
        economic_index_bytes.push(b'\n');
        let economic_index_path = sources.join("checkpoint-economic-source-set-index.json");
        fs::write(&economic_index_path, economic_index_bytes).expect("economic index file");

        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let paths = PlanPaths {
            checkpoint_source_index: &source_index_path,
            economic_source_index: &economic_index_path,
            source_directory: &sources,
            chunk_elf: &artifact(
                crate_root,
                "dom-usdom-economic-chunk-risc0-guest",
                "usdom-economic-chunk.elf",
            ),
            chunk_program: &artifact(
                crate_root,
                "dom-usdom-economic-chunk-risc0-guest",
                "usdom-economic-chunk.bin",
            ),
            chunk_image_id: &artifact(
                crate_root,
                "dom-usdom-economic-chunk-risc0-guest",
                "usdom-economic-chunk.iid",
            ),
            block_elf: &artifact(
                crate_root,
                "dom-usdom-economic-block-risc0-guest",
                "usdom-economic-block.elf",
            ),
            block_program: &artifact(
                crate_root,
                "dom-usdom-economic-block-risc0-guest",
                "usdom-economic-block.bin",
            ),
            block_image_id: &artifact(
                crate_root,
                "dom-usdom-economic-block-risc0-guest",
                "usdom-economic-block.iid",
            ),
            output_directory: &jobs,
        };
        let first = publish_plan(&paths).expect("first plan");
        assert_eq!(first.block_job_count, 2);
        assert_eq!(first.chunk_job_count, 4);
        let first_bytes =
            fs::read(jobs.join("economic-proof-job-index.json")).expect("first job index");
        let second = publish_plan(&paths).expect("second plan");
        assert_eq!(first.job_index_sha256, second.job_index_sha256);
        assert_eq!(
            first_bytes,
            fs::read(jobs.join("economic-proof-job-index.json")).expect("second job index")
        );

        let witness =
            sources.join("checkpoint-segment-0000-economic-block-0001-chunk-0001-witness.bin");
        let mut corrupted = fs::read(&witness).expect("witness bytes");
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        fs::write(witness, corrupted).expect("corrupt witness");
        assert!(publish_plan(&paths).is_err());
    }
}
