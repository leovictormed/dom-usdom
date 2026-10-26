//! Authenticated planning and proof publication for per-block RandomX receipts.

#![deny(unsafe_code)]

#[cfg(feature = "verify")]
mod aggregate;

#[cfg(feature = "prove")]
pub use aggregate::{prove_aggregate_set, AggregateProofSummary};
#[cfg(feature = "verify")]
pub use aggregate::{
    publish_aggregate_plan, AggregatePlanPaths, AggregatePlanSummary, AggregateProofPaths,
};

use std::fs;
#[cfg(feature = "prove")]
use std::fs::File;
use std::path::Path;

use dom_usdom_checkpoint_statement::{
    CheckpointRandomXStatement, CHECKPOINT_RANDOMX_STATEMENT_BYTES,
};
use dom_wallet_crypto::{read_captured_bytes, save_private_bytes};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const STATEMENT_INDEX_SCHEMA: &str = "usdom-authenticated-randomx-statement-set-v1";
const JOB_INDEX_SCHEMA: &str = "usdom-randomx-proof-job-set-v1";
#[cfg(feature = "prove")]
const RECEIPT_INDEX_SCHEMA: &str = "usdom-randomx-receipt-set-v1";
const SOURCE_INDEX_LOGICAL_PATH: &str =
    "evidence/checkpoint-source-set/checkpoint-source-set-index.json";
const STATEMENT_INDEX_LOGICAL_PATH: &str =
    "evidence/randomx-statement-set/randomx-statement-set-index.json";
#[cfg(feature = "prove")]
const JOB_INDEX_LOGICAL_PATH: &str = "evidence/randomx-proof-jobs/randomx-proof-job-index.json";
const ELF_LOGICAL_PATH: &str = "../../crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.elf";
const PROGRAM_LOGICAL_PATH: &str =
    "../../crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.bin";
const IMAGE_ID_LOGICAL_PATH: &str =
    "../../crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.iid";
const JOB_INDEX_NAME: &str = "randomx-proof-job-index.json";
#[cfg(feature = "prove")]
const RECEIPT_INDEX_NAME: &str = "randomx-receipt-set-index.json";
const RISC0_VERSION: &str = "3.0.6";
const RECEIPT_KIND: &str = "succinct";
const EXPECTED_ELF_SHA256: &str =
    "1a8e491304763477094da84ff0701ea18d935600a3b3a79eb1c1250facd6903f";
const EXPECTED_PROGRAM_SHA256: &str =
    "0601bf022575b060edaeb0b32414b2f53e72f39d2284028069099414653591dd";
const EXPECTED_IMAGE_ID: &str = "8efa49d4fe0f616840013adb1d3029ef71642099cb336c577a2691f7eea1dc24";
const EXPECTED_IMAGE_ID_FILE_SHA256: &str =
    "57ec90732f703bd58efd1682ab608b1a1efc3c66dce65480384cf72db4891245";
const MAX_INDEX_BYTES: usize = 2 * 1024 * 1024;
const MAX_ELF_BYTES: usize = 512 * 1024 * 1024;
const MAX_PROGRAM_BYTES: usize = 512 * 1024 * 1024;
#[cfg(feature = "verify")]
const MAX_RECEIPT_BYTES: usize = 256 * 1024 * 1024;
const MAX_STATEMENTS: usize = 720;

#[cfg(feature = "prove")]
pub(crate) fn require_local_prover_environment(context: &str) -> Result<(), String> {
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

/// Fixed filesystem inputs and output for deterministic job planning.
pub struct PlanPaths<'a> {
    /// Final authenticated statement-set index.
    pub statement_index: &'a Path,
    /// Directory containing numbered statement files.
    pub statement_directory: &'a Path,
    /// Pinned RISC Zero ELF.
    pub elf: &'a Path,
    /// Pinned packaged program binary.
    pub program: &'a Path,
    /// Pinned textual ImageID.
    pub image_id: &'a Path,
    /// Direct output directory for the final job index.
    pub output_directory: &'a Path,
}

impl PlanPaths<'static> {
    /// Production paths relative to the USDOM reserve laboratory root.
    pub fn production() -> Self {
        Self {
            statement_index: Path::new(
                "evidence/randomx-statement-set/randomx-statement-set-index.json",
            ),
            statement_directory: Path::new("evidence/randomx-statement-set"),
            elf: Path::new(ELF_LOGICAL_PATH),
            program: Path::new(PROGRAM_LOGICAL_PATH),
            image_id: Path::new(IMAGE_ID_LOGICAL_PATH),
            output_directory: Path::new("evidence/randomx-proof-jobs"),
        }
    }
}

/// Fixed inputs and output for the explicitly authorized proving step.
pub struct ProofPaths<'a> {
    /// Inputs used to deterministically rebuild the job plan.
    pub plan: PlanPaths<'a>,
    /// Published job index that must equal the rebuilt plan byte for byte.
    pub job_index: &'a Path,
    /// Direct output directory for resumable receipts and their final index.
    pub output_directory: &'a Path,
}

impl ProofPaths<'static> {
    /// Production paths relative to the USDOM reserve laboratory root.
    pub fn production() -> Self {
        Self {
            plan: PlanPaths::production(),
            job_index: Path::new("evidence/randomx-proof-jobs/randomx-proof-job-index.json"),
            output_directory: Path::new("evidence/randomx-receipt-set"),
        }
    }
}

/// Observable result of deterministic, non-proving job planning.
pub struct PlanSummary {
    /// Number of one-statement proof jobs.
    pub job_count: usize,
    /// SHA-256 of the consumed statement-set index.
    pub statement_index_sha256: String,
    /// SHA-256 of the published job index.
    pub job_index_sha256: String,
}

/// Observable result after every receipt has been proved and verified.
#[cfg(feature = "prove")]
pub struct ProofSummary {
    /// Number of verified succinct receipts.
    pub receipt_count: usize,
    /// SHA-256 of the exact consumed proof-job index.
    pub job_index_sha256: String,
    /// SHA-256 of the final receipt-set index.
    pub receipt_index_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatementSetIndex {
    schema: String,
    source_index_path: String,
    source_index_sha256: String,
    manifest_sha256: String,
    randomx_receipt_image_id: String,
    previous_height: u64,
    target_height: u64,
    confirmation_height: u64,
    segment_count: usize,
    statement_count: usize,
    portable_segments_executed: bool,
    randomx_relations_executed: bool,
    generates_proofs: bool,
    mines: bool,
    statements: Vec<StatementRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatementRecord {
    index: usize,
    segment_index: usize,
    block_index: usize,
    block_height: u64,
    block_hash: String,
    transition_commitment: String,
    statement_file: String,
    statement_sha256: String,
    statement_commitment: String,
    native_reference_commitment: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProofJobIndex {
    schema: String,
    statement_index_path: String,
    statement_index_sha256: String,
    manifest_sha256: String,
    randomx_receipt_image_id: String,
    randomx_user_elf_path: String,
    randomx_user_elf_sha256: String,
    randomx_program_path: String,
    randomx_program_sha256: String,
    randomx_image_id_path: String,
    randomx_image_id_file_sha256: String,
    risc0_zkvm_version: String,
    receipt_kind: String,
    previous_height: u64,
    target_height: u64,
    confirmation_height: u64,
    segment_count: usize,
    job_count: usize,
    executes_guest: bool,
    generates_proofs: bool,
    mines: bool,
    jobs: Vec<ProofJob>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProofJob {
    index: usize,
    segment_index: usize,
    block_index: usize,
    block_height: u64,
    block_hash: String,
    transition_commitment: String,
    statement_file: String,
    statement_sha256: String,
    statement_commitment: String,
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

#[cfg(any(feature = "verify", test))]
fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if !canonical_sha256(value) {
        return Err("value is not one canonical lowercase 32-byte hex string".into());
    }
    let mut output = [0u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(|| "invalid hex digit".to_string())?;
        let low = hex_nibble(pair[1]).ok_or_else(|| "invalid hex digit".to_string())?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

#[cfg(any(feature = "verify", test))]
fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
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

fn canonical_nonzero_hash(value: &str) -> bool {
    canonical_sha256(value) && value != "0".repeat(64)
}

fn statement_name(index: usize) -> String {
    format!("randomx-statement-{index:04}.bin")
}

fn statement_logical_path(index: usize) -> String {
    format!("evidence/randomx-statement-set/{}", statement_name(index))
}

fn receipt_name(index: usize) -> String {
    format!("randomx-receipt-{index:04}.bin")
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

fn atomic_publish(path: &Path, value: &[u8]) -> Result<(), String> {
    save_private_bytes(path, value)
        .map_err(|error| format!("cannot publish {}: {error}", path.display()))
}

fn validate_artifact(path: &Path, maximum: usize, expected: &str) -> Result<Vec<u8>, String> {
    let bytes = read_direct_regular_file(path, maximum)?;
    if sha256(&bytes) != expected {
        return Err(format!("pinned artifact hash mismatch: {}", path.display()));
    }
    Ok(bytes)
}

fn build_plan(paths: &PlanPaths<'_>) -> Result<(ProofJobIndex, Vec<u8>, String), String> {
    ensure_direct_directory(paths.statement_directory)?;
    let index_bytes = read_direct_regular_file(paths.statement_index, MAX_INDEX_BYTES)?;
    let source: StatementSetIndex = serde_json::from_slice(&index_bytes)
        .map_err(|error| format!("invalid statement-set index: {error}"))?;
    if source.schema != STATEMENT_INDEX_SCHEMA
        || source.source_index_path != SOURCE_INDEX_LOGICAL_PATH
        || !canonical_nonzero_hash(&source.source_index_sha256)
        || !canonical_nonzero_hash(&source.manifest_sha256)
        || source.randomx_receipt_image_id != EXPECTED_IMAGE_ID
        || source.previous_height >= source.target_height
        || source.target_height >= source.confirmation_height
        || source.segment_count == 0
        || source.segment_count > 32
        || source.statement_count == 0
        || source.statement_count > MAX_STATEMENTS
        || source.statement_count != source.statements.len()
        || source.statement_count
            != usize::try_from(source.confirmation_height - source.previous_height)
                .map_err(|_| "statement span does not fit memory bounds".to_string())?
        || !source.portable_segments_executed
        || !source.randomx_relations_executed
        || source.generates_proofs
        || source.mines
    {
        return Err("statement-set index identity, bounds or execution claims are invalid".into());
    }

    validate_artifact(paths.elf, MAX_ELF_BYTES, EXPECTED_ELF_SHA256)?;
    validate_artifact(paths.program, MAX_PROGRAM_BYTES, EXPECTED_PROGRAM_SHA256)?;
    let image_id_bytes = validate_artifact(paths.image_id, 65, EXPECTED_IMAGE_ID_FILE_SHA256)?;
    let expected_image_id_file = format!("{EXPECTED_IMAGE_ID}\n");
    if image_id_bytes.as_slice() != expected_image_id_file.as_bytes() {
        return Err("pinned ImageID file is not the exact canonical ImageID".into());
    }

    let mut jobs = Vec::with_capacity(source.statement_count);
    let mut current_segment = 0usize;
    let mut expected_block_index = 0usize;
    let mut current_transition: Option<&str> = None;
    let mut network_magic: Option<u32> = None;
    let mut chain_id: Option<[u8; 32]> = None;
    for (expected_index, record) in source.statements.iter().enumerate() {
        let expected_offset = u64::try_from(expected_index)
            .map_err(|_| "statement index does not fit the height domain".to_string())?
            .checked_add(1)
            .ok_or_else(|| "statement height offset overflow".to_string())?;
        let expected_height = source
            .previous_height
            .checked_add(expected_offset)
            .ok_or_else(|| "statement height overflow".to_string())?;
        if record.index != expected_index
            || record.block_height != expected_height
            || record.statement_file != statement_name(expected_index)
            || !canonical_nonzero_hash(&record.block_hash)
            || !canonical_nonzero_hash(&record.transition_commitment)
            || !canonical_nonzero_hash(&record.statement_sha256)
            || !canonical_nonzero_hash(&record.statement_commitment)
            || !canonical_nonzero_hash(&record.native_reference_commitment)
            || record.segment_index >= source.segment_count
            || record.block_index >= 32
        {
            return Err(format!(
                "invalid statement record at index {expected_index}"
            ));
        }
        if record.segment_index == current_segment {
            if record.block_index != expected_block_index {
                return Err(format!(
                    "nonconsecutive block index at job {expected_index}"
                ));
            }
            if let Some(commitment) = current_transition {
                if record.transition_commitment != commitment {
                    return Err(format!(
                        "transition commitment changed within segment {current_segment}"
                    ));
                }
            } else {
                current_transition = Some(&record.transition_commitment);
            }
        } else if record.segment_index == current_segment + 1 && record.block_index == 0 {
            current_segment += 1;
            expected_block_index = 0;
            current_transition = Some(&record.transition_commitment);
        } else {
            return Err(format!(
                "nonconsecutive segment order at job {expected_index}"
            ));
        }

        let statement_path = paths.statement_directory.join(&record.statement_file);
        let statement_bytes =
            read_direct_regular_file(&statement_path, CHECKPOINT_RANDOMX_STATEMENT_BYTES)?;
        if statement_bytes.len() != CHECKPOINT_RANDOMX_STATEMENT_BYTES
            || sha256(&statement_bytes) != record.statement_sha256
        {
            return Err(format!(
                "statement bytes mismatch at index {expected_index}"
            ));
        }
        let statement = CheckpointRandomXStatement::from_bytes(&statement_bytes)
            .map_err(|error| format!("invalid statement at index {expected_index}: {error}"))?;
        let commitment = statement.commitment().map_err(|error| {
            format!("cannot commit statement at index {expected_index}: {error}")
        })?;
        let commitment_hex = hex(&commitment);
        if statement.block_height != record.block_height
            || commitment_hex != record.statement_commitment
            || commitment_hex != record.native_reference_commitment
        {
            return Err(format!(
                "statement semantics mismatch at index {expected_index}"
            ));
        }
        if let Some(expected) = network_magic {
            if statement.network_magic != expected {
                return Err("statement set mixes network identities".into());
            }
        } else {
            network_magic = Some(statement.network_magic);
        }
        if let Some(expected) = chain_id {
            if statement.chain_id != expected {
                return Err("statement set mixes chain identities".into());
            }
        } else {
            chain_id = Some(statement.chain_id);
        }

        jobs.push(ProofJob {
            index: expected_index,
            segment_index: record.segment_index,
            block_index: record.block_index,
            block_height: record.block_height,
            block_hash: record.block_hash.clone(),
            transition_commitment: record.transition_commitment.clone(),
            statement_file: statement_logical_path(expected_index),
            statement_sha256: record.statement_sha256.clone(),
            statement_commitment: commitment_hex.clone(),
            expected_journal: commitment_hex,
            receipt_file: receipt_name(expected_index),
        });
        expected_block_index += 1;
    }
    if current_segment + 1 != source.segment_count {
        return Err("statement records do not cover every declared segment".into());
    }
    let target_offset = usize::try_from(source.target_height - source.previous_height - 1)
        .map_err(|_| "checkpoint target offset does not fit memory bounds".to_string())?;
    let target_record = source
        .statements
        .get(target_offset)
        .ok_or_else(|| "checkpoint target is absent from statement set".to_string())?;
    let confirmation_record = source
        .statements
        .get(
            target_offset
                .checked_add(1)
                .ok_or_else(|| "checkpoint confirmation offset overflow".to_string())?,
        )
        .ok_or_else(|| "checkpoint confirmation phase is absent".to_string())?;
    let first_confirmation_height = source
        .target_height
        .checked_add(1)
        .ok_or_else(|| "checkpoint confirmation height overflow".to_string())?;
    let first_confirmation_segment = target_record
        .segment_index
        .checked_add(1)
        .ok_or_else(|| "checkpoint confirmation segment overflow".to_string())?;
    if target_record.block_height != source.target_height
        || confirmation_record.block_height != first_confirmation_height
        || confirmation_record.segment_index != first_confirmation_segment
        || confirmation_record.block_index != 0
    {
        return Err("checkpoint target is not an exact segment boundary".into());
    }

    let plan = ProofJobIndex {
        schema: JOB_INDEX_SCHEMA.into(),
        statement_index_path: STATEMENT_INDEX_LOGICAL_PATH.into(),
        statement_index_sha256: sha256(&index_bytes),
        manifest_sha256: source.manifest_sha256,
        randomx_receipt_image_id: source.randomx_receipt_image_id,
        randomx_user_elf_path: ELF_LOGICAL_PATH.into(),
        randomx_user_elf_sha256: EXPECTED_ELF_SHA256.into(),
        randomx_program_path: PROGRAM_LOGICAL_PATH.into(),
        randomx_program_sha256: EXPECTED_PROGRAM_SHA256.into(),
        randomx_image_id_path: IMAGE_ID_LOGICAL_PATH.into(),
        randomx_image_id_file_sha256: sha256(&image_id_bytes),
        risc0_zkvm_version: RISC0_VERSION.into(),
        receipt_kind: RECEIPT_KIND.into(),
        previous_height: source.previous_height,
        target_height: source.target_height,
        confirmation_height: source.confirmation_height,
        segment_count: source.segment_count,
        job_count: jobs.len(),
        executes_guest: false,
        generates_proofs: false,
        mines: false,
        jobs,
    };
    let mut bytes = serde_json::to_vec_pretty(&plan)
        .map_err(|error| format!("cannot encode proof-job index: {error}"))?;
    bytes.push(b'\n');
    Ok((plan, bytes, sha256(&index_bytes)))
}

/// Validate the full statement set and atomically publish a deterministic job index.
pub fn publish_plan(paths: &PlanPaths<'_>) -> Result<PlanSummary, String> {
    ensure_direct_directory(paths.output_directory)?;
    let (plan, bytes, statement_index_sha256) = build_plan(paths)?;
    let job_index_sha256 = sha256(&bytes);
    atomic_publish(&paths.output_directory.join(JOB_INDEX_NAME), &bytes)?;
    Ok(PlanSummary {
        job_count: plan.job_count,
        statement_index_sha256,
        job_index_sha256,
    })
}

#[cfg(feature = "prove")]
fn verify_receipt(
    bytes: &[u8],
    image_id: [u8; 32],
    expected_journal: [u8; 32],
) -> Result<(), String> {
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
        return Err("receipt journal differs from the exact statement commitment".into());
    }
    receipt
        .verify(Risc0Digest::from(image_id))
        .map_err(|error| format!("receipt verification failed: {error}"))?;
    Ok(())
}

#[cfg(feature = "prove")]
fn remove_invalid_receipt(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect existing {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "existing {} is not a direct regular file",
            path.display()
        ));
    }
    fs::remove_file(path)
        .map_err(|error| format!("cannot remove invalid {}: {error}", path.display()))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync {}: {error}", parent.display()))
}

/// Prove missing jobs locally, verify every receipt and publish the final receipt index.
#[cfg(feature = "prove")]
pub fn prove_receipt_set(paths: &ProofPaths<'_>) -> Result<ProofSummary, String> {
    use risc0_zkvm::{
        default_prover, sha::Digest as Risc0Digest, ExecutorEnv, InnerReceipt, Prover, ProverOpts,
    };

    require_local_prover_environment("RandomX proving")?;
    ensure_direct_directory(paths.output_directory)?;
    let (plan, rebuilt_plan_bytes, _) = build_plan(&paths.plan)?;
    let published_plan_bytes = read_direct_regular_file(paths.job_index, MAX_INDEX_BYTES)?;
    if published_plan_bytes != rebuilt_plan_bytes {
        return Err("published proof-job index differs from the exact rebuilt plan".into());
    }
    let job_index_sha256 = sha256(&published_plan_bytes);
    // RISC Zero 3.x proves the packaged ProgramBinary (user ELF plus the
    // pinned zkVM kernel), not the raw user ELF.  build_plan validates both
    // artifacts; reload the packaged binary here so the exact bytes committed
    // by EXPECTED_PROGRAM_SHA256 are the bytes handed to the prover.
    let program = validate_artifact(
        paths.plan.program,
        MAX_PROGRAM_BYTES,
        EXPECTED_PROGRAM_SHA256,
    )?;
    let image_id = decode_hex_32(&plan.randomx_receipt_image_id)?;
    let prover = default_prover();
    if prover.get_name() != "local" {
        return Err("selected RISC Zero prover is not the fixed local prover".into());
    }
    let options = ProverOpts::succinct().with_dev_mode(false);
    let final_index = paths.output_directory.join(RECEIPT_INDEX_NAME);
    match fs::symlink_metadata(&final_index) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("receipt-set index path is not a direct regular file".into());
            }
            // The index is the completion marker. Its removal must reach the
            // parent directory before any receipt can be reused or replaced;
            // otherwise a crash may resurrect a stale complete generation.
            remove_invalid_receipt(&final_index)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "cannot inspect receipt-set index {}: {error}",
                final_index.display()
            ));
        }
    }
    let mut receipt_records = Vec::with_capacity(plan.job_count);
    for job in &plan.jobs {
        let statement_path = paths
            .plan
            .statement_directory
            .join(statement_name(job.index));
        let statement =
            read_direct_regular_file(&statement_path, CHECKPOINT_RANDOMX_STATEMENT_BYTES)?;
        if sha256(&statement) != job.statement_sha256 {
            return Err(format!("statement changed before proof job {}", job.index));
        }
        let expected_journal = decode_hex_32(&job.expected_journal)?;
        let receipt_path = paths.output_directory.join(&job.receipt_file);
        let receipt_bytes = if receipt_path.exists() {
            let existing = read_direct_regular_file(&receipt_path, MAX_RECEIPT_BYTES)?;
            if verify_receipt(&existing, image_id, expected_journal).is_ok() {
                existing
            } else {
                remove_invalid_receipt(&receipt_path)?;
                Vec::new()
            }
        } else {
            Vec::new()
        };
        let receipt_bytes = if receipt_bytes.is_empty() {
            let mut builder = ExecutorEnv::builder();
            builder.write_slice(&statement);
            let environment = builder
                .build()
                .map_err(|error| format!("cannot build job {} environment: {error}", job.index))?;
            let proof = prover
                .prove_with_opts(environment, &program, &options)
                .map_err(|error| format!("proof job {} failed: {error}", job.index))?;
            if !matches!(proof.receipt.inner, InnerReceipt::Succinct(_)) {
                return Err(format!(
                    "proof job {} did not return a succinct receipt",
                    job.index
                ));
            }
            if proof.receipt.journal.bytes.as_slice() != expected_journal {
                return Err(format!(
                    "proof job {} returned the wrong journal",
                    job.index
                ));
            }
            proof
                .receipt
                .verify(Risc0Digest::from(image_id))
                .map_err(|error| format!("proof job {} verification failed: {error}", job.index))?;
            let encoded = bincode::serialize(&proof.receipt).map_err(|error| {
                format!("cannot encode proof job {} receipt: {error}", job.index)
            })?;
            if encoded.is_empty() || encoded.len() > MAX_RECEIPT_BYTES {
                return Err(format!("proof job {} receipt exceeds its bound", job.index));
            }
            verify_receipt(&encoded, image_id, expected_journal)?;
            atomic_publish(&receipt_path, &encoded)?;
            encoded
        } else {
            receipt_bytes
        };
        receipt_records.push(serde_json::json!({
            "index": job.index,
            "segment_index": job.segment_index,
            "block_index": job.block_index,
            "block_height": job.block_height,
            "statement_sha256": job.statement_sha256,
            "expected_journal": job.expected_journal,
            "receipt_file": job.receipt_file,
            "receipt_sha256": sha256(&receipt_bytes),
            "receipt_bytes": receipt_bytes.len()
        }));
    }

    let receipt_index = serde_json::json!({
        "schema": RECEIPT_INDEX_SCHEMA,
        "proof_job_index_path": JOB_INDEX_LOGICAL_PATH,
        "proof_job_index_sha256": job_index_sha256,
        "manifest_sha256": plan.manifest_sha256,
        "randomx_receipt_image_id": plan.randomx_receipt_image_id,
        "randomx_user_elf_sha256": plan.randomx_user_elf_sha256,
        "risc0_zkvm_version": RISC0_VERSION,
        "receipt_kind": RECEIPT_KIND,
        "previous_height": plan.previous_height,
        "target_height": plan.target_height,
        "confirmation_height": plan.confirmation_height,
        "segment_count": plan.segment_count,
        "receipt_count": receipt_records.len(),
        "randomx_relations_executed": true,
        "receipts_verified": true,
        "dev_mode": false,
        "generates_proofs": true,
        "mines": false,
        "receipts": receipt_records
    });
    let mut receipt_index_bytes = serde_json::to_vec_pretty(&receipt_index)
        .map_err(|error| format!("cannot encode receipt-set index: {error}"))?;
    receipt_index_bytes.push(b'\n');
    let receipt_index_sha256 = sha256(&receipt_index_bytes);
    atomic_publish(&final_index, &receipt_index_bytes)?;
    Ok(ProofSummary {
        receipt_count: plan.job_count,
        job_index_sha256: sha256(&published_plan_bytes),
        receipt_index_sha256,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use dom_usdom_checkpoint_statement::{
        checkpoint_compact_target, checkpoint_randomx_seed_height, CheckpointRandomXStatement,
        CHECKPOINT_RANDOMX_BLOCK_VERSION, CHECKPOINT_RANDOMX_PREIMAGE_BYTES,
        CHECKPOINT_RANDOMX_PREIMAGE_HEIGHT_OFFSET, CHECKPOINT_RANDOMX_PREIMAGE_TARGET_OFFSET,
    };
    use tempfile::tempdir;

    use super::{
        canonical_nonzero_hash, decode_hex_32, publish_plan, receipt_name, sha256, statement_name,
        PlanPaths,
    };

    #[test]
    fn identities_and_names_are_canonical() {
        assert_eq!(statement_name(7), "randomx-statement-0007.bin");
        assert_eq!(receipt_name(7), "randomx-receipt-0007.bin");
        assert!(canonical_nonzero_hash(&"ab".repeat(32)));
        assert!(!canonical_nonzero_hash(&"00".repeat(32)));
        assert_eq!(decode_hex_32(&"01".repeat(32)).unwrap(), [1u8; 32]);
        assert!(decode_hex_32(&"AB".repeat(32)).is_err());
    }

    fn statement(height: u64, discriminator: u8) -> Vec<u8> {
        let compact = 0x1e7f_ffffu32;
        let mut preimage = [0u8; CHECKPOINT_RANDOMX_PREIMAGE_BYTES];
        preimage[..4].copy_from_slice(&CHECKPOINT_RANDOMX_BLOCK_VERSION.to_le_bytes());
        preimage[CHECKPOINT_RANDOMX_PREIMAGE_HEIGHT_OFFSET
            ..CHECKPOINT_RANDOMX_PREIMAGE_HEIGHT_OFFSET + 8]
            .copy_from_slice(&height.to_le_bytes());
        preimage[CHECKPOINT_RANDOMX_PREIMAGE_TARGET_OFFSET
            ..CHECKPOINT_RANDOMX_PREIMAGE_TARGET_OFFSET + 4]
            .copy_from_slice(&compact.to_le_bytes());
        preimage[CHECKPOINT_RANDOMX_PREIMAGE_BYTES - 1] = discriminator;
        let mut randomx_hash = [0u8; 32];
        randomx_hash[31] = discriminator.max(1);
        CheckpointRandomXStatement {
            network_magic: 0xA1B2_C3D4,
            chain_id: [0x11; 32],
            block_height: height,
            seed_height: checkpoint_randomx_seed_height(height),
            seed_hash: [0x12; 32],
            pow_preimage: preimage,
            randomx_hash,
            target: checkpoint_compact_target(compact).unwrap(),
        }
        .to_bytes()
        .unwrap()
        .to_vec()
    }

    fn artifact(crate_root: &Path, name: &str) -> std::path::PathBuf {
        crate_root
            .parent()
            .unwrap()
            .join("dom-usdom-randomx-risc0-guest/elfs")
            .join(name)
    }

    #[test]
    fn deterministic_plan_binds_every_statement_and_pinned_artifact() {
        let temporary = tempdir().unwrap();
        let statement_directory = temporary.path().join("statements");
        let output_directory = temporary.path().join("jobs");
        fs::create_dir(&statement_directory).unwrap();
        fs::create_dir(&output_directory).unwrap();
        let statements = [statement(2_048, 1), statement(2_049, 2)];
        let mut records = Vec::new();
        for (index, bytes) in statements.iter().enumerate() {
            let parsed = CheckpointRandomXStatement::from_bytes(bytes).unwrap();
            let commitment = super::hex(&parsed.commitment().unwrap());
            fs::write(statement_directory.join(statement_name(index)), bytes).unwrap();
            records.push(serde_json::json!({
                "index": index,
                "segment_index": index,
                "block_index": 0,
                "block_height": 2_048 + index as u64,
                "block_hash": if index == 0 { "11".repeat(32) } else { "22".repeat(32) },
                "transition_commitment": if index == 0 { "33".repeat(32) } else { "44".repeat(32) },
                "statement_file": statement_name(index),
                "statement_sha256": sha256(bytes),
                "statement_commitment": commitment.clone(),
                "native_reference_commitment": commitment
            }));
        }
        let index = serde_json::json!({
            "schema": "usdom-authenticated-randomx-statement-set-v1",
            "source_index_path": "evidence/checkpoint-source-set/checkpoint-source-set-index.json",
            "source_index_sha256": "55".repeat(32),
            "manifest_sha256": "66".repeat(32),
            "randomx_receipt_image_id": "8efa49d4fe0f616840013adb1d3029ef71642099cb336c577a2691f7eea1dc24",
            "previous_height": 2_047,
            "target_height": 2_048,
            "confirmation_height": 2_049,
            "segment_count": 2,
            "statement_count": 2,
            "portable_segments_executed": true,
            "randomx_relations_executed": true,
            "generates_proofs": false,
            "mines": false,
            "statements": records
        });
        let index_path = statement_directory.join("randomx-statement-set-index.json");
        fs::write(&index_path, serde_json::to_vec_pretty(&index).unwrap()).unwrap();
        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let paths = PlanPaths {
            statement_index: &index_path,
            statement_directory: &statement_directory,
            elf: &artifact(crate_root, "usdom-randomx.elf"),
            program: &artifact(crate_root, "usdom-randomx.bin"),
            image_id: &artifact(crate_root, "usdom-randomx.iid"),
            output_directory: &output_directory,
        };
        let first = publish_plan(&paths).unwrap();
        assert_eq!(first.job_count, 2);
        let first_bytes = fs::read(output_directory.join("randomx-proof-job-index.json")).unwrap();
        let second = publish_plan(&paths).unwrap();
        let second_bytes = fs::read(output_directory.join("randomx-proof-job-index.json")).unwrap();
        assert_eq!(first.job_index_sha256, second.job_index_sha256);
        assert_eq!(first_bytes, second_bytes);

        let mut changed = statements[1].clone();
        changed[100] ^= 1;
        fs::write(statement_directory.join(statement_name(1)), changed).unwrap();
        assert!(publish_plan(&paths).is_err());
    }
}
