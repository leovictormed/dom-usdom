//! Authenticated planning and explicit local proving for one finalized USDOM burn.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::fs::{self, File};
use std::path::Path;

#[cfg(feature = "prove")]
use dom_usdom_finalized_burn_program::execute_with_checkpoint_assumption;
use dom_usdom_finalized_burn_program::{
    execute, FinalizedBurnProverInput, MAX_FINALIZED_BURN_PROVER_INPUT_BYTES,
};
use dom_wallet_crypto::{read_captured_bytes, save_private_bytes};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const INPUT_LOGICAL_PATH: &str = "evidence/finalized-burn-source/finalized-burn-input.bin";
const PROGRAM_LOGICAL_PATH: &str = "evidence/finalized-burn-guest/usdom-finalized-burn.elf";
const IMAGE_ID_LOGICAL_PATH: &str = "evidence/finalized-burn-guest/usdom-finalized-burn.iid";
const OUTPUT_DIRECTORY: &str = "evidence/finalized-burn-proof-job";
const COPIED_INPUT_NAME: &str = "finalized-burn-input.bin";
const JOB_INDEX_NAME: &str = "finalized-burn-proof-job-index.json";
const JOB_INDEX_LOGICAL_PATH: &str =
    "evidence/finalized-burn-proof-job/finalized-burn-proof-job-index.json";
const JOB_INPUT_LOGICAL_PATH: &str = "evidence/finalized-burn-proof-job/finalized-burn-input.bin";
const CHECKPOINT_OUTER_RECEIPT_LOGICAL_PATH: &str =
    "evidence/checkpoint-outer-receipt-set/checkpoint-outer-receipt.bin";
const RECEIPT_OUTPUT_DIRECTORY: &str = "evidence/finalized-burn-receipt";
const RECEIPT_NAME: &str = "finalized-burn-receipt.bin";
#[cfg(feature = "prove")]
const COMPOSITE_RECEIPT_NAME: &str = "finalized-burn-composite-receipt.bin";
#[cfg(feature = "prove")]
const RECEIPT_INDEX_NAME: &str = "finalized-burn-receipt-index.json";
#[cfg(feature = "prove")]
const RECEIPT_INDEX_LOGICAL_PATH: &str =
    "evidence/finalized-burn-receipt/finalized-burn-receipt-index.json";
#[cfg(feature = "prove")]
const EVM_OUTPUT_DIRECTORY: &str = "evidence/finalized-burn-evm-proof";
#[cfg(feature = "prove")]
const GROTH16_RECEIPT_NAME: &str = "finalized-burn-groth16-receipt.bin";
#[cfg(feature = "prove")]
const EVM_SEAL_NAME: &str = "finalized-burn-evm-seal.bin";
#[cfg(feature = "prove")]
const EVM_PACKAGE_INDEX_NAME: &str = "finalized-burn-evm-proof-index.json";
const PROGRAM_SHA256: &str = "883ec39b03e3a0703e592026fc7d92a15ce7d949cb937551c5dd8360184cde21";
const IMAGE_ID_FILE_SHA256: &str =
    "5c07a37b10235eb0b42c667408ff4f890cb9273d8e68d0f70a04e8e697677103";
const IMAGE_ID: &str = "2e26f74497b54b680dfff4c116d56280d016f01d0125329f49bf6d744b1c18ea";
const MAX_PROGRAM_BYTES: usize = 4 * 1024 * 1024;
#[cfg(feature = "prove")]
const MAX_JOB_INDEX_BYTES: usize = 16 * 1024;
#[cfg(feature = "prove")]
const MAX_RECEIPT_BYTES: usize = 256 * 1024 * 1024;
#[cfg(feature = "prove")]
const MAX_COMPOSITE_RECEIPT_BYTES: usize = 512 * 1024 * 1024;
#[cfg(feature = "prove")]
const FINALIZED_BURN_SEGMENT_LIMIT_PO2: u32 = 18;
#[cfg(feature = "prove")]
const RISC0_VERSION: &str = "3.0.6";
#[cfg(feature = "prove")]
const GROTH16_VERIFIER_PARAMETERS: &str =
    "73c457ba541936f0d907daf0c7253a39a9c5c427c225ba7709e44702d3c6eedc";
#[cfg(feature = "prove")]
const EVM_SEAL_SELECTOR: [u8; 4] = [0x73, 0xc4, 0x57, 0xba];
#[cfg(feature = "prove")]
const EVM_SEAL_BYTES: usize = 4 + 8 * 32;

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

/// Fixed authenticated input, guest artifacts and output directory.
pub struct PlanPaths<'a> {
    /// Canonical `UDFINL04` source exported from audited DOM state.
    pub input: &'a Path,
    /// Pinned RISC Zero ProgramBinary.
    pub program: &'a Path,
    /// Pinned RISC Zero ImageID bytes.
    pub image_id: &'a Path,
    /// Directory receiving the immutable input copy and job index.
    pub output_directory: &'a Path,
}

impl PlanPaths<'static> {
    /// Production paths relative to the reserve laboratory root.
    pub fn production() -> Self {
        Self {
            input: Path::new(INPUT_LOGICAL_PATH),
            program: Path::new(PROGRAM_LOGICAL_PATH),
            image_id: Path::new(IMAGE_ID_LOGICAL_PATH),
            output_directory: Path::new(OUTPUT_DIRECTORY),
        }
    }
}

/// Observable result of deterministic finalized-burn proof planning.
pub struct PlanSummary {
    /// Exact Solidity-compatible statement hash committed by the future proof.
    pub statement_hash: String,
    /// SHA-256 of the canonical private input.
    pub input_sha256: String,
    /// SHA-256 of the published deterministic job index.
    pub job_index_sha256: String,
}

/// Fixed job inputs and output for the explicitly authorized proving step.
pub struct ProofPaths<'a> {
    /// Immutable private input copied by the planner.
    pub input: &'a Path,
    /// Canonical job index emitted by the planner.
    pub job_index: &'a Path,
    /// Pinned RISC Zero guest ELF.
    pub program: &'a Path,
    /// Pinned raw 32-byte RISC Zero ImageID.
    pub image_id: &'a Path,
    /// Succinct checkpoint-outer receipt required by the recursive guest.
    pub checkpoint_outer_receipt: &'a Path,
    /// Direct directory receiving a verified receipt and its final index.
    pub output_directory: &'a Path,
}

impl ProofPaths<'static> {
    /// Production paths relative to the reserve laboratory root.
    pub fn production() -> Self {
        Self {
            input: Path::new(JOB_INPUT_LOGICAL_PATH),
            job_index: Path::new(JOB_INDEX_LOGICAL_PATH),
            program: Path::new(PROGRAM_LOGICAL_PATH),
            image_id: Path::new(IMAGE_ID_LOGICAL_PATH),
            checkpoint_outer_receipt: Path::new(CHECKPOINT_OUTER_RECEIPT_LOGICAL_PATH),
            output_directory: Path::new(RECEIPT_OUTPUT_DIRECTORY),
        }
    }
}

/// Observable result after the receipt has been proved and independently verified.
#[cfg(feature = "prove")]
pub struct ProofSummary {
    /// Exact Solidity-compatible statement hash committed by the receipt.
    pub statement_hash: String,
    /// SHA-256 of the exact consumed proof-job index.
    pub job_index_sha256: String,
    /// SHA-256 of the published receipt index.
    pub receipt_index_sha256: String,
    /// Whether a pre-existing valid receipt was reused.
    pub reused_receipt: bool,
    /// Whether succinct compression resumed from a verified composite receipt.
    pub reused_composite_receipt: bool,
    /// Fixed maximum segment size used by the local prover.
    pub segment_limit_po2: u32,
}

/// Fixed inputs and output for explicitly authorized local STARK-to-SNARK
/// compression and EVM seal packaging.
#[cfg(feature = "prove")]
pub struct EvmProofPaths<'a> {
    /// Inputs used to rebuild the exact authenticated finalized-burn proof job.
    pub proof: ProofPaths<'a>,
    /// Published verified succinct-receipt index.
    pub receipt_index: &'a Path,
    /// Directory containing the succinct receipt.
    pub receipt_directory: &'a Path,
    /// Directory receiving the Groth16 receipt, EVM seal and package index.
    pub output_directory: &'a Path,
}

#[cfg(feature = "prove")]
impl EvmProofPaths<'static> {
    /// Production paths relative to the reserve laboratory root.
    pub fn production() -> Self {
        Self {
            proof: ProofPaths::production(),
            receipt_index: Path::new(RECEIPT_INDEX_LOGICAL_PATH),
            receipt_directory: Path::new(RECEIPT_OUTPUT_DIRECTORY),
            output_directory: Path::new(EVM_OUTPUT_DIRECTORY),
        }
    }
}

/// Observable result of local Groth16 compression and EVM seal packaging.
#[cfg(feature = "prove")]
pub struct EvmProofSummary {
    /// Solidity-compatible finalized-burn statement committed by the proof.
    pub statement_hash: String,
    /// SHA-256 of the exact selector-prefixed EVM seal.
    pub evm_seal_sha256: String,
    /// SHA-256 of the published EVM-proof package index.
    pub package_index_sha256: String,
    /// Whether a pre-existing valid Groth16 receipt was reused.
    pub reused_groth16_receipt: bool,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct JobIndex {
    schema: String,
    source_input_path: String,
    source_input_sha256: String,
    input_file: String,
    input_sha256: String,
    input_bytes: usize,
    statement_hash: String,
    program_path: String,
    program_sha256: String,
    image_id_path: String,
    image_id_file_sha256: String,
    image_id: String,
    risc0_zkvm_version: String,
    receipt_kind: String,
    relation_executed: bool,
    generates_proofs: bool,
    mines: bool,
    receipt_file: String,
}

#[cfg(feature = "prove")]
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReceiptIndex {
    schema: String,
    proof_job_index_path: String,
    proof_job_index_sha256: String,
    input_path: String,
    input_sha256: String,
    statement_hash: String,
    program_path: String,
    program_sha256: String,
    image_id: String,
    risc0_zkvm_version: String,
    receipt_kind: String,
    segment_limit_po2: u32,
    receipt_file: String,
    receipt_sha256: String,
    receipt_bytes: usize,
    relation_executed: bool,
    receipt_verified: bool,
    dev_mode: bool,
    generates_proofs: bool,
    mines: bool,
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

fn require_direct_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(format!("{} is not a direct directory", path.display()));
    }
    Ok(())
}

fn read_direct(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    read_captured_bytes(path, maximum)
        .map_err(|error| format!("cannot capture {}: {error}", path.display()))
}

fn atomic_publish(path: &Path, bytes: &[u8]) -> Result<(), String> {
    save_private_bytes(path, bytes)
        .map_err(|error| format!("cannot publish {}: {error}", path.display()))
}

fn invalidate_job_outputs(output_directory: &Path) -> Result<(), String> {
    require_direct_directory(output_directory)?;
    for name in [COPIED_INPUT_NAME, JOB_INDEX_NAME] {
        let path = output_directory.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
                fs::remove_file(&path)
                    .map_err(|error| format!("cannot invalidate {}: {error}", path.display()))?;
            }
            Ok(_) => return Err(format!("{} is not a removable output file", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
        }
    }
    File::open(output_directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync {}: {error}", output_directory.display()))
}

fn publish_job_outputs(output_directory: &Path, input: &[u8], index: &[u8]) -> Result<(), String> {
    let result = (|| {
        atomic_publish(&output_directory.join(COPIED_INPUT_NAME), input)?;
        atomic_publish(&output_directory.join(JOB_INDEX_NAME), index)
    })();
    if let Err(error) = result {
        return match invalidate_job_outputs(output_directory) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!("{error}; output invalidation failed: {cleanup}")),
        };
    }
    Ok(())
}

fn expected_job_index(input: &[u8], statement_hash: &str) -> JobIndex {
    let input_sha256 = sha256(input);
    JobIndex {
        schema: "usdom-finalized-burn-proof-job-v1".into(),
        source_input_path: INPUT_LOGICAL_PATH.into(),
        source_input_sha256: input_sha256.clone(),
        input_file: COPIED_INPUT_NAME.into(),
        input_sha256,
        input_bytes: input.len(),
        statement_hash: statement_hash.into(),
        program_path: PROGRAM_LOGICAL_PATH.into(),
        program_sha256: PROGRAM_SHA256.into(),
        image_id_path: IMAGE_ID_LOGICAL_PATH.into(),
        image_id_file_sha256: IMAGE_ID_FILE_SHA256.into(),
        image_id: IMAGE_ID.into(),
        risc0_zkvm_version: "3.0.6".into(),
        receipt_kind: "succinct".into(),
        relation_executed: true,
        generates_proofs: false,
        mines: false,
        receipt_file: RECEIPT_NAME.into(),
    }
}

fn encode_job_index(index: &JobIndex) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(index)
        .map_err(|error| format!("cannot encode finalized-burn job index: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn validate_relation(input: &[u8]) -> Result<[u8; 32], String> {
    let decoded = FinalizedBurnProverInput::from_bytes(input)
        .map_err(|error| format!("invalid canonical UDFINL04 input: {error}"))?;
    let canonical = decoded
        .to_bytes()
        .map_err(|error| format!("cannot re-encode UDFINL04 input: {error}"))?;
    if canonical != input {
        return Err("UDFINL04 input is not canonically encoded".into());
    }
    let output = execute(input)
        .map_err(|error| format!("finalized-burn relation execution failed: {error}"))?;
    if output.as_bytes() != decoded.statement_hash().as_bytes() {
        return Err("finalized-burn public output changed after decoding".into());
    }
    let mut statement = [0u8; 32];
    statement.copy_from_slice(output.as_bytes());
    Ok(statement)
}

fn validate_guest_artifacts(
    program_path: &Path,
    image_id_path: &Path,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let program = read_direct(program_path, MAX_PROGRAM_BYTES)?;
    if sha256(&program) != PROGRAM_SHA256 {
        return Err("pinned finalized-burn ProgramBinary hash mismatch".into());
    }
    let image_id_bytes = read_direct(image_id_path, 32)?;
    if image_id_bytes.len() != 32
        || sha256(&image_id_bytes) != IMAGE_ID_FILE_SHA256
        || hex(&image_id_bytes) != IMAGE_ID
    {
        return Err("pinned finalized-burn ImageID mismatch".into());
    }
    let mut image_id = [0u8; 32];
    image_id.copy_from_slice(&image_id_bytes);
    Ok((program, image_id))
}

/// Verify the canonical input and guest identities, then atomically publish an
/// immutable proof job. This executes only the pure Rust relation; it never
/// invokes a zkVM prover, mines, signs, broadcasts or accesses a network.
pub fn plan_finalized_burn(paths: &PlanPaths<'_>) -> Result<PlanSummary, String> {
    invalidate_job_outputs(paths.output_directory)?;
    let input = Zeroizing::new(read_direct(
        paths.input,
        MAX_FINALIZED_BURN_PROVER_INPUT_BYTES,
    )?);
    let statement = validate_relation(&input)?;
    let _ = validate_guest_artifacts(paths.program, paths.image_id)?;
    let input_sha256 = sha256(&input);
    let statement_hash = hex(&statement);
    let index = expected_job_index(&input, &statement_hash);
    let index_bytes = encode_job_index(&index)?;
    let job_index_sha256 = sha256(&index_bytes);
    publish_job_outputs(paths.output_directory, &input, &index_bytes)?;
    Ok(PlanSummary {
        statement_hash,
        input_sha256,
        job_index_sha256,
    })
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
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync {}: {error}", parent.display()))
}

#[cfg(feature = "prove")]
fn invalidate_receipt_index(output_directory: &Path) -> Result<(), String> {
    require_direct_directory(output_directory)?;
    let path = output_directory.join(RECEIPT_INDEX_NAME);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_file() => {
            fs::remove_file(&path)
                .map_err(|error| format!("cannot invalidate {}: {error}", path.display()))?;
        }
        Ok(_) => return Err(format!("{} is not a removable output file", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
    }
    File::open(output_directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync {}: {error}", output_directory.display()))
}

#[cfg(feature = "prove")]
fn verify_receipt(
    bytes: &[u8],
    image_id: [u8; 32],
    statement: [u8; 32],
) -> Result<risc0_zkvm::Receipt, String> {
    use bincode::Options;
    use risc0_zkvm::{sha::Digest as Risc0Digest, InnerReceipt, Receipt};

    if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
        return Err("finalized-burn receipt byte length is outside bounds".into());
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
        return Err("finalized-burn receipt is not canonically encoded".into());
    }
    if !matches!(receipt.inner, InnerReceipt::Succinct(_)) {
        return Err("finalized-burn receipt is not succinct".into());
    }
    if receipt.journal.bytes.as_slice() != statement {
        return Err("finalized-burn receipt journal differs from the planned statement".into());
    }
    receipt
        .verify(Risc0Digest::from(image_id))
        .map_err(|error| format!("finalized-burn receipt verification failed: {error}"))?;
    Ok(receipt)
}

#[cfg(feature = "prove")]
fn verify_composite_receipt(
    bytes: &[u8],
    image_id: [u8; 32],
    statement: [u8; 32],
) -> Result<risc0_zkvm::Receipt, String> {
    use bincode::Options;
    use risc0_zkvm::{sha::Digest as Risc0Digest, InnerReceipt, Receipt};

    if bytes.is_empty() || bytes.len() > MAX_COMPOSITE_RECEIPT_BYTES {
        return Err("finalized-burn composite receipt byte length is outside bounds".into());
    }
    let receipt: Receipt = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_COMPOSITE_RECEIPT_BYTES as u64)
        .deserialize(bytes)
        .map_err(|error| format!("cannot decode RISC Zero composite receipt: {error}"))?;
    if bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&receipt)
        .map_err(|error| format!("cannot canonically encode composite receipt: {error}"))?
        != bytes
    {
        return Err("finalized-burn composite receipt is not canonically encoded".into());
    }
    if !matches!(receipt.inner, InnerReceipt::Composite(_)) {
        return Err("finalized-burn intermediate receipt is not composite".into());
    }
    if receipt.journal.bytes.as_slice() != statement {
        return Err("finalized-burn composite journal differs from the planned statement".into());
    }
    receipt
        .verify(Risc0Digest::from(image_id))
        .map_err(|error| format!("finalized-burn composite verification failed: {error}"))?;
    Ok(receipt)
}

#[cfg(feature = "prove")]
fn verify_groth16_receipt(
    bytes: &[u8],
    image_id: [u8; 32],
    statement: [u8; 32],
) -> Result<risc0_zkvm::Receipt, String> {
    use bincode::Options;
    use risc0_zkvm::{sha::Digest as Risc0Digest, InnerReceipt, Receipt};

    if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
        return Err("finalized-burn Groth16 receipt byte length is outside bounds".into());
    }
    let receipt: Receipt = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_RECEIPT_BYTES as u64)
        .deserialize(bytes)
        .map_err(|error| format!("cannot decode finalized-burn Groth16 receipt: {error}"))?;
    if bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&receipt)
        .map_err(|error| format!("cannot canonically encode Groth16 receipt: {error}"))?
        != bytes
    {
        return Err("finalized-burn Groth16 receipt is not canonically encoded".into());
    }
    let groth16 = match &receipt.inner {
        InnerReceipt::Groth16(inner) => inner,
        _ => return Err("finalized-burn receipt is not Groth16".into()),
    };
    if hex(groth16.verifier_parameters.as_bytes()) != GROTH16_VERIFIER_PARAMETERS {
        return Err("finalized-burn Groth16 verifier parameters mismatch".into());
    }
    if receipt.journal.bytes.as_slice() != statement {
        return Err("finalized-burn Groth16 journal differs from the planned statement".into());
    }
    receipt
        .verify(Risc0Digest::from(image_id))
        .map_err(|error| format!("finalized-burn Groth16 receipt verification failed: {error}"))?;
    Ok(receipt)
}

#[cfg(feature = "prove")]
fn expected_receipt_index(
    input: &[u8],
    statement_hash: &str,
    job_index_sha256: &str,
    receipt_bytes: &[u8],
) -> ReceiptIndex {
    ReceiptIndex {
        schema: "usdom-finalized-burn-receipt-v1".into(),
        proof_job_index_path: JOB_INDEX_LOGICAL_PATH.into(),
        proof_job_index_sha256: job_index_sha256.into(),
        input_path: JOB_INPUT_LOGICAL_PATH.into(),
        input_sha256: sha256(input),
        statement_hash: statement_hash.into(),
        program_path: PROGRAM_LOGICAL_PATH.into(),
        program_sha256: PROGRAM_SHA256.into(),
        image_id: IMAGE_ID.into(),
        risc0_zkvm_version: RISC0_VERSION.into(),
        receipt_kind: "succinct".into(),
        segment_limit_po2: FINALIZED_BURN_SEGMENT_LIMIT_PO2,
        receipt_file: RECEIPT_NAME.into(),
        receipt_sha256: sha256(receipt_bytes),
        receipt_bytes: receipt_bytes.len(),
        relation_executed: true,
        receipt_verified: true,
        dev_mode: false,
        generates_proofs: true,
        mines: false,
    }
}

#[cfg(feature = "prove")]
fn encode_receipt_index(index: &ReceiptIndex) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(index)
        .map_err(|error| format!("cannot encode finalized-burn receipt index: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(feature = "prove")]
fn existing_verified_receipt(
    path: &Path,
    image_id: [u8; 32],
    statement: [u8; 32],
) -> Result<Option<Vec<u8>>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!("{} is not a direct receipt file", path.display()));
            }
            let bytes = read_direct(path, MAX_RECEIPT_BYTES)?;
            if verify_receipt(&bytes, image_id, statement).is_ok() {
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

#[cfg(feature = "prove")]
fn existing_verified_composite_receipt(
    path: &Path,
    image_id: [u8; 32],
    statement: [u8; 32],
) -> Result<Option<Vec<u8>>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!("{} is not a direct regular file", path.display()));
            }
            let bytes = read_direct(path, MAX_COMPOSITE_RECEIPT_BYTES)?;
            if verify_composite_receipt(&bytes, image_id, statement).is_ok() {
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

/// Prove one exact planned finalized-burn job with the fixed local prover,
/// verify its succinct receipt and atomically publish the receipt index.
///
/// This is intentionally expensive and must only be invoked through the
/// separate operator command after explicit authorization.
#[cfg(feature = "prove")]
pub fn prove_finalized_burn(paths: &ProofPaths<'_>) -> Result<ProofSummary, String> {
    use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, Prover, ProverOpts};

    require_local_prover_environment("finalized-burn proving")?;
    invalidate_receipt_index(paths.output_directory)?;

    let input = Zeroizing::new(read_direct(
        paths.input,
        MAX_FINALIZED_BURN_PROVER_INPUT_BYTES,
    )?);
    let statement = validate_relation(&input)?;
    let statement_hash = hex(&statement);
    let expected_index = expected_job_index(&input, &statement_hash);
    let expected_index_bytes = encode_job_index(&expected_index)?;
    let published_index = read_direct(paths.job_index, MAX_JOB_INDEX_BYTES)?;
    let decoded_index: JobIndex = serde_json::from_slice(&published_index)
        .map_err(|error| format!("invalid finalized-burn proof-job index: {error}"))?;
    if decoded_index != expected_index || published_index != expected_index_bytes {
        return Err("published finalized-burn job differs from its exact canonical plan".into());
    }
    let job_index_sha256 = sha256(&published_index);
    let (program, image_id) = validate_guest_artifacts(paths.program, paths.image_id)?;
    let recursive = execute_with_checkpoint_assumption(&input)
        .map_err(|error| format!("invalid finalized-burn recursive relation: {error}"))?
        .checkpoint_receipt();
    let checkpoint_receipt_bytes = read_direct(paths.checkpoint_outer_receipt, MAX_RECEIPT_BYTES)?;
    let checkpoint_receipt = verify_receipt(
        &checkpoint_receipt_bytes,
        *recursive.image_id(),
        *recursive.journal(),
    )
    .map_err(|error| format!("checkpoint-outer assumption verification failed: {error}"))?;

    let prover = default_prover();
    if prover.get_name() != "local" {
        return Err("selected finalized-burn prover is not the fixed local prover".into());
    }
    let receipt_path = paths.output_directory.join(RECEIPT_NAME);
    let composite_path = paths.output_directory.join(COMPOSITE_RECEIPT_NAME);
    let mut reused_composite_receipt = false;
    let (receipt_bytes, reused_receipt) =
        if let Some(bytes) = existing_verified_receipt(&receipt_path, image_id, statement)? {
            (bytes, true)
        } else {
            let input_len = u32::try_from(input.len())
                .map_err(|_| "finalized-burn prover input length exceeds u32".to_string())?;
            let mut builder = ExecutorEnv::builder();
            builder.segment_limit_po2(FINALIZED_BURN_SEGMENT_LIMIT_PO2);
            builder.add_assumption(checkpoint_receipt);
            builder
                .write(&input_len)
                .map_err(|error| format!("cannot encode finalized-burn input length: {error}"))?;
            builder.write_slice(&input);
            let environment = builder.build().map_err(|error| {
                format!("cannot build finalized-burn prover environment: {error}")
            })?;
            let composite = if let Some(bytes) =
                existing_verified_composite_receipt(&composite_path, image_id, statement)?
            {
                reused_composite_receipt = true;
                verify_composite_receipt(&bytes, image_id, statement)?
            } else {
                let options = ProverOpts::composite().with_dev_mode(false);
                let proof = prover
                    .prove_with_opts(environment, &program, &options)
                    .map_err(|error| format!("finalized-burn composite proof failed: {error}"))?;
                if !matches!(proof.receipt.inner, InnerReceipt::Composite(_)) {
                    return Err("finalized-burn prover did not return a composite receipt".into());
                }
                let bytes = bincode::serialize(&proof.receipt).map_err(|error| {
                    format!("cannot encode finalized-burn composite receipt: {error}")
                })?;
                if bytes.is_empty() || bytes.len() > MAX_COMPOSITE_RECEIPT_BYTES {
                    return Err("finalized-burn composite receipt exceeds its byte bound".into());
                }
                let receipt = verify_composite_receipt(&bytes, image_id, statement)?;
                atomic_publish(&composite_path, &bytes)?;
                receipt
            };
            let options = ProverOpts::succinct().with_dev_mode(false);
            let receipt = prover
                .compress(&options, &composite)
                .map_err(|error| format!("finalized-burn succinct compression failed: {error}"))?;
            if !matches!(receipt.inner, InnerReceipt::Succinct(_)) {
                return Err("finalized-burn compression did not return a succinct receipt".into());
            }
            let bytes = bincode::serialize(&receipt)
                .map_err(|error| format!("cannot encode finalized-burn receipt: {error}"))?;
            if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
                return Err("finalized-burn receipt exceeds its byte bound".into());
            }
            verify_receipt(&bytes, image_id, statement)?;
            atomic_publish(&receipt_path, &bytes)?;
            (bytes, false)
        };

    let receipt_index =
        expected_receipt_index(&input, &statement_hash, &job_index_sha256, &receipt_bytes);
    let receipt_index_bytes = encode_receipt_index(&receipt_index)?;
    let receipt_index_sha256 = sha256(&receipt_index_bytes);
    atomic_publish(
        &paths.output_directory.join(RECEIPT_INDEX_NAME),
        &receipt_index_bytes,
    )?;
    if composite_path.exists() {
        remove_direct_file(&composite_path)?;
    }
    Ok(ProofSummary {
        statement_hash,
        job_index_sha256,
        receipt_index_sha256,
        reused_receipt,
        reused_composite_receipt,
        segment_limit_po2: FINALIZED_BURN_SEGMENT_LIMIT_PO2,
    })
}

#[cfg(feature = "prove")]
fn invalidate_evm_package_index(output_directory: &Path) -> Result<(), String> {
    require_direct_directory(output_directory)?;
    let path = output_directory.join(EVM_PACKAGE_INDEX_NAME);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_file() => {
            fs::remove_file(&path)
                .map_err(|error| format!("cannot invalidate {}: {error}", path.display()))?;
        }
        Ok(_) => return Err(format!("{} is not a removable output file", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
    }
    File::open(output_directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync {}: {error}", output_directory.display()))?;

    // Once the completion marker is durably absent, clear the cheap derived
    // seal as well. The verified Groth16 receipt remains resumable and will
    // deterministically recreate this calldata artifact.
    let seal_path = output_directory.join(EVM_SEAL_NAME);
    match fs::symlink_metadata(&seal_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!("{} is not a direct EVM seal", seal_path.display()));
            }
            remove_direct_file(&seal_path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot inspect EVM seal {}: {error}",
            seal_path.display()
        )),
    }
}

#[cfg(feature = "prove")]
fn existing_verified_groth16_receipt(
    path: &Path,
    image_id: [u8; 32],
    statement: [u8; 32],
) -> Result<Option<(Vec<u8>, risc0_zkvm::Receipt)>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!(
                    "{} is not a direct Groth16 receipt",
                    path.display()
                ));
            }
            let bytes = read_direct(path, MAX_RECEIPT_BYTES)?;
            match verify_groth16_receipt(&bytes, image_id, statement) {
                Ok(receipt) => Ok(Some((bytes, receipt))),
                Err(_) => {
                    remove_direct_file(path)?;
                    Ok(None)
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot inspect {}: {error}", path.display())),
    }
}

/// Compress one verified finalized-burn succinct receipt to Groth16 and publish
/// the exact selector-prefixed seal consumed by the immutable EVM adapter.
///
/// This performs expensive STARK-to-SNARK compression and must only be called
/// through its separate operator command after explicit authorization.
#[cfg(feature = "prove")]
#[allow(clippy::too_many_lines)]
pub fn package_finalized_burn_evm_proof(
    paths: &EvmProofPaths<'_>,
) -> Result<EvmProofSummary, String> {
    use risc0_zkvm::{default_prover, InnerReceipt, Prover, ProverOpts};

    require_local_prover_environment("finalized-burn Groth16 compression")?;
    require_direct_directory(paths.receipt_directory)?;
    invalidate_evm_package_index(paths.output_directory)?;

    let input = Zeroizing::new(read_direct(
        paths.proof.input,
        MAX_FINALIZED_BURN_PROVER_INPUT_BYTES,
    )?);
    let statement = validate_relation(&input)?;
    let statement_hash = hex(&statement);
    let expected_job = expected_job_index(&input, &statement_hash);
    let expected_job_bytes = encode_job_index(&expected_job)?;
    let published_job = read_direct(paths.proof.job_index, MAX_JOB_INDEX_BYTES)?;
    let decoded_job: JobIndex = serde_json::from_slice(&published_job)
        .map_err(|error| format!("invalid finalized-burn proof-job index: {error}"))?;
    if decoded_job != expected_job || published_job != expected_job_bytes {
        return Err("published finalized-burn job differs from its exact canonical plan".into());
    }
    let job_index_sha256 = sha256(&published_job);
    let (_, image_id) = validate_guest_artifacts(paths.proof.program, paths.proof.image_id)?;

    let receipt_index_bytes = read_direct(paths.receipt_index, MAX_JOB_INDEX_BYTES)?;
    let receipt_index: ReceiptIndex = serde_json::from_slice(&receipt_index_bytes)
        .map_err(|error| format!("invalid finalized-burn receipt index: {error}"))?;
    if receipt_index.receipt_file != RECEIPT_NAME
        || receipt_index.receipt_bytes == 0
        || receipt_index.receipt_bytes > MAX_RECEIPT_BYTES
    {
        return Err("finalized-burn receipt index contains an invalid receipt record".into());
    }
    let succinct_bytes = read_direct(
        &paths.receipt_directory.join(RECEIPT_NAME),
        MAX_RECEIPT_BYTES,
    )?;
    let expected_receipt =
        expected_receipt_index(&input, &statement_hash, &job_index_sha256, &succinct_bytes);
    let expected_receipt_bytes = encode_receipt_index(&expected_receipt)?;
    if receipt_index != expected_receipt || receipt_index_bytes != expected_receipt_bytes {
        return Err("published finalized-burn receipt differs from its exact proof job".into());
    }
    let succinct_receipt = verify_receipt(&succinct_bytes, image_id, statement)?;

    let prover = default_prover();
    if prover.get_name() != "local" {
        return Err(
            "selected finalized-burn Groth16 compressor is not the fixed local prover".into(),
        );
    }
    let groth16_path = paths.output_directory.join(GROTH16_RECEIPT_NAME);
    let (groth16_bytes, groth16_receipt, reused_groth16_receipt) = if let Some((bytes, receipt)) =
        existing_verified_groth16_receipt(&groth16_path, image_id, statement)?
    {
        (bytes, receipt, true)
    } else {
        let options = ProverOpts::groth16().with_dev_mode(false);
        let receipt = prover
            .compress(&options, &succinct_receipt)
            .map_err(|error| format!("finalized-burn Groth16 compression failed: {error}"))?;
        if !matches!(receipt.inner, InnerReceipt::Groth16(_)) {
            return Err("compressed finalized-burn receipt is not Groth16".into());
        }
        let bytes = bincode::serialize(&receipt)
            .map_err(|error| format!("cannot encode finalized-burn Groth16 receipt: {error}"))?;
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
            return Err("finalized-burn Groth16 receipt exceeds its byte bound".into());
        }
        verify_groth16_receipt(&bytes, image_id, statement)?;
        atomic_publish(&groth16_path, &bytes)?;
        (bytes, receipt, false)
    };
    let groth16 = match &groth16_receipt.inner {
        InnerReceipt::Groth16(inner) => inner,
        _ => return Err("verified finalized-burn receipt lost Groth16 identity".into()),
    };
    if groth16.seal.is_empty() {
        return Err("finalized-burn Groth16 seal is empty".into());
    }
    let mut evm_seal = Vec::with_capacity(EVM_SEAL_SELECTOR.len() + groth16.seal.len());
    evm_seal.extend_from_slice(&EVM_SEAL_SELECTOR);
    evm_seal.extend_from_slice(&groth16.seal);
    if evm_seal.len() != EVM_SEAL_BYTES || evm_seal[..4] != EVM_SEAL_SELECTOR {
        return Err(
            "selector-prefixed finalized-burn EVM seal is not the canonical 260-byte Groth16 proof"
                .into(),
        );
    }
    atomic_publish(&paths.output_directory.join(EVM_SEAL_NAME), &evm_seal)?;

    let output = serde_json::json!({
        "schema": "usdom-finalized-burn-evm-proof-v1",
        "receipt_index_path": RECEIPT_INDEX_LOGICAL_PATH,
        "receipt_index_sha256": sha256(&receipt_index_bytes),
        "image_id": IMAGE_ID,
        "statement_hash": statement_hash,
        "journal_digest": sha256(&statement),
        "risc0_zkvm_version": RISC0_VERSION,
        "receipt_kind": "groth16",
        "groth16_verifier_parameters": GROTH16_VERIFIER_PARAMETERS,
        "evm_verifier_selector": hex(&EVM_SEAL_SELECTOR),
        "groth16_receipt_file": GROTH16_RECEIPT_NAME,
        "groth16_receipt_sha256": sha256(&groth16_bytes),
        "groth16_receipt_bytes": groth16_bytes.len(),
        "evm_seal_file": EVM_SEAL_NAME,
        "evm_seal_sha256": sha256(&evm_seal),
        "evm_seal_bytes": evm_seal.len(),
        "receipt_verified": true,
        "dev_mode": false,
        "generates_proofs": true,
        "mines": false
    });
    let mut output_bytes = serde_json::to_vec_pretty(&output)
        .map_err(|error| format!("cannot encode finalized-burn EVM proof index: {error}"))?;
    output_bytes.push(b'\n');
    let package_index_sha256 = sha256(&output_bytes);
    atomic_publish(
        &paths.output_directory.join(EVM_PACKAGE_INDEX_NAME),
        &output_bytes,
    )?;
    Ok(EvmProofSummary {
        statement_hash: hex(&statement),
        evm_seal_sha256: sha256(&evm_seal),
        package_index_sha256,
        reused_groth16_receipt,
    })
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "prove")]
    use super::existing_verified_composite_receipt;
    use super::{
        hex, invalidate_job_outputs, publish_job_outputs, read_direct, require_direct_directory,
        sha256, COPIED_INPUT_NAME, JOB_INDEX_NAME,
    };
    use std::fs;

    #[test]
    fn hash_helpers_are_canonical() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn direct_reads_reject_symlinks_and_bounds() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let file = directory.path().join("input.bin");
        let link = directory.path().join("link.bin");
        fs::write(&file, b"abc")?;
        std::os::unix::fs::symlink(&file, &link)?;
        assert_eq!(read_direct(&file, 3)?, b"abc");
        assert!(read_direct(&file, 2).is_err());
        assert!(read_direct(&link, 3).is_err());
        assert!(require_direct_directory(directory.path()).is_ok());
        assert!(require_direct_directory(&link).is_err());
        Ok(())
    }

    #[test]
    fn stale_output_invalidation_preserves_unrelated_files(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::write(directory.path().join(COPIED_INPUT_NAME), b"stale input")?;
        fs::write(directory.path().join(JOB_INDEX_NAME), b"stale index")?;
        fs::write(directory.path().join("checkpoint-witness.bin"), b"source")?;
        invalidate_job_outputs(directory.path())?;
        assert!(!directory.path().join(COPIED_INPUT_NAME).exists());
        assert!(!directory.path().join(JOB_INDEX_NAME).exists());
        assert_eq!(
            fs::read(directory.path().join("checkpoint-witness.bin"))?,
            b"source"
        );
        Ok(())
    }

    #[test]
    fn failed_pair_publication_invalidates_both_outputs() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        fs::write(directory.path().join(COPIED_INPUT_NAME), b"stale input")?;
        fs::write(directory.path().join(JOB_INDEX_NAME), b"stale index")?;
        invalidate_job_outputs(directory.path())?;
        let blocked_destination = directory.path().join(JOB_INDEX_NAME);
        fs::create_dir(&blocked_destination)?;
        assert!(publish_job_outputs(directory.path(), b"new input", b"new index").is_err());
        assert!(!directory.path().join(COPIED_INPUT_NAME).exists());
        assert!(blocked_destination.is_dir());
        Ok(())
    }

    #[cfg(feature = "prove")]
    #[test]
    fn malformed_composite_checkpoint_is_removed_before_proving(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let checkpoint = directory.path().join("composite.bin");
        fs::write(&checkpoint, b"not-a-risc-zero-receipt")?;

        assert!(existing_verified_composite_receipt(&checkpoint, [0; 32], [0; 32])?.is_none());
        assert!(!checkpoint.exists());
        Ok(())
    }
}
