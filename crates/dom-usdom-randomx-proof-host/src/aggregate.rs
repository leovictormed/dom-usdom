//! Per-segment aggregation of authenticated RandomX receipts.

use std::path::Path;

#[cfg(feature = "prove")]
use std::fs;

use bincode::Options;
use dom_usdom_checkpoint_program::{
    checkpoint_segment_randomx_aggregate, CheckpointSegmentPolicyInput,
    CheckpointSegmentPrivateInput, CheckpointSegmentState, CheckpointSegmentTransition,
    CHECKPOINT_SEGMENT_TRANSITION_BYTES, MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES,
    MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES, MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
};
use risc0_zkvm::{sha::Digest as Risc0Digest, InnerReceipt, Receipt};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    atomic_publish, build_plan, canonical_nonzero_hash, decode_hex_32, ensure_direct_directory,
    read_direct_regular_file, sha256, ProofPaths, MAX_INDEX_BYTES, MAX_RECEIPT_BYTES, RECEIPT_KIND,
    RISC0_VERSION,
};
#[cfg(feature = "prove")]
use super::{remove_invalid_receipt, require_local_prover_environment, verify_receipt};

const SOURCE_INDEX_SCHEMA: &str = "usdom-canonical-checkpoint-source-set-v1";
const RECEIPT_SET_SCHEMA: &str = "usdom-randomx-receipt-set-v1";
const AGGREGATE_JOB_SCHEMA: &str = "usdom-randomx-aggregate-job-set-v1";
#[cfg(feature = "prove")]
const AGGREGATE_RECEIPT_SCHEMA: &str = "usdom-randomx-aggregate-receipt-set-v1";
const SOURCE_INDEX_LOGICAL_PATH: &str =
    "evidence/checkpoint-source-set/checkpoint-source-set-index.json";
const RECEIPT_INDEX_LOGICAL_PATH: &str =
    "evidence/randomx-receipt-set/randomx-receipt-set-index.json";
#[cfg(feature = "prove")]
const AGGREGATE_JOB_INDEX_LOGICAL_PATH: &str =
    "evidence/randomx-aggregate-jobs/randomx-aggregate-job-index.json";
const AGGREGATE_PROGRAM_LOGICAL_PATH: &str =
    "../../crates/dom-usdom-randomx-aggregate-risc0-guest/elfs/usdom-randomx-aggregate.bin";
const AGGREGATE_IMAGE_ID_LOGICAL_PATH: &str =
    "../../crates/dom-usdom-randomx-aggregate-risc0-guest/elfs/usdom-randomx-aggregate.iid";
const AGGREGATE_PROGRAM_SHA256: &str =
    "3dad95bf467a807c7ef033f88595ea44f14578dca4c7558ad95b7ad76c0d198f";
const AGGREGATE_IMAGE_ID: &str = "08abf768e699ecb9d5cd2abc7603368103bcd3ee61afe9066d8a77272ac02ebf";
const AGGREGATE_IMAGE_ID_FILE_SHA256: &str =
    "a43bba85b71e317e9b9d92d720a9fb94b31ae082202455d72e0dab85fb3113ff";
const AGGREGATE_JOB_INDEX_NAME: &str = "randomx-aggregate-job-index.json";
#[cfg(feature = "prove")]
const AGGREGATE_RECEIPT_INDEX_NAME: &str = "randomx-aggregate-receipt-set-index.json";
const MAX_AGGREGATE_PROGRAM_BYTES: usize = 16 * 1024 * 1024;

/// Fixed inputs for aggregate-job planning.
pub struct AggregatePlanPaths<'a> {
    /// Inputs and per-block receipt directory from stage 259.
    pub block_proof: ProofPaths<'a>,
    /// Final per-block receipt-set index.
    pub receipt_set_index: &'a Path,
    /// Canonical checkpoint source-set index.
    pub source_index: &'a Path,
    /// Directory containing numbered source segments.
    pub source_directory: &'a Path,
    /// Pinned aggregate ProgramBinary.
    pub aggregate_program: &'a Path,
    /// Pinned aggregate ImageID file.
    pub aggregate_image_id: &'a Path,
    /// Output directory for the deterministic aggregate-job index.
    pub output_directory: &'a Path,
}

impl AggregatePlanPaths<'static> {
    /// Production paths relative to the reserve laboratory root.
    pub fn production() -> Self {
        Self {
            block_proof: ProofPaths::production(),
            receipt_set_index: Path::new(
                "evidence/randomx-receipt-set/randomx-receipt-set-index.json",
            ),
            source_index: Path::new(
                "evidence/checkpoint-source-set/checkpoint-source-set-index.json",
            ),
            source_directory: Path::new("evidence/checkpoint-source-set"),
            aggregate_program: Path::new(AGGREGATE_PROGRAM_LOGICAL_PATH),
            aggregate_image_id: Path::new(AGGREGATE_IMAGE_ID_LOGICAL_PATH),
            output_directory: Path::new("evidence/randomx-aggregate-jobs"),
        }
    }
}

/// Fixed inputs and output for explicitly authorized aggregate proving.
pub struct AggregateProofPaths<'a> {
    /// Inputs used to rebuild the aggregate plan.
    pub plan: AggregatePlanPaths<'a>,
    /// Published aggregate-job index.
    pub job_index: &'a Path,
    /// Output directory for aggregate receipts.
    pub output_directory: &'a Path,
}

impl AggregateProofPaths<'static> {
    /// Production paths relative to the reserve laboratory root.
    pub fn production() -> Self {
        Self {
            plan: AggregatePlanPaths::production(),
            job_index: Path::new(
                "evidence/randomx-aggregate-jobs/randomx-aggregate-job-index.json",
            ),
            output_directory: Path::new("evidence/randomx-aggregate-receipt-set"),
        }
    }
}

/// Observable deterministic aggregate-plan result.
pub struct AggregatePlanSummary {
    /// Number of segment aggregate jobs.
    pub job_count: usize,
    /// SHA-256 of the verified inner receipt-set index.
    pub receipt_set_index_sha256: String,
    /// SHA-256 of the aggregate-job index.
    pub job_index_sha256: String,
}

/// Observable result of aggregate proving.
#[cfg(feature = "prove")]
pub struct AggregateProofSummary {
    /// Number of verified aggregate receipts.
    pub receipt_count: usize,
    /// SHA-256 of the consumed aggregate-job index.
    pub job_index_sha256: String,
    /// SHA-256 of the final aggregate-receipt index.
    pub receipt_index_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptSetIndex {
    schema: String,
    proof_job_index_path: String,
    proof_job_index_sha256: String,
    manifest_sha256: String,
    randomx_receipt_image_id: String,
    randomx_user_elf_sha256: String,
    risc0_zkvm_version: String,
    receipt_kind: String,
    previous_height: u64,
    target_height: u64,
    confirmation_height: u64,
    segment_count: usize,
    receipt_count: usize,
    randomx_relations_executed: bool,
    receipts_verified: bool,
    dev_mode: bool,
    generates_proofs: bool,
    mines: bool,
    receipts: Vec<ReceiptRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptRecord {
    index: usize,
    segment_index: usize,
    block_index: usize,
    block_height: u64,
    statement_sha256: String,
    expected_journal: String,
    receipt_file: String,
    receipt_sha256: String,
    receipt_bytes: usize,
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

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AggregateJobIndex {
    schema: String,
    source_index_path: String,
    source_index_sha256: String,
    receipt_set_index_path: String,
    receipt_set_index_sha256: String,
    manifest_sha256: String,
    inner_randomx_image_id: String,
    aggregate_program_path: String,
    aggregate_program_sha256: String,
    aggregate_image_id_path: String,
    aggregate_image_id_file_sha256: String,
    aggregate_image_id: String,
    risc0_zkvm_version: String,
    receipt_kind: String,
    segment_count: usize,
    job_count: usize,
    executes_guest: bool,
    generates_proofs: bool,
    mines: bool,
    jobs: Vec<AggregateJob>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AggregateJob {
    index: usize,
    previous_height: u64,
    next_height: u64,
    block_count: u16,
    transition_file: String,
    transition_sha256: String,
    private_input_file: String,
    private_input_sha256: String,
    dom_genesis_hash: String,
    first_inner_receipt_index: usize,
    inner_receipt_count: usize,
    inner_receipt_files: Vec<String>,
    inner_receipt_sha256: Vec<String>,
    expected_journal: String,
    aggregate_receipt_file: String,
}

fn source_name(index: usize, suffix: &str) -> String {
    format!("checkpoint-segment-{index:04}-{suffix}")
}

fn aggregate_receipt_name(index: usize) -> String {
    format!("randomx-aggregate-receipt-{index:04}.bin")
}

fn validate_source_cadence(source: &SourceIndex) -> Result<(), String> {
    if source.checkpoint_interval_blocks == 0
        || source.checkpoint_confirmation_depth_blocks == 0
        || source.checkpoint_confirmation_depth_blocks > source.checkpoint_interval_blocks
        || source.previous_height >= source.target_height
        || source.target_height >= source.confirmation_height
        || source.target_height.checked_sub(source.previous_height)
            != Some(u64::from(source.checkpoint_interval_blocks))
        || source.confirmation_height.checked_sub(source.target_height)
            != Some(u64::from(source.checkpoint_confirmation_depth_blocks))
    {
        return Err("checkpoint source-set cadence is invalid".into());
    }
    Ok(())
}

fn validate_source_segment(
    source: &SourceIndex,
    index: usize,
    segment: &SourceSegment,
    expected_previous: u64,
) -> Result<(), String> {
    if segment.index != index
        || segment.previous_height != expected_previous
        || segment.block_count == 0
        || segment.block_count > 32
        || segment.next_height.checked_sub(segment.previous_height)
            != Some(u64::from(segment.block_count))
        || segment.next_height > source.confirmation_height
        || (segment.previous_height < source.target_height
            && segment.next_height > source.target_height)
        || segment.transition_file != source_name(index, "transition.bin")
        || segment.private_input_file != source_name(index, "private-input.bin")
        || segment.policy_input_file != source_name(index, "policy-input.bin")
        || segment.native_state_opening_file != source_name(index, "native-state-opening.bin")
        || !canonical_nonzero_hash(&segment.transition_sha256)
        || !canonical_nonzero_hash(&segment.private_input_sha256)
        || !canonical_nonzero_hash(&segment.policy_input_sha256)
        || !canonical_nonzero_hash(&segment.native_state_opening_sha256)
    {
        return Err(format!("invalid source segment at index {index}"));
    }
    Ok(())
}

fn validate_artifact(path: &Path, expected_hash: &str, maximum: usize) -> Result<Vec<u8>, String> {
    let bytes = read_direct_regular_file(path, maximum)?;
    if sha256(&bytes) != expected_hash {
        return Err(format!(
            "aggregate artifact hash mismatch: {}",
            path.display()
        ));
    }
    Ok(bytes)
}

fn decode_verified_receipt(
    bytes: &[u8],
    image_id: [u8; 32],
    journal: [u8; 32],
) -> Result<Receipt, String> {
    if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
        return Err("inner receipt byte length is outside the accepted bounds".into());
    }
    let receipt: Receipt = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_RECEIPT_BYTES as u64)
        .deserialize(bytes)
        .map_err(|error| format!("cannot decode inner receipt: {error}"))?;
    if bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&receipt)
        .map_err(|error| format!("cannot canonically encode inner receipt: {error}"))?
        != bytes
    {
        return Err("inner receipt is not canonically encoded".into());
    }
    if !matches!(receipt.inner, InnerReceipt::Succinct(_)) {
        return Err("inner receipt is not succinct".into());
    }
    if receipt.journal.bytes.as_slice() != journal {
        return Err("inner receipt journal mismatch".into());
    }
    receipt
        .verify(Risc0Digest::from(image_id))
        .map_err(|error| format!("inner receipt verification failed: {error}"))?;
    Ok(receipt)
}

fn build_aggregate_plan(
    paths: &AggregatePlanPaths<'_>,
) -> Result<(AggregateJobIndex, Vec<u8>, String), String> {
    ensure_direct_directory(paths.source_directory)?;
    ensure_direct_directory(paths.block_proof.output_directory)?;
    let (block_plan, block_plan_bytes, _) = build_plan(&paths.block_proof.plan)?;
    let published_block_plan =
        read_direct_regular_file(paths.block_proof.job_index, MAX_INDEX_BYTES)?;
    if published_block_plan != block_plan_bytes {
        return Err("per-block job index differs from its rebuilt plan".into());
    }
    let block_plan_hash = sha256(&published_block_plan);
    let receipt_index_bytes = read_direct_regular_file(paths.receipt_set_index, MAX_INDEX_BYTES)?;
    let receipts: ReceiptSetIndex = serde_json::from_slice(&receipt_index_bytes)
        .map_err(|error| format!("invalid inner receipt-set index: {error}"))?;
    if receipts.schema != RECEIPT_SET_SCHEMA
        || receipts.proof_job_index_path
            != "evidence/randomx-proof-jobs/randomx-proof-job-index.json"
        || receipts.proof_job_index_sha256 != block_plan_hash
        || receipts.manifest_sha256 != block_plan.manifest_sha256
        || receipts.randomx_receipt_image_id != block_plan.randomx_receipt_image_id
        || receipts.randomx_user_elf_sha256 != block_plan.randomx_user_elf_sha256
        || receipts.risc0_zkvm_version != RISC0_VERSION
        || receipts.receipt_kind != RECEIPT_KIND
        || receipts.previous_height != block_plan.previous_height
        || receipts.target_height != block_plan.target_height
        || receipts.confirmation_height != block_plan.confirmation_height
        || receipts.segment_count != block_plan.segment_count
        || receipts.receipt_count != block_plan.job_count
        || receipts.receipt_count != receipts.receipts.len()
        || !receipts.randomx_relations_executed
        || !receipts.receipts_verified
        || receipts.dev_mode
        || !receipts.generates_proofs
        || receipts.mines
    {
        return Err("inner receipt-set identity or execution claims are invalid".into());
    }
    let inner_image_id = decode_hex_32(&receipts.randomx_receipt_image_id)?;
    for (index, (record, job)) in receipts.receipts.iter().zip(&block_plan.jobs).enumerate() {
        if record.index != index
            || record.segment_index != job.segment_index
            || record.block_index != job.block_index
            || record.block_height != job.block_height
            || record.statement_sha256 != job.statement_sha256
            || record.expected_journal != job.expected_journal
            || record.receipt_file != job.receipt_file
            || !canonical_nonzero_hash(&record.receipt_sha256)
            || record.receipt_bytes == 0
            || record.receipt_bytes > MAX_RECEIPT_BYTES
        {
            return Err(format!("invalid inner receipt record at index {index}"));
        }
        let bytes = read_direct_regular_file(
            &paths
                .block_proof
                .output_directory
                .join(&record.receipt_file),
            MAX_RECEIPT_BYTES,
        )?;
        if bytes.len() != record.receipt_bytes || sha256(&bytes) != record.receipt_sha256 {
            return Err(format!("inner receipt file mismatch at index {index}"));
        }
        decode_verified_receipt(
            &bytes,
            inner_image_id,
            decode_hex_32(&record.expected_journal)?,
        )?;
    }

    let source_index_bytes = read_direct_regular_file(paths.source_index, MAX_INDEX_BYTES)?;
    let statement_index_bytes =
        read_direct_regular_file(paths.block_proof.plan.statement_index, MAX_INDEX_BYTES)?;
    let statements: super::StatementSetIndex = serde_json::from_slice(&statement_index_bytes)
        .map_err(|error| format!("invalid statement-set index: {error}"))?;
    let source: SourceIndex = serde_json::from_slice(&source_index_bytes)
        .map_err(|error| format!("invalid checkpoint source-set index: {error}"))?;
    validate_source_cadence(&source)?;
    if source.schema != SOURCE_INDEX_SCHEMA
        || statements.source_index_path != SOURCE_INDEX_LOGICAL_PATH
        || statements.source_index_sha256 != sha256(&source_index_bytes)
        || source.manifest_sha256 != block_plan.manifest_sha256
        || source.randomx_receipt_image_id != block_plan.randomx_receipt_image_id
        || source.previous_height != block_plan.previous_height
        || source.target_height != block_plan.target_height
        || source.confirmation_height != block_plan.confirmation_height
        || source.segment_count != block_plan.segment_count
        || source.segment_count != source.segments.len()
    {
        return Err("checkpoint source-set and receipt plan disagree".into());
    }
    validate_artifact(
        paths.aggregate_program,
        AGGREGATE_PROGRAM_SHA256,
        MAX_AGGREGATE_PROGRAM_BYTES,
    )?;
    let iid = validate_artifact(paths.aggregate_image_id, AGGREGATE_IMAGE_ID_FILE_SHA256, 65)?;
    if iid.as_slice() != format!("{AGGREGATE_IMAGE_ID}\n").as_bytes() {
        return Err("aggregate ImageID file content mismatch".into());
    }

    let mut jobs = Vec::with_capacity(source.segment_count);
    let mut first_receipt = 0usize;
    let mut expected_previous = source.previous_height;
    let mut target_boundary_seen = false;
    let mut expected_state: Option<CheckpointSegmentState> = None;
    let mut expected_genesis: Option<[u8; 32]> = None;
    for (index, segment) in source.segments.iter().enumerate() {
        validate_source_segment(&source, index, segment, expected_previous)?;
        if segment.next_height == source.target_height {
            if target_boundary_seen {
                return Err("checkpoint target boundary is duplicated".into());
            }
            target_boundary_seen = true;
        }
        let transition_bytes = read_direct_regular_file(
            &paths.source_directory.join(&segment.transition_file),
            CHECKPOINT_SEGMENT_TRANSITION_BYTES,
        )?;
        let private_bytes = Zeroizing::new(read_direct_regular_file(
            &paths.source_directory.join(&segment.private_input_file),
            MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
        )?);
        let policy_bytes = read_direct_regular_file(
            &paths.source_directory.join(&segment.policy_input_file),
            MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES,
        )?;
        let native_opening_bytes = read_direct_regular_file(
            &paths
                .source_directory
                .join(&segment.native_state_opening_file),
            MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES,
        )?;
        if sha256(&transition_bytes) != segment.transition_sha256
            || sha256(&private_bytes) != segment.private_input_sha256
            || sha256(&policy_bytes) != segment.policy_input_sha256
            || sha256(&native_opening_bytes) != segment.native_state_opening_sha256
        {
            return Err(format!("source component hash mismatch at segment {index}"));
        }
        let transition = CheckpointSegmentTransition::from_bytes(&transition_bytes)
            .map_err(|error| format!("invalid transition {index}: {error}"))?;
        let private = CheckpointSegmentPrivateInput::from_bytes(&private_bytes)
            .map_err(|error| format!("invalid private input {index}: {error}"))?;
        let policy = CheckpointSegmentPolicyInput::from_bytes(&policy_bytes)
            .map_err(|error| format!("invalid policy input {index}: {error}"))?;
        if transition.previous.height != segment.previous_height
            || transition.next.height != segment.next_height
            || transition.block_count != segment.block_count
            || transition.previous.randomx_receipt_image_id != inner_image_id
            || transition.next.randomx_receipt_image_id != inner_image_id
        {
            return Err(format!(
                "source transition index mismatch at segment {index}"
            ));
        }
        if expected_state.is_some_and(|state| state != transition.previous) {
            return Err(format!("source state chain mismatch at segment {index}"));
        }
        if expected_genesis.is_some_and(|genesis| genesis != *policy.dom_genesis_hash()) {
            return Err(format!("DOM genesis changed at segment {index}"));
        }
        let (aggregate, bindings) =
            checkpoint_segment_randomx_aggregate(&transition, &private, *policy.dom_genesis_hash())
                .map_err(|error| format!("cannot derive aggregate {index}: {error}"))?;
        if bindings.len() != usize::from(segment.block_count) {
            return Err(format!("binding count mismatch at segment {index}"));
        }
        let end = first_receipt
            .checked_add(bindings.len())
            .ok_or_else(|| format!("inner receipt range overflow at segment {index}"))?;
        let receipt_records = receipts
            .receipts
            .get(first_receipt..end)
            .ok_or_else(|| format!("inner receipt range missing for segment {index}"))?;
        for (binding, record) in bindings.iter().zip(receipt_records) {
            if record.segment_index != index
                || record.expected_journal != super::hex(binding.assumption().journal())
            {
                return Err(format!("inner receipt order mismatch at segment {index}"));
            }
        }
        jobs.push(AggregateJob {
            index,
            previous_height: segment.previous_height,
            next_height: segment.next_height,
            block_count: segment.block_count,
            transition_file: format!("evidence/checkpoint-source-set/{}", segment.transition_file),
            transition_sha256: segment.transition_sha256.clone(),
            private_input_file: format!(
                "evidence/checkpoint-source-set/{}",
                segment.private_input_file
            ),
            private_input_sha256: segment.private_input_sha256.clone(),
            dom_genesis_hash: super::hex(policy.dom_genesis_hash()),
            first_inner_receipt_index: first_receipt,
            inner_receipt_count: bindings.len(),
            inner_receipt_files: receipt_records
                .iter()
                .map(|record| record.receipt_file.clone())
                .collect(),
            inner_receipt_sha256: receipt_records
                .iter()
                .map(|record| record.receipt_sha256.clone())
                .collect(),
            expected_journal: super::hex(
                &aggregate
                    .commitment()
                    .map_err(|error| format!("cannot commit aggregate {index}: {error}"))?,
            ),
            aggregate_receipt_file: aggregate_receipt_name(index),
        });
        first_receipt = end;
        expected_previous = segment.next_height;
        expected_state = Some(transition.next);
        expected_genesis = Some(*policy.dom_genesis_hash());
    }
    if expected_previous != source.confirmation_height || !target_boundary_seen {
        return Err("source segments do not reach both required boundaries".into());
    }
    if first_receipt != receipts.receipt_count {
        return Err("source segments do not consume every inner receipt".into());
    }
    let index = AggregateJobIndex {
        schema: AGGREGATE_JOB_SCHEMA.into(),
        source_index_path: SOURCE_INDEX_LOGICAL_PATH.into(),
        source_index_sha256: sha256(&source_index_bytes),
        receipt_set_index_path: RECEIPT_INDEX_LOGICAL_PATH.into(),
        receipt_set_index_sha256: sha256(&receipt_index_bytes),
        manifest_sha256: block_plan.manifest_sha256,
        inner_randomx_image_id: block_plan.randomx_receipt_image_id,
        aggregate_program_path: AGGREGATE_PROGRAM_LOGICAL_PATH.into(),
        aggregate_program_sha256: AGGREGATE_PROGRAM_SHA256.into(),
        aggregate_image_id_path: AGGREGATE_IMAGE_ID_LOGICAL_PATH.into(),
        aggregate_image_id_file_sha256: AGGREGATE_IMAGE_ID_FILE_SHA256.into(),
        aggregate_image_id: AGGREGATE_IMAGE_ID.into(),
        risc0_zkvm_version: RISC0_VERSION.into(),
        receipt_kind: RECEIPT_KIND.into(),
        segment_count: source.segment_count,
        job_count: jobs.len(),
        executes_guest: false,
        generates_proofs: false,
        mines: false,
        jobs,
    };
    let mut bytes = serde_json::to_vec_pretty(&index)
        .map_err(|error| format!("cannot encode aggregate-job index: {error}"))?;
    bytes.push(b'\n');
    Ok((index, bytes, sha256(&receipt_index_bytes)))
}

/// Verify all inner receipts and atomically publish deterministic aggregate jobs.
pub fn publish_aggregate_plan(
    paths: &AggregatePlanPaths<'_>,
) -> Result<AggregatePlanSummary, String> {
    ensure_direct_directory(paths.output_directory)?;
    let (plan, bytes, receipt_set_index_sha256) = build_aggregate_plan(paths)?;
    let job_index_sha256 = sha256(&bytes);
    atomic_publish(
        &paths.output_directory.join(AGGREGATE_JOB_INDEX_NAME),
        &bytes,
    )?;
    Ok(AggregatePlanSummary {
        job_count: plan.job_count,
        receipt_set_index_sha256,
        job_index_sha256,
    })
}

/// Prove every aggregate job locally and publish a verified receipt-set index.
#[cfg(feature = "prove")]
pub fn prove_aggregate_set(
    paths: &AggregateProofPaths<'_>,
) -> Result<AggregateProofSummary, String> {
    use risc0_zkvm::{default_prover, ExecutorEnv, Prover, ProverOpts};

    require_local_prover_environment("RandomX aggregate proving")?;
    ensure_direct_directory(paths.output_directory)?;
    let (plan, rebuilt, _) = build_aggregate_plan(&paths.plan)?;
    let published = read_direct_regular_file(paths.job_index, MAX_INDEX_BYTES)?;
    if published != rebuilt {
        return Err("aggregate-job index differs from its exact rebuilt plan".into());
    }
    let program = validate_artifact(
        paths.plan.aggregate_program,
        AGGREGATE_PROGRAM_SHA256,
        MAX_AGGREGATE_PROGRAM_BYTES,
    )?;
    let aggregate_image_id = decode_hex_32(AGGREGATE_IMAGE_ID)?;
    let inner_image_id = decode_hex_32(&plan.inner_randomx_image_id)?;
    let prover = default_prover();
    if prover.get_name() != "local" {
        return Err("selected aggregate prover is not local".into());
    }
    let options = ProverOpts::succinct().with_dev_mode(false);
    let final_index = paths.output_directory.join(AGGREGATE_RECEIPT_INDEX_NAME);
    match fs::symlink_metadata(&final_index) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("aggregate receipt-set index is not a direct regular file".into());
            }
            remove_invalid_receipt(&final_index)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "cannot inspect aggregate receipt-set index: {error}"
            ));
        }
    }
    let receipt_set_bytes =
        read_direct_regular_file(paths.plan.receipt_set_index, MAX_INDEX_BYTES)?;
    let receipt_set: ReceiptSetIndex = serde_json::from_slice(&receipt_set_bytes)
        .map_err(|error| format!("invalid inner receipt index: {error}"))?;
    let mut records = Vec::with_capacity(plan.job_count);
    for job in &plan.jobs {
        let expected_journal = decode_hex_32(&job.expected_journal)?;
        let receipt_path = paths.output_directory.join(&job.aggregate_receipt_file);
        let existing = match fs::symlink_metadata(&receipt_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(format!(
                        "existing aggregate receipt {} is not a direct regular file",
                        receipt_path.display()
                    ));
                }
                let bytes = read_direct_regular_file(&receipt_path, MAX_RECEIPT_BYTES)?;
                if verify_receipt(&bytes, aggregate_image_id, expected_journal).is_ok() {
                    Some(bytes)
                } else {
                    remove_invalid_receipt(&receipt_path)?;
                    None
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(format!(
                    "cannot inspect existing aggregate receipt {}: {error}",
                    receipt_path.display()
                ));
            }
        };
        let encoded = if let Some(bytes) = existing {
            bytes
        } else {
            let transition = read_direct_regular_file(
                &paths
                    .plan
                    .source_directory
                    .join(source_name(job.index, "transition.bin")),
                CHECKPOINT_SEGMENT_TRANSITION_BYTES,
            )?;
            let private = read_direct_regular_file(
                &paths
                    .plan
                    .source_directory
                    .join(source_name(job.index, "private-input.bin")),
                MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
            )?;
            let mut builder = ExecutorEnv::builder();
            builder.write_slice(&transition);
            builder.write_slice(&decode_hex_32(&job.dom_genesis_hash)?);
            let private_len = u32::try_from(private.len())
                .map_err(|_| "aggregate private input length exceeds u32".to_string())?;
            builder
                .write(&private_len)
                .map_err(|error| format!("cannot encode aggregate length: {error}"))?;
            builder.write_slice(&private);
            let end = job
                .first_inner_receipt_index
                .checked_add(job.inner_receipt_count)
                .ok_or_else(|| format!("aggregate receipt range overflow at job {}", job.index))?;
            for record in receipt_set
                .receipts
                .get(job.first_inner_receipt_index..end)
                .ok_or_else(|| "aggregate inner receipt range is absent".to_string())?
            {
                let bytes = read_direct_regular_file(
                    &paths
                        .plan
                        .block_proof
                        .output_directory
                        .join(&record.receipt_file),
                    MAX_RECEIPT_BYTES,
                )?;
                let receipt = decode_verified_receipt(
                    &bytes,
                    inner_image_id,
                    decode_hex_32(&record.expected_journal)?,
                )?;
                builder.add_assumption(receipt);
            }
            let environment = builder
                .build()
                .map_err(|error| format!("cannot build aggregate job {}: {error}", job.index))?;
            let proof = prover
                .prove_with_opts(environment, &program, &options)
                .map_err(|error| format!("aggregate proof {} failed: {error}", job.index))?;
            let encoded = bincode::serialize(&proof.receipt).map_err(|error| {
                format!("cannot encode aggregate receipt {}: {error}", job.index)
            })?;
            if encoded.is_empty() || encoded.len() > MAX_RECEIPT_BYTES {
                return Err(format!(
                    "aggregate receipt {} is empty or exceeds its bound",
                    job.index
                ));
            }
            verify_receipt(&encoded, aggregate_image_id, expected_journal)?;
            atomic_publish(&receipt_path, &encoded)?;
            encoded
        };
        records.push(serde_json::json!({
            "index": job.index,
            "previous_height": job.previous_height,
            "next_height": job.next_height,
            "block_count": job.block_count,
            "expected_journal": job.expected_journal,
            "receipt_file": job.aggregate_receipt_file,
            "receipt_sha256": sha256(&encoded),
            "receipt_bytes": encoded.len()
        }));
    }
    let output = serde_json::json!({
        "schema": AGGREGATE_RECEIPT_SCHEMA,
        "aggregate_job_index_path": AGGREGATE_JOB_INDEX_LOGICAL_PATH,
        "aggregate_job_index_sha256": sha256(&published),
        "aggregate_image_id": AGGREGATE_IMAGE_ID,
        "risc0_zkvm_version": RISC0_VERSION,
        "receipt_kind": RECEIPT_KIND,
        "receipt_count": records.len(),
        "inner_receipts_verified": true,
        "aggregate_receipts_verified": true,
        "dev_mode": false,
        "generates_proofs": true,
        "mines": false,
        "receipts": records
    });
    let mut output_bytes = serde_json::to_vec_pretty(&output)
        .map_err(|error| format!("cannot encode aggregate receipt index: {error}"))?;
    output_bytes.push(b'\n');
    let receipt_index_sha256 = sha256(&output_bytes);
    atomic_publish(&final_index, &output_bytes)?;
    Ok(AggregateProofSummary {
        receipt_count: plan.job_count,
        job_index_sha256: sha256(&published),
        receipt_index_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::{validate_source_cadence, validate_source_segment, SourceIndex, SourceSegment};

    fn hash() -> String {
        "11".repeat(32)
    }

    fn source() -> SourceIndex {
        SourceIndex {
            schema: "usdom-canonical-checkpoint-source-set-v1".into(),
            manifest_sha256: hash(),
            randomx_receipt_image_id: hash(),
            checkpoint_interval_blocks: 10,
            checkpoint_confirmation_depth_blocks: 4,
            previous_height: 100,
            target_height: 110,
            confirmation_height: 114,
            segment_count: 1,
            segments: Vec::new(),
        }
    }

    fn segment(previous_height: u64, next_height: u64, block_count: u16) -> SourceSegment {
        SourceSegment {
            index: 0,
            previous_height,
            next_height,
            block_count,
            transition_file: "checkpoint-segment-0000-transition.bin".into(),
            transition_sha256: hash(),
            private_input_file: "checkpoint-segment-0000-private-input.bin".into(),
            private_input_sha256: hash(),
            policy_input_file: "checkpoint-segment-0000-policy-input.bin".into(),
            policy_input_sha256: hash(),
            native_state_opening_file: "checkpoint-segment-0000-native-state-opening.bin".into(),
            native_state_opening_sha256: hash(),
        }
    }

    #[test]
    fn source_boundaries_reject_underflow_and_target_crossing() {
        let valid = source();
        assert!(validate_source_cadence(&valid).is_ok());
        assert!(validate_source_segment(&valid, 0, &segment(100, 110, 10), 100).is_ok());

        let mut underflow = source();
        underflow.previous_height = u64::MAX;
        assert!(validate_source_cadence(&underflow).is_err());
        assert!(validate_source_segment(&valid, 0, &segment(110, 100, 10), 110).is_err());
        assert!(validate_source_segment(&valid, 0, &segment(100, 111, 11), 100).is_err());
    }
}
