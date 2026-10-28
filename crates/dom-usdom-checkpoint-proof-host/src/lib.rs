//! Authenticated, deterministic planning for complete checkpoint-segment proof jobs.

#![deny(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "verify")]
mod verified {
    use std::fs;
    use std::path::Path;
    use zeroize::Zeroizing;

    use bincode::Options;
    use dom_usdom_checkpoint_program::{
        derive_checkpoint_statement_v6, execute_checkpoint_segment_portable,
        validate_checkpoint_outer_chain_v6, CheckpointOuterChain,
        CheckpointSegmentNativeStateOpening, CheckpointSegmentPolicyInput,
        CheckpointSegmentPrivateInput, CheckpointSegmentTransition,
        CHECKPOINT_SEGMENT_TRANSITION_BYTES, CHECKPOINT_STATEMENT_V6_BYTES,
        MAX_CHECKPOINT_OUTER_CHAIN_BYTES, MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES,
        MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES, MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
    };
    use dom_wallet_crypto::{read_captured_bytes, save_private_bytes};
    use risc0_zkvm::{sha::Digest as Risc0Digest, InnerReceipt, Receipt};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    const SOURCE_SCHEMA: &str = "usdom-canonical-checkpoint-source-set-v1";
    const RANDOMX_RECEIPT_SCHEMA: &str = "usdom-randomx-receipt-set-v1";
    const ECONOMIC_RECEIPT_SCHEMA: &str = "usdom-economic-receipt-set-v1";
    const JOB_SCHEMA: &str = "usdom-checkpoint-segment-proof-job-set-v1";
    const SOURCE_INDEX_LOGICAL_PATH: &str =
        "evidence/checkpoint-source-set/checkpoint-source-set-index.json";
    const RANDOMX_JOB_INDEX_LOGICAL_PATH: &str =
        "evidence/randomx-proof-jobs/randomx-proof-job-index.json";
    const RANDOMX_RECEIPT_INDEX_LOGICAL_PATH: &str =
        "evidence/randomx-receipt-set/randomx-receipt-set-index.json";
    const ECONOMIC_JOB_INDEX_LOGICAL_PATH: &str =
        "evidence/economic-proof-jobs/economic-proof-job-index.json";
    const ECONOMIC_RECEIPT_INDEX_LOGICAL_PATH: &str =
        "evidence/economic-receipt-set/economic-receipt-set-index.json";
    const SEGMENT_ELF_LOGICAL_PATH: &str =
        "../../crates/dom-usdom-checkpoint-segment-risc0-guest/elfs/usdom-checkpoint-segment.elf";
    const SEGMENT_PROGRAM_LOGICAL_PATH: &str =
        "../../crates/dom-usdom-checkpoint-segment-risc0-guest/elfs/usdom-checkpoint-segment.bin";
    const SEGMENT_IMAGE_ID_LOGICAL_PATH: &str =
        "../../crates/dom-usdom-checkpoint-segment-risc0-guest/elfs/usdom-checkpoint-segment.iid";
    const SEGMENT_ELF_SHA256: &str =
        "5f4d087842d61a463a93242c88efa6ff3c54b52a4e176b1b9a225cc2a8ee7092";
    const SEGMENT_PROGRAM_SHA256: &str =
        "426cc782490b8d680e5bd2266cc4a03b3e731194d92eda44875ea5d552cb5f74";
    const SEGMENT_IMAGE_ID_FILE_SHA256: &str =
        "49e779070bbbc97ac88b39c4dfee8250b08864cf10be1d8c35d9598271e1f173";
    const SEGMENT_IMAGE_ID: &str =
        "371e408b360a0e4a0aae2cb994bddb2d66afcc5891a7ed574fa83119734bfbf7";
    const ECONOMIC_BLOCK_IMAGE_ID: &str =
        "03dc111fee3c42a772f142c80d4a921a19bde10f932f86c888606503a28c22a7";
    const RISC0_VERSION: &str = "3.0.6";
    const RECEIPT_KIND: &str = "succinct";
    const JOB_INDEX_NAME: &str = "checkpoint-segment-proof-job-index.json";
    const JOB_INDEX_LOGICAL_PATH: &str =
        "evidence/checkpoint-segment-proof-jobs/checkpoint-segment-proof-job-index.json";
    const SEGMENT_RECEIPT_INDEX_LOGICAL_PATH: &str =
        "evidence/checkpoint-segment-receipt-set/checkpoint-segment-receipt-set-index.json";
    const SEGMENT_RECEIPT_SCHEMA: &str = "usdom-checkpoint-segment-receipt-set-v1";
    const OUTER_JOB_SCHEMA: &str = "usdom-checkpoint-outer-proof-job-v1";
    const OUTER_ELF_LOGICAL_PATH: &str =
        "../../crates/dom-usdom-checkpoint-outer-risc0-guest/elfs/usdom-checkpoint-outer.elf";
    const OUTER_PROGRAM_LOGICAL_PATH: &str =
        "../../crates/dom-usdom-checkpoint-outer-risc0-guest/elfs/usdom-checkpoint-outer.bin";
    const OUTER_IMAGE_ID_LOGICAL_PATH: &str =
        "../../crates/dom-usdom-checkpoint-outer-risc0-guest/elfs/usdom-checkpoint-outer.iid";
    const OUTER_ELF_SHA256: &str =
        "9dff25635234da9d769fb1ac43896d15e799c3b2b1b4589cab94eb7a5ad4f69b";
    const OUTER_PROGRAM_SHA256: &str =
        "ee707b6a1d2a135656ef9ee93a13487b6e1c24bafba8c66e9215708e184b9a90";
    const OUTER_IMAGE_ID_FILE_SHA256: &str =
        "1c16479dbea87ff3dd6e452f68a54761c85bd03684f7566aca61c45135787218";
    const OUTER_IMAGE_ID: &str = "311d58dadcb97cac783e3ec0efe3c4570f42b944cbda1e48aeb56b055682257b";
    const OUTER_JOB_INDEX_NAME: &str = "checkpoint-outer-proof-job-index.json";
    #[cfg(feature = "prove")]
    const OUTER_JOB_INDEX_LOGICAL_PATH: &str =
        "evidence/checkpoint-outer-proof-job/checkpoint-outer-proof-job-index.json";
    const OUTER_STATEMENT_NAME: &str = "checkpoint-statement-v6.bin";
    const OUTER_CHAIN_NAME: &str = "checkpoint-outer-chain.bin";
    #[cfg(feature = "prove")]
    const OUTER_RECEIPT_INDEX_NAME: &str = "checkpoint-outer-receipt-set-index.json";
    #[cfg(feature = "prove")]
    const OUTER_RECEIPT_INDEX_LOGICAL_PATH: &str =
        "evidence/checkpoint-outer-receipt-set/checkpoint-outer-receipt-set-index.json";
    #[cfg(feature = "prove")]
    const GROTH16_VERIFIER_PARAMETERS: &str =
        "73c457ba541936f0d907daf0c7253a39a9c5c427c225ba7709e44702d3c6eedc";
    #[cfg(feature = "prove")]
    const EVM_SEAL_SELECTOR: [u8; 4] = [0x73, 0xc4, 0x57, 0xba];
    #[cfg(feature = "prove")]
    const EVM_SEAL_BYTES: usize = 4 + 8 * 32;
    #[cfg(feature = "prove")]
    const OUTER_EVM_PACKAGE_INDEX_NAME: &str = "checkpoint-outer-evm-proof-index.json";
    #[cfg(feature = "prove")]
    const RECEIPT_INDEX_NAME: &str = "checkpoint-segment-receipt-set-index.json";
    const MAX_INDEX_BYTES: usize = 64 * 1024 * 1024;
    const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
    const MAX_RECEIPT_BYTES: usize = 256 * 1024 * 1024;
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

    /// Fixed authenticated inputs and output for checkpoint-segment planning.
    pub struct SegmentPlanPaths<'a> {
        /// Canonical checkpoint source-set index.
        pub source_index: &'a Path,
        /// Directory containing canonical segment sources.
        pub source_directory: &'a Path,
        /// Published authenticated RandomX job index.
        pub randomx_job_index: &'a Path,
        /// Verified per-block RandomX receipt-set index.
        pub randomx_receipt_index: &'a Path,
        /// Directory containing per-block RandomX receipts.
        pub randomx_receipt_directory: &'a Path,
        /// Published authenticated economic job index.
        pub economic_job_index: &'a Path,
        /// Verified economic receipt-set index.
        pub economic_receipt_index: &'a Path,
        /// Directory containing economic block receipts.
        pub economic_receipt_directory: &'a Path,
        /// Pinned complete-segment guest ELF.
        pub segment_elf: &'a Path,
        /// Pinned complete-segment ProgramBinary.
        pub segment_program: &'a Path,
        /// Pinned complete-segment ImageID file.
        pub segment_image_id: &'a Path,
        /// Directory receiving the deterministic segment-job index.
        pub output_directory: &'a Path,
    }

    impl SegmentPlanPaths<'static> {
        /// Production paths relative to the reserve laboratory root.
        pub fn production() -> Self {
            Self {
                source_index: Path::new(SOURCE_INDEX_LOGICAL_PATH),
                source_directory: Path::new("evidence/checkpoint-source-set"),
                randomx_job_index: Path::new(RANDOMX_JOB_INDEX_LOGICAL_PATH),
                randomx_receipt_index: Path::new(RANDOMX_RECEIPT_INDEX_LOGICAL_PATH),
                randomx_receipt_directory: Path::new("evidence/randomx-receipt-set"),
                economic_job_index: Path::new(ECONOMIC_JOB_INDEX_LOGICAL_PATH),
                economic_receipt_index: Path::new(ECONOMIC_RECEIPT_INDEX_LOGICAL_PATH),
                economic_receipt_directory: Path::new("evidence/economic-receipt-set"),
                segment_elf: Path::new(SEGMENT_ELF_LOGICAL_PATH),
                segment_program: Path::new(SEGMENT_PROGRAM_LOGICAL_PATH),
                segment_image_id: Path::new(SEGMENT_IMAGE_ID_LOGICAL_PATH),
                output_directory: Path::new("evidence/checkpoint-segment-proof-jobs"),
            }
        }
    }

    /// Fixed inputs and output for explicitly authorized local segment proving.
    #[cfg(feature = "prove")]
    pub struct SegmentProofPaths<'a> {
        /// Inputs used to rebuild the exact authenticated segment plan.
        pub plan: SegmentPlanPaths<'a>,
        /// Published job index, required to equal the rebuilt plan byte for byte.
        pub job_index: &'a Path,
        /// Directory receiving verified segment receipts and their final index.
        pub output_directory: &'a Path,
    }

    #[cfg(feature = "prove")]
    impl SegmentProofPaths<'static> {
        /// Production paths relative to the reserve laboratory root.
        pub fn production() -> Self {
            Self {
                plan: SegmentPlanPaths::production(),
                job_index: Path::new(JOB_INDEX_LOGICAL_PATH),
                output_directory: Path::new("evidence/checkpoint-segment-receipt-set"),
            }
        }
    }

    /// Observable result after all segment receipts are proved and verified.
    #[cfg(feature = "prove")]
    pub struct SegmentProofSummary {
        /// Number of verified complete-segment receipts.
        pub segment_receipt_count: usize,
        /// SHA-256 of the exact consumed segment-job index.
        pub job_index_sha256: String,
        /// SHA-256 of the published segment receipt-set index.
        pub receipt_index_sha256: String,
    }

    /// Observable result of authenticated checkpoint-segment planning.
    pub struct SegmentPlanSummary {
        /// Number of bounded complete-segment jobs.
        pub segment_job_count: usize,
        /// SHA-256 of the canonical source-set index.
        pub source_index_sha256: String,
        /// SHA-256 of the verified RandomX receipt-set index.
        pub randomx_receipt_index_sha256: String,
        /// SHA-256 of the verified economic receipt-set index.
        pub economic_receipt_index_sha256: String,
        /// SHA-256 of the published deterministic job index.
        pub job_index_sha256: String,
    }

    /// Fixed authenticated inputs and outputs for outer-checkpoint planning.
    pub struct OuterPlanPaths<'a> {
        /// Inputs used to rebuild the exact authenticated segment plan.
        pub segment_plan: SegmentPlanPaths<'a>,
        /// Published segment job index required to equal the rebuilt plan.
        pub segment_job_index: &'a Path,
        /// Verified complete-segment receipt-set index.
        pub segment_receipt_index: &'a Path,
        /// Directory containing complete-segment receipts.
        pub segment_receipt_directory: &'a Path,
        /// Pinned outer guest ELF.
        pub outer_elf: &'a Path,
        /// Pinned outer guest ProgramBinary.
        pub outer_program: &'a Path,
        /// Pinned outer guest ImageID file.
        pub outer_image_id: &'a Path,
        /// Directory receiving the statement, chain and deterministic job index.
        pub output_directory: &'a Path,
    }

    impl OuterPlanPaths<'static> {
        /// Production paths relative to the reserve laboratory root.
        pub fn production() -> Self {
            Self {
                segment_plan: SegmentPlanPaths::production(),
                segment_job_index: Path::new(JOB_INDEX_LOGICAL_PATH),
                segment_receipt_index: Path::new(SEGMENT_RECEIPT_INDEX_LOGICAL_PATH),
                segment_receipt_directory: Path::new("evidence/checkpoint-segment-receipt-set"),
                outer_elf: Path::new(OUTER_ELF_LOGICAL_PATH),
                outer_program: Path::new(OUTER_PROGRAM_LOGICAL_PATH),
                outer_image_id: Path::new(OUTER_IMAGE_ID_LOGICAL_PATH),
                output_directory: Path::new("evidence/checkpoint-outer-proof-job"),
            }
        }
    }

    /// Observable result of authenticated outer-checkpoint planning.
    pub struct OuterPlanSummary {
        /// Number of verified complete-segment receipt assumptions.
        pub segment_receipt_count: usize,
        /// Solidity-compatible hash committed by the planned outer proof.
        pub statement_hash: String,
        /// SHA-256 of the published deterministic outer-job index.
        pub job_index_sha256: String,
    }

    /// Fixed inputs and output for explicitly authorized local outer proving.
    #[cfg(feature = "prove")]
    pub struct OuterProofPaths<'a> {
        /// Inputs used to rebuild the exact authenticated outer plan.
        pub plan: OuterPlanPaths<'a>,
        /// Published outer proof-job index.
        pub job_index: &'a Path,
        /// Published canonical V6 statement.
        pub statement: &'a Path,
        /// Published canonical outer transition chain.
        pub chain: &'a Path,
        /// Directory receiving the verified outer receipt and final index.
        pub output_directory: &'a Path,
    }

    #[cfg(feature = "prove")]
    impl OuterProofPaths<'static> {
        /// Production paths relative to the reserve laboratory root.
        pub fn production() -> Self {
            Self {
                plan: OuterPlanPaths::production(),
                job_index: Path::new(OUTER_JOB_INDEX_LOGICAL_PATH),
                statement: Path::new(
                    "evidence/checkpoint-outer-proof-job/checkpoint-statement-v6.bin",
                ),
                chain: Path::new("evidence/checkpoint-outer-proof-job/checkpoint-outer-chain.bin"),
                output_directory: Path::new("evidence/checkpoint-outer-receipt-set"),
            }
        }
    }

    /// Observable result after the outer receipt is proved and verified.
    #[cfg(feature = "prove")]
    pub struct OuterProofSummary {
        /// Solidity-compatible checkpoint statement hash committed by the receipt.
        pub statement_hash: String,
        /// SHA-256 of the exact consumed outer job index.
        pub job_index_sha256: String,
        /// SHA-256 of the published outer receipt-set index.
        pub receipt_index_sha256: String,
    }

    /// Fixed inputs and output for explicitly authorized local STARK-to-SNARK
    /// compression and EVM seal packaging.
    #[cfg(feature = "prove")]
    pub struct OuterEvmProofPaths<'a> {
        /// Inputs used to rebuild the authenticated outer proof job.
        pub outer_proof: OuterProofPaths<'a>,
        /// Published verified outer receipt-set index.
        pub receipt_index: &'a Path,
        /// Directory containing the succinct outer receipt.
        pub receipt_directory: &'a Path,
        /// Directory receiving the Groth16 receipt, EVM seal and package index.
        pub output_directory: &'a Path,
    }

    #[cfg(feature = "prove")]
    impl OuterEvmProofPaths<'static> {
        /// Production paths relative to the reserve laboratory root.
        pub fn production() -> Self {
            Self {
                outer_proof: OuterProofPaths::production(),
                receipt_index: Path::new(OUTER_RECEIPT_INDEX_LOGICAL_PATH),
                receipt_directory: Path::new("evidence/checkpoint-outer-receipt-set"),
                output_directory: Path::new("evidence/checkpoint-outer-evm-proof"),
            }
        }
    }

    /// Observable result of local Groth16 compression and EVM seal packaging.
    #[cfg(feature = "prove")]
    pub struct OuterEvmProofSummary {
        /// Solidity-compatible checkpoint statement hash committed by the proof.
        pub statement_hash: String,
        /// SHA-256 of the exact EVM seal bytes.
        pub evm_seal_sha256: String,
        /// SHA-256 of the published EVM proof package index.
        pub package_index_sha256: String,
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

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RandomxReceiptIndex {
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
        receipts: Vec<RandomxReceiptRecord>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RandomxReceiptRecord {
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
    struct EconomicReceiptIndex {
        schema: String,
        proof_job_index_path: String,
        proof_job_index_sha256: String,
        chunk_image_id: String,
        block_image_id: String,
        risc0_zkvm_version: String,
        receipt_kind: String,
        chunk_receipt_count: usize,
        block_receipt_count: usize,
        chunk_proving_wall_milliseconds: u64,
        chunk_peak_resident_kib: u64,
        block_proving_wall_milliseconds: u64,
        block_peak_resident_kib: u64,
        chunk_receipts_verified: bool,
        block_receipts_verified: bool,
        dev_mode: bool,
        generates_proofs: bool,
        mines: bool,
        chunk_receipts: Vec<EconomicChunkReceiptRecord>,
        block_receipts: Vec<EconomicBlockReceiptRecord>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EconomicChunkReceiptRecord {
        index: usize,
        segment_index: usize,
        block_index: usize,
        chunk_index: usize,
        block_height: u64,
        expected_journal: String,
        receipt_file: String,
        receipt_sha256: String,
        receipt_bytes: usize,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EconomicBlockReceiptRecord {
        index: usize,
        segment_index: usize,
        block_index: usize,
        block_height: u64,
        expected_journal: String,
        receipt_file: String,
        receipt_sha256: String,
        receipt_bytes: usize,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct SegmentJobIndex {
        schema: String,
        source_index_path: String,
        source_index_sha256: String,
        randomx_job_index_path: String,
        randomx_job_index_sha256: String,
        randomx_receipt_index_path: String,
        randomx_receipt_index_sha256: String,
        economic_job_index_path: String,
        economic_job_index_sha256: String,
        economic_receipt_index_path: String,
        economic_receipt_index_sha256: String,
        manifest_sha256: String,
        randomx_image_id: String,
        economic_block_image_id: String,
        segment_user_elf_path: String,
        segment_user_elf_sha256: String,
        segment_program_path: String,
        segment_program_sha256: String,
        segment_image_id_path: String,
        segment_image_id_file_sha256: String,
        segment_image_id: String,
        risc0_zkvm_version: String,
        receipt_kind: String,
        previous_height: u64,
        target_height: u64,
        confirmation_height: u64,
        segment_job_count: usize,
        randomx_receipt_count: usize,
        economic_block_receipt_count: usize,
        executes_guests: bool,
        generates_proofs: bool,
        mines: bool,
        jobs: Vec<SegmentJob>,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct SegmentJob {
        index: usize,
        previous_height: u64,
        next_height: u64,
        block_count: u16,
        transition_file: String,
        transition_sha256: String,
        policy_input_file: String,
        policy_input_sha256: String,
        native_state_opening_file: String,
        native_state_opening_sha256: String,
        private_input_file: String,
        private_input_sha256: String,
        expected_journal: String,
        randomx_receipts: Vec<InnerReceiptRecord>,
        economic_block_receipts: Vec<InnerReceiptRecord>,
        receipt_file: String,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct InnerReceiptRecord {
        block_index: usize,
        block_height: u64,
        expected_journal: String,
        receipt_file: String,
        receipt_sha256: String,
        receipt_bytes: usize,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SegmentReceiptIndex {
        schema: String,
        proof_job_index_path: String,
        proof_job_index_sha256: String,
        segment_image_id: String,
        risc0_zkvm_version: String,
        receipt_kind: String,
        receipt_count: usize,
        inner_receipts_verified: bool,
        segment_receipts_verified: bool,
        dev_mode: bool,
        generates_proofs: bool,
        mines: bool,
        receipts: Vec<SegmentReceiptRecord>,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct SegmentReceiptRecord {
        index: usize,
        previous_height: u64,
        next_height: u64,
        block_count: u16,
        expected_journal: String,
        receipt_file: String,
        receipt_sha256: String,
        receipt_bytes: usize,
    }

    #[cfg(feature = "prove")]
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OuterReceiptIndex {
        schema: String,
        proof_job_index_path: String,
        proof_job_index_sha256: String,
        outer_image_id: String,
        statement_hash: String,
        risc0_zkvm_version: String,
        receipt_kind: String,
        segment_receipt_count: usize,
        segment_receipts_verified: bool,
        outer_receipt_verified: bool,
        dev_mode: bool,
        generates_proofs: bool,
        mines: bool,
        receipt_file: String,
        receipt_sha256: String,
        receipt_bytes: usize,
    }

    #[derive(Serialize)]
    struct OuterJobIndex {
        schema: String,
        source_index_path: String,
        source_index_sha256: String,
        segment_job_index_path: String,
        segment_job_index_sha256: String,
        segment_receipt_index_path: String,
        segment_receipt_index_sha256: String,
        segment_image_id: String,
        outer_user_elf_path: String,
        outer_user_elf_sha256: String,
        outer_program_path: String,
        outer_program_sha256: String,
        outer_image_id_path: String,
        outer_image_id_file_sha256: String,
        outer_image_id: String,
        risc0_zkvm_version: String,
        receipt_kind: String,
        previous_height: u64,
        target_height: u64,
        confirmation_height: u64,
        statement_file: String,
        statement_sha256: String,
        statement_hash: String,
        chain_file: String,
        chain_sha256: String,
        segment_receipt_count: usize,
        segment_receipts_verified: bool,
        executes_guests: bool,
        generates_proofs: bool,
        mines: bool,
        segment_receipts: Vec<SegmentReceiptRecord>,
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

    fn nonzero_hash(value: &str) -> bool {
        canonical_hash(value) && value != "0".repeat(64)
    }

    fn decode_hash(value: &str) -> Result<[u8; 32], String> {
        // Every caller uses this value as cryptographic authority (ImageID or
        // journal/statement commitment).  An all-zero value is syntactically
        // valid hex but can only represent an uninitialized/default binding,
        // never an authorized checkpoint artifact.
        if !nonzero_hash(value) {
            return Err("invalid canonical nonzero hash".into());
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

    fn direct_directory(path: &Path) -> Result<(), String> {
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

    fn checked_source(
        directory: &Path,
        actual_name: &str,
        expected_name: &str,
        expected_hash: &str,
        maximum: usize,
    ) -> Result<Vec<u8>, String> {
        if actual_name != expected_name || !canonical_hash(expected_hash) {
            return Err(format!("noncanonical source record {actual_name:?}"));
        }
        let bytes = read_direct(&directory.join(actual_name), maximum)?;
        if sha256(&bytes) != expected_hash {
            return Err(format!("source hash mismatch: {actual_name}"));
        }
        Ok(bytes)
    }

    fn checked_artifact(path: &Path, expected_hash: &str, maximum: usize) -> Result<(), String> {
        if sha256(&read_direct(path, maximum)?) != expected_hash {
            return Err(format!("pinned artifact hash mismatch: {}", path.display()));
        }
        Ok(())
    }

    fn read_unchanged(
        path: &Path,
        maximum: usize,
        expected_hash: &str,
        label: &str,
    ) -> Result<Vec<u8>, String> {
        let bytes = read_direct(path, maximum)?;
        if sha256(&bytes) != expected_hash {
            return Err(format!("{label} changed after plan rebuild"));
        }
        Ok(bytes)
    }

    fn decode_verified_receipt(
        bytes: &[u8],
        name: &str,
        image_id: [u8; 32],
        journal: [u8; 32],
    ) -> Result<Receipt, String> {
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
            return Err(format!("receipt byte length is outside bounds: {name}"));
        }
        let receipt: Receipt = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .with_limit(MAX_RECEIPT_BYTES as u64)
            .deserialize(bytes)
            .map_err(|error| format!("cannot decode receipt {name}: {error}"))?;
        if bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&receipt)
            .map_err(|error| format!("cannot canonically encode receipt {name}: {error}"))?
            != bytes
        {
            return Err(format!("receipt is not canonically encoded: {name}"));
        }
        if !matches!(receipt.inner, InnerReceipt::Succinct(_)) {
            return Err(format!("receipt is not succinct: {name}"));
        }
        if receipt.journal.bytes.as_slice() != journal {
            return Err(format!("receipt journal mismatch: {name}"));
        }
        receipt
            .verify(Risc0Digest::from(image_id))
            .map_err(|error| format!("receipt verification failed for {name}: {error}"))?;
        Ok(receipt)
    }

    /// Opens a bounded direct receipt, checks its pinned hash, canonical
    /// encoding, exact journal and ImageID, then performs RISC Zero
    /// cryptographic verification without writing any artifact.
    pub fn verify_rebuild_receipt(
        path: &Path,
        expected_sha256: &str,
        image_id: &str,
        journal: &str,
    ) -> Result<usize, String> {
        if !nonzero_hash(expected_sha256) {
            return Err("receipt SHA-256 is not canonical".into());
        }
        let bytes = read_direct(path, MAX_RECEIPT_BYTES)?;
        if sha256(&bytes) != expected_sha256 {
            return Err("receipt SHA-256 mismatch".into());
        }
        decode_verified_receipt(
            &bytes,
            &path.display().to_string(),
            decode_hash(image_id)?,
            decode_hash(journal)?,
        )?;
        Ok(bytes.len())
    }

    #[cfg(feature = "prove")]
    fn decode_verified_groth16_receipt(
        bytes: &[u8],
        name: &str,
        image_id: [u8; 32],
        journal: [u8; 32],
    ) -> Result<Receipt, String> {
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
            return Err(format!(
                "Groth16 receipt byte length is outside bounds: {name}"
            ));
        }
        let receipt: Receipt = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .with_limit(MAX_RECEIPT_BYTES as u64)
            .deserialize(bytes)
            .map_err(|error| format!("cannot decode Groth16 receipt {name}: {error}"))?;
        if bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&receipt)
            .map_err(|error| format!("cannot canonically encode Groth16 receipt {name}: {error}"))?
            != bytes
        {
            return Err(format!(
                "Groth16 receipt is not canonically encoded: {name}"
            ));
        }
        let groth16 = match &receipt.inner {
            InnerReceipt::Groth16(inner) => inner,
            _ => return Err(format!("receipt is not Groth16: {name}")),
        };
        if hex(groth16.verifier_parameters.as_bytes()) != GROTH16_VERIFIER_PARAMETERS {
            return Err(format!("Groth16 verifier parameters mismatch: {name}"));
        }
        if receipt.journal.bytes.as_slice() != journal {
            return Err(format!("Groth16 receipt journal mismatch: {name}"));
        }
        receipt
            .verify(Risc0Digest::from(image_id))
            .map_err(|error| format!("Groth16 receipt verification failed for {name}: {error}"))?;
        Ok(receipt)
    }

    fn verify_receipt_file(
        directory: &Path,
        name: &str,
        expected_name: &str,
        expected_hash: &str,
        expected_bytes: usize,
        image_id: [u8; 32],
        journal: [u8; 32],
    ) -> Result<Receipt, String> {
        if name != expected_name
            || !nonzero_hash(expected_hash)
            || expected_bytes == 0
            || expected_bytes > MAX_RECEIPT_BYTES
        {
            return Err(format!("invalid receipt record {name:?}"));
        }
        let bytes = read_direct(&directory.join(name), MAX_RECEIPT_BYTES)?;
        if bytes.len() != expected_bytes || sha256(&bytes) != expected_hash {
            return Err(format!("receipt file mismatch: {name}"));
        }
        decode_verified_receipt(&bytes, name, image_id, journal)
    }

    fn atomic_publish(path: &Path, bytes: &[u8]) -> Result<(), String> {
        save_private_bytes(path, bytes)
            .map_err(|error| format!("cannot publish {}: {error}", path.display()))
    }

    #[allow(clippy::too_many_lines)]
    fn build_plan(paths: &SegmentPlanPaths<'_>) -> Result<(SegmentJobIndex, Vec<u8>), String> {
        direct_directory(paths.source_directory)?;
        direct_directory(paths.randomx_receipt_directory)?;
        direct_directory(paths.economic_receipt_directory)?;
        checked_artifact(paths.segment_elf, SEGMENT_ELF_SHA256, MAX_ARTIFACT_BYTES)?;
        checked_artifact(
            paths.segment_program,
            SEGMENT_PROGRAM_SHA256,
            MAX_ARTIFACT_BYTES,
        )?;
        let image_id_file = read_direct(paths.segment_image_id, 128)?;
        if sha256(&image_id_file) != SEGMENT_IMAGE_ID_FILE_SHA256
            || image_id_file != format!("{SEGMENT_IMAGE_ID}\n").as_bytes()
        {
            return Err("pinned segment ImageID mismatch".into());
        }

        let source_bytes = read_direct(paths.source_index, MAX_INDEX_BYTES)?;
        let source: SourceIndex = serde_json::from_slice(&source_bytes)
            .map_err(|error| format!("invalid source-set index: {error}"))?;
        if source.schema != SOURCE_SCHEMA
            || !nonzero_hash(&source.manifest_sha256)
            || !nonzero_hash(&source.randomx_receipt_image_id)
            || source.segment_count == 0
            || source.segment_count > MAX_BLOCKS
            || source.segment_count != source.segments.len()
            || source.checkpoint_interval_blocks == 0
            || source.checkpoint_confirmation_depth_blocks == 0
            || source.checkpoint_confirmation_depth_blocks > source.checkpoint_interval_blocks
            || source.target_height.checked_sub(source.previous_height)
                != Some(u64::from(source.checkpoint_interval_blocks))
            || source.confirmation_height.checked_sub(source.target_height)
                != Some(u64::from(source.checkpoint_confirmation_depth_blocks))
        {
            return Err("invalid checkpoint source-set identity or cadence".into());
        }

        let randomx_job_bytes = read_direct(paths.randomx_job_index, MAX_INDEX_BYTES)?;
        let randomx_receipt_bytes = read_direct(paths.randomx_receipt_index, MAX_INDEX_BYTES)?;
        let randomx: RandomxReceiptIndex = serde_json::from_slice(&randomx_receipt_bytes)
            .map_err(|error| format!("invalid RandomX receipt index: {error}"))?;
        if randomx.schema != RANDOMX_RECEIPT_SCHEMA
            || randomx.proof_job_index_path != RANDOMX_JOB_INDEX_LOGICAL_PATH
            || randomx.proof_job_index_sha256 != sha256(&randomx_job_bytes)
            || randomx.manifest_sha256 != source.manifest_sha256
            || randomx.randomx_receipt_image_id != source.randomx_receipt_image_id
            || !nonzero_hash(&randomx.randomx_user_elf_sha256)
            || randomx.risc0_zkvm_version != RISC0_VERSION
            || randomx.receipt_kind != RECEIPT_KIND
            || randomx.previous_height != source.previous_height
            || randomx.target_height != source.target_height
            || randomx.confirmation_height != source.confirmation_height
            || randomx.segment_count != source.segment_count
            || randomx.receipt_count == 0
            || randomx.receipt_count > MAX_BLOCKS
            || randomx.receipt_count != randomx.receipts.len()
            || !randomx.randomx_relations_executed
            || !randomx.receipts_verified
            || randomx.dev_mode
            || !randomx.generates_proofs
            || randomx.mines
        {
            return Err("invalid RandomX receipt-set identity or claims".into());
        }

        let economic_job_bytes = read_direct(paths.economic_job_index, MAX_INDEX_BYTES)?;
        let economic_receipt_bytes = read_direct(paths.economic_receipt_index, MAX_INDEX_BYTES)?;
        let economic: EconomicReceiptIndex = serde_json::from_slice(&economic_receipt_bytes)
            .map_err(|error| format!("invalid economic receipt index: {error}"))?;
        if economic.schema != ECONOMIC_RECEIPT_SCHEMA
            || economic.proof_job_index_path != ECONOMIC_JOB_INDEX_LOGICAL_PATH
            || economic.proof_job_index_sha256 != sha256(&economic_job_bytes)
            || !nonzero_hash(&economic.chunk_image_id)
            || economic.block_image_id != ECONOMIC_BLOCK_IMAGE_ID
            || economic.risc0_zkvm_version != RISC0_VERSION
            || economic.receipt_kind != RECEIPT_KIND
            || economic.chunk_receipt_count == 0
            || economic.chunk_receipt_count != economic.chunk_receipts.len()
            || economic.block_receipt_count == 0
            || economic.block_receipt_count > MAX_BLOCKS
            || economic.block_receipt_count != economic.block_receipts.len()
            || economic.chunk_proving_wall_milliseconds == 0
            || economic.chunk_proving_wall_milliseconds > 30 * 24 * 60 * 60 * 1000
            || economic.block_proving_wall_milliseconds == 0
            || economic.block_proving_wall_milliseconds > 30 * 24 * 60 * 60 * 1000
            || economic.chunk_peak_resident_kib == 0
            || economic.chunk_peak_resident_kib > 64 * 1024 * 1024
            || economic.block_peak_resident_kib == 0
            || economic.block_peak_resident_kib > 64 * 1024 * 1024
            || !economic.chunk_receipts_verified
            || !economic.block_receipts_verified
            || economic.dev_mode
            || !economic.generates_proofs
            || economic.mines
        {
            return Err("invalid economic receipt-set identity or claims".into());
        }
        for (index, record) in economic.chunk_receipts.iter().enumerate() {
            if record.index != index
                || record.receipt_file != format!("economic-chunk-receipt-{index:04}.bin")
                || record.segment_index >= source.segment_count
                || record.block_index >= 32
                || record.chunk_index >= economic.chunk_receipt_count
                || record.block_height <= source.previous_height
                || !nonzero_hash(&record.expected_journal)
                || !nonzero_hash(&record.receipt_sha256)
                || record.receipt_bytes == 0
                || record.receipt_bytes > MAX_RECEIPT_BYTES
            {
                return Err(format!("invalid economic chunk receipt record {index}"));
            }
        }

        let randomx_image_id = decode_hash(&source.randomx_receipt_image_id)?;
        let economic_image_id = decode_hash(ECONOMIC_BLOCK_IMAGE_ID)?;
        let mut randomx_cursor = 0usize;
        let mut economic_cursor = 0usize;
        let mut expected_previous = source.previous_height;
        let mut expected_state = None;
        let mut target_boundary_seen = false;
        let mut jobs = Vec::with_capacity(source.segment_count);
        for (index, segment) in source.segments.iter().enumerate() {
            let transition_name = format!("checkpoint-segment-{index:04}-transition.bin");
            let private_name = format!("checkpoint-segment-{index:04}-private-input.bin");
            let policy_name = format!("checkpoint-segment-{index:04}-policy-input.bin");
            let opening_name = format!("checkpoint-segment-{index:04}-native-state-opening.bin");
            if segment.index != index
                || segment.previous_height != expected_previous
                || segment.next_height <= segment.previous_height
                || segment.next_height - segment.previous_height != u64::from(segment.block_count)
                || segment.next_height > source.confirmation_height
                || (segment.previous_height < source.target_height
                    && segment.next_height > source.target_height)
            {
                return Err(format!("invalid source segment record {index}"));
            }
            if segment.next_height == source.target_height {
                if target_boundary_seen {
                    return Err("duplicated checkpoint target boundary".into());
                }
                target_boundary_seen = true;
            }
            let transition_bytes = checked_source(
                paths.source_directory,
                &segment.transition_file,
                &transition_name,
                &segment.transition_sha256,
                CHECKPOINT_SEGMENT_TRANSITION_BYTES,
            )?;
            let private_bytes = Zeroizing::new(checked_source(
                paths.source_directory,
                &segment.private_input_file,
                &private_name,
                &segment.private_input_sha256,
                MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
            )?);
            let policy_bytes = checked_source(
                paths.source_directory,
                &segment.policy_input_file,
                &policy_name,
                &segment.policy_input_sha256,
                MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES,
            )?;
            let opening_bytes = checked_source(
                paths.source_directory,
                &segment.native_state_opening_file,
                &opening_name,
                &segment.native_state_opening_sha256,
                MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES,
            )?;
            let transition = CheckpointSegmentTransition::from_bytes(&transition_bytes)
                .map_err(|error| format!("invalid segment transition {index}: {error}"))?;
            let private = CheckpointSegmentPrivateInput::from_bytes(&private_bytes)
                .map_err(|error| format!("invalid segment private input {index}: {error}"))?;
            let policy = CheckpointSegmentPolicyInput::from_bytes(&policy_bytes)
                .map_err(|error| format!("invalid segment policy {index}: {error}"))?;
            let opening = CheckpointSegmentNativeStateOpening::from_bytes(&opening_bytes)
                .map_err(|error| format!("invalid segment opening {index}: {error}"))?;
            if transition.previous.height != segment.previous_height
                || transition.next.height != segment.next_height
                || transition.block_count != segment.block_count
                || transition.previous.randomx_receipt_image_id != randomx_image_id
                || transition.next.randomx_receipt_image_id != randomx_image_id
                || expected_state.is_some_and(|state| state != transition.previous)
            {
                return Err(format!("segment transition chain mismatch at {index}"));
            }
            let executed =
                execute_checkpoint_segment_portable(&transition, &private, &policy, &opening)
                    .map_err(|error| {
                        format!("portable segment execution {index} failed: {error}")
                    })?;
            let block_count = usize::from(segment.block_count);
            if executed.randomx_bindings().len() != block_count
                || executed.economic_block_bindings().len() != block_count
            {
                return Err(format!(
                    "segment receipt requirement count mismatch at {index}"
                ));
            }
            let randomx_end = randomx_cursor
                .checked_add(block_count)
                .ok_or_else(|| "RandomX receipt range overflow".to_string())?;
            let economic_end = economic_cursor
                .checked_add(block_count)
                .ok_or_else(|| "economic receipt range overflow".to_string())?;
            let randomx_records = randomx
                .receipts
                .get(randomx_cursor..randomx_end)
                .ok_or_else(|| format!("missing RandomX receipt range for segment {index}"))?;
            let economic_records = economic
                .block_receipts
                .get(economic_cursor..economic_end)
                .ok_or_else(|| format!("missing economic receipt range for segment {index}"))?;
            let mut randomx_jobs = Vec::with_capacity(block_count);
            let mut economic_jobs = Vec::with_capacity(block_count);
            for block_index in 0..block_count {
                let height = segment
                    .previous_height
                    .checked_add(block_index as u64 + 1)
                    .ok_or_else(|| "segment block height overflow".to_string())?;
                let randomx_record = &randomx_records[block_index];
                let randomx_binding = &executed.randomx_bindings()[block_index];
                let randomx_expected = hex(randomx_binding.assumption().journal());
                if randomx_record.index != randomx_cursor + block_index
                    || randomx_record.segment_index != index
                    || randomx_record.block_index != block_index
                    || randomx_record.block_height != height
                    || !nonzero_hash(&randomx_record.statement_sha256)
                    || randomx_record.expected_journal != randomx_expected
                {
                    return Err(format!(
                        "RandomX receipt order mismatch at segment {index} block {block_index}"
                    ));
                }
                let expected_randomx_name =
                    format!("randomx-receipt-{:04}.bin", randomx_record.index);
                verify_receipt_file(
                    paths.randomx_receipt_directory,
                    &randomx_record.receipt_file,
                    &expected_randomx_name,
                    &randomx_record.receipt_sha256,
                    randomx_record.receipt_bytes,
                    randomx_image_id,
                    decode_hash(&randomx_expected)?,
                )?;
                randomx_jobs.push(InnerReceiptRecord {
                    block_index,
                    block_height: height,
                    expected_journal: randomx_expected,
                    receipt_file: randomx_record.receipt_file.clone(),
                    receipt_sha256: randomx_record.receipt_sha256.clone(),
                    receipt_bytes: randomx_record.receipt_bytes,
                });

                let economic_record = &economic_records[block_index];
                let economic_expected =
                    hex(executed.economic_block_bindings()[block_index].journal());
                if economic_record.index != economic_cursor + block_index
                    || economic_record.segment_index != index
                    || economic_record.block_index != block_index
                    || economic_record.block_height != height
                    || economic_record.expected_journal != economic_expected
                {
                    return Err(format!(
                        "economic receipt order mismatch at segment {index} block {block_index}"
                    ));
                }
                let expected_economic_name =
                    format!("economic-block-receipt-{:04}.bin", economic_record.index);
                verify_receipt_file(
                    paths.economic_receipt_directory,
                    &economic_record.receipt_file,
                    &expected_economic_name,
                    &economic_record.receipt_sha256,
                    economic_record.receipt_bytes,
                    economic_image_id,
                    decode_hash(&economic_expected)?,
                )?;
                economic_jobs.push(InnerReceiptRecord {
                    block_index,
                    block_height: height,
                    expected_journal: economic_expected,
                    receipt_file: economic_record.receipt_file.clone(),
                    receipt_sha256: economic_record.receipt_sha256.clone(),
                    receipt_bytes: economic_record.receipt_bytes,
                });
            }
            jobs.push(SegmentJob {
                index,
                previous_height: segment.previous_height,
                next_height: segment.next_height,
                block_count: segment.block_count,
                transition_file: format!("evidence/checkpoint-source-set/{transition_name}"),
                transition_sha256: segment.transition_sha256.clone(),
                policy_input_file: format!("evidence/checkpoint-source-set/{policy_name}"),
                policy_input_sha256: segment.policy_input_sha256.clone(),
                native_state_opening_file: format!("evidence/checkpoint-source-set/{opening_name}"),
                native_state_opening_sha256: segment.native_state_opening_sha256.clone(),
                private_input_file: format!("evidence/checkpoint-source-set/{private_name}"),
                private_input_sha256: segment.private_input_sha256.clone(),
                expected_journal: hex(&executed.transition_commitment()),
                randomx_receipts: randomx_jobs,
                economic_block_receipts: economic_jobs,
                receipt_file: format!("checkpoint-segment-receipt-{index:04}.bin"),
            });
            randomx_cursor = randomx_end;
            economic_cursor = economic_end;
            expected_previous = segment.next_height;
            expected_state = Some(transition.next);
        }
        if expected_previous != source.confirmation_height
            || !target_boundary_seen
            || randomx_cursor != randomx.receipt_count
            || economic_cursor != economic.block_receipt_count
        {
            return Err("segment jobs do not consume the complete authenticated source".into());
        }
        let index = SegmentJobIndex {
            schema: JOB_SCHEMA.into(),
            source_index_path: SOURCE_INDEX_LOGICAL_PATH.into(),
            source_index_sha256: sha256(&source_bytes),
            randomx_job_index_path: RANDOMX_JOB_INDEX_LOGICAL_PATH.into(),
            randomx_job_index_sha256: sha256(&randomx_job_bytes),
            randomx_receipt_index_path: RANDOMX_RECEIPT_INDEX_LOGICAL_PATH.into(),
            randomx_receipt_index_sha256: sha256(&randomx_receipt_bytes),
            economic_job_index_path: ECONOMIC_JOB_INDEX_LOGICAL_PATH.into(),
            economic_job_index_sha256: sha256(&economic_job_bytes),
            economic_receipt_index_path: ECONOMIC_RECEIPT_INDEX_LOGICAL_PATH.into(),
            economic_receipt_index_sha256: sha256(&economic_receipt_bytes),
            manifest_sha256: source.manifest_sha256,
            randomx_image_id: source.randomx_receipt_image_id,
            economic_block_image_id: ECONOMIC_BLOCK_IMAGE_ID.into(),
            segment_user_elf_path: SEGMENT_ELF_LOGICAL_PATH.into(),
            segment_user_elf_sha256: SEGMENT_ELF_SHA256.into(),
            segment_program_path: SEGMENT_PROGRAM_LOGICAL_PATH.into(),
            segment_program_sha256: SEGMENT_PROGRAM_SHA256.into(),
            segment_image_id_path: SEGMENT_IMAGE_ID_LOGICAL_PATH.into(),
            segment_image_id_file_sha256: SEGMENT_IMAGE_ID_FILE_SHA256.into(),
            segment_image_id: SEGMENT_IMAGE_ID.into(),
            risc0_zkvm_version: RISC0_VERSION.into(),
            receipt_kind: RECEIPT_KIND.into(),
            previous_height: source.previous_height,
            target_height: source.target_height,
            confirmation_height: source.confirmation_height,
            segment_job_count: jobs.len(),
            randomx_receipt_count: randomx_cursor,
            economic_block_receipt_count: economic_cursor,
            executes_guests: false,
            generates_proofs: false,
            mines: false,
            jobs,
        };
        let mut bytes = serde_json::to_vec_pretty(&index)
            .map_err(|error| format!("cannot encode segment job index: {error}"))?;
        bytes.push(b'\n');
        Ok((index, bytes))
    }

    /// Verify every upstream source and receipt, then publish deterministic segment jobs.
    pub fn publish_segment_plan(
        paths: &SegmentPlanPaths<'_>,
    ) -> Result<SegmentPlanSummary, String> {
        direct_directory(paths.output_directory)?;
        let source_index_sha256 = sha256(&read_direct(paths.source_index, MAX_INDEX_BYTES)?);
        let randomx_receipt_index_sha256 =
            sha256(&read_direct(paths.randomx_receipt_index, MAX_INDEX_BYTES)?);
        let economic_receipt_index_sha256 =
            sha256(&read_direct(paths.economic_receipt_index, MAX_INDEX_BYTES)?);
        let (plan, bytes) = build_plan(paths)?;
        let job_index_sha256 = sha256(&bytes);
        atomic_publish(&paths.output_directory.join(JOB_INDEX_NAME), &bytes)?;
        Ok(SegmentPlanSummary {
            segment_job_count: plan.segment_job_count,
            source_index_sha256,
            randomx_receipt_index_sha256,
            economic_receipt_index_sha256,
            job_index_sha256,
        })
    }

    struct BuiltOuterPlan {
        segment_receipt_count: usize,
        statement_hash: String,
        index_bytes: Vec<u8>,
        statement_bytes: Vec<u8>,
        #[cfg(feature = "prove")]
        policy_bytes: Vec<u8>,
        #[cfg(feature = "prove")]
        opening_bytes: Vec<u8>,
        chain_bytes: Vec<u8>,
        #[cfg(feature = "prove")]
        verified_receipts: Vec<Receipt>,
    }

    /// Rebuild and verify the complete segment plan and receipt set and derive
    /// the unique outer statement, chain and deterministic proof job.
    #[allow(clippy::too_many_lines)]
    fn build_outer_plan(paths: &OuterPlanPaths<'_>) -> Result<BuiltOuterPlan, String> {
        direct_directory(paths.segment_receipt_directory)?;
        checked_artifact(paths.outer_elf, OUTER_ELF_SHA256, MAX_ARTIFACT_BYTES)?;
        checked_artifact(
            paths.outer_program,
            OUTER_PROGRAM_SHA256,
            MAX_ARTIFACT_BYTES,
        )?;
        let outer_image_file = read_direct(paths.outer_image_id, 128)?;
        if sha256(&outer_image_file) != OUTER_IMAGE_ID_FILE_SHA256
            || outer_image_file != format!("{OUTER_IMAGE_ID}\n").as_bytes()
        {
            return Err("pinned outer ImageID mismatch".into());
        }

        let (segment_plan, rebuilt_segment_jobs) = build_plan(&paths.segment_plan)?;
        let published_segment_jobs = read_direct(paths.segment_job_index, MAX_INDEX_BYTES)?;
        if published_segment_jobs != rebuilt_segment_jobs {
            return Err("published segment job index differs from its exact rebuilt plan".into());
        }
        let receipt_index_bytes = read_direct(paths.segment_receipt_index, MAX_INDEX_BYTES)?;
        let receipt_index: SegmentReceiptIndex = serde_json::from_slice(&receipt_index_bytes)
            .map_err(|error| format!("invalid segment receipt-set index: {error}"))?;
        if receipt_index.schema != SEGMENT_RECEIPT_SCHEMA
            || receipt_index.proof_job_index_path != JOB_INDEX_LOGICAL_PATH
            || receipt_index.proof_job_index_sha256 != sha256(&published_segment_jobs)
            || receipt_index.segment_image_id != SEGMENT_IMAGE_ID
            || receipt_index.risc0_zkvm_version != RISC0_VERSION
            || receipt_index.receipt_kind != RECEIPT_KIND
            || receipt_index.receipt_count == 0
            || receipt_index.receipt_count != segment_plan.segment_job_count
            || receipt_index.receipt_count != receipt_index.receipts.len()
            || !receipt_index.inner_receipts_verified
            || !receipt_index.segment_receipts_verified
            || receipt_index.dev_mode
            || !receipt_index.generates_proofs
            || receipt_index.mines
        {
            return Err("invalid segment receipt-set identity or claims".into());
        }

        let segment_image_id = decode_hash(SEGMENT_IMAGE_ID)?;
        let mut transitions = Vec::with_capacity(segment_plan.segment_job_count);
        #[cfg(feature = "prove")]
        let mut verified_receipts = Vec::with_capacity(segment_plan.segment_job_count);
        for (index, job) in segment_plan.jobs.iter().enumerate() {
            let transition_bytes = read_direct(
                &source_logical_file(paths.segment_plan.source_directory, &job.transition_file)?,
                CHECKPOINT_SEGMENT_TRANSITION_BYTES,
            )?;
            if sha256(&transition_bytes) != job.transition_sha256 {
                return Err(format!(
                    "segment transition changed after planning at {index}"
                ));
            }
            transitions.push(
                CheckpointSegmentTransition::from_bytes(&transition_bytes)
                    .map_err(|error| format!("invalid segment transition {index}: {error}"))?,
            );

            let record = &receipt_index.receipts[index];
            let expected_receipt_name = format!("checkpoint-segment-receipt-{index:04}.bin");
            if record.index != index
                || record.previous_height != job.previous_height
                || record.next_height != job.next_height
                || record.block_count != job.block_count
                || record.expected_journal != job.expected_journal
            {
                return Err(format!("segment receipt order mismatch at {index}"));
            }
            let verified_receipt = verify_receipt_file(
                paths.segment_receipt_directory,
                &record.receipt_file,
                &expected_receipt_name,
                &record.receipt_sha256,
                record.receipt_bytes,
                segment_image_id,
                decode_hash(&job.expected_journal)?,
            )?;
            #[cfg(feature = "prove")]
            verified_receipts.push(verified_receipt);
            #[cfg(not(feature = "prove"))]
            drop(verified_receipt);
        }
        let chain = CheckpointOuterChain::new(transitions)
            .map_err(|error| format!("invalid outer checkpoint chain: {error}"))?;
        let first_job = segment_plan
            .jobs
            .first()
            .ok_or_else(|| "segment plan is empty".to_string())?;
        let policy_bytes = read_direct(
            &source_logical_file(
                paths.segment_plan.source_directory,
                &first_job.policy_input_file,
            )?,
            MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES,
        )?;
        let opening_bytes = read_direct(
            &source_logical_file(
                paths.segment_plan.source_directory,
                &first_job.native_state_opening_file,
            )?,
            MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES,
        )?;
        if sha256(&policy_bytes) != first_job.policy_input_sha256
            || sha256(&opening_bytes) != first_job.native_state_opening_sha256
        {
            return Err("first segment policy or opening changed after planning".into());
        }
        let policy = CheckpointSegmentPolicyInput::from_bytes(&policy_bytes)
            .map_err(|error| format!("invalid first segment policy: {error}"))?;
        let opening = CheckpointSegmentNativeStateOpening::from_bytes(&opening_bytes)
            .map_err(|error| format!("invalid first segment opening: {error}"))?;
        let statement = derive_checkpoint_statement_v6(
            &chain,
            segment_plan.target_height,
            &policy,
            &opening,
            segment_image_id,
        )
        .map_err(|error| format!("cannot derive outer checkpoint statement: {error}"))?;
        let executed = validate_checkpoint_outer_chain_v6(
            &statement,
            &chain,
            &policy,
            &opening,
            segment_image_id,
        )
        .map_err(|error| format!("outer checkpoint composition failed: {error}"))?;
        if executed.segment_receipts().len() != receipt_index.receipt_count {
            return Err("outer receipt assumptions do not cover the complete segment set".into());
        }
        for (index, assumption) in executed.segment_receipts().iter().enumerate() {
            if assumption.image_id() != &segment_image_id
                || assumption.journal()
                    != &decode_hash(&receipt_index.receipts[index].expected_journal)?
            {
                return Err(format!("outer receipt assumption mismatch at {index}"));
            }
        }

        let statement_bytes = statement
            .to_bytes()
            .map_err(|error| format!("cannot encode checkpoint statement: {error}"))?
            .to_vec();
        if statement_bytes.len() != CHECKPOINT_STATEMENT_V6_BYTES {
            return Err("checkpoint statement length changed".into());
        }
        let chain_bytes = chain
            .to_bytes()
            .map_err(|error| format!("cannot encode outer checkpoint chain: {error}"))?;
        if chain_bytes.is_empty() || chain_bytes.len() > MAX_CHECKPOINT_OUTER_CHAIN_BYTES {
            return Err("outer checkpoint chain exceeds its bound".into());
        }
        let statement_hash = hex(&executed.statement_hash());
        // `build_plan` authenticated one exact source-index generation.  Do
        // not let a concurrent replacement become the provenance hash of the
        // outer job after the statement and chain were derived from the old
        // bytes.
        let source_index_bytes = read_unchanged(
            paths.segment_plan.source_index,
            MAX_INDEX_BYTES,
            &segment_plan.source_index_sha256,
            "checkpoint source-set index",
        )?;
        let index = OuterJobIndex {
            schema: OUTER_JOB_SCHEMA.into(),
            source_index_path: SOURCE_INDEX_LOGICAL_PATH.into(),
            source_index_sha256: sha256(&source_index_bytes),
            segment_job_index_path: JOB_INDEX_LOGICAL_PATH.into(),
            segment_job_index_sha256: sha256(&published_segment_jobs),
            segment_receipt_index_path: SEGMENT_RECEIPT_INDEX_LOGICAL_PATH.into(),
            segment_receipt_index_sha256: sha256(&receipt_index_bytes),
            segment_image_id: SEGMENT_IMAGE_ID.into(),
            outer_user_elf_path: OUTER_ELF_LOGICAL_PATH.into(),
            outer_user_elf_sha256: OUTER_ELF_SHA256.into(),
            outer_program_path: OUTER_PROGRAM_LOGICAL_PATH.into(),
            outer_program_sha256: OUTER_PROGRAM_SHA256.into(),
            outer_image_id_path: OUTER_IMAGE_ID_LOGICAL_PATH.into(),
            outer_image_id_file_sha256: OUTER_IMAGE_ID_FILE_SHA256.into(),
            outer_image_id: OUTER_IMAGE_ID.into(),
            risc0_zkvm_version: RISC0_VERSION.into(),
            receipt_kind: RECEIPT_KIND.into(),
            previous_height: segment_plan.previous_height,
            target_height: segment_plan.target_height,
            confirmation_height: segment_plan.confirmation_height,
            statement_file: OUTER_STATEMENT_NAME.into(),
            statement_sha256: sha256(&statement_bytes),
            statement_hash: statement_hash.clone(),
            chain_file: OUTER_CHAIN_NAME.into(),
            chain_sha256: sha256(&chain_bytes),
            segment_receipt_count: receipt_index.receipt_count,
            segment_receipts_verified: true,
            executes_guests: false,
            generates_proofs: false,
            mines: false,
            segment_receipts: receipt_index.receipts,
            receipt_file: "checkpoint-outer-receipt.bin".into(),
        };
        let mut index_bytes = serde_json::to_vec_pretty(&index)
            .map_err(|error| format!("cannot encode outer job index: {error}"))?;
        index_bytes.push(b'\n');
        Ok(BuiltOuterPlan {
            segment_receipt_count: segment_plan.segment_job_count,
            statement_hash,
            index_bytes,
            statement_bytes,
            #[cfg(feature = "prove")]
            policy_bytes,
            #[cfg(feature = "prove")]
            opening_bytes,
            chain_bytes,
            #[cfg(feature = "prove")]
            verified_receipts,
        })
    }

    /// Rebuild and verify every upstream value, then atomically publish the
    /// canonical outer statement, chain and deterministic proof job.
    pub fn publish_outer_plan(paths: &OuterPlanPaths<'_>) -> Result<OuterPlanSummary, String> {
        direct_directory(paths.output_directory)?;
        let built = build_outer_plan(paths)?;
        atomic_publish(
            &paths.output_directory.join(OUTER_STATEMENT_NAME),
            &built.statement_bytes,
        )?;
        atomic_publish(
            &paths.output_directory.join(OUTER_CHAIN_NAME),
            &built.chain_bytes,
        )?;
        let job_index_sha256 = sha256(&built.index_bytes);
        atomic_publish(
            &paths.output_directory.join(OUTER_JOB_INDEX_NAME),
            &built.index_bytes,
        )?;
        Ok(OuterPlanSummary {
            segment_receipt_count: built.segment_receipt_count,
            statement_hash: built.statement_hash,
            job_index_sha256,
        })
    }

    fn source_logical_file(directory: &Path, logical: &str) -> Result<std::path::PathBuf, String> {
        let prefix = "evidence/checkpoint-source-set/";
        let name = logical
            .strip_prefix(prefix)
            .ok_or_else(|| format!("source path is outside the fixed directory: {logical}"))?;
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || matches!(name, "." | "..")
        {
            return Err(format!(
                "source path is not one canonical filename: {logical}"
            ));
        }
        Ok(directory.join(name))
    }

    #[cfg(feature = "prove")]
    fn remove_direct_file(path: &Path) -> Result<(), String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(format!("{} is not a direct regular file", path.display()));
        }
        fs::remove_file(path)
            .map_err(|error| format!("cannot remove {}: {error}", path.display()))?;
        let parent = path
            .parent()
            .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("cannot sync {}: {error}", parent.display()))
    }

    #[cfg(feature = "prove")]
    fn existing_verified_segment_receipt(
        path: &Path,
        image_id: [u8; 32],
        journal: [u8; 32],
    ) -> Result<Option<Vec<u8>>, String> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                    return Err(format!("{} is not a direct regular file", path.display()));
                }
                let bytes = read_direct(path, MAX_RECEIPT_BYTES)?;
                if decode_verified_receipt(&bytes, &path.display().to_string(), image_id, journal)
                    .is_ok()
                {
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
    fn existing_verified_groth16_receipt(
        path: &Path,
        image_id: [u8; 32],
        journal: [u8; 32],
    ) -> Result<Option<(Vec<u8>, Receipt)>, String> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                    return Err(format!("{} is not a direct regular file", path.display()));
                }
                let bytes = read_direct(path, MAX_RECEIPT_BYTES)?;
                match decode_verified_groth16_receipt(
                    &bytes,
                    &path.display().to_string(),
                    image_id,
                    journal,
                ) {
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

    #[cfg(feature = "prove")]
    fn invalidate_outer_evm_package_index(output_directory: &Path) -> Result<(), String> {
        let path = output_directory.join(OUTER_EVM_PACKAGE_INDEX_NAME);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err("outer EVM package index is not a direct regular file".into());
                }
                remove_direct_file(&path)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cannot inspect outer EVM package index {}: {error}",
                    path.display()
                ))
            }
        }

        // Keep the expensive verified Groth16 receipt resumable, but durably
        // remove its cheap derived seal after the completion marker. Thus a
        // crash cannot expose old calldata as part of an incomplete package.
        let seal_path = output_directory.join("checkpoint-outer-evm-seal.bin");
        match fs::symlink_metadata(&seal_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err("outer EVM seal is not a direct regular file".into());
                }
                remove_direct_file(&seal_path)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "cannot inspect outer EVM seal {}: {error}",
                seal_path.display()
            )),
        }
    }

    /// Prove every planned segment locally and publish a verified receipt-set index.
    ///
    /// This function performs expensive cryptographic proving and must only be called through
    /// the separate operator command after explicit authorization.
    #[cfg(feature = "prove")]
    #[allow(clippy::too_many_lines)]
    pub fn prove_segment_set(paths: &SegmentProofPaths<'_>) -> Result<SegmentProofSummary, String> {
        use risc0_zkvm::{default_prover, ExecutorEnv, Prover, ProverOpts};

        require_local_prover_environment("checkpoint segment proving")?;
        direct_directory(paths.output_directory)?;
        let (plan, rebuilt) = build_plan(&paths.plan)?;
        let published = read_direct(paths.job_index, MAX_INDEX_BYTES)?;
        if published != rebuilt {
            return Err("published segment job index differs from its exact rebuilt plan".into());
        }
        let decoded: SegmentJobIndex = serde_json::from_slice(&published)
            .map_err(|error| format!("invalid published segment job index: {error}"))?;
        if decoded.segment_job_count != plan.segment_job_count
            || decoded.randomx_receipt_count != plan.randomx_receipt_count
            || decoded.economic_block_receipt_count != plan.economic_block_receipt_count
        {
            return Err("published segment job counts differ from rebuilt plan".into());
        }
        let segment_program = read_direct(paths.plan.segment_program, MAX_ARTIFACT_BYTES)?;
        if sha256(&segment_program) != SEGMENT_PROGRAM_SHA256 {
            return Err("segment packaged guest program changed after plan rebuild".into());
        }
        let segment_image_id = decode_hash(SEGMENT_IMAGE_ID)?;
        let randomx_image_id = decode_hash(&plan.randomx_image_id)?;
        let economic_image_id = decode_hash(ECONOMIC_BLOCK_IMAGE_ID)?;
        let prover = default_prover();
        if prover.get_name() != "local" {
            return Err("selected segment prover is not the fixed local prover".into());
        }
        let options = ProverOpts::succinct().with_dev_mode(false);
        let final_index = paths.output_directory.join(RECEIPT_INDEX_NAME);
        match fs::symlink_metadata(&final_index) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                    return Err("segment receipt-set index is not a direct regular file".into());
                }
                remove_direct_file(&final_index)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("cannot inspect segment receipt-set index: {error}"));
            }
        }

        let mut records = Vec::with_capacity(plan.segment_job_count);
        for job in &plan.jobs {
            let journal = decode_hash(&job.expected_journal)?;
            let receipt_path = paths.output_directory.join(&job.receipt_file);
            let encoded = if let Some(bytes) =
                existing_verified_segment_receipt(&receipt_path, segment_image_id, journal)?
            {
                bytes
            } else {
                let transition = read_direct(
                    &source_logical_file(paths.plan.source_directory, &job.transition_file)?,
                    CHECKPOINT_SEGMENT_TRANSITION_BYTES,
                )?;
                let policy = read_direct(
                    &source_logical_file(paths.plan.source_directory, &job.policy_input_file)?,
                    MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES,
                )?;
                let opening = read_direct(
                    &source_logical_file(
                        paths.plan.source_directory,
                        &job.native_state_opening_file,
                    )?,
                    MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES,
                )?;
                let private = Zeroizing::new(read_direct(
                    &source_logical_file(paths.plan.source_directory, &job.private_input_file)?,
                    MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
                )?);
                if sha256(&transition) != job.transition_sha256
                    || sha256(&policy) != job.policy_input_sha256
                    || sha256(&opening) != job.native_state_opening_sha256
                    || sha256(&private) != job.private_input_sha256
                {
                    return Err(format!(
                        "segment job {} source changed after planning",
                        job.index
                    ));
                }
                let mut assumptions = Vec::with_capacity(
                    job.randomx_receipts.len() + job.economic_block_receipts.len(),
                );
                let receipt_offset = job
                    .previous_height
                    .checked_sub(plan.previous_height)
                    .and_then(|offset| usize::try_from(offset).ok())
                    .ok_or_else(|| format!("segment job {} receipt offset overflow", job.index))?;
                for record in &job.randomx_receipts {
                    let global_index =
                        receipt_offset
                            .checked_add(record.block_index)
                            .ok_or_else(|| {
                                format!("segment job {} receipt index overflow", job.index)
                            })?;
                    assumptions.push(verify_receipt_file(
                        paths.plan.randomx_receipt_directory,
                        &record.receipt_file,
                        &format!("randomx-receipt-{global_index:04}.bin"),
                        &record.receipt_sha256,
                        record.receipt_bytes,
                        randomx_image_id,
                        decode_hash(&record.expected_journal)?,
                    )?);
                }
                for record in &job.economic_block_receipts {
                    let global_index =
                        receipt_offset
                            .checked_add(record.block_index)
                            .ok_or_else(|| {
                                format!("segment job {} receipt index overflow", job.index)
                            })?;
                    assumptions.push(verify_receipt_file(
                        paths.plan.economic_receipt_directory,
                        &record.receipt_file,
                        &format!("economic-block-receipt-{global_index:04}.bin"),
                        &record.receipt_sha256,
                        record.receipt_bytes,
                        economic_image_id,
                        decode_hash(&record.expected_journal)?,
                    )?);
                }
                let policy_length = u32::try_from(policy.len())
                    .map_err(|_| format!("segment job {} policy exceeds u32", job.index))?;
                let opening_length = u32::try_from(opening.len())
                    .map_err(|_| format!("segment job {} opening exceeds u32", job.index))?;
                let private_length = u32::try_from(private.len())
                    .map_err(|_| format!("segment job {} private input exceeds u32", job.index))?;
                let mut builder = ExecutorEnv::builder();
                builder.write_slice(&transition);
                builder.write(&policy_length).map_err(|error| {
                    format!(
                        "cannot encode segment job {} policy length: {error}",
                        job.index
                    )
                })?;
                builder.write_slice(&policy);
                builder.write(&opening_length).map_err(|error| {
                    format!(
                        "cannot encode segment job {} opening length: {error}",
                        job.index
                    )
                })?;
                builder.write_slice(&opening);
                builder.write(&private_length).map_err(|error| {
                    format!(
                        "cannot encode segment job {} private length: {error}",
                        job.index
                    )
                })?;
                builder.write_slice(&private);
                for receipt in assumptions {
                    builder.add_assumption(receipt);
                }
                let environment = builder
                    .build()
                    .map_err(|error| format!("cannot build segment job {}: {error}", job.index))?;
                let proof = prover
                    .prove_with_opts(environment, &segment_program, &options)
                    .map_err(|error| format!("segment proof {} failed: {error}", job.index))?;
                if !matches!(proof.receipt.inner, InnerReceipt::Succinct(_)) {
                    return Err(format!("segment proof {} is not succinct", job.index));
                }
                let bytes = bincode::serialize(&proof.receipt).map_err(|error| {
                    format!("cannot encode segment receipt {}: {error}", job.index)
                })?;
                if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
                    return Err(format!("segment receipt {} exceeds its bound", job.index));
                }
                decode_verified_receipt(&bytes, &job.receipt_file, segment_image_id, journal)?;
                atomic_publish(&receipt_path, &bytes)?;
                bytes
            };
            records.push(serde_json::json!({
                "index": job.index,
                "previous_height": job.previous_height,
                "next_height": job.next_height,
                "block_count": job.block_count,
                "expected_journal": job.expected_journal,
                "receipt_file": job.receipt_file,
                "receipt_sha256": sha256(&encoded),
                "receipt_bytes": encoded.len()
            }));
        }
        let output = serde_json::json!({
            "schema": "usdom-checkpoint-segment-receipt-set-v1",
            "proof_job_index_path": JOB_INDEX_LOGICAL_PATH,
            "proof_job_index_sha256": sha256(&published),
            "segment_image_id": SEGMENT_IMAGE_ID,
            "risc0_zkvm_version": RISC0_VERSION,
            "receipt_kind": RECEIPT_KIND,
            "receipt_count": records.len(),
            "inner_receipts_verified": true,
            "segment_receipts_verified": true,
            "dev_mode": false,
            "generates_proofs": true,
            "mines": false,
            "receipts": records
        });
        let mut output_bytes = serde_json::to_vec_pretty(&output)
            .map_err(|error| format!("cannot encode segment receipt index: {error}"))?;
        output_bytes.push(b'\n');
        let receipt_index_sha256 = sha256(&output_bytes);
        atomic_publish(&final_index, &output_bytes)?;
        Ok(SegmentProofSummary {
            segment_receipt_count: plan.segment_job_count,
            job_index_sha256: sha256(&published),
            receipt_index_sha256,
        })
    }

    /// Prove the exact authenticated outer checkpoint locally and publish a
    /// cryptographically verified succinct receipt index.
    ///
    /// This function performs expensive cryptographic proving and must only be
    /// called through the separate operator command after explicit authorization.
    #[cfg(feature = "prove")]
    #[allow(clippy::too_many_lines)]
    pub fn prove_outer_checkpoint(
        paths: &OuterProofPaths<'_>,
    ) -> Result<OuterProofSummary, String> {
        use risc0_zkvm::{default_prover, ExecutorEnv, Prover, ProverOpts};

        require_local_prover_environment("checkpoint outer proving")?;
        direct_directory(paths.output_directory)?;
        let built = build_outer_plan(&paths.plan)?;
        let published_job = read_direct(paths.job_index, MAX_INDEX_BYTES)?;
        let published_statement = read_direct(paths.statement, CHECKPOINT_STATEMENT_V6_BYTES)?;
        let published_chain = read_direct(paths.chain, MAX_CHECKPOINT_OUTER_CHAIN_BYTES)?;
        if published_job != built.index_bytes
            || published_statement != built.statement_bytes
            || published_chain != built.chain_bytes
        {
            return Err(
                "published outer job, statement or chain differs from its rebuilt plan".into(),
            );
        }
        let outer_program = read_direct(paths.plan.outer_program, MAX_ARTIFACT_BYTES)?;
        if sha256(&outer_program) != OUTER_PROGRAM_SHA256 {
            return Err("outer packaged guest program changed after plan rebuild".into());
        }
        let outer_image_id = decode_hash(OUTER_IMAGE_ID)?;
        let statement_hash = decode_hash(&built.statement_hash)?;
        let prover = default_prover();
        if prover.get_name() != "local" {
            return Err("selected outer prover is not the fixed local prover".into());
        }
        let options = ProverOpts::succinct().with_dev_mode(false);
        let final_index = paths.output_directory.join(OUTER_RECEIPT_INDEX_NAME);
        match fs::symlink_metadata(&final_index) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                    return Err("outer receipt-set index is not a direct regular file".into());
                }
                remove_direct_file(&final_index)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect outer receipt-set index: {error}")),
        }

        let receipt_name = "checkpoint-outer-receipt.bin";
        let receipt_path = paths.output_directory.join(receipt_name);
        let encoded = if let Some(bytes) =
            existing_verified_segment_receipt(&receipt_path, outer_image_id, statement_hash)?
        {
            bytes
        } else {
            let policy_length = u32::try_from(built.policy_bytes.len())
                .map_err(|_| "outer policy exceeds u32".to_string())?;
            let opening_length = u32::try_from(built.opening_bytes.len())
                .map_err(|_| "outer opening exceeds u32".to_string())?;
            let chain_length = u32::try_from(built.chain_bytes.len())
                .map_err(|_| "outer chain exceeds u32".to_string())?;
            let mut builder = ExecutorEnv::builder();
            builder.write_slice(&built.statement_bytes);
            builder
                .write(&policy_length)
                .map_err(|error| format!("cannot encode outer policy length: {error}"))?;
            builder.write_slice(&built.policy_bytes);
            builder
                .write(&opening_length)
                .map_err(|error| format!("cannot encode outer opening length: {error}"))?;
            builder.write_slice(&built.opening_bytes);
            builder
                .write(&chain_length)
                .map_err(|error| format!("cannot encode outer chain length: {error}"))?;
            builder.write_slice(&built.chain_bytes);
            for receipt in built.verified_receipts {
                builder.add_assumption(receipt);
            }
            let environment = builder
                .build()
                .map_err(|error| format!("cannot build outer proof job: {error}"))?;
            let proof = prover
                .prove_with_opts(environment, &outer_program, &options)
                .map_err(|error| format!("outer checkpoint proof failed: {error}"))?;
            if !matches!(proof.receipt.inner, InnerReceipt::Succinct(_)) {
                return Err("outer checkpoint proof is not succinct".into());
            }
            let bytes = bincode::serialize(&proof.receipt)
                .map_err(|error| format!("cannot encode outer checkpoint receipt: {error}"))?;
            if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
                return Err("outer checkpoint receipt exceeds its bound".into());
            }
            decode_verified_receipt(&bytes, receipt_name, outer_image_id, statement_hash)?;
            atomic_publish(&receipt_path, &bytes)?;
            bytes
        };
        let output = serde_json::json!({
            "schema": "usdom-checkpoint-outer-receipt-set-v1",
            "proof_job_index_path": OUTER_JOB_INDEX_LOGICAL_PATH,
            "proof_job_index_sha256": sha256(&published_job),
            "outer_image_id": OUTER_IMAGE_ID,
            "statement_hash": built.statement_hash,
            "risc0_zkvm_version": RISC0_VERSION,
            "receipt_kind": RECEIPT_KIND,
            "segment_receipt_count": built.segment_receipt_count,
            "segment_receipts_verified": true,
            "outer_receipt_verified": true,
            "dev_mode": false,
            "generates_proofs": true,
            "mines": false,
            "receipt_file": receipt_name,
            "receipt_sha256": sha256(&encoded),
            "receipt_bytes": encoded.len()
        });
        let mut output_bytes = serde_json::to_vec_pretty(&output)
            .map_err(|error| format!("cannot encode outer receipt index: {error}"))?;
        output_bytes.push(b'\n');
        let receipt_index_sha256 = sha256(&output_bytes);
        atomic_publish(&final_index, &output_bytes)?;
        Ok(OuterProofSummary {
            statement_hash: hex(&statement_hash),
            job_index_sha256: sha256(&published_job),
            receipt_index_sha256,
        })
    }

    /// Compress one verified succinct outer receipt to Groth16 locally and
    /// publish the exact selector-prefixed seal consumed by the EVM verifier.
    ///
    /// This function performs expensive STARK-to-SNARK work and must only be
    /// called through the separate operator command after explicit authorization.
    #[cfg(feature = "prove")]
    #[allow(clippy::too_many_lines)]
    pub fn package_outer_evm_proof(
        paths: &OuterEvmProofPaths<'_>,
    ) -> Result<OuterEvmProofSummary, String> {
        use risc0_zkvm::{default_prover, Prover, ProverOpts};

        require_local_prover_environment("checkpoint outer Groth16 compression")?;
        direct_directory(paths.receipt_directory)?;
        direct_directory(paths.output_directory)?;
        // This index is the durable completion marker. Remove and fsync it
        // before reusing or replacing any Groth16/seal artifact so a crash can
        // never expose an older index over a mixed-generation output set.
        invalidate_outer_evm_package_index(paths.output_directory)?;
        let built = build_outer_plan(&paths.outer_proof.plan)?;
        let published_job = read_direct(paths.outer_proof.job_index, MAX_INDEX_BYTES)?;
        let published_statement =
            read_direct(paths.outer_proof.statement, CHECKPOINT_STATEMENT_V6_BYTES)?;
        let published_chain =
            read_direct(paths.outer_proof.chain, MAX_CHECKPOINT_OUTER_CHAIN_BYTES)?;
        if published_job != built.index_bytes
            || published_statement != built.statement_bytes
            || published_chain != built.chain_bytes
        {
            return Err("published outer proof inputs differ from their rebuilt plan".into());
        }
        let receipt_index_bytes = read_direct(paths.receipt_index, MAX_INDEX_BYTES)?;
        let receipt_index: OuterReceiptIndex = serde_json::from_slice(&receipt_index_bytes)
            .map_err(|error| format!("invalid outer receipt-set index: {error}"))?;
        let expected_receipt_name = "checkpoint-outer-receipt.bin";
        if receipt_index.schema != "usdom-checkpoint-outer-receipt-set-v1"
            || receipt_index.proof_job_index_path != OUTER_JOB_INDEX_LOGICAL_PATH
            || receipt_index.proof_job_index_sha256 != sha256(&published_job)
            || receipt_index.outer_image_id != OUTER_IMAGE_ID
            || receipt_index.statement_hash != built.statement_hash
            || receipt_index.risc0_zkvm_version != RISC0_VERSION
            || receipt_index.receipt_kind != RECEIPT_KIND
            || receipt_index.segment_receipt_count != built.segment_receipt_count
            || !receipt_index.segment_receipts_verified
            || !receipt_index.outer_receipt_verified
            || receipt_index.dev_mode
            || !receipt_index.generates_proofs
            || receipt_index.mines
        {
            return Err("invalid outer receipt-set identity or claims".into());
        }
        let outer_image_id = decode_hash(OUTER_IMAGE_ID)?;
        let statement_hash = decode_hash(&built.statement_hash)?;
        let succinct_receipt = verify_receipt_file(
            paths.receipt_directory,
            &receipt_index.receipt_file,
            expected_receipt_name,
            &receipt_index.receipt_sha256,
            receipt_index.receipt_bytes,
            outer_image_id,
            statement_hash,
        )?;
        let prover = default_prover();
        if prover.get_name() != "local" {
            return Err("selected Groth16 compressor is not the fixed local prover".into());
        }
        let groth16_path = paths
            .output_directory
            .join("checkpoint-outer-groth16-receipt.bin");
        let (groth16_bytes, groth16_receipt) = if let Some(existing) =
            existing_verified_groth16_receipt(&groth16_path, outer_image_id, statement_hash)?
        {
            existing
        } else {
            let options = ProverOpts::groth16().with_dev_mode(false);
            let receipt = prover
                .compress(&options, &succinct_receipt)
                .map_err(|error| format!("outer Groth16 compression failed: {error}"))?;
            if !matches!(receipt.inner, InnerReceipt::Groth16(_)) {
                return Err("compressed outer receipt is not Groth16".into());
            }
            let bytes = bincode::serialize(&receipt)
                .map_err(|error| format!("cannot encode outer Groth16 receipt: {error}"))?;
            if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
                return Err("outer Groth16 receipt exceeds its bound".into());
            }
            decode_verified_groth16_receipt(
                &bytes,
                "checkpoint-outer-groth16-receipt.bin",
                outer_image_id,
                statement_hash,
            )?;
            atomic_publish(&groth16_path, &bytes)?;
            (bytes, receipt)
        };
        let groth16 = match &groth16_receipt.inner {
            InnerReceipt::Groth16(inner) => inner,
            _ => return Err("verified compressed receipt lost Groth16 identity".into()),
        };
        if groth16.seal.is_empty() {
            return Err("outer Groth16 seal is empty".into());
        }
        let mut evm_seal = Vec::with_capacity(EVM_SEAL_SELECTOR.len() + groth16.seal.len());
        evm_seal.extend_from_slice(&EVM_SEAL_SELECTOR);
        evm_seal.extend_from_slice(&groth16.seal);
        if evm_seal.len() != EVM_SEAL_BYTES || evm_seal[..4] != EVM_SEAL_SELECTOR {
            return Err(
                "selector-prefixed EVM seal is not the canonical 260-byte Groth16 proof".into(),
            );
        }
        let evm_seal_name = "checkpoint-outer-evm-seal.bin";
        atomic_publish(&paths.output_directory.join(evm_seal_name), &evm_seal)?;
        let output = serde_json::json!({
            "schema": "usdom-checkpoint-outer-evm-proof-v1",
            "outer_receipt_index_path": OUTER_RECEIPT_INDEX_LOGICAL_PATH,
            "outer_receipt_index_sha256": sha256(&receipt_index_bytes),
            "outer_image_id": OUTER_IMAGE_ID,
            "statement_hash": built.statement_hash,
            "journal_digest": sha256(&statement_hash),
            "risc0_zkvm_version": RISC0_VERSION,
            "receipt_kind": "groth16",
            "groth16_verifier_parameters": GROTH16_VERIFIER_PARAMETERS,
            "evm_verifier_selector": hex(&EVM_SEAL_SELECTOR),
            "groth16_receipt_file": "checkpoint-outer-groth16-receipt.bin",
            "groth16_receipt_sha256": sha256(&groth16_bytes),
            "groth16_receipt_bytes": groth16_bytes.len(),
            "evm_seal_file": evm_seal_name,
            "evm_seal_sha256": sha256(&evm_seal),
            "evm_seal_bytes": evm_seal.len(),
            "receipt_verified": true,
            "dev_mode": false,
            "generates_proofs": true,
            "mines": false
        });
        let mut output_bytes = serde_json::to_vec_pretty(&output)
            .map_err(|error| format!("cannot encode outer EVM proof index: {error}"))?;
        output_bytes.push(b'\n');
        let package_index_sha256 = sha256(&output_bytes);
        atomic_publish(
            &paths.output_directory.join(OUTER_EVM_PACKAGE_INDEX_NAME),
            &output_bytes,
        )?;
        Ok(OuterEvmProofSummary {
            statement_hash: hex(&statement_hash),
            evm_seal_sha256: sha256(&evm_seal),
            package_index_sha256,
        })
    }

    #[cfg(test)]
    mod tests {
        use std::fs;

        use tempfile::TempDir;

        use super::{canonical_hash, decode_hash, nonzero_hash, read_unchanged, sha256};

        #[test]
        fn canonical_hash_decoder_rejects_ambiguous_values() {
            let valid = "ab".repeat(32);
            assert!(canonical_hash(&valid));
            assert!(nonzero_hash(&valid));
            assert_eq!(decode_hash(&valid), Ok([0xab; 32]));
            assert!(decode_hash(&"0".repeat(64)).is_err());
            assert!(!canonical_hash(&format!("0x{valid}")));
            assert!(!canonical_hash(&valid.to_uppercase()));
            assert!(!nonzero_hash(&"00".repeat(32)));
        }

        #[test]
        fn outer_provenance_rejects_source_index_replacement() {
            let directory = TempDir::new().expect("temporary directory");
            let path = directory.path().join("checkpoint-source-set-index.json");
            let original = br#"{"schema":"generation-a"}"#;
            fs::write(&path, original).expect("write original source index");
            let expected = sha256(original);
            assert_eq!(
                read_unchanged(&path, 1024, &expected, "checkpoint source-set index")
                    .expect("unchanged source index"),
                original
            );

            fs::write(&path, br#"{"schema":"generation-b"}"#).expect("replace source index");
            let error = read_unchanged(&path, 1024, &expected, "checkpoint source-set index")
                .expect_err("replacement must fail closed");
            assert_eq!(
                error,
                "checkpoint source-set index changed after plan rebuild"
            );
        }
    }
}

#[cfg(feature = "prove")]
pub use verified::{
    package_outer_evm_proof, prove_outer_checkpoint, prove_segment_set, OuterEvmProofPaths,
    OuterEvmProofSummary, OuterProofPaths, OuterProofSummary, SegmentProofPaths,
    SegmentProofSummary,
};
#[cfg(feature = "verify")]
pub use verified::{
    publish_outer_plan, publish_segment_plan, verify_rebuild_receipt, OuterPlanPaths,
    OuterPlanSummary, SegmentPlanPaths, SegmentPlanSummary,
};
