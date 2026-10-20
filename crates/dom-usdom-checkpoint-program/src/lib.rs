//! Deterministic reference boundary for DOM checkpoint extension proofs.
//!
//! The first implemented layer freezes the ordinary DOM economic state that
//! must continue alongside native USDOM state. A checkpoint proof that omits
//! this layer could accept nonexistent inputs, immature coinbase spends,
//! duplicate outputs, or replayed kernels while still presenting valid PoW
//! headers. The sparse roots here are carried through `UDCCTX02`.
//!
//! This crate is a host reference relation. It is not a deployed proving guest
//! or an Ethereum verifier and grants no checkpoint authority on its own.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};

#[cfg(all(feature = "host-reference", test))]
use dom_chain::canonical_header_identifier;
#[cfg(feature = "host-reference")]
use dom_chain::{NativeUsdomV2ActivationSchedule, UsdomV2ExecutionWitnesses, UsdomV4BlockPackage};
#[cfg(feature = "host-reference")]
use dom_consensus::derive_chain_id;
#[cfg(any(feature = "host-reference", feature = "portable-execution"))]
use dom_consensus::Block;
#[cfg(feature = "host-reference")]
use dom_consensus::BlockHeader;
#[cfg(feature = "host-reference")]
use dom_pow::randomx_pool::randomx_hash;
#[cfg(all(feature = "host-reference", test))]
use dom_serialization::DomSerialize;
pub use dom_usdom_checkpoint_statement::{
    checkpoint_compact_target, checkpoint_hash_meets_target, checkpoint_randomx_seed_height,
    CheckpointRandomXStatement, CheckpointRandomXStatementError, CheckpointStatementV4,
    CHECKPOINT_RANDOMX_BLOCK_VERSION, CHECKPOINT_RANDOMX_PREIMAGE_BYTES,
    CHECKPOINT_RANDOMX_PREIMAGE_HEIGHT_OFFSET, CHECKPOINT_RANDOMX_PREIMAGE_TARGET_OFFSET,
    CHECKPOINT_RANDOMX_STATEMENT_BYTES, CHECKPOINT_STATEMENT_V4_BYTES,
};
use dom_usdom_checkpoint_statement::{
    checkpoint_economic_state_root, CheckpointContext, CHECKPOINT_CONTEXT_BYTES,
    CHECKPOINT_NATIVE_STATE_VERSION, CHECKPOINT_TRANSITION_BATCH_VERSION,
};
#[cfg(any(feature = "host-reference", feature = "segment-portable-policy"))]
use dom_usdom_privacy::verifier::SpendVerifier;
use sha3::{Digest, Keccak256};
use thiserror::Error;
#[cfg(any(feature = "host-reference", feature = "segment-portable-policy"))]
use usdom_ethereum_finality_experiment::{
    checkpoints::StaticCheckpointTrustPolicy, deposits::StaticDepositTrustPolicy,
};

#[cfg(feature = "economic-chunks")]
mod economic_chunks;
#[cfg(feature = "economic-chunks")]
pub use economic_chunks::execute_economic_chunk_portable;
#[cfg(feature = "economic-chunks")]
pub use economic_chunks::{
    economic_chunk_package_commitment, EconomicBlockTransition, EconomicChunkExecution,
    EconomicChunkTransition, EconomicChunkTransitionError, EconomicChunkWitness,
    ECONOMIC_BLOCK_TRANSITION_BYTES, ECONOMIC_CHUNK_TRANSITION_BYTES,
};

#[cfg(feature = "portable-execution")]
mod portable;
#[cfg(all(
    feature = "portable-execution",
    feature = "risc0-recursion",
    target_os = "zkvm"
))]
pub use portable::verify_checkpoint_economic_block_receipts_in_guest;
#[cfg(feature = "portable-execution")]
pub use portable::{
    execute_checkpoint_segment_portable, CheckpointEconomicBlockBinding,
    PortableCheckpointSegmentError, PortableCheckpointSegmentExecution,
};

#[cfg(feature = "outer-execution")]
mod outer;
#[cfg(all(
    feature = "outer-execution",
    feature = "risc0-recursion",
    target_os = "zkvm"
))]
pub use outer::verify_checkpoint_segment_receipts_in_guest;
#[cfg(feature = "outer-execution")]
pub use outer::{
    validate_checkpoint_outer_chain, CheckpointOuterChain, CheckpointOuterChainError,
    CheckpointOuterExecution, CheckpointSegmentReceiptAssumption, MAX_CHECKPOINT_OUTER_CHAIN_BYTES,
    MAX_CHECKPOINT_OUTER_SEGMENTS,
};

#[cfg(feature = "host-reference")]
mod reference;
#[cfg(feature = "host-reference")]
pub use reference::{
    execute_checkpoint_extension, execute_checkpoint_extension_v2_with_witnesses,
    execute_checkpoint_extension_with_economic_witnesses, CheckpointProgramError,
    CheckpointProgramPolicy, CheckpointProgramPolicyV2, CheckpointPublicOutput,
};

const SMT_DOMAIN: &[u8] = b"DOM:checkpoint-smt:v1";
const UTXO_TREE: u8 = b'U';
const KERNEL_TREE: u8 = b'K';
const EMPTY_NODE: u8 = 0;
const INTERNAL_NODE: u8 = 1;
const UTXO_LEAF: u8 = 2;
const KERNEL_LEAF: u8 = 3;
const TREE_DEPTH: usize = 256;
const ECONOMIC_PROOF_MAGIC: &[u8; 8] = b"UDECPR01";
const ECONOMIC_PROOF_HEADER_BYTES: usize = 8 + 1 + 33 + 32 + 2;

/// Maximum canonical encoding of one economic-state sparse path.
pub const MAX_ECONOMIC_PROOF_BYTES: usize = ECONOMIC_PROOF_HEADER_BYTES + TREE_DEPTH * 32;
/// Maximum keys in one block-level economic multiproof. This equals the
/// current 40,000 block-weight ceiling; every UTXO key consumes at least one
/// weight unit and every kernel consumes three.
pub const MAX_ECONOMIC_MULTIPROOF_KEYS: usize = 40_000;
const ECONOMIC_MULTIPROOF_MAGIC: &[u8; 8] = b"UDECMP01";
const ECONOMIC_MULTIPROOF_HEADER_BYTES: usize = 8 + 1 + 4 + 4;
/// Absolute encoding bound for a canonical depth-256 economic multiproof.
pub const MAX_ECONOMIC_MULTIPROOF_BYTES: usize = ECONOMIC_MULTIPROOF_HEADER_BYTES
    + MAX_ECONOMIC_MULTIPROOF_KEYS * 33
    + (MAX_ECONOMIC_MULTIPROOF_KEYS * TREE_DEPTH).div_ceil(8)
    + MAX_ECONOMIC_MULTIPROOF_KEYS * TREE_DEPTH * 32;
const ECONOMIC_BLOCK_WITNESS_MAGIC: &[u8; 8] = b"UDECBW01";
const ECONOMIC_BLOCK_WITNESS_HEADER_BYTES: usize = 8 + 4 + 4;
/// Maximum sparse-tree keys advanced by one bounded economic chunk.
#[cfg(feature = "economic-chunks")]
pub const MAX_ECONOMIC_CHUNK_KEYS: usize = 512;
/// Maximum deterministic UTXO/kernel chunks for one consensus-weight block.
#[cfg(feature = "economic-chunks")]
pub const MAX_ECONOMIC_BLOCK_CHUNKS: usize =
    (dom_core::MAX_BLOCK_WEIGHT as usize).div_ceil(MAX_ECONOMIC_CHUNK_KEYS) + 1;
/// Absolute canonical size of one economic chunk witness.
#[cfg(feature = "economic-chunks")]
pub const MAX_ECONOMIC_CHUNK_WITNESS_BYTES: usize = (8 + 2 + 4 + 4 + 4)
    + ECONOMIC_MULTIPROOF_HEADER_BYTES
    + MAX_ECONOMIC_CHUNK_KEYS * 33
    + (MAX_ECONOMIC_CHUNK_KEYS * TREE_DEPTH).div_ceil(8)
    + MAX_ECONOMIC_CHUNK_KEYS * TREE_DEPTH * 32
    + MAX_ECONOMIC_CHUNK_KEYS * 10;
const CHECKPOINT_SEGMENT_STATE_MAGIC: &[u8; 8] = b"UDCSEG02";
const CHECKPOINT_SEGMENT_STATE_VERSION: u16 = 2;
const CHECKPOINT_SEGMENT_STATE_PREFIX_BYTES: usize = 410;
const CHECKPOINT_SEGMENT_STATE_DOMAIN: &[u8] = b"DOM:checkpoint-segment-state:v2";
const CHECKPOINT_SEGMENT_TRANSITION_MAGIC: &[u8; 8] = b"UDCSTN02";
const CHECKPOINT_SEGMENT_TRANSITION_VERSION: u16 = 2;
const CHECKPOINT_SEGMENT_TRANSITION_PREFIX_BYTES: usize = 44;
const CHECKPOINT_SEGMENT_TRANSITION_DOMAIN: &[u8] = b"DOM:checkpoint-segment-transition:v2";
const CHECKPOINT_SEGMENT_PRIVATE_INPUT_MAGIC: &[u8; 8] = b"UDCSPI01";
const CHECKPOINT_SEGMENT_PRIVATE_INPUT_VERSION: u16 = 1;
const CHECKPOINT_SEGMENT_PRIVATE_INPUT_HEADER_BYTES: usize = 12;
const CHECKPOINT_SEGMENT_PRIVATE_BLOCK_HEADER_BYTES: usize = 12;
const CHECKPOINT_SEGMENT_PRIVATE_INPUT_DOMAIN: &[u8] = b"DOM:checkpoint-segment-private-input:v1";
const CHECKPOINT_SEGMENT_POLICY_INPUT_MAGIC: &[u8; 8] = b"UDCSPOL1";
const CHECKPOINT_SEGMENT_POLICY_INPUT_VERSION: u16 = 1;
const CHECKPOINT_SEGMENT_POLICY_INPUT_DOMAIN: &[u8] = b"DOM:checkpoint-segment-policy-input:v1";
const CHECKPOINT_SEGMENT_POLICY_INPUT_HEADER_BYTES: usize = 12;
const CHECKPOINT_SEGMENT_NATIVE_OPENING_MAGIC: &[u8; 8] = b"UDCSNS01";
const CHECKPOINT_SEGMENT_NATIVE_OPENING_VERSION: u16 = 1;
const CHECKPOINT_SEGMENT_NATIVE_OPENING_HEADER_BYTES: usize = 12;
const CHECKPOINT_SEGMENT_NATIVE_OPENING_DOMAIN: &[u8] =
    b"DOM:checkpoint-segment-native-state-opening:v1";
#[cfg(feature = "segment-portable-policy")]
const CHECKPOINT_SEGMENT_V2_ACTIVATION_MAGIC: &[u8; 8] = b"UDACTV02";
#[cfg(feature = "segment-portable-policy")]
const CHECKPOINT_SEGMENT_V2_ACTIVATION_VERSION: u16 = 2;
#[cfg(feature = "segment-portable-policy")]
const CHECKPOINT_SEGMENT_V2_ACTIVATION_DOMAIN: &str = "DOM:usdom-v2-activation-schedule:v1";
#[cfg(feature = "segment-bindings")]
const CHECKPOINT_RANDOMX_AGGREGATE_MAGIC: &[u8; 8] = b"UDCRXAG1";
#[cfg(feature = "segment-bindings")]
const CHECKPOINT_RANDOMX_AGGREGATE_VERSION: u16 = 1;
#[cfg(feature = "segment-bindings")]
const CHECKPOINT_RANDOMX_AGGREGATE_DOMAIN: &[u8] = b"DOM:checkpoint-randomx-aggregate:v1";
#[cfg(feature = "segment-bindings")]
const CHECKPOINT_RANDOMX_RECEIPT_SET_DOMAIN: &[u8] = b"DOM:checkpoint-randomx-receipt-set:v1";
#[cfg(feature = "segment-bindings")]
const CHECKPOINT_USDOM_V4_PACKAGE_MAGIC: &[u8; 8] = b"USDOMBL4";
#[cfg(feature = "segment-bindings")]
const CHECKPOINT_USDOM_V4_PACKAGE_VERSION: u16 = 1;
#[cfg(feature = "segment-bindings")]
const CHECKPOINT_USDOM_V4_PACKAGE_HEADER_BYTES: usize = 18;
#[cfg(feature = "segment-bindings")]
const CHECKPOINT_DOM_V4_HEADER_BYTES: usize = 256;
#[cfg(feature = "segment-bindings")]
const CHECKPOINT_USDOM_V4_ENVELOPE_MIN_BYTES: usize = 14;
#[cfg(feature = "segment-bindings")]
const CHECKPOINT_USDOM_V4_ENVELOPE_MAGIC: &[u8; 8] = b"USDOMV41";
#[cfg(feature = "segment-bindings")]
const CHECKPOINT_USDOM_V4_ENVELOPE_VERSION: u16 = 1;
#[cfg(feature = "segment-bindings")]
const CHECKPOINT_USDOM_V4_ENTRY_HEADER_BYTES: usize = 5;
/// Exact byte length of one ordered segment RandomX aggregate statement.
pub const CHECKPOINT_RANDOMX_AGGREGATE_BYTES: usize = 8 + 2 + 2 + 32 + 32;
/// Exact byte length of one recursive checkpoint segment state.
pub const CHECKPOINT_SEGMENT_STATE_BYTES: usize =
    CHECKPOINT_SEGMENT_STATE_PREFIX_BYTES + CHECKPOINT_CONTEXT_BYTES;
/// Maximum blocks proved by one recursive checkpoint segment.
pub const MAX_CHECKPOINT_SEGMENT_BLOCKS: u16 = 32;
/// Exact byte length of one recursive checkpoint segment transition statement.
pub const CHECKPOINT_SEGMENT_TRANSITION_BYTES: usize =
    CHECKPOINT_SEGMENT_TRANSITION_PREFIX_BYTES + 2 * CHECKPOINT_SEGMENT_STATE_BYTES;
/// Maximum canonical bytes accepted for one private segment input.
pub const MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES: usize = 64 * 1024 * 1024;
/// Maximum canonical DOM package bytes accepted for one segment block.
pub const MAX_CHECKPOINT_SEGMENT_PACKAGE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum native state-opening bytes accepted for one segment block.
pub const MAX_CHECKPOINT_SEGMENT_NATIVE_WITNESS_BYTES: usize = 4 * 1024 * 1024;
/// Practical release ceiling for one ordinary-DOM economic witness.
pub const MAX_CHECKPOINT_SEGMENT_ECONOMIC_WITNESS_BYTES: usize = 16 * 1024 * 1024;
/// Exact candidate-v2 activation schedule bytes supplied to a segment guest.
pub const CHECKPOINT_SEGMENT_ACTIVATION_SCHEDULE_BYTES: usize = 154;
/// Exact immutable Ethereum checkpoint policy bytes supplied to a segment guest.
pub const CHECKPOINT_SEGMENT_CHECKPOINT_POLICY_BYTES: usize = 362;
/// Exact immutable Ethereum deposit policy bytes supplied to a segment guest.
pub const CHECKPOINT_SEGMENT_DEPOSIT_POLICY_BYTES: usize = 302;
/// Maximum canonical compressed BN254 spend verifying key accepted by a segment guest.
pub const MAX_CHECKPOINT_SEGMENT_SPEND_VERIFYING_KEY_BYTES: usize = 4 * 1024;
/// Maximum canonical bytes accepted for the previous candidate-v2 state
/// opening. The framing adds a fixed header to the largest canonical state.
pub const MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES: usize =
    CHECKPOINT_SEGMENT_NATIVE_OPENING_HEADER_BYTES + 847;
/// Maximum canonical policy input bytes accepted by one segment guest.
pub const MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES: usize =
    CHECKPOINT_SEGMENT_POLICY_INPUT_HEADER_BYTES
        + 32
        + CHECKPOINT_SEGMENT_ACTIVATION_SCHEDULE_BYTES
        + CHECKPOINT_SEGMENT_CHECKPOINT_POLICY_BYTES
        + CHECKPOINT_SEGMENT_DEPOSIT_POLICY_BYTES
        + MAX_CHECKPOINT_SEGMENT_SPEND_VERIFYING_KEY_BYTES;

/// Failure while executing the native RandomX reference relation.
#[cfg(feature = "host-reference")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CheckpointRandomXReferenceError {
    /// The public statement is malformed or does not satisfy its target.
    #[error(transparent)]
    InvalidStatement(#[from] CheckpointRandomXStatementError),
    /// The native RandomX implementation could not evaluate the relation.
    #[error("native RandomX reference execution failed")]
    ExecutionFailed,
    /// The statement's claimed output differs from exact RandomX execution.
    #[error("checkpoint RandomX output does not match native execution")]
    HashMismatch,
}

/// Derive the only valid RandomX statement for one canonically parsed header.
///
/// The caller supplies only the immutable chain identity and the already
/// authenticated seed block. Height, preimage, claimed output and target are
/// copied from the header and cannot diverge from it.
#[cfg(feature = "host-reference")]
pub fn checkpoint_randomx_statement_for_header(
    network_magic: u32,
    chain_id: [u8; 32],
    seed_hash: [u8; 32],
    header: &BlockHeader,
) -> Result<CheckpointRandomXStatement, CheckpointRandomXStatementError> {
    let pow_preimage: [u8; CHECKPOINT_RANDOMX_PREIMAGE_BYTES] = header
        .pow_preimage()
        .try_into()
        .map_err(|_| CheckpointRandomXStatementError::InvalidFraming)?;
    let statement = CheckpointRandomXStatement {
        network_magic,
        chain_id,
        block_height: header.height.0,
        seed_height: checkpoint_randomx_seed_height(header.height.0),
        seed_hash,
        pow_preimage,
        randomx_hash: *header.pow.randomx_hash.as_bytes(),
        target: header
            .target
            .to_target()
            .map_err(|_| CheckpointRandomXStatementError::InvalidTarget)?,
    };
    statement.validate()?;
    Ok(statement)
}

/// Recompute the exact RandomX relation for one in-memory statement.
///
/// This function checks only `RandomX(seed_hash, pow_preimage) ==
/// randomx_hash`. Callers that authorize work must additionally validate the
/// canonical statement, target and consensus context. Keeping the relation
/// separate permits known-answer tests whose output intentionally does not
/// satisfy a live-network difficulty target.
#[cfg(feature = "host-reference")]
pub fn verify_checkpoint_randomx_relation(
    statement: &CheckpointRandomXStatement,
) -> Result<(), CheckpointRandomXReferenceError> {
    let computed = randomx_hash(&statement.seed_hash, &statement.pow_preimage)
        .map_err(|_| CheckpointRandomXReferenceError::ExecutionFailed)?;
    if computed != statement.randomx_hash {
        return Err(CheckpointRandomXReferenceError::HashMismatch);
    }
    Ok(())
}

/// Execute the complete native reference boundary for canonical `UDCRXST1`.
///
/// The fixed-width statement is parsed and validated before RandomX is
/// recomputed. A commitment is returned only when framing, seed schedule,
/// target binding, accumulated work claim and the actual hash relation all
/// agree. This is a native reference oracle and grants no proof authority.
#[cfg(feature = "host-reference")]
pub fn execute_checkpoint_randomx_reference(
    statement_bytes: &[u8],
) -> Result<[u8; 32], CheckpointRandomXReferenceError> {
    let statement = CheckpointRandomXStatement::from_bytes(statement_bytes)?;
    verify_checkpoint_randomx_relation(&statement)?;
    Ok(statement.commitment()?)
}

/// Public state carried between bounded recursive checkpoint proof segments.
///
/// This type authenticates no block by itself. A segment guest must validate
/// one or more complete DOM transitions before it may emit the next value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointSegmentState {
    /// DOM network magic selected by the immutable proving policy.
    pub network_magic: u32,
    /// Canonical DOM chain identity.
    pub chain_id: [u8; 32],
    /// Ratified native-v2 activation schedule commitment.
    pub activation_schedule_commitment: [u8; 32],
    /// Immutable Ethereum checkpoint-registry configuration commitment.
    pub checkpoint_config_hash: [u8; 32],
    /// Immutable Ethereum checkpoint-finality verification policy.
    pub checkpoint_policy_hash: [u8; 32],
    /// Immutable Ethereum deposit-finality verification policy.
    pub deposit_policy_hash: [u8; 32],
    /// Exact native private-spend verifier configuration.
    pub privacy_verifier_config_hash: [u8; 32],
    /// RISC Zero ImageID authorized to prove every RandomX header relation.
    pub randomx_receipt_image_id: [u8; 32],
    /// Height of the state after the preceding proved segment.
    pub height: u64,
    /// Canonical DOM block identifier at `height`.
    pub block_hash: [u8; 32],
    /// Candidate-v2 native USDOM state root at `height`.
    pub native_state_root: [u8; 32],
    /// Authenticated ordinary-DOM UTXO sparse root.
    pub economic_utxo_root: [u8; 32],
    /// Authenticated ordinary-DOM historical-kernel sparse root.
    pub economic_kernel_root: [u8; 32],
    /// Big-endian accumulated DOM work at `height`.
    pub total_difficulty: [u8; 32],
    /// Complete MTP, RandomX-seed and economic continuation context.
    pub context: CheckpointContext,
}

/// Failure to encode or validate a recursive checkpoint segment state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CheckpointSegmentStateError {
    /// Magic, version, length or canonical representation is invalid.
    #[error("invalid checkpoint segment state framing")]
    InvalidFraming,
    /// A required chain, policy, block, state or work identity is zero.
    #[error("invalid checkpoint segment state identity")]
    InvalidIdentity,
    /// The continuation context does not open the same block and economic roots.
    #[error("checkpoint segment state context mismatch")]
    ContextMismatch,
}

impl CheckpointSegmentState {
    /// Validate identities and the complete continuation-context opening.
    pub fn validate(&self) -> Result<(), CheckpointSegmentStateError> {
        if self.network_magic == 0
            || [
                self.chain_id,
                self.activation_schedule_commitment,
                self.checkpoint_config_hash,
                self.checkpoint_policy_hash,
                self.deposit_policy_hash,
                self.privacy_verifier_config_hash,
                self.randomx_receipt_image_id,
                self.block_hash,
                self.native_state_root,
                self.economic_utxo_root,
                self.economic_kernel_root,
                self.total_difficulty,
            ]
            .contains(&[0; 32])
            || self.height == 0
        {
            return Err(CheckpointSegmentStateError::InvalidIdentity);
        }
        self.context
            .validate()
            .map_err(|_| CheckpointSegmentStateError::ContextMismatch)?;
        let economic_root =
            checkpoint_economic_state_root(self.economic_utxo_root, self.economic_kernel_root)
                .map_err(|_| CheckpointSegmentStateError::ContextMismatch)?;
        if self.context.checkpoint_height != self.height
            || self.context.checkpoint_block != self.block_hash
            || self.context.economic_state_root != economic_root
        {
            return Err(CheckpointSegmentStateError::ContextMismatch);
        }
        Ok(())
    }

    /// Encode the unique fixed-width `UDCSEG02` representation.
    pub fn to_bytes(
        &self,
    ) -> Result<[u8; CHECKPOINT_SEGMENT_STATE_BYTES], CheckpointSegmentStateError> {
        self.validate()?;
        let context = self
            .context
            .to_bytes()
            .map_err(|_| CheckpointSegmentStateError::ContextMismatch)?;
        let mut bytes = [0u8; CHECKPOINT_SEGMENT_STATE_BYTES];
        bytes[..8].copy_from_slice(CHECKPOINT_SEGMENT_STATE_MAGIC);
        bytes[8..10].copy_from_slice(&CHECKPOINT_SEGMENT_STATE_VERSION.to_be_bytes());
        bytes[10..12].copy_from_slice(&CHECKPOINT_NATIVE_STATE_VERSION.to_be_bytes());
        bytes[12..14].copy_from_slice(&CHECKPOINT_TRANSITION_BATCH_VERSION.to_be_bytes());
        bytes[14..18].copy_from_slice(&self.network_magic.to_be_bytes());
        bytes[18..50].copy_from_slice(&self.chain_id);
        bytes[50..82].copy_from_slice(&self.activation_schedule_commitment);
        bytes[82..114].copy_from_slice(&self.checkpoint_config_hash);
        bytes[114..146].copy_from_slice(&self.checkpoint_policy_hash);
        bytes[146..178].copy_from_slice(&self.deposit_policy_hash);
        bytes[178..210].copy_from_slice(&self.privacy_verifier_config_hash);
        bytes[210..242].copy_from_slice(&self.randomx_receipt_image_id);
        bytes[242..250].copy_from_slice(&self.height.to_be_bytes());
        bytes[250..282].copy_from_slice(&self.block_hash);
        bytes[282..314].copy_from_slice(&self.native_state_root);
        bytes[314..346].copy_from_slice(&self.economic_utxo_root);
        bytes[346..378].copy_from_slice(&self.economic_kernel_root);
        bytes[378..410].copy_from_slice(&self.total_difficulty);
        bytes[410..].copy_from_slice(&context);
        Ok(bytes)
    }

    /// Decode, validate and canonically re-encode one `UDCSEG02` state.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CheckpointSegmentStateError> {
        if bytes.len() != CHECKPOINT_SEGMENT_STATE_BYTES
            || bytes.get(..8) != Some(CHECKPOINT_SEGMENT_STATE_MAGIC.as_slice())
            || u16::from_be_bytes(segment_array(bytes, 8)?) != CHECKPOINT_SEGMENT_STATE_VERSION
            || u16::from_be_bytes(segment_array(bytes, 10)?) != CHECKPOINT_NATIVE_STATE_VERSION
            || u16::from_be_bytes(segment_array(bytes, 12)?) != CHECKPOINT_TRANSITION_BATCH_VERSION
        {
            return Err(CheckpointSegmentStateError::InvalidFraming);
        }
        let state = Self {
            network_magic: u32::from_be_bytes(segment_array(bytes, 14)?),
            chain_id: segment_array(bytes, 18)?,
            activation_schedule_commitment: segment_array(bytes, 50)?,
            checkpoint_config_hash: segment_array(bytes, 82)?,
            checkpoint_policy_hash: segment_array(bytes, 114)?,
            deposit_policy_hash: segment_array(bytes, 146)?,
            privacy_verifier_config_hash: segment_array(bytes, 178)?,
            randomx_receipt_image_id: segment_array(bytes, 210)?,
            height: u64::from_be_bytes(segment_array(bytes, 242)?),
            block_hash: segment_array(bytes, 250)?,
            native_state_root: segment_array(bytes, 282)?,
            economic_utxo_root: segment_array(bytes, 314)?,
            economic_kernel_root: segment_array(bytes, 346)?,
            total_difficulty: segment_array(bytes, 378)?,
            context: CheckpointContext::from_bytes(
                bytes
                    .get(CHECKPOINT_SEGMENT_STATE_PREFIX_BYTES..)
                    .ok_or(CheckpointSegmentStateError::InvalidFraming)?,
            )
            .map_err(|_| CheckpointSegmentStateError::ContextMismatch)?,
        };
        state.validate()?;
        if state.to_bytes()?.as_slice() != bytes {
            return Err(CheckpointSegmentStateError::InvalidFraming);
        }
        Ok(state)
    }

    /// Keccak commitment used to chain a segment receipt to its exact state.
    pub fn commitment(&self) -> Result<[u8; 32], CheckpointSegmentStateError> {
        let bytes = self.to_bytes()?;
        let mut hasher = Keccak256::new();
        hasher.update(CHECKPOINT_SEGMENT_STATE_DOMAIN);
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }
}

/// Canonical public-policy preimages consumed by a checkpoint segment guest.
///
/// The recursive state carries hashes of these values. A generic guest still
/// needs the exact activation schedule, Ethereum trust policies and spend
/// verifying key to execute the transition. This bounded transport provides
/// those bytes without granting them authority: host-reference validation must
/// reconstruct every typed policy and match it against the chained state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointSegmentPolicyInput {
    dom_genesis_hash: [u8; 32],
    activation_schedule: [u8; CHECKPOINT_SEGMENT_ACTIVATION_SCHEDULE_BYTES],
    checkpoint_policy: [u8; CHECKPOINT_SEGMENT_CHECKPOINT_POLICY_BYTES],
    deposit_policy: [u8; CHECKPOINT_SEGMENT_DEPOSIT_POLICY_BYTES],
    spend_verifying_key: Vec<u8>,
}

/// Failure to decode or authenticate one segment policy input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CheckpointSegmentPolicyInputError {
    /// Magic, version, exact lengths or canonical representation is invalid.
    #[error("invalid checkpoint segment policy input framing")]
    InvalidFraming,
    /// Genesis identity or verifying-key bytes are empty or oversized.
    #[error("invalid checkpoint segment policy input identity")]
    InvalidIdentity,
    /// A typed schedule, policy or verifying key cannot be reconstructed.
    #[error("invalid checkpoint segment execution policy")]
    InvalidPolicy,
    /// Reconstructed policy identities do not match the chained segment state.
    #[error("checkpoint segment execution policy does not match state")]
    PolicyMismatch,
}

impl CheckpointSegmentPolicyInput {
    /// Construct one bounded canonical policy input.
    pub fn new(
        dom_genesis_hash: [u8; 32],
        activation_schedule: [u8; CHECKPOINT_SEGMENT_ACTIVATION_SCHEDULE_BYTES],
        checkpoint_policy: [u8; CHECKPOINT_SEGMENT_CHECKPOINT_POLICY_BYTES],
        deposit_policy: [u8; CHECKPOINT_SEGMENT_DEPOSIT_POLICY_BYTES],
        spend_verifying_key: Vec<u8>,
    ) -> Result<Self, CheckpointSegmentPolicyInputError> {
        let input = Self {
            dom_genesis_hash,
            activation_schedule,
            checkpoint_policy,
            deposit_policy,
            spend_verifying_key,
        };
        input.validate()?;
        Ok(input)
    }

    /// Canonical DOM genesis identifier used for chain and epoch-zero binding.
    pub fn dom_genesis_hash(&self) -> &[u8; 32] {
        &self.dom_genesis_hash
    }

    /// Exact candidate-v2 activation schedule bytes.
    pub fn activation_schedule_bytes(&self) -> &[u8; CHECKPOINT_SEGMENT_ACTIVATION_SCHEDULE_BYTES] {
        &self.activation_schedule
    }

    /// Exact immutable Ethereum checkpoint trust-policy bytes.
    pub fn checkpoint_policy_bytes(&self) -> &[u8; CHECKPOINT_SEGMENT_CHECKPOINT_POLICY_BYTES] {
        &self.checkpoint_policy
    }

    /// Exact immutable Ethereum deposit trust-policy bytes.
    pub fn deposit_policy_bytes(&self) -> &[u8; CHECKPOINT_SEGMENT_DEPOSIT_POLICY_BYTES] {
        &self.deposit_policy
    }

    /// Exact compressed BN254 spend verifying-key bytes.
    pub fn spend_verifying_key_bytes(&self) -> &[u8] {
        &self.spend_verifying_key
    }

    /// Validate allocation and identity bounds without interpreting policies.
    pub fn validate(&self) -> Result<(), CheckpointSegmentPolicyInputError> {
        if self.dom_genesis_hash == [0; 32]
            || self.spend_verifying_key.is_empty()
            || self.spend_verifying_key.len() > MAX_CHECKPOINT_SEGMENT_SPEND_VERIFYING_KEY_BYTES
        {
            return Err(CheckpointSegmentPolicyInputError::InvalidIdentity);
        }
        Ok(())
    }

    /// Encode the unique bounded `UDCSPOL1` representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CheckpointSegmentPolicyInputError> {
        self.validate()?;
        let key_length = u16::try_from(self.spend_verifying_key.len())
            .map_err(|_| CheckpointSegmentPolicyInputError::InvalidIdentity)?;
        let mut bytes = Vec::with_capacity(
            CHECKPOINT_SEGMENT_POLICY_INPUT_HEADER_BYTES
                + 32
                + CHECKPOINT_SEGMENT_ACTIVATION_SCHEDULE_BYTES
                + CHECKPOINT_SEGMENT_CHECKPOINT_POLICY_BYTES
                + CHECKPOINT_SEGMENT_DEPOSIT_POLICY_BYTES
                + self.spend_verifying_key.len(),
        );
        bytes.extend_from_slice(CHECKPOINT_SEGMENT_POLICY_INPUT_MAGIC);
        bytes.extend_from_slice(&CHECKPOINT_SEGMENT_POLICY_INPUT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&key_length.to_be_bytes());
        bytes.extend_from_slice(&self.dom_genesis_hash);
        bytes.extend_from_slice(&self.activation_schedule);
        bytes.extend_from_slice(&self.checkpoint_policy);
        bytes.extend_from_slice(&self.deposit_policy);
        bytes.extend_from_slice(&self.spend_verifying_key);
        Ok(bytes)
    }

    /// Decode and canonically re-encode one exact `UDCSPOL1` input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CheckpointSegmentPolicyInputError> {
        const FIXED_BYTES: usize = CHECKPOINT_SEGMENT_POLICY_INPUT_HEADER_BYTES
            + 32
            + CHECKPOINT_SEGMENT_ACTIVATION_SCHEDULE_BYTES
            + CHECKPOINT_SEGMENT_CHECKPOINT_POLICY_BYTES
            + CHECKPOINT_SEGMENT_DEPOSIT_POLICY_BYTES;
        if bytes.len() <= FIXED_BYTES
            || bytes.len() > MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES
            || bytes.get(..8) != Some(CHECKPOINT_SEGMENT_POLICY_INPUT_MAGIC.as_slice())
            || u16::from_be_bytes(
                bytes
                    .get(8..10)
                    .ok_or(CheckpointSegmentPolicyInputError::InvalidFraming)?
                    .try_into()
                    .map_err(|_| CheckpointSegmentPolicyInputError::InvalidFraming)?,
            ) != CHECKPOINT_SEGMENT_POLICY_INPUT_VERSION
        {
            return Err(CheckpointSegmentPolicyInputError::InvalidFraming);
        }
        let key_length = usize::from(u16::from_be_bytes(
            bytes
                .get(10..12)
                .ok_or(CheckpointSegmentPolicyInputError::InvalidFraming)?
                .try_into()
                .map_err(|_| CheckpointSegmentPolicyInputError::InvalidFraming)?,
        ));
        if key_length == 0
            || key_length > MAX_CHECKPOINT_SEGMENT_SPEND_VERIFYING_KEY_BYTES
            || bytes.len() != FIXED_BYTES + key_length
        {
            return Err(CheckpointSegmentPolicyInputError::InvalidFraming);
        }
        let mut cursor = CHECKPOINT_SEGMENT_POLICY_INPUT_HEADER_BYTES;
        let mut take = |length: usize| -> Result<&[u8], CheckpointSegmentPolicyInputError> {
            let end = cursor
                .checked_add(length)
                .ok_or(CheckpointSegmentPolicyInputError::InvalidFraming)?;
            let value = bytes
                .get(cursor..end)
                .ok_or(CheckpointSegmentPolicyInputError::InvalidFraming)?;
            cursor = end;
            Ok(value)
        };
        let input = Self::new(
            take(32)?
                .try_into()
                .map_err(|_| CheckpointSegmentPolicyInputError::InvalidFraming)?,
            take(CHECKPOINT_SEGMENT_ACTIVATION_SCHEDULE_BYTES)?
                .try_into()
                .map_err(|_| CheckpointSegmentPolicyInputError::InvalidFraming)?,
            take(CHECKPOINT_SEGMENT_CHECKPOINT_POLICY_BYTES)?
                .try_into()
                .map_err(|_| CheckpointSegmentPolicyInputError::InvalidFraming)?,
            take(CHECKPOINT_SEGMENT_DEPOSIT_POLICY_BYTES)?
                .try_into()
                .map_err(|_| CheckpointSegmentPolicyInputError::InvalidFraming)?,
            take(key_length)?.to_vec(),
        )?;
        if cursor != bytes.len() || input.to_bytes()?.as_slice() != bytes {
            return Err(CheckpointSegmentPolicyInputError::InvalidFraming);
        }
        Ok(input)
    }

    /// Keccak commitment to every policy preimage and the DOM genesis identity.
    pub fn commitment(&self) -> Result<[u8; 32], CheckpointSegmentPolicyInputError> {
        let bytes = self.to_bytes()?;
        let mut hasher = Keccak256::new();
        hasher.update(CHECKPOINT_SEGMENT_POLICY_INPUT_DOMAIN);
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }

    /// Reconstruct every typed policy and authenticate it against `state`.
    #[cfg(feature = "host-reference")]
    pub fn validate_for_state(
        &self,
        state: &CheckpointSegmentState,
    ) -> Result<ValidatedCheckpointSegmentPolicy, CheckpointSegmentPolicyInputError> {
        self.validate()?;
        state
            .validate()
            .map_err(|_| CheckpointSegmentPolicyInputError::PolicyMismatch)?;
        let genesis = dom_core::Hash256::from_bytes(self.dom_genesis_hash);
        let schedule = NativeUsdomV2ActivationSchedule::from_bytes(&self.activation_schedule)
            .map_err(|_| CheckpointSegmentPolicyInputError::InvalidPolicy)?;
        let checkpoint_policy = StaticCheckpointTrustPolicy::from_bytes(&self.checkpoint_policy)
            .map_err(|_| CheckpointSegmentPolicyInputError::InvalidPolicy)?;
        let deposit_policy = StaticDepositTrustPolicy::from_bytes(&self.deposit_policy)
            .map_err(|_| CheckpointSegmentPolicyInputError::InvalidPolicy)?;
        let spend_verifier = SpendVerifier::from_bytes(&self.spend_verifying_key)
            .map_err(|_| CheckpointSegmentPolicyInputError::InvalidPolicy)?;
        let checkpoint = checkpoint_policy.checkpoint();
        let deposit = deposit_policy.deposit();
        let next_height = state
            .height
            .checked_add(1)
            .ok_or(CheckpointSegmentPolicyInputError::PolicyMismatch)?;
        let activation_boundary_matches = next_height != schedule.first_v2_height()
            || (state.block_hash == *schedule.activation_parent().as_bytes()
                && state.native_state_root == *schedule.initial_v2_state_root().as_bytes());
        if schedule.network_magic() != state.network_magic
            || schedule.chain_id().as_bytes() != &state.chain_id
            || derive_chain_id(state.network_magic, &genesis).as_bytes() != &state.chain_id
            || schedule.commitment().as_bytes() != &state.activation_schedule_commitment
            || next_height < schedule.first_v2_height()
            || !activation_boundary_matches
            || checkpoint_policy.policy_hash().as_slice() != state.checkpoint_policy_hash
            || checkpoint.checkpoint_config_hash.as_slice() != state.checkpoint_config_hash
            || checkpoint.dom_network_magic != state.network_magic
            || deposit_policy.policy_hash().as_slice() != state.deposit_policy_hash
            || checkpoint.ethereum_chain_id != deposit.ethereum_chain_id
            || checkpoint.ethereum_genesis_validators_root
                != deposit.ethereum_genesis_validators_root
            || checkpoint.bridge_domain != deposit.bridge_domain
            || spend_verifier.config_hash().as_bytes() != &state.privacy_verifier_config_hash
        {
            return Err(CheckpointSegmentPolicyInputError::PolicyMismatch);
        }
        Ok(ValidatedCheckpointSegmentPolicy {
            dom_genesis_hash: genesis,
            schedule,
            checkpoint_policy,
            deposit_policy,
            spend_verifier,
        })
    }
}

/// Canonical private opening of the candidate-v2 native state at a segment
/// boundary.
///
/// `UDCSEG02` carries only the state root. Executing the next segment requires
/// the complete fixed-order [`dom_usdom_state::StateCommitmentV2`] preimage so
/// that sparse transition witnesses have authenticated starting roots and
/// counters. This transport grants no authority by itself: an execution guest
/// must call [`Self::authenticate`] against `transition.previous` before using
/// the decoded state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointSegmentNativeStateOpening {
    state_bytes: Vec<u8>,
}

/// Failure to decode or authenticate a native-state segment opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CheckpointSegmentNativeStateOpeningError {
    /// Magic, version, length, or canonical representation is invalid.
    #[error("invalid checkpoint segment native-state opening framing")]
    InvalidFraming,
    /// The candidate-v2 state bytes are not canonical.
    #[error("invalid checkpoint segment candidate-v2 state")]
    InvalidState,
    /// The opening does not match the chained segment state and policies.
    #[error("checkpoint segment native-state opening does not match state")]
    StateMismatch,
}

impl CheckpointSegmentNativeStateOpening {
    /// Construct a bounded opening without granting validity to the state.
    pub fn new(state_bytes: Vec<u8>) -> Result<Self, CheckpointSegmentNativeStateOpeningError> {
        let opening = Self { state_bytes };
        opening.validate_framing()?;
        Ok(opening)
    }

    /// Exact canonical candidate-v2 state bytes.
    pub fn state_bytes(&self) -> &[u8] {
        &self.state_bytes
    }

    fn validate_framing(&self) -> Result<(), CheckpointSegmentNativeStateOpeningError> {
        // StateCommitmentV2 has exactly two canonical lengths: without or with
        // the optional 120-byte Ethereum anchor. Keeping these exact bounds in
        // the transport rejects ambiguous future encodings fail-closed.
        if !matches!(self.state_bytes.len(), 727 | 847)
            || self.state_bytes.get(..8) != Some(b"UDSTV002".as_slice())
        {
            return Err(CheckpointSegmentNativeStateOpeningError::InvalidFraming);
        }
        Ok(())
    }

    /// Encode the unique bounded `UDCSNS01` representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CheckpointSegmentNativeStateOpeningError> {
        self.validate_framing()?;
        let state_length = u16::try_from(self.state_bytes.len())
            .map_err(|_| CheckpointSegmentNativeStateOpeningError::InvalidFraming)?;
        let mut bytes = Vec::with_capacity(
            CHECKPOINT_SEGMENT_NATIVE_OPENING_HEADER_BYTES + self.state_bytes.len(),
        );
        bytes.extend_from_slice(CHECKPOINT_SEGMENT_NATIVE_OPENING_MAGIC);
        bytes.extend_from_slice(&CHECKPOINT_SEGMENT_NATIVE_OPENING_VERSION.to_be_bytes());
        bytes.extend_from_slice(&state_length.to_be_bytes());
        bytes.extend_from_slice(&self.state_bytes);
        Ok(bytes)
    }

    /// Decode and canonically re-encode one exact `UDCSNS01` opening.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CheckpointSegmentNativeStateOpeningError> {
        if bytes.len() <= CHECKPOINT_SEGMENT_NATIVE_OPENING_HEADER_BYTES
            || bytes.len() > MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES
            || bytes.get(..8) != Some(CHECKPOINT_SEGMENT_NATIVE_OPENING_MAGIC.as_slice())
            || u16::from_be_bytes(
                bytes
                    .get(8..10)
                    .ok_or(CheckpointSegmentNativeStateOpeningError::InvalidFraming)?
                    .try_into()
                    .map_err(|_| CheckpointSegmentNativeStateOpeningError::InvalidFraming)?,
            ) != CHECKPOINT_SEGMENT_NATIVE_OPENING_VERSION
        {
            return Err(CheckpointSegmentNativeStateOpeningError::InvalidFraming);
        }
        let state_length = usize::from(u16::from_be_bytes(
            bytes
                .get(10..12)
                .ok_or(CheckpointSegmentNativeStateOpeningError::InvalidFraming)?
                .try_into()
                .map_err(|_| CheckpointSegmentNativeStateOpeningError::InvalidFraming)?,
        ));
        let state_end = CHECKPOINT_SEGMENT_NATIVE_OPENING_HEADER_BYTES
            .checked_add(state_length)
            .ok_or(CheckpointSegmentNativeStateOpeningError::InvalidFraming)?;
        if state_end != bytes.len() {
            return Err(CheckpointSegmentNativeStateOpeningError::InvalidFraming);
        }
        let opening = Self::new(
            bytes
                .get(CHECKPOINT_SEGMENT_NATIVE_OPENING_HEADER_BYTES..state_end)
                .ok_or(CheckpointSegmentNativeStateOpeningError::InvalidFraming)?
                .to_vec(),
        )?;
        if opening.to_bytes()?.as_slice() != bytes {
            return Err(CheckpointSegmentNativeStateOpeningError::InvalidFraming);
        }
        Ok(opening)
    }

    /// Commitment used by prover-side inventories and reproducibility checks.
    ///
    /// The consensus authority remains the root in `UDCSEG02`; this digest is
    /// an observation identifier and cannot replace [`Self::authenticate`].
    pub fn commitment(&self) -> Result<[u8; 32], CheckpointSegmentNativeStateOpeningError> {
        let bytes = self.to_bytes()?;
        let mut hasher = Keccak256::new();
        hasher.update(CHECKPOINT_SEGMENT_NATIVE_OPENING_DOMAIN);
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }

    /// Decode the exact candidate-v2 state and bind it to a chained segment.
    #[cfg(feature = "segment-state-opening")]
    pub fn authenticate(
        &self,
        state: &CheckpointSegmentState,
    ) -> Result<dom_usdom_state::StateCommitmentV2, CheckpointSegmentNativeStateOpeningError> {
        self.validate_framing()?;
        state
            .validate()
            .map_err(|_| CheckpointSegmentNativeStateOpeningError::StateMismatch)?;
        let opened = dom_usdom_state::StateCommitmentV2::from_bytes(&self.state_bytes)
            .map_err(|_| CheckpointSegmentNativeStateOpeningError::InvalidState)?;
        if opened
            .to_bytes()
            .map_err(|_| CheckpointSegmentNativeStateOpeningError::InvalidState)?
            != self.state_bytes
            || opened.root().as_bytes() != &state.native_state_root
            || opened.ethereum_checkpoint_policy_hash != state.checkpoint_policy_hash
            || opened.ethereum_deposit_policy_hash != state.deposit_policy_hash
            || opened.privacy_verifier_config_hash != state.privacy_verifier_config_hash
        {
            return Err(CheckpointSegmentNativeStateOpeningError::StateMismatch);
        }
        Ok(opened)
    }
}

/// Portable projection of the exact `UDACTV02` activation schedule.
///
/// This type exists in the checkpoint boundary so the zkVM does not need the
/// storage and runtime dependencies of `dom-chain`. Its parser and commitment
/// are byte-for-byte compatible with the node-owned schedule.
#[cfg(feature = "segment-portable-policy")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointSegmentV2ActivationSchedule {
    network_magic: u32,
    chain_id: [u8; 32],
    first_v2_height: u64,
    activation_parent: [u8; 32],
    previous_v1_state_root: [u8; 32],
    initial_v2_state_root: [u8; 32],
}

#[cfg(feature = "segment-portable-policy")]
impl CheckpointSegmentV2ActivationSchedule {
    /// Decode and canonically re-encode one exact node-compatible schedule.
    pub fn from_bytes(
        bytes: &[u8; CHECKPOINT_SEGMENT_ACTIVATION_SCHEDULE_BYTES],
    ) -> Result<Self, CheckpointSegmentPolicyInputError> {
        if bytes.get(..8) != Some(CHECKPOINT_SEGMENT_V2_ACTIVATION_MAGIC.as_slice())
            || u16::from_be_bytes(
                bytes[8..10]
                    .try_into()
                    .map_err(|_| CheckpointSegmentPolicyInputError::InvalidPolicy)?,
            ) != CHECKPOINT_SEGMENT_V2_ACTIVATION_VERSION
            || u16::from_be_bytes(
                bytes[10..12]
                    .try_into()
                    .map_err(|_| CheckpointSegmentPolicyInputError::InvalidPolicy)?,
            ) != CHECKPOINT_NATIVE_STATE_VERSION
            || u16::from_be_bytes(
                bytes[12..14]
                    .try_into()
                    .map_err(|_| CheckpointSegmentPolicyInputError::InvalidPolicy)?,
            ) != CHECKPOINT_TRANSITION_BATCH_VERSION
        {
            return Err(CheckpointSegmentPolicyInputError::InvalidPolicy);
        }
        let schedule = Self {
            network_magic: u32::from_be_bytes(
                bytes[14..18]
                    .try_into()
                    .map_err(|_| CheckpointSegmentPolicyInputError::InvalidPolicy)?,
            ),
            chain_id: bytes[18..50]
                .try_into()
                .map_err(|_| CheckpointSegmentPolicyInputError::InvalidPolicy)?,
            first_v2_height: u64::from_be_bytes(
                bytes[50..58]
                    .try_into()
                    .map_err(|_| CheckpointSegmentPolicyInputError::InvalidPolicy)?,
            ),
            activation_parent: bytes[58..90]
                .try_into()
                .map_err(|_| CheckpointSegmentPolicyInputError::InvalidPolicy)?,
            previous_v1_state_root: bytes[90..122]
                .try_into()
                .map_err(|_| CheckpointSegmentPolicyInputError::InvalidPolicy)?,
            initial_v2_state_root: bytes[122..154]
                .try_into()
                .map_err(|_| CheckpointSegmentPolicyInputError::InvalidPolicy)?,
        };
        schedule.validate()?;
        if &schedule.to_bytes() != bytes {
            return Err(CheckpointSegmentPolicyInputError::InvalidPolicy);
        }
        Ok(schedule)
    }

    fn validate(&self) -> Result<(), CheckpointSegmentPolicyInputError> {
        if !matches!(
            self.network_magic,
            dom_core::NETWORK_MAGIC_MAINNET
                | dom_core::NETWORK_MAGIC_TESTNET
                | dom_core::NETWORK_MAGIC_REGTEST
        ) || self.chain_id == [0; 32]
            || self.first_v2_height == 0
            || self.activation_parent == [0; 32]
            || self.previous_v1_state_root == [0; 32]
            || self.initial_v2_state_root == [0; 32]
        {
            return Err(CheckpointSegmentPolicyInputError::InvalidPolicy);
        }
        Ok(())
    }

    /// Encode the exact fixed-width `UDACTV02` representation.
    pub fn to_bytes(self) -> [u8; CHECKPOINT_SEGMENT_ACTIVATION_SCHEDULE_BYTES] {
        let mut bytes = [0u8; CHECKPOINT_SEGMENT_ACTIVATION_SCHEDULE_BYTES];
        bytes[..8].copy_from_slice(CHECKPOINT_SEGMENT_V2_ACTIVATION_MAGIC);
        bytes[8..10].copy_from_slice(&CHECKPOINT_SEGMENT_V2_ACTIVATION_VERSION.to_be_bytes());
        bytes[10..12].copy_from_slice(&CHECKPOINT_NATIVE_STATE_VERSION.to_be_bytes());
        bytes[12..14].copy_from_slice(&CHECKPOINT_TRANSITION_BATCH_VERSION.to_be_bytes());
        bytes[14..18].copy_from_slice(&self.network_magic.to_be_bytes());
        bytes[18..50].copy_from_slice(&self.chain_id);
        bytes[50..58].copy_from_slice(&self.first_v2_height.to_be_bytes());
        bytes[58..90].copy_from_slice(&self.activation_parent);
        bytes[90..122].copy_from_slice(&self.previous_v1_state_root);
        bytes[122..154].copy_from_slice(&self.initial_v2_state_root);
        bytes
    }

    /// Domain-separated commitment used by node and checkpoint state.
    pub fn commitment(self) -> [u8; 32] {
        *dom_core::blake2b_256_tagged(CHECKPOINT_SEGMENT_V2_ACTIVATION_DOMAIN, &self.to_bytes())
            .as_bytes()
    }

    /// DOM network selected by the migration.
    pub const fn network_magic(self) -> u32 {
        self.network_magic
    }

    /// Canonical DOM chain identifier.
    pub const fn chain_id(self) -> [u8; 32] {
        self.chain_id
    }

    /// First height interpreted with candidate-v2 state semantics.
    pub const fn first_v2_height(self) -> u64 {
        self.first_v2_height
    }

    /// Exact activation parent ratified with the migration snapshot.
    pub const fn activation_parent(self) -> [u8; 32] {
        self.activation_parent
    }

    /// Active-v1 state root ratified at migration.
    pub const fn previous_v1_state_root(self) -> [u8; 32] {
        self.previous_v1_state_root
    }

    /// Candidate-v2 root derived from the same migration snapshot.
    pub const fn initial_v2_state_root(self) -> [u8; 32] {
        self.initial_v2_state_root
    }
}

/// Fully reconstructed policy available to a portable segment executor.
#[cfg(feature = "segment-portable-policy")]
pub struct ValidatedPortableCheckpointSegmentPolicy {
    dom_genesis_hash: [u8; 32],
    schedule: CheckpointSegmentV2ActivationSchedule,
    bridge: dom_usdom_state::BridgeIdentity,
    previous_native_state: dom_usdom_state::StateCommitmentV2,
    checkpoint_policy: StaticCheckpointTrustPolicy,
    deposit_policy: StaticDepositTrustPolicy,
    spend_verifier: SpendVerifier,
}

#[cfg(feature = "segment-portable-policy")]
impl ValidatedPortableCheckpointSegmentPolicy {
    /// Authenticated DOM genesis identifier.
    pub const fn dom_genesis_hash(&self) -> [u8; 32] {
        self.dom_genesis_hash
    }

    /// Ratified candidate-v2 migration schedule.
    pub const fn schedule(&self) -> CheckpointSegmentV2ActivationSchedule {
        self.schedule
    }

    /// Bridge identity opened from the authenticated previous state.
    pub const fn bridge(&self) -> dom_usdom_state::BridgeIdentity {
        self.bridge
    }

    /// Previous candidate-v2 state authenticated against `UDCSEG02`.
    pub const fn previous_native_state(&self) -> dom_usdom_state::StateCommitmentV2 {
        self.previous_native_state
    }

    /// Immutable Ethereum checkpoint policy.
    pub const fn checkpoint_policy(&self) -> &StaticCheckpointTrustPolicy {
        &self.checkpoint_policy
    }

    /// Immutable Ethereum deposit policy.
    pub const fn deposit_policy(&self) -> &StaticDepositTrustPolicy {
        &self.deposit_policy
    }

    /// Bridge-committed private-spend verifier.
    pub const fn spend_verifier(&self) -> &SpendVerifier {
        &self.spend_verifier
    }
}

#[cfg(feature = "segment-portable-policy")]
impl CheckpointSegmentPolicyInput {
    /// Reconstruct and authenticate every policy needed by a portable guest.
    pub fn validate_portable_for_state(
        &self,
        state: &CheckpointSegmentState,
        opening: &CheckpointSegmentNativeStateOpening,
    ) -> Result<ValidatedPortableCheckpointSegmentPolicy, CheckpointSegmentPolicyInputError> {
        self.validate()?;
        state
            .validate()
            .map_err(|_| CheckpointSegmentPolicyInputError::PolicyMismatch)?;
        let previous_native_state = opening
            .authenticate(state)
            .map_err(|_| CheckpointSegmentPolicyInputError::PolicyMismatch)?;
        let schedule =
            CheckpointSegmentV2ActivationSchedule::from_bytes(&self.activation_schedule)?;
        let checkpoint_policy = StaticCheckpointTrustPolicy::from_bytes(&self.checkpoint_policy)
            .map_err(|_| CheckpointSegmentPolicyInputError::InvalidPolicy)?;
        let deposit_policy = StaticDepositTrustPolicy::from_bytes(&self.deposit_policy)
            .map_err(|_| CheckpointSegmentPolicyInputError::InvalidPolicy)?;
        let spend_verifier = SpendVerifier::from_bytes(&self.spend_verifying_key)
            .map_err(|_| CheckpointSegmentPolicyInputError::InvalidPolicy)?;
        let checkpoint = checkpoint_policy.checkpoint();
        let deposit = deposit_policy.deposit();
        let next_height = state
            .height
            .checked_add(1)
            .ok_or(CheckpointSegmentPolicyInputError::PolicyMismatch)?;
        let activation_boundary_matches = next_height != schedule.first_v2_height
            || (state.block_hash == schedule.activation_parent
                && state.native_state_root == schedule.initial_v2_state_root);
        let mut ethereum_chain_id = [0u8; 32];
        ethereum_chain_id[24..].copy_from_slice(&checkpoint.ethereum_chain_id.to_be_bytes());
        let bridge = dom_usdom_state::BridgeIdentity {
            dom_domain: previous_native_state.domain,
            ethereum_genesis_validators_root: previous_native_state
                .ethereum_genesis_validators_root,
            ethereum_chain_id: previous_native_state.ethereum_chain_id,
            ethereum_checkpoint_policy_hash: previous_native_state.ethereum_checkpoint_policy_hash,
            ethereum_deposit_policy_hash: previous_native_state.ethereum_deposit_policy_hash,
            privacy_policy_hash: previous_native_state.privacy_policy_hash,
            privacy_verifier_config_hash: previous_native_state.privacy_verifier_config_hash,
            reserve: previous_native_state.reserve,
            burn_timing: previous_native_state.burn_timing,
        };
        if schedule.network_magic != state.network_magic
            || schedule.chain_id != state.chain_id
            || checkpoint_segment_chain_id(state.network_magic, self.dom_genesis_hash)
                != state.chain_id
            || schedule.commitment() != state.activation_schedule_commitment
            || next_height < schedule.first_v2_height
            || !activation_boundary_matches
            || checkpoint_policy.policy_hash().as_slice() != state.checkpoint_policy_hash
            || checkpoint.checkpoint_config_hash.as_slice() != state.checkpoint_config_hash
            || checkpoint.dom_network_magic != state.network_magic
            || deposit_policy.policy_hash().as_slice() != state.deposit_policy_hash
            || checkpoint.ethereum_chain_id != deposit.ethereum_chain_id
            || checkpoint.ethereum_genesis_validators_root
                != deposit.ethereum_genesis_validators_root
            || checkpoint.bridge_domain != deposit.bridge_domain
            || checkpoint.bridge_domain.as_slice() != previous_native_state.domain
            || checkpoint.ethereum_genesis_validators_root.as_slice()
                != previous_native_state.ethereum_genesis_validators_root
            || ethereum_chain_id != previous_native_state.ethereum_chain_id
            || deposit.reserve.as_slice() != previous_native_state.reserve
            || spend_verifier.config_hash().as_bytes()
                != &previous_native_state.privacy_verifier_config_hash
            || dom_usdom_privacy::privacy_policy_hash().as_bytes()
                != &previous_native_state.privacy_policy_hash
        {
            return Err(CheckpointSegmentPolicyInputError::PolicyMismatch);
        }
        Ok(ValidatedPortableCheckpointSegmentPolicy {
            dom_genesis_hash: self.dom_genesis_hash,
            schedule,
            bridge,
            previous_native_state,
            checkpoint_policy,
            deposit_policy,
            spend_verifier,
        })
    }
}

/// Typed policy objects authenticated against one chained segment state.
#[cfg(feature = "host-reference")]
pub struct ValidatedCheckpointSegmentPolicy {
    dom_genesis_hash: dom_core::Hash256,
    schedule: NativeUsdomV2ActivationSchedule,
    checkpoint_policy: StaticCheckpointTrustPolicy,
    deposit_policy: StaticDepositTrustPolicy,
    spend_verifier: SpendVerifier,
}

#[cfg(feature = "host-reference")]
impl ValidatedCheckpointSegmentPolicy {
    /// DOM genesis identifier authenticated through the state's chain ID.
    pub fn dom_genesis_hash(&self) -> dom_core::Hash256 {
        self.dom_genesis_hash
    }

    /// Candidate-v2 activation schedule authenticated by the state.
    pub fn schedule(&self) -> NativeUsdomV2ActivationSchedule {
        self.schedule
    }

    /// Immutable Ethereum checkpoint policy authenticated by the state.
    pub fn checkpoint_policy(&self) -> &StaticCheckpointTrustPolicy {
        &self.checkpoint_policy
    }

    /// Immutable Ethereum deposit policy authenticated by the state.
    pub fn deposit_policy(&self) -> &StaticDepositTrustPolicy {
        &self.deposit_policy
    }

    /// Native private-spend verifier authenticated by the state.
    pub fn spend_verifier(&self) -> &SpendVerifier {
        &self.spend_verifier
    }
}

/// Exact recursive receipt assumption required for one RandomX statement.
///
/// `image_id` is copied from the ratified segment state and `journal` is the
/// canonical `UDCRXST1` commitment. A future segment guest must pass these
/// exact values to its receipt verifier. This value describes the boundary;
/// it does not verify or create a receipt by itself.
///
/// ```compile_fail
/// use dom_usdom_checkpoint_program::CheckpointRandomXReceiptAssumption;
/// let _forged = CheckpointRandomXReceiptAssumption {
///     image_id: [0x11; 32],
///     journal: [0x22; 32],
/// };
/// ```
///
/// ```compile_fail
/// use dom_usdom_checkpoint_program::checkpoint_randomx_receipt_assumption_for_transition;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointRandomXReceiptAssumption {
    image_id: [u8; 32],
    journal: [u8; 32],
}

impl CheckpointRandomXReceiptAssumption {
    /// RISC Zero ImageID authorized by the recursive checkpoint policy.
    pub fn image_id(&self) -> &[u8; 32] {
        &self.image_id
    }

    /// Exact journal bytes committed by the RandomX receipt.
    pub fn journal(&self) -> &[u8; 32] {
        &self.journal
    }
}

/// Failure to derive the RandomX receipt assumption for a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CheckpointRandomXReceiptAssumptionError {
    /// The recursive checkpoint transition is not valid.
    #[error("invalid checkpoint transition for RandomX receipt assumption")]
    InvalidTransition,
    /// The RandomX public statement is not valid.
    #[error("invalid RandomX statement for receipt assumption")]
    InvalidStatement,
    /// The statement belongs to a different network or chain.
    #[error("RandomX receipt statement identity differs from checkpoint state")]
    IdentityMismatch,
    /// The statement is not one of the blocks proved by the segment.
    #[error("RandomX receipt statement height is outside the checkpoint segment")]
    HeightMismatch,
}

#[cfg(any(feature = "segment-bindings", test))]
fn checkpoint_randomx_receipt_assumption_for_state(
    state: &CheckpointSegmentState,
    statement: &CheckpointRandomXStatement,
) -> Result<CheckpointRandomXReceiptAssumption, CheckpointRandomXReceiptAssumptionError> {
    state
        .validate()
        .map_err(|_| CheckpointRandomXReceiptAssumptionError::InvalidTransition)?;
    statement
        .validate()
        .map_err(|_| CheckpointRandomXReceiptAssumptionError::InvalidStatement)?;
    if statement.network_magic != state.network_magic || statement.chain_id != state.chain_id {
        return Err(CheckpointRandomXReceiptAssumptionError::IdentityMismatch);
    }
    let journal = statement
        .commitment()
        .map_err(|_| CheckpointRandomXReceiptAssumptionError::InvalidStatement)?;
    Ok(CheckpointRandomXReceiptAssumption {
        image_id: state.randomx_receipt_image_id,
        journal,
    })
}

/// Convert the policy-bound ImageID bytes to the exact RISC Zero digest.
///
/// RISC Zero's byte-array conversion preserves all 32 bytes in their existing
/// order. Callers must not parse the bytes as integers or reverse 32-bit words.
#[cfg(feature = "risc0-recursion")]
pub fn checkpoint_randomx_receipt_image_id_digest(
    assumption: &CheckpointRandomXReceiptAssumption,
) -> risc0_zkvm::sha::Digest {
    risc0_zkvm::sha::Digest::from(*assumption.image_id())
}

/// Register the exact RandomX receipt assumption inside a RISC Zero guest.
///
/// The guest verifies a receipt for the state-pinned ImageID whose raw journal
/// is exactly the 32-byte `UDCRXST1` commitment. This function is unavailable
/// to host builds so a native test cannot be mistaken for receipt verification.
#[cfg(all(feature = "risc0-recursion", target_os = "zkvm"))]
pub fn verify_checkpoint_randomx_receipt_assumption_in_guest(
    assumption: &CheckpointRandomXReceiptAssumption,
) -> Result<(), core::convert::Infallible> {
    risc0_zkvm::guest::env::verify(
        checkpoint_randomx_receipt_image_id_digest(assumption),
        assumption.journal().as_slice(),
    )
}

/// Public statement linking two segment states through one bounded private input.
///
/// This statement authenticates no transition by itself. A proving guest must
/// verify the committed private block and witness input before emitting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointSegmentTransition {
    /// Number of consecutive DOM blocks proved by this segment.
    pub block_count: u16,
    /// Keccak commitment to the canonical private block and witness input.
    pub private_input_commitment: [u8; 32],
    /// State before the first proved block.
    pub previous: CheckpointSegmentState,
    /// State after the final proved block.
    pub next: CheckpointSegmentState,
}

/// Failure to encode or validate a recursive checkpoint segment transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CheckpointSegmentTransitionError {
    /// Magic, version, length or canonical representation is invalid.
    #[error("invalid checkpoint segment transition framing")]
    InvalidFraming,
    /// Either endpoint is not a valid canonical segment state.
    #[error("invalid checkpoint segment transition state")]
    InvalidState,
    /// Immutable network, chain or verifier policy changed across the segment.
    #[error("checkpoint segment transition identity changed")]
    IdentityChanged,
    /// Block count is zero, exceeds the bound or disagrees with the height delta.
    #[error("invalid checkpoint segment transition span")]
    InvalidSpan,
    /// Accumulated work did not strictly increase.
    #[error("checkpoint segment transition work did not increase")]
    InvalidWork,
    /// The committed private input is missing.
    #[error("invalid checkpoint segment private input commitment")]
    InvalidPrivateInput,
}

impl CheckpointSegmentTransition {
    /// Validate both endpoints and their public continuity invariants.
    pub fn validate(&self) -> Result<(), CheckpointSegmentTransitionError> {
        self.previous
            .validate()
            .map_err(|_| CheckpointSegmentTransitionError::InvalidState)?;
        self.next
            .validate()
            .map_err(|_| CheckpointSegmentTransitionError::InvalidState)?;
        if self.private_input_commitment == [0; 32] {
            return Err(CheckpointSegmentTransitionError::InvalidPrivateInput);
        }
        if self.block_count == 0 || self.block_count > MAX_CHECKPOINT_SEGMENT_BLOCKS {
            return Err(CheckpointSegmentTransitionError::InvalidSpan);
        }
        let expected_height = self
            .previous
            .height
            .checked_add(u64::from(self.block_count))
            .ok_or(CheckpointSegmentTransitionError::InvalidSpan)?;
        if self.next.height != expected_height || self.next.block_hash == self.previous.block_hash {
            return Err(CheckpointSegmentTransitionError::InvalidSpan);
        }
        if self.next.total_difficulty <= self.previous.total_difficulty {
            return Err(CheckpointSegmentTransitionError::InvalidWork);
        }
        if self.previous.network_magic != self.next.network_magic
            || self.previous.chain_id != self.next.chain_id
            || self.previous.activation_schedule_commitment
                != self.next.activation_schedule_commitment
            || self.previous.checkpoint_config_hash != self.next.checkpoint_config_hash
            || self.previous.checkpoint_policy_hash != self.next.checkpoint_policy_hash
            || self.previous.deposit_policy_hash != self.next.deposit_policy_hash
            || self.previous.privacy_verifier_config_hash != self.next.privacy_verifier_config_hash
            || self.previous.randomx_receipt_image_id != self.next.randomx_receipt_image_id
        {
            return Err(CheckpointSegmentTransitionError::IdentityChanged);
        }
        Ok(())
    }

    /// Encode the unique fixed-width `UDCSTN02` representation.
    pub fn to_bytes(
        &self,
    ) -> Result<[u8; CHECKPOINT_SEGMENT_TRANSITION_BYTES], CheckpointSegmentTransitionError> {
        self.validate()?;
        let previous = self
            .previous
            .to_bytes()
            .map_err(|_| CheckpointSegmentTransitionError::InvalidState)?;
        let next = self
            .next
            .to_bytes()
            .map_err(|_| CheckpointSegmentTransitionError::InvalidState)?;
        let mut bytes = [0u8; CHECKPOINT_SEGMENT_TRANSITION_BYTES];
        bytes[..8].copy_from_slice(CHECKPOINT_SEGMENT_TRANSITION_MAGIC);
        bytes[8..10].copy_from_slice(&CHECKPOINT_SEGMENT_TRANSITION_VERSION.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.block_count.to_be_bytes());
        bytes[12..44].copy_from_slice(&self.private_input_commitment);
        bytes[44..44 + CHECKPOINT_SEGMENT_STATE_BYTES].copy_from_slice(&previous);
        bytes[44 + CHECKPOINT_SEGMENT_STATE_BYTES..].copy_from_slice(&next);
        Ok(bytes)
    }

    /// Decode, validate and canonically re-encode one `UDCSTN02` statement.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CheckpointSegmentTransitionError> {
        if bytes.len() != CHECKPOINT_SEGMENT_TRANSITION_BYTES
            || bytes.get(..8) != Some(CHECKPOINT_SEGMENT_TRANSITION_MAGIC.as_slice())
            || u16::from_be_bytes(
                bytes
                    .get(8..10)
                    .ok_or(CheckpointSegmentTransitionError::InvalidFraming)?
                    .try_into()
                    .map_err(|_| CheckpointSegmentTransitionError::InvalidFraming)?,
            ) != CHECKPOINT_SEGMENT_TRANSITION_VERSION
        {
            return Err(CheckpointSegmentTransitionError::InvalidFraming);
        }
        let previous_end =
            CHECKPOINT_SEGMENT_TRANSITION_PREFIX_BYTES + CHECKPOINT_SEGMENT_STATE_BYTES;
        let transition = Self {
            block_count: u16::from_be_bytes(
                bytes[10..12]
                    .try_into()
                    .map_err(|_| CheckpointSegmentTransitionError::InvalidFraming)?,
            ),
            private_input_commitment: bytes[12..44]
                .try_into()
                .map_err(|_| CheckpointSegmentTransitionError::InvalidFraming)?,
            previous: CheckpointSegmentState::from_bytes(
                bytes
                    .get(CHECKPOINT_SEGMENT_TRANSITION_PREFIX_BYTES..previous_end)
                    .ok_or(CheckpointSegmentTransitionError::InvalidFraming)?,
            )
            .map_err(|_| CheckpointSegmentTransitionError::InvalidState)?,
            next: CheckpointSegmentState::from_bytes(
                bytes
                    .get(previous_end..)
                    .ok_or(CheckpointSegmentTransitionError::InvalidFraming)?,
            )
            .map_err(|_| CheckpointSegmentTransitionError::InvalidState)?,
        };
        transition.validate()?;
        if transition.to_bytes()?.as_slice() != bytes {
            return Err(CheckpointSegmentTransitionError::InvalidFraming);
        }
        Ok(transition)
    }

    /// Keccak commitment used to bind a receipt to the exact segment statement.
    pub fn commitment(&self) -> Result<[u8; 32], CheckpointSegmentTransitionError> {
        let bytes = self.to_bytes()?;
        let mut hasher = Keccak256::new();
        hasher.update(CHECKPOINT_SEGMENT_TRANSITION_DOMAIN);
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }
}

/// Derive the only RandomX receipt assumption allowed for a segment block.
///
/// The transition must be canonical, the statement height must lie strictly
/// after `previous.height` and no later than `next.height`, and its network and
/// chain must match the chained state. The returned type has private fields, so
/// an external guest cannot fabricate a prover-selected ImageID or journal.
#[cfg(any(feature = "segment-bindings", test))]
fn checkpoint_randomx_receipt_assumption_for_transition(
    transition: &CheckpointSegmentTransition,
    statement: &CheckpointRandomXStatement,
) -> Result<CheckpointRandomXReceiptAssumption, CheckpointRandomXReceiptAssumptionError> {
    transition
        .validate()
        .map_err(|_| CheckpointRandomXReceiptAssumptionError::InvalidTransition)?;
    if statement.block_height <= transition.previous.height
        || statement.block_height > transition.next.height
    {
        return Err(CheckpointRandomXReceiptAssumptionError::HeightMismatch);
    }
    checkpoint_randomx_receipt_assumption_for_state(&transition.previous, statement)
}

/// Canonical private bytes needed to validate one block in a checkpoint segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointSegmentBlockInput {
    package_bytes: Vec<u8>,
    native_witness_bytes: Vec<u8>,
    economic_witness_bytes: Vec<u8>,
}

impl CheckpointSegmentBlockInput {
    /// Construct one bounded block input without granting validity to its bytes.
    pub fn new(
        package_bytes: Vec<u8>,
        native_witness_bytes: Vec<u8>,
        economic_witness_bytes: Vec<u8>,
    ) -> Result<Self, CheckpointSegmentPrivateInputError> {
        let input = Self {
            package_bytes,
            native_witness_bytes,
            economic_witness_bytes,
        };
        input.validate_lengths()?;
        Ok(input)
    }

    /// Canonical DOM block package bytes.
    pub fn package_bytes(&self) -> &[u8] {
        &self.package_bytes
    }

    /// Canonical candidate-v2 native state-opening bundle bytes.
    pub fn native_witness_bytes(&self) -> &[u8] {
        &self.native_witness_bytes
    }

    /// Canonical ordinary-DOM economic witness bytes.
    pub fn economic_witness_bytes(&self) -> &[u8] {
        &self.economic_witness_bytes
    }

    fn validate_lengths(&self) -> Result<(), CheckpointSegmentPrivateInputError> {
        if self.package_bytes.is_empty()
            || self.package_bytes.len() > MAX_CHECKPOINT_SEGMENT_PACKAGE_BYTES
            || self.native_witness_bytes.is_empty()
            || self.native_witness_bytes.len() > MAX_CHECKPOINT_SEGMENT_NATIVE_WITNESS_BYTES
            || self.economic_witness_bytes.is_empty()
            || self.economic_witness_bytes.len() > MAX_CHECKPOINT_SEGMENT_ECONOMIC_WITNESS_BYTES
        {
            return Err(CheckpointSegmentPrivateInputError::InvalidComponent);
        }
        Ok(())
    }
}

/// Exact bounded private input committed by one `UDCSTN02` transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointSegmentPrivateInput {
    blocks: Vec<CheckpointSegmentBlockInput>,
}

/// Failure to encode, decode or validate a private checkpoint segment input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CheckpointSegmentPrivateInputError {
    /// Magic, version, lengths or canonical representation is invalid.
    #[error("invalid checkpoint segment private input framing")]
    InvalidFraming,
    /// The number of blocks is zero or exceeds the segment ceiling.
    #[error("invalid checkpoint segment private input block count")]
    InvalidBlockCount,
    /// A package or witness is empty, oversized or not canonically typed.
    #[error("invalid checkpoint segment private input component")]
    InvalidComponent,
    /// Total encoded size overflows or exceeds the segment ceiling.
    #[error("checkpoint segment private input exceeds its byte ceiling")]
    SizeLimit,
}

impl CheckpointSegmentPrivateInput {
    /// Construct one ordered, bounded segment input.
    pub fn new(
        blocks: Vec<CheckpointSegmentBlockInput>,
    ) -> Result<Self, CheckpointSegmentPrivateInputError> {
        let input = Self { blocks };
        input.validate()?;
        Ok(input)
    }

    /// Ordered block inputs consumed by a future transition guest.
    pub fn blocks(&self) -> &[CheckpointSegmentBlockInput] {
        &self.blocks
    }

    /// Validate count, component and aggregate byte limits before allocation.
    pub fn validate(&self) -> Result<(), CheckpointSegmentPrivateInputError> {
        if self.blocks.is_empty() || self.blocks.len() > usize::from(MAX_CHECKPOINT_SEGMENT_BLOCKS)
        {
            return Err(CheckpointSegmentPrivateInputError::InvalidBlockCount);
        }
        let mut total = CHECKPOINT_SEGMENT_PRIVATE_INPUT_HEADER_BYTES;
        for block in &self.blocks {
            block.validate_lengths()?;
            total = total
                .checked_add(CHECKPOINT_SEGMENT_PRIVATE_BLOCK_HEADER_BYTES)
                .and_then(|value| value.checked_add(block.package_bytes.len()))
                .and_then(|value| value.checked_add(block.native_witness_bytes.len()))
                .and_then(|value| value.checked_add(block.economic_witness_bytes.len()))
                .ok_or(CheckpointSegmentPrivateInputError::SizeLimit)?;
            if total > MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES {
                return Err(CheckpointSegmentPrivateInputError::SizeLimit);
            }
        }
        Ok(())
    }

    /// Encode the unique bounded `UDCSPI01` representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CheckpointSegmentPrivateInputError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(CHECKPOINT_SEGMENT_PRIVATE_INPUT_HEADER_BYTES);
        bytes.extend_from_slice(CHECKPOINT_SEGMENT_PRIVATE_INPUT_MAGIC);
        bytes.extend_from_slice(&CHECKPOINT_SEGMENT_PRIVATE_INPUT_VERSION.to_be_bytes());
        bytes.extend_from_slice(
            &u16::try_from(self.blocks.len())
                .map_err(|_| CheckpointSegmentPrivateInputError::InvalidBlockCount)?
                .to_be_bytes(),
        );
        for block in &self.blocks {
            for length in [
                block.package_bytes.len(),
                block.native_witness_bytes.len(),
                block.economic_witness_bytes.len(),
            ] {
                bytes.extend_from_slice(
                    &u32::try_from(length)
                        .map_err(|_| CheckpointSegmentPrivateInputError::SizeLimit)?
                        .to_be_bytes(),
                );
            }
            bytes.extend_from_slice(&block.package_bytes);
            bytes.extend_from_slice(&block.native_witness_bytes);
            bytes.extend_from_slice(&block.economic_witness_bytes);
        }
        if bytes.len() > MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES {
            return Err(CheckpointSegmentPrivateInputError::SizeLimit);
        }
        Ok(bytes)
    }

    /// Decode and canonically re-encode one exact `UDCSPI01` input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CheckpointSegmentPrivateInputError> {
        if bytes.len() < CHECKPOINT_SEGMENT_PRIVATE_INPUT_HEADER_BYTES
            || bytes.len() > MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES
            || bytes.get(..8) != Some(CHECKPOINT_SEGMENT_PRIVATE_INPUT_MAGIC.as_slice())
            || u16::from_be_bytes(
                bytes
                    .get(8..10)
                    .ok_or(CheckpointSegmentPrivateInputError::InvalidFraming)?
                    .try_into()
                    .map_err(|_| CheckpointSegmentPrivateInputError::InvalidFraming)?,
            ) != CHECKPOINT_SEGMENT_PRIVATE_INPUT_VERSION
        {
            return Err(CheckpointSegmentPrivateInputError::InvalidFraming);
        }
        let count = usize::from(u16::from_be_bytes(
            bytes
                .get(10..12)
                .ok_or(CheckpointSegmentPrivateInputError::InvalidFraming)?
                .try_into()
                .map_err(|_| CheckpointSegmentPrivateInputError::InvalidFraming)?,
        ));
        if count == 0 || count > usize::from(MAX_CHECKPOINT_SEGMENT_BLOCKS) {
            return Err(CheckpointSegmentPrivateInputError::InvalidBlockCount);
        }
        let mut blocks = Vec::with_capacity(count);
        let mut cursor = CHECKPOINT_SEGMENT_PRIVATE_INPUT_HEADER_BYTES;
        for _ in 0..count {
            let lengths_end = cursor
                .checked_add(CHECKPOINT_SEGMENT_PRIVATE_BLOCK_HEADER_BYTES)
                .ok_or(CheckpointSegmentPrivateInputError::SizeLimit)?;
            let lengths = bytes
                .get(cursor..lengths_end)
                .ok_or(CheckpointSegmentPrivateInputError::InvalidFraming)?;
            let package_len = usize::try_from(u32::from_be_bytes(
                lengths[0..4]
                    .try_into()
                    .map_err(|_| CheckpointSegmentPrivateInputError::InvalidFraming)?,
            ))
            .map_err(|_| CheckpointSegmentPrivateInputError::SizeLimit)?;
            let native_len = usize::try_from(u32::from_be_bytes(
                lengths[4..8]
                    .try_into()
                    .map_err(|_| CheckpointSegmentPrivateInputError::InvalidFraming)?,
            ))
            .map_err(|_| CheckpointSegmentPrivateInputError::SizeLimit)?;
            let economic_len = usize::try_from(u32::from_be_bytes(
                lengths[8..12]
                    .try_into()
                    .map_err(|_| CheckpointSegmentPrivateInputError::InvalidFraming)?,
            ))
            .map_err(|_| CheckpointSegmentPrivateInputError::SizeLimit)?;
            if package_len == 0
                || package_len > MAX_CHECKPOINT_SEGMENT_PACKAGE_BYTES
                || native_len == 0
                || native_len > MAX_CHECKPOINT_SEGMENT_NATIVE_WITNESS_BYTES
                || economic_len == 0
                || economic_len > MAX_CHECKPOINT_SEGMENT_ECONOMIC_WITNESS_BYTES
            {
                return Err(CheckpointSegmentPrivateInputError::InvalidComponent);
            }
            let package_end = lengths_end
                .checked_add(package_len)
                .ok_or(CheckpointSegmentPrivateInputError::SizeLimit)?;
            let native_end = package_end
                .checked_add(native_len)
                .ok_or(CheckpointSegmentPrivateInputError::SizeLimit)?;
            let economic_end = native_end
                .checked_add(economic_len)
                .ok_or(CheckpointSegmentPrivateInputError::SizeLimit)?;
            if economic_end > bytes.len() {
                return Err(CheckpointSegmentPrivateInputError::InvalidFraming);
            }
            blocks.push(CheckpointSegmentBlockInput::new(
                bytes[lengths_end..package_end].to_vec(),
                bytes[package_end..native_end].to_vec(),
                bytes[native_end..economic_end].to_vec(),
            )?);
            cursor = economic_end;
        }
        if cursor != bytes.len() {
            return Err(CheckpointSegmentPrivateInputError::InvalidFraming);
        }
        let input = Self::new(blocks)?;
        if input.to_bytes()?.as_slice() != bytes {
            return Err(CheckpointSegmentPrivateInputError::InvalidFraming);
        }
        Ok(input)
    }

    /// Keccak commitment stored in the matching `UDCSTN02` statement.
    pub fn commitment(&self) -> Result<[u8; 32], CheckpointSegmentPrivateInputError> {
        let bytes = self.to_bytes()?;
        let mut hasher = Keccak256::new();
        hasher.update(CHECKPOINT_SEGMENT_PRIVATE_INPUT_DOMAIN);
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }

    /// Build the exact public transition statement for these private bytes.
    pub fn transition_statement(
        &self,
        previous: CheckpointSegmentState,
        next: CheckpointSegmentState,
    ) -> Result<CheckpointSegmentTransition, CheckpointSegmentTransitionError> {
        let block_count = u16::try_from(self.blocks.len())
            .map_err(|_| CheckpointSegmentTransitionError::InvalidSpan)?;
        let private_input_commitment = self
            .commitment()
            .map_err(|_| CheckpointSegmentTransitionError::InvalidPrivateInput)?;
        let transition = CheckpointSegmentTransition {
            block_count,
            private_input_commitment,
            previous,
            next,
        };
        transition.validate()?;
        Ok(transition)
    }

    /// Parse every component through its consensus-owned canonical decoder.
    #[cfg(feature = "host-reference")]
    pub fn validate_typed_components(&self) -> Result<(), CheckpointSegmentPrivateInputError> {
        self.validate()?;
        for block in &self.blocks {
            UsdomV4BlockPackage::from_bytes(&block.package_bytes)
                .map_err(|_| CheckpointSegmentPrivateInputError::InvalidComponent)?;
            UsdomV2ExecutionWitnesses::from_bytes(&block.native_witness_bytes)
                .map_err(|_| CheckpointSegmentPrivateInputError::InvalidComponent)?;
            EconomicBlockWitness::from_bytes(&block.economic_witness_bytes)
                .map(|_| ())
                .or_else(|_| {
                    EconomicBlockTransition::from_bytes(&block.economic_witness_bytes).map(|_| ())
                })
                .map_err(|_| CheckpointSegmentPrivateInputError::InvalidComponent)?;
        }
        Ok(())
    }
}

/// One ordered RandomX receipt requirement derived from an exact segment block.
///
/// Construction is restricted to [`checkpoint_segment_randomx_bindings`],
/// which parses the committed package, authenticates its position and derives
/// the seed from chained checkpoint state. Observing this value grants no proof
/// authority; a segment guest must still verify the matching receipt.
#[cfg(feature = "segment-bindings")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointSegmentRandomXBinding {
    block_hash: [u8; 32],
    statement: CheckpointRandomXStatement,
    assumption: CheckpointRandomXReceiptAssumption,
}

#[cfg(feature = "segment-bindings")]
impl CheckpointSegmentRandomXBinding {
    /// Canonical identifier of the exact parsed header.
    pub fn block_hash(&self) -> &[u8; 32] {
        &self.block_hash
    }

    /// Public RandomX relation copied from the exact parsed header.
    pub fn statement(&self) -> &CheckpointRandomXStatement {
        &self.statement
    }

    /// Policy-bound recursive receipt requirement for this statement.
    pub fn assumption(&self) -> &CheckpointRandomXReceiptAssumption {
        &self.assumption
    }
}

/// Public journal statement for an ordered set of segment RandomX receipts.
///
/// This statement proves only that the exact headers committed by one segment
/// transition each have a matching receipt under the state-pinned RandomX
/// ImageID. It deliberately has a distinct domain from UDCSTN02 and cannot be
/// used as a complete checkpoint transition proof.
#[cfg(feature = "segment-bindings")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointSegmentRandomXAggregate {
    block_count: u16,
    transition_commitment: [u8; 32],
    receipt_set_commitment: [u8; 32],
}

#[cfg(feature = "segment-bindings")]
impl CheckpointSegmentRandomXAggregate {
    /// Number of consecutive header receipts in the ordered set.
    pub fn block_count(&self) -> u16 {
        self.block_count
    }

    /// Commitment of the exact UDCSTN02 transition whose packages were parsed.
    pub fn transition_commitment(&self) -> &[u8; 32] {
        &self.transition_commitment
    }

    /// Commitment to every ordered inner receipt journal.
    pub fn receipt_set_commitment(&self) -> &[u8; 32] {
        &self.receipt_set_commitment
    }

    /// Encode the unique fixed-width `UDCRXAG1` statement.
    pub fn to_bytes(&self) -> [u8; CHECKPOINT_RANDOMX_AGGREGATE_BYTES] {
        let mut bytes = [0u8; CHECKPOINT_RANDOMX_AGGREGATE_BYTES];
        bytes[..8].copy_from_slice(CHECKPOINT_RANDOMX_AGGREGATE_MAGIC);
        bytes[8..10].copy_from_slice(&CHECKPOINT_RANDOMX_AGGREGATE_VERSION.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.block_count.to_be_bytes());
        bytes[12..44].copy_from_slice(&self.transition_commitment);
        bytes[44..76].copy_from_slice(&self.receipt_set_commitment);
        bytes
    }

    /// Decode one exact canonical `UDCRXAG1` statement.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CheckpointSegmentRandomXAggregateError> {
        if bytes.len() != CHECKPOINT_RANDOMX_AGGREGATE_BYTES
            || bytes.get(..8) != Some(CHECKPOINT_RANDOMX_AGGREGATE_MAGIC.as_slice())
            || u16::from_be_bytes(
                bytes[8..10]
                    .try_into()
                    .map_err(|_| CheckpointSegmentRandomXAggregateError::InvalidFraming)?,
            ) != CHECKPOINT_RANDOMX_AGGREGATE_VERSION
        {
            return Err(CheckpointSegmentRandomXAggregateError::InvalidFraming);
        }
        let statement = Self {
            block_count: u16::from_be_bytes(
                bytes[10..12]
                    .try_into()
                    .map_err(|_| CheckpointSegmentRandomXAggregateError::InvalidFraming)?,
            ),
            transition_commitment: bytes[12..44]
                .try_into()
                .map_err(|_| CheckpointSegmentRandomXAggregateError::InvalidFraming)?,
            receipt_set_commitment: bytes[44..76]
                .try_into()
                .map_err(|_| CheckpointSegmentRandomXAggregateError::InvalidFraming)?,
        };
        statement.validate()?;
        if statement.to_bytes().as_slice() != bytes {
            return Err(CheckpointSegmentRandomXAggregateError::InvalidFraming);
        }
        Ok(statement)
    }

    /// Validate the count and nonzero commitments.
    pub fn validate(&self) -> Result<(), CheckpointSegmentRandomXAggregateError> {
        if self.block_count == 0 || self.block_count > MAX_CHECKPOINT_SEGMENT_BLOCKS {
            return Err(CheckpointSegmentRandomXAggregateError::InvalidCount);
        }
        if self.transition_commitment == [0; 32] || self.receipt_set_commitment == [0; 32] {
            return Err(CheckpointSegmentRandomXAggregateError::InvalidCommitment);
        }
        Ok(())
    }

    /// Keccak journal committed by the aggregate receipt.
    pub fn commitment(&self) -> Result<[u8; 32], CheckpointSegmentRandomXAggregateError> {
        self.validate()?;
        let mut hasher = Keccak256::new();
        hasher.update(CHECKPOINT_RANDOMX_AGGREGATE_DOMAIN);
        hasher.update(self.to_bytes());
        Ok(hasher.finalize().into())
    }
}

/// Failure to derive or validate an ordered segment RandomX aggregate.
#[cfg(feature = "segment-bindings")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CheckpointSegmentRandomXAggregateError {
    /// Magic, version, length or canonical representation is invalid.
    #[error("invalid checkpoint RandomX aggregate framing")]
    InvalidFraming,
    /// The aggregate count is zero or exceeds the segment bound.
    #[error("invalid checkpoint RandomX aggregate block count")]
    InvalidCount,
    /// A transition or ordered receipt-set commitment is zero.
    #[error("invalid checkpoint RandomX aggregate commitment")]
    InvalidCommitment,
    /// Exact per-block receipt requirements could not be derived.
    #[error("invalid checkpoint RandomX segment binding: {0}")]
    Binding(CheckpointSegmentRandomXBindingError),
    /// The UDCSTN02 transition commitment could not be recomputed.
    #[error("invalid checkpoint transition commitment")]
    InvalidTransition,
}

/// Failure to derive the complete ordered RandomX receipt set for a segment.
#[cfg(feature = "segment-bindings")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CheckpointSegmentRandomXBindingError {
    /// The public transition is not canonical.
    #[error("invalid checkpoint segment transition")]
    InvalidTransition,
    /// The private input is malformed or does not open the public commitment.
    #[error("checkpoint segment private input does not match transition")]
    PrivateInputMismatch,
    /// The supplied genesis hash does not open the transition's chain ID.
    #[error("DOM genesis hash does not match checkpoint chain identity")]
    GenesisIdentityMismatch,
    /// A block package is not a canonical native-USDOM v4 package.
    #[error("invalid checkpoint segment block package")]
    InvalidPackage,
    /// Heights, parent identifiers or the terminal identifier are not exact.
    #[error("checkpoint segment block sequence is not contiguous")]
    InvalidBlockSequence,
    /// The authenticated continuation context cannot supply the scheduled seed.
    #[error("checkpoint segment is missing an authenticated RandomX seed")]
    MissingSeed,
    /// The next continuation context is not the exact projection of the blocks.
    #[error("checkpoint segment next context does not match parsed headers")]
    ContextMismatch,
    /// A parsed header cannot form a canonical RandomX statement.
    #[error("checkpoint segment header has an invalid RandomX statement: {0}")]
    InvalidStatement(CheckpointRandomXStatementError),
    /// A policy-bound receipt requirement could not be derived.
    #[error("checkpoint segment RandomX receipt requirement is invalid")]
    InvalidAssumption,
}

/// Derive every RandomX receipt requirement from the exact committed packages.
///
/// The only auxiliary value is the DOM genesis hash. It is accepted only when
/// `derive_chain_id(network_magic, genesis_hash)` opens the chain ID already
/// committed by the segment state. All later seeds come exclusively from the
/// authenticated previous context or from an earlier linked package. Package
/// order, heights, parent hashes, the terminal hash, the complete rolling
/// header context and all next-context seed anchors are checked exactly.
#[cfg(feature = "segment-bindings")]
pub fn checkpoint_segment_randomx_bindings(
    transition: &CheckpointSegmentTransition,
    private_input: &CheckpointSegmentPrivateInput,
    dom_genesis_hash: [u8; 32],
) -> Result<Vec<CheckpointSegmentRandomXBinding>, CheckpointSegmentRandomXBindingError> {
    transition
        .validate()
        .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidTransition)?;
    private_input
        .validate()
        .map_err(|_| CheckpointSegmentRandomXBindingError::PrivateInputMismatch)?;
    #[cfg(feature = "host-reference")]
    private_input
        .validate_typed_components()
        .map_err(|_| CheckpointSegmentRandomXBindingError::PrivateInputMismatch)?;
    let input_commitment = private_input
        .commitment()
        .map_err(|_| CheckpointSegmentRandomXBindingError::PrivateInputMismatch)?;
    if input_commitment != transition.private_input_commitment
        || private_input.blocks.len() != usize::from(transition.block_count)
    {
        return Err(CheckpointSegmentRandomXBindingError::PrivateInputMismatch);
    }

    if dom_genesis_hash == [0; 32]
        || checkpoint_segment_chain_id(transition.previous.network_magic, dom_genesis_hash)
            != transition.previous.chain_id
    {
        return Err(CheckpointSegmentRandomXBindingError::GenesisIdentityMismatch);
    }
    if transition.previous.context.max_span != transition.next.context.max_span {
        return Err(CheckpointSegmentRandomXBindingError::ContextMismatch);
    }

    let mut known_blocks = BTreeMap::<u64, [u8; 32]>::new();
    known_blocks.insert(0, dom_genesis_hash);
    for header in &transition.previous.context.recent_headers {
        if let Some(existing) = known_blocks.insert(header.height, header.block) {
            if existing != header.block {
                return Err(CheckpointSegmentRandomXBindingError::ContextMismatch);
            }
        }
    }
    for anchor in transition
        .previous
        .context
        .seed_anchors
        .iter()
        .take(usize::from(transition.previous.context.seed_anchor_count))
    {
        if let Some(existing) = known_blocks.insert(anchor.height, anchor.block) {
            if existing != anchor.block {
                return Err(CheckpointSegmentRandomXBindingError::ContextMismatch);
            }
        }
    }

    let mut rolling_headers = transition.previous.context.recent_headers.to_vec();
    let mut previous_hash = transition.previous.block_hash;
    let mut bindings = Vec::with_capacity(private_input.blocks.len());
    for (index, block_input) in private_input.blocks.iter().enumerate() {
        let header = checkpoint_segment_header_projection(block_input.package_bytes())?;
        let expected_height = transition
            .previous
            .height
            .checked_add(index as u64 + 1)
            .ok_or(CheckpointSegmentRandomXBindingError::InvalidBlockSequence)?;
        if header.height != expected_height || header.prev_hash != previous_hash {
            return Err(CheckpointSegmentRandomXBindingError::InvalidBlockSequence);
        }
        let block_hash = *dom_core::blake2b_256(&header.header_bytes).as_bytes();
        let seed_height = checkpoint_randomx_seed_height(expected_height);
        let seed_hash = known_blocks
            .get(&seed_height)
            .copied()
            .ok_or(CheckpointSegmentRandomXBindingError::MissingSeed)?;
        let statement = header
            .randomx_statement(
                transition.previous.network_magic,
                transition.previous.chain_id,
                seed_hash,
            )
            .map_err(CheckpointSegmentRandomXBindingError::InvalidStatement)?;
        let assumption =
            checkpoint_randomx_receipt_assumption_for_transition(transition, &statement)
                .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidAssumption)?;

        if let Some(existing) = known_blocks.insert(expected_height, block_hash) {
            if existing != block_hash {
                return Err(CheckpointSegmentRandomXBindingError::InvalidBlockSequence);
            }
        }
        rolling_headers.push(dom_usdom_checkpoint_statement::ContextHeader {
            height: expected_height,
            block: block_hash,
            timestamp: header.timestamp,
        });
        previous_hash = block_hash;
        bindings.push(CheckpointSegmentRandomXBinding {
            block_hash,
            statement,
            assumption,
        });
    }

    if previous_hash != transition.next.block_hash {
        return Err(CheckpointSegmentRandomXBindingError::InvalidBlockSequence);
    }
    let expected_recent = rolling_headers
        .get(rolling_headers.len() - transition.next.context.recent_headers.len()..)
        .ok_or(CheckpointSegmentRandomXBindingError::ContextMismatch)?;
    if expected_recent != transition.next.context.recent_headers.as_slice() {
        return Err(CheckpointSegmentRandomXBindingError::ContextMismatch);
    }
    for anchor in transition
        .next
        .context
        .seed_anchors
        .iter()
        .take(usize::from(transition.next.context.seed_anchor_count))
    {
        if known_blocks.get(&anchor.height) != Some(&anchor.block) {
            return Err(CheckpointSegmentRandomXBindingError::ContextMismatch);
        }
    }
    Ok(bindings)
}

/// Derive the distinct public statement for an ordered inner-receipt set.
///
/// The returned bindings are the only receipt assumptions that an aggregation
/// guest may verify. The aggregate statement is intentionally insufficient to
/// authorize a checkpoint transition; full native and economic execution must
/// be proved by a separate outer relation.
#[cfg(feature = "segment-bindings")]
pub fn checkpoint_segment_randomx_aggregate(
    transition: &CheckpointSegmentTransition,
    private_input: &CheckpointSegmentPrivateInput,
    dom_genesis_hash: [u8; 32],
) -> Result<
    (
        CheckpointSegmentRandomXAggregate,
        Vec<CheckpointSegmentRandomXBinding>,
    ),
    CheckpointSegmentRandomXAggregateError,
> {
    let bindings = checkpoint_segment_randomx_bindings(transition, private_input, dom_genesis_hash)
        .map_err(CheckpointSegmentRandomXAggregateError::Binding)?;
    let transition_commitment = transition
        .commitment()
        .map_err(|_| CheckpointSegmentRandomXAggregateError::InvalidTransition)?;
    let mut receipt_set = Keccak256::new();
    receipt_set.update(CHECKPOINT_RANDOMX_RECEIPT_SET_DOMAIN);
    receipt_set.update(transition.block_count.to_be_bytes());
    for binding in &bindings {
        receipt_set.update(binding.assumption().journal());
    }
    let statement = CheckpointSegmentRandomXAggregate {
        block_count: transition.block_count,
        transition_commitment,
        receipt_set_commitment: receipt_set.finalize().into(),
    };
    statement.validate()?;
    Ok((statement, bindings))
}

/// Verify every exact inner RandomX receipt inside a RISC Zero guest.
///
/// This function publishes nothing and proves no native/economic state change.
/// A caller must commit the distinct aggregate statement only after this loop
/// succeeds, then compose that receipt into a complete checkpoint guest.
#[cfg(all(
    feature = "segment-bindings",
    feature = "risc0-recursion",
    target_os = "zkvm"
))]
pub fn verify_checkpoint_segment_randomx_bindings_in_guest(
    bindings: &[CheckpointSegmentRandomXBinding],
) -> Result<(), core::convert::Infallible> {
    for binding in bindings {
        verify_checkpoint_randomx_receipt_assumption_in_guest(binding.assumption())?;
    }
    Ok(())
}

#[cfg(feature = "segment-bindings")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckpointSegmentHeaderProjection {
    header_bytes: [u8; CHECKPOINT_DOM_V4_HEADER_BYTES],
    height: u64,
    prev_hash: [u8; 32],
    timestamp: u64,
    pow_preimage: [u8; CHECKPOINT_RANDOMX_PREIMAGE_BYTES],
    randomx_hash: [u8; 32],
    compact_target: u32,
}

#[cfg(feature = "segment-bindings")]
impl CheckpointSegmentHeaderProjection {
    fn randomx_statement(
        &self,
        network_magic: u32,
        chain_id: [u8; 32],
        seed_hash: [u8; 32],
    ) -> Result<CheckpointRandomXStatement, CheckpointRandomXStatementError> {
        let statement = CheckpointRandomXStatement {
            network_magic,
            chain_id,
            block_height: self.height,
            seed_height: checkpoint_randomx_seed_height(self.height),
            seed_hash,
            pow_preimage: self.pow_preimage,
            randomx_hash: self.randomx_hash,
            target: checkpoint_compact_target(self.compact_target)
                .ok_or(CheckpointRandomXStatementError::InvalidTarget)?,
        };
        statement.validate()?;
        Ok(statement)
    }
}

#[cfg(feature = "segment-bindings")]
fn checkpoint_segment_chain_id(network_magic: u32, genesis_hash: [u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 36];
    input[..4].copy_from_slice(&network_magic.to_be_bytes());
    input[4..].copy_from_slice(&genesis_hash);
    *dom_core::blake2b_256_tagged(dom_core::TAG_CHAIN_ID, &input).as_bytes()
}

#[cfg(feature = "segment-bindings")]
fn checkpoint_segment_header_projection(
    package_bytes: &[u8],
) -> Result<CheckpointSegmentHeaderProjection, CheckpointSegmentRandomXBindingError> {
    if package_bytes.len()
        < CHECKPOINT_USDOM_V4_PACKAGE_HEADER_BYTES
            + CHECKPOINT_DOM_V4_HEADER_BYTES
            + CHECKPOINT_USDOM_V4_ENVELOPE_MIN_BYTES
        || package_bytes.len() > MAX_CHECKPOINT_SEGMENT_PACKAGE_BYTES
        || package_bytes.get(..8) != Some(CHECKPOINT_USDOM_V4_PACKAGE_MAGIC.as_slice())
    {
        return Err(CheckpointSegmentRandomXBindingError::InvalidPackage);
    }
    let framing_version = u16::from_be_bytes(
        package_bytes[8..10]
            .try_into()
            .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?,
    );
    let block_len = usize::try_from(u32::from_be_bytes(
        package_bytes[10..14]
            .try_into()
            .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?,
    ))
    .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?;
    let proof_len = usize::try_from(u32::from_be_bytes(
        package_bytes[14..18]
            .try_into()
            .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?,
    ))
    .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?;
    let block_end = CHECKPOINT_USDOM_V4_PACKAGE_HEADER_BYTES
        .checked_add(block_len)
        .ok_or(CheckpointSegmentRandomXBindingError::InvalidPackage)?;
    let package_end = block_end
        .checked_add(proof_len)
        .ok_or(CheckpointSegmentRandomXBindingError::InvalidPackage)?;
    if framing_version != CHECKPOINT_USDOM_V4_PACKAGE_VERSION
        || block_len < CHECKPOINT_DOM_V4_HEADER_BYTES
        || proof_len < CHECKPOINT_USDOM_V4_ENVELOPE_MIN_BYTES
        || package_end != package_bytes.len()
    {
        return Err(CheckpointSegmentRandomXBindingError::InvalidPackage);
    }
    checkpoint_segment_validate_envelope_framing(&package_bytes[block_end..package_end])?;
    let header_bytes: [u8; CHECKPOINT_DOM_V4_HEADER_BYTES] = package_bytes
        [CHECKPOINT_USDOM_V4_PACKAGE_HEADER_BYTES
            ..CHECKPOINT_USDOM_V4_PACKAGE_HEADER_BYTES + CHECKPOINT_DOM_V4_HEADER_BYTES]
        .try_into()
        .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?;
    if u32::from_le_bytes(
        header_bytes[..4]
            .try_into()
            .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?,
    ) != CHECKPOINT_RANDOMX_BLOCK_VERSION
    {
        return Err(CheckpointSegmentRandomXBindingError::InvalidPackage);
    }
    let mut pow_preimage = [0u8; CHECKPOINT_RANDOMX_PREIMAGE_BYTES];
    pow_preimage[..4].copy_from_slice(&header_bytes[..4]);
    pow_preimage[4..36].copy_from_slice(&header_bytes[12..44]);
    pow_preimage[36..44].copy_from_slice(&header_bytes[4..12]);
    pow_preimage[44..].copy_from_slice(&header_bytes[44..224]);
    Ok(CheckpointSegmentHeaderProjection {
        header_bytes,
        height: u64::from_le_bytes(
            header_bytes[4..12]
                .try_into()
                .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?,
        ),
        prev_hash: header_bytes[12..44]
            .try_into()
            .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?,
        timestamp: u64::from_le_bytes(
            header_bytes[44..52]
                .try_into()
                .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?,
        ),
        pow_preimage,
        randomx_hash: header_bytes[224..256]
            .try_into()
            .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?,
        compact_target: u32::from_le_bytes(
            header_bytes[180..184]
                .try_into()
                .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?,
        ),
    })
}

#[cfg(feature = "segment-bindings")]
fn checkpoint_segment_validate_envelope_framing(
    envelope: &[u8],
) -> Result<(), CheckpointSegmentRandomXBindingError> {
    if envelope.len() < CHECKPOINT_USDOM_V4_ENVELOPE_MIN_BYTES
        || envelope.get(..8) != Some(CHECKPOINT_USDOM_V4_ENVELOPE_MAGIC.as_slice())
        || u16::from_be_bytes(
            envelope[8..10]
                .try_into()
                .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?,
        ) != CHECKPOINT_USDOM_V4_ENVELOPE_VERSION
    {
        return Err(CheckpointSegmentRandomXBindingError::InvalidPackage);
    }
    let count = usize::try_from(u32::from_be_bytes(
        envelope[10..14]
            .try_into()
            .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?,
    ))
    .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?;
    let mut cursor = CHECKPOINT_USDOM_V4_ENVELOPE_MIN_BYTES;
    for _ in 0..count {
        let entry_end = cursor
            .checked_add(CHECKPOINT_USDOM_V4_ENTRY_HEADER_BYTES)
            .ok_or(CheckpointSegmentRandomXBindingError::InvalidPackage)?;
        let entry = envelope
            .get(cursor..entry_end)
            .ok_or(CheckpointSegmentRandomXBindingError::InvalidPackage)?;
        if !(1..=4).contains(&entry[0]) {
            return Err(CheckpointSegmentRandomXBindingError::InvalidPackage);
        }
        let payload_len = usize::try_from(u32::from_be_bytes(
            entry[1..5]
                .try_into()
                .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?,
        ))
        .map_err(|_| CheckpointSegmentRandomXBindingError::InvalidPackage)?;
        if payload_len == 0 {
            return Err(CheckpointSegmentRandomXBindingError::InvalidPackage);
        }
        cursor = entry_end
            .checked_add(payload_len)
            .ok_or(CheckpointSegmentRandomXBindingError::InvalidPackage)?;
        if cursor > envelope.len() {
            return Err(CheckpointSegmentRandomXBindingError::InvalidPackage);
        }
    }
    if cursor != envelope.len() {
        return Err(CheckpointSegmentRandomXBindingError::InvalidPackage);
    }
    Ok(())
}
/// Absolute canonical bound for both block component multiproofs and UTXO
/// maturity metadata. Release policy must select a much smaller practical cap.
pub const MAX_ECONOMIC_BLOCK_WITNESS_BYTES: usize = ECONOMIC_BLOCK_WITNESS_HEADER_BYTES
    + 2 * MAX_ECONOMIC_MULTIPROOF_BYTES
    + MAX_ECONOMIC_MULTIPROOF_KEYS * 10;

/// One ordinary DOM unspent output needed by contextual block validation.
///
/// The historical range proof is already authenticated and verified by the
/// block that created the output. Future consensus decisions need only the
/// commitment's existence, creation height, and coinbase maturity flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EconomicUtxo {
    /// Height at which the output was created.
    pub created_height: u64,
    /// Whether the output is subject to the network coinbase maturity rule.
    pub is_coinbase: bool,
}

/// Failure while reconstructing or advancing authenticated DOM economic state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EconomicStateError {
    /// A snapshot key is zero, duplicated, or hashes to the same sparse path.
    #[error("invalid DOM economic-state snapshot")]
    InvalidSnapshot,
    /// A transaction spends an output absent from the authenticated state.
    #[error("DOM block spends a missing output")]
    MissingInput,
    /// A transaction spends an immature coinbase output.
    #[error("DOM block spends an immature coinbase output")]
    ImmatureCoinbase,
    /// A block recreates an existing output commitment.
    #[error("DOM block contains an existing output commitment")]
    DuplicateOutput,
    /// A block repeats a historical kernel excess.
    #[error("DOM block replays a historical kernel excess")]
    DuplicateKernel,
    /// The combined economic root could not be constructed.
    #[error("invalid DOM economic-state root")]
    InvalidRoot,
    /// A compressed economic sparse path is malformed or noncanonical.
    #[error("invalid DOM economic-state proof")]
    InvalidProof,
    /// A compressed path does not open the claimed economic component root.
    #[error("DOM economic-state proof root mismatch")]
    ProofRootMismatch,
}

/// One canonical compressed UTXO or kernel sparse path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicPathProof {
    tree: u8,
    key: [u8; 33],
    sibling_bitmap: [u8; 32],
    siblings: Vec<[u8; 32]>,
}

/// Canonical sparse multiproof sharing all unchanged side nodes for one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicMultiProof {
    tree: u8,
    keys: Vec<[u8; 33]>,
    side_bitmap: Vec<u8>,
    side_nodes: Vec<[u8; 32]>,
}

/// Public component roots carried privately beneath one UDCCTX02 commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EconomicRoots {
    /// Sparse root of ordinary unspent DOM outputs.
    pub utxo_root: [u8; 32],
    /// Sparse root of every historical DOM kernel excess.
    pub kernel_root: [u8; 32],
}

impl EconomicRoots {
    /// Recompute the exact economic root carried by UDCCTX02.
    pub fn context_root(self) -> Result<[u8; 32], EconomicStateError> {
        checkpoint_economic_state_root(self.utxo_root, self.kernel_root)
            .map_err(|_| EconomicStateError::InvalidRoot)
    }
}

/// Canonical block-level witness sharing sparse side nodes across all effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicBlockWitness {
    utxo_proof: EconomicMultiProof,
    kernel_proof: EconomicMultiProof,
    old_utxos: Vec<Option<EconomicUtxo>>,
}

impl EconomicBlockWitness {
    /// Build a witness for one already body-valid block from full host state.
    #[cfg(feature = "host-reference")]
    pub fn from_state(state: &EconomicState, block: &Block) -> Result<Self, EconomicStateError> {
        let (utxo_effects, kernels) = economic_block_effects(block)?;
        let utxo_proof =
            EconomicMultiProof::from_state(state, true, utxo_effects.iter().map(|(key, _)| *key))?;
        let kernel_proof = EconomicMultiProof::from_state(state, false, kernels.iter().copied())?;
        let old_utxos = utxo_proof
            .keys()
            .iter()
            .map(|key| state.utxos.get(key).copied())
            .collect();
        let witness = Self {
            utxo_proof,
            kernel_proof,
            old_utxos,
        };
        // The constructor must never create an opening that fails against the
        // exact host roots or mismatches a block effect.
        witness.apply(
            EconomicRoots {
                utxo_root: state.utxo_set_root()?,
                kernel_root: state.kernel_set_root()?,
            },
            block,
            0,
        )?;
        Ok(witness)
    }

    /// Verify exact input/output/kernel effects and return the two new roots.
    #[cfg(any(feature = "host-reference", feature = "portable-execution"))]
    pub fn apply(
        &self,
        roots: EconomicRoots,
        block: &Block,
        coinbase_maturity: u64,
    ) -> Result<EconomicRoots, EconomicStateError> {
        self.validate()?;
        let (effects, kernels) = economic_block_effects(block)?;
        if self.utxo_proof.keys() != effects.iter().map(|(key, _)| *key).collect::<Vec<_>>()
            || self.kernel_proof.keys() != kernels.as_slice()
        {
            return Err(EconomicStateError::InvalidProof);
        }
        let mut old = Vec::with_capacity(effects.len());
        let mut new = Vec::with_capacity(effects.len());
        for ((_, effect), opened) in effects.iter().zip(&self.old_utxos) {
            if effect.spent {
                let value = opened.ok_or(EconomicStateError::MissingInput)?;
                if value.is_coinbase
                    && block.header.height.0.saturating_sub(value.created_height)
                        < coinbase_maturity
                {
                    return Err(EconomicStateError::ImmatureCoinbase);
                }
                old.push(Some(value));
                new.push(None);
            } else {
                if opened.is_some() {
                    return Err(EconomicStateError::DuplicateOutput);
                }
                old.push(None);
                new.push(Some(EconomicUtxo {
                    created_height: block.header.height.0,
                    is_coinbase: effect.coinbase,
                }));
            }
        }
        let utxo_root = self
            .utxo_proof
            .update_utxo_root(roots.utxo_root, &old, &new)?;
        let absent = vec![false; kernels.len()];
        let present = vec![true; kernels.len()];
        let kernel_root =
            self.kernel_proof
                .update_kernel_root(roots.kernel_root, &absent, &present)?;
        Ok(EconomicRoots {
            utxo_root,
            kernel_root,
        })
    }

    /// Encode the unique bounded `UDECBW01` block witness.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EconomicStateError> {
        self.validate()?;
        let utxo = self.utxo_proof.to_bytes()?;
        let kernel = self.kernel_proof.to_bytes()?;
        let utxo_len: u32 = utxo
            .len()
            .try_into()
            .map_err(|_| EconomicStateError::InvalidProof)?;
        let kernel_len: u32 = kernel
            .len()
            .try_into()
            .map_err(|_| EconomicStateError::InvalidProof)?;
        let mut bytes = Vec::with_capacity(
            ECONOMIC_BLOCK_WITNESS_HEADER_BYTES
                + utxo.len()
                + kernel.len()
                + self.old_utxos.len() * 10,
        );
        bytes.extend_from_slice(ECONOMIC_BLOCK_WITNESS_MAGIC);
        bytes.extend_from_slice(&utxo_len.to_be_bytes());
        bytes.extend_from_slice(&kernel_len.to_be_bytes());
        bytes.extend_from_slice(&utxo);
        bytes.extend_from_slice(&kernel);
        for value in &self.old_utxos {
            match value {
                Some(value) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&value.created_height.to_be_bytes());
                    bytes.push(u8::from(value.is_coinbase));
                }
                None => bytes.push(0),
            }
        }
        if bytes.len() > MAX_ECONOMIC_BLOCK_WITNESS_BYTES {
            return Err(EconomicStateError::InvalidProof);
        }
        Ok(bytes)
    }

    /// Decode and canonically revalidate one exact `UDECBW01` witness.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EconomicStateError> {
        if bytes.len() < ECONOMIC_BLOCK_WITNESS_HEADER_BYTES
            || bytes.len() > MAX_ECONOMIC_BLOCK_WITNESS_BYTES
            || &bytes[..8] != ECONOMIC_BLOCK_WITNESS_MAGIC
        {
            return Err(EconomicStateError::InvalidProof);
        }
        let utxo_len = u32::from_be_bytes(economic_array(bytes, 8)?) as usize;
        let kernel_len = u32::from_be_bytes(economic_array(bytes, 12)?) as usize;
        let utxo_start = ECONOMIC_BLOCK_WITNESS_HEADER_BYTES;
        let utxo_end = utxo_start
            .checked_add(utxo_len)
            .ok_or(EconomicStateError::InvalidProof)?;
        let kernel_end = utxo_end
            .checked_add(kernel_len)
            .ok_or(EconomicStateError::InvalidProof)?;
        if kernel_end > bytes.len() {
            return Err(EconomicStateError::InvalidProof);
        }
        let utxo_proof = EconomicMultiProof::from_bytes(&bytes[utxo_start..utxo_end])?;
        let kernel_proof = EconomicMultiProof::from_bytes(&bytes[utxo_end..kernel_end])?;
        let mut old_utxos = Vec::with_capacity(utxo_proof.keys.len());
        let mut cursor = kernel_end;
        for _ in 0..utxo_proof.keys.len() {
            let flag = *bytes.get(cursor).ok_or(EconomicStateError::InvalidProof)?;
            cursor += 1;
            old_utxos.push(match flag {
                0 => None,
                1 => {
                    let created_height = u64::from_be_bytes(economic_array(bytes, cursor)?);
                    let coinbase = *bytes
                        .get(cursor + 8)
                        .ok_or(EconomicStateError::InvalidProof)?;
                    cursor += 9;
                    if coinbase > 1 {
                        return Err(EconomicStateError::InvalidProof);
                    }
                    Some(EconomicUtxo {
                        created_height,
                        is_coinbase: coinbase == 1,
                    })
                }
                _ => return Err(EconomicStateError::InvalidProof),
            });
        }
        if cursor != bytes.len() {
            return Err(EconomicStateError::InvalidProof);
        }
        let witness = Self {
            utxo_proof,
            kernel_proof,
            old_utxos,
        };
        witness.validate()?;
        if witness.to_bytes()?.as_slice() != bytes {
            return Err(EconomicStateError::InvalidProof);
        }
        Ok(witness)
    }

    fn validate(&self) -> Result<(), EconomicStateError> {
        self.utxo_proof.validate()?;
        self.kernel_proof.validate()?;
        if self.utxo_proof.tree != UTXO_TREE
            || self.kernel_proof.tree != KERNEL_TREE
            || self.old_utxos.len() != self.utxo_proof.keys.len()
        {
            return Err(EconomicStateError::InvalidProof);
        }
        Ok(())
    }
}

#[cfg(any(feature = "host-reference", feature = "portable-execution"))]
#[derive(Debug, Clone, Copy)]
struct UtxoEffect {
    spent: bool,
    coinbase: bool,
}

#[cfg(any(feature = "host-reference", feature = "portable-execution"))]
type BlockEffects = (Vec<([u8; 33], UtxoEffect)>, Vec<[u8; 33]>);

#[cfg(any(feature = "host-reference", feature = "portable-execution"))]
fn economic_block_effects(block: &Block) -> Result<BlockEffects, EconomicStateError> {
    let mut effects = BTreeMap::new();
    for transaction in &block.transactions {
        for input in &transaction.inputs {
            let key = *input.commitment.as_bytes();
            if key == [0; 33]
                || effects
                    .insert(
                        key,
                        UtxoEffect {
                            spent: true,
                            coinbase: false,
                        },
                    )
                    .is_some()
            {
                return Err(EconomicStateError::InvalidProof);
            }
        }
    }

    let coinbase = *block.coinbase.output.commitment.as_bytes();
    if coinbase == [0; 33]
        || effects
            .insert(
                coinbase,
                UtxoEffect {
                    spent: false,
                    coinbase: true,
                },
            )
            .is_some()
    {
        return Err(EconomicStateError::InvalidProof);
    }
    for transaction in &block.transactions {
        for output in &transaction.outputs {
            let key = *output.commitment.as_bytes();
            if key == [0; 33]
                || effects
                    .insert(
                        key,
                        UtxoEffect {
                            spent: false,
                            coinbase: false,
                        },
                    )
                    .is_some()
            {
                return Err(EconomicStateError::InvalidProof);
            }
        }
    }
    let mut effects: Vec<_> = effects.into_iter().collect();
    effects.sort_unstable_by_key(|(key, _)| sparse_path(UTXO_TREE, key));
    if effects
        .windows(2)
        .any(|pair| sparse_path(UTXO_TREE, &pair[0].0) >= sparse_path(UTXO_TREE, &pair[1].0))
    {
        return Err(EconomicStateError::InvalidProof);
    }

    let mut kernels = BTreeSet::new();
    let coinbase_kernel = *block.coinbase.kernel.excess.as_bytes();
    if coinbase_kernel == [0; 33] || !kernels.insert(coinbase_kernel) {
        return Err(EconomicStateError::InvalidProof);
    }
    for transaction in &block.transactions {
        for kernel in &transaction.kernels {
            let key = *kernel.excess.as_bytes();
            if key == [0; 33] || !kernels.insert(key) {
                return Err(EconomicStateError::InvalidProof);
            }
        }
    }
    let mut kernels: Vec<_> = kernels.into_iter().collect();
    kernels.sort_unstable_by_key(|key| sparse_path(KERNEL_TREE, key));
    if kernels
        .windows(2)
        .any(|pair| sparse_path(KERNEL_TREE, &pair[0]) >= sparse_path(KERNEL_TREE, &pair[1]))
    {
        return Err(EconomicStateError::InvalidProof);
    }
    Ok((effects, kernels))
}

impl EconomicMultiProof {
    /// Build the minimal canonical multiproof for unique block-effect keys.
    pub fn from_state(
        state: &EconomicState,
        utxo_tree: bool,
        keys: impl IntoIterator<Item = [u8; 33]>,
    ) -> Result<Self, EconomicStateError> {
        let tree = if utxo_tree { UTXO_TREE } else { KERNEL_TREE };
        let mut queries: Vec<_> = keys
            .into_iter()
            .map(|key| (sparse_path(tree, &key), key))
            .collect();
        validate_and_sort_queries(&mut queries)?;
        let keys: Vec<_> = queries.iter().map(|(_, key)| *key).collect();
        let paths: Vec<_> = queries.iter().map(|(path, _)| *path).collect();
        let mut leaves = if utxo_tree {
            economic_utxo_leaves(&state.utxos)
        } else {
            economic_kernel_leaves(&state.kernels)
        };
        leaves.sort_unstable_by_key(|(path, _)| *path);
        let empty = economic_empty_roots(tree);
        let boundaries = multiproof_boundary_count(&paths, 0)?;
        let mut side_bitmap = vec![0u8; boundaries.div_ceil(8)];
        let mut side_nodes = Vec::new();
        let mut boundary_index = 0usize;
        collect_multi_sides(
            tree,
            &leaves,
            &paths,
            0,
            &empty,
            &mut boundary_index,
            &mut side_bitmap,
            &mut side_nodes,
        )?;
        if boundary_index != boundaries {
            return Err(EconomicStateError::InvalidProof);
        }
        let proof = Self {
            tree,
            keys,
            side_bitmap,
            side_nodes,
        };
        proof.validate()?;
        Ok(proof)
    }

    /// Keys in canonical sparse-path order.
    pub fn keys(&self) -> &[[u8; 33]] {
        &self.keys
    }

    /// Open a UTXO multiproof with values aligned to [`Self::keys`].
    pub fn utxo_root(
        &self,
        values: &[Option<EconomicUtxo>],
    ) -> Result<[u8; 32], EconomicStateError> {
        if self.tree != UTXO_TREE || values.len() != self.keys.len() {
            return Err(EconomicStateError::InvalidProof);
        }
        let leaves: Vec<_> = self
            .keys
            .iter()
            .zip(values)
            .map(|(key, value)| value.map(|entry| economic_utxo_leaf(*key, entry)))
            .collect();
        self.root(&leaves)
    }

    /// Verify old UTXOs and compute the root after all block effects.
    pub fn update_utxo_root(
        &self,
        expected_root: [u8; 32],
        old: &[Option<EconomicUtxo>],
        new: &[Option<EconomicUtxo>],
    ) -> Result<[u8; 32], EconomicStateError> {
        if self.utxo_root(old)? != expected_root {
            return Err(EconomicStateError::ProofRootMismatch);
        }
        self.utxo_root(new)
    }

    /// Open a historical-kernel multiproof with presence bits aligned to keys.
    pub fn kernel_root(&self, present: &[bool]) -> Result<[u8; 32], EconomicStateError> {
        if self.tree != KERNEL_TREE || present.len() != self.keys.len() {
            return Err(EconomicStateError::InvalidProof);
        }
        let leaves: Vec<_> = self
            .keys
            .iter()
            .zip(present)
            .map(|(key, present)| present.then(|| economic_kernel_leaf(*key)))
            .collect();
        self.root(&leaves)
    }

    /// Verify old kernel presence and compute the root after replacement.
    pub fn update_kernel_root(
        &self,
        expected_root: [u8; 32],
        old: &[bool],
        new: &[bool],
    ) -> Result<[u8; 32], EconomicStateError> {
        if self.kernel_root(old)? != expected_root {
            return Err(EconomicStateError::ProofRootMismatch);
        }
        self.kernel_root(new)
    }

    /// Encode the unique bounded `UDECMP01` multiproof.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EconomicStateError> {
        self.validate()?;
        let key_count: u32 = self
            .keys
            .len()
            .try_into()
            .map_err(|_| EconomicStateError::InvalidProof)?;
        let side_count: u32 = self
            .side_nodes
            .len()
            .try_into()
            .map_err(|_| EconomicStateError::InvalidProof)?;
        let mut bytes = Vec::with_capacity(
            ECONOMIC_MULTIPROOF_HEADER_BYTES
                + self.keys.len() * 33
                + self.side_bitmap.len()
                + self.side_nodes.len() * 32,
        );
        bytes.extend_from_slice(ECONOMIC_MULTIPROOF_MAGIC);
        bytes.push(self.tree);
        bytes.extend_from_slice(&key_count.to_be_bytes());
        bytes.extend_from_slice(&side_count.to_be_bytes());
        for key in &self.keys {
            bytes.extend_from_slice(key);
        }
        bytes.extend_from_slice(&self.side_bitmap);
        for side in &self.side_nodes {
            bytes.extend_from_slice(side);
        }
        if bytes.len() > MAX_ECONOMIC_MULTIPROOF_BYTES {
            return Err(EconomicStateError::InvalidProof);
        }
        Ok(bytes)
    }

    /// Decode and canonically revalidate one exact `UDECMP01` multiproof.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EconomicStateError> {
        if bytes.len() < ECONOMIC_MULTIPROOF_HEADER_BYTES
            || bytes.len() > MAX_ECONOMIC_MULTIPROOF_BYTES
            || &bytes[..8] != ECONOMIC_MULTIPROOF_MAGIC
        {
            return Err(EconomicStateError::InvalidProof);
        }
        let tree = bytes[8];
        let key_count = u32::from_be_bytes(economic_array(bytes, 9)?) as usize;
        let side_count = u32::from_be_bytes(economic_array(bytes, 13)?) as usize;
        if key_count == 0 || key_count > MAX_ECONOMIC_MULTIPROOF_KEYS {
            return Err(EconomicStateError::InvalidProof);
        }
        let keys_end = ECONOMIC_MULTIPROOF_HEADER_BYTES
            .checked_add(
                key_count
                    .checked_mul(33)
                    .ok_or(EconomicStateError::InvalidProof)?,
            )
            .ok_or(EconomicStateError::InvalidProof)?;
        if keys_end > bytes.len() {
            return Err(EconomicStateError::InvalidProof);
        }
        let mut keys = Vec::with_capacity(key_count);
        let mut cursor = ECONOMIC_MULTIPROOF_HEADER_BYTES;
        for _ in 0..key_count {
            keys.push(economic_array(bytes, cursor)?);
            cursor += 33;
        }
        let paths = query_paths(tree, &keys)?;
        let boundaries = multiproof_boundary_count(&paths, 0)?;
        let bitmap_len = boundaries.div_ceil(8);
        let bitmap_end = cursor
            .checked_add(bitmap_len)
            .ok_or(EconomicStateError::InvalidProof)?;
        let expected = bitmap_end
            .checked_add(
                side_count
                    .checked_mul(32)
                    .ok_or(EconomicStateError::InvalidProof)?,
            )
            .ok_or(EconomicStateError::InvalidProof)?;
        if expected != bytes.len() {
            return Err(EconomicStateError::InvalidProof);
        }
        let side_bitmap = bytes[cursor..bitmap_end].to_vec();
        cursor = bitmap_end;
        let mut side_nodes = Vec::with_capacity(side_count);
        for _ in 0..side_count {
            side_nodes.push(economic_array(bytes, cursor)?);
            cursor += 32;
        }
        let proof = Self {
            tree,
            keys,
            side_bitmap,
            side_nodes,
        };
        proof.validate()?;
        if proof.to_bytes()?.as_slice() != bytes {
            return Err(EconomicStateError::InvalidProof);
        }
        Ok(proof)
    }

    fn root(&self, leaves: &[Option<[u8; 32]>]) -> Result<[u8; 32], EconomicStateError> {
        self.validate()?;
        if leaves.len() != self.keys.len() {
            return Err(EconomicStateError::InvalidProof);
        }
        let paths = query_paths(self.tree, &self.keys)?;
        let empty = economic_empty_roots(self.tree);
        let mut boundary_index = 0usize;
        let mut side_index = 0usize;
        let root = reconstruct_multi_root(
            self.tree,
            &paths,
            leaves,
            0,
            &empty,
            &self.side_bitmap,
            &self.side_nodes,
            &mut boundary_index,
            &mut side_index,
        )?;
        if boundary_index != multiproof_boundary_count(&paths, 0)?
            || side_index != self.side_nodes.len()
        {
            return Err(EconomicStateError::InvalidProof);
        }
        Ok(root)
    }

    fn validate(&self) -> Result<(), EconomicStateError> {
        if !matches!(self.tree, UTXO_TREE | KERNEL_TREE)
            || self.keys.is_empty()
            || self.keys.len() > MAX_ECONOMIC_MULTIPROOF_KEYS
        {
            return Err(EconomicStateError::InvalidProof);
        }
        let paths = query_paths(self.tree, &self.keys)?;
        let boundaries = multiproof_boundary_count(&paths, 0)?;
        if self.side_bitmap.len() != boundaries.div_ceil(8)
            || self.side_nodes.len() != bitmap_population(&self.side_bitmap)
            || self.side_nodes.len() > boundaries
            || (boundaries % 8 != 0
                && self
                    .side_bitmap
                    .last()
                    .is_some_and(|last| *last & !((1u8 << (boundaries % 8)) - 1) != 0))
        {
            return Err(EconomicStateError::InvalidProof);
        }
        let empty = economic_empty_roots(self.tree);
        let mut boundary_index = 0usize;
        let mut side_index = 0usize;
        validate_multi_sides(
            &paths,
            0,
            &empty,
            &self.side_bitmap,
            &self.side_nodes,
            &mut boundary_index,
            &mut side_index,
        )?;
        if boundary_index != boundaries || side_index != self.side_nodes.len() {
            return Err(EconomicStateError::InvalidProof);
        }
        Ok(())
    }
}

impl EconomicPathProof {
    /// Build the unique path for `key` from an authenticated host snapshot.
    pub fn from_state(
        state: &EconomicState,
        utxo_tree: bool,
        key: [u8; 33],
    ) -> Result<Self, EconomicStateError> {
        if key == [0; 33] {
            return Err(EconomicStateError::InvalidProof);
        }
        let tree = if utxo_tree { UTXO_TREE } else { KERNEL_TREE };
        let mut leaves = if utxo_tree {
            economic_utxo_leaves(&state.utxos)
        } else {
            economic_kernel_leaves(&state.kernels)
        };
        leaves.sort_unstable_by_key(|(path, _)| *path);
        let path = sparse_path(tree, &key);
        let empty = economic_empty_roots(tree);
        let mut by_level = [None; TREE_DEPTH];
        collect_siblings(tree, &leaves, &path, 0, &empty, &mut by_level);
        let mut sibling_bitmap = [0u8; 32];
        let mut siblings = Vec::new();
        for (level, sibling) in by_level.into_iter().enumerate() {
            if let Some(sibling) = sibling {
                set_little_bit(&mut sibling_bitmap, level);
                siblings.push(sibling);
            }
        }
        let proof = Self {
            tree,
            key,
            sibling_bitmap,
            siblings,
        };
        proof.validate()?;
        Ok(proof)
    }

    /// Whether this path belongs to the UTXO tree rather than the kernel tree.
    pub const fn is_utxo(&self) -> bool {
        self.tree == UTXO_TREE
    }

    /// Exact uncompressed 33-byte commitment or excess key.
    pub const fn key(&self) -> [u8; 33] {
        self.key
    }

    /// Open a UTXO membership or nonmembership path.
    pub fn utxo_root(&self, value: Option<EconomicUtxo>) -> Result<[u8; 32], EconomicStateError> {
        if self.tree != UTXO_TREE {
            return Err(EconomicStateError::InvalidProof);
        }
        self.root(value.map(|entry| economic_utxo_leaf(self.key, entry)))
    }

    /// Verify an old UTXO value and return the root after replacement.
    pub fn update_utxo_root(
        &self,
        expected_root: [u8; 32],
        old: Option<EconomicUtxo>,
        new: Option<EconomicUtxo>,
    ) -> Result<[u8; 32], EconomicStateError> {
        if self.utxo_root(old)? != expected_root {
            return Err(EconomicStateError::ProofRootMismatch);
        }
        self.utxo_root(new)
    }

    /// Open a kernel membership or nonmembership path.
    pub fn kernel_root(&self, present: bool) -> Result<[u8; 32], EconomicStateError> {
        if self.tree != KERNEL_TREE {
            return Err(EconomicStateError::InvalidProof);
        }
        self.root(present.then(|| economic_kernel_leaf(self.key)))
    }

    /// Verify old kernel presence and return the root after replacement.
    pub fn update_kernel_root(
        &self,
        expected_root: [u8; 32],
        old_present: bool,
        new_present: bool,
    ) -> Result<[u8; 32], EconomicStateError> {
        if self.kernel_root(old_present)? != expected_root {
            return Err(EconomicStateError::ProofRootMismatch);
        }
        self.kernel_root(new_present)
    }

    /// Encode the unique bounded `UDECPR01` representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EconomicStateError> {
        self.validate()?;
        let count: u16 = self
            .siblings
            .len()
            .try_into()
            .map_err(|_| EconomicStateError::InvalidProof)?;
        let mut bytes = Vec::with_capacity(ECONOMIC_PROOF_HEADER_BYTES + self.siblings.len() * 32);
        bytes.extend_from_slice(ECONOMIC_PROOF_MAGIC);
        bytes.push(self.tree);
        bytes.extend_from_slice(&self.key);
        bytes.extend_from_slice(&self.sibling_bitmap);
        bytes.extend_from_slice(&count.to_be_bytes());
        for sibling in &self.siblings {
            bytes.extend_from_slice(sibling);
        }
        Ok(bytes)
    }

    /// Decode and canonically revalidate one exact `UDECPR01` path.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EconomicStateError> {
        if bytes.len() < ECONOMIC_PROOF_HEADER_BYTES
            || bytes.len() > MAX_ECONOMIC_PROOF_BYTES
            || &bytes[..8] != ECONOMIC_PROOF_MAGIC
        {
            return Err(EconomicStateError::InvalidProof);
        }
        let tree = bytes[8];
        let key = economic_array(bytes, 9)?;
        let sibling_bitmap = economic_array(bytes, 42)?;
        let count = usize::from(u16::from_be_bytes(economic_array(bytes, 74)?));
        let expected = ECONOMIC_PROOF_HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(32)
                    .ok_or(EconomicStateError::InvalidProof)?,
            )
            .ok_or(EconomicStateError::InvalidProof)?;
        if count > TREE_DEPTH || expected != bytes.len() {
            return Err(EconomicStateError::InvalidProof);
        }
        let mut siblings = Vec::with_capacity(count);
        let mut cursor = ECONOMIC_PROOF_HEADER_BYTES;
        for _ in 0..count {
            siblings.push(economic_array(bytes, cursor)?);
            cursor += 32;
        }
        let proof = Self {
            tree,
            key,
            sibling_bitmap,
            siblings,
        };
        proof.validate()?;
        if proof.to_bytes()?.as_slice() != bytes {
            return Err(EconomicStateError::InvalidProof);
        }
        Ok(proof)
    }

    fn root(&self, leaf: Option<[u8; 32]>) -> Result<[u8; 32], EconomicStateError> {
        self.validate()?;
        let path = sparse_path(self.tree, &self.key);
        let empty = economic_empty_roots(self.tree);
        let mut current = leaf.unwrap_or(empty[TREE_DEPTH]);
        let mut supplied = self.siblings.iter();
        for level in 0..TREE_DEPTH {
            let empty_sibling = empty[TREE_DEPTH - level];
            let sibling = if little_bit(&self.sibling_bitmap, level) {
                *supplied.next().ok_or(EconomicStateError::InvalidProof)?
            } else {
                empty_sibling
            };
            let root_depth = TREE_DEPTH - 1 - level;
            current = if path_bit(&path, root_depth) {
                sparse_node_hash(self.tree, INTERNAL_NODE, &sibling, &current)
            } else {
                sparse_node_hash(self.tree, INTERNAL_NODE, &current, &sibling)
            };
        }
        if supplied.next().is_some() {
            return Err(EconomicStateError::InvalidProof);
        }
        Ok(current)
    }

    fn validate(&self) -> Result<(), EconomicStateError> {
        if !matches!(self.tree, UTXO_TREE | KERNEL_TREE)
            || self.key == [0; 33]
            || self.siblings.len() > TREE_DEPTH
        {
            return Err(EconomicStateError::InvalidProof);
        }
        let count: usize = self
            .sibling_bitmap
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum();
        if count != self.siblings.len() {
            return Err(EconomicStateError::InvalidProof);
        }
        let empty = economic_empty_roots(self.tree);
        let mut supplied = self.siblings.iter();
        for level in 0..TREE_DEPTH {
            if little_bit(&self.sibling_bitmap, level)
                && *supplied.next().ok_or(EconomicStateError::InvalidProof)?
                    == empty[TREE_DEPTH - level]
            {
                return Err(EconomicStateError::InvalidProof);
            }
        }
        if supplied.next().is_some() {
            return Err(EconomicStateError::InvalidProof);
        }
        Ok(())
    }
}

/// Complete deterministic ordinary DOM state at one checkpoint.
///
/// `BTreeMap` and `BTreeSet` give one canonical snapshot order. The public root
/// uses key-addressed sparse trees, so a production proving backend can replace
/// the full host snapshot with authenticated update multiproofs without
/// changing the committed state semantics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EconomicState {
    utxos: BTreeMap<[u8; 33], EconomicUtxo>,
    kernels: BTreeSet<[u8; 33]>,
}

impl EconomicState {
    /// Reconstruct one exact state from canonical unique entries.
    pub fn from_entries(
        utxos: impl IntoIterator<Item = ([u8; 33], EconomicUtxo)>,
        kernels: impl IntoIterator<Item = [u8; 33]>,
    ) -> Result<Self, EconomicStateError> {
        let mut state = Self::default();
        for (commitment, entry) in utxos {
            if commitment == [0; 33] || state.utxos.insert(commitment, entry).is_some() {
                return Err(EconomicStateError::InvalidSnapshot);
            }
        }
        for excess in kernels {
            if excess == [0; 33] || !state.kernels.insert(excess) {
                return Err(EconomicStateError::InvalidSnapshot);
            }
        }
        // Detect the computationally infeasible but consensus-relevant case in
        // which distinct public keys address the same sparse-tree path.
        ensure_unique_paths(state.utxos.keys().copied(), UTXO_TREE)?;
        ensure_unique_paths(state.kernels.iter().copied(), KERNEL_TREE)?;
        Ok(state)
    }

    /// Ordered read-only UTXO snapshot.
    pub fn utxos(&self) -> &BTreeMap<[u8; 33], EconomicUtxo> {
        &self.utxos
    }

    /// Ordered read-only historical kernel set.
    pub fn kernels(&self) -> &BTreeSet<[u8; 33]> {
        &self.kernels
    }

    /// Sparse root of every unspent output and its maturity metadata.
    pub fn utxo_set_root(&self) -> Result<[u8; 32], EconomicStateError> {
        let mut leaves = economic_utxo_leaves(&self.utxos);
        leaves.sort_unstable_by_key(|(path, _)| *path);
        sparse_root(UTXO_TREE, &leaves)
    }

    /// Sparse root of every historical kernel excess used for replay rejection.
    pub fn kernel_set_root(&self) -> Result<[u8; 32], EconomicStateError> {
        let mut leaves = economic_kernel_leaves(&self.kernels);
        leaves.sort_unstable_by_key(|(path, _)| *path);
        sparse_root(KERNEL_TREE, &leaves)
    }

    /// Exact `UDCCTX02` economic-state commitment.
    pub fn context_root(&self) -> Result<[u8; 32], EconomicStateError> {
        checkpoint_economic_state_root(self.utxo_set_root()?, self.kernel_set_root()?)
            .map_err(|_| EconomicStateError::InvalidRoot)
    }

    /// Validate and atomically apply the contextual UTXO and kernel effects of
    /// one already body-valid block.
    #[cfg(feature = "host-reference")]
    pub fn apply_block(
        &mut self,
        block: &Block,
        coinbase_maturity: u64,
    ) -> Result<(), EconomicStateError> {
        let mut candidate = self.clone();
        let height = block.header.height.0;

        for transaction in &block.transactions {
            for input in &transaction.inputs {
                let key = *input.commitment.as_bytes();
                let entry = candidate
                    .utxos
                    .remove(&key)
                    .ok_or(EconomicStateError::MissingInput)?;
                if entry.is_coinbase
                    && height.saturating_sub(entry.created_height) < coinbase_maturity
                {
                    return Err(EconomicStateError::ImmatureCoinbase);
                }
            }
        }

        let coinbase = *block.coinbase.output.commitment.as_bytes();
        if candidate
            .utxos
            .insert(
                coinbase,
                EconomicUtxo {
                    created_height: height,
                    is_coinbase: true,
                },
            )
            .is_some()
        {
            return Err(EconomicStateError::DuplicateOutput);
        }
        for transaction in &block.transactions {
            for output in &transaction.outputs {
                if candidate
                    .utxos
                    .insert(
                        *output.commitment.as_bytes(),
                        EconomicUtxo {
                            created_height: height,
                            is_coinbase: false,
                        },
                    )
                    .is_some()
                {
                    return Err(EconomicStateError::DuplicateOutput);
                }
            }
        }

        if !candidate
            .kernels
            .insert(*block.coinbase.kernel.excess.as_bytes())
        {
            return Err(EconomicStateError::DuplicateKernel);
        }
        for transaction in &block.transactions {
            for kernel in &transaction.kernels {
                if !candidate.kernels.insert(*kernel.excess.as_bytes()) {
                    return Err(EconomicStateError::DuplicateKernel);
                }
            }
        }
        *self = candidate;
        Ok(())
    }
}

fn ensure_unique_paths(
    keys: impl IntoIterator<Item = [u8; 33]>,
    tree: u8,
) -> Result<(), EconomicStateError> {
    let mut paths = BTreeSet::new();
    for key in keys {
        if !paths.insert(sparse_path(tree, &key)) {
            return Err(EconomicStateError::InvalidSnapshot);
        }
    }
    Ok(())
}

fn sparse_path(tree: u8, key: &[u8; 33]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(SMT_DOMAIN.len() + 1 + key.len());
    preimage.extend_from_slice(SMT_DOMAIN);
    preimage.push(tree);
    preimage.extend_from_slice(key);
    keccak(&preimage)
}

fn economic_utxo_leaf(key: [u8; 33], entry: EconomicUtxo) -> [u8; 32] {
    let path = sparse_path(UTXO_TREE, &key);
    let mut preimage = Vec::with_capacity(SMT_DOMAIN.len() + 1 + 1 + 32 + 8 + 1);
    preimage.extend_from_slice(SMT_DOMAIN);
    preimage.push(UTXO_TREE);
    preimage.push(UTXO_LEAF);
    preimage.extend_from_slice(&path);
    preimage.extend_from_slice(&entry.created_height.to_be_bytes());
    preimage.push(u8::from(entry.is_coinbase));
    keccak(&preimage)
}

fn economic_kernel_leaf(key: [u8; 33]) -> [u8; 32] {
    let path = sparse_path(KERNEL_TREE, &key);
    let mut preimage = Vec::with_capacity(SMT_DOMAIN.len() + 1 + 1 + 32);
    preimage.extend_from_slice(SMT_DOMAIN);
    preimage.push(KERNEL_TREE);
    preimage.push(KERNEL_LEAF);
    preimage.extend_from_slice(&path);
    keccak(&preimage)
}

fn economic_utxo_leaves(values: &BTreeMap<[u8; 33], EconomicUtxo>) -> Vec<([u8; 32], [u8; 32])> {
    values
        .iter()
        .map(|(key, value)| {
            (
                sparse_path(UTXO_TREE, key),
                economic_utxo_leaf(*key, *value),
            )
        })
        .collect()
}

fn economic_kernel_leaves(values: &BTreeSet<[u8; 33]>) -> Vec<([u8; 32], [u8; 32])> {
    values
        .iter()
        .map(|key| (sparse_path(KERNEL_TREE, key), economic_kernel_leaf(*key)))
        .collect()
}

fn economic_empty_roots(tree: u8) -> [[u8; 32]; TREE_DEPTH + 1] {
    let mut empty = [[0u8; 32]; TREE_DEPTH + 1];
    empty[TREE_DEPTH] = sparse_node_hash(tree, EMPTY_NODE, &[0; 32], &[0; 32]);
    for depth in (0..TREE_DEPTH).rev() {
        empty[depth] = sparse_node_hash(tree, INTERNAL_NODE, &empty[depth + 1], &empty[depth + 1]);
    }
    empty
}

fn collect_siblings(
    tree: u8,
    leaves: &[([u8; 32], [u8; 32])],
    target: &[u8; 32],
    depth: usize,
    empty: &[[u8; 32]; TREE_DEPTH + 1],
    by_level: &mut [Option<[u8; 32]>; TREE_DEPTH],
) {
    if depth == TREE_DEPTH || leaves.is_empty() {
        return;
    }
    let first_right = leaves.partition_point(|(path, _)| !path_bit(path, depth));
    let (selected, sibling) = if path_bit(target, depth) {
        (&leaves[first_right..], &leaves[..first_right])
    } else {
        (&leaves[..first_right], &leaves[first_right..])
    };
    let sibling_root = sparse_subtree(tree, sibling, depth + 1, empty);
    if sibling_root != empty[depth + 1] {
        by_level[TREE_DEPTH - 1 - depth] = Some(sibling_root);
    }
    collect_siblings(tree, selected, target, depth + 1, empty, by_level);
}

fn validate_and_sort_queries(
    queries: &mut [([u8; 32], [u8; 33])],
) -> Result<(), EconomicStateError> {
    if queries.is_empty() || queries.len() > MAX_ECONOMIC_MULTIPROOF_KEYS {
        return Err(EconomicStateError::InvalidProof);
    }
    if queries.iter().any(|(_, key)| *key == [0; 33]) {
        return Err(EconomicStateError::InvalidProof);
    }
    queries.sort_unstable_by_key(|(path, _)| *path);
    if queries.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(EconomicStateError::InvalidProof);
    }
    Ok(())
}

fn query_paths(tree: u8, keys: &[[u8; 33]]) -> Result<Vec<[u8; 32]>, EconomicStateError> {
    if !matches!(tree, UTXO_TREE | KERNEL_TREE) {
        return Err(EconomicStateError::InvalidProof);
    }
    let queries: Vec<_> = keys
        .iter()
        .map(|key| (sparse_path(tree, key), *key))
        .collect();
    if queries.iter().any(|(_, key)| *key == [0; 33])
        || queries.windows(2).any(|pair| pair[0].0 >= pair[1].0)
    {
        return Err(EconomicStateError::InvalidProof);
    }
    Ok(queries.into_iter().map(|(path, _)| path).collect())
}

fn multiproof_boundary_count(
    paths: &[[u8; 32]],
    depth: usize,
) -> Result<usize, EconomicStateError> {
    if paths.is_empty() || depth > TREE_DEPTH {
        return Err(EconomicStateError::InvalidProof);
    }
    if depth == TREE_DEPTH {
        return if paths.len() == 1 {
            Ok(0)
        } else {
            Err(EconomicStateError::InvalidProof)
        };
    }
    let first_right = paths.partition_point(|path| !path_bit(path, depth));
    let left = if first_right == 0 {
        1
    } else {
        multiproof_boundary_count(&paths[..first_right], depth + 1)?
    };
    let right = if first_right == paths.len() {
        1
    } else {
        multiproof_boundary_count(&paths[first_right..], depth + 1)?
    };
    left.checked_add(right)
        .ok_or(EconomicStateError::InvalidProof)
}

#[allow(clippy::too_many_arguments)]
fn collect_multi_sides(
    tree: u8,
    leaves: &[([u8; 32], [u8; 32])],
    queries: &[[u8; 32]],
    depth: usize,
    empty: &[[u8; 32]; TREE_DEPTH + 1],
    boundary_index: &mut usize,
    side_bitmap: &mut [u8],
    side_nodes: &mut Vec<[u8; 32]>,
) -> Result<(), EconomicStateError> {
    if queries.is_empty() || depth > TREE_DEPTH {
        return Err(EconomicStateError::InvalidProof);
    }
    if depth == TREE_DEPTH {
        return if queries.len() == 1 {
            Ok(())
        } else {
            Err(EconomicStateError::InvalidProof)
        };
    }
    let leaf_split = leaves.partition_point(|(path, _)| !path_bit(path, depth));
    let query_split = queries.partition_point(|path| !path_bit(path, depth));
    for (side_leaves, side_queries) in [
        (&leaves[..leaf_split], &queries[..query_split]),
        (&leaves[leaf_split..], &queries[query_split..]),
    ] {
        if side_queries.is_empty() {
            let side = sparse_subtree(tree, side_leaves, depth + 1, empty);
            if side != empty[depth + 1] {
                set_dynamic_bit(side_bitmap, *boundary_index)?;
                side_nodes.push(side);
            }
            *boundary_index = boundary_index
                .checked_add(1)
                .ok_or(EconomicStateError::InvalidProof)?;
        } else {
            collect_multi_sides(
                tree,
                side_leaves,
                side_queries,
                depth + 1,
                empty,
                boundary_index,
                side_bitmap,
                side_nodes,
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_multi_root(
    tree: u8,
    paths: &[[u8; 32]],
    leaves: &[Option<[u8; 32]>],
    depth: usize,
    empty: &[[u8; 32]; TREE_DEPTH + 1],
    side_bitmap: &[u8],
    side_nodes: &[[u8; 32]],
    boundary_index: &mut usize,
    side_index: &mut usize,
) -> Result<[u8; 32], EconomicStateError> {
    if paths.is_empty() || paths.len() != leaves.len() || depth > TREE_DEPTH {
        return Err(EconomicStateError::InvalidProof);
    }
    if depth == TREE_DEPTH {
        if paths.len() != 1 {
            return Err(EconomicStateError::InvalidProof);
        }
        return Ok(leaves[0].unwrap_or(empty[TREE_DEPTH]));
    }
    let split = paths.partition_point(|path| !path_bit(path, depth));
    let mut children = [[0u8; 32]; 2];
    for (index, (side_paths, side_leaves)) in [
        (&paths[..split], &leaves[..split]),
        (&paths[split..], &leaves[split..]),
    ]
    .into_iter()
    .enumerate()
    {
        children[index] = if side_paths.is_empty() {
            let present = dynamic_bit(side_bitmap, *boundary_index)?;
            *boundary_index = boundary_index
                .checked_add(1)
                .ok_or(EconomicStateError::InvalidProof)?;
            if present {
                let side = *side_nodes
                    .get(*side_index)
                    .ok_or(EconomicStateError::InvalidProof)?;
                *side_index = side_index
                    .checked_add(1)
                    .ok_or(EconomicStateError::InvalidProof)?;
                if side == empty[depth + 1] {
                    return Err(EconomicStateError::InvalidProof);
                }
                side
            } else {
                empty[depth + 1]
            }
        } else {
            reconstruct_multi_root(
                tree,
                side_paths,
                side_leaves,
                depth + 1,
                empty,
                side_bitmap,
                side_nodes,
                boundary_index,
                side_index,
            )?
        };
    }
    Ok(sparse_node_hash(
        tree,
        INTERNAL_NODE,
        &children[0],
        &children[1],
    ))
}

fn validate_multi_sides(
    paths: &[[u8; 32]],
    depth: usize,
    empty: &[[u8; 32]; TREE_DEPTH + 1],
    side_bitmap: &[u8],
    side_nodes: &[[u8; 32]],
    boundary_index: &mut usize,
    side_index: &mut usize,
) -> Result<(), EconomicStateError> {
    if paths.is_empty() || depth > TREE_DEPTH {
        return Err(EconomicStateError::InvalidProof);
    }
    if depth == TREE_DEPTH {
        return if paths.len() == 1 {
            Ok(())
        } else {
            Err(EconomicStateError::InvalidProof)
        };
    }
    let split = paths.partition_point(|path| !path_bit(path, depth));
    for side in [&paths[..split], &paths[split..]] {
        if side.is_empty() {
            if dynamic_bit(side_bitmap, *boundary_index)? {
                let hash = side_nodes
                    .get(*side_index)
                    .ok_or(EconomicStateError::InvalidProof)?;
                if *hash == empty[depth + 1] {
                    return Err(EconomicStateError::InvalidProof);
                }
                *side_index += 1;
            }
            *boundary_index += 1;
        } else {
            validate_multi_sides(
                side,
                depth + 1,
                empty,
                side_bitmap,
                side_nodes,
                boundary_index,
                side_index,
            )?;
        }
    }
    Ok(())
}

fn bitmap_population(bitmap: &[u8]) -> usize {
    bitmap.iter().map(|byte| byte.count_ones() as usize).sum()
}

fn dynamic_bit(bitmap: &[u8], index: usize) -> Result<bool, EconomicStateError> {
    let byte = bitmap
        .get(index / 8)
        .ok_or(EconomicStateError::InvalidProof)?;
    Ok(*byte & (1 << (index % 8)) != 0)
}

fn set_dynamic_bit(bitmap: &mut [u8], index: usize) -> Result<(), EconomicStateError> {
    let byte = bitmap
        .get_mut(index / 8)
        .ok_or(EconomicStateError::InvalidProof)?;
    *byte |= 1 << (index % 8);
    Ok(())
}

fn sparse_root(tree: u8, leaves: &[([u8; 32], [u8; 32])]) -> Result<[u8; 32], EconomicStateError> {
    for pair in leaves.windows(2) {
        if pair[0].0 >= pair[1].0 {
            return Err(EconomicStateError::InvalidSnapshot);
        }
    }
    let empty = economic_empty_roots(tree);
    Ok(sparse_subtree(tree, leaves, 0, &empty))
}

fn sparse_subtree(
    tree: u8,
    leaves: &[([u8; 32], [u8; 32])],
    depth: usize,
    empty: &[[u8; 32]; TREE_DEPTH + 1],
) -> [u8; 32] {
    if leaves.is_empty() {
        return empty[depth];
    }
    if depth == TREE_DEPTH {
        return leaves[0].1;
    }
    let first_right = leaves.partition_point(|(path, _)| !path_bit(path, depth));
    let left = sparse_subtree(tree, &leaves[..first_right], depth + 1, empty);
    let right = sparse_subtree(tree, &leaves[first_right..], depth + 1, empty);
    sparse_node_hash(tree, INTERNAL_NODE, &left, &right)
}

fn path_bit(path: &[u8; 32], depth: usize) -> bool {
    path[depth / 8] & (0x80 >> (depth % 8)) != 0
}

fn little_bit(bitmap: &[u8; 32], level: usize) -> bool {
    bitmap[level / 8] & (1 << (level % 8)) != 0
}

fn set_little_bit(bitmap: &mut [u8; 32], level: usize) {
    bitmap[level / 8] |= 1 << (level % 8);
}

fn sparse_node_hash(tree: u8, kind: u8, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(SMT_DOMAIN.len() + 2 + 64);
    preimage.extend_from_slice(SMT_DOMAIN);
    preimage.push(tree);
    preimage.push(kind);
    preimage.extend_from_slice(left);
    preimage.extend_from_slice(right);
    keccak(&preimage)
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

fn economic_array<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], EconomicStateError> {
    bytes
        .get(start..start + N)
        .ok_or(EconomicStateError::InvalidProof)?
        .try_into()
        .map_err(|_| EconomicStateError::InvalidProof)
}

fn segment_array<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], CheckpointSegmentStateError> {
    bytes
        .get(start..start + N)
        .ok_or(CheckpointSegmentStateError::InvalidFraming)?
        .try_into()
        .map_err(|_| CheckpointSegmentStateError::InvalidFraming)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "host-reference")]
    use dom_chain::UsdomV4ProofEnvelope;
    #[cfg(feature = "host-reference")]
    use dom_consensus::block::ProofOfWork;
    #[cfg(feature = "host-reference")]
    use dom_consensus::{
        BlockHeader, CoinbaseKernel, CoinbaseTransaction, Transaction, TransactionInput,
        TransactionOutput,
    };
    #[cfg(feature = "host-reference")]
    use dom_core::{BlockHeight, Hash256, Timestamp};
    #[cfg(feature = "host-reference")]
    use dom_crypto::{pedersen::Commitment, BlindingFactor};
    #[cfg(feature = "host-reference")]
    use dom_pow::CompactTarget;
    use dom_usdom_checkpoint_statement::{
        ContextHeader, SeedAnchor, CHECKPOINT_CONTEXT_HEADER_COUNT,
        CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS,
    };
    #[cfg(feature = "host-reference")]
    use primitive_types::U256;

    fn key(byte: u8) -> [u8; 33] {
        [byte; 33]
    }

    fn randomx_statement() -> CheckpointRandomXStatement {
        let block_height = 2_048u64;
        let compact = 0x1e7f_ffffu32;
        let mut pow_preimage = [0u8; CHECKPOINT_RANDOMX_PREIMAGE_BYTES];
        pow_preimage[..4].copy_from_slice(&CHECKPOINT_RANDOMX_BLOCK_VERSION.to_le_bytes());
        pow_preimage[CHECKPOINT_RANDOMX_PREIMAGE_HEIGHT_OFFSET
            ..CHECKPOINT_RANDOMX_PREIMAGE_HEIGHT_OFFSET + 8]
            .copy_from_slice(&block_height.to_le_bytes());
        pow_preimage[CHECKPOINT_RANDOMX_PREIMAGE_TARGET_OFFSET
            ..CHECKPOINT_RANDOMX_PREIMAGE_TARGET_OFFSET + 4]
            .copy_from_slice(&compact.to_le_bytes());
        pow_preimage[CHECKPOINT_RANDOMX_PREIMAGE_BYTES - 8..]
            .copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        let mut randomx_hash = [0u8; 32];
        randomx_hash[31] = 1;
        CheckpointRandomXStatement {
            network_magic: 0xA1B2C3D4,
            chain_id: [0x11; 32],
            block_height,
            seed_height: checkpoint_randomx_seed_height(block_height),
            seed_hash: [0x12; 32],
            pow_preimage,
            randomx_hash,
            target: checkpoint_compact_target(compact).expect("target"),
        }
    }

    #[cfg(feature = "host-reference")]
    fn randomx_relation_vector() -> CheckpointRandomXStatement {
        let mut statement = randomx_statement();
        let mut preimage = [0u8; CHECKPOINT_RANDOMX_PREIMAGE_BYTES];
        preimage[..32].copy_from_slice(b"DOM/checkpoint/randomx/vector/v1");
        preimage[32..40].copy_from_slice(&2_048u64.to_le_bytes());
        preimage[CHECKPOINT_RANDOMX_PREIMAGE_BYTES - 8..]
            .copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        statement.seed_hash = [0x12; 32];
        statement.pow_preimage = preimage;
        statement.randomx_hash =
            hex::decode("851b96702ac00d43d4a594fb22ecefcb9924f2964cc259dbc9b5b6b9cf639a1e")
                .expect("fixed RandomX vector")
                .try_into()
                .expect("32-byte RandomX vector");
        statement
    }

    #[test]
    fn checkpoint_randomx_statement_is_exact_canonical_and_bounded() {
        let statement = randomx_statement();
        let bytes = statement.to_bytes().expect("encode");
        assert_eq!(bytes.len(), CHECKPOINT_RANDOMX_STATEMENT_BYTES);
        assert_eq!(
            CheckpointRandomXStatement::from_bytes(&bytes).unwrap(),
            statement
        );
        assert_ne!(statement.commitment().unwrap(), [0; 32]);
        for end in 0..CHECKPOINT_RANDOMX_STATEMENT_BYTES {
            assert!(CheckpointRandomXStatement::from_bytes(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(CheckpointRandomXStatement::from_bytes(&trailing).is_err());
        for index in [0usize, 9, 11] {
            let mut malformed = bytes;
            malformed[index] ^= 1;
            assert!(CheckpointRandomXStatement::from_bytes(&malformed).is_err());
        }
    }

    #[test]
    fn checkpoint_randomx_statement_rejects_schedule_target_and_work_substitution() {
        let statement = randomx_statement();
        let mut changed = statement;
        changed.seed_height += 1;
        assert_eq!(
            changed.validate(),
            Err(CheckpointRandomXStatementError::InvalidSeedSchedule)
        );
        changed = statement;
        changed.pow_preimage[CHECKPOINT_RANDOMX_PREIMAGE_HEIGHT_OFFSET] ^= 1;
        assert_eq!(
            changed.validate(),
            Err(CheckpointRandomXStatementError::InvalidSeedSchedule)
        );
        changed = statement;
        changed.target[31] ^= 1;
        assert_eq!(
            changed.validate(),
            Err(CheckpointRandomXStatementError::InvalidTarget)
        );
        changed = statement;
        changed.randomx_hash = [0xff; 32];
        assert_eq!(
            changed.validate(),
            Err(CheckpointRandomXStatementError::InsufficientWork)
        );
        changed = statement;
        changed.seed_hash = [0; 32];
        assert_eq!(
            changed.validate(),
            Err(CheckpointRandomXStatementError::InvalidIdentity)
        );
    }

    #[test]
    fn checkpoint_randomx_statement_commitment_binds_all_relation_inputs() {
        let statement = randomx_statement();
        let expected = statement.commitment().unwrap();
        let mut variants = Vec::new();
        let mut changed = statement;
        changed.network_magic ^= 1;
        variants.push(changed);
        changed = statement;
        changed.chain_id[0] ^= 1;
        variants.push(changed);
        changed = statement;
        changed.seed_hash[0] ^= 1;
        variants.push(changed);
        changed = statement;
        changed.pow_preimage[CHECKPOINT_RANDOMX_PREIMAGE_BYTES - 1] ^= 1;
        variants.push(changed);
        changed = statement;
        changed.randomx_hash[31] ^= 2;
        variants.push(changed);
        for variant in variants {
            assert_ne!(variant.commitment().unwrap(), expected);
        }
    }

    #[cfg(feature = "host-reference")]
    #[test]
    fn portable_randomx_primitives_match_consensus_implementations() {
        for height in [0, 1, 2_047, 2_048, 4_095, 4_096, u32::MAX as u64, u64::MAX] {
            assert_eq!(
                checkpoint_randomx_seed_height(height),
                dom_pow::randomx_seed_height(height)
            );
        }
        let mut sample = 0x5553_444fu32;
        for _ in 0..100_000 {
            sample = sample.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            assert_eq!(
                checkpoint_compact_target(sample),
                dom_pow::CompactTarget(sample).to_target().ok()
            );
            let hash = sample.to_be_bytes().repeat(8).try_into().unwrap();
            let target = sample
                .rotate_left(13)
                .to_be_bytes()
                .repeat(8)
                .try_into()
                .unwrap();
            assert_eq!(
                checkpoint_hash_meets_target(&hash, &target),
                dom_pow::hash_meets_target(&hash, &target)
            );
        }
    }

    #[cfg(feature = "host-reference")]
    #[test]
    fn checkpoint_randomx_statement_is_derived_from_exact_parsed_header() {
        let mut candidate = block(15, commitment(2), commitment(3), Vec::new());
        candidate.header.target = CompactTarget(0x1e7f_ffff);
        let mut claimed = [0u8; 32];
        claimed[31] = 1;
        candidate.header.pow.randomx_hash = Hash256::from_bytes(claimed);
        let statement = checkpoint_randomx_statement_for_header(
            0xA1B2C3D4,
            [0x11; 32],
            [0x12; 32],
            &candidate.header,
        )
        .expect("header statement");
        assert_eq!(statement.block_height, candidate.header.height.0);
        assert_eq!(statement.seed_height, 0);
        assert_eq!(
            statement.pow_preimage.as_slice(),
            candidate.header.pow_preimage()
        );
        assert_eq!(statement.randomx_hash, claimed);

        let expected = statement.commitment().unwrap();
        candidate.header.pow.nonce += 1;
        let changed = checkpoint_randomx_statement_for_header(
            0xA1B2C3D4,
            [0x11; 32],
            [0x12; 32],
            &candidate.header,
        )
        .expect("changed header statement");
        assert_ne!(changed.commitment().unwrap(), expected);
        assert_eq!(
            checkpoint_randomx_statement_for_header(
                0xA1B2C3D4,
                [0x11; 32],
                [0; 32],
                &candidate.header,
            ),
            Err(CheckpointRandomXStatementError::InvalidIdentity)
        );
    }

    #[cfg(feature = "host-reference")]
    #[test]
    fn checkpoint_randomx_native_reference_matches_fixed_224_byte_vector() {
        let statement = randomx_relation_vector();
        verify_checkpoint_randomx_relation(&statement).expect("known-answer relation");

        let mut changed_hash = statement;
        changed_hash.randomx_hash[31] ^= 1;
        assert_eq!(
            verify_checkpoint_randomx_relation(&changed_hash),
            Err(CheckpointRandomXReferenceError::HashMismatch)
        );

        let mut changed_preimage = statement;
        changed_preimage.pow_preimage[CHECKPOINT_RANDOMX_PREIMAGE_BYTES - 1] ^= 1;
        assert_eq!(
            verify_checkpoint_randomx_relation(&changed_preimage),
            Err(CheckpointRandomXReferenceError::HashMismatch)
        );
    }

    #[cfg(feature = "host-reference")]
    #[test]
    fn checkpoint_randomx_native_reference_rejects_unproved_canonical_claim() {
        let statement = randomx_statement();
        let bytes = statement.to_bytes().expect("canonical statement");
        assert_eq!(
            execute_checkpoint_randomx_reference(&bytes),
            Err(CheckpointRandomXReferenceError::HashMismatch)
        );

        assert_eq!(
            execute_checkpoint_randomx_reference(&bytes[..bytes.len() - 1]),
            Err(CheckpointRandomXReferenceError::InvalidStatement(
                CheckpointRandomXStatementError::InvalidFraming
            ))
        );
    }

    fn segment_state() -> CheckpointSegmentState {
        let height = 1_000u64;
        let block_hash = [0x21; 32];
        let economic_utxo_root = [0x31; 32];
        let economic_kernel_root = [0x32; 32];
        let mut recent_headers = [ContextHeader {
            height: 0,
            block: [0; 32],
            timestamp: 0,
        }; CHECKPOINT_CONTEXT_HEADER_COUNT];
        for (index, header) in recent_headers.iter_mut().enumerate() {
            header.height = height - (CHECKPOINT_CONTEXT_HEADER_COUNT - 1 - index) as u64;
            header.block = [0x40 + index as u8; 32];
            header.timestamp = 1_700_000_000 + index as u64;
        }
        recent_headers[CHECKPOINT_CONTEXT_HEADER_COUNT - 1].block = block_hash;
        let context = CheckpointContext {
            checkpoint_height: height,
            checkpoint_block: block_hash,
            max_span: 390,
            economic_state_root: checkpoint_economic_state_root(
                economic_utxo_root,
                economic_kernel_root,
            )
            .expect("economic root"),
            recent_headers,
            seed_anchor_count: 0,
            seed_anchors: [SeedAnchor::default(); CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS],
        };
        CheckpointSegmentState {
            network_magic: 0xA1B2C3D4,
            chain_id: [0x11; 32],
            activation_schedule_commitment: [0x12; 32],
            checkpoint_config_hash: [0x13; 32],
            checkpoint_policy_hash: [0x14; 32],
            deposit_policy_hash: [0x15; 32],
            privacy_verifier_config_hash: [0x16; 32],
            randomx_receipt_image_id: [0x17; 32],
            height,
            block_hash,
            native_state_root: [0x22; 32],
            economic_utxo_root,
            economic_kernel_root,
            total_difficulty: [0x23; 32],
            context,
        }
    }

    fn segment_policy_input() -> CheckpointSegmentPolicyInput {
        CheckpointSegmentPolicyInput::new(
            [0x71; 32],
            [0x72; CHECKPOINT_SEGMENT_ACTIVATION_SCHEDULE_BYTES],
            [0x73; CHECKPOINT_SEGMENT_CHECKPOINT_POLICY_BYTES],
            [0x74; CHECKPOINT_SEGMENT_DEPOSIT_POLICY_BYTES],
            vec![0x75; 96],
        )
        .expect("segment policy input")
    }

    #[test]
    fn checkpoint_segment_policy_input_is_canonical_bounded_and_committed() {
        let input = segment_policy_input();
        let bytes = input.to_bytes().expect("encode policy input");
        assert_eq!(&bytes[..8], b"UDCSPOL1");
        assert_eq!(
            CheckpointSegmentPolicyInput::from_bytes(&bytes).unwrap(),
            input
        );
        assert_ne!(input.commitment().unwrap(), [0; 32]);
        for end in 0..bytes.len() {
            assert!(CheckpointSegmentPolicyInput::from_bytes(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(CheckpointSegmentPolicyInput::from_bytes(&trailing).is_err());
        for index in [0usize, 9, 11] {
            let mut malformed = bytes.clone();
            malformed[index] ^= 1;
            assert!(CheckpointSegmentPolicyInput::from_bytes(&malformed).is_err());
        }
        let mut changed = input.clone();
        changed.activation_schedule[0] ^= 1;
        assert_ne!(changed.commitment().unwrap(), input.commitment().unwrap());
        changed = input.clone();
        changed.checkpoint_policy[0] ^= 1;
        assert_ne!(changed.commitment().unwrap(), input.commitment().unwrap());
        changed = input.clone();
        changed.deposit_policy[0] ^= 1;
        assert_ne!(changed.commitment().unwrap(), input.commitment().unwrap());
        changed = input.clone();
        changed.spend_verifying_key[0] ^= 1;
        assert_ne!(changed.commitment().unwrap(), input.commitment().unwrap());
    }

    #[test]
    fn checkpoint_segment_policy_input_rejects_empty_zero_and_oversized_values() {
        let input = segment_policy_input();
        assert_eq!(
            CheckpointSegmentPolicyInput::new(
                [0; 32],
                input.activation_schedule,
                input.checkpoint_policy,
                input.deposit_policy,
                input.spend_verifying_key.clone(),
            ),
            Err(CheckpointSegmentPolicyInputError::InvalidIdentity)
        );
        assert_eq!(
            CheckpointSegmentPolicyInput::new(
                input.dom_genesis_hash,
                input.activation_schedule,
                input.checkpoint_policy,
                input.deposit_policy,
                Vec::new(),
            ),
            Err(CheckpointSegmentPolicyInputError::InvalidIdentity)
        );
        assert_eq!(
            CheckpointSegmentPolicyInput::new(
                input.dom_genesis_hash,
                input.activation_schedule,
                input.checkpoint_policy,
                input.deposit_policy,
                vec![0; MAX_CHECKPOINT_SEGMENT_SPEND_VERIFYING_KEY_BYTES + 1],
            ),
            Err(CheckpointSegmentPolicyInputError::InvalidIdentity)
        );
    }

    fn segment_transition() -> CheckpointSegmentTransition {
        let previous = segment_state();
        let block_count = 2u16;
        let mut next = previous;
        let shift = usize::from(block_count);
        next.context.recent_headers.rotate_left(shift);
        let first_new_height = previous.height + 1;
        let first_new_timestamp =
            previous.context.recent_headers[CHECKPOINT_CONTEXT_HEADER_COUNT - 1].timestamp + 1;
        for offset in 0..shift {
            let index = CHECKPOINT_CONTEXT_HEADER_COUNT - shift + offset;
            next.context.recent_headers[index] = ContextHeader {
                height: first_new_height + offset as u64,
                block: [0x80 + offset as u8; 32],
                timestamp: first_new_timestamp + offset as u64,
            };
        }
        next.height = previous.height + u64::from(block_count);
        next.block_hash = next.context.recent_headers[CHECKPOINT_CONTEXT_HEADER_COUNT - 1].block;
        next.native_state_root = [0x52; 32];
        next.economic_utxo_root = [0x53; 32];
        next.economic_kernel_root = [0x54; 32];
        next.total_difficulty = [0x55; 32];
        next.context.checkpoint_height = next.height;
        next.context.checkpoint_block = next.block_hash;
        next.context.economic_state_root =
            checkpoint_economic_state_root(next.economic_utxo_root, next.economic_kernel_root)
                .expect("next economic root");
        CheckpointSegmentTransition {
            block_count,
            private_input_commitment: [0x61; 32],
            previous,
            next,
        }
    }

    fn segment_randomx_statement(
        transition: &CheckpointSegmentTransition,
        block_height: u64,
    ) -> CheckpointRandomXStatement {
        let mut statement = randomx_statement();
        statement.network_magic = transition.previous.network_magic;
        statement.chain_id = transition.previous.chain_id;
        statement.block_height = block_height;
        statement.seed_height = checkpoint_randomx_seed_height(block_height);
        statement.pow_preimage[CHECKPOINT_RANDOMX_PREIMAGE_HEIGHT_OFFSET
            ..CHECKPOINT_RANDOMX_PREIMAGE_HEIGHT_OFFSET + 8]
            .copy_from_slice(&block_height.to_le_bytes());
        statement
    }

    fn segment_private_input() -> CheckpointSegmentPrivateInput {
        CheckpointSegmentPrivateInput::new(vec![
            CheckpointSegmentBlockInput::new(vec![1, 2], vec![3], vec![4, 5])
                .expect("first block input"),
            CheckpointSegmentBlockInput::new(vec![6], vec![7, 8], vec![9])
                .expect("second block input"),
        ])
        .expect("segment private input")
    }

    #[cfg(all(feature = "segment-bindings", not(feature = "host-reference")))]
    fn portable_segment_package(
        height: u64,
        parent: [u8; 32],
        timestamp: u64,
        claimed_work_last_byte: u8,
    ) -> Vec<u8> {
        let mut header = [0u8; CHECKPOINT_DOM_V4_HEADER_BYTES];
        header[..4].copy_from_slice(&CHECKPOINT_RANDOMX_BLOCK_VERSION.to_le_bytes());
        header[4..12].copy_from_slice(&height.to_le_bytes());
        header[12..44].copy_from_slice(&parent);
        header[44..52].copy_from_slice(&timestamp.to_le_bytes());
        header[180..184].copy_from_slice(&0x1e7f_ffffu32.to_le_bytes());
        header[216..224].copy_from_slice(&height.to_le_bytes());
        header[255] = claimed_work_last_byte;
        let mut envelope = Vec::with_capacity(CHECKPOINT_USDOM_V4_ENVELOPE_MIN_BYTES);
        envelope.extend_from_slice(CHECKPOINT_USDOM_V4_ENVELOPE_MAGIC);
        envelope.extend_from_slice(&CHECKPOINT_USDOM_V4_ENVELOPE_VERSION.to_be_bytes());
        envelope.extend_from_slice(&0u32.to_be_bytes());
        let mut package = Vec::with_capacity(
            CHECKPOINT_USDOM_V4_PACKAGE_HEADER_BYTES + header.len() + envelope.len(),
        );
        package.extend_from_slice(CHECKPOINT_USDOM_V4_PACKAGE_MAGIC);
        package.extend_from_slice(&CHECKPOINT_USDOM_V4_PACKAGE_VERSION.to_be_bytes());
        package.extend_from_slice(&(header.len() as u32).to_be_bytes());
        package.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
        package.extend_from_slice(&header);
        package.extend_from_slice(&envelope);
        package
    }

    #[cfg(all(feature = "segment-bindings", not(feature = "host-reference")))]
    fn portable_segment_binding_fixture() -> (
        CheckpointSegmentTransition,
        CheckpointSegmentPrivateInput,
        [u8; 32],
    ) {
        let genesis_hash = [0x71; 32];
        let mut previous = segment_state();
        previous.network_magic = dom_core::NETWORK_MAGIC_REGTEST;
        previous.chain_id = checkpoint_segment_chain_id(previous.network_magic, genesis_hash);
        let mut next = previous;
        let mut parent = previous.block_hash;
        let mut projections = previous.context.recent_headers.to_vec();
        let mut blocks = Vec::new();
        for offset in 0..2u8 {
            let height = previous.height + u64::from(offset) + 1;
            let timestamp = projections.last().expect("prior header").timestamp + 1;
            let package = portable_segment_package(height, parent, timestamp, offset + 1);
            let header = checkpoint_segment_header_projection(&package).expect("portable header");
            let block_hash = *dom_core::blake2b_256(&header.header_bytes).as_bytes();
            blocks.push(
                CheckpointSegmentBlockInput::new(package, vec![1], vec![1])
                    .expect("portable block input"),
            );
            projections.push(ContextHeader {
                height,
                block: block_hash,
                timestamp,
            });
            parent = block_hash;
        }
        next.height = previous.height + 2;
        next.block_hash = parent;
        next.native_state_root = [0x52; 32];
        next.economic_utxo_root = [0x53; 32];
        next.economic_kernel_root = [0x54; 32];
        next.total_difficulty = [0x55; 32];
        next.context.checkpoint_height = next.height;
        next.context.checkpoint_block = next.block_hash;
        next.context.economic_state_root =
            checkpoint_economic_state_root(next.economic_utxo_root, next.economic_kernel_root)
                .expect("next economic root");
        next.context
            .recent_headers
            .copy_from_slice(&projections[projections.len() - CHECKPOINT_CONTEXT_HEADER_COUNT..]);
        let input = CheckpointSegmentPrivateInput::new(blocks).expect("portable input");
        let transition = input
            .transition_statement(previous, next)
            .expect("portable transition");
        (transition, input, genesis_hash)
    }

    #[cfg(feature = "host-reference")]
    fn segment_randomx_binding_fixture_at(
        previous_height: u64,
    ) -> (
        CheckpointSegmentTransition,
        CheckpointSegmentPrivateInput,
        [u8; 32],
    ) {
        let genesis_hash = [0x71; 32];
        let mut previous = segment_state();
        previous.height = previous_height;
        previous.context.checkpoint_height = previous_height;
        for (index, header) in previous.context.recent_headers.iter_mut().enumerate() {
            header.height = previous_height - (CHECKPOINT_CONTEXT_HEADER_COUNT - 1 - index) as u64;
            header.block = [0x40 + index as u8; 32];
            header.timestamp = 1_700_000_000 + index as u64;
        }
        previous.block_hash =
            previous.context.recent_headers[CHECKPOINT_CONTEXT_HEADER_COUNT - 1].block;
        previous.context.checkpoint_block = previous.block_hash;
        let required_seeds = dom_usdom_checkpoint_statement::required_historical_seed_heights(
            previous_height,
            previous.context.max_span,
        )
        .expect("required seed schedule");
        previous.context.seed_anchor_count = u8::try_from(required_seeds.len()).unwrap();
        previous.context.seed_anchors =
            [SeedAnchor::default(); CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS];
        for (index, height) in required_seeds.into_iter().enumerate() {
            previous.context.seed_anchors[index] = SeedAnchor {
                height,
                block: [0x90 + index as u8; 32],
            };
        }
        previous.network_magic = dom_core::NETWORK_MAGIC_REGTEST;
        previous.chain_id =
            *derive_chain_id(previous.network_magic, &Hash256::from_bytes(genesis_hash)).as_bytes();
        let mut next = previous;
        let empty_economic = EconomicState::from_entries(
            std::iter::empty::<([u8; 33], EconomicUtxo)>(),
            std::iter::empty::<[u8; 33]>(),
        )
        .expect("empty economic state");
        let native = UsdomV2ExecutionWitnesses::new(Vec::new())
            .expect("empty native witness")
            .to_bytes()
            .expect("native witness bytes");
        let mut parent = Hash256::from_bytes(previous.block_hash);
        let mut projections = previous.context.recent_headers.to_vec();
        let mut block_inputs = Vec::new();
        for offset in 0..2u8 {
            let height = previous.height + u64::from(offset) + 1;
            let mut candidate = block(
                height,
                commitment(10 + offset * 2),
                commitment(11 + offset * 2),
                Vec::new(),
            );
            candidate.header.prev_hash = parent;
            candidate.header.target = CompactTarget(0x1e7f_ffff);
            let mut claimed_work = [0u8; 32];
            claimed_work[31] = u8::saturating_add(offset, 1);
            candidate.header.pow.randomx_hash = Hash256::from_bytes(claimed_work);
            let header_bytes = DomSerialize::to_bytes(&candidate.header).expect("header bytes");
            let block_hash = canonical_header_identifier(previous.network_magic, &header_bytes)
                .expect("canonical block identifier");
            let economic = EconomicBlockWitness::from_state(&empty_economic, &candidate)
                .expect("economic witness")
                .to_bytes()
                .expect("economic witness bytes");
            let package =
                UsdomV4BlockPackage::new(candidate.clone(), UsdomV4ProofEnvelope::empty())
                    .expect("block package")
                    .to_bytes()
                    .expect("block package bytes");
            block_inputs.push(
                CheckpointSegmentBlockInput::new(package, native.clone(), economic)
                    .expect("segment block input"),
            );
            projections.push(ContextHeader {
                height,
                block: *block_hash.as_bytes(),
                timestamp: candidate.header.timestamp.0,
            });
            parent = block_hash;
        }

        next.height = previous.height + 2;
        next.block_hash = *parent.as_bytes();
        next.native_state_root = [0x52; 32];
        next.economic_utxo_root = [0x53; 32];
        next.economic_kernel_root = [0x54; 32];
        next.total_difficulty = [0x55; 32];
        next.context.checkpoint_height = next.height;
        next.context.checkpoint_block = next.block_hash;
        next.context.economic_state_root =
            checkpoint_economic_state_root(next.economic_utxo_root, next.economic_kernel_root)
                .expect("next economic root");
        next.context
            .recent_headers
            .copy_from_slice(&projections[projections.len() - CHECKPOINT_CONTEXT_HEADER_COUNT..]);

        let input =
            CheckpointSegmentPrivateInput::new(block_inputs).expect("typed segment private input");
        let transition = input
            .transition_statement(previous, next)
            .expect("typed segment transition");
        (transition, input, genesis_hash)
    }

    #[cfg(feature = "host-reference")]
    fn segment_randomx_binding_fixture() -> (
        CheckpointSegmentTransition,
        CheckpointSegmentPrivateInput,
        [u8; 32],
    ) {
        segment_randomx_binding_fixture_at(1_000)
    }

    #[test]
    fn checkpoint_segment_state_is_exact_canonical_and_bounded() {
        let state = segment_state();
        let bytes = state.to_bytes().expect("encode");
        assert_eq!(bytes.len(), CHECKPOINT_SEGMENT_STATE_BYTES);
        assert_eq!(&bytes[..8], b"UDCSEG02");
        assert_eq!(&bytes[210..242], &state.randomx_receipt_image_id);
        assert_eq!(CheckpointSegmentState::from_bytes(&bytes).unwrap(), state);
        assert_ne!(state.commitment().unwrap(), [0; 32]);
        for end in 0..CHECKPOINT_SEGMENT_STATE_BYTES {
            assert!(CheckpointSegmentState::from_bytes(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(CheckpointSegmentState::from_bytes(&trailing).is_err());
        for index in [0usize, 9, 11, 13] {
            let mut malformed = bytes;
            malformed[index] ^= 1;
            assert!(CheckpointSegmentState::from_bytes(&malformed).is_err());
        }
        let mut legacy = bytes;
        legacy[..8].copy_from_slice(b"UDCSEG01");
        assert_eq!(
            CheckpointSegmentState::from_bytes(&legacy),
            Err(CheckpointSegmentStateError::InvalidFraming)
        );
    }

    #[test]
    fn checkpoint_segment_state_rejects_context_substitution_and_zero_identity() {
        let state = segment_state();
        let mut changed = state;
        changed.block_hash[0] ^= 1;
        assert_eq!(
            changed.validate(),
            Err(CheckpointSegmentStateError::ContextMismatch)
        );
        changed = state;
        changed.economic_utxo_root[0] ^= 1;
        assert_eq!(
            changed.validate(),
            Err(CheckpointSegmentStateError::ContextMismatch)
        );
        changed = state;
        changed.context.recent_headers[1].timestamp = changed.context.recent_headers[0].timestamp;
        assert_eq!(
            changed.validate(),
            Err(CheckpointSegmentStateError::ContextMismatch)
        );
        changed = state;
        changed.checkpoint_policy_hash = [0; 32];
        assert_eq!(
            changed.validate(),
            Err(CheckpointSegmentStateError::InvalidIdentity)
        );
        changed = state;
        changed.randomx_receipt_image_id = [0; 32];
        assert_eq!(
            changed.validate(),
            Err(CheckpointSegmentStateError::InvalidIdentity)
        );
    }

    #[test]
    fn checkpoint_segment_commitment_binds_policy_state_work_and_context() {
        let state = segment_state();
        let expected = state.commitment().unwrap();
        let mut variants = Vec::new();
        let mut changed = state;
        changed.network_magic ^= 1;
        variants.push(changed);
        changed = state;
        changed.chain_id[0] ^= 1;
        variants.push(changed);
        changed = state;
        changed.activation_schedule_commitment[0] ^= 1;
        variants.push(changed);
        changed = state;
        changed.checkpoint_config_hash[0] ^= 1;
        variants.push(changed);
        changed = state;
        changed.checkpoint_policy_hash[0] ^= 1;
        variants.push(changed);
        changed = state;
        changed.deposit_policy_hash[0] ^= 1;
        variants.push(changed);
        changed = state;
        changed.privacy_verifier_config_hash[0] ^= 1;
        variants.push(changed);
        changed = state;
        changed.randomx_receipt_image_id[0] ^= 1;
        variants.push(changed);
        changed = state;
        changed.native_state_root[0] ^= 1;
        variants.push(changed);
        changed = state;
        changed.total_difficulty[0] ^= 1;
        variants.push(changed);
        changed = state;
        changed.context.recent_headers[0].timestamp -= 1;
        variants.push(changed);
        for variant in variants {
            assert_ne!(variant.commitment().unwrap(), expected);
        }
    }

    #[test]
    fn checkpoint_randomx_receipt_assumption_is_policy_bound() {
        let transition = segment_transition();
        let statement = segment_randomx_statement(&transition, transition.previous.height + 1);
        let assumption =
            checkpoint_randomx_receipt_assumption_for_transition(&transition, &statement).unwrap();
        assert_eq!(
            assumption.image_id(),
            &transition.previous.randomx_receipt_image_id
        );
        assert_eq!(assumption.journal(), &statement.commitment().unwrap());

        let mut other_chain = statement;
        other_chain.chain_id[0] ^= 1;
        assert_eq!(
            checkpoint_randomx_receipt_assumption_for_transition(&transition, &other_chain),
            Err(CheckpointRandomXReceiptAssumptionError::IdentityMismatch)
        );

        let mut other_network = statement;
        other_network.network_magic ^= 1;
        assert_eq!(
            checkpoint_randomx_receipt_assumption_for_transition(&transition, &other_network),
            Err(CheckpointRandomXReceiptAssumptionError::IdentityMismatch)
        );

        let before = segment_randomx_statement(&transition, transition.previous.height);
        assert_eq!(
            checkpoint_randomx_receipt_assumption_for_transition(&transition, &before),
            Err(CheckpointRandomXReceiptAssumptionError::HeightMismatch)
        );
        let after = segment_randomx_statement(&transition, transition.next.height + 1);
        assert_eq!(
            checkpoint_randomx_receipt_assumption_for_transition(&transition, &after),
            Err(CheckpointRandomXReceiptAssumptionError::HeightMismatch)
        );

        let mut invalid_statement = statement;
        invalid_statement.seed_hash = [0; 32];
        assert_eq!(
            checkpoint_randomx_receipt_assumption_for_transition(&transition, &invalid_statement),
            Err(CheckpointRandomXReceiptAssumptionError::InvalidStatement)
        );
        let mut invalid_transition = transition;
        invalid_transition.private_input_commitment = [0; 32];
        assert_eq!(
            checkpoint_randomx_receipt_assumption_for_transition(&invalid_transition, &statement),
            Err(CheckpointRandomXReceiptAssumptionError::InvalidTransition)
        );
    }

    #[cfg(feature = "host-reference")]
    #[test]
    fn checkpoint_segment_randomx_bindings_are_derived_in_exact_package_order() {
        let (transition, input, genesis_hash) = segment_randomx_binding_fixture();
        let bindings = checkpoint_segment_randomx_bindings(&transition, &input, genesis_hash)
            .expect("ordered RandomX bindings");
        let (aggregate, aggregate_bindings) =
            checkpoint_segment_randomx_aggregate(&transition, &input, genesis_hash)
                .expect("ordered RandomX aggregate");
        assert_eq!(aggregate_bindings, bindings);
        assert_eq!(aggregate.block_count(), transition.block_count);
        assert_eq!(
            aggregate.transition_commitment(),
            &transition.commitment().expect("transition commitment")
        );
        assert_ne!(
            aggregate.commitment().unwrap(),
            transition.commitment().unwrap()
        );
        assert_eq!(bindings.len(), usize::from(transition.block_count));
        assert_eq!(
            bindings[0].statement().block_height,
            transition.previous.height + 1
        );
        assert_eq!(bindings[1].statement().block_height, transition.next.height);
        assert_eq!(bindings[0].statement().seed_hash, genesis_hash);
        assert_eq!(bindings[1].statement().seed_hash, genesis_hash);
        assert_eq!(bindings[1].block_hash(), &transition.next.block_hash);
        for (index, binding) in bindings.iter().enumerate() {
            let package = UsdomV4BlockPackage::from_bytes(input.blocks()[index].package_bytes())
                .expect("typed package");
            let typed_statement = checkpoint_randomx_statement_for_header(
                transition.previous.network_magic,
                transition.previous.chain_id,
                genesis_hash,
                &package.block().header,
            )
            .expect("typed header statement");
            assert_eq!(binding.statement(), &typed_statement);
            assert_eq!(
                binding.assumption().image_id(),
                &transition.previous.randomx_receipt_image_id
            );
            assert_eq!(
                binding.assumption().journal(),
                &binding
                    .statement()
                    .commitment()
                    .expect("statement commitment")
            );
        }
        assert_ne!(
            bindings[0].assumption().journal(),
            bindings[1].assumption().journal()
        );
    }

    #[cfg(feature = "host-reference")]
    #[test]
    fn checkpoint_segment_randomx_bindings_use_authenticated_epoch_seed_anchor() {
        let (transition, input, genesis_hash) = segment_randomx_binding_fixture_at(2_047);
        assert_eq!(transition.previous.context.seed_anchor_count, 1);
        assert_eq!(transition.previous.context.seed_anchors[0].height, 1_984);
        let authenticated_seed = transition.previous.context.seed_anchors[0].block;
        let bindings = checkpoint_segment_randomx_bindings(&transition, &input, genesis_hash)
            .expect("epoch-bound RandomX bindings");
        assert_eq!(bindings[0].statement().block_height, 2_048);
        assert_eq!(bindings[0].statement().seed_height, 1_984);
        assert_eq!(bindings[0].statement().seed_hash, authenticated_seed);
        assert_eq!(bindings[1].statement().seed_hash, authenticated_seed);
    }

    #[cfg(feature = "host-reference")]
    #[test]
    fn checkpoint_segment_randomx_bindings_reject_substitution_reorder_and_reuse() {
        let (transition, input, genesis_hash) = segment_randomx_binding_fixture();
        let mut wrong_genesis = genesis_hash;
        wrong_genesis[0] ^= 1;
        assert_eq!(
            checkpoint_segment_randomx_bindings(&transition, &input, wrong_genesis),
            Err(CheckpointSegmentRandomXBindingError::GenesisIdentityMismatch)
        );

        let swapped = CheckpointSegmentPrivateInput::new(vec![
            input.blocks()[1].clone(),
            input.blocks()[0].clone(),
        ])
        .expect("swapped bounded input");
        assert_eq!(
            checkpoint_segment_randomx_bindings(&transition, &swapped, genesis_hash),
            Err(CheckpointSegmentRandomXBindingError::PrivateInputMismatch)
        );
        let swapped_transition = swapped
            .transition_statement(transition.previous, transition.next)
            .expect("swapped transition statement");
        assert_eq!(
            checkpoint_segment_randomx_bindings(&swapped_transition, &swapped, genesis_hash),
            Err(CheckpointSegmentRandomXBindingError::InvalidBlockSequence)
        );

        let duplicated = CheckpointSegmentPrivateInput::new(vec![
            input.blocks()[0].clone(),
            input.blocks()[0].clone(),
        ])
        .expect("duplicated bounded input");
        let duplicated_transition = duplicated
            .transition_statement(transition.previous, transition.next)
            .expect("duplicated transition statement");
        assert_eq!(
            checkpoint_segment_randomx_bindings(&duplicated_transition, &duplicated, genesis_hash,),
            Err(CheckpointSegmentRandomXBindingError::InvalidBlockSequence)
        );
    }

    #[cfg(feature = "host-reference")]
    #[test]
    fn checkpoint_segment_randomx_bindings_reject_forged_next_context() {
        let (transition, input, genesis_hash) = segment_randomx_binding_fixture();
        let mut forged_next = transition.next;
        forged_next.context.recent_headers[0].block[0] ^= 1;
        let forged_transition = input
            .transition_statement(transition.previous, forged_next)
            .expect("otherwise canonical forged context");
        assert_eq!(
            checkpoint_segment_randomx_bindings(&forged_transition, &input, genesis_hash),
            Err(CheckpointSegmentRandomXBindingError::ContextMismatch)
        );

        let mut changed_span = transition.next;
        changed_span.context.max_span -= 1;
        let changed_span_transition = input
            .transition_statement(transition.previous, changed_span)
            .expect("otherwise canonical span change");
        assert_eq!(
            checkpoint_segment_randomx_bindings(&changed_span_transition, &input, genesis_hash),
            Err(CheckpointSegmentRandomXBindingError::ContextMismatch)
        );
    }

    #[cfg(all(feature = "segment-bindings", not(feature = "host-reference")))]
    #[test]
    fn portable_segment_bindings_need_no_host_consensus_or_randomx_runtime() {
        let (transition, input, genesis_hash) = portable_segment_binding_fixture();
        let bindings = checkpoint_segment_randomx_bindings(&transition, &input, genesis_hash)
            .expect("portable ordered bindings");
        let (aggregate, aggregate_bindings) =
            checkpoint_segment_randomx_aggregate(&transition, &input, genesis_hash)
                .expect("portable aggregate");
        assert_eq!(aggregate_bindings, bindings);
        let aggregate_bytes = aggregate.to_bytes();
        assert_eq!(
            hex::encode(aggregate_bytes),
            "554443525841473100010002be10c21b571fc2acfd24e41205a0b8253a881414db3f1f5c32fad78152858a3a662c3e5e0f920e1ef69897393541874e54995a28d87268c671c978ac508c6abe"
        );
        assert_eq!(
            hex::encode(aggregate.commitment().unwrap()),
            "072c4e89c548038b9bcbd590bd9c861ac3a67a76c65885db67949469f45df961"
        );
        assert_eq!(aggregate_bytes.len(), CHECKPOINT_RANDOMX_AGGREGATE_BYTES);
        assert_eq!(&aggregate_bytes[..8], b"UDCRXAG1");
        assert_eq!(
            CheckpointSegmentRandomXAggregate::from_bytes(&aggregate_bytes).unwrap(),
            aggregate
        );
        assert_ne!(
            aggregate.commitment().unwrap(),
            transition.commitment().unwrap()
        );
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].statement().block_height, 1_001);
        assert_eq!(bindings[1].statement().block_height, 1_002);
        assert_eq!(bindings[0].statement().seed_hash, genesis_hash);
        assert_eq!(bindings[1].block_hash(), &transition.next.block_hash);

        for index in [0usize, 9] {
            let mut changed = aggregate_bytes;
            changed[index] ^= 1;
            assert!(CheckpointSegmentRandomXAggregate::from_bytes(&changed).is_err());
        }
        let mut zero_count = aggregate_bytes;
        zero_count[10..12].fill(0);
        assert_eq!(
            CheckpointSegmentRandomXAggregate::from_bytes(&zero_count),
            Err(CheckpointSegmentRandomXAggregateError::InvalidCount)
        );
        let mut zero_commitment = aggregate_bytes;
        zero_commitment[12..44].fill(0);
        assert_eq!(
            CheckpointSegmentRandomXAggregate::from_bytes(&zero_commitment),
            Err(CheckpointSegmentRandomXAggregateError::InvalidCommitment)
        );
        let mut substituted = aggregate_bytes;
        substituted[20] ^= 1;
        let substituted = CheckpointSegmentRandomXAggregate::from_bytes(&substituted).unwrap();
        assert_ne!(
            substituted.commitment().unwrap(),
            aggregate.commitment().unwrap()
        );
        let mut trailing = aggregate_bytes.to_vec();
        trailing.push(0);
        assert_eq!(
            CheckpointSegmentRandomXAggregate::from_bytes(&trailing),
            Err(CheckpointSegmentRandomXAggregateError::InvalidFraming)
        );
    }

    #[cfg(all(feature = "segment-bindings", not(feature = "host-reference")))]
    #[test]
    fn portable_segment_bindings_reject_malformed_envelope_and_parent() {
        let (transition, input, genesis_hash) = portable_segment_binding_fixture();
        let mut malformed_blocks = input.blocks().to_vec();
        let mut malformed_package = malformed_blocks[0].package_bytes().to_vec();
        let proof_start = CHECKPOINT_USDOM_V4_PACKAGE_HEADER_BYTES + CHECKPOINT_DOM_V4_HEADER_BYTES;
        malformed_package[proof_start] ^= 1;
        malformed_blocks[0] =
            CheckpointSegmentBlockInput::new(malformed_package, vec![1], vec![1]).unwrap();
        let malformed = CheckpointSegmentPrivateInput::new(malformed_blocks).unwrap();
        let malformed_transition = malformed
            .transition_statement(transition.previous, transition.next)
            .unwrap();
        assert_eq!(
            checkpoint_segment_randomx_bindings(&malformed_transition, &malformed, genesis_hash,),
            Err(CheckpointSegmentRandomXBindingError::InvalidPackage)
        );

        let mut unlinked_blocks = input.blocks().to_vec();
        let mut unlinked_package = unlinked_blocks[1].package_bytes().to_vec();
        let parent_offset = CHECKPOINT_USDOM_V4_PACKAGE_HEADER_BYTES + 12;
        unlinked_package[parent_offset] ^= 1;
        unlinked_blocks[1] =
            CheckpointSegmentBlockInput::new(unlinked_package, vec![1], vec![1]).unwrap();
        let unlinked = CheckpointSegmentPrivateInput::new(unlinked_blocks).unwrap();
        let unlinked_transition = unlinked
            .transition_statement(transition.previous, transition.next)
            .unwrap();
        assert_eq!(
            checkpoint_segment_randomx_bindings(&unlinked_transition, &unlinked, genesis_hash,),
            Err(CheckpointSegmentRandomXBindingError::InvalidBlockSequence)
        );
    }

    #[cfg(feature = "risc0-recursion")]
    #[test]
    fn checkpoint_randomx_receipt_image_id_preserves_exact_byte_order() {
        let mut image_id = [0u8; 32];
        for (index, byte) in image_id.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap();
        }
        let mut transition = segment_transition();
        transition.previous.randomx_receipt_image_id = image_id;
        transition.next.randomx_receipt_image_id = image_id;
        let statement = segment_randomx_statement(&transition, transition.previous.height + 1);
        let assumption =
            checkpoint_randomx_receipt_assumption_for_transition(&transition, &statement).unwrap();
        let digest = checkpoint_randomx_receipt_image_id_digest(&assumption);
        assert_eq!(digest.as_bytes(), image_id.as_slice());
        assert_eq!(
            digest.to_string(),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        assert_eq!(digest.as_words()[0], u32::from_ne_bytes([0, 1, 2, 3]));
    }

    #[test]
    fn checkpoint_segment_transition_is_exact_canonical_and_bounded() {
        let transition = segment_transition();
        let bytes = transition.to_bytes().expect("encode");
        assert_eq!(bytes.len(), CHECKPOINT_SEGMENT_TRANSITION_BYTES);
        assert_eq!(&bytes[..8], b"UDCSTN02");
        assert_eq!(
            CheckpointSegmentTransition::from_bytes(&bytes).unwrap(),
            transition
        );
        assert_ne!(transition.commitment().unwrap(), [0; 32]);
        for end in 0..CHECKPOINT_SEGMENT_TRANSITION_BYTES {
            assert!(CheckpointSegmentTransition::from_bytes(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(CheckpointSegmentTransition::from_bytes(&trailing).is_err());
        for index in [0usize, 9] {
            let mut malformed = bytes;
            malformed[index] ^= 1;
            assert!(CheckpointSegmentTransition::from_bytes(&malformed).is_err());
        }
        let mut legacy = bytes;
        legacy[..8].copy_from_slice(b"UDCSTN01");
        assert_eq!(
            CheckpointSegmentTransition::from_bytes(&legacy),
            Err(CheckpointSegmentTransitionError::InvalidFraming)
        );
    }

    #[test]
    fn checkpoint_segment_transition_rejects_discontinuity_and_policy_change() {
        let transition = segment_transition();
        let mut changed = transition;
        changed.block_count = 0;
        assert_eq!(
            changed.validate(),
            Err(CheckpointSegmentTransitionError::InvalidSpan)
        );
        changed = transition;
        changed.block_count = MAX_CHECKPOINT_SEGMENT_BLOCKS + 1;
        assert_eq!(
            changed.validate(),
            Err(CheckpointSegmentTransitionError::InvalidSpan)
        );
        changed = transition;
        changed.block_count -= 1;
        assert_eq!(
            changed.validate(),
            Err(CheckpointSegmentTransitionError::InvalidSpan)
        );
        changed = transition;
        changed.next.total_difficulty = transition.previous.total_difficulty;
        assert_eq!(
            changed.validate(),
            Err(CheckpointSegmentTransitionError::InvalidWork)
        );
        changed = transition;
        changed.next.checkpoint_policy_hash[0] ^= 1;
        assert_eq!(
            changed.validate(),
            Err(CheckpointSegmentTransitionError::IdentityChanged)
        );
        changed = transition;
        changed.next.randomx_receipt_image_id[0] ^= 1;
        assert_eq!(
            changed.validate(),
            Err(CheckpointSegmentTransitionError::IdentityChanged)
        );
        changed = transition;
        changed.private_input_commitment = [0; 32];
        assert_eq!(
            changed.validate(),
            Err(CheckpointSegmentTransitionError::InvalidPrivateInput)
        );
    }

    #[test]
    fn checkpoint_segment_transition_commitment_binds_endpoints_span_and_input() {
        let transition = segment_transition();
        let expected = transition.commitment().unwrap();
        let mut changed = transition;
        changed.private_input_commitment[0] ^= 1;
        assert_ne!(changed.commitment().unwrap(), expected);
        changed = transition;
        changed.previous.native_state_root[0] ^= 1;
        assert_ne!(changed.commitment().unwrap(), expected);
        changed = transition;
        changed.next.native_state_root[0] ^= 1;
        assert_ne!(changed.commitment().unwrap(), expected);
    }

    #[test]
    fn checkpoint_segment_private_input_is_canonical_bounded_and_committed() {
        let input = segment_private_input();
        let bytes = input.to_bytes().expect("encode");
        assert!(bytes.len() < MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES);
        assert_eq!(
            CheckpointSegmentPrivateInput::from_bytes(&bytes).unwrap(),
            input
        );
        assert_ne!(input.commitment().unwrap(), [0; 32]);
        for end in 0..bytes.len() {
            assert!(CheckpointSegmentPrivateInput::from_bytes(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(CheckpointSegmentPrivateInput::from_bytes(&trailing).is_err());
        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            CheckpointSegmentPrivateInput::from_bytes(&bad_magic),
            Err(CheckpointSegmentPrivateInputError::InvalidFraming)
        );
        let mut oversized_component = bytes;
        oversized_component[12..16].copy_from_slice(
            &u32::try_from(MAX_CHECKPOINT_SEGMENT_PACKAGE_BYTES + 1)
                .unwrap()
                .to_be_bytes(),
        );
        assert_eq!(
            CheckpointSegmentPrivateInput::from_bytes(&oversized_component),
            Err(CheckpointSegmentPrivateInputError::InvalidComponent)
        );
    }

    #[test]
    fn checkpoint_segment_private_input_rejects_invalid_count_and_empty_components() {
        assert_eq!(
            CheckpointSegmentPrivateInput::new(Vec::new()),
            Err(CheckpointSegmentPrivateInputError::InvalidBlockCount)
        );
        let block = CheckpointSegmentBlockInput::new(vec![1], vec![2], vec![3]).unwrap();
        assert_eq!(
            CheckpointSegmentPrivateInput::new(vec![
                block;
                usize::from(MAX_CHECKPOINT_SEGMENT_BLOCKS) + 1
            ]),
            Err(CheckpointSegmentPrivateInputError::InvalidBlockCount)
        );
        assert_eq!(
            CheckpointSegmentBlockInput::new(Vec::new(), vec![1], vec![2]),
            Err(CheckpointSegmentPrivateInputError::InvalidComponent)
        );
    }

    #[test]
    fn checkpoint_segment_private_input_constructs_exact_transition_statement() {
        let input = segment_private_input();
        let expected_commitment = input.commitment().unwrap();
        let expected = segment_transition();
        let statement = input
            .transition_statement(expected.previous, expected.next)
            .expect("transition statement");
        assert_eq!(statement.block_count, 2);
        assert_eq!(statement.private_input_commitment, expected_commitment);
        assert_eq!(statement.previous, expected.previous);
        assert_eq!(statement.next, expected.next);
    }

    #[cfg(feature = "host-reference")]
    #[test]
    fn checkpoint_segment_private_input_parses_all_consensus_components() {
        let candidate = block(15, commitment(2), commitment(3), Vec::new());
        let state = EconomicState::from_entries(
            std::iter::empty::<([u8; 33], EconomicUtxo)>(),
            std::iter::empty::<[u8; 33]>(),
        )
        .expect("empty economic state");
        let economic = EconomicBlockWitness::from_state(&state, &candidate)
            .expect("economic witness")
            .to_bytes()
            .expect("economic bytes");
        let package = UsdomV4BlockPackage::new(candidate, UsdomV4ProofEnvelope::empty())
            .expect("package")
            .to_bytes()
            .expect("package bytes");
        let native = UsdomV2ExecutionWitnesses::new(Vec::new())
            .expect("native witness bundle")
            .to_bytes()
            .expect("native bytes");
        let input = CheckpointSegmentPrivateInput::new(vec![CheckpointSegmentBlockInput::new(
            package, native, economic,
        )
        .expect("block input")])
        .expect("private input");
        input
            .validate_typed_components()
            .expect("typed component validation");

        let malformed = CheckpointSegmentPrivateInput::new(vec![CheckpointSegmentBlockInput::new(
            vec![1],
            vec![2],
            vec![3],
        )
        .unwrap()])
        .unwrap();
        assert_eq!(
            malformed.validate_typed_components(),
            Err(CheckpointSegmentPrivateInputError::InvalidComponent)
        );
    }

    #[cfg(feature = "host-reference")]
    fn commitment(seed: u8) -> Commitment {
        let mut scalar = [0u8; 32];
        scalar[31] = seed;
        Commitment::commit(0, &BlindingFactor::from_bytes(scalar).expect("test scalar"))
    }

    #[cfg(feature = "host-reference")]
    fn commitment_index(seed: u16) -> Commitment {
        let mut scalar = [0u8; 32];
        scalar[30..].copy_from_slice(&seed.to_be_bytes());
        Commitment::commit(0, &BlindingFactor::from_bytes(scalar).expect("test scalar"))
    }

    #[cfg(feature = "host-reference")]
    fn block(
        height: u64,
        coinbase_output: Commitment,
        coinbase_excess: Commitment,
        transactions: Vec<Transaction>,
    ) -> Block {
        Block {
            header: BlockHeader {
                version: 4,
                height: BlockHeight(height),
                prev_hash: Hash256::from_bytes([1; 32]),
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
                    commitment: coinbase_output,
                    proof: Vec::new(),
                },
                kernel: CoinbaseKernel {
                    features: 1,
                    explicit_value: 0,
                    excess: coinbase_excess,
                    excess_signature: [0; 65],
                },
                offset: [0; 32],
            },
            transactions,
        }
    }

    #[test]
    fn roots_are_deterministic_ordered_and_bind_maturity_metadata() {
        let a = EconomicState::from_entries(
            [
                (
                    key(1),
                    EconomicUtxo {
                        created_height: 8,
                        is_coinbase: true,
                    },
                ),
                (
                    key(2),
                    EconomicUtxo {
                        created_height: 9,
                        is_coinbase: false,
                    },
                ),
            ],
            [key(3), key(4)],
        )
        .expect("state");
        let b = EconomicState::from_entries(
            [
                (
                    key(2),
                    EconomicUtxo {
                        created_height: 9,
                        is_coinbase: false,
                    },
                ),
                (
                    key(1),
                    EconomicUtxo {
                        created_height: 8,
                        is_coinbase: true,
                    },
                ),
            ],
            [key(4), key(3)],
        )
        .expect("reordered state");
        assert_eq!(a, b);
        assert_eq!(
            a.context_root().expect("root"),
            b.context_root().expect("root")
        );
        assert_eq!(
            hex::encode(a.context_root().expect("vector root")),
            "c170632c857afe2a93f69cb508edb32a2a36e90598c4d765dd17e2aa08305519"
        );
        let changed = EconomicState::from_entries(
            [
                (
                    key(1),
                    EconomicUtxo {
                        created_height: 9,
                        is_coinbase: true,
                    },
                ),
                (
                    key(2),
                    EconomicUtxo {
                        created_height: 9,
                        is_coinbase: false,
                    },
                ),
            ],
            [key(3), key(4)],
        )
        .expect("changed state");
        assert_ne!(
            a.context_root().expect("root"),
            changed.context_root().expect("changed")
        );
    }

    #[test]
    fn snapshots_reject_zero_and_duplicate_keys() {
        assert_eq!(
            EconomicState::from_entries(
                [(
                    [0; 33],
                    EconomicUtxo {
                        created_height: 1,
                        is_coinbase: false
                    }
                )],
                [],
            ),
            Err(EconomicStateError::InvalidSnapshot)
        );
        assert_eq!(
            EconomicState::from_entries(
                std::iter::empty::<([u8; 33], EconomicUtxo)>(),
                [key(7), key(7)],
            ),
            Err(EconomicStateError::InvalidSnapshot)
        );
    }

    #[test]
    fn compressed_economic_paths_open_and_update_both_trees() {
        let mut state = EconomicState::from_entries(
            [
                (
                    key(1),
                    EconomicUtxo {
                        created_height: 8,
                        is_coinbase: true,
                    },
                ),
                (
                    key(2),
                    EconomicUtxo {
                        created_height: 9,
                        is_coinbase: false,
                    },
                ),
            ],
            [key(3), key(4)],
        )
        .expect("state");
        let utxo_root = state.utxo_set_root().expect("utxo root");
        let membership = EconomicPathProof::from_state(&state, true, key(1)).expect("membership");
        assert_eq!(
            membership
                .utxo_root(Some(EconomicUtxo {
                    created_height: 8,
                    is_coinbase: true,
                }))
                .expect("open"),
            utxo_root
        );
        let absent = EconomicPathProof::from_state(&state, true, key(9)).expect("absence");
        assert_eq!(absent.utxo_root(None).expect("empty open"), utxo_root);
        let inserted = EconomicUtxo {
            created_height: 10,
            is_coinbase: false,
        };
        let updated = absent
            .update_utxo_root(utxo_root, None, Some(inserted))
            .expect("insert");
        state.utxos.insert(key(9), inserted);
        assert_eq!(updated, state.utxo_set_root().expect("full insert"));

        let kernel_root = state.kernel_set_root().expect("kernel root");
        let kernel = EconomicPathProof::from_state(&state, false, key(3)).expect("kernel proof");
        assert_eq!(kernel.kernel_root(true).expect("kernel open"), kernel_root);
        let deleted = kernel
            .update_kernel_root(kernel_root, true, false)
            .expect("kernel delete");
        state.kernels.remove(&key(3));
        assert_eq!(deleted, state.kernel_set_root().expect("full delete"));
    }

    #[test]
    fn economic_path_encoding_is_unique_bounded_and_frozen() {
        let state = EconomicState::from_entries(
            [(
                key(1),
                EconomicUtxo {
                    created_height: 8,
                    is_coinbase: true,
                },
            )],
            [key(3), key(4)],
        )
        .expect("state");
        let proof = EconomicPathProof::from_state(&state, false, key(3)).expect("proof");
        let bytes = proof.to_bytes().expect("encode");
        assert!(bytes.len() <= MAX_ECONOMIC_PROOF_BYTES);
        assert_eq!(
            EconomicPathProof::from_bytes(&bytes).expect("decode"),
            proof
        );
        assert_eq!(
            hex::encode(&bytes),
            "55444543505230314b0303030303030303030303030303030303030303030303030303030303030303030000000000000000000000000000000000000000000000000000000000000040000132490a9ae8b38b1eee22d5dacc8ec3e34d2c1f80f5628e81a34f3f4d239be393"
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            EconomicPathProof::from_bytes(&trailing),
            Err(EconomicStateError::InvalidProof)
        );
        let mut wrong_count = bytes;
        wrong_count[74..76].copy_from_slice(&256u16.to_be_bytes());
        assert_eq!(
            EconomicPathProof::from_bytes(&wrong_count),
            Err(EconomicStateError::InvalidProof)
        );
    }

    #[test]
    fn economic_multiproof_shares_sides_and_updates_all_effects_atomically() {
        let mut state = EconomicState::from_entries(
            [
                (
                    key(1),
                    EconomicUtxo {
                        created_height: 8,
                        is_coinbase: true,
                    },
                ),
                (
                    key(2),
                    EconomicUtxo {
                        created_height: 9,
                        is_coinbase: false,
                    },
                ),
                (
                    key(5),
                    EconomicUtxo {
                        created_height: 10,
                        is_coinbase: false,
                    },
                ),
            ],
            [key(3), key(4), key(6)],
        )
        .expect("state");
        let inserted = EconomicUtxo {
            created_height: 20,
            is_coinbase: false,
        };
        let proof = EconomicMultiProof::from_state(&state, true, [key(1), key(9)])
            .expect("utxo multiproof");
        let old: Vec<_> = proof
            .keys()
            .iter()
            .map(|query_key| match *query_key {
                value if value == key(1) => Some(EconomicUtxo {
                    created_height: 8,
                    is_coinbase: true,
                }),
                value if value == key(9) => None,
                _ => panic!("unexpected key"),
            })
            .collect();
        let new: Vec<_> = proof
            .keys()
            .iter()
            .map(|query_key| match *query_key {
                value if value == key(1) => None,
                value if value == key(9) => Some(inserted),
                _ => panic!("unexpected key"),
            })
            .collect();
        let updated = proof
            .update_utxo_root(state.utxo_set_root().expect("root"), &old, &new)
            .expect("batch update");
        state.utxos.remove(&key(1));
        state.utxos.insert(key(9), inserted);
        assert_eq!(updated, state.utxo_set_root().expect("full update"));

        let kernel = EconomicMultiProof::from_state(&state, false, [key(7), key(8)])
            .expect("kernel multiproof");
        let old = vec![false; kernel.keys().len()];
        let new = vec![true; kernel.keys().len()];
        let updated = kernel
            .update_kernel_root(state.kernel_set_root().expect("kernel root"), &old, &new)
            .expect("kernel update");
        state.kernels.extend([key(7), key(8)]);
        assert_eq!(updated, state.kernel_set_root().expect("full kernels"));
    }

    #[test]
    fn economic_multiproof_encoding_is_canonical_and_rejects_duplicate_queries() {
        let state = EconomicState::from_entries(
            [(
                key(1),
                EconomicUtxo {
                    created_height: 8,
                    is_coinbase: true,
                },
            )],
            [key(3), key(4), key(6)],
        )
        .expect("state");
        assert_eq!(
            EconomicMultiProof::from_state(&state, false, [key(3), key(3)]),
            Err(EconomicStateError::InvalidProof)
        );
        let proof = EconomicMultiProof::from_state(&state, false, [key(3), key(7), key(8)])
            .expect("multiproof");
        let bytes = proof.to_bytes().expect("encode");
        assert_eq!(
            EconomicMultiProof::from_bytes(&bytes).expect("decode"),
            proof
        );
        assert_eq!(
            hex::encode(&bytes),
            "554445434d5030314b00000003000000010303030303030303030303030303030303030303030303030303030303030303030808080808080808080808080808080808080808080808080808080808080808080707070707070707070707070707070707070707070707070707070707070707070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000009259eeda31b53046f292fd10763eebf76c912bad0cc13a8253f5e5f4d75bd122"
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            EconomicMultiProof::from_bytes(&trailing),
            Err(EconomicStateError::InvalidProof)
        );
    }

    #[cfg(feature = "host-reference")]
    #[test]
    fn block_witness_matches_full_state_and_has_canonical_transport() {
        let spent = commitment(1);
        let retained = commitment(9);
        let mut state = EconomicState::from_entries(
            [
                (
                    *spent.as_bytes(),
                    EconomicUtxo {
                        created_height: 5,
                        is_coinbase: true,
                    },
                ),
                (
                    *retained.as_bytes(),
                    EconomicUtxo {
                        created_height: 3,
                        is_coinbase: false,
                    },
                ),
            ],
            [*commitment(10).as_bytes()],
        )
        .expect("state");
        let candidate = block(
            15,
            commitment(2),
            commitment(3),
            vec![Transaction {
                inputs: vec![TransactionInput { commitment: spent }],
                outputs: vec![TransactionOutput {
                    commitment: commitment(4),
                    proof: Vec::new(),
                }],
                kernels: Vec::new(),
                offset: [0; 32],
            }],
        );
        let roots = EconomicRoots {
            utxo_root: state.utxo_set_root().expect("utxo root"),
            kernel_root: state.kernel_set_root().expect("kernel root"),
        };
        let witness = EconomicBlockWitness::from_state(&state, &candidate).expect("witness");
        let updated = witness.apply(roots, &candidate, 10).expect("apply witness");
        state.apply_block(&candidate, 10).expect("apply full state");
        assert_eq!(updated.utxo_root, state.utxo_set_root().expect("full utxo"));
        assert_eq!(
            updated.kernel_root,
            state.kernel_set_root().expect("full kernel")
        );

        let bytes = witness.to_bytes().expect("encode");
        assert!(bytes.len() <= MAX_ECONOMIC_BLOCK_WITNESS_BYTES);
        assert_eq!(
            EconomicBlockWitness::from_bytes(&bytes).expect("decode"),
            witness
        );
        assert_eq!(
            hex::encode(keccak(&bytes)),
            "27d567fe1fb791d9f8f2422f22f8eaf6924a6e2839298151ae3428f84c95acb2"
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            EconomicBlockWitness::from_bytes(&trailing),
            Err(EconomicStateError::InvalidProof)
        );
    }

    #[cfg(feature = "host-reference")]
    #[test]
    fn economic_chunks_cover_utxo_then_kernel_effects_with_bounded_transport() {
        let spent = commitment(1);
        let mut state = EconomicState::from_entries(
            [(
                *spent.as_bytes(),
                EconomicUtxo {
                    created_height: 5,
                    is_coinbase: true,
                },
            )],
            std::iter::empty(),
        )
        .expect("state");
        let candidate = block(
            15,
            commitment(2),
            commitment(3),
            vec![Transaction {
                inputs: vec![TransactionInput { commitment: spent }],
                outputs: vec![TransactionOutput {
                    commitment: commitment(4),
                    proof: Vec::new(),
                }],
                kernels: Vec::new(),
                offset: [0; 32],
            }],
        );
        let initial = EconomicRoots {
            utxo_root: state.utxo_set_root().expect("utxo root"),
            kernel_root: state.kernel_set_root().expect("kernel root"),
        };
        let utxo = EconomicChunkWitness::from_state(&state, &candidate, 0).expect("utxo chunk");
        let encoded = utxo.to_bytes().expect("chunk bytes");
        assert!(encoded.len() <= MAX_ECONOMIC_CHUNK_WITNESS_BYTES);
        assert_eq!(
            EconomicChunkWitness::from_bytes(&encoded).expect("chunk decode"),
            utxo
        );
        let first = utxo.apply(initial, &candidate, 10).expect("utxo apply");
        assert!(first.next_cursor < first.total_effects);
        let package = UsdomV4BlockPackage::new(candidate.clone(), UsdomV4ProofEnvelope::empty())
            .expect("package")
            .to_bytes()
            .expect("package bytes");
        let transition = execute_economic_chunk_portable(
            &package,
            &utxo,
            dom_core::NETWORK_MAGIC_REGTEST,
            initial,
        )
        .expect("portable chunk");
        assert_eq!(transition.cursor, 0);
        assert_eq!(transition.next_cursor, first.next_cursor);
        assert_eq!(transition.next_roots, first.roots);
        assert_eq!(
            EconomicChunkTransition::from_bytes(&transition.to_bytes().expect("transition bytes"))
                .expect("transition decode"),
            transition
        );
        assert_ne!(transition.commitment().expect("journal"), [0; 32]);

        let kernel = EconomicChunkWitness::from_state(&state, &candidate, first.next_cursor)
            .expect("kernel chunk");
        let final_chunk = kernel
            .apply(first.roots, &candidate, 10)
            .expect("kernel apply");
        assert_eq!(final_chunk.next_cursor, final_chunk.total_effects);

        state.apply_block(&candidate, 10).expect("full apply");
        assert_eq!(
            final_chunk.roots,
            EconomicRoots {
                utxo_root: state.utxo_set_root().expect("full utxo"),
                kernel_root: state.kernel_set_root().expect("full kernel"),
            }
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            EconomicChunkWitness::from_bytes(&trailing),
            Err(EconomicStateError::InvalidProof)
        );
    }

    #[cfg(feature = "host-reference")]
    #[test]
    fn economic_chunks_split_more_than_512_effects_without_root_drift() {
        let outputs: Vec<_> = (10u16..610)
            .map(|seed| TransactionOutput {
                commitment: commitment_index(seed),
                proof: Vec::new(),
            })
            .collect();
        let transactions = outputs
            .chunks(200)
            .map(|chunk| Transaction {
                inputs: Vec::new(),
                outputs: chunk.to_vec(),
                kernels: Vec::new(),
                offset: [0; 32],
            })
            .collect();
        let candidate = block(20, commitment_index(1), commitment_index(2), transactions);
        let mut proving_state = EconomicState::default();
        let initial = EconomicRoots {
            utxo_root: proving_state.utxo_set_root().expect("utxo root"),
            kernel_root: proving_state.kernel_set_root().expect("kernel root"),
        };
        let (effects, _) = economic_block_effects(&candidate).expect("effects");
        assert_eq!(effects.len(), 601);
        assert_eq!(MAX_ECONOMIC_BLOCK_CHUNKS, 80);

        let first =
            EconomicChunkWitness::from_state(&proving_state, &candidate, 0).expect("first chunk");
        assert!(first.to_bytes().expect("first bytes").len() <= MAX_ECONOMIC_CHUNK_WITNESS_BYTES);
        let first_result = first.apply(initial, &candidate, 10).expect("first apply");
        assert_eq!(first_result.next_cursor, 512);
        for (key, effect) in &effects[..512] {
            assert!(!effect.spent);
            proving_state.utxos.insert(
                *key,
                EconomicUtxo {
                    created_height: 20,
                    is_coinbase: effect.coinbase,
                },
            );
        }

        let second =
            EconomicChunkWitness::from_state(&proving_state, &candidate, first_result.next_cursor)
                .expect("second chunk");
        let second_result = second
            .apply(first_result.roots, &candidate, 10)
            .expect("second apply");
        assert_eq!(second_result.next_cursor, 601);
        for (key, effect) in &effects[512..] {
            proving_state.utxos.insert(
                *key,
                EconomicUtxo {
                    created_height: 20,
                    is_coinbase: effect.coinbase,
                },
            );
        }

        let kernel =
            EconomicChunkWitness::from_state(&proving_state, &candidate, second_result.next_cursor)
                .expect("kernel chunk");
        let final_result = kernel
            .apply(second_result.roots, &candidate, 10)
            .expect("kernel apply");
        assert_eq!(final_result.next_cursor, final_result.total_effects);

        let mut full_state = EconomicState::default();
        full_state
            .apply_block(&candidate, 10)
            .expect("full block apply");
        assert_eq!(
            final_result.roots,
            EconomicRoots {
                utxo_root: full_state.utxo_set_root().expect("full utxo"),
                kernel_root: full_state.kernel_set_root().expect("full kernel"),
            }
        );
    }

    #[cfg(feature = "host-reference")]
    #[test]
    fn block_witness_enforces_authenticated_coinbase_maturity() {
        let spent = commitment(1);
        let state = EconomicState::from_entries(
            [(
                *spent.as_bytes(),
                EconomicUtxo {
                    created_height: 5,
                    is_coinbase: true,
                },
            )],
            std::iter::empty(),
        )
        .expect("state");
        let candidate = block(
            14,
            commitment(2),
            commitment(3),
            vec![Transaction {
                inputs: vec![TransactionInput { commitment: spent }],
                outputs: Vec::new(),
                kernels: Vec::new(),
                offset: [0; 32],
            }],
        );
        let witness = EconomicBlockWitness::from_state(&state, &candidate).expect("witness");
        let roots = EconomicRoots {
            utxo_root: state.utxo_set_root().expect("utxo root"),
            kernel_root: state.kernel_set_root().expect("kernel root"),
        };
        assert_eq!(
            witness.apply(roots, &candidate, 10),
            Err(EconomicStateError::ImmatureCoinbase)
        );
    }

    #[cfg(feature = "host-reference")]
    #[test]
    fn contextual_block_effects_are_atomic_and_enforce_maturity() {
        let spent = commitment(1);
        let mut state = EconomicState::from_entries(
            [(
                *spent.as_bytes(),
                EconomicUtxo {
                    created_height: 5,
                    is_coinbase: true,
                },
            )],
            std::iter::empty(),
        )
        .expect("initial state");
        let spend = Transaction {
            inputs: vec![TransactionInput {
                commitment: spent.clone(),
            }],
            outputs: Vec::new(),
            kernels: Vec::new(),
            offset: [0; 32],
        };
        let immature = block(10, commitment(2), commitment(3), vec![spend.clone()]);
        let before = state.clone();
        assert_eq!(
            state.apply_block(&immature, 10),
            Err(EconomicStateError::ImmatureCoinbase)
        );
        assert_eq!(state, before);

        let mature = block(15, commitment(2), commitment(3), vec![spend]);
        state.apply_block(&mature, 10).expect("mature spend");
        assert!(!state.utxos().contains_key(spent.as_bytes()));
        assert!(state.utxos().contains_key(commitment(2).as_bytes()));
        assert!(state.kernels().contains(commitment(3).as_bytes()));
    }

    #[cfg(feature = "host-reference")]
    #[test]
    fn contextual_block_effects_reject_missing_outputs_and_kernel_replays() {
        let existing_output = commitment(4);
        let existing_kernel = commitment(5);
        let base = EconomicState::from_entries(
            [(
                *existing_output.as_bytes(),
                EconomicUtxo {
                    created_height: 1,
                    is_coinbase: false,
                },
            )],
            [*existing_kernel.as_bytes()],
        )
        .expect("base state");

        let mut duplicate_output = base.clone();
        assert_eq!(
            duplicate_output
                .apply_block(&block(20, existing_output, commitment(6), Vec::new()), 10),
            Err(EconomicStateError::DuplicateOutput)
        );
        assert_eq!(duplicate_output, base);

        let mut duplicate_kernel = base.clone();
        assert_eq!(
            duplicate_kernel
                .apply_block(&block(20, commitment(6), existing_kernel, Vec::new()), 10),
            Err(EconomicStateError::DuplicateKernel)
        );
        assert_eq!(duplicate_kernel, base);

        let missing = commitment(7);
        let mut missing_state = base.clone();
        assert_eq!(
            missing_state.apply_block(
                &block(
                    20,
                    commitment(8),
                    commitment(9),
                    vec![Transaction {
                        inputs: vec![TransactionInput {
                            commitment: missing,
                        }],
                        outputs: Vec::new(),
                        kernels: Vec::new(),
                        offset: [0; 32],
                    }],
                ),
                10,
            ),
            Err(EconomicStateError::MissingInput)
        );
        assert_eq!(missing_state, base);
    }
}
