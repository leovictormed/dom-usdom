//! Canonical public-statement boundary for a DOM checkpoint proof.
//!
//! `UDCPST03` is deliberately much smaller than a consensus-extension witness.
//! It encodes only the public values already committed by the immutable
//! Ethereum registry. A future proving guest must validate the private DOM
//! header, PoW, fork-choice and native-USD state-transition witness before it
//! emits the exact 32-byte hash produced here. Parsing this statement alone
//! grants no checkpoint or consensus authority.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::{error::Error, fmt};

use sha3::{Digest, Keccak256};

const MAGIC: &[u8; 8] = b"UDCPST03";
const VERSION: u16 = 3;
const TYPE_STRING: &str = "DOMCheckpoint(bytes32 bridgeDomain,uint32 domNetworkMagic,uint64 previousHeight,bytes32 previousBlock,bytes32 previousStateRoot,bytes32 previousContextHash,uint256 previousTotalDifficulty,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 domContextHash,uint256 domTotalDifficulty,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp,uint256 ethereumChainId,address registry,bytes32 activationScheduleCommitment,bytes32 checkpointConfigHash)";
const V4_MAGIC: &[u8; 8] = b"UDCPST04";
const V4_VERSION: u16 = 4;
const V4_TYPE_STRING: &str = "DOMCheckpointV2(bytes32 bridgeDomain,uint32 domNetworkMagic,uint16 nativeStateVersion,uint16 transitionBatchVersion,uint64 previousHeight,bytes32 previousBlock,bytes32 previousStateRoot,bytes32 previousContextHash,uint256 previousTotalDifficulty,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 domContextHash,uint256 domTotalDifficulty,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp,uint256 ethereumChainId,address registry,bytes32 activationScheduleCommitment,bytes32 checkpointConfigHash)";
const V5_MAGIC: &[u8; 8] = b"UDCPST05";
const V5_VERSION: u16 = 5;
const V5_TYPE_STRING: &str = "DOMCheckpointV3(bytes32 bridgeDomain,uint32 domNetworkMagic,uint16 nativeStateVersion,uint16 transitionBatchVersion,uint64 previousHeight,bytes32 previousBlock,bytes32 previousStateRoot,bytes32 previousContextHash,uint256 previousTotalDifficulty,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 domContextHash,uint256 domTotalDifficulty,uint128 totalIssued,uint128 totalBurned,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp,uint256 ethereumChainId,address registry,bytes32 activationScheduleCommitment,bytes32 checkpointConfigHash)";
const V6_MAGIC: &[u8; 8] = b"UDCPST06";
const V6_VERSION: u16 = 6;
const V6_TYPE_STRING: &str = "DOMCheckpointV4(bytes32 bridgeDomain,uint32 domNetworkMagic,uint16 nativeStateVersion,uint16 transitionBatchVersion,uint64 previousHeight,bytes32 previousBlock,bytes32 previousStateRoot,bytes32 previousContextHash,uint256 previousTotalDifficulty,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 domContextHash,uint256 domTotalDifficulty,uint128 totalIssued,uint128 totalBurned,bool issuanceClosed,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp,uint256 ethereumChainId,address registry,bytes32 activationScheduleCommitment,bytes32 checkpointConfigHash)";
const ABI_WORDS: usize = 21;
const CONTEXT_MAGIC: &[u8; 8] = b"UDCCTX02";
const CONTEXT_VERSION: u16 = 2;
const RANDOMX_SEED_INTERVAL: u64 = 2_048;
const RANDOMX_SEED_OFFSET: u64 = 64;
const ECONOMIC_STATE_DOMAIN: &[u8] = b"DOM:checkpoint-economic-state:v1";
const CHECKPOINT_RANDOMX_STATEMENT_MAGIC: &[u8; 8] = b"UDCRXST1";
const CHECKPOINT_RANDOMX_STATEMENT_VERSION: u16 = 1;
const CHECKPOINT_RANDOMX_ALGORITHM_VERSION: u16 = 1;
const CHECKPOINT_RANDOMX_STATEMENT_DOMAIN: &[u8] = b"DOM:checkpoint-randomx-statement:v1";
const CHECKPOINT_RANDOMX_SEED_INTERVAL: u64 = 2_048;
const CHECKPOINT_RANDOMX_SEED_OFFSET: u64 = 64;
/// Number of authenticated ancestor timestamps carried between proofs.
pub const CHECKPOINT_CONTEXT_HEADER_COUNT: usize = 11;
/// Maximum number of historical RandomX seed anchors carried between proofs.
pub const CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS: usize = 2;
const MTP_HEADER_COUNT: usize = CHECKPOINT_CONTEXT_HEADER_COUNT;
const MAX_SEED_ANCHORS: usize = CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS;

/// Exact canonical byte length of one `UDCPST03` statement.
pub const CHECKPOINT_STATEMENT_BYTES: usize = 514;
/// Exact canonical byte length of one candidate-v2 `UDCPST04` statement.
pub const CHECKPOINT_STATEMENT_V4_BYTES: usize = 518;
/// Exact canonical byte length of one economic `UDCPST05` statement.
pub const CHECKPOINT_STATEMENT_V5_BYTES: usize = CHECKPOINT_STATEMENT_V4_BYTES + 32;
/// Exact canonical byte length of one closure-aware `UDCPST06` statement.
pub const CHECKPOINT_STATEMENT_V6_BYTES: usize = CHECKPOINT_STATEMENT_V5_BYTES + 1;
/// Native closed-state interpretation frozen by `UDCPST06`.
pub const CHECKPOINT_NATIVE_STATE_V6_VERSION: u16 = 3;
/// Native state-root interpretation frozen by `UDCPST04`.
pub const CHECKPOINT_NATIVE_STATE_VERSION: u16 = 2;
/// Transition-batch commitment interpretation frozen by `UDCPST04`.
pub const CHECKPOINT_TRANSITION_BATCH_VERSION: u16 = 3;
/// Transition-batch commitment interpretation frozen by `UDCPST05`.
pub const CHECKPOINT_TRANSITION_BATCH_V5_VERSION: u16 = 4;
/// Exact raw public output expected by `DOMCheckpointRegistry`'s verifier.
pub const CHECKPOINT_PUBLIC_OUTPUT_BYTES: usize = 32;
/// Semantic version of the unframed 32-byte public output.
pub const CHECKPOINT_PUBLIC_OUTPUT_VERSION: u16 = 1;
/// Exact fixed-width byte length of one `UDCCTX02` continuation context.
pub const CHECKPOINT_CONTEXT_BYTES: usize =
    8 + 2 + 8 + 32 + 4 + 32 + MTP_HEADER_COUNT * (8 + 32 + 8) + 1 + MAX_SEED_ANCHORS * (8 + 32);
/// Maximum number of blocks one context may support in the following proof.
pub const MAX_CONTEXT_SPAN: u32 = 720;
/// DOM block version whose exact preimage is accepted by `UDCRXST1`.
pub const CHECKPOINT_RANDOMX_BLOCK_VERSION: u32 = 4;
/// Byte offset of the little-endian block height inside the PoW preimage.
pub const CHECKPOINT_RANDOMX_PREIMAGE_HEIGHT_OFFSET: usize = 36;
/// Byte offset of the little-endian compact target inside the PoW preimage.
pub const CHECKPOINT_RANDOMX_PREIMAGE_TARGET_OFFSET: usize = 180;
/// Exact canonical RandomX preimage length for a DOM block header.
pub const CHECKPOINT_RANDOMX_PREIMAGE_BYTES: usize = 224;
/// Exact byte length of one portable RandomX proof statement.
pub const CHECKPOINT_RANDOMX_STATEMENT_BYTES: usize = 384;

/// Consensus RandomX seed height selected for `height`.
pub fn checkpoint_randomx_seed_height(height: u64) -> u64 {
    let epoch = height / CHECKPOINT_RANDOMX_SEED_INTERVAL;
    if epoch == 0 {
        0
    } else {
        (epoch * CHECKPOINT_RANDOMX_SEED_INTERVAL).saturating_sub(CHECKPOINT_RANDOMX_SEED_OFFSET)
    }
}

/// Expand and validate one canonical DOM compact target.
pub fn checkpoint_compact_target(bits: u32) -> Option<[u8; 32]> {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    if mantissa == 0 {
        return Some([0; 32]);
    }
    if bits & 0x0080_0000 != 0 || exponent > 32 {
        return None;
    }
    let mut target = [0u8; 32];
    let mut write = |position: usize, value: u8| {
        if position < 32 {
            target[31 - position] = value;
        }
    };
    if exponent >= 1 {
        write(exponent - 1, (mantissa & 0xff) as u8);
    }
    if exponent >= 2 {
        write(exponent - 2, ((mantissa >> 8) & 0xff) as u8);
    }
    if exponent >= 3 {
        write(exponent - 3, ((mantissa >> 16) & 0xff) as u8);
    }
    let mut maximum = dom_core::MAX_TARGET_BYTES;
    maximum[1] = 0xff;
    if target > maximum || target < dom_core::MIN_TARGET_BYTES {
        return None;
    }
    Some(target)
}

/// Compare a big-endian RandomX output against its expanded target.
pub fn checkpoint_hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    hash <= target
}

/// Public values that a recursive RandomX proof establishes for one header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointRandomXStatement {
    /// DOM network magic selected by the checkpoint policy.
    pub network_magic: u32,
    /// Canonical DOM chain identity.
    pub chain_id: [u8; 32],
    /// Height of the header whose PoW is proved.
    pub block_height: u64,
    /// Consensus-derived height of the block used as RandomX seed.
    pub seed_height: u64,
    /// Canonical block identifier at `seed_height`.
    pub seed_hash: [u8; 32],
    /// Exact 224-byte block-header PoW preimage.
    pub pow_preimage: [u8; CHECKPOINT_RANDOMX_PREIMAGE_BYTES],
    /// RandomX output claimed by the header.
    pub randomx_hash: [u8; 32],
    /// Expanded big-endian target committed by the header.
    pub target: [u8; 32],
}

/// Failure to encode or validate one portable RandomX proof statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointRandomXStatementError {
    /// Magic, versions, length or canonical representation is invalid.
    InvalidFraming,
    /// Network, chain, seed or hash identity is zero or malformed.
    InvalidIdentity,
    /// Height or seed-height does not match the exact consensus schedule.
    InvalidSeedSchedule,
    /// The compact target in the preimage does not open the stated target.
    InvalidTarget,
    /// The claimed RandomX output is above the stated target.
    InsufficientWork,
}

impl fmt::Display for CheckpointRandomXStatementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFraming => "invalid checkpoint RandomX statement framing",
            Self::InvalidIdentity => "invalid checkpoint RandomX statement identity",
            Self::InvalidSeedSchedule => "invalid checkpoint RandomX seed schedule",
            Self::InvalidTarget => "invalid checkpoint RandomX target binding",
            Self::InsufficientWork => "checkpoint RandomX output does not meet target",
        })
    }
}

impl Error for CheckpointRandomXStatementError {}

impl CheckpointRandomXStatement {
    /// Validate every public invariant other than computing RandomX itself.
    pub fn validate(&self) -> Result<(), CheckpointRandomXStatementError> {
        if self.network_magic == 0
            || self.chain_id == [0; 32]
            || self.block_height == 0
            || self.seed_hash == [0; 32]
            || self.randomx_hash == [0; 32]
            || self.target == [0; 32]
        {
            return Err(CheckpointRandomXStatementError::InvalidIdentity);
        }
        let version = u32::from_le_bytes(
            self.pow_preimage[..4]
                .try_into()
                .map_err(|_| CheckpointRandomXStatementError::InvalidFraming)?,
        );
        let preimage_height = u64::from_le_bytes(
            self.pow_preimage[CHECKPOINT_RANDOMX_PREIMAGE_HEIGHT_OFFSET
                ..CHECKPOINT_RANDOMX_PREIMAGE_HEIGHT_OFFSET + 8]
                .try_into()
                .map_err(|_| CheckpointRandomXStatementError::InvalidFraming)?,
        );
        if version != CHECKPOINT_RANDOMX_BLOCK_VERSION
            || preimage_height != self.block_height
            || self.seed_height != checkpoint_randomx_seed_height(self.block_height)
            || self.seed_height >= self.block_height
        {
            return Err(CheckpointRandomXStatementError::InvalidSeedSchedule);
        }
        let compact = u32::from_le_bytes(
            self.pow_preimage[CHECKPOINT_RANDOMX_PREIMAGE_TARGET_OFFSET
                ..CHECKPOINT_RANDOMX_PREIMAGE_TARGET_OFFSET + 4]
                .try_into()
                .map_err(|_| CheckpointRandomXStatementError::InvalidFraming)?,
        );
        let expanded = checkpoint_compact_target(compact)
            .ok_or(CheckpointRandomXStatementError::InvalidTarget)?;
        if expanded != self.target {
            return Err(CheckpointRandomXStatementError::InvalidTarget);
        }
        if !checkpoint_hash_meets_target(&self.randomx_hash, &self.target) {
            return Err(CheckpointRandomXStatementError::InsufficientWork);
        }
        Ok(())
    }

    /// Encode the unique fixed-width `UDCRXST1` representation.
    pub fn to_bytes(
        &self,
    ) -> Result<[u8; CHECKPOINT_RANDOMX_STATEMENT_BYTES], CheckpointRandomXStatementError> {
        self.validate()?;
        let mut bytes = [0u8; CHECKPOINT_RANDOMX_STATEMENT_BYTES];
        bytes[..8].copy_from_slice(CHECKPOINT_RANDOMX_STATEMENT_MAGIC);
        bytes[8..10].copy_from_slice(&CHECKPOINT_RANDOMX_STATEMENT_VERSION.to_be_bytes());
        bytes[10..12].copy_from_slice(&CHECKPOINT_RANDOMX_ALGORITHM_VERSION.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.network_magic.to_be_bytes());
        bytes[16..48].copy_from_slice(&self.chain_id);
        bytes[48..56].copy_from_slice(&self.block_height.to_be_bytes());
        bytes[56..64].copy_from_slice(&self.seed_height.to_be_bytes());
        bytes[64..96].copy_from_slice(&self.seed_hash);
        bytes[96..320].copy_from_slice(&self.pow_preimage);
        bytes[320..352].copy_from_slice(&self.randomx_hash);
        bytes[352..384].copy_from_slice(&self.target);
        Ok(bytes)
    }

    /// Decode, validate and canonically re-encode one `UDCRXST1` statement.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CheckpointRandomXStatementError> {
        if bytes.len() != CHECKPOINT_RANDOMX_STATEMENT_BYTES
            || bytes.get(..8) != Some(CHECKPOINT_RANDOMX_STATEMENT_MAGIC.as_slice())
            || u16::from_be_bytes(
                bytes
                    .get(8..10)
                    .ok_or(CheckpointRandomXStatementError::InvalidFraming)?
                    .try_into()
                    .map_err(|_| CheckpointRandomXStatementError::InvalidFraming)?,
            ) != CHECKPOINT_RANDOMX_STATEMENT_VERSION
            || u16::from_be_bytes(
                bytes
                    .get(10..12)
                    .ok_or(CheckpointRandomXStatementError::InvalidFraming)?
                    .try_into()
                    .map_err(|_| CheckpointRandomXStatementError::InvalidFraming)?,
            ) != CHECKPOINT_RANDOMX_ALGORITHM_VERSION
        {
            return Err(CheckpointRandomXStatementError::InvalidFraming);
        }
        let statement = Self {
            network_magic: u32::from_be_bytes(
                bytes[12..16]
                    .try_into()
                    .map_err(|_| CheckpointRandomXStatementError::InvalidFraming)?,
            ),
            chain_id: bytes[16..48]
                .try_into()
                .map_err(|_| CheckpointRandomXStatementError::InvalidFraming)?,
            block_height: u64::from_be_bytes(
                bytes[48..56]
                    .try_into()
                    .map_err(|_| CheckpointRandomXStatementError::InvalidFraming)?,
            ),
            seed_height: u64::from_be_bytes(
                bytes[56..64]
                    .try_into()
                    .map_err(|_| CheckpointRandomXStatementError::InvalidFraming)?,
            ),
            seed_hash: bytes[64..96]
                .try_into()
                .map_err(|_| CheckpointRandomXStatementError::InvalidFraming)?,
            pow_preimage: bytes[96..320]
                .try_into()
                .map_err(|_| CheckpointRandomXStatementError::InvalidFraming)?,
            randomx_hash: bytes[320..352]
                .try_into()
                .map_err(|_| CheckpointRandomXStatementError::InvalidFraming)?,
            target: bytes[352..384]
                .try_into()
                .map_err(|_| CheckpointRandomXStatementError::InvalidFraming)?,
        };
        statement.validate()?;
        if statement.to_bytes()?.as_slice() != bytes {
            return Err(CheckpointRandomXStatementError::InvalidFraming);
        }
        Ok(statement)
    }

    /// Keccak commitment returned by a recursive RandomX receipt.
    pub fn commitment(&self) -> Result<[u8; 32], CheckpointRandomXStatementError> {
        let bytes = self.to_bytes()?;
        let mut hasher = Keccak256::new();
        hasher.update(CHECKPOINT_RANDOMX_STATEMENT_DOMAIN);
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }
}

/// Commit the ordinary DOM UTXO-set root and historical kernel-set root into
/// the single continuation value carried by [`CheckpointContext`].
///
/// The two component roots must be derived by the proving program from the
/// exact ratified economic-state rules. This helper only freezes their
/// ordering, domain separation, and nonzero semantics.
pub fn checkpoint_economic_state_root(
    utxo_set_root: [u8; 32],
    kernel_set_root: [u8; 32],
) -> Result<[u8; 32], ContextError> {
    if utxo_set_root == [0; 32] || kernel_set_root == [0; 32] {
        return Err(ContextError::InvalidHistory);
    }
    let mut preimage = Vec::with_capacity(ECONOMIC_STATE_DOMAIN.len() + 64);
    preimage.extend_from_slice(ECONOMIC_STATE_DOMAIN);
    preimage.extend_from_slice(&utxo_set_root);
    preimage.extend_from_slice(&kernel_set_root);
    let root: [u8; 32] = Keccak256::digest(preimage).into();
    if root == [0; 32] {
        return Err(ContextError::InvalidHistory);
    }
    Ok(root)
}

/// One authenticated header projection used by the next round's MTP checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextHeader {
    /// Header height.
    pub height: u64,
    /// Canonical DOM block identifier.
    pub block: [u8; 32],
    /// Consensus header timestamp.
    pub timestamp: u64,
}

/// A historical RandomX seed block needed after the checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SeedAnchor {
    /// Seed block height.
    pub height: u64,
    /// Canonical DOM block identifier at `height`.
    pub block: [u8; 32],
}

/// Bounded consensus state carried from one proved checkpoint to the next.
///
/// The prior proof constructs this value from headers it has fully validated.
/// The next proof must match its Keccak commitment before using the MTP window
/// or historical RandomX seeds. A bootstrap context requires independent
/// ratification against the canonical DOM chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointContext {
    /// Height and block to which this context belongs.
    pub checkpoint_height: u64,
    /// Canonical block identifier at `checkpoint_height`.
    pub checkpoint_block: [u8; 32],
    /// Maximum following extension span covered by the seed selection.
    pub max_span: u32,
    /// Commitment to the complete ordinary DOM UTXO and kernel-replay state.
    ///
    /// A continuation proof must open this commitment before it validates
    /// input existence, coinbase maturity, output uniqueness, or kernel
    /// uniqueness. The next proof emits the updated commitment. This prevents
    /// a prover from validating headers and native USDOM transitions against a
    /// privately selected economic state.
    pub economic_state_root: [u8; 32],
    /// The eleven consecutive headers ending at the checkpoint, oldest first.
    pub recent_headers: [ContextHeader; MTP_HEADER_COUNT],
    /// Number of populated entries at the start of `seed_anchors`.
    pub seed_anchor_count: u8,
    /// Exact historical seed anchors required by the next extension.
    pub seed_anchors: [SeedAnchor; MAX_SEED_ANCHORS],
}

/// Failure to encode or validate a checkpoint continuation context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError {
    /// Input length, magic, version or canonical padding is invalid.
    InvalidFraming,
    /// The checkpoint, recent headers, or their timestamps are invalid.
    InvalidHistory,
    /// The requested following proof span is outside the supported bound.
    InvalidSpan,
    /// The RandomX seed anchors do not exactly match the required schedule.
    InvalidSeedAnchors,
    /// Checked height arithmetic overflowed.
    HeightOverflow,
}

impl fmt::Display for ContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFraming => "invalid DOM checkpoint context framing",
            Self::InvalidHistory => "invalid DOM checkpoint context history",
            Self::InvalidSpan => "invalid DOM checkpoint context span",
            Self::InvalidSeedAnchors => "invalid DOM checkpoint context RandomX seed anchors",
            Self::HeightOverflow => "DOM checkpoint context height overflow",
        })
    }
}

impl Error for ContextError {}

impl CheckpointContext {
    /// Validate all fixed-width history and exact RandomX schedule invariants.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.checkpoint_height < (MTP_HEADER_COUNT - 1) as u64
            || self.checkpoint_block == [0; 32]
        {
            return Err(ContextError::InvalidHistory);
        }
        if self.max_span == 0 || self.max_span > MAX_CONTEXT_SPAN {
            return Err(ContextError::InvalidSpan);
        }
        if self.economic_state_root == [0; 32] {
            return Err(ContextError::InvalidHistory);
        }
        let first_height = self
            .checkpoint_height
            .checked_sub((MTP_HEADER_COUNT - 1) as u64)
            .ok_or(ContextError::HeightOverflow)?;
        for (index, header) in self.recent_headers.iter().enumerate() {
            let expected_height = first_height
                .checked_add(index as u64)
                .ok_or(ContextError::HeightOverflow)?;
            if header.height != expected_height || header.block == [0; 32] {
                return Err(ContextError::InvalidHistory);
            }
            if index > 0 && header.timestamp <= self.recent_headers[index - 1].timestamp {
                return Err(ContextError::InvalidHistory);
            }
        }
        if self.recent_headers[MTP_HEADER_COUNT - 1].block != self.checkpoint_block {
            return Err(ContextError::InvalidHistory);
        }

        let required = required_historical_seed_heights(self.checkpoint_height, self.max_span)?;
        if usize::from(self.seed_anchor_count) != required.len() {
            return Err(ContextError::InvalidSeedAnchors);
        }
        for (index, anchor) in self.seed_anchors.iter().enumerate() {
            if index < required.len() {
                if anchor.height != required[index] || anchor.block == [0; 32] {
                    return Err(ContextError::InvalidSeedAnchors);
                }
                if let Some(header) = self
                    .recent_headers
                    .iter()
                    .find(|header| header.height == anchor.height)
                {
                    if header.block != anchor.block {
                        return Err(ContextError::InvalidSeedAnchors);
                    }
                }
            } else if *anchor != SeedAnchor::default() {
                return Err(ContextError::InvalidFraming);
            }
        }
        Ok(())
    }

    /// Encode the unique fixed-width `UDCCTX02` representation.
    pub fn to_bytes(&self) -> Result<[u8; CHECKPOINT_CONTEXT_BYTES], ContextError> {
        self.validate()?;
        let mut bytes = [0u8; CHECKPOINT_CONTEXT_BYTES];
        bytes[..8].copy_from_slice(CONTEXT_MAGIC);
        bytes[8..10].copy_from_slice(&CONTEXT_VERSION.to_be_bytes());
        bytes[10..18].copy_from_slice(&self.checkpoint_height.to_be_bytes());
        bytes[18..50].copy_from_slice(&self.checkpoint_block);
        bytes[50..54].copy_from_slice(&self.max_span.to_be_bytes());
        bytes[54..86].copy_from_slice(&self.economic_state_root);
        let mut cursor = 86;
        for header in &self.recent_headers {
            bytes[cursor..cursor + 8].copy_from_slice(&header.height.to_be_bytes());
            bytes[cursor + 8..cursor + 40].copy_from_slice(&header.block);
            bytes[cursor + 40..cursor + 48].copy_from_slice(&header.timestamp.to_be_bytes());
            cursor += 48;
        }
        bytes[cursor] = self.seed_anchor_count;
        cursor += 1;
        for anchor in &self.seed_anchors {
            bytes[cursor..cursor + 8].copy_from_slice(&anchor.height.to_be_bytes());
            bytes[cursor + 8..cursor + 40].copy_from_slice(&anchor.block);
            cursor += 40;
        }
        debug_assert_eq!(cursor, CHECKPOINT_CONTEXT_BYTES);
        Ok(bytes)
    }

    /// Decode and canonically validate one exact `UDCCTX02` value.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContextError> {
        if bytes.len() != CHECKPOINT_CONTEXT_BYTES
            || &bytes[..8] != CONTEXT_MAGIC
            || u16::from_be_bytes(context_array(bytes, 8)?) != CONTEXT_VERSION
        {
            return Err(ContextError::InvalidFraming);
        }
        let mut cursor = 86;
        let mut recent_headers = [ContextHeader {
            height: 0,
            block: [0; 32],
            timestamp: 0,
        }; MTP_HEADER_COUNT];
        for header in &mut recent_headers {
            header.height = u64::from_be_bytes(context_array(bytes, cursor)?);
            header.block = context_array(bytes, cursor + 8)?;
            header.timestamp = u64::from_be_bytes(context_array(bytes, cursor + 40)?);
            cursor += 48;
        }
        let seed_anchor_count = *bytes.get(cursor).ok_or(ContextError::InvalidFraming)?;
        cursor += 1;
        let mut seed_anchors = [SeedAnchor::default(); MAX_SEED_ANCHORS];
        for anchor in &mut seed_anchors {
            anchor.height = u64::from_be_bytes(context_array(bytes, cursor)?);
            anchor.block = context_array(bytes, cursor + 8)?;
            cursor += 40;
        }
        if cursor != bytes.len() {
            return Err(ContextError::InvalidFraming);
        }
        let context = Self {
            checkpoint_height: u64::from_be_bytes(context_array(bytes, 10)?),
            checkpoint_block: context_array(bytes, 18)?,
            max_span: u32::from_be_bytes(context_array(bytes, 50)?),
            economic_state_root: context_array(bytes, 54)?,
            recent_headers,
            seed_anchor_count,
            seed_anchors,
        };
        context.validate()?;
        if context.to_bytes()?.as_slice() != bytes {
            return Err(ContextError::InvalidFraming);
        }
        Ok(context)
    }

    /// Return the Keccak commitment carried by `UDCPST03` and the registry.
    pub fn commitment(&self) -> Result<[u8; 32], ContextError> {
        Ok(Keccak256::digest(self.to_bytes()?).into())
    }
}

/// Return the exact historical seed heights that must be carried at a
/// checkpoint for every child through `checkpoint_height + max_span`.
pub fn required_historical_seed_heights(
    checkpoint_height: u64,
    max_span: u32,
) -> Result<Vec<u64>, ContextError> {
    if max_span == 0 || max_span > MAX_CONTEXT_SPAN {
        return Err(ContextError::InvalidSpan);
    }
    let first = checkpoint_height
        .checked_add(1)
        .ok_or(ContextError::HeightOverflow)?;
    let last = checkpoint_height
        .checked_add(u64::from(max_span))
        .ok_or(ContextError::HeightOverflow)?;
    let first_epoch = first / RANDOMX_SEED_INTERVAL;
    let last_epoch = last / RANDOMX_SEED_INTERVAL;
    let mut heights = Vec::with_capacity(MAX_SEED_ANCHORS);
    for epoch in first_epoch..=last_epoch {
        let seed_height = if epoch == 0 {
            0
        } else {
            epoch
                .checked_mul(RANDOMX_SEED_INTERVAL)
                .and_then(|height| height.checked_sub(RANDOMX_SEED_OFFSET))
                .ok_or(ContextError::HeightOverflow)?
        };
        if seed_height != 0
            && seed_height <= checkpoint_height
            && heights.last().copied() != Some(seed_height)
        {
            heights.push(seed_height);
        }
    }
    if heights.len() > MAX_SEED_ANCHORS {
        return Err(ContextError::InvalidSeedAnchors);
    }
    Ok(heights)
}

/// Failure to decode or hash a canonical checkpoint statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementError {
    /// Input length, magic or version is not exact.
    InvalidFraming,
    /// A required identity is zero.
    ZeroIdentity,
    /// The proposed checkpoint does not strictly extend its predecessor.
    InvalidExtension,
}

impl fmt::Display for StatementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFraming => "invalid DOM checkpoint statement framing",
            Self::ZeroIdentity => "zero DOM checkpoint statement identity",
            Self::InvalidExtension => "invalid DOM checkpoint statement extension",
        })
    }
}

impl Error for StatementError {}

/// Public checkpoint values committed by both the proof and registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointStatement {
    /// Cross-chain bridge domain.
    pub bridge_domain: [u8; 32],
    /// DOM network magic.
    pub dom_network_magic: u32,
    /// Height of the registry's current checkpoint.
    pub previous_height: u64,
    /// DOM block identifier at `previous_height`.
    pub previous_block: [u8; 32],
    /// Native USDOM root at `previous_height`.
    pub previous_state_root: [u8; 32],
    /// Authenticated consensus continuation context at `previous_height`.
    pub previous_context_hash: [u8; 32],
    /// Cumulative DOM proof-of-work at `previous_height`.
    pub previous_total_difficulty: [u8; 32],
    /// Height of the proposed checkpoint.
    pub height: u64,
    /// Proposed canonical DOM block identifier.
    pub block: [u8; 32],
    /// Proposed native USDOM state root.
    pub state_root: [u8; 32],
    /// Authenticated consensus continuation context at the proposed checkpoint.
    pub context_hash: [u8; 32],
    /// Cumulative DOM proof-of-work at the proposed checkpoint.
    pub total_difficulty: [u8; 32],
    /// Fixed suffix height used to compare competing checkpoint branches.
    pub confirmation_height: u64,
    /// DOM block identifier at `confirmation_height`.
    pub confirmation_block: [u8; 32],
    /// Cumulative DOM proof-of-work at `confirmation_height`.
    pub confirmation_total_difficulty: [u8; 32],
    /// Timestamp of the suffix tip, bounded by Ethereum when submitted.
    pub confirmation_timestamp: u64,
    /// Ethereum chain ID as one canonical ABI uint256 word.
    pub ethereum_chain_id: [u8; 32],
    /// Immutable checkpoint registry address.
    pub registry: [u8; 20],
    /// Commitment to the ratified native v4 activation schedule.
    pub activation_schedule_commitment: [u8; 32],
    /// Exact immutable registry generation and bootstrap identity.
    pub checkpoint_config_hash: [u8; 32],
}

impl CheckpointStatement {
    /// Validate the public identity and strict extension relation.
    pub fn validate(&self) -> Result<(), StatementError> {
        if self.bridge_domain == [0; 32]
            || self.dom_network_magic == 0
            || self.previous_height == 0
            || self.previous_block == [0; 32]
            || self.previous_state_root == [0; 32]
            || self.previous_context_hash == [0; 32]
            || self.previous_total_difficulty == [0; 32]
            || self.block == [0; 32]
            || self.state_root == [0; 32]
            || self.context_hash == [0; 32]
            || self.total_difficulty == [0; 32]
            || self.confirmation_block == [0; 32]
            || self.confirmation_total_difficulty == [0; 32]
            || self.confirmation_timestamp == 0
            || self.ethereum_chain_id == [0; 32]
            || self.registry == [0; 20]
            || self.activation_schedule_commitment == [0; 32]
            || self.checkpoint_config_hash == [0; 32]
        {
            return Err(StatementError::ZeroIdentity);
        }
        if self.height <= self.previous_height
            || self.confirmation_height <= self.height
            || self.block == self.previous_block
            || self.context_hash == self.previous_context_hash
            || self.confirmation_block == self.block
            || self.total_difficulty <= self.previous_total_difficulty
            || self.confirmation_total_difficulty <= self.total_difficulty
        {
            return Err(StatementError::InvalidExtension);
        }
        Ok(())
    }

    /// Encode the unique fixed-width `UDCPST03` representation.
    pub fn to_bytes(&self) -> Result<[u8; CHECKPOINT_STATEMENT_BYTES], StatementError> {
        self.validate()?;
        let mut bytes = [0u8; CHECKPOINT_STATEMENT_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[10..42].copy_from_slice(&self.bridge_domain);
        bytes[42..46].copy_from_slice(&self.dom_network_magic.to_be_bytes());
        bytes[46..54].copy_from_slice(&self.previous_height.to_be_bytes());
        bytes[54..86].copy_from_slice(&self.previous_block);
        bytes[86..118].copy_from_slice(&self.previous_state_root);
        bytes[118..150].copy_from_slice(&self.previous_context_hash);
        bytes[150..182].copy_from_slice(&self.previous_total_difficulty);
        bytes[182..190].copy_from_slice(&self.height.to_be_bytes());
        bytes[190..222].copy_from_slice(&self.block);
        bytes[222..254].copy_from_slice(&self.state_root);
        bytes[254..286].copy_from_slice(&self.context_hash);
        bytes[286..318].copy_from_slice(&self.total_difficulty);
        bytes[318..326].copy_from_slice(&self.confirmation_height.to_be_bytes());
        bytes[326..358].copy_from_slice(&self.confirmation_block);
        bytes[358..390].copy_from_slice(&self.confirmation_total_difficulty);
        bytes[390..398].copy_from_slice(&self.confirmation_timestamp.to_be_bytes());
        bytes[398..430].copy_from_slice(&self.ethereum_chain_id);
        bytes[430..450].copy_from_slice(&self.registry);
        bytes[450..482].copy_from_slice(&self.activation_schedule_commitment);
        bytes[482..514].copy_from_slice(&self.checkpoint_config_hash);
        Ok(bytes)
    }

    /// Decode and canonically validate one exact `UDCPST03` value.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StatementError> {
        if bytes.len() != CHECKPOINT_STATEMENT_BYTES
            || &bytes[..8] != MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != VERSION
        {
            return Err(StatementError::InvalidFraming);
        }
        let statement = Self {
            bridge_domain: array(bytes, 10)?,
            dom_network_magic: u32::from_be_bytes(array(bytes, 42)?),
            previous_height: u64::from_be_bytes(array(bytes, 46)?),
            previous_block: array(bytes, 54)?,
            previous_state_root: array(bytes, 86)?,
            previous_context_hash: array(bytes, 118)?,
            previous_total_difficulty: array(bytes, 150)?,
            height: u64::from_be_bytes(array(bytes, 182)?),
            block: array(bytes, 190)?,
            state_root: array(bytes, 222)?,
            context_hash: array(bytes, 254)?,
            total_difficulty: array(bytes, 286)?,
            confirmation_height: u64::from_be_bytes(array(bytes, 318)?),
            confirmation_block: array(bytes, 326)?,
            confirmation_total_difficulty: array(bytes, 358)?,
            confirmation_timestamp: u64::from_be_bytes(array(bytes, 390)?),
            ethereum_chain_id: array(bytes, 398)?,
            registry: array(bytes, 430)?,
            activation_schedule_commitment: array(bytes, 450)?,
            checkpoint_config_hash: array(bytes, 482)?,
        };
        statement.validate()?;
        if statement.to_bytes()?.as_slice() != bytes {
            return Err(StatementError::InvalidFraming);
        }
        Ok(statement)
    }

    /// Return the exact Solidity `keccak256(abi.encode(...))` statement hash.
    pub fn statement_hash(&self) -> Result<[u8; 32], StatementError> {
        self.validate()?;
        let mut encoded = [0u8; ABI_WORDS * 32];
        encoded[..32].copy_from_slice(&Keccak256::digest(TYPE_STRING.as_bytes()));
        encoded[32..64].copy_from_slice(&self.bridge_domain);
        encoded[92..96].copy_from_slice(&self.dom_network_magic.to_be_bytes());
        encoded[120..128].copy_from_slice(&self.previous_height.to_be_bytes());
        encoded[128..160].copy_from_slice(&self.previous_block);
        encoded[160..192].copy_from_slice(&self.previous_state_root);
        encoded[192..224].copy_from_slice(&self.previous_context_hash);
        encoded[224..256].copy_from_slice(&self.previous_total_difficulty);
        encoded[280..288].copy_from_slice(&self.height.to_be_bytes());
        encoded[288..320].copy_from_slice(&self.block);
        encoded[320..352].copy_from_slice(&self.state_root);
        encoded[352..384].copy_from_slice(&self.context_hash);
        encoded[384..416].copy_from_slice(&self.total_difficulty);
        encoded[440..448].copy_from_slice(&self.confirmation_height.to_be_bytes());
        encoded[448..480].copy_from_slice(&self.confirmation_block);
        encoded[480..512].copy_from_slice(&self.confirmation_total_difficulty);
        encoded[536..544].copy_from_slice(&self.confirmation_timestamp.to_be_bytes());
        encoded[544..576].copy_from_slice(&self.ethereum_chain_id);
        encoded[588..608].copy_from_slice(&self.registry);
        encoded[608..640].copy_from_slice(&self.activation_schedule_commitment);
        encoded[640..672].copy_from_slice(&self.checkpoint_config_hash);
        Ok(Keccak256::digest(encoded).into())
    }
}

/// Candidate-v2 checkpoint statement with explicit state and batch semantics.
///
/// The legacy payload remains available for field access, but V4 has a
/// different framing and Solidity type hash and cannot be decoded as V3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointStatementV4 {
    /// Exact legacy public fields interpreted under the explicit V4 versions.
    pub checkpoint: CheckpointStatement,
}

impl CheckpointStatementV4 {
    /// Validate the legacy extension relation and the frozen V2/V3 selection.
    pub fn validate(&self) -> Result<(), StatementError> {
        self.checkpoint.validate()
    }

    /// Encode the unique fixed-width `UDCPST04` representation.
    pub fn to_bytes(&self) -> Result<[u8; CHECKPOINT_STATEMENT_V4_BYTES], StatementError> {
        self.validate()?;
        let legacy = self.checkpoint.to_bytes()?;
        let mut bytes = [0u8; CHECKPOINT_STATEMENT_V4_BYTES];
        bytes[..8].copy_from_slice(V4_MAGIC);
        bytes[8..10].copy_from_slice(&V4_VERSION.to_be_bytes());
        bytes[10..12].copy_from_slice(&CHECKPOINT_NATIVE_STATE_VERSION.to_be_bytes());
        bytes[12..14].copy_from_slice(&CHECKPOINT_TRANSITION_BATCH_VERSION.to_be_bytes());
        bytes[14..].copy_from_slice(&legacy[10..]);
        Ok(bytes)
    }

    /// Decode one exact V4 value and reject all other state/batch versions.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StatementError> {
        if bytes.len() != CHECKPOINT_STATEMENT_V4_BYTES
            || &bytes[..8] != V4_MAGIC
            || u16::from_be_bytes(array(bytes, 8)?) != V4_VERSION
            || u16::from_be_bytes(array(bytes, 10)?) != CHECKPOINT_NATIVE_STATE_VERSION
            || u16::from_be_bytes(array(bytes, 12)?) != CHECKPOINT_TRANSITION_BATCH_VERSION
        {
            return Err(StatementError::InvalidFraming);
        }
        let mut legacy = [0u8; CHECKPOINT_STATEMENT_BYTES];
        legacy[..8].copy_from_slice(MAGIC);
        legacy[8..10].copy_from_slice(&VERSION.to_be_bytes());
        legacy[10..].copy_from_slice(&bytes[14..]);
        let value = Self {
            checkpoint: CheckpointStatement::from_bytes(&legacy)?,
        };
        if value.to_bytes()?.as_slice() != bytes {
            return Err(StatementError::InvalidFraming);
        }
        Ok(value)
    }

    /// Return the exact V4 Solidity ABI statement hash.
    pub fn statement_hash(&self) -> Result<[u8; 32], StatementError> {
        self.validate()?;
        let value = &self.checkpoint;
        let mut encoded = [0u8; 23 * 32];
        encoded[..32].copy_from_slice(&Keccak256::digest(V4_TYPE_STRING.as_bytes()));
        encoded[32..64].copy_from_slice(&value.bridge_domain);
        encoded[92..96].copy_from_slice(&value.dom_network_magic.to_be_bytes());
        encoded[126..128].copy_from_slice(&CHECKPOINT_NATIVE_STATE_VERSION.to_be_bytes());
        encoded[158..160].copy_from_slice(&CHECKPOINT_TRANSITION_BATCH_VERSION.to_be_bytes());
        encoded[184..192].copy_from_slice(&value.previous_height.to_be_bytes());
        encoded[192..224].copy_from_slice(&value.previous_block);
        encoded[224..256].copy_from_slice(&value.previous_state_root);
        encoded[256..288].copy_from_slice(&value.previous_context_hash);
        encoded[288..320].copy_from_slice(&value.previous_total_difficulty);
        encoded[344..352].copy_from_slice(&value.height.to_be_bytes());
        encoded[352..384].copy_from_slice(&value.block);
        encoded[384..416].copy_from_slice(&value.state_root);
        encoded[416..448].copy_from_slice(&value.context_hash);
        encoded[448..480].copy_from_slice(&value.total_difficulty);
        encoded[504..512].copy_from_slice(&value.confirmation_height.to_be_bytes());
        encoded[512..544].copy_from_slice(&value.confirmation_block);
        encoded[544..576].copy_from_slice(&value.confirmation_total_difficulty);
        encoded[600..608].copy_from_slice(&value.confirmation_timestamp.to_be_bytes());
        encoded[608..640].copy_from_slice(&value.ethereum_chain_id);
        encoded[652..672].copy_from_slice(&value.registry);
        encoded[672..704].copy_from_slice(&value.activation_schedule_commitment);
        encoded[704..736].copy_from_slice(&value.checkpoint_config_hash);
        Ok(Keccak256::digest(encoded).into())
    }
}

/// Candidate-v2 checkpoint statement with authenticated economic totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointStatementV5 {
    /// Exact V4 consensus/checkpoint fields.
    pub checkpoint: CheckpointStatement,
    /// Deposit-backed issuance at the selected checkpoint height.
    pub total_issued: u128,
    /// Native burns at the selected checkpoint height.
    pub total_burned: u128,
}

impl CheckpointStatementV5 {
    /// Validate the checkpoint relation and economic conservation bound.
    pub fn validate(&self) -> Result<(), StatementError> {
        self.checkpoint.validate()?;
        if self.total_burned > self.total_issued {
            return Err(StatementError::InvalidExtension);
        }
        Ok(())
    }

    /// Encode the unique fixed-width `UDCPST05` representation.
    pub fn to_bytes(&self) -> Result<[u8; CHECKPOINT_STATEMENT_V5_BYTES], StatementError> {
        self.validate()?;
        let v4 = CheckpointStatementV4 {
            checkpoint: self.checkpoint,
        }
        .to_bytes()?;
        let mut bytes = [0u8; CHECKPOINT_STATEMENT_V5_BYTES];
        bytes[..8].copy_from_slice(V5_MAGIC);
        bytes[8..10].copy_from_slice(&V5_VERSION.to_be_bytes());
        bytes[10..CHECKPOINT_STATEMENT_V4_BYTES].copy_from_slice(&v4[10..]);
        bytes[12..14].copy_from_slice(&CHECKPOINT_TRANSITION_BATCH_V5_VERSION.to_be_bytes());
        bytes[CHECKPOINT_STATEMENT_V4_BYTES..CHECKPOINT_STATEMENT_V4_BYTES + 16]
            .copy_from_slice(&self.total_issued.to_be_bytes());
        bytes[CHECKPOINT_STATEMENT_V4_BYTES + 16..]
            .copy_from_slice(&self.total_burned.to_be_bytes());
        Ok(bytes)
    }

    /// Decode only the V5 frame; V3/V4 bytes remain distinct and fail closed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StatementError> {
        if bytes.len() != CHECKPOINT_STATEMENT_V5_BYTES
            || &bytes[..8] != V5_MAGIC
            || u16::from_be_bytes(array(bytes, 8)?) != V5_VERSION
            || u16::from_be_bytes(array(bytes, 12)?) != CHECKPOINT_TRANSITION_BATCH_V5_VERSION
        {
            return Err(StatementError::InvalidFraming);
        }
        let mut v4 = [0u8; CHECKPOINT_STATEMENT_V4_BYTES];
        v4[..8].copy_from_slice(V4_MAGIC);
        v4[8..10].copy_from_slice(&V4_VERSION.to_be_bytes());
        v4[10..].copy_from_slice(&bytes[10..CHECKPOINT_STATEMENT_V4_BYTES]);
        v4[12..14].copy_from_slice(&CHECKPOINT_TRANSITION_BATCH_VERSION.to_be_bytes());
        let value = Self {
            checkpoint: CheckpointStatementV4::from_bytes(&v4)?.checkpoint,
            total_issued: u128::from_be_bytes(array(bytes, CHECKPOINT_STATEMENT_V4_BYTES)?),
            total_burned: u128::from_be_bytes(array(bytes, CHECKPOINT_STATEMENT_V4_BYTES + 16)?),
        };
        value.validate()?;
        if value.to_bytes()?.as_slice() != bytes {
            return Err(StatementError::InvalidFraming);
        }
        Ok(value)
    }

    /// Return the exact `DOMCheckpointV3` Solidity ABI statement hash.
    pub fn statement_hash(&self) -> Result<[u8; 32], StatementError> {
        self.validate()?;
        let v = &self.checkpoint;
        let mut encoded = [0u8; 25 * 32];
        encoded[..32].copy_from_slice(&Keccak256::digest(V5_TYPE_STRING.as_bytes()));
        encoded[32..64].copy_from_slice(&v.bridge_domain);
        encoded[92..96].copy_from_slice(&v.dom_network_magic.to_be_bytes());
        encoded[126..128].copy_from_slice(&CHECKPOINT_NATIVE_STATE_VERSION.to_be_bytes());
        encoded[158..160].copy_from_slice(&CHECKPOINT_TRANSITION_BATCH_V5_VERSION.to_be_bytes());
        encoded[184..192].copy_from_slice(&v.previous_height.to_be_bytes());
        encoded[192..224].copy_from_slice(&v.previous_block);
        encoded[224..256].copy_from_slice(&v.previous_state_root);
        encoded[256..288].copy_from_slice(&v.previous_context_hash);
        encoded[288..320].copy_from_slice(&v.previous_total_difficulty);
        encoded[344..352].copy_from_slice(&v.height.to_be_bytes());
        encoded[352..384].copy_from_slice(&v.block);
        encoded[384..416].copy_from_slice(&v.state_root);
        encoded[416..448].copy_from_slice(&v.context_hash);
        encoded[448..480].copy_from_slice(&v.total_difficulty);
        encoded[496..512].copy_from_slice(&self.total_issued.to_be_bytes());
        encoded[528..544].copy_from_slice(&self.total_burned.to_be_bytes());
        encoded[568..576].copy_from_slice(&v.confirmation_height.to_be_bytes());
        encoded[576..608].copy_from_slice(&v.confirmation_block);
        encoded[608..640].copy_from_slice(&v.confirmation_total_difficulty);
        encoded[664..672].copy_from_slice(&v.confirmation_timestamp.to_be_bytes());
        encoded[672..704].copy_from_slice(&v.ethereum_chain_id);
        encoded[716..736].copy_from_slice(&v.registry);
        encoded[736..768].copy_from_slice(&v.activation_schedule_commitment);
        encoded[768..800].copy_from_slice(&v.checkpoint_config_hash);
        Ok(Keccak256::digest(encoded).into())
    }
}

/// Closure-aware checkpoint statement. Historical V5 statements cannot
/// authorize graceful shutdown because they do not carry this authenticated bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointStatementV6 {
    /// Exact checkpoint fields.
    pub checkpoint: CheckpointStatement,
    /// Deposit-backed issuance at the selected checkpoint height.
    pub total_issued: u128,
    /// Native burns at the selected checkpoint height.
    pub total_burned: u128,
    /// Authenticated terminal issuance boundary at the selected height.
    pub issuance_closed: bool,
}

impl CheckpointStatementV6 {
    /// Validate checkpoint identity and economic conservation.
    pub fn validate(&self) -> Result<(), StatementError> {
        self.checkpoint.validate()?;
        if self.total_burned > self.total_issued {
            return Err(StatementError::InvalidExtension);
        }
        Ok(())
    }

    /// Encode the unique fixed-width `UDCPST06` representation.
    pub fn to_bytes(&self) -> Result<[u8; CHECKPOINT_STATEMENT_V6_BYTES], StatementError> {
        self.validate()?;
        let legacy = self.checkpoint.to_bytes()?;
        let mut bytes = [0u8; CHECKPOINT_STATEMENT_V6_BYTES];
        bytes[..8].copy_from_slice(V6_MAGIC);
        bytes[8..10].copy_from_slice(&V6_VERSION.to_be_bytes());
        bytes[10..12].copy_from_slice(&CHECKPOINT_NATIVE_STATE_V6_VERSION.to_be_bytes());
        bytes[12..14].copy_from_slice(&CHECKPOINT_TRANSITION_BATCH_V5_VERSION.to_be_bytes());
        bytes[14..CHECKPOINT_STATEMENT_V4_BYTES].copy_from_slice(&legacy[10..]);
        bytes[CHECKPOINT_STATEMENT_V4_BYTES..CHECKPOINT_STATEMENT_V4_BYTES + 16]
            .copy_from_slice(&self.total_issued.to_be_bytes());
        bytes[CHECKPOINT_STATEMENT_V4_BYTES + 16..CHECKPOINT_STATEMENT_V5_BYTES]
            .copy_from_slice(&self.total_burned.to_be_bytes());
        bytes[CHECKPOINT_STATEMENT_V5_BYTES] = u8::from(self.issuance_closed);
        Ok(bytes)
    }

    /// Decode only closure-aware V6 framing and reject noncanonical flags.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StatementError> {
        if bytes.len() != CHECKPOINT_STATEMENT_V6_BYTES
            || &bytes[..8] != V6_MAGIC
            || u16::from_be_bytes(array(bytes, 8)?) != V6_VERSION
            || u16::from_be_bytes(array(bytes, 10)?) != CHECKPOINT_NATIVE_STATE_V6_VERSION
            || u16::from_be_bytes(array(bytes, 12)?) != CHECKPOINT_TRANSITION_BATCH_V5_VERSION
        {
            return Err(StatementError::InvalidFraming);
        }
        let issuance_closed = match bytes[CHECKPOINT_STATEMENT_V5_BYTES] {
            0 => false,
            1 => true,
            _ => return Err(StatementError::InvalidFraming),
        };
        let mut legacy = [0u8; CHECKPOINT_STATEMENT_BYTES];
        legacy[..8].copy_from_slice(MAGIC);
        legacy[8..10].copy_from_slice(&VERSION.to_be_bytes());
        legacy[10..].copy_from_slice(&bytes[14..CHECKPOINT_STATEMENT_V4_BYTES]);
        let value = Self {
            checkpoint: CheckpointStatement::from_bytes(&legacy)?,
            total_issued: u128::from_be_bytes(array(bytes, CHECKPOINT_STATEMENT_V4_BYTES)?),
            total_burned: u128::from_be_bytes(array(bytes, CHECKPOINT_STATEMENT_V4_BYTES + 16)?),
            issuance_closed,
        };
        value.validate()?;
        if value.to_bytes()?.as_slice() != bytes {
            return Err(StatementError::InvalidFraming);
        }
        Ok(value)
    }

    /// Return the exact `DOMCheckpointV4` Solidity ABI statement hash.
    pub fn statement_hash(&self) -> Result<[u8; 32], StatementError> {
        self.validate()?;
        let v = &self.checkpoint;
        let mut encoded = [0u8; 26 * 32];
        encoded[..32].copy_from_slice(&Keccak256::digest(V6_TYPE_STRING.as_bytes()));
        encoded[32..64].copy_from_slice(&v.bridge_domain);
        encoded[92..96].copy_from_slice(&v.dom_network_magic.to_be_bytes());
        encoded[126..128].copy_from_slice(&CHECKPOINT_NATIVE_STATE_V6_VERSION.to_be_bytes());
        encoded[158..160].copy_from_slice(&CHECKPOINT_TRANSITION_BATCH_V5_VERSION.to_be_bytes());
        encoded[184..192].copy_from_slice(&v.previous_height.to_be_bytes());
        encoded[192..224].copy_from_slice(&v.previous_block);
        encoded[224..256].copy_from_slice(&v.previous_state_root);
        encoded[256..288].copy_from_slice(&v.previous_context_hash);
        encoded[288..320].copy_from_slice(&v.previous_total_difficulty);
        encoded[344..352].copy_from_slice(&v.height.to_be_bytes());
        encoded[352..384].copy_from_slice(&v.block);
        encoded[384..416].copy_from_slice(&v.state_root);
        encoded[416..448].copy_from_slice(&v.context_hash);
        encoded[448..480].copy_from_slice(&v.total_difficulty);
        encoded[496..512].copy_from_slice(&self.total_issued.to_be_bytes());
        encoded[528..544].copy_from_slice(&self.total_burned.to_be_bytes());
        encoded[575] = u8::from(self.issuance_closed);
        encoded[600..608].copy_from_slice(&v.confirmation_height.to_be_bytes());
        encoded[608..640].copy_from_slice(&v.confirmation_block);
        encoded[640..672].copy_from_slice(&v.confirmation_total_difficulty);
        encoded[696..704].copy_from_slice(&v.confirmation_timestamp.to_be_bytes());
        encoded[704..736].copy_from_slice(&v.ethereum_chain_id);
        encoded[748..768].copy_from_slice(&v.registry);
        encoded[768..800].copy_from_slice(&v.activation_schedule_commitment);
        encoded[800..832].copy_from_slice(&v.checkpoint_config_hash);
        Ok(Keccak256::digest(encoded).into())
    }
}

/// Decode the exact public statement and emit only its raw 32-byte hash.
///
/// This function intentionally does not accept a private consensus witness and
/// therefore is not a checkpoint verifier. It freezes the public I/O relation
/// that a separately reviewed proving guest must use after consensus validation.
pub fn hash_canonical_statement(bytes: &[u8]) -> Result<[u8; 32], StatementError> {
    CheckpointStatement::from_bytes(bytes)?.statement_hash()
}

/// Decode the exact candidate-v2 public statement and return its V4 hash.
pub fn hash_canonical_statement_v4(bytes: &[u8]) -> Result<[u8; 32], StatementError> {
    CheckpointStatementV4::from_bytes(bytes)?.statement_hash()
}

/// Decode the economic statement and return its exact V5/V3 ABI hash.
pub fn hash_canonical_statement_v5(bytes: &[u8]) -> Result<[u8; 32], StatementError> {
    CheckpointStatementV5::from_bytes(bytes)?.statement_hash()
}

/// Decode the closure-aware statement and return its exact V6/V4 ABI hash.
pub fn hash_canonical_statement_v6(bytes: &[u8]) -> Result<[u8; 32], StatementError> {
    CheckpointStatementV6::from_bytes(bytes)?.statement_hash()
}

fn array<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], StatementError> {
    bytes
        .get(start..start + N)
        .ok_or(StatementError::InvalidFraming)?
        .try_into()
        .map_err(|_| StatementError::InvalidFraming)
}

fn context_array<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], ContextError> {
    bytes
        .get(start..start + N)
        .ok_or(ContextError::InvalidFraming)?
        .try_into()
        .map_err(|_| ContextError::InvalidFraming)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uint256(value: u64) -> [u8; 32] {
        let mut encoded = [0u8; 32];
        encoded[24..].copy_from_slice(&value.to_be_bytes());
        encoded
    }

    fn vector() -> CheckpointStatement {
        let mut chain_id = [0u8; 32];
        chain_id[31] = 1;
        CheckpointStatement {
            bridge_domain: [0x22; 32],
            dom_network_magic: 2_712_847_316,
            previous_height: 100_000,
            previous_block: [0x99; 32],
            previous_state_root: [0xaa; 32],
            previous_context_hash: [0xee; 32],
            previous_total_difficulty: uint256(1_000_000),
            height: 100_360,
            block: [0xbb; 32],
            state_root: [0xcc; 32],
            context_hash: [0xff; 32],
            total_difficulty: uint256(1_000_360),
            confirmation_height: 100_390,
            confirmation_block: [0xdd; 32],
            confirmation_total_difficulty: uint256(1_000_390),
            confirmation_timestamp: 1_700_000_000,
            ethereum_chain_id: chain_id,
            registry: [0x11; 20],
            activation_schedule_commitment: [0x33; 32],
            checkpoint_config_hash: hex::decode(
                "4ab7848ffc06d09ea7462a0ff65ec55e364749839a79a71815171dd1543a1615",
            )
            .expect("frozen config hash")
            .try_into()
            .expect("32-byte config hash"),
        }
    }

    fn context(height: u64, max_span: u32) -> CheckpointContext {
        let first = height - 10;
        let recent_headers = std::array::from_fn(|index| ContextHeader {
            height: first + index as u64,
            block: [index as u8 + 1; 32],
            timestamp: 1_700_000_000 + index as u64,
        });
        let checkpoint_block = recent_headers[10].block;
        let required = required_historical_seed_heights(height, max_span).expect("seed schedule");
        let mut seed_anchors = [SeedAnchor::default(); MAX_SEED_ANCHORS];
        for (index, seed_height) in required.iter().copied().enumerate() {
            seed_anchors[index] = SeedAnchor {
                height: seed_height,
                block: if let Some(header) = recent_headers.iter().find(|h| h.height == seed_height)
                {
                    header.block
                } else {
                    [0x80 + index as u8; 32]
                },
            };
        }
        CheckpointContext {
            checkpoint_height: height,
            checkpoint_block,
            max_span,
            economic_state_root: [0x82; 32],
            recent_headers,
            seed_anchor_count: required.len() as u8,
            seed_anchors,
        }
    }

    #[test]
    fn continuation_context_round_trips_and_commits_every_byte() {
        // 1,984 is already in the ancestry and becomes the seed at block 2,048.
        let value = context(2_000, 390);
        assert_eq!(value.seed_anchor_count, 1);
        assert_eq!(value.seed_anchors[0].height, 1_984);
        // Both epoch-1 and epoch-2 seeds are historic just before epoch 2.
        let two = context(4_050, 390);
        assert_eq!(two.seed_anchor_count, 2);
        assert_eq!(two.seed_anchors[0].height, 1_984);
        assert_eq!(two.seed_anchors[1].height, 4_032);

        let bytes = two.to_bytes().expect("encode context");
        assert_eq!(bytes.len(), CHECKPOINT_CONTEXT_BYTES);
        assert_eq!(
            CheckpointContext::from_bytes(&bytes).expect("decode context"),
            two
        );
        let commitment = two.commitment().expect("commit context");
        assert_eq!(
            hex::encode(commitment),
            "7bb5a7a3b2cfb770abe46d3c2050fc42429246b71acf0ed27523711ad24d1c80"
        );
        let mut changed = two;
        changed.recent_headers[0].block[0] ^= 1;
        assert_ne!(changed.commitment().expect("changed context"), commitment);
        changed = two;
        changed.seed_anchors[1].block[0] ^= 1;
        assert_ne!(changed.commitment().expect("changed seed"), commitment);
        changed = two;
        changed.economic_state_root[0] ^= 1;
        assert_ne!(changed.commitment().expect("changed economy"), commitment);
    }

    #[test]
    fn economic_state_commitment_is_ordered_and_domain_separated() {
        let root =
            checkpoint_economic_state_root([0x83; 32], [0x84; 32]).expect("economic state root");
        assert_eq!(
            hex::encode(root),
            "92b53aa48ec606fdff0e2159cd11ba2651de6d3c2ac6146092d3712a77e3e50f"
        );
        assert_ne!(
            root,
            checkpoint_economic_state_root([0x84; 32], [0x83; 32])
                .expect("ordered economic state root")
        );
        assert_eq!(
            checkpoint_economic_state_root([0; 32], [0x84; 32]),
            Err(ContextError::InvalidHistory)
        );
    }

    #[test]
    fn continuation_context_rejects_missing_extra_and_inconsistent_authority() {
        let value = context(4_050, 390);
        let mut wrong = value;
        wrong.seed_anchor_count = 1;
        assert_eq!(wrong.validate(), Err(ContextError::InvalidSeedAnchors));
        wrong = value;
        wrong.seed_anchors[1].height -= 1;
        assert_eq!(wrong.validate(), Err(ContextError::InvalidSeedAnchors));
        wrong = value;
        wrong.recent_headers[5].timestamp = wrong.recent_headers[4].timestamp;
        assert_eq!(wrong.validate(), Err(ContextError::InvalidHistory));
        wrong = context(1_993, 100);
        assert_eq!(wrong.seed_anchors[0].height, 1_984);
        // The required seed is inside the MTP projection and must name that block.
        wrong.seed_anchors[0].block[0] ^= 1;
        assert_eq!(wrong.validate(), Err(ContextError::InvalidSeedAnchors));

        let bytes = value.to_bytes().expect("valid context");
        for end in 0..bytes.len() {
            assert!(CheckpointContext::from_bytes(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert_eq!(
            CheckpointContext::from_bytes(&trailing),
            Err(ContextError::InvalidFraming)
        );
    }

    #[test]
    fn seed_schedule_handles_boundaries_and_overflow() {
        assert_eq!(
            required_historical_seed_heights(1_900, 100).unwrap(),
            Vec::<u64>::new()
        );
        assert_eq!(
            required_historical_seed_heights(1_984, 64).unwrap(),
            vec![1_984]
        );
        assert_eq!(
            required_historical_seed_heights(2_000, 390).unwrap(),
            vec![1_984]
        );
        assert_eq!(
            required_historical_seed_heights(4_050, 390).unwrap(),
            vec![1_984, 4_032]
        );
        assert_eq!(
            required_historical_seed_heights(u64::MAX, 1),
            Err(ContextError::HeightOverflow)
        );
        assert_eq!(
            required_historical_seed_heights(1_000, MAX_CONTEXT_SPAN + 1),
            Err(ContextError::InvalidSpan)
        );
    }

    #[test]
    fn continuation_seed_schedule_matches_dom_consensus() {
        assert_eq!(RANDOMX_SEED_INTERVAL, dom_pow::RANDOMX_SEED_INTERVAL);
        assert_eq!(RANDOMX_SEED_OFFSET, dom_pow::RANDOMX_SEED_OFFSET);
        for height in [
            0,
            1,
            1_983,
            1_984,
            2_047,
            2_048,
            4_031,
            4_032,
            4_095,
            4_096,
            u32::MAX as u64,
        ] {
            let local = if height / RANDOMX_SEED_INTERVAL == 0 {
                0
            } else {
                (height / RANDOMX_SEED_INTERVAL) * RANDOMX_SEED_INTERVAL - RANDOMX_SEED_OFFSET
            };
            assert_eq!(local, dom_pow::randomx_seed_height(height));
        }
    }

    #[test]
    fn rust_hash_matches_solidity_and_javascript_vector() {
        let statement = vector();
        assert_eq!(
            hex::encode(statement.statement_hash().expect("valid statement")),
            "ecf78a2c48d81ad85f614fb23a156b7ca6a97f33c32402e3fd88eaa7f017d625"
        );
        let encoded = statement.to_bytes().expect("valid encoding");
        assert_eq!(encoded.len(), CHECKPOINT_STATEMENT_BYTES);
        assert_eq!(
            CheckpointStatement::from_bytes(&encoded).expect("round trip"),
            statement
        );
        assert_eq!(
            hash_canonical_statement(&encoded).expect("hash canonical"),
            statement.statement_hash().expect("hash struct")
        );
    }

    #[test]
    fn v4_explicitly_selects_native_v2_and_batch_v3() {
        let statement = CheckpointStatementV4 {
            checkpoint: vector(),
        };
        let bytes = statement.to_bytes().expect("v4 encoding");
        assert_eq!(bytes.len(), CHECKPOINT_STATEMENT_V4_BYTES);
        assert_eq!(
            CheckpointStatementV4::from_bytes(&bytes).unwrap(),
            statement
        );
        assert_ne!(
            statement.statement_hash().unwrap(),
            statement.checkpoint.statement_hash().unwrap()
        );
        assert_eq!(
            hex::encode(statement.statement_hash().unwrap()),
            "aea1d132059ed25184d27671e5c52061f53f6f767074d6aa10c0ce35fc11249e"
        );
        assert!(CheckpointStatement::from_bytes(&bytes).is_err());
        let mut wrong_state = bytes;
        wrong_state[11] ^= 1;
        assert!(CheckpointStatementV4::from_bytes(&wrong_state).is_err());
        let mut wrong_batch = bytes;
        wrong_batch[13] ^= 1;
        assert!(CheckpointStatementV4::from_bytes(&wrong_batch).is_err());
    }

    #[test]
    fn v5_is_economically_bound_and_disjoint_from_frozen_v4() {
        let v4 = CheckpointStatementV4 {
            checkpoint: vector(),
        };
        let v4_bytes = v4.to_bytes().unwrap();
        assert_eq!(
            hex::encode(v4.statement_hash().unwrap()),
            "aea1d132059ed25184d27671e5c52061f53f6f767074d6aa10c0ce35fc11249e"
        );
        let v5 = CheckpointStatementV5 {
            checkpoint: vector(),
            total_issued: 1_000_000,
            total_burned: 250_000,
        };
        let v5_bytes = v5.to_bytes().unwrap();
        assert_eq!(CheckpointStatementV5::from_bytes(&v5_bytes).unwrap(), v5);
        assert_eq!(
            &v5_bytes[CHECKPOINT_STATEMENT_V4_BYTES..CHECKPOINT_STATEMENT_V4_BYTES + 16],
            &v5.total_issued.to_be_bytes()
        );
        assert_eq!(
            &v5_bytes[CHECKPOINT_STATEMENT_V4_BYTES + 16..],
            &v5.total_burned.to_be_bytes()
        );
        assert!(CheckpointStatementV5::from_bytes(&v4_bytes).is_err());
        assert!(CheckpointStatementV4::from_bytes(&v5_bytes).is_err());
        let expected_hash = v5.statement_hash().unwrap();
        let mut changed_issued = v5;
        changed_issued.total_issued += 1;
        assert_ne!(changed_issued.statement_hash().unwrap(), expected_hash);
        let mut changed_burned = v5;
        changed_burned.total_burned += 1;
        assert_ne!(changed_burned.statement_hash().unwrap(), expected_hash);
        let mut regressed = v5;
        regressed.total_burned = regressed.total_issued + 1;
        assert_eq!(regressed.validate(), Err(StatementError::InvalidExtension));
    }

    #[test]
    fn v6_binds_canonical_issuance_closure_and_rejects_v5_replay() {
        let open = CheckpointStatementV6 {
            checkpoint: vector(),
            total_issued: 1_000_000,
            total_burned: 1_000_000,
            issuance_closed: false,
        };
        let open_bytes = open.to_bytes().unwrap();
        assert_eq!(
            CheckpointStatementV6::from_bytes(&open_bytes).unwrap(),
            open
        );
        let closed = CheckpointStatementV6 {
            issuance_closed: true,
            ..open
        };
        assert_ne!(
            open.statement_hash().unwrap(),
            closed.statement_hash().unwrap()
        );
        let closed_bytes = closed.to_bytes().unwrap();
        assert_eq!(closed_bytes[CHECKPOINT_STATEMENT_V5_BYTES], 1);
        let mut noncanonical = closed_bytes;
        noncanonical[CHECKPOINT_STATEMENT_V5_BYTES] = 2;
        assert!(CheckpointStatementV6::from_bytes(&noncanonical).is_err());
        let v5 = CheckpointStatementV5 {
            checkpoint: vector(),
            total_issued: 1_000_000,
            total_burned: 1_000_000,
        };
        assert!(CheckpointStatementV6::from_bytes(&v5.to_bytes().unwrap()).is_err());
    }

    #[test]
    fn every_public_field_is_hash_bound() {
        let original = vector();
        let expected = original.statement_hash().expect("valid vector");
        let mutations: [fn(&mut CheckpointStatement); 20] = [
            |v| v.bridge_domain[0] ^= 1,
            |v| v.dom_network_magic -= 1,
            |v| v.previous_height -= 1,
            |v| v.previous_block[0] ^= 1,
            |v| v.previous_state_root[0] ^= 1,
            |v| v.previous_context_hash[0] ^= 1,
            |v| v.previous_total_difficulty[31] -= 1,
            |v| v.height += 1,
            |v| v.block[0] ^= 1,
            |v| v.state_root[0] ^= 1,
            |v| v.context_hash[0] ^= 1,
            |v| v.total_difficulty[31] += 1,
            |v| v.confirmation_height += 1,
            |v| v.confirmation_block[0] ^= 1,
            |v| v.confirmation_total_difficulty[31] += 1,
            |v| v.confirmation_timestamp += 1,
            |v| v.ethereum_chain_id[31] = 2,
            |v| v.registry[0] ^= 1,
            |v| v.activation_schedule_commitment[0] ^= 1,
            |v| v.checkpoint_config_hash[0] ^= 1,
        ];
        for mutate in mutations {
            let mut changed = original;
            mutate(&mut changed);
            assert_ne!(changed.statement_hash().expect("valid mutation"), expected);
        }
    }

    #[test]
    fn randomx_statement_is_canonical_and_binds_every_relation_input() {
        let height = 2_048u64;
        let compact = 0x1e7f_ffffu32;
        let mut preimage = [0u8; CHECKPOINT_RANDOMX_PREIMAGE_BYTES];
        preimage[..4].copy_from_slice(&CHECKPOINT_RANDOMX_BLOCK_VERSION.to_le_bytes());
        preimage[CHECKPOINT_RANDOMX_PREIMAGE_HEIGHT_OFFSET
            ..CHECKPOINT_RANDOMX_PREIMAGE_HEIGHT_OFFSET + 8]
            .copy_from_slice(&height.to_le_bytes());
        preimage[CHECKPOINT_RANDOMX_PREIMAGE_TARGET_OFFSET
            ..CHECKPOINT_RANDOMX_PREIMAGE_TARGET_OFFSET + 4]
            .copy_from_slice(&compact.to_le_bytes());
        let mut randomx_hash = [0u8; 32];
        randomx_hash[31] = 1;
        let statement = CheckpointRandomXStatement {
            network_magic: 0xA1B2_C3D4,
            chain_id: [0x11; 32],
            block_height: height,
            seed_height: checkpoint_randomx_seed_height(height),
            seed_hash: [0x12; 32],
            pow_preimage: preimage,
            randomx_hash,
            target: checkpoint_compact_target(compact).unwrap(),
        };
        let bytes = statement.to_bytes().unwrap();
        assert_eq!(bytes.len(), CHECKPOINT_RANDOMX_STATEMENT_BYTES);
        assert_eq!(
            CheckpointRandomXStatement::from_bytes(&bytes).unwrap(),
            statement
        );
        let commitment = statement.commitment().unwrap();
        let mut changed = statement;
        changed.seed_hash[0] ^= 1;
        assert_ne!(changed.commitment().unwrap(), commitment);
        changed = statement;
        changed.pow_preimage[CHECKPOINT_RANDOMX_PREIMAGE_BYTES - 1] ^= 1;
        assert_ne!(changed.commitment().unwrap(), commitment);
        changed = statement;
        changed.seed_height += 1;
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
        for end in 0..bytes.len() {
            assert!(CheckpointRandomXStatement::from_bytes(&bytes[..end]).is_err());
        }
    }

    #[test]
    fn malformed_zero_and_nonextending_inputs_fail_closed() {
        let bytes = vector().to_bytes().expect("valid vector");
        for end in 0..bytes.len() {
            assert!(CheckpointStatement::from_bytes(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(CheckpointStatement::from_bytes(&trailing).is_err());
        let mut wrong_magic = bytes;
        wrong_magic[0] ^= 1;
        assert!(CheckpointStatement::from_bytes(&wrong_magic).is_err());
        let mut wrong_version = bytes;
        wrong_version[9] = 1;
        assert!(CheckpointStatement::from_bytes(&wrong_version).is_err());

        let mut zero = vector();
        zero.state_root = [0; 32];
        assert_eq!(zero.validate(), Err(StatementError::ZeroIdentity));
        let mut zero_timestamp = vector();
        zero_timestamp.confirmation_timestamp = 0;
        assert_eq!(zero_timestamp.validate(), Err(StatementError::ZeroIdentity));
        let mut same_height = vector();
        same_height.height = same_height.previous_height;
        assert_eq!(
            same_height.validate(),
            Err(StatementError::InvalidExtension)
        );
        let mut same_block = vector();
        same_block.block = same_block.previous_block;
        assert_eq!(same_block.validate(), Err(StatementError::InvalidExtension));
        let mut same_context = vector();
        same_context.context_hash = same_context.previous_context_hash;
        assert_eq!(
            same_context.validate(),
            Err(StatementError::InvalidExtension)
        );
        let mut non_increasing_work = vector();
        non_increasing_work.total_difficulty = non_increasing_work.previous_total_difficulty;
        assert_eq!(
            non_increasing_work.validate(),
            Err(StatementError::InvalidExtension)
        );
        let mut invalid_confirmation = vector();
        invalid_confirmation.confirmation_height = invalid_confirmation.height;
        assert_eq!(
            invalid_confirmation.validate(),
            Err(StatementError::InvalidExtension)
        );
    }
}
