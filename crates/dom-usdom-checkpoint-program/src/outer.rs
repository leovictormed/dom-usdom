//! Portable recursive composition of complete checkpoint-segment receipts.

use super::{
    CheckpointSegmentNativeStateOpening, CheckpointSegmentPolicyInput, CheckpointSegmentState,
    CheckpointSegmentTransition, CHECKPOINT_SEGMENT_TRANSITION_BYTES,
    MAX_CHECKPOINT_SEGMENT_BLOCKS,
};
use dom_usdom_checkpoint_statement::{CheckpointStatementV4, MAX_CONTEXT_SPAN};
use thiserror::Error;

const OUTER_CHAIN_MAGIC: &[u8; 8] = b"UDCOUT01";
const OUTER_CHAIN_VERSION: u16 = 1;
const OUTER_CHAIN_HEADER_BYTES: usize = 12;

/// Maximum number of complete segments in one checkpoint continuation.
///
/// A prover may use one segment per block when package or witness byte limits
/// prevent a larger segment. The public context span still bounds the number
/// of recursive assumptions, so this flexibility cannot create an unbounded
/// outer input.
pub const MAX_CHECKPOINT_OUTER_SEGMENTS: usize = MAX_CONTEXT_SPAN as usize;

/// Maximum encoded `UDCOUT01` chain input accepted by the outer guest.
pub const MAX_CHECKPOINT_OUTER_CHAIN_BYTES: usize =
    OUTER_CHAIN_HEADER_BYTES + MAX_CHECKPOINT_OUTER_SEGMENTS * CHECKPOINT_SEGMENT_TRANSITION_BYTES;

/// Canonically encoded ordered segment transitions consumed by the outer guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointOuterChain {
    transitions: Vec<CheckpointSegmentTransition>,
}

/// Failure while decoding or recursively composing a checkpoint chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CheckpointOuterChainError {
    /// Magic, version, length, count, or canonical representation is invalid.
    #[error("invalid outer checkpoint chain framing")]
    InvalidFraming,
    /// The public checkpoint statement is invalid or does not match policy.
    #[error("invalid outer checkpoint statement")]
    InvalidStatement,
    /// The first segment does not open the registry's previous checkpoint.
    #[error("outer checkpoint previous state mismatch")]
    PreviousMismatch,
    /// Segment order, size, target boundary, or terminal boundary is invalid.
    #[error("invalid outer checkpoint segment chain")]
    InvalidChain,
    /// The target checkpoint state does not match the public statement.
    #[error("outer checkpoint target state mismatch")]
    TargetMismatch,
    /// The confirmation suffix does not match the public statement.
    #[error("outer checkpoint confirmation state mismatch")]
    ConfirmationMismatch,
    /// The expected segment ImageID is zero.
    #[error("invalid outer checkpoint segment ImageID")]
    InvalidImageId,
}

impl CheckpointOuterChain {
    /// Construct a bounded ordered transition chain.
    pub fn new(
        transitions: Vec<CheckpointSegmentTransition>,
    ) -> Result<Self, CheckpointOuterChainError> {
        if transitions.is_empty() || transitions.len() > MAX_CHECKPOINT_OUTER_SEGMENTS {
            return Err(CheckpointOuterChainError::InvalidFraming);
        }
        for transition in &transitions {
            transition
                .validate()
                .map_err(|_| CheckpointOuterChainError::InvalidChain)?;
        }
        Ok(Self { transitions })
    }

    /// Ordered segment transitions.
    pub fn transitions(&self) -> &[CheckpointSegmentTransition] {
        &self.transitions
    }

    /// Encode the unique bounded `UDCOUT01` representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CheckpointOuterChainError> {
        if self.transitions.is_empty() || self.transitions.len() > MAX_CHECKPOINT_OUTER_SEGMENTS {
            return Err(CheckpointOuterChainError::InvalidFraming);
        }
        let mut bytes = Vec::with_capacity(
            OUTER_CHAIN_HEADER_BYTES + self.transitions.len() * CHECKPOINT_SEGMENT_TRANSITION_BYTES,
        );
        bytes.extend_from_slice(OUTER_CHAIN_MAGIC);
        bytes.extend_from_slice(&OUTER_CHAIN_VERSION.to_be_bytes());
        bytes.extend_from_slice(
            &u16::try_from(self.transitions.len())
                .map_err(|_| CheckpointOuterChainError::InvalidFraming)?
                .to_be_bytes(),
        );
        for transition in &self.transitions {
            bytes.extend_from_slice(
                &transition
                    .to_bytes()
                    .map_err(|_| CheckpointOuterChainError::InvalidChain)?,
            );
        }
        Ok(bytes)
    }

    /// Decode, validate and canonically re-encode one `UDCOUT01` input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CheckpointOuterChainError> {
        if bytes.len() < OUTER_CHAIN_HEADER_BYTES + CHECKPOINT_SEGMENT_TRANSITION_BYTES
            || bytes.len() > MAX_CHECKPOINT_OUTER_CHAIN_BYTES
            || bytes.get(..8) != Some(OUTER_CHAIN_MAGIC.as_slice())
            || u16::from_be_bytes(
                bytes[8..10]
                    .try_into()
                    .map_err(|_| CheckpointOuterChainError::InvalidFraming)?,
            ) != OUTER_CHAIN_VERSION
        {
            return Err(CheckpointOuterChainError::InvalidFraming);
        }
        let count = usize::from(u16::from_be_bytes(
            bytes[10..12]
                .try_into()
                .map_err(|_| CheckpointOuterChainError::InvalidFraming)?,
        ));
        let expected = OUTER_CHAIN_HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(CHECKPOINT_SEGMENT_TRANSITION_BYTES)
                    .ok_or(CheckpointOuterChainError::InvalidFraming)?,
            )
            .ok_or(CheckpointOuterChainError::InvalidFraming)?;
        if count == 0 || count > MAX_CHECKPOINT_OUTER_SEGMENTS || bytes.len() != expected {
            return Err(CheckpointOuterChainError::InvalidFraming);
        }
        let mut transitions = Vec::with_capacity(count);
        let mut cursor = OUTER_CHAIN_HEADER_BYTES;
        for _ in 0..count {
            let end = cursor
                .checked_add(CHECKPOINT_SEGMENT_TRANSITION_BYTES)
                .ok_or(CheckpointOuterChainError::InvalidFraming)?;
            transitions.push(
                CheckpointSegmentTransition::from_bytes(
                    bytes
                        .get(cursor..end)
                        .ok_or(CheckpointOuterChainError::InvalidFraming)?,
                )
                .map_err(|_| CheckpointOuterChainError::InvalidChain)?,
            );
            cursor = end;
        }
        let chain = Self::new(transitions)?;
        if chain.to_bytes()?.as_slice() != bytes {
            return Err(CheckpointOuterChainError::InvalidFraming);
        }
        Ok(chain)
    }
}

/// Exact recursive receipt requirement for one complete segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointSegmentReceiptAssumption {
    image_id: [u8; 32],
    journal: [u8; 32],
}

impl CheckpointSegmentReceiptAssumption {
    /// Pinned complete segment guest ImageID.
    pub const fn image_id(&self) -> &[u8; 32] {
        &self.image_id
    }

    /// Exact `UDCSTN02` commitment expected as the segment journal.
    pub const fn journal(&self) -> &[u8; 32] {
        &self.journal
    }
}

/// Validated public output and ordered segment receipt requirements.
pub struct CheckpointOuterExecution {
    statement_hash: [u8; 32],
    segment_receipts: Vec<CheckpointSegmentReceiptAssumption>,
}

impl CheckpointOuterExecution {
    /// Exact V4 Solidity statement hash committed by the outer guest.
    pub const fn statement_hash(&self) -> [u8; 32] {
        self.statement_hash
    }

    /// Ordered complete-segment receipts required by the chain.
    pub fn segment_receipts(&self) -> &[CheckpointSegmentReceiptAssumption] {
        &self.segment_receipts
    }
}

/// Validate a bounded segment chain against one public Ethereum statement.
#[allow(clippy::too_many_lines)]
pub fn validate_checkpoint_outer_chain(
    statement: &CheckpointStatementV4,
    chain: &CheckpointOuterChain,
    policy_input: &CheckpointSegmentPolicyInput,
    native_opening: &CheckpointSegmentNativeStateOpening,
    expected_segment_image_id: [u8; 32],
) -> Result<CheckpointOuterExecution, CheckpointOuterChainError> {
    statement
        .validate()
        .map_err(|_| CheckpointOuterChainError::InvalidStatement)?;
    if expected_segment_image_id == [0; 32] {
        return Err(CheckpointOuterChainError::InvalidImageId);
    }
    let public = statement.checkpoint;
    let first = chain
        .transitions
        .first()
        .ok_or(CheckpointOuterChainError::InvalidChain)?;
    let policy = policy_input
        .validate_portable_for_state(&first.previous, native_opening)
        .map_err(|_| CheckpointOuterChainError::PreviousMismatch)?;
    let checkpoint = policy.checkpoint_policy().checkpoint();
    let bridge = policy.bridge();
    let previous_context_hash = first
        .previous
        .context
        .commitment()
        .map_err(|_| CheckpointOuterChainError::PreviousMismatch)?;
    let total_span = public
        .confirmation_height
        .checked_sub(public.previous_height)
        .ok_or(CheckpointOuterChainError::InvalidStatement)?;
    if total_span == 0
        || total_span > u64::from(MAX_CONTEXT_SPAN)
        || first.previous.context.max_span != total_span as u32
        || public.bridge_domain != bridge.dom_domain
        || public.dom_network_magic != first.previous.network_magic
        || public.ethereum_chain_id != bridge.ethereum_chain_id
        || checkpoint.registry.as_slice() != public.registry
        || checkpoint.checkpoint_config_hash.as_slice() != public.checkpoint_config_hash
        || public.activation_schedule_commitment != first.previous.activation_schedule_commitment
        || public.previous_height != first.previous.height
        || public.previous_block != first.previous.block_hash
        || public.previous_state_root != first.previous.native_state_root
        || public.previous_context_hash != previous_context_hash
        || public.previous_total_difficulty != first.previous.total_difficulty
    {
        return Err(CheckpointOuterChainError::PreviousMismatch);
    }

    let mut current = first.previous;
    let mut target: Option<CheckpointSegmentState> = None;
    let mut receipts = Vec::with_capacity(chain.transitions.len());
    for transition in &chain.transitions {
        transition
            .validate()
            .map_err(|_| CheckpointOuterChainError::InvalidChain)?;
        if transition.previous != current
            || current.height >= public.confirmation_height
            || current.context.max_span != first.previous.context.max_span
        {
            return Err(CheckpointOuterChainError::InvalidChain);
        }
        let boundary = if current.height < public.height {
            public.height
        } else {
            public.confirmation_height
        };
        let remaining = boundary
            .checked_sub(current.height)
            .ok_or(CheckpointOuterChainError::InvalidChain)?;
        let block_count = u64::from(transition.block_count);
        if block_count == 0
            || block_count > remaining.min(u64::from(MAX_CHECKPOINT_SEGMENT_BLOCKS))
            || transition.next.height != current.height + block_count
        {
            return Err(CheckpointOuterChainError::InvalidChain);
        }
        receipts.push(CheckpointSegmentReceiptAssumption {
            image_id: expected_segment_image_id,
            journal: transition
                .commitment()
                .map_err(|_| CheckpointOuterChainError::InvalidChain)?,
        });
        current = transition.next;
        if current.height == public.height && target.replace(current).is_some() {
            return Err(CheckpointOuterChainError::InvalidChain);
        }
    }
    if current.height != public.confirmation_height {
        return Err(CheckpointOuterChainError::ConfirmationMismatch);
    }
    let target = target.ok_or(CheckpointOuterChainError::TargetMismatch)?;
    let target_context_hash = target
        .context
        .commitment()
        .map_err(|_| CheckpointOuterChainError::TargetMismatch)?;
    if target.block_hash != public.block
        || target.native_state_root != public.state_root
        || target_context_hash != public.context_hash
        || target.total_difficulty != public.total_difficulty
    {
        return Err(CheckpointOuterChainError::TargetMismatch);
    }
    let terminal_timestamp = current
        .context
        .recent_headers
        .last()
        .ok_or(CheckpointOuterChainError::ConfirmationMismatch)?
        .timestamp;
    if current.block_hash != public.confirmation_block
        || current.total_difficulty != public.confirmation_total_difficulty
        || terminal_timestamp != public.confirmation_timestamp
    {
        return Err(CheckpointOuterChainError::ConfirmationMismatch);
    }
    let statement_hash = statement
        .statement_hash()
        .map_err(|_| CheckpointOuterChainError::InvalidStatement)?;
    Ok(CheckpointOuterExecution {
        statement_hash,
        segment_receipts: receipts,
    })
}

/// Verify every pinned complete-segment receipt inside the outer RISC Zero guest.
#[cfg(all(feature = "risc0-recursion", target_os = "zkvm"))]
pub fn verify_checkpoint_segment_receipts_in_guest(
    assumptions: &[CheckpointSegmentReceiptAssumption],
) -> Result<(), core::convert::Infallible> {
    for assumption in assumptions {
        risc0_zkvm::guest::env::verify(
            risc0_zkvm::sha::Digest::from(*assumption.image_id()),
            assumption.journal().as_slice(),
        )?;
    }
    Ok(())
}
