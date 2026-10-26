//! Portable execution of one bounded recursive checkpoint segment.

use super::{
    checkpoint_segment_randomx_bindings, economic_block_effects, economic_chunk_package_commitment,
    CheckpointSegmentNativeStateOpening, CheckpointSegmentPolicyInput,
    CheckpointSegmentPrivateInput, CheckpointSegmentRandomXBinding, CheckpointSegmentTransition,
    EconomicBlockTransition, EconomicBlockWitness, EconomicRoots,
    ValidatedPortableCheckpointSegmentPolicy, CHECKPOINT_USDOM_V4_ENTRY_HEADER_BYTES,
    CHECKPOINT_USDOM_V4_ENVELOPE_MAGIC, CHECKPOINT_USDOM_V4_ENVELOPE_MIN_BYTES,
    CHECKPOINT_USDOM_V4_PACKAGE_HEADER_BYTES, CHECKPOINT_USDOM_V4_PACKAGE_MAGIC,
    CHECKPOINT_USDOM_V4_PACKAGE_VERSION, MAX_CHECKPOINT_SEGMENT_PACKAGE_BYTES,
};
use dom_consensus::block::{validate_header_syntax_v4_scheduled, validate_median_time_past};
use dom_consensus::{
    checked_accumulated_difficulty, validate_block_v4_scheduled, Block, UsdomV4Commitment,
    ValidationContext,
};
use dom_core::{Timestamp, COINBASE_MATURITY, NETWORK_MAGIC_REGTEST, REGTEST_COINBASE_MATURITY};
use dom_pow::{compute_expected_target, target_to_difficulty_for_network_height};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_usdom_state::{
    apply_v2_transition_batch_with_receipt, ethereum_checkpoint_transition,
    ethereum_deposit_transition, ethereum_issuance_closure_transition, verify_private_burn_payload,
    verify_private_transfer_payload, BlockContext, NativeTransitionWitness, VerifiedTransition,
    MAX_NATIVE_TRANSITION_WITNESS_BYTES, MAX_PRIVATE_BURN_PAYLOAD_BYTES,
    MAX_PRIVATE_TRANSFER_PAYLOAD_BYTES, MAX_TRANSITIONS_PER_BATCH,
};
use primitive_types::U256;
use thiserror::Error;
use usdom_ethereum_finality_experiment::checkpoints::{
    verify_checkpoint_witness, CheckpointTrustPolicy, MAX_CHECKPOINT_WITNESS_BYTES,
};
use usdom_ethereum_finality_experiment::closures::{
    verify_issuance_closure_witness, MAX_ISSUANCE_CLOSURE_WITNESS_BYTES,
};
use usdom_ethereum_finality_experiment::deposits::{
    verify_deposit_witness, DepositTrustPolicy, MAX_DEPOSIT_WITNESS_BYTES,
};

const ETHEREUM_MAINNET_GENESIS_TIME: u64 = 1_606_824_023;
const ETHEREUM_SECONDS_PER_SLOT: u64 = 12;
const WITNESS_MAGIC: &[u8; 8] = b"UDV2W001";
const WITNESS_VERSION: u16 = 1;
const WITNESS_HEADER_BYTES: usize = 14;

/// Failure while executing a portable checkpoint segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PortableCheckpointSegmentError {
    /// Public transition, policy, or private-input framing is invalid.
    #[error("invalid portable checkpoint segment input")]
    InvalidInput,
    /// A package or its native/economic witness is malformed.
    #[error("invalid portable checkpoint segment component")]
    InvalidComponent,
    /// Header sequence, syntax, timestamp, target, or accumulated work failed.
    #[error("invalid portable checkpoint segment consensus")]
    InvalidConsensus,
    /// An Ethereum or private USDOM proof failed.
    #[error("invalid portable checkpoint segment proof")]
    InvalidProof,
    /// Candidate-v2 native state execution failed or mismatched the next root.
    #[error("invalid portable checkpoint native state transition")]
    InvalidNativeState,
    /// Ordinary DOM economic execution failed or mismatched the next roots.
    #[error("invalid portable checkpoint economic state transition")]
    InvalidEconomicState,
    /// The computed terminal state differs from the public transition.
    #[error("portable checkpoint terminal state mismatch")]
    TerminalMismatch,
}

/// Successful execution plus the exact inner RandomX receipt requirements.
pub struct PortableCheckpointSegmentExecution {
    transition_commitment: [u8; 32],
    randomx_bindings: Vec<CheckpointSegmentRandomXBinding>,
    economic_block_bindings: Vec<CheckpointEconomicBlockBinding>,
}

impl PortableCheckpointSegmentExecution {
    /// Commitment of the fully executed `UDCSTN04` transition.
    pub const fn transition_commitment(&self) -> [u8; 32] {
        self.transition_commitment
    }

    /// Ordered receipt requirements derived from the exact executed packages.
    pub fn randomx_bindings(&self) -> &[CheckpointSegmentRandomXBinding] {
        &self.randomx_bindings
    }

    /// Ordered recursively proved economic block transitions.
    pub fn economic_block_bindings(&self) -> &[CheckpointEconomicBlockBinding] {
        &self.economic_block_bindings
    }
}

/// Exact complete-block journal required when a segment uses chunk recursion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointEconomicBlockBinding {
    journal: [u8; 32],
}

impl CheckpointEconomicBlockBinding {
    /// Domain-separated `UDECBT01` journal.
    pub const fn journal(&self) -> &[u8; 32] {
        &self.journal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofKind {
    Issuance,
    Transfer,
    Burn,
    EthereumCheckpoint,
    IssuanceClosure,
}

impl ProofKind {
    fn from_byte(value: u8) -> Result<Self, PortableCheckpointSegmentError> {
        match value {
            1 => Ok(Self::Issuance),
            2 => Ok(Self::Transfer),
            3 => Ok(Self::Burn),
            4 => Ok(Self::EthereumCheckpoint),
            5 => Ok(Self::IssuanceClosure),
            _ => Err(PortableCheckpointSegmentError::InvalidComponent),
        }
    }
}

struct ProofEntry<'a> {
    kind: ProofKind,
    payload: &'a [u8],
}

struct ParsedPackage<'a> {
    block: Block,
    entries: Vec<ProofEntry<'a>>,
}

/// Execute all non-RandomX relations for one exact bounded segment.
///
/// The returned RandomX bindings must be verified as recursive receipts by the
/// calling guest before it publishes `transition_commitment`.
#[allow(clippy::too_many_lines)]
pub fn execute_checkpoint_segment_portable(
    transition: &CheckpointSegmentTransition,
    private_input: &CheckpointSegmentPrivateInput,
    policy_input: &CheckpointSegmentPolicyInput,
    native_opening: &CheckpointSegmentNativeStateOpening,
) -> Result<PortableCheckpointSegmentExecution, PortableCheckpointSegmentError> {
    transition
        .validate()
        .map_err(|_| PortableCheckpointSegmentError::InvalidInput)?;
    private_input
        .validate()
        .map_err(|_| PortableCheckpointSegmentError::InvalidInput)?;
    if private_input
        .commitment()
        .map_err(|_| PortableCheckpointSegmentError::InvalidInput)?
        != transition.private_input_commitment
        || private_input.blocks.len() != usize::from(transition.block_count)
    {
        return Err(PortableCheckpointSegmentError::InvalidInput);
    }
    let policy = policy_input
        .validate_portable_for_state(&transition.previous, native_opening)
        .map_err(|_| PortableCheckpointSegmentError::InvalidInput)?;
    let randomx_bindings =
        checkpoint_segment_randomx_bindings(transition, private_input, policy.dom_genesis_hash())
            .map_err(|_| PortableCheckpointSegmentError::InvalidConsensus)?;
    let mut economic_block_bindings = Vec::new();

    let mut native_state = policy.previous_native_state();
    if native_state.total_issued != transition.previous_total_issued
        || native_state.total_burned != transition.previous_total_burned
        || native_state.issuance_closure.is_some() != transition.previous_issuance_closed
    {
        return Err(PortableCheckpointSegmentError::InvalidNativeState);
    }
    let mut authenticated_total_issued = transition.previous_total_issued;
    let mut authenticated_total_burned = transition.previous_total_burned;
    let mut economic_roots = EconomicRoots {
        utxo_root: transition.previous.economic_utxo_root,
        kernel_root: transition.previous.economic_kernel_root,
    };
    let mut previous_hash = transition.previous.block_hash;
    let mut previous_timestamp = transition
        .previous
        .context
        .recent_headers
        .last()
        .ok_or(PortableCheckpointSegmentError::InvalidInput)?
        .timestamp;
    let mut timestamp_window: Vec<Timestamp> = transition
        .previous
        .context
        .recent_headers
        .iter()
        .map(|header| Timestamp(header.timestamp))
        .collect();
    let mut total_difficulty = U256::from_big_endian(&transition.previous.total_difficulty);
    let terminal_timestamp = transition
        .next
        .context
        .recent_headers
        .last()
        .ok_or(PortableCheckpointSegmentError::InvalidInput)?
        .timestamp;

    for (index, block_input) in private_input.blocks.iter().enumerate() {
        let parsed = parse_package(block_input.package_bytes())?;
        let block = &parsed.block;
        let height_offset = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(PortableCheckpointSegmentError::InvalidConsensus)?;
        let expected_height = transition
            .previous
            .height
            .checked_add(height_offset)
            .ok_or(PortableCheckpointSegmentError::InvalidConsensus)?;
        if block.header.height.0 != expected_height
            || block.header.prev_hash.as_bytes() != &previous_hash
            || block.header.timestamp.0 <= previous_timestamp
            || block.header.timestamp.0 > terminal_timestamp
        {
            return Err(PortableCheckpointSegmentError::InvalidConsensus);
        }
        validate_header_syntax_v4_scheduled(&block.header, transition.previous.network_magic)
            .map_err(|_| PortableCheckpointSegmentError::InvalidConsensus)?;
        validate_median_time_past(&block.header, &timestamp_window)
            .map_err(|_| PortableCheckpointSegmentError::InvalidConsensus)?;
        let target = block
            .header
            .target
            .to_target()
            .map_err(|_| PortableCheckpointSegmentError::InvalidConsensus)?;
        if target
            != compute_expected_target(
                transition.previous.network_magic,
                block.header.timestamp,
                block.header.height,
            )
            .map_err(|_| PortableCheckpointSegmentError::InvalidConsensus)?
        {
            return Err(PortableCheckpointSegmentError::InvalidConsensus);
        }
        let block_work = target_to_difficulty_for_network_height(
            transition.previous.network_magic,
            block.header.height,
            &target,
        )
        .map_err(|_| PortableCheckpointSegmentError::InvalidConsensus)?;
        total_difficulty = checked_accumulated_difficulty(total_difficulty, block_work)
            .map_err(|_| PortableCheckpointSegmentError::InvalidConsensus)?;
        if block.header.total_difficulty != total_difficulty {
            return Err(PortableCheckpointSegmentError::InvalidConsensus);
        }

        let header_bytes = DomSerialize::to_bytes(&block.header)
            .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?;
        let block_hash = *dom_core::blake2b_256(&header_bytes).as_bytes();
        if randomx_bindings
            .get(index)
            .map(|binding| *binding.block_hash())
            != Some(block_hash)
        {
            return Err(PortableCheckpointSegmentError::InvalidConsensus);
        }

        let transitions = verify_entries(&parsed.entries, block.header.timestamp.0, &policy)?;
        let witnesses = parse_native_witnesses(block_input.native_witness_bytes())?;
        let (next_native_state, receipt) = apply_v2_transition_batch_with_receipt(
            native_state.root(),
            BlockContext {
                timestamp: block.header.timestamp.0,
            },
            native_state,
            &transitions,
            &witnesses,
        )
        .map_err(|_| PortableCheckpointSegmentError::InvalidNativeState)?;
        if receipt.previous_total_issued != authenticated_total_issued
            || receipt.previous_total_burned != authenticated_total_burned
            || receipt.new_total_issued != next_native_state.total_issued
            || receipt.new_total_burned != next_native_state.total_burned
        {
            return Err(PortableCheckpointSegmentError::InvalidNativeState);
        }
        authenticated_total_issued = receipt.new_total_issued;
        authenticated_total_burned = receipt.new_total_burned;
        let validation_context = ValidationContext {
            current_height: block.header.height,
            chain_id: transition.previous.chain_id,
            now: Timestamp(terminal_timestamp),
        };
        validate_block_v4_scheduled(
            block,
            &validation_context,
            transition.previous.network_magic,
            UsdomV4Commitment {
                batch_header_commitment: receipt.header_commitment,
                block_timestamp: Timestamp(receipt.block_timestamp),
            },
        )
        .map_err(|_| PortableCheckpointSegmentError::InvalidNativeState)?;
        native_state = next_native_state;

        if let Ok(economic_witness) =
            EconomicBlockWitness::from_bytes(block_input.economic_witness_bytes())
        {
            economic_roots = economic_witness
                .apply(
                    economic_roots,
                    block,
                    coinbase_maturity(transition.previous.network_magic),
                )
                .map_err(|_| PortableCheckpointSegmentError::InvalidEconomicState)?;
        } else {
            let claim = EconomicBlockTransition::from_bytes(block_input.economic_witness_bytes())
                .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?;
            let (utxo_effects, kernels) = economic_block_effects(block)
                .map_err(|_| PortableCheckpointSegmentError::InvalidEconomicState)?;
            if claim.network_magic != transition.previous.network_magic
                || claim.package_commitment
                    != economic_chunk_package_commitment(block_input.package_bytes())
                || claim.block_hash != block_hash
                || claim.block_height != block.header.height.0
                || usize::try_from(claim.utxo_effects).ok() != Some(utxo_effects.len())
                || usize::try_from(claim.kernel_effects).ok() != Some(kernels.len())
                || claim.previous_roots != economic_roots
            {
                return Err(PortableCheckpointSegmentError::InvalidEconomicState);
            }
            economic_roots = claim.next_roots;
            economic_block_bindings.push(CheckpointEconomicBlockBinding {
                journal: claim
                    .commitment()
                    .map_err(|_| PortableCheckpointSegmentError::InvalidEconomicState)?,
            });
        }

        previous_hash = block_hash;
        previous_timestamp = block.header.timestamp.0;
        timestamp_window.push(block.header.timestamp);
        if timestamp_window.len() > dom_usdom_checkpoint_statement::CHECKPOINT_CONTEXT_HEADER_COUNT
        {
            timestamp_window.remove(0);
        }
    }

    let mut difficulty_bytes = [0u8; 32];
    total_difficulty.to_big_endian(&mut difficulty_bytes);
    if previous_hash != transition.next.block_hash
        || native_state.root().as_bytes() != &transition.next.native_state_root
        || economic_roots.utxo_root != transition.next.economic_utxo_root
        || economic_roots.kernel_root != transition.next.economic_kernel_root
        || difficulty_bytes != transition.next.total_difficulty
        || authenticated_total_issued != transition.new_total_issued
        || authenticated_total_burned != transition.new_total_burned
        || native_state.issuance_closure.is_some() != transition.new_issuance_closed
    {
        return Err(PortableCheckpointSegmentError::TerminalMismatch);
    }
    let transition_commitment = transition
        .commitment()
        .map_err(|_| PortableCheckpointSegmentError::InvalidInput)?;
    Ok(PortableCheckpointSegmentExecution {
        transition_commitment,
        randomx_bindings,
        economic_block_bindings,
    })
}

/// Verify every pinned complete economic-block receipt inside the segment guest.
#[cfg(all(feature = "risc0-recursion", target_os = "zkvm"))]
pub fn verify_checkpoint_economic_block_receipts_in_guest(
    bindings: &[CheckpointEconomicBlockBinding],
    image_id: [u8; 32],
) -> Result<(), core::convert::Infallible> {
    for binding in bindings {
        risc0_zkvm::guest::env::verify(
            risc0_zkvm::sha::Digest::from(image_id),
            binding.journal().as_slice(),
        )?;
    }
    Ok(())
}

fn parse_package(bytes: &[u8]) -> Result<ParsedPackage<'_>, PortableCheckpointSegmentError> {
    if bytes.len() < CHECKPOINT_USDOM_V4_PACKAGE_HEADER_BYTES
        || bytes.len() > MAX_CHECKPOINT_SEGMENT_PACKAGE_BYTES
        || bytes.get(..8) != Some(CHECKPOINT_USDOM_V4_PACKAGE_MAGIC.as_slice())
        || u16::from_be_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?,
        ) != CHECKPOINT_USDOM_V4_PACKAGE_VERSION
    {
        return Err(PortableCheckpointSegmentError::InvalidComponent);
    }
    let block_len = usize::try_from(u32::from_be_bytes(
        bytes[10..14]
            .try_into()
            .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?,
    ))
    .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?;
    let envelope_len = usize::try_from(u32::from_be_bytes(
        bytes[14..18]
            .try_into()
            .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?,
    ))
    .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?;
    let block_end = CHECKPOINT_USDOM_V4_PACKAGE_HEADER_BYTES
        .checked_add(block_len)
        .ok_or(PortableCheckpointSegmentError::InvalidComponent)?;
    let package_end = block_end
        .checked_add(envelope_len)
        .ok_or(PortableCheckpointSegmentError::InvalidComponent)?;
    if block_len < Block::MIN_SERIALIZED_SIZE || package_end != bytes.len() {
        return Err(PortableCheckpointSegmentError::InvalidComponent);
    }
    let block_bytes = bytes
        .get(CHECKPOINT_USDOM_V4_PACKAGE_HEADER_BYTES..block_end)
        .ok_or(PortableCheckpointSegmentError::InvalidComponent)?;
    let block = Block::from_bytes(block_bytes)
        .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?;
    if DomSerialize::to_bytes(&block)
        .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?
        != block_bytes
    {
        return Err(PortableCheckpointSegmentError::InvalidComponent);
    }
    let entries = parse_envelope(
        bytes
            .get(block_end..package_end)
            .ok_or(PortableCheckpointSegmentError::InvalidComponent)?,
    )?;
    Ok(ParsedPackage { block, entries })
}

#[cfg(feature = "economic-chunks")]
pub(crate) fn parse_checkpoint_package_block(
    bytes: &[u8],
) -> Result<Block, PortableCheckpointSegmentError> {
    Ok(parse_package(bytes)?.block)
}

fn parse_envelope(bytes: &[u8]) -> Result<Vec<ProofEntry<'_>>, PortableCheckpointSegmentError> {
    if bytes.len() < CHECKPOINT_USDOM_V4_ENVELOPE_MIN_BYTES
        || bytes.get(..8) != Some(CHECKPOINT_USDOM_V4_ENVELOPE_MAGIC.as_slice())
        || u16::from_be_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?,
        ) != 1
    {
        return Err(PortableCheckpointSegmentError::InvalidComponent);
    }
    let count = usize::try_from(u32::from_be_bytes(
        bytes[10..14]
            .try_into()
            .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?,
    ))
    .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?;
    if count > MAX_TRANSITIONS_PER_BATCH {
        return Err(PortableCheckpointSegmentError::InvalidComponent);
    }
    let minimum = CHECKPOINT_USDOM_V4_ENVELOPE_MIN_BYTES
        .checked_add(
            count
                .checked_mul(CHECKPOINT_USDOM_V4_ENTRY_HEADER_BYTES)
                .ok_or(PortableCheckpointSegmentError::InvalidComponent)?,
        )
        .ok_or(PortableCheckpointSegmentError::InvalidComponent)?;
    if bytes.len() < minimum {
        return Err(PortableCheckpointSegmentError::InvalidComponent);
    }
    let mut cursor = CHECKPOINT_USDOM_V4_ENVELOPE_MIN_BYTES;
    let mut entries = Vec::with_capacity(count);
    let mut checkpoints = 0usize;
    let mut issuances = 0usize;
    let mut private_spends = 0usize;
    let mut issuance_closures = 0usize;
    for _ in 0..count {
        let header_end = cursor
            .checked_add(CHECKPOINT_USDOM_V4_ENTRY_HEADER_BYTES)
            .ok_or(PortableCheckpointSegmentError::InvalidComponent)?;
        let header = bytes
            .get(cursor..header_end)
            .ok_or(PortableCheckpointSegmentError::InvalidComponent)?;
        let kind = ProofKind::from_byte(header[0])?;
        let length = usize::try_from(u32::from_be_bytes(
            header[1..5]
                .try_into()
                .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?,
        ))
        .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?;
        let end = header_end
            .checked_add(length)
            .ok_or(PortableCheckpointSegmentError::InvalidComponent)?;
        let payload = bytes
            .get(header_end..end)
            .ok_or(PortableCheckpointSegmentError::InvalidComponent)?;
        let limit = match kind {
            ProofKind::Issuance => {
                issuances += 1;
                MAX_DEPOSIT_WITNESS_BYTES
            }
            ProofKind::Transfer => {
                private_spends += 1;
                MAX_PRIVATE_TRANSFER_PAYLOAD_BYTES
            }
            ProofKind::Burn => {
                private_spends += 1;
                MAX_PRIVATE_BURN_PAYLOAD_BYTES
            }
            ProofKind::EthereumCheckpoint => {
                checkpoints += 1;
                MAX_CHECKPOINT_WITNESS_BYTES
            }
            ProofKind::IssuanceClosure => {
                issuance_closures += 1;
                MAX_ISSUANCE_CLOSURE_WITNESS_BYTES
            }
        };
        if length == 0 || length > limit {
            return Err(PortableCheckpointSegmentError::InvalidComponent);
        }
        entries.push(ProofEntry { kind, payload });
        cursor = end;
    }
    if cursor != bytes.len()
        || checkpoints > 1
        || issuances > 4
        || issuance_closures > 1
        || private_spends > 16
    {
        return Err(PortableCheckpointSegmentError::InvalidComponent);
    }
    Ok(entries)
}

fn parse_native_witnesses(
    bytes: &[u8],
) -> Result<Vec<NativeTransitionWitness>, PortableCheckpointSegmentError> {
    if bytes.len() < WITNESS_HEADER_BYTES
        || bytes.get(..8) != Some(WITNESS_MAGIC.as_slice())
        || u16::from_be_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?,
        ) != WITNESS_VERSION
    {
        return Err(PortableCheckpointSegmentError::InvalidComponent);
    }
    let count = usize::try_from(u32::from_be_bytes(
        bytes[10..14]
            .try_into()
            .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?,
    ))
    .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?;
    if count > MAX_TRANSITIONS_PER_BATCH {
        return Err(PortableCheckpointSegmentError::InvalidComponent);
    }
    let minimum = WITNESS_HEADER_BYTES
        .checked_add(
            count
                .checked_mul(4)
                .ok_or(PortableCheckpointSegmentError::InvalidComponent)?,
        )
        .ok_or(PortableCheckpointSegmentError::InvalidComponent)?;
    if bytes.len() < minimum {
        return Err(PortableCheckpointSegmentError::InvalidComponent);
    }
    let mut cursor = WITNESS_HEADER_BYTES;
    let mut witnesses = Vec::with_capacity(count);
    for _ in 0..count {
        let length_end = cursor
            .checked_add(4)
            .ok_or(PortableCheckpointSegmentError::InvalidComponent)?;
        let length = usize::try_from(u32::from_be_bytes(
            bytes
                .get(cursor..length_end)
                .ok_or(PortableCheckpointSegmentError::InvalidComponent)?
                .try_into()
                .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?,
        ))
        .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?;
        let end = length_end
            .checked_add(length)
            .ok_or(PortableCheckpointSegmentError::InvalidComponent)?;
        if length == 0 || length > MAX_NATIVE_TRANSITION_WITNESS_BYTES {
            return Err(PortableCheckpointSegmentError::InvalidComponent);
        }
        let witness = NativeTransitionWitness::from_bytes(
            bytes
                .get(length_end..end)
                .ok_or(PortableCheckpointSegmentError::InvalidComponent)?,
        )
        .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?;
        if witness
            .to_bytes()
            .map_err(|_| PortableCheckpointSegmentError::InvalidComponent)?
            != bytes[length_end..end]
        {
            return Err(PortableCheckpointSegmentError::InvalidComponent);
        }
        witnesses.push(witness);
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(PortableCheckpointSegmentError::InvalidComponent);
    }
    Ok(witnesses)
}

fn verify_entries(
    entries: &[ProofEntry<'_>],
    block_timestamp: u64,
    policy: &ValidatedPortableCheckpointSegmentPolicy,
) -> Result<Vec<VerifiedTransition>, PortableCheckpointSegmentError> {
    let mut transitions = Vec::with_capacity(entries.len());
    for entry in entries {
        let transition = match entry.kind {
            ProofKind::Issuance => {
                let dynamic = deposit_policy_for_block(block_timestamp, policy)?;
                let deposit = verify_deposit_witness(entry.payload, &dynamic)
                    .map_err(|_| PortableCheckpointSegmentError::InvalidProof)?;
                validate_finality_freshness(
                    block_timestamp,
                    policy,
                    deposit.finalized_execution().timestamp,
                )?;
                ethereum_deposit_transition(policy.bridge(), &deposit)
                    .map_err(|_| PortableCheckpointSegmentError::InvalidProof)?
            }
            ProofKind::EthereumCheckpoint => {
                let dynamic = checkpoint_policy_for_block(block_timestamp, policy)?;
                let checkpoint = verify_checkpoint_witness(entry.payload, &dynamic)
                    .map_err(|_| PortableCheckpointSegmentError::InvalidProof)?;
                validate_finality_freshness(
                    block_timestamp,
                    policy,
                    checkpoint.finalized_execution().timestamp,
                )?;
                ethereum_checkpoint_transition(policy.bridge(), &checkpoint)
                    .map_err(|_| PortableCheckpointSegmentError::InvalidProof)?
            }
            ProofKind::IssuanceClosure => {
                let static_policy = policy
                    .issuance_closure_policy()
                    .ok_or(PortableCheckpointSegmentError::InvalidProof)?;
                let dynamic = static_policy
                    .at_max_current_slot(ethereum_slot_ceiling(block_timestamp)?)
                    .map_err(|_| PortableCheckpointSegmentError::InvalidProof)?;
                let closure = verify_issuance_closure_witness(entry.payload, &dynamic)
                    .map_err(|_| PortableCheckpointSegmentError::InvalidProof)?;
                validate_finality_freshness(
                    block_timestamp,
                    policy,
                    closure.finalized_execution().timestamp,
                )?;
                ethereum_issuance_closure_transition(policy.bridge(), &closure)
                    .map(VerifiedTransition::IssuanceClose)
                    .map_err(|_| PortableCheckpointSegmentError::InvalidProof)?
            }
            ProofKind::Transfer => verify_private_transfer_payload(
                policy.bridge(),
                policy.spend_verifier(),
                entry.payload,
            )
            .map_err(|_| PortableCheckpointSegmentError::InvalidProof)?,
            ProofKind::Burn => {
                verify_private_burn_payload(policy.bridge(), policy.spend_verifier(), entry.payload)
                    .map_err(|_| PortableCheckpointSegmentError::InvalidProof)?
            }
        };
        transitions.push(transition);
    }
    Ok(transitions)
}

fn validate_finality_freshness(
    block_timestamp: u64,
    policy: &ValidatedPortableCheckpointSegmentPolicy,
    finalized_timestamp: u64,
) -> Result<(), PortableCheckpointSegmentError> {
    let timing = policy.bridge().burn_timing;
    usdom_ethereum_finality_experiment::validate_finalized_time_window(
        finalized_timestamp,
        block_timestamp,
        timing.max_ethereum_anchor_age_secs,
        timing.max_dom_clock_lead_secs,
    )
    .map_err(|_| PortableCheckpointSegmentError::InvalidProof)
}

fn checkpoint_policy_for_block(
    block_timestamp: u64,
    policy: &ValidatedPortableCheckpointSegmentPolicy,
) -> Result<CheckpointTrustPolicy, PortableCheckpointSegmentError> {
    let max_current_slot = block_timestamp
        .checked_sub(ETHEREUM_MAINNET_GENESIS_TIME)
        .map(|elapsed| elapsed / ETHEREUM_SECONDS_PER_SLOT)
        .ok_or(PortableCheckpointSegmentError::InvalidProof)?;
    policy
        .checkpoint_policy()
        .at_max_current_slot(max_current_slot)
        .map_err(|_| PortableCheckpointSegmentError::InvalidProof)
}

fn ethereum_slot_ceiling(block_timestamp: u64) -> Result<u64, PortableCheckpointSegmentError> {
    block_timestamp
        .checked_sub(ETHEREUM_MAINNET_GENESIS_TIME)
        .map(|elapsed| elapsed / ETHEREUM_SECONDS_PER_SLOT)
        .ok_or(PortableCheckpointSegmentError::InvalidProof)
}

fn deposit_policy_for_block(
    block_timestamp: u64,
    policy: &ValidatedPortableCheckpointSegmentPolicy,
) -> Result<DepositTrustPolicy, PortableCheckpointSegmentError> {
    let max_current_slot = block_timestamp
        .checked_sub(ETHEREUM_MAINNET_GENESIS_TIME)
        .map(|elapsed| elapsed / ETHEREUM_SECONDS_PER_SLOT)
        .ok_or(PortableCheckpointSegmentError::InvalidProof)?;
    policy
        .deposit_policy()
        .at_max_current_slot(max_current_slot)
        .map_err(|_| PortableCheckpointSegmentError::InvalidProof)
}

const fn coinbase_maturity(network_magic: u32) -> u64 {
    if network_magic == NETWORK_MAGIC_REGTEST {
        REGTEST_COINBASE_MATURITY
    } else {
        COINBASE_MATURITY
    }
}
