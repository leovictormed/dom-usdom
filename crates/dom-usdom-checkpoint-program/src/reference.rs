//! Host implementation of the complete deterministic checkpoint relation.

use std::collections::BTreeMap;

use dom_chain::{
    canonical_header_identifier, verify_usdom_v4_serialized_candidate_for_schedule,
    verify_usdom_v4_serialized_transition_batch_for_v2_schedule, NativeUsdomV2ActivationSchedule,
    NativeUsdomV4ActivationSchedule, UsdomV4BlockPackage,
};
use dom_consensus::{
    block::{
        validate_future_timestamp_with_limit, validate_header_syntax_v4_scheduled,
        validate_median_time_past, validate_pow_for_network,
    },
    checked_accumulated_difficulty, derive_chain_id, ValidationContext,
};
use dom_core::{
    Hash256, Timestamp, MAX_FUTURE_BLOCK_TIME, NETWORK_MAGIC_REGTEST, NETWORK_MAGIC_TESTNET,
    REGTEST_COINBASE_MATURITY, TESTNET_MAX_FUTURE_BLOCK_TIME,
};
use dom_pow::{
    compute_expected_target, randomx_seed_height, target_to_difficulty_for_network_height,
};
use dom_serialization::DomSerialize;
use dom_usdom_checkpoint_statement::{
    required_historical_seed_heights, CheckpointContext, CheckpointStatement,
    CheckpointStatementV6, ContextHeader, SeedAnchor, CHECKPOINT_CONTEXT_HEADER_COUNT,
    CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS, MAX_CONTEXT_SPAN,
};
use dom_usdom_privacy::verifier::SpendVerifier;
use dom_usdom_state::{
    BridgeIdentity, NativeTransitionWitness, NativeUsdomState, StateCommitmentV2,
};
use primitive_types::U256;
use thiserror::Error;
use usdom_ethereum_finality_experiment::{
    checkpoints::StaticCheckpointTrustPolicy, closures::StaticIssuanceClosureTrustPolicy,
    deposits::StaticDepositTrustPolicy,
};

use crate::{EconomicBlockWitness, EconomicRoots, EconomicState, EconomicStateError};

/// Immutable consensus policy selected by the verifier release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointProgramPolicy {
    schedule: NativeUsdomV4ActivationSchedule,
    bridge: BridgeIdentity,
    dom_genesis_hash: Hash256,
    checkpoint_interval: u32,
    confirmation_depth: u32,
}

/// Candidate state-v2 checkpoint policy bound to one ratified v1/v2 snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointProgramPolicyV2 {
    schedule: NativeUsdomV2ActivationSchedule,
    bridge: BridgeIdentity,
    dom_genesis_hash: Hash256,
    checkpoint_interval: u32,
    confirmation_depth: u32,
}

impl CheckpointProgramPolicyV2 {
    /// Validate the network, snapshot roots and bounded proof span.
    pub fn new(
        schedule: NativeUsdomV2ActivationSchedule,
        bridge: BridgeIdentity,
        activation_state: &NativeUsdomState,
        dom_genesis_hash: Hash256,
        checkpoint_interval: u32,
        confirmation_depth: u32,
    ) -> Result<Self, CheckpointProgramError> {
        let span = checkpoint_interval
            .checked_add(confirmation_depth)
            .ok_or(CheckpointProgramError::InvalidPolicy)?;
        if dom_genesis_hash == Hash256::ZERO
            || checkpoint_interval == 0
            || checkpoint_interval > 360
            || confirmation_depth == 0
            || confirmation_depth > checkpoint_interval
            || span > MAX_CONTEXT_SPAN
            || activation_state.bridge_identity() != bridge
            || schedule.network_magic() == 0
            || schedule.chain_id() != derive_chain_id(schedule.network_magic(), &dom_genesis_hash)
            || schedule.previous_v1_state_root() != activation_state.state_root()
            || schedule.initial_v2_state_root()
                != activation_state
                    .state_commitment_v2()
                    .map_err(|_| CheckpointProgramError::InvalidPolicy)?
                    .root()
        {
            return Err(CheckpointProgramError::InvalidPolicy);
        }
        Ok(Self {
            schedule,
            bridge,
            dom_genesis_hash,
            checkpoint_interval,
            confirmation_depth,
        })
    }

    /// Exact versioned activation migration.
    pub const fn schedule(self) -> NativeUsdomV2ActivationSchedule {
        self.schedule
    }

    /// Exact immutable bridge identity.
    pub const fn bridge(self) -> BridgeIdentity {
        self.bridge
    }

    /// Canonical DOM genesis identifier.
    pub const fn dom_genesis_hash(self) -> Hash256 {
        self.dom_genesis_hash
    }

    /// Fixed checkpoint distance.
    pub const fn checkpoint_interval(self) -> u32 {
        self.checkpoint_interval
    }

    /// Fixed work-confirmation suffix distance.
    pub const fn confirmation_depth(self) -> u32 {
        self.confirmation_depth
    }
}

#[derive(Clone, Copy)]
enum ProgramPolicy {
    V1(CheckpointProgramPolicy),
    V2(CheckpointProgramPolicyV2),
}

impl ProgramPolicy {
    fn bridge(self) -> BridgeIdentity {
        match self {
            Self::V1(value) => value.bridge,
            Self::V2(value) => value.bridge,
        }
    }
    fn network_magic(self) -> u32 {
        match self {
            Self::V1(value) => value.schedule.network_magic(),
            Self::V2(value) => value.schedule.network_magic(),
        }
    }
    fn chain_id(self) -> Hash256 {
        match self {
            Self::V1(value) => value.schedule.chain_id(),
            Self::V2(value) => value.schedule.chain_id(),
        }
    }
    fn first_height(self) -> u64 {
        match self {
            Self::V1(value) => value.schedule.first_v4_height(),
            Self::V2(value) => value.schedule.first_v2_height(),
        }
    }
    fn schedule_commitment(self) -> Hash256 {
        match self {
            Self::V1(value) => value.schedule.commitment(),
            Self::V2(value) => value.schedule.commitment(),
        }
    }
    fn dom_genesis_hash(self) -> Hash256 {
        match self {
            Self::V1(value) => value.dom_genesis_hash,
            Self::V2(value) => value.dom_genesis_hash,
        }
    }
    fn checkpoint_interval(self) -> u32 {
        match self {
            Self::V1(value) => value.checkpoint_interval,
            Self::V2(value) => value.checkpoint_interval,
        }
    }
    fn confirmation_depth(self) -> u32 {
        match self {
            Self::V1(value) => value.confirmation_depth,
            Self::V2(value) => value.confirmation_depth,
        }
    }
    fn span(self) -> u32 {
        self.checkpoint_interval() + self.confirmation_depth()
    }
}

impl CheckpointProgramPolicy {
    /// Validate and freeze one exact checkpoint relation.
    pub fn new(
        schedule: NativeUsdomV4ActivationSchedule,
        bridge: BridgeIdentity,
        dom_genesis_hash: Hash256,
        checkpoint_interval: u32,
        confirmation_depth: u32,
    ) -> Result<Self, CheckpointProgramError> {
        let span = checkpoint_interval
            .checked_add(confirmation_depth)
            .ok_or(CheckpointProgramError::InvalidPolicy)?;
        if dom_genesis_hash == Hash256::ZERO
            || checkpoint_interval == 0
            || checkpoint_interval > 360
            || confirmation_depth == 0
            || confirmation_depth > checkpoint_interval
            || span > MAX_CONTEXT_SPAN
            || schedule.network_magic() == 0
            || schedule.chain_id() != derive_chain_id(schedule.network_magic(), &dom_genesis_hash)
            || NativeUsdomState::new(bridge)
                .map_err(|_| CheckpointProgramError::InvalidPolicy)?
                .state_root()
                != schedule.empty_state_root()
        {
            return Err(CheckpointProgramError::InvalidPolicy);
        }
        Ok(Self {
            schedule,
            bridge,
            dom_genesis_hash,
            checkpoint_interval,
            confirmation_depth,
        })
    }

    /// Exact native activation schedule.
    pub const fn schedule(self) -> NativeUsdomV4ActivationSchedule {
        self.schedule
    }

    /// Exact native bridge identity.
    pub const fn bridge(self) -> BridgeIdentity {
        self.bridge
    }

    /// Canonical DOM genesis identifier used by RandomX epoch zero.
    pub const fn dom_genesis_hash(self) -> Hash256 {
        self.dom_genesis_hash
    }

    /// Fixed checkpoint distance.
    pub const fn checkpoint_interval(self) -> u32 {
        self.checkpoint_interval
    }

    /// Fixed work-confirmation suffix distance.
    pub const fn confirmation_depth(self) -> u32 {
        self.confirmation_depth
    }

    /// Total checkpoint plus confirmation span.
    pub const fn span(self) -> u32 {
        self.checkpoint_interval + self.confirmation_depth
    }
}

/// Raw 32-byte public value returned only after the complete relation succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointPublicOutput([u8; 32]);

impl CheckpointPublicOutput {
    /// Exact hash supplied to the immutable Ethereum checkpoint verifier.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Failure of the deterministic checkpoint relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CheckpointProgramError {
    /// The frozen release policy is internally inconsistent.
    #[error("invalid checkpoint program policy")]
    InvalidPolicy,
    /// The public statement is malformed or does not match the release policy.
    #[error("invalid checkpoint public statement")]
    InvalidStatement,
    /// The previous continuation context is malformed or mismatched.
    #[error("invalid previous checkpoint context")]
    InvalidContext,
    /// The supplied native or ordinary state does not open the previous roots.
    #[error("checkpoint state opening does not match the previous checkpoint")]
    InvalidPreviousState,
    /// The extension has the wrong length or a broken header relation.
    #[error("invalid DOM checkpoint extension")]
    InvalidExtension,
    /// Header syntax, time, target, work, or proof of work failed.
    #[error("invalid DOM checkpoint consensus header")]
    InvalidConsensus,
    /// Ordinary DOM contextual economic validation failed.
    #[error("invalid DOM checkpoint economic transition")]
    InvalidEconomicState,
    /// Native USDOM body or state transition validation failed.
    #[error("invalid native USDOM checkpoint transition")]
    InvalidNativeState,
    /// The target or confirmation suffix does not match the public statement.
    #[error("DOM checkpoint result does not match the public statement")]
    PublicMismatch,
}

enum EconomicExecution<'a> {
    Full(EconomicState),
    Witnessed {
        roots: EconomicRoots,
        witnesses: &'a [EconomicBlockWitness],
    },
}

enum NativeExecution<'a> {
    Full(Box<NativeUsdomState>),
    StatelessV2 {
        state: Box<StateCommitmentV2>,
        witnesses: &'a [Vec<NativeTransitionWitness>],
    },
}

impl NativeExecution<'_> {
    fn root(&self) -> Hash256 {
        match self {
            Self::Full(state) => state.state_root(),
            Self::StatelessV2 { state, .. } => state.root(),
        }
    }

    fn economic_totals(&self) -> Option<(u128, u128)> {
        match self {
            Self::Full(_) => None,
            Self::StatelessV2 { state, .. } => Some((state.total_issued, state.total_burned)),
        }
    }

    fn issuance_closed(&self) -> Option<bool> {
        match self {
            Self::Full(_) => None,
            Self::StatelessV2 { state, .. } => Some(state.issuance_closure.is_some()),
        }
    }

    fn validate_length(&self, expected: usize) -> Result<(), CheckpointProgramError> {
        if matches!(self, Self::StatelessV2 { witnesses, .. } if witnesses.len() != expected) {
            return Err(CheckpointProgramError::InvalidExtension);
        }
        Ok(())
    }
}

fn validate_v6_target_state(
    actual_totals: Option<(u128, u128)>,
    actual_issuance_closed: Option<bool>,
    expected: Option<(u128, u128, bool)>,
) -> Result<(), CheckpointProgramError> {
    if let Some((issued, burned, issuance_closed)) = expected {
        if actual_totals != Some((issued, burned))
            || actual_issuance_closed != Some(issuance_closed)
        {
            return Err(CheckpointProgramError::PublicMismatch);
        }
    }
    Ok(())
}

impl EconomicExecution<'_> {
    fn context_root(&self) -> Result<[u8; 32], CheckpointProgramError> {
        match self {
            Self::Full(state) => state.context_root().map_err(map_economic),
            Self::Witnessed { roots, .. } => roots.context_root().map_err(map_economic),
        }
    }

    fn validate_length(&self, expected: usize) -> Result<(), CheckpointProgramError> {
        if matches!(
            self,
            Self::Witnessed { witnesses, .. } if witnesses.len() != expected
        ) {
            return Err(CheckpointProgramError::InvalidExtension);
        }
        Ok(())
    }

    fn apply(
        &mut self,
        index: usize,
        block: &dom_consensus::Block,
        coinbase_maturity: u64,
    ) -> Result<(), CheckpointProgramError> {
        match self {
            Self::Full(state) => state
                .apply_block(block, coinbase_maturity)
                .map_err(map_economic),
            Self::Witnessed { roots, witnesses } => {
                *roots = witnesses
                    .get(index)
                    .ok_or(CheckpointProgramError::InvalidExtension)?
                    .apply(*roots, block, coinbase_maturity)
                    .map_err(map_economic)?;
                Ok(())
            }
        }
    }
}

/// Execute the full bounded checkpoint extension and emit only its public hash.
///
/// The previous native and economic states are private openings of the roots
/// authenticated by the prior checkpoint. `packages` must contain exactly the
/// fixed checkpoint interval followed by the fixed confirmation suffix.
#[allow(clippy::too_many_arguments)]
pub fn execute_checkpoint_extension(
    policy: CheckpointProgramPolicy,
    statement_bytes: &[u8],
    previous_context_bytes: &[u8],
    previous_native_state: &NativeUsdomState,
    previous_economic_state: &EconomicState,
    packages: &[Vec<u8>],
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    spend_verifier: &SpendVerifier,
) -> Result<CheckpointPublicOutput, CheckpointProgramError> {
    let statement = CheckpointStatement::from_bytes(statement_bytes)
        .map_err(|_| CheckpointProgramError::InvalidStatement)?;
    let public_output = statement
        .statement_hash()
        .map_err(|_| CheckpointProgramError::InvalidStatement)?;
    execute_checkpoint_extension_inner(
        ProgramPolicy::V1(policy),
        statement,
        public_output,
        None,
        None,
        previous_context_bytes,
        NativeExecution::Full(Box::new(previous_native_state.clone())),
        EconomicExecution::Full(previous_economic_state.clone()),
        packages,
        checkpoint_policy,
        deposit_policy,
        spend_verifier,
    )
}

/// Execute the same full relation with one authenticated economic witness per
/// block instead of opening the complete ordinary DOM state inside the guest.
#[allow(clippy::too_many_arguments)]
pub fn execute_checkpoint_extension_with_economic_witnesses(
    policy: CheckpointProgramPolicy,
    statement_bytes: &[u8],
    previous_context_bytes: &[u8],
    previous_native_state: &NativeUsdomState,
    previous_economic_roots: EconomicRoots,
    packages: &[Vec<u8>],
    economic_witnesses: &[EconomicBlockWitness],
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    spend_verifier: &SpendVerifier,
) -> Result<CheckpointPublicOutput, CheckpointProgramError> {
    let statement = CheckpointStatement::from_bytes(statement_bytes)
        .map_err(|_| CheckpointProgramError::InvalidStatement)?;
    let public_output = statement
        .statement_hash()
        .map_err(|_| CheckpointProgramError::InvalidStatement)?;
    execute_checkpoint_extension_inner(
        ProgramPolicy::V1(policy),
        statement,
        public_output,
        None,
        None,
        previous_context_bytes,
        NativeExecution::Full(Box::new(previous_native_state.clone())),
        EconomicExecution::Witnessed {
            roots: previous_economic_roots,
            witnesses: economic_witnesses,
        },
        packages,
        checkpoint_policy,
        deposit_policy,
        spend_verifier,
    )
}

/// Execute the complete checkpoint relation with explicit state-v2/batch-v3
/// semantics and bounded native plus ordinary-economic witnesses.
#[allow(clippy::too_many_arguments)]
pub fn execute_checkpoint_extension_v2_with_witnesses(
    policy: CheckpointProgramPolicyV2,
    statement_bytes: &[u8],
    previous_context_bytes: &[u8],
    previous_native_state: StateCommitmentV2,
    previous_economic_roots: EconomicRoots,
    packages: &[Vec<u8>],
    native_witnesses: &[Vec<NativeTransitionWitness>],
    economic_witnesses: &[EconomicBlockWitness],
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    closure_policy: &StaticIssuanceClosureTrustPolicy,
    spend_verifier: &SpendVerifier,
) -> Result<CheckpointPublicOutput, CheckpointProgramError> {
    let statement = CheckpointStatementV6::from_bytes(statement_bytes)
        .map_err(|_| CheckpointProgramError::InvalidStatement)?;
    let public_output = statement
        .statement_hash()
        .map_err(|_| CheckpointProgramError::InvalidStatement)?;
    let legacy = statement.checkpoint;
    if legacy.previous_height.checked_add(1) == Some(policy.schedule.first_v2_height())
        && (legacy.previous_block != *policy.schedule.activation_parent().as_bytes()
            || legacy.previous_state_root != *policy.schedule.initial_v2_state_root().as_bytes())
    {
        return Err(CheckpointProgramError::InvalidPreviousState);
    }
    execute_checkpoint_extension_inner(
        ProgramPolicy::V2(policy),
        legacy,
        public_output,
        Some((
            statement.total_issued,
            statement.total_burned,
            statement.issuance_closed,
        )),
        Some(closure_policy),
        previous_context_bytes,
        NativeExecution::StatelessV2 {
            state: Box::new(previous_native_state),
            witnesses: native_witnesses,
        },
        EconomicExecution::Witnessed {
            roots: previous_economic_roots,
            witnesses: economic_witnesses,
        },
        packages,
        checkpoint_policy,
        deposit_policy,
        spend_verifier,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_checkpoint_extension_inner(
    policy: ProgramPolicy,
    statement: CheckpointStatement,
    public_output: [u8; 32],
    expected_target_state: Option<(u128, u128, bool)>,
    closure_policy: Option<&StaticIssuanceClosureTrustPolicy>,
    previous_context_bytes: &[u8],
    mut native_execution: NativeExecution<'_>,
    mut economic_execution: EconomicExecution<'_>,
    packages: &[Vec<u8>],
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    spend_verifier: &SpendVerifier,
) -> Result<CheckpointPublicOutput, CheckpointProgramError> {
    if matches!(policy, ProgramPolicy::V2(_)) && closure_policy.is_none() {
        return Err(CheckpointProgramError::InvalidPolicy);
    }
    let context = CheckpointContext::from_bytes(previous_context_bytes)
        .map_err(|_| CheckpointProgramError::InvalidContext)?;
    validate_public_policy(
        policy,
        &statement,
        &context,
        checkpoint_policy,
        deposit_policy,
        spend_verifier,
    )?;
    if native_execution.root().as_bytes() != &statement.previous_state_root
        || economic_execution.context_root()? != context.economic_state_root
    {
        return Err(CheckpointProgramError::InvalidPreviousState);
    }

    let expected_packages =
        usize::try_from(policy.span()).map_err(|_| CheckpointProgramError::InvalidPolicy)?;
    if packages.len() != expected_packages {
        return Err(CheckpointProgramError::InvalidExtension);
    }
    economic_execution.validate_length(expected_packages)?;

    native_execution.validate_length(expected_packages)?;
    let mut previous_block = Hash256::from_bytes(statement.previous_block);
    let mut previous_timestamp =
        context.recent_headers[CHECKPOINT_CONTEXT_HEADER_COUNT - 1].timestamp;
    let mut total_difficulty = U256::from_big_endian(&statement.previous_total_difficulty);
    let mut timestamp_window: Vec<Timestamp> = context
        .recent_headers
        .iter()
        .map(|header| Timestamp(header.timestamp))
        .collect();
    let mut projections: Vec<ContextHeader> = context.recent_headers.to_vec();
    let mut known_blocks = BTreeMap::new();
    for header in &context.recent_headers {
        insert_known(&mut known_blocks, header.height, header.block)?;
    }
    for anchor in context
        .seed_anchors
        .iter()
        .take(usize::from(context.seed_anchor_count))
    {
        insert_known(&mut known_blocks, anchor.height, anchor.block)?;
    }

    let target_index = usize::try_from(policy.checkpoint_interval() - 1)
        .map_err(|_| CheckpointProgramError::InvalidPolicy)?;
    for (index, package_bytes) in packages.iter().enumerate() {
        let expected_height = statement
            .previous_height
            .checked_add(index as u64 + 1)
            .ok_or(CheckpointProgramError::InvalidExtension)?;
        let package = UsdomV4BlockPackage::from_bytes(package_bytes)
            .map_err(|_| CheckpointProgramError::InvalidExtension)?;
        let header = &package.block().header;
        if header.height.0 != expected_height
            || header.prev_hash != previous_block
            || header.timestamp.0 <= previous_timestamp
        {
            return Err(CheckpointProgramError::InvalidExtension);
        }
        validate_header_syntax_v4_scheduled(header, policy.network_magic())
            .map_err(|_| CheckpointProgramError::InvalidConsensus)?;
        let future_limit = if policy.network_magic() == NETWORK_MAGIC_TESTNET {
            TESTNET_MAX_FUTURE_BLOCK_TIME
        } else {
            MAX_FUTURE_BLOCK_TIME
        };
        validate_future_timestamp_with_limit(
            header,
            Timestamp(statement.confirmation_timestamp),
            future_limit,
        )
        .map_err(|_| CheckpointProgramError::InvalidConsensus)?;
        validate_median_time_past(header, &timestamp_window)
            .map_err(|_| CheckpointProgramError::InvalidConsensus)?;

        let target = header
            .target
            .to_target()
            .map_err(|_| CheckpointProgramError::InvalidConsensus)?;
        if target
            != compute_expected_target(policy.network_magic(), header.timestamp, header.height)
                .map_err(|_| CheckpointProgramError::InvalidConsensus)?
        {
            return Err(CheckpointProgramError::InvalidConsensus);
        }
        let seed_height = randomx_seed_height(expected_height);
        let seed = if seed_height == 0 {
            *policy.dom_genesis_hash().as_bytes()
        } else {
            known_blocks
                .get(&seed_height)
                .copied()
                .ok_or(CheckpointProgramError::InvalidContext)?
        };
        validate_pow_for_network(policy.network_magic(), header, &seed)
            .map_err(|_| CheckpointProgramError::InvalidConsensus)?;
        let block_work =
            target_to_difficulty_for_network_height(policy.network_magic(), header.height, &target)
                .map_err(|_| CheckpointProgramError::InvalidConsensus)?;
        total_difficulty = checked_accumulated_difficulty(total_difficulty, block_work)
            .map_err(|_| CheckpointProgramError::InvalidConsensus)?;
        if header.total_difficulty != total_difficulty {
            return Err(CheckpointProgramError::InvalidConsensus);
        }

        let header_bytes =
            DomSerialize::to_bytes(header).map_err(|_| CheckpointProgramError::InvalidExtension)?;
        let block_identifier = canonical_header_identifier(policy.network_magic(), &header_bytes)
            .map_err(|_| CheckpointProgramError::InvalidExtension)?;
        let validation_context = ValidationContext {
            current_height: header.height,
            chain_id: *policy.chain_id().as_bytes(),
            now: Timestamp(statement.confirmation_timestamp),
        };
        match (&mut native_execution, policy) {
            (NativeExecution::Full(state), ProgramPolicy::V1(policy)) => {
                let verified = verify_usdom_v4_serialized_candidate_for_schedule(
                    package_bytes,
                    &validation_context,
                    policy.schedule.network_magic(),
                    state,
                    policy.bridge,
                    checkpoint_policy,
                    deposit_policy,
                    closure_policy,
                    spend_verifier,
                    policy.schedule,
                )
                .map_err(|_| CheckpointProgramError::InvalidNativeState)?;
                if verified.block_identifier() != block_identifier {
                    return Err(CheckpointProgramError::InvalidNativeState);
                }
                **state = verified.next_state().clone();
            }
            (NativeExecution::StatelessV2 { state, witnesses }, ProgramPolicy::V2(policy)) => {
                let verified = verify_usdom_v4_serialized_transition_batch_for_v2_schedule(
                    package_bytes,
                    &validation_context,
                    policy.schedule.network_magic(),
                    policy.bridge,
                    checkpoint_policy,
                    deposit_policy,
                    closure_policy,
                    spend_verifier,
                    policy.schedule,
                )
                .map_err(|_| CheckpointProgramError::InvalidNativeState)?;
                let candidate = verified
                    .execute_v2(
                        &validation_context,
                        state.root(),
                        **state,
                        witnesses
                            .get(index)
                            .ok_or(CheckpointProgramError::InvalidExtension)?,
                    )
                    .map_err(|_| CheckpointProgramError::InvalidNativeState)?;
                if candidate.block_identifier() != block_identifier {
                    return Err(CheckpointProgramError::InvalidNativeState);
                }
                **state = candidate.next_state();
            }
            _ => return Err(CheckpointProgramError::InvalidPolicy),
        }
        economic_execution.apply(
            index,
            package.block(),
            coinbase_maturity(policy.network_magic()),
        )?;

        previous_block = block_identifier;
        previous_timestamp = header.timestamp.0;
        timestamp_window.push(header.timestamp);
        if timestamp_window.len() > CHECKPOINT_CONTEXT_HEADER_COUNT {
            timestamp_window.remove(0);
        }
        let projection = ContextHeader {
            height: expected_height,
            block: *block_identifier.as_bytes(),
            timestamp: header.timestamp.0,
        };
        projections.push(projection);
        if projections.len() > CHECKPOINT_CONTEXT_HEADER_COUNT {
            projections.remove(0);
        }
        insert_known(
            &mut known_blocks,
            expected_height,
            *block_identifier.as_bytes(),
        )?;

        if index == target_index {
            validate_v6_target_state(
                native_execution.economic_totals(),
                native_execution.issuance_closed(),
                expected_target_state,
            )?;
            validate_target(
                policy,
                &statement,
                block_identifier,
                total_difficulty,
                native_execution.root(),
                economic_execution.context_root()?,
                &projections,
                &known_blocks,
            )?;
        }
    }

    if previous_block.as_bytes() != &statement.confirmation_block
        || total_difficulty != U256::from_big_endian(&statement.confirmation_total_difficulty)
        || previous_timestamp != statement.confirmation_timestamp
    {
        return Err(CheckpointProgramError::PublicMismatch);
    }
    Ok(CheckpointPublicOutput(public_output))
}

fn validate_public_policy(
    policy: ProgramPolicy,
    statement: &CheckpointStatement,
    context: &CheckpointContext,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    spend_verifier: &SpendVerifier,
) -> Result<(), CheckpointProgramError> {
    let expected_target = statement
        .previous_height
        .checked_add(u64::from(policy.checkpoint_interval()))
        .ok_or(CheckpointProgramError::InvalidStatement)?;
    let expected_confirmation = expected_target
        .checked_add(u64::from(policy.confirmation_depth()))
        .ok_or(CheckpointProgramError::InvalidStatement)?;
    let first_extension_height = statement
        .previous_height
        .checked_add(1)
        .ok_or(CheckpointProgramError::InvalidStatement)?;
    let checkpoint = checkpoint_policy.checkpoint();
    let deposit = deposit_policy.deposit();
    let mut ethereum_chain_id = [0u8; 32];
    ethereum_chain_id[24..].copy_from_slice(&checkpoint.ethereum_chain_id.to_be_bytes());
    if statement.bridge_domain != policy.bridge().dom_domain
        || statement.dom_network_magic != policy.network_magic()
        || statement.ethereum_chain_id != policy.bridge().ethereum_chain_id
        || statement.ethereum_chain_id != ethereum_chain_id
        || statement.activation_schedule_commitment != *policy.schedule_commitment().as_bytes()
        || statement.height != expected_target
        || statement.confirmation_height != expected_confirmation
        || first_extension_height < policy.first_height()
        || context.checkpoint_height != statement.previous_height
        || context.checkpoint_block != statement.previous_block
        || context.max_span != policy.span()
        || context
            .commitment()
            .map_err(|_| CheckpointProgramError::InvalidContext)?
            != statement.previous_context_hash
        || checkpoint_policy.policy_hash().as_slice()
            != policy.bridge().ethereum_checkpoint_policy_hash
        || deposit_policy.policy_hash().as_slice() != policy.bridge().ethereum_deposit_policy_hash
        || spend_verifier.config_hash().as_bytes() != &policy.bridge().privacy_verifier_config_hash
        || checkpoint.bridge_domain.as_slice() != policy.bridge().dom_domain
        || checkpoint.dom_network_magic != policy.network_magic()
        || checkpoint.ethereum_genesis_validators_root.as_slice()
            != policy.bridge().ethereum_genesis_validators_root
        || checkpoint.registry.as_slice() != statement.registry
        || checkpoint.checkpoint_config_hash.as_slice() != statement.checkpoint_config_hash
        || deposit.ethereum_chain_id != checkpoint.ethereum_chain_id
        || deposit.ethereum_genesis_validators_root != checkpoint.ethereum_genesis_validators_root
        || deposit.reserve.as_slice() != policy.bridge().reserve
        || deposit.bridge_domain.as_slice() != policy.bridge().dom_domain
    {
        return Err(CheckpointProgramError::InvalidStatement);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_target(
    policy: ProgramPolicy,
    statement: &CheckpointStatement,
    block_identifier: Hash256,
    total_difficulty: U256,
    native_state_root: Hash256,
    economic_state_root: [u8; 32],
    projections: &[ContextHeader],
    known_blocks: &BTreeMap<u64, [u8; 32]>,
) -> Result<(), CheckpointProgramError> {
    if block_identifier.as_bytes() != &statement.block
        || native_state_root.as_bytes() != &statement.state_root
        || total_difficulty != U256::from_big_endian(&statement.total_difficulty)
        || projections.len() != CHECKPOINT_CONTEXT_HEADER_COUNT
    {
        return Err(CheckpointProgramError::PublicMismatch);
    }
    let recent_headers: [ContextHeader; CHECKPOINT_CONTEXT_HEADER_COUNT] =
        projections
            .try_into()
            .map_err(|_| CheckpointProgramError::InvalidExtension)?;
    let required = required_historical_seed_heights(statement.height, policy.span())
        .map_err(|_| CheckpointProgramError::InvalidContext)?;
    let mut seed_anchors = [SeedAnchor::default(); CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS];
    for (index, height) in required.iter().copied().enumerate() {
        let slot = seed_anchors
            .get_mut(index)
            .ok_or(CheckpointProgramError::InvalidContext)?;
        *slot = SeedAnchor {
            height,
            block: known_blocks
                .get(&height)
                .copied()
                .ok_or(CheckpointProgramError::InvalidContext)?,
        };
    }
    let next_context = CheckpointContext {
        checkpoint_height: statement.height,
        checkpoint_block: statement.block,
        max_span: policy.span(),
        economic_state_root,
        recent_headers,
        seed_anchor_count: required
            .len()
            .try_into()
            .map_err(|_| CheckpointProgramError::InvalidContext)?,
        seed_anchors,
    };
    if next_context
        .commitment()
        .map_err(|_| CheckpointProgramError::InvalidContext)?
        != statement.context_hash
    {
        return Err(CheckpointProgramError::PublicMismatch);
    }
    Ok(())
}

fn insert_known(
    known: &mut BTreeMap<u64, [u8; 32]>,
    height: u64,
    block: [u8; 32],
) -> Result<(), CheckpointProgramError> {
    if block == [0; 32] {
        return Err(CheckpointProgramError::InvalidContext);
    }
    if let Some(existing) = known.insert(height, block) {
        if existing != block {
            return Err(CheckpointProgramError::InvalidContext);
        }
    }
    Ok(())
}

fn coinbase_maturity(network_magic: u32) -> u64 {
    if network_magic == NETWORK_MAGIC_REGTEST {
        REGTEST_COINBASE_MATURITY
    } else {
        dom_core::COINBASE_MATURITY
    }
}

fn map_economic(_: EconomicStateError) -> CheckpointProgramError {
    CheckpointProgramError::InvalidEconomicState
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_core::MAX_FUTURE_BLOCK_TIME;
    use dom_usdom_state::{
        BurnTimingPolicy, RESERVE_MAX_CERTIFICATE_LIFETIME_SECS, RESERVE_MIN_EXECUTION_WINDOW_SECS,
    };

    fn bridge() -> BridgeIdentity {
        let mut chain_id = [0; 32];
        chain_id[31] = 1;
        BridgeIdentity {
            dom_domain: [0x11; 32],
            ethereum_genesis_validators_root: [0x22; 32],
            ethereum_chain_id: chain_id,
            ethereum_checkpoint_policy_hash: [0x33; 32],
            ethereum_deposit_policy_hash: [0x44; 32],
            privacy_policy_hash: *dom_chain::native_usdom_v4::native_usdom_privacy_policy_hash()
                .as_bytes(),
            privacy_verifier_config_hash: [0x55; 32],
            reserve: [0x66; 20],
            burn_timing: BurnTimingPolicy {
                withdrawal_delay_secs: 86_400,
                min_execution_window_secs: RESERVE_MIN_EXECUTION_WINDOW_SECS,
                max_certificate_lifetime_secs: RESERVE_MAX_CERTIFICATE_LIFETIME_SECS,
                relay_safety_margin_secs: 3_600,
                max_ethereum_anchor_age_secs: 1_800,
                max_dom_clock_lead_secs: MAX_FUTURE_BLOCK_TIME,
            },
        }
    }

    #[test]
    fn policy_binds_genesis_chain_schedule_and_exact_span() {
        let genesis = Hash256::from_bytes([0x77; 32]);
        let chain_id = derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis);
        let schedule =
            NativeUsdomV4ActivationSchedule::new(NETWORK_MAGIC_REGTEST, chain_id, 100, bridge())
                .expect("schedule");
        let policy = CheckpointProgramPolicy::new(schedule, bridge(), genesis, 360, 30)
            .expect("program policy");
        assert_eq!(policy.span(), 390);
        assert_eq!(
            CheckpointProgramPolicy::new(
                schedule,
                bridge(),
                Hash256::from_bytes([0x78; 32]),
                360,
                30
            ),
            Err(CheckpointProgramError::InvalidPolicy)
        );
        assert_eq!(
            CheckpointProgramPolicy::new(schedule, bridge(), genesis, 0, 30),
            Err(CheckpointProgramError::InvalidPolicy)
        );
        assert_eq!(
            CheckpointProgramPolicy::new(schedule, bridge(), genesis, 360, 361),
            Err(CheckpointProgramError::InvalidPolicy)
        );

        let activation_state = NativeUsdomState::new(bridge()).unwrap();
        let v2_schedule = NativeUsdomV2ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            chain_id,
            101,
            Hash256::from_bytes([0x79; 32]),
            &activation_state,
        )
        .unwrap();
        let v2_policy = CheckpointProgramPolicyV2::new(
            v2_schedule,
            bridge(),
            &activation_state,
            genesis,
            360,
            30,
        )
        .unwrap();
        assert_eq!(v2_policy.schedule(), v2_schedule);
        // A distinct bridge proves that the snapshot binding fails closed.
        let mut wrong_bridge = bridge();
        wrong_bridge.reserve[0] ^= 1;
        let wrong_state = NativeUsdomState::new(wrong_bridge).unwrap();
        assert_eq!(
            CheckpointProgramPolicyV2::new(v2_schedule, bridge(), &wrong_state, genesis, 360, 30,),
            Err(CheckpointProgramError::InvalidPolicy)
        );
    }

    #[test]
    fn short_390_v6_target_binding_rejects_span_total_and_closure_drift() {
        let genesis = Hash256::from_bytes([0x77; 32]);
        let chain_id = derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis);
        let schedule =
            NativeUsdomV4ActivationSchedule::new(NETWORK_MAGIC_REGTEST, chain_id, 100, bridge())
                .expect("schedule");
        let policy = CheckpointProgramPolicy::new(schedule, bridge(), genesis, 360, 30)
            .expect("program policy");
        assert_eq!(policy.span(), 390);

        let expected = Some((10, 4, false));
        assert_eq!(
            validate_v6_target_state(Some((10, 4)), Some(false), expected),
            Ok(())
        );
        for (totals, closed) in [
            (Some((11, 4)), Some(false)),
            (Some((10, 5)), Some(false)),
            (Some((10, 4)), Some(true)),
            (None, Some(false)),
            (Some((10, 4)), None),
        ] {
            assert_eq!(
                validate_v6_target_state(totals, closed, expected),
                Err(CheckpointProgramError::PublicMismatch)
            );
        }
        assert_eq!(validate_v6_target_state(None, None, None), Ok(()));
    }
}
