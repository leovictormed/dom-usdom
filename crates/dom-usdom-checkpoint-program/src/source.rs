//! Authenticated source construction from one canonical DOM node snapshot.

use dom_chain::{
    canonical_header_identifier, load_persisted_usdom_v2_execution_witnesses,
    load_persisted_usdom_v4_package, rewind_persisted_usdom_v2_state_to_ancestor, ChainState,
    NativeUsdomV2ActivationSchedule, UsdomV4BlockPackage,
};
use dom_consensus::{Block, BlockHeader};
use dom_core::{BlockHeight, DomError, Hash256};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_usdom_checkpoint_statement::{
    checkpoint_economic_state_root, required_historical_seed_heights, CheckpointContext,
    ContextHeader, SeedAnchor, CHECKPOINT_CONTEXT_HEADER_COUNT,
    CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS,
};
use dom_usdom_state::StateCommitmentV2;
use lmdb::Transaction;
use usdom_ethereum_finality_experiment::{
    checkpoints::StaticCheckpointTrustPolicy, closures::StaticIssuanceClosureTrustPolicy,
    deposits::StaticDepositTrustPolicy,
};

use crate::{
    build_economic_block_proof_source, execute_checkpoint_segment_portable,
    CheckpointSegmentBlockInput, CheckpointSegmentNativeStateOpening, CheckpointSegmentPolicyInput,
    CheckpointSegmentPrivateInput, CheckpointSegmentState, EconomicBlockProofSource, EconomicRoots,
    EconomicState, CHECKPOINT_SEGMENT_TRANSITION_BYTES, ECONOMIC_BLOCK_TRANSITION_BYTES,
    MAX_CHECKPOINT_SEGMENT_NATIVE_WITNESS_BYTES, MAX_CHECKPOINT_SEGMENT_PACKAGE_BYTES,
    MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
};

/// Three maximum-size package/native inputs plus recursive economic claims fit
/// below the 64 MiB canonical private-input ceiling.
const MAX_AUTHENTICATED_SOURCE_SEGMENT_BLOCKS: u16 = 3;
const _: () = assert!(
    12 + MAX_AUTHENTICATED_SOURCE_SEGMENT_BLOCKS as usize
        * (12
            + MAX_CHECKPOINT_SEGMENT_PACKAGE_BYTES
            + MAX_CHECKPOINT_SEGMENT_NATIVE_WITNESS_BYTES
            + ECONOMIC_BLOCK_TRANSITION_BYTES)
        <= MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES
);

/// Recursive economic proof source attached to one block in a segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedEconomicBlockSource {
    block_index: usize,
    source: EconomicBlockProofSource,
}

impl AuthenticatedEconomicBlockSource {
    /// Zero-based block position in the containing checkpoint segment.
    pub const fn block_index(&self) -> usize {
        self.block_index
    }

    /// Canonical complete-block and ordered chunk source bytes.
    pub const fn source(&self) -> &EconomicBlockProofSource {
        &self.source
    }
}

/// Four exact files consumed by the authenticated RandomX statement exporter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedCheckpointSourceBundle {
    transition: [u8; CHECKPOINT_SEGMENT_TRANSITION_BYTES],
    private_input: Vec<u8>,
    policy_input: Vec<u8>,
    native_state_opening: Vec<u8>,
    economic_blocks: Vec<AuthenticatedEconomicBlockSource>,
}

/// Canonical proof-source segments for the latest fully confirmed checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedCheckpointSourceSet {
    previous_height: u64,
    target_height: u64,
    confirmation_height: u64,
    segments: Vec<AuthenticatedCheckpointSourceBundle>,
}

/// Canonical predecessor facts needed to ratify the first checkpoint.
///
/// The context commitment authenticates the ordinary DOM economic state,
/// recent timestamp window and all RandomX seed anchors needed by the first
/// extension. It is derived only from one atomic, fully opened canonical-chain
/// snapshot; callers cannot supply any of the returned fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedCheckpointBootstrapAnchor {
    /// Canonical predecessor height.
    pub height: u64,
    /// Canonical block identifier at `height`.
    pub block: [u8; 32],
    /// Keccak commitment of the canonical continuation context.
    pub context_hash: [u8; 32],
    /// Cumulative PoW difficulty at the predecessor, big-endian.
    pub total_difficulty: [u8; 32],
}

/// Derive the immutable checkpoint bootstrap anchor from canonical node state.
///
/// This performs a complete economic replay through the current tip and binds
/// the resulting sparse-state roots to the recent-header and RandomX seed
/// context. Every database read is made through one LMDB snapshot, so a
/// concurrent commit cannot produce a mixed anchor. Operators should still run
/// the exporter offline: a long-lived read transaction pins old LMDB pages and
/// could otherwise increase the live node's storage pressure.
pub fn authenticated_checkpoint_bootstrap_anchor(
    chain: &ChainState,
    max_span: u32,
) -> Result<AuthenticatedCheckpointBootstrapAnchor, DomError> {
    // Every byte used below is read through this one LMDB transaction. Merely
    // comparing the tip before and after replay is insufficient: a live node
    // can commit A -> B -> A (or replace an intermediate height) between
    // independent transactions and defeat such an ABA check.
    let txn = chain
        .store
        .env
        .begin_ro_txn()
        .map_err(|error| rejected(format!("checkpoint snapshot failed: {error}")))?;
    let tip = txn_get_hash(&txn, chain.store.db_tip, b"tip", "chain tip")?
        .ok_or_else(|| rejected("checkpoint bootstrap chain is empty"))?;
    let tip_header_bytes = txn
        .get(chain.store.db_blocks, &tip)
        .map_err(|error| rejected(format!("checkpoint tip header is unavailable: {error}")))?;
    let tip_header = BlockHeader::from_bytes(tip_header_bytes)
        .map_err(|error| rejected(format!("checkpoint tip header is corrupt: {error}")))?;
    let height = tip_header.height.0;
    if tip != *chain.tip_hash.as_bytes()
        || height != chain.tip_height.0
        || tip_header.total_difficulty != chain.tip_difficulty
    {
        return Err(rejected(
            "opened chain state does not match the atomic checkpoint snapshot",
        ));
    }
    let required_seeds = required_historical_seed_heights(height, max_span)
        .map_err(|error| rejected(format!("checkpoint seed schedule failed: {error}")))?;
    let first_recent = height
        .checked_sub((CHECKPOINT_CONTEXT_HEADER_COUNT - 1) as u64)
        .ok_or_else(|| rejected("checkpoint lacks eleven canonical headers"))?;
    let mut recent_headers = Vec::with_capacity(CHECKPOINT_CONTEXT_HEADER_COUNT);
    let mut seed_anchors = Vec::with_capacity(required_seeds.len());
    let mut state = EconomicState::default();
    let mut previous_hash = None;
    let mut previous_difficulty = None;
    for current in 0..=height {
        let key = current.to_le_bytes();
        let hash = txn_get_hash(&txn, chain.store.db_height, &key, "height index")?
            .ok_or_else(|| rejected(format!("canonical hash {current} is missing")))?;
        if current == 0 && hash != *chain.genesis_hash.as_bytes() {
            return Err(rejected(
                "canonical checkpoint snapshot has the wrong genesis identity",
            ));
        }
        let header_bytes = txn
            .get(chain.store.db_blocks, &hash)
            .map_err(|error| rejected(format!("canonical header {current} is missing: {error}")))?;
        let header = BlockHeader::from_bytes(header_bytes)
            .map_err(|error| rejected(format!("canonical header {current} is corrupt: {error}")))?;
        validate_snapshot_header(
            chain.network_magic,
            current,
            hash,
            header_bytes,
            &header,
            previous_hash,
            previous_difficulty,
        )?;
        let body = txn
            .get(chain.store.db_block_bodies, &hash)
            .map_err(|error| {
                rejected(format!(
                    "canonical block body {current} is missing: {error}"
                ))
            })?;
        if current == BlockHeight::GENESIS.0
            && chain.network_magic == dom_core::NETWORK_MAGIC_MAINNET
        {
            // The frozen legacy mainnet genesis has a special representation,
            // but it must still be the exact compiled-in body. Falling back to
            // generic decoding here would let a locally altered genesis seed
            // the economic replay.
            dom_chain::validate_mainnet_genesis_identity(body).map_err(|error| {
                rejected(format!(
                    "canonical mainnet genesis body is not the frozen identity: {error}"
                ))
            })?;
        } else {
            let block = Block::from_bytes(body).map_err(|error| {
                rejected(format!("canonical block {current} is corrupt: {error}"))
            })?;
            if block.header != header {
                return Err(rejected(format!(
                    "canonical block {current} does not match its indexed header"
                )));
            }
            state
                .apply_block(&block, coinbase_maturity(chain.network_magic))
                .map_err(|error| {
                    rejected(format!(
                        "canonical economic replay failed at height {current}: {error}"
                    ))
                })?;
        }
        if current >= first_recent {
            recent_headers.push(ContextHeader {
                height: current,
                block: hash,
                timestamp: header.timestamp.0,
            });
        }
        if required_seeds.get(seed_anchors.len()) == Some(&current) {
            seed_anchors.push(SeedAnchor {
                height: current,
                block: hash,
            });
        }
        previous_hash = Some(hash);
        previous_difficulty = Some(header.total_difficulty);
    }
    if previous_hash != Some(tip)
        || recent_headers.len() != CHECKPOINT_CONTEXT_HEADER_COUNT
        || seed_anchors.len() != required_seeds.len()
    {
        return Err(rejected("checkpoint snapshot inventory is incomplete"));
    }
    let economic = economic_roots(&state)?;
    let context = checkpoint_context_from_snapshot(
        height,
        tip,
        economic,
        max_span,
        &recent_headers,
        &seed_anchors,
    )?;
    let context_hash = context
        .commitment()
        .map_err(|error| rejected(format!("checkpoint bootstrap commitment failed: {error}")))?;
    let mut total_difficulty = [0u8; 32];
    tip_header
        .total_difficulty
        .to_big_endian(&mut total_difficulty);
    if total_difficulty == [0; 32] {
        return Err(rejected("checkpoint bootstrap total difficulty is zero"));
    }
    Ok(AuthenticatedCheckpointBootstrapAnchor {
        height,
        block: tip,
        context_hash,
        total_difficulty,
    })
}

fn txn_get_hash(
    txn: &lmdb::RoTransaction<'_>,
    database: lmdb::Database,
    key: &[u8],
    label: &str,
) -> Result<Option<[u8; 32]>, DomError> {
    match txn.get(database, &key) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut hash = [0; 32];
            hash.copy_from_slice(bytes);
            Ok(Some(hash))
        }
        Ok(_) => Err(rejected(format!("corrupt {label}"))),
        Err(lmdb::Error::NotFound) => Ok(None),
        Err(error) => Err(rejected(format!("read {label} failed: {error}"))),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_snapshot_header(
    network_magic: u32,
    height: u64,
    hash: [u8; 32],
    encoded: &[u8],
    header: &BlockHeader,
    previous_hash: Option<[u8; 32]>,
    previous_difficulty: Option<primitive_types::U256>,
) -> Result<(), DomError> {
    if header.height.0 != height
        || canonical_header_identifier(network_magic, encoded)?.as_bytes() != &hash
        || (height == 0 && (previous_hash.is_some() || header.prev_hash != Hash256::ZERO))
        || (height > 0 && header.prev_hash.as_bytes() != previous_hash.as_ref().unwrap_or(&[0; 32]))
        || previous_difficulty.is_some_and(|difficulty| header.total_difficulty <= difficulty)
    {
        return Err(rejected(format!(
            "canonical header {height} fails identity, ancestry, or cumulative-work validation"
        )));
    }
    Ok(())
}

fn checkpoint_context_from_snapshot(
    height: u64,
    block: [u8; 32],
    economic: EconomicRoots,
    max_span: u32,
    recent: &[ContextHeader],
    seeds: &[SeedAnchor],
) -> Result<CheckpointContext, DomError> {
    let recent_headers: [ContextHeader; CHECKPOINT_CONTEXT_HEADER_COUNT] = recent
        .try_into()
        .map_err(|_| rejected("checkpoint recent-header inventory is incomplete"))?;
    if seeds.len() > CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS {
        return Err(rejected(
            "checkpoint seed-anchor inventory exceeds its bound",
        ));
    }
    let mut seed_anchors = [SeedAnchor::default(); CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS];
    seed_anchors[..seeds.len()].copy_from_slice(seeds);
    let context = CheckpointContext {
        checkpoint_height: height,
        checkpoint_block: block,
        max_span,
        economic_state_root: checkpoint_economic_state_root(
            economic.utxo_root,
            economic.kernel_root,
        )
        .map_err(|error| rejected(format!("economic context root failed: {error}")))?,
        recent_headers,
        seed_anchor_count: seeds
            .len()
            .try_into()
            .map_err(|_| rejected("checkpoint seed-anchor count overflow"))?,
        seed_anchors,
    };
    context
        .validate()
        .map_err(|error| rejected(format!("checkpoint context failed: {error}")))?;
    Ok(context)
}

impl AuthenticatedCheckpointSourceSet {
    /// Previously finalized checkpoint height opened by the first segment.
    pub const fn previous_height(&self) -> u64 {
        self.previous_height
    }

    /// Checkpoint target that must be reached at an exact segment boundary.
    pub const fn target_height(&self) -> u64 {
        self.target_height
    }

    /// Terminal work-confirmation height reached by the final segment.
    pub const fn confirmation_height(&self) -> u64 {
        self.confirmation_height
    }

    /// Ordered source bundles, each covering at most 32 canonical blocks.
    pub fn segments(&self) -> &[AuthenticatedCheckpointSourceBundle] {
        &self.segments
    }
}

impl AuthenticatedCheckpointSourceBundle {
    /// Canonical transition bytes.
    pub fn transition_bytes(&self) -> &[u8; CHECKPOINT_SEGMENT_TRANSITION_BYTES] {
        &self.transition
    }

    /// Canonical private segment bytes.
    pub fn private_input_bytes(&self) -> &[u8] {
        &self.private_input
    }

    /// Canonical immutable policy bytes.
    pub fn policy_input_bytes(&self) -> &[u8] {
        &self.policy_input
    }

    /// Canonical previous native-state opening.
    pub fn native_state_opening_bytes(&self) -> &[u8] {
        &self.native_state_opening
    }

    /// Blocks whose large economic witness is supplied through recursion.
    pub fn economic_blocks(&self) -> &[AuthenticatedEconomicBlockSource] {
        &self.economic_blocks
    }
}

fn economic_source_component(
    state: &EconomicState,
    block: &Block,
    package_bytes: &[u8],
    network_magic: u32,
) -> Result<(Vec<u8>, Option<EconomicBlockProofSource>), DomError> {
    let source = build_economic_block_proof_source(
        state,
        block,
        package_bytes,
        network_magic,
        coinbase_maturity(network_magic),
    )
    .map_err(|error| rejected(format!("economic recursive source failed: {error}")))?;
    Ok((source.transition_bytes().to_vec(), Some(source)))
}

/// Build the first one-block candidate-v2 checkpoint source from canonical
/// persisted node state.
///
/// This narrow bootstrap accepts no block, height, seed, package or state-root
/// override. The chain must be exactly at the first candidate-v2 height and
/// the supplied current native state must be the runtime-restored state for
/// that tip. Callers that share a live node must retain its chain and native
/// runtime locks for the duration of this function.
#[allow(clippy::too_many_arguments)]
pub fn build_first_v2_checkpoint_source(
    chain: &ChainState,
    schedule: NativeUsdomV2ActivationSchedule,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    issuance_closure_policy: &StaticIssuanceClosureTrustPolicy,
    spend_verifying_key: &[u8],
    current_native_state: StateCommitmentV2,
    randomx_receipt_image_id: [u8; 32],
) -> Result<AuthenticatedCheckpointSourceBundle, DomError> {
    let first_height = schedule.first_v2_height();
    let tip = chain.tip_hash;
    if randomx_receipt_image_id == [0; 32]
        || schedule.network_magic() != chain.network_magic
        || schedule.chain_id()
            != dom_consensus::derive_chain_id(chain.network_magic, &chain.genesis_hash)
        || chain.tip_height.0 != first_height
        || first_height < CHECKPOINT_CONTEXT_HEADER_COUNT as u64
        || chain.store.get_chain_tip()? != Some(*tip.as_bytes())
        || chain.store.get_hash_at_height(first_height)? != Some(*tip.as_bytes())
    {
        return Err(rejected(
            "canonical candidate-v2 checkpoint source identity is unavailable",
        ));
    }

    let package_bytes = load_persisted_usdom_v4_package(&chain.store, chain.network_magic, tip)?
        .ok_or_else(|| rejected("canonical candidate-v2 package is missing"))?;
    let package = UsdomV4BlockPackage::from_bytes(&package_bytes)?;
    let block = package.block();
    if block.header.height.0 != first_height
        || block.header.prev_hash != schedule.activation_parent()
    {
        return Err(rejected(
            "canonical candidate-v2 package does not open the activation block",
        ));
    }
    let header_bytes = block.header.to_bytes()?;
    if canonical_header_identifier(chain.network_magic, &header_bytes)? != tip {
        return Err(rejected(
            "canonical candidate-v2 package identifier mismatch",
        ));
    }

    let previous_native_state = rewind_persisted_usdom_v2_state_to_ancestor(
        &chain.store,
        tip,
        current_native_state,
        schedule.activation_parent(),
        schedule,
    )?;
    let native_witnesses = load_persisted_usdom_v2_execution_witnesses(&chain.store, tip)?
        .ok_or_else(|| rejected("canonical candidate-v2 execution witnesses are missing"))?;

    let parent_height = first_height
        .checked_sub(1)
        .ok_or_else(|| rejected("candidate-v2 activation height underflow"))?;
    let mut economic_state = reconstruct_economic_state(chain, parent_height)?;
    let previous_economic = economic_roots(&economic_state)?;
    let (economic_component, economic_source) =
        economic_source_component(&economic_state, block, &package_bytes, chain.network_magic)?;
    economic_state
        .apply_block(block, coinbase_maturity(chain.network_magic))
        .map_err(|error| rejected(format!("economic state advance failed: {error}")))?;
    let next_economic = economic_roots(&economic_state)?;

    let parent_hash = canonical_hash_at_height(chain, parent_height)?;
    if parent_hash != schedule.activation_parent() {
        return Err(rejected("candidate-v2 activation parent is not canonical"));
    }
    let parent_header = canonical_header_at_height(chain, parent_height)?;
    let previous_context = checkpoint_context(chain, parent_height, previous_economic, 1)?;
    let next_context = checkpoint_context(chain, first_height, next_economic, 1)?;
    let chain_id = schedule.chain_id();
    let schedule_commitment = schedule.commitment();
    let mut previous_total_difficulty = [0u8; 32];
    parent_header
        .total_difficulty
        .to_big_endian(&mut previous_total_difficulty);
    let mut next_total_difficulty = [0u8; 32];
    block
        .header
        .total_difficulty
        .to_big_endian(&mut next_total_difficulty);
    let previous = CheckpointSegmentState {
        network_magic: chain.network_magic,
        chain_id: *chain_id.as_bytes(),
        activation_schedule_commitment: *schedule_commitment.as_bytes(),
        checkpoint_config_hash: checkpoint_policy.checkpoint().checkpoint_config_hash.into(),
        checkpoint_policy_hash: checkpoint_policy.policy_hash().into(),
        deposit_policy_hash: deposit_policy.policy_hash().into(),
        privacy_verifier_config_hash: previous_native_state.privacy_verifier_config_hash,
        randomx_receipt_image_id,
        height: parent_height,
        block_hash: *parent_hash.as_bytes(),
        native_state_root: *previous_native_state.root().as_bytes(),
        economic_utxo_root: previous_economic.utxo_root,
        economic_kernel_root: previous_economic.kernel_root,
        total_difficulty: previous_total_difficulty,
        context: previous_context,
    };
    let next = CheckpointSegmentState {
        height: first_height,
        block_hash: *tip.as_bytes(),
        native_state_root: *current_native_state.root().as_bytes(),
        economic_utxo_root: next_economic.utxo_root,
        economic_kernel_root: next_economic.kernel_root,
        total_difficulty: next_total_difficulty,
        context: next_context,
        ..previous
    };

    let private_input = CheckpointSegmentPrivateInput::new(vec![CheckpointSegmentBlockInput::new(
        package_bytes,
        native_witnesses.to_bytes()?,
        economic_component,
    )
    .map_err(|error| rejected(format!("checkpoint block input failed: {error}")))?])
    .map_err(|error| rejected(format!("checkpoint private input failed: {error}")))?;
    let transition = private_input
        .transition_statement_with_totals(
            previous,
            next,
            previous_native_state.total_issued,
            previous_native_state.total_burned,
            current_native_state.total_issued,
            current_native_state.total_burned,
            previous_native_state.issuance_closure.is_some(),
            current_native_state.issuance_closure.is_some(),
        )
        .map_err(|error| rejected(format!("checkpoint transition failed: {error}")))?;
    let policy_input = checkpoint_policy_input(
        *chain.genesis_hash.as_bytes(),
        schedule.to_bytes(),
        checkpoint_policy,
        deposit_policy,
        Some(issuance_closure_policy),
        spend_verifying_key.to_vec(),
    )
    .map_err(|error| rejected(format!("checkpoint policy input failed: {error}")))?;
    let native_opening = CheckpointSegmentNativeStateOpening::new(
        previous_native_state
            .to_bytes()
            .map_err(|error| rejected(format!("native state opening encoding failed: {error}")))?,
    )
    .map_err(|error| rejected(format!("native state opening failed: {error}")))?;

    execute_checkpoint_segment_portable(
        &transition,
        &private_input,
        &policy_input,
        &native_opening,
    )
    .map_err(|error| rejected(format!("portable checkpoint self-check failed: {error}")))?;

    if chain.store.get_chain_tip()? != Some(*tip.as_bytes())
        || chain.store.get_hash_at_height(first_height)? != Some(*tip.as_bytes())
    {
        return Err(rejected(
            "canonical DOM tip changed while checkpoint source was built",
        ));
    }

    Ok(AuthenticatedCheckpointSourceBundle {
        transition: transition
            .to_bytes()
            .map_err(|error| rejected(format!("checkpoint transition encoding failed: {error}")))?,
        private_input: private_input
            .to_bytes()
            .map_err(|error| rejected(format!("private input encoding failed: {error}")))?,
        policy_input: policy_input
            .to_bytes()
            .map_err(|error| rejected(format!("policy input encoding failed: {error}")))?,
        native_state_opening: native_opening
            .to_bytes()
            .map_err(|error| rejected(format!("native opening encoding failed: {error}")))?,
        economic_blocks: economic_source
            .into_iter()
            .map(|source| AuthenticatedEconomicBlockSource {
                block_index: 0,
                source,
            })
            .collect(),
    })
}

/// Build every bounded source segment for the latest fully confirmed
/// candidate-v2 checkpoint available at the canonical tip.
///
/// The checkpoint cadence is a hash-pinned runtime-manifest input. Segment
/// boundaries are deterministic and never cross the checkpoint target: each
/// target and confirmation phase is partitioned into consecutive chunks of at
/// most [`MAX_AUTHENTICATED_SOURCE_SEGMENT_BLOCKS`]. A later canonical tip is allowed,
/// but the selected confirmation point is always the latest complete cadence.
#[allow(clippy::too_many_arguments)]
pub fn build_latest_v2_checkpoint_sources(
    chain: &ChainState,
    schedule: NativeUsdomV2ActivationSchedule,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    issuance_closure_policy: &StaticIssuanceClosureTrustPolicy,
    spend_verifying_key: &[u8],
    current_native_state: StateCommitmentV2,
    randomx_receipt_image_id: [u8; 32],
    checkpoint_interval_blocks: u32,
    checkpoint_confirmation_depth_blocks: u32,
) -> Result<AuthenticatedCheckpointSourceSet, DomError> {
    let total_span = checkpoint_interval_blocks
        .checked_add(checkpoint_confirmation_depth_blocks)
        .ok_or_else(|| rejected("candidate-v2 checkpoint span overflow"))?;
    let maximum_rewind = checkpoint_interval_blocks
        .checked_mul(2)
        .and_then(|span| span.checked_add(checkpoint_confirmation_depth_blocks))
        .and_then(|span| span.checked_sub(1))
        .ok_or_else(|| rejected("candidate-v2 checkpoint rewind bound overflow"))?;
    let first_height = schedule.first_v2_height();
    let activation_parent_height = first_height
        .checked_sub(1)
        .ok_or_else(|| rejected("candidate-v2 activation height underflow"))?;
    let tip = chain.tip_hash;
    if randomx_receipt_image_id == [0; 32]
        || checkpoint_interval_blocks == 0
        || checkpoint_interval_blocks > 360
        || checkpoint_confirmation_depth_blocks == 0
        || checkpoint_confirmation_depth_blocks > checkpoint_interval_blocks
        || total_span > dom_usdom_checkpoint_statement::MAX_CONTEXT_SPAN
        || u64::from(maximum_rewind) > dom_core::MAX_REORG_DEPTH_POLICY
        || schedule.network_magic() != chain.network_magic
        || schedule.chain_id()
            != dom_consensus::derive_chain_id(chain.network_magic, &chain.genesis_hash)
        || chain.tip_height.0 < first_height
        || activation_parent_height < CHECKPOINT_CONTEXT_HEADER_COUNT as u64 - 1
        || chain.store.get_chain_tip()? != Some(*tip.as_bytes())
        || chain.store.get_hash_at_height(chain.tip_height.0)? != Some(*tip.as_bytes())
    {
        return Err(rejected(
            "canonical candidate-v2 checkpoint source identity is unavailable",
        ));
    }
    let available = chain
        .tip_height
        .0
        .checked_sub(activation_parent_height)
        .ok_or_else(|| rejected("candidate-v2 checkpoint height underflow"))?;
    if available < u64::from(total_span) {
        return Err(rejected(
            "no fully confirmed candidate-v2 checkpoint is available",
        ));
    }
    let cycles = available
        .checked_sub(u64::from(checkpoint_confirmation_depth_blocks))
        .ok_or_else(|| rejected("candidate-v2 confirmation depth underflow"))?
        / u64::from(checkpoint_interval_blocks);
    if cycles == 0 {
        return Err(rejected(
            "no fully confirmed candidate-v2 checkpoint is available",
        ));
    }
    let target_height = activation_parent_height
        .checked_add(
            cycles
                .checked_mul(u64::from(checkpoint_interval_blocks))
                .ok_or_else(|| rejected("candidate-v2 target height overflow"))?,
        )
        .ok_or_else(|| rejected("candidate-v2 target height overflow"))?;
    let previous_height = target_height
        .checked_sub(u64::from(checkpoint_interval_blocks))
        .ok_or_else(|| rejected("candidate-v2 previous height underflow"))?;
    let confirmation_height = target_height
        .checked_add(u64::from(checkpoint_confirmation_depth_blocks))
        .ok_or_else(|| rejected("candidate-v2 confirmation height overflow"))?;
    if previous_height < activation_parent_height || confirmation_height > chain.tip_height.0 {
        return Err(rejected("candidate-v2 checkpoint cadence is unavailable"));
    }

    let previous_hash = canonical_hash_at_height(chain, previous_height)?;
    let mut segment_native_state = rewind_persisted_usdom_v2_state_to_ancestor(
        &chain.store,
        tip,
        current_native_state,
        previous_hash,
        schedule,
    )?;
    let mut economic_state = reconstruct_economic_state(chain, previous_height)?;
    let policy_input = checkpoint_policy_input(
        *chain.genesis_hash.as_bytes(),
        schedule.to_bytes(),
        checkpoint_policy,
        deposit_policy,
        Some(issuance_closure_policy),
        spend_verifying_key.to_vec(),
    )
    .map_err(|error| rejected(format!("checkpoint policy input failed: {error}")))?;
    let policy_bytes = policy_input
        .to_bytes()
        .map_err(|error| rejected(format!("policy input encoding failed: {error}")))?;
    let boundaries = segment_boundaries(previous_height, target_height, confirmation_height)?;
    let mut segments = Vec::with_capacity(boundaries.len());

    for (segment_start, segment_end) in boundaries {
        let start_hash = canonical_hash_at_height(chain, segment_start)?;
        let start_economic = economic_roots(&economic_state)?;
        let start_header = canonical_header_at_height(chain, segment_start)?;
        let previous = checkpoint_segment_state(
            chain,
            schedule,
            checkpoint_policy,
            deposit_policy,
            segment_native_state,
            randomx_receipt_image_id,
            segment_start,
            start_hash,
            start_header,
            start_economic,
            total_span,
        )?;
        let mut block_inputs = Vec::with_capacity((segment_end - segment_start) as usize);
        let mut economic_blocks = Vec::new();
        for height in segment_start + 1..=segment_end {
            let block_hash = canonical_hash_at_height(chain, height)?;
            let package_bytes =
                load_persisted_usdom_v4_package(&chain.store, chain.network_magic, block_hash)?
                    .ok_or_else(|| {
                        rejected(format!(
                            "canonical candidate-v2 package {height} is missing"
                        ))
                    })?;
            let package = UsdomV4BlockPackage::from_bytes(&package_bytes)?;
            let block = package.block();
            if block.header.height.0 != height
                || canonical_header_identifier(chain.network_magic, &block.header.to_bytes()?)?
                    != block_hash
            {
                return Err(rejected(format!(
                    "canonical candidate-v2 package {height} identifier mismatch"
                )));
            }
            let witnesses = load_persisted_usdom_v2_execution_witnesses(&chain.store, block_hash)?
                .ok_or_else(|| {
                    rejected(format!(
                        "canonical candidate-v2 execution witnesses {height} are missing"
                    ))
                })?;
            let (economic_component, economic_source) = economic_source_component(
                &economic_state,
                block,
                &package_bytes,
                chain.network_magic,
            )
            .map_err(|error| rejected(format!("economic source failed at {height}: {error}")))?;
            economic_state
                .apply_block(block, coinbase_maturity(chain.network_magic))
                .map_err(|error| {
                    rejected(format!(
                        "economic state advance failed at {height}: {error}"
                    ))
                })?;
            let block_index = block_inputs.len();
            block_inputs.push(
                CheckpointSegmentBlockInput::new(
                    package_bytes,
                    witnesses.to_bytes()?,
                    economic_component,
                )
                .map_err(|error| rejected(format!("checkpoint block input failed: {error}")))?,
            );
            if let Some(source) = economic_source {
                economic_blocks.push(AuthenticatedEconomicBlockSource {
                    block_index,
                    source,
                });
            }
        }
        let end_hash = canonical_hash_at_height(chain, segment_end)?;
        let end_native_state = rewind_persisted_usdom_v2_state_to_ancestor(
            &chain.store,
            tip,
            current_native_state,
            end_hash,
            schedule,
        )?;
        let end_economic = economic_roots(&economic_state)?;
        let end_header = canonical_header_at_height(chain, segment_end)?;
        let next = checkpoint_segment_state(
            chain,
            schedule,
            checkpoint_policy,
            deposit_policy,
            end_native_state,
            randomx_receipt_image_id,
            segment_end,
            end_hash,
            end_header,
            end_economic,
            total_span,
        )?;
        let private_input = CheckpointSegmentPrivateInput::new(block_inputs)
            .map_err(|error| rejected(format!("checkpoint private input failed: {error}")))?;
        let transition = private_input
            .transition_statement_with_totals(
                previous,
                next,
                segment_native_state.total_issued,
                segment_native_state.total_burned,
                end_native_state.total_issued,
                end_native_state.total_burned,
                segment_native_state.issuance_closure.is_some(),
                end_native_state.issuance_closure.is_some(),
            )
            .map_err(|error| rejected(format!("checkpoint transition failed: {error}")))?;
        let native_opening =
            CheckpointSegmentNativeStateOpening::new(segment_native_state.to_bytes().map_err(
                |error| rejected(format!("native state opening encoding failed: {error}")),
            )?)
            .map_err(|error| rejected(format!("native state opening failed: {error}")))?;
        execute_checkpoint_segment_portable(
            &transition,
            &private_input,
            &policy_input,
            &native_opening,
        )
        .map_err(|error| rejected(format!("portable checkpoint self-check failed: {error}")))?;
        segments.push(AuthenticatedCheckpointSourceBundle {
            transition: transition.to_bytes().map_err(|error| {
                rejected(format!("checkpoint transition encoding failed: {error}"))
            })?,
            private_input: private_input
                .to_bytes()
                .map_err(|error| rejected(format!("private input encoding failed: {error}")))?,
            policy_input: policy_bytes.clone(),
            native_state_opening: native_opening
                .to_bytes()
                .map_err(|error| rejected(format!("native opening encoding failed: {error}")))?,
            economic_blocks,
        });
        segment_native_state = end_native_state;
    }

    if chain.store.get_chain_tip()? != Some(*tip.as_bytes())
        || chain.store.get_hash_at_height(chain.tip_height.0)? != Some(*tip.as_bytes())
    {
        return Err(rejected(
            "canonical DOM tip changed while checkpoint sources were built",
        ));
    }
    Ok(AuthenticatedCheckpointSourceSet {
        previous_height,
        target_height,
        confirmation_height,
        segments,
    })
}

fn segment_boundaries(
    previous_height: u64,
    target_height: u64,
    confirmation_height: u64,
) -> Result<Vec<(u64, u64)>, DomError> {
    let mut boundaries = Vec::new();
    for phase_end in [target_height, confirmation_height] {
        let mut start = boundaries.last().map_or(previous_height, |(_, end)| *end);
        while start < phase_end {
            let end = start
                .checked_add(u64::from(MAX_AUTHENTICATED_SOURCE_SEGMENT_BLOCKS))
                .ok_or_else(|| rejected("checkpoint segment boundary overflow"))?
                .min(phase_end);
            boundaries.push((start, end));
            start = end;
        }
    }
    if boundaries.is_empty() {
        return Err(rejected("empty checkpoint source boundary set"));
    }
    Ok(boundaries)
}

#[allow(clippy::too_many_arguments)]
fn checkpoint_segment_state(
    chain: &ChainState,
    schedule: NativeUsdomV2ActivationSchedule,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    native_state: StateCommitmentV2,
    randomx_receipt_image_id: [u8; 32],
    height: u64,
    block_hash: Hash256,
    header: BlockHeader,
    economic: EconomicRoots,
    max_span: u32,
) -> Result<CheckpointSegmentState, DomError> {
    let mut total_difficulty = [0u8; 32];
    header.total_difficulty.to_big_endian(&mut total_difficulty);
    Ok(CheckpointSegmentState {
        network_magic: chain.network_magic,
        chain_id: *schedule.chain_id().as_bytes(),
        activation_schedule_commitment: *schedule.commitment().as_bytes(),
        checkpoint_config_hash: checkpoint_policy.checkpoint().checkpoint_config_hash.into(),
        checkpoint_policy_hash: checkpoint_policy.policy_hash().into(),
        deposit_policy_hash: deposit_policy.policy_hash().into(),
        privacy_verifier_config_hash: native_state.privacy_verifier_config_hash,
        randomx_receipt_image_id,
        height,
        block_hash: *block_hash.as_bytes(),
        native_state_root: *native_state.root().as_bytes(),
        economic_utxo_root: economic.utxo_root,
        economic_kernel_root: economic.kernel_root,
        total_difficulty,
        context: checkpoint_context(chain, height, economic, max_span)?,
    })
}

fn checkpoint_policy_input(
    dom_genesis_hash: [u8; 32],
    activation_schedule: [u8; crate::CHECKPOINT_SEGMENT_ACTIVATION_SCHEDULE_BYTES],
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    closure_policy: Option<&StaticIssuanceClosureTrustPolicy>,
    spend_verifying_key: Vec<u8>,
) -> Result<CheckpointSegmentPolicyInput, DomError> {
    let checkpoint = checkpoint_policy
        .to_bytes()
        .try_into()
        .map_err(|_| rejected("checkpoint policy has an invalid canonical length"))?;
    let deposit = deposit_policy
        .to_bytes()
        .try_into()
        .map_err(|_| rejected("deposit policy has an invalid canonical length"))?;
    match closure_policy {
        Some(policy) => CheckpointSegmentPolicyInput::new_with_issuance_closure(
            dom_genesis_hash,
            activation_schedule,
            checkpoint,
            deposit,
            policy
                .to_bytes()
                .try_into()
                .map_err(|_| rejected("closure policy has an invalid canonical length"))?,
            spend_verifying_key,
        ),
        None => CheckpointSegmentPolicyInput::new(
            dom_genesis_hash,
            activation_schedule,
            checkpoint,
            deposit,
            spend_verifying_key,
        ),
    }
    .map_err(|error| rejected(format!("checkpoint policy input failed: {error}")))
}

fn reconstruct_economic_state(
    chain: &ChainState,
    terminal_height: u64,
) -> Result<EconomicState, DomError> {
    let mut state = EconomicState::default();
    for height in 0..=terminal_height {
        let hash = canonical_hash_at_height(chain, height)?;
        let body = chain
            .store
            .get_block_body(hash.as_bytes())?
            .ok_or_else(|| rejected(format!("canonical block body {height} is missing")))?;
        if height == BlockHeight::GENESIS.0
            && chain.network_magic == dom_core::NETWORK_MAGIC_MAINNET
            && dom_chain::validate_mainnet_genesis_identity(&body).is_ok()
        {
            continue;
        }
        let block = Block::from_bytes(&body)
            .map_err(|error| rejected(format!("canonical block {height} is corrupt: {error}")))?;
        if block.header.height.0 != height {
            return Err(rejected(format!(
                "canonical block {height} declares another height"
            )));
        }
        let header_bytes = block.header.to_bytes()?;
        if canonical_header_identifier(chain.network_magic, &header_bytes)? != hash {
            return Err(rejected(format!(
                "canonical block {height} identifier mismatch"
            )));
        }
        state
            .apply_block(&block, coinbase_maturity(chain.network_magic))
            .map_err(|error| {
                rejected(format!(
                    "canonical economic replay failed at height {height}: {error}"
                ))
            })?;
    }
    Ok(state)
}

fn checkpoint_context(
    chain: &ChainState,
    height: u64,
    economic: EconomicRoots,
    max_span: u32,
) -> Result<CheckpointContext, DomError> {
    let first = height
        .checked_sub((CHECKPOINT_CONTEXT_HEADER_COUNT - 1) as u64)
        .ok_or_else(|| rejected("checkpoint lacks eleven canonical headers"))?;
    let mut recent_headers = [ContextHeader {
        height: 0,
        block: [0; 32],
        timestamp: 0,
    }; CHECKPOINT_CONTEXT_HEADER_COUNT];
    for (index, projection) in recent_headers.iter_mut().enumerate() {
        let current = first
            .checked_add(index as u64)
            .ok_or_else(|| rejected("checkpoint header height overflow"))?;
        let hash = canonical_hash_at_height(chain, current)?;
        let header = canonical_header_at_height(chain, current)?;
        *projection = ContextHeader {
            height: current,
            block: *hash.as_bytes(),
            timestamp: header.timestamp.0,
        };
    }
    let required = required_historical_seed_heights(height, max_span)
        .map_err(|error| rejected(format!("checkpoint seed schedule failed: {error}")))?;
    let mut seed_anchors = [SeedAnchor::default(); CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS];
    for (index, seed_height) in required.iter().copied().enumerate() {
        let slot = seed_anchors
            .get_mut(index)
            .ok_or_else(|| rejected("checkpoint seed-anchor count exceeds context capacity"))?;
        *slot = SeedAnchor {
            height: seed_height,
            block: *canonical_hash_at_height(chain, seed_height)?.as_bytes(),
        };
    }
    let checkpoint = canonical_hash_at_height(chain, height)?;
    let context = CheckpointContext {
        checkpoint_height: height,
        checkpoint_block: *checkpoint.as_bytes(),
        max_span,
        economic_state_root: checkpoint_economic_state_root(
            economic.utxo_root,
            economic.kernel_root,
        )
        .map_err(|error| rejected(format!("economic context root failed: {error}")))?,
        recent_headers,
        seed_anchor_count: required
            .len()
            .try_into()
            .map_err(|_| rejected("checkpoint seed-anchor count overflow"))?,
        seed_anchors,
    };
    context
        .validate()
        .map_err(|error| rejected(format!("checkpoint context failed: {error}")))?;
    Ok(context)
}

fn canonical_hash_at_height(chain: &ChainState, height: u64) -> Result<Hash256, DomError> {
    chain
        .store
        .get_hash_at_height(height)?
        .map(Hash256::from_bytes)
        .ok_or_else(|| rejected(format!("canonical hash {height} is missing")))
}

fn canonical_header_at_height(chain: &ChainState, height: u64) -> Result<BlockHeader, DomError> {
    let hash = canonical_hash_at_height(chain, height)?;
    let bytes = chain
        .store
        .get_block_header(hash.as_bytes())?
        .ok_or_else(|| rejected(format!("canonical header {height} is missing")))?;
    let header = BlockHeader::from_bytes(&bytes)
        .map_err(|error| rejected(format!("canonical header {height} is corrupt: {error}")))?;
    if header.height.0 != height
        || canonical_header_identifier(chain.network_magic, &bytes)? != hash
    {
        return Err(rejected(format!(
            "canonical header {height} identity mismatch"
        )));
    }
    Ok(header)
}

fn economic_roots(state: &EconomicState) -> Result<EconomicRoots, DomError> {
    Ok(EconomicRoots {
        utxo_root: state
            .utxo_set_root()
            .map_err(|error| rejected(format!("economic UTXO root failed: {error}")))?,
        kernel_root: state
            .kernel_set_root()
            .map_err(|error| rejected(format!("economic kernel root failed: {error}")))?,
    })
}

const fn coinbase_maturity(network_magic: u32) -> u64 {
    if network_magic == dom_core::NETWORK_MAGIC_REGTEST {
        dom_core::REGTEST_COINBASE_MATURITY
    } else {
        dom_core::COINBASE_MATURITY
    }
}

fn rejected(message: impl Into<String>) -> DomError {
    DomError::PolicyRejected(message.into())
}

#[cfg(test)]
mod tests {
    use super::{
        segment_boundaries, validate_snapshot_header, MAX_AUTHENTICATED_SOURCE_SEGMENT_BLOCKS,
    };
    use dom_chain::canonical_header_identifier;
    use dom_consensus::{block::ProofOfWork, BlockHeader};
    use dom_core::{BlockHeight, Hash256, Timestamp, NETWORK_MAGIC_REGTEST};
    use dom_pow::CompactTarget;
    use dom_serialization::DomSerialize;
    use primitive_types::U256;

    fn header(height: u64, previous: [u8; 32], difficulty: u64) -> BlockHeader {
        BlockHeader {
            version: 4,
            height: BlockHeight(height),
            prev_hash: Hash256::from_bytes(previous),
            timestamp: Timestamp(1_700_000_000 + height),
            output_root: Hash256::from_bytes([2; 32]),
            kernel_root: Hash256::from_bytes([3; 32]),
            rangeproof_root: Hash256::from_bytes([4; 32]),
            total_kernel_offset: [0; 32],
            target: CompactTarget(0x207f_ffff),
            total_difficulty: U256::from(difficulty),
            pow: ProofOfWork {
                nonce: height,
                randomx_hash: Hash256::from_bytes([5; 32]),
            },
        }
    }

    fn encoded_and_id(header: &BlockHeader) -> (Vec<u8>, [u8; 32]) {
        let encoded = header.to_bytes().expect("encode header");
        let id =
            canonical_header_identifier(NETWORK_MAGIC_REGTEST, &encoded).expect("identify header");
        (encoded, *id.as_bytes())
    }

    #[test]
    fn segment_partition_never_crosses_target_or_transport_bound() {
        let boundaries = segment_boundaries(100, 165, 198).unwrap();
        assert_eq!(boundaries.first(), Some(&(100, 103)));
        assert_eq!(boundaries.last(), Some(&(195, 198)));
        assert!(boundaries
            .iter()
            .all(|(start, end)| end - start <= u64::from(MAX_AUTHENTICATED_SOURCE_SEGMENT_BLOCKS)));
        assert!(boundaries.iter().any(|(_, end)| *end == 165));
        assert!(!boundaries
            .iter()
            .any(|(start, end)| *start < 165 && *end > 165));
    }

    #[test]
    fn atomic_snapshot_header_validation_binds_identity_ancestry_and_work() {
        let genesis = header(0, [0; 32], 1);
        let (genesis_bytes, genesis_id) = encoded_and_id(&genesis);
        validate_snapshot_header(
            NETWORK_MAGIC_REGTEST,
            0,
            genesis_id,
            &genesis_bytes,
            &genesis,
            None,
            None,
        )
        .expect("valid genesis projection");

        let child = header(1, genesis_id, 2);
        let (child_bytes, child_id) = encoded_and_id(&child);
        validate_snapshot_header(
            NETWORK_MAGIC_REGTEST,
            1,
            child_id,
            &child_bytes,
            &child,
            Some(genesis_id),
            Some(U256::one()),
        )
        .expect("valid linked child");

        assert!(validate_snapshot_header(
            NETWORK_MAGIC_REGTEST,
            1,
            [9; 32],
            &child_bytes,
            &child,
            Some(genesis_id),
            Some(U256::one()),
        )
        .is_err());
        assert!(validate_snapshot_header(
            NETWORK_MAGIC_REGTEST,
            1,
            child_id,
            &child_bytes,
            &child,
            Some([8; 32]),
            Some(U256::one()),
        )
        .is_err());
        assert!(validate_snapshot_header(
            NETWORK_MAGIC_REGTEST,
            1,
            child_id,
            &child_bytes,
            &child,
            Some(genesis_id),
            Some(U256::from(2u8)),
        )
        .is_err());
    }
}
