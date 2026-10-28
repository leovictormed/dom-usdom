#![allow(missing_docs)]
//! Chain state — current tip, validation, block commitment.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use dom_consensus::block::{
    validate_future_timestamp_with_limit, validate_header_syntax, validate_median_time_past,
    validate_parent_timestamp_progression, validate_pow_for_network, BlockHeader,
};
use dom_consensus::{
    checked_accumulated_difficulty, derive_chain_id, validate_block_for_network, Block,
    Transaction, ValidationContext,
};
use dom_core::{BlockHeight, DomError, Hash256, Timestamp};
use dom_pow::{
    asert_anchor_for_network_height, compute_expected_target, genesis_anchor,
    pow_params_for_network_at_height, randomx_seed_height, target_to_difficulty_for_network_height,
    AsertAnchor,
};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_store::utxo::UtxoEntry;
use dom_store::{DomStore, METADATA_UTXO_SET_DIGEST_KEY};
use primitive_types::U256;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use tracing::{debug, error, info, warn};

use crate::reorg::{check_reorg_depth, check_rolling_finality, find_common_ancestor};

/// Sentinel substring callers grep for to recognise a chainstate
/// corruption distinctly from other `DomError::Internal` cases. When
/// `ChainState::open` returns an error containing this string, the
/// safe operator response is "stop the node, move the data_dir aside,
/// re-sync from genesis" — continuing on a corrupted state would
/// fork the local chain from itself.
pub const CHAIN_CORRUPT_SENTINEL: &str = "CHAIN_CORRUPT";
const UTXO_SET_DIGEST_DOMAIN: &[u8] = b"DOM_CANONICAL_UTXO_SET_V1";
pub const MAX_RETAINED_SIDE_BRANCH_TIPS: usize = 8;
pub const MAX_RETAINED_SIDE_BRANCH_REORG_DEPTH: u64 = dom_core::MAX_REORG_DEPTH_POLICY;
pub const MAX_RETAINED_SIDE_BRANCH_LENGTH: u64 = dom_core::MAX_REORG_DEPTH_POLICY;

type UtxoBytes = ([u8; 33], Vec<u8>);
type SpentCommitment = [u8; 33];
type KernelExcess = ([u8; 33], [u8; 32]);
type UtxoUpdate = ([u8; 33], Option<Vec<u8>>);
type KernelUpdate = ([u8; 33], Option<[u8; 32]>);

#[derive(Clone, Copy)]
enum IbdHeaderMode {
    Ordinary,
    #[cfg(feature = "native-usdom-v4-poc")]
    NativeUsdomV4 {
        first_v4_height: u64,
    },
    #[cfg(feature = "native-usdom-v4-poc")]
    NativeUsdomV2 {
        first_v2_height: u64,
    },
}

impl IbdHeaderMode {
    fn native_first_height(self) -> Option<u64> {
        match self {
            Self::Ordinary => None,
            #[cfg(feature = "native-usdom-v4-poc")]
            Self::NativeUsdomV4 { first_v4_height } => Some(first_v4_height),
            #[cfg(feature = "native-usdom-v4-poc")]
            Self::NativeUsdomV2 { first_v2_height } => Some(first_v2_height),
        }
    }
}

pub struct ChainState {
    pub store: DomStore,
    pub tip_hash: Hash256,
    pub tip_height: BlockHeight,
    pub tip_difficulty: U256,
    pub genesis_hash: Hash256,
    pub asert_anchor: AsertAnchor,
    pub network_magic: u32,
    /// Coinbase maturity threshold derived from `network_magic`.
    ///
    /// `COINBASE_MATURITY` for Mainnet/Testnet, `REGTEST_COINBASE_MATURITY`
    /// for Regtest. Stored on the state so the consensus path can apply
    /// the network-specific rule without re-deriving on every block —
    /// and without dragging `dom-config` into the consensus crate.
    pub coinbase_maturity: u64,
    /// In-memory high-water mark restored only after an independently retained
    /// restart floor has been supplied. Persisted state alone cannot detect an
    /// internally consistent rollback to an older database snapshot.
    #[cfg(feature = "ethereum-checkpoint-poc")]
    checkpoint_floor: Option<crate::ethereum_checkpoint_poc::TestOracleCheckpoint>,
}

/// Deterministic expected-target metadata for the next or validated block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedTarget {
    /// Previous canonical target expanded from the parent header.
    pub previous_target: [u8; 32],
    /// Canonical target expected for the child header.
    pub next_target: [u8; 32],
    /// Child height minus ASERT anchor height.
    pub height_delta: u64,
    /// Child timestamp minus ASERT anchor timestamp.
    pub actual_elapsed_secs: u64,
    /// Ideal elapsed time for `height_delta` under network ASERT params.
    pub expected_elapsed_secs: u64,
}

/// Deterministic transaction delta produced by a canonical reorganization.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReorgDelta {
    /// Common ancestor height that remains canonical after disconnecting the
    /// old branch. Wallet and mempool rollback must rewind effects strictly
    /// above this height before applying the promoted branch.
    pub common_ancestor_height: u64,
    /// Blocks disconnected from the former canonical branch, ordered by
    /// rollback order (old tip back toward the common ancestor).
    pub disconnected_blocks: Vec<ReorgBlockDelta>,
    /// Blocks connected on the promoted branch, ordered from the common
    /// ancestor forward to the new tip.
    pub connected_blocks: Vec<ReorgBlockDelta>,
    /// Transactions disconnected from the former canonical branch, ordered by
    /// rollback order (old tip back toward the common ancestor).
    pub disconnected_txs: Vec<Transaction>,
    /// Transactions connected on the promoted branch, ordered from the common
    /// ancestor forward to the new tip.
    pub connected_txs: Vec<Transaction>,
}

/// Canonical block-level wallet/mempool effect metadata for reorg recovery.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReorgBlockDelta {
    /// Canonical block hash.
    pub block_hash: [u8; 32],
    /// Canonical block height.
    pub block_height: u64,
    /// Transactions carried by this block.
    pub transactions: Vec<Transaction>,
}

/// Map a 32-bit network magic to the coinbase maturity rule that applies
/// to that network. Mainnet/Testnet/unknown all use the canonical
/// `COINBASE_MATURITY`; Regtest uses `REGTEST_COINBASE_MATURITY`.
///
/// Keeping the resolution here (rather than in `dom-config`) avoids a
/// dependency cycle and keeps `dom-chain` self-contained.
fn coinbase_maturity_for_magic(magic: u32) -> u64 {
    if magic == dom_core::NETWORK_MAGIC_REGTEST {
        dom_core::REGTEST_COINBASE_MATURITY
    } else {
        dom_core::COINBASE_MATURITY
    }
}

/// Return whether a candidate tip deterministically outranks the current tip.
///
/// Total accumulated difficulty is primary.  Equal-work candidates use the
/// lexicographically lower canonical block identifier as the deterministic
/// tie-breaker, so arrival order cannot influence the selected chain.
pub(crate) fn is_better_fork_choice_tip(
    candidate_total_difficulty: U256,
    candidate_hash: Hash256,
    current_total_difficulty: U256,
    current_hash: Hash256,
) -> bool {
    candidate_total_difficulty > current_total_difficulty
        || (candidate_total_difficulty == current_total_difficulty
            && candidate_hash.as_bytes() < current_hash.as_bytes())
}

impl ChainState {
    /// Default startup path. A divergence between the persisted UTXO set and
    /// the canonical set reconstructed from committed block history is treated
    /// as fatal corruption (FIX-020): the node refuses to open rather than
    /// silently healing a possibly-tampered set. Recovery is operator-driven
    /// via [`ChainState::open_with_utxo_repair`].
    pub fn open(
        store: DomStore,
        genesis_hash: Hash256,
        network_magic: u32,
    ) -> Result<Self, DomError> {
        Self::open_inner(
            store,
            genesis_hash,
            network_magic,
            false,
            #[cfg(feature = "ethereum-checkpoint-poc")]
            None,
        )
    }

    /// Explicit operator recovery entry point. Identical to [`ChainState::open`]
    /// except that a divergence between the persisted UTXO set and the canonical
    /// set reconstructed from block history is REPAIRED (the persisted set is
    /// replaced by the canonical one) instead of being rejected as fatal
    /// corruption. This is the opt-in the fatal error raised by
    /// [`ChainState::open`] instructs the operator to use; it must never be the
    /// unattended default startup path, because a node must not silently run on
    /// a divergent UTXO set without human intervention.
    pub fn open_with_utxo_repair(
        store: DomStore,
        genesis_hash: Hash256,
        network_magic: u32,
    ) -> Result<Self, DomError> {
        Self::open_inner(
            store,
            genesis_hash,
            network_magic,
            true,
            #[cfg(feature = "ethereum-checkpoint-poc")]
            None,
        )
    }

    /// Regtest-only startup with an independently retained TEST ORACLE floor.
    /// The caller must supply the required anchor independently of this database.
    /// This API does not authenticate Ethereum or authorize production operation.
    #[cfg(feature = "ethereum-checkpoint-poc")]
    pub fn open_with_test_checkpoint_floor(
        store: DomStore,
        genesis_hash: Hash256,
        network_magic: u32,
        floor: crate::ethereum_checkpoint_poc::TestOracleCheckpoint,
    ) -> Result<Self, DomError> {
        if network_magic != dom_core::NETWORK_MAGIC_REGTEST {
            return Err(DomError::PolicyRejected(
                "CHECKPOINT_POC: test floor is regtest-only".into(),
            ));
        }
        if floor.dom_network_magic != network_magic {
            return Err(DomError::PolicyRejected(
                "CHECKPOINT_POC: checkpoint DOM network mismatch".into(),
            ));
        }
        Self::open_inner(store, genesis_hash, network_magic, false, Some(floor))
    }

    /// Reopen with an independently retained, cryptographically
    /// verified checkpoint floor. The caller must supply the immutable policy
    /// hash from trusted configuration; a decoded database record is not an
    /// acceptable substitute for this opaque capability.
    #[cfg(feature = "ethereum-checkpoint-verified-poc")]
    pub fn open_with_verified_checkpoint_floor(
        store: DomStore,
        genesis_hash: Hash256,
        network_magic: u32,
        verified: &usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint,
        expected_policy_hash: [u8; 32],
    ) -> Result<Self, DomError> {
        if expected_policy_hash == [0; 32]
            || verified.trust_policy_hash().as_slice() != expected_policy_hash
        {
            return Err(DomError::PolicyRejected(
                "CHECKPOINT_POC: verified external restart floor policy mismatch".into(),
            ));
        }
        let floor = crate::ethereum_checkpoint_poc::decode_test_oracle_v2(verified.record())?;
        if floor.dom_network_magic != network_magic {
            return Err(DomError::PolicyRejected(
                "CHECKPOINT_POC: verified external restart floor network mismatch".into(),
            ));
        }
        Self::open_inner(store, genesis_hash, network_magic, false, Some(floor))
    }

    /// Install a regtest TEST assertion and remember it across runtime checks.
    /// Success persists the anchor before advancing the in-memory high-water mark.
    /// After restart the caller must independently supply an up-to-date floor.
    #[cfg(feature = "ethereum-checkpoint-poc")]
    pub fn install_test_checkpoint(
        &mut self,
        checkpoint: crate::ethereum_checkpoint_poc::TestOracleCheckpoint,
    ) -> Result<(), DomError> {
        self.ensure_checkpoint_floor()?;
        crate::ethereum_checkpoint_poc::install_from_test_oracle(
            &self.store,
            self.network_magic,
            self.tip_height.0,
            checkpoint,
        )?;
        self.checkpoint_floor = Some(checkpoint);
        Ok(())
    }

    /// Install an opaque result produced by the concrete Ethereum verifier.
    /// Mainnet remains rejected until DOM consensus commits and validates the
    /// native USDOM state root carried by that result.
    #[cfg(feature = "ethereum-checkpoint-verified-poc")]
    pub fn install_verified_checkpoint(
        &mut self,
        verified: &usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint,
    ) -> Result<(), DomError> {
        self.ensure_checkpoint_floor()?;
        let checkpoint = crate::ethereum_checkpoint_poc::install_from_verified_handoff(
            &self.store,
            self.network_magic,
            self.tip_height.0,
            verified,
        )?;
        self.checkpoint_floor = Some(checkpoint);
        Ok(())
    }

    /// Install an Ethereum-verified checkpoint only after it is matched to an
    /// exact canonical native burn package and state. The checkpoint remains a
    /// Regtest research barrier; no public-network activation is implied.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn install_verified_native_burn_checkpoint(
        &mut self,
        input: &crate::NativeBurnBlockProverInput,
        verified: &usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint,
    ) -> Result<crate::NativeBurnCheckpointBinding, DomError> {
        self.ensure_checkpoint_floor()?;
        let (binding, checkpoint) = crate::install_verified_native_burn_checkpoint(
            &self.store,
            self.network_magic,
            self.tip_height.0,
            input,
            verified,
        )?;
        self.checkpoint_floor = Some(checkpoint);
        Ok(binding)
    }

    /// Replay bounded witness bytes under consensus-selected Ethereum policy,
    /// then persist only the resulting opaque checkpoint. This remains a
    /// regtest research path and does not add the witness to DOM blocks.
    #[cfg(feature = "ethereum-checkpoint-verified-poc")]
    pub fn verify_and_install_checkpoint_witness(
        &mut self,
        witness: &[u8],
        policy: &usdom_ethereum_finality_experiment::checkpoints::CheckpointTrustPolicy,
    ) -> Result<(), DomError> {
        self.ensure_checkpoint_floor()?;
        let checkpoint = crate::ethereum_checkpoint_poc::verify_and_install_witness(
            &self.store,
            self.network_magic,
            self.tip_height.0,
            witness,
            policy,
        )?;
        self.checkpoint_floor = Some(checkpoint);
        Ok(())
    }

    #[cfg(feature = "ethereum-checkpoint-poc")]
    fn ensure_checkpoint_floor(&mut self) -> Result<(), DomError> {
        self.checkpoint_floor = crate::ethereum_checkpoint_poc::ensure_at_least(
            &self.store,
            self.tip_height.0,
            self.checkpoint_floor,
        )?;
        Ok(())
    }

    #[cfg(feature = "ethereum-checkpoint-poc")]
    fn ensure_checkpoint_floor_readonly(&self) -> Result<(), DomError> {
        crate::ethereum_checkpoint_poc::ensure_at_least(
            &self.store,
            self.tip_height.0,
            self.checkpoint_floor,
        )?;
        Ok(())
    }

    fn open_inner(
        store: DomStore,
        genesis_hash: Hash256,
        network_magic: u32,
        allow_utxo_repair: bool,
        #[cfg(feature = "ethereum-checkpoint-poc")] checkpoint_floor: Option<
            crate::ethereum_checkpoint_poc::TestOracleCheckpoint,
        >,
    ) -> Result<Self, DomError> {
        let asert_anchor = genesis_anchor(network_magic)
            .map_err(|e| DomError::Internal(format!("genesis anchor: {e}")))?;

        let (tip_hash, tip_height, tip_difficulty) = match store.get_chain_tip()? {
            Some(hash) => {
                let header_bytes = store.get_block_header(&hash)?.ok_or_else(|| {
                    DomError::Internal(format!(
                        "{CHAIN_CORRUPT_SENTINEL}: chain_tip {} points at missing header",
                        hex::encode(hash)
                    ))
                })?;
                let header = BlockHeader::from_bytes(&header_bytes)?;
                // Body MUST exist alongside the header — commit_block writes
                // them in the same atomic LMDB txn (RFC-0007 §14). A
                // header-without-body is one of the partial-persistence
                // states the chain-init layer is contractually required to
                // detect (see dom-store/src/db.rs § "Partial-persistence
                // contract").
                if store.get_block_body(&hash)?.is_none() {
                    return Err(DomError::Internal(format!(
                        "{CHAIN_CORRUPT_SENTINEL}: tip {} has header but no body",
                        hex::encode(hash)
                    )));
                }
                // The height index MUST match the header's recorded height.
                // A divergence means an interrupted prior write left the two
                // databases pointing at different blocks and continuing to
                // mine from here would fork the local view from itself.
                match store.get_hash_at_height(header.height.0)? {
                    Some(indexed) if indexed == hash => {}
                    Some(other) => {
                        return Err(DomError::Internal(format!(
                            "{CHAIN_CORRUPT_SENTINEL}: height_index[{}] = {} but tip = {}",
                            header.height.0,
                            hex::encode(other),
                            hex::encode(hash)
                        )));
                    }
                    None => {
                        return Err(DomError::Internal(format!(
                            "{CHAIN_CORRUPT_SENTINEL}: tip {} has no height_index entry at height {}",
                            hex::encode(hash),
                            header.height.0
                        )));
                    }
                }
                // Check before index rebuilding, UTXO repair, or branch pruning.
                #[cfg(feature = "ethereum-checkpoint-poc")]
                crate::ethereum_checkpoint_poc::ensure_restart_floor(
                    &store,
                    header.height.0,
                    checkpoint_floor,
                )?;
                rebuild_kernel_index_from_canonical_chain(&store, header.height, network_magic)?;
                ensure_canonical_utxo_set(&store, header.height, network_magic, allow_utxo_repair)?;
                prune_retained_side_chains(&store, header.height, hash)?;
                (
                    Hash256::from_bytes(hash),
                    header.height,
                    header.total_difficulty,
                )
            }
            None => {
                #[cfg(feature = "ethereum-checkpoint-poc")]
                crate::ethereum_checkpoint_poc::ensure_restart_floor(&store, 0, checkpoint_floor)?;
                prune_retained_side_chains(&store, BlockHeight::GENESIS, [0u8; 32])?;
                (Hash256::ZERO, BlockHeight::GENESIS, U256::zero())
            }
        };

        validate_persisted_genesis_identity(&store, genesis_hash)?;

        #[cfg(feature = "ethereum-checkpoint-poc")]
        let checkpoint_floor = crate::ethereum_checkpoint_poc::ensure_restart_floor(
            &store,
            tip_height.0,
            checkpoint_floor,
        )?;

        Ok(Self {
            store,
            tip_hash,
            tip_height,
            tip_difficulty,
            genesis_hash,
            asert_anchor,
            network_magic,
            coinbase_maturity: coinbase_maturity_for_magic(network_magic),
            #[cfg(feature = "ethereum-checkpoint-poc")]
            checkpoint_floor,
        })
    }

    pub fn connect_block(
        &mut self,
        block: &Block,
        now: Timestamp,
    ) -> Result<ConnectResult, DomError> {
        #[cfg(feature = "ethereum-checkpoint-poc")]
        self.ensure_checkpoint_floor()?;
        let header = &block.header;
        let header_bytes = header.to_bytes()?;
        let block_hash = compute_block_identifier(self.network_magic, &header_bytes)?;

        // DOM-SEC-RELAY-LOOP fix: early-return for already-known blocks.
        // Without this check, duplicate blocks (e.g. from relay loops between
        // peers) would re-execute full validation, re-write the store with
        // identical data, and trigger another rebroadcast — creating an
        // infinite amplification loop. Discovered via Doc 8 two_node test
        // on 2026-05-23.
        //
        // DOM-DUP-002 NOTE (audit follow-up, deliberately not implemented):
        // The auditor suggested checking BOTH header AND body to detect
        // partial-write corruption. After analysis, the suggestion was
        // not adopted because:
        //   1. commit_block in dom-store is atomic (RFC-0007 step 14:
        //      all puts under a single txn.commit()). Header existence
        //      implies body existence by construction.
        //   2. If a future refactor breaks that atomicity, the
        //      WriteFlags::NO_OVERWRITE protection from DOM-LMDB-001
        //      (commit 1b26b13) would detect the resulting partial
        //      state on the next connect attempt: re-committing a
        //      header that already exists triggers a KeyExist error
        //      with a loud-fail message identifying the bug.
        //   3. A check that allowed re-commit on partial state would
        //      conflict with the NO_OVERWRITE protection — the
        //      recovery write would itself fail. Better to keep the
        //      loud-fail signal than to mask it with a silent retry.
        // If a future change splits commit_block writes across multiple
        // transactions, the DOM-DUP-002 hardening should be revisited
        // jointly with that change.
        if self
            .store
            .get_block_header(block_hash.as_bytes())?
            .is_some()
        {
            return Ok(ConnectResult::AlreadyHave);
        }

        #[cfg(feature = "native-usdom-v4-poc")]
        self.reject_ordinary_block_after_native_usdom_v4_activation()?;

        validate_header_syntax(header, self.network_magic)?;
        self.validate_genesis_identity(header, block_hash)?;
        self.validate_genesis_body_identity(block)?;

        let parent = if header.height != BlockHeight::GENESIS {
            let parent_bytes = self
                .store
                .get_block_header(header.prev_hash.as_bytes())?
                .ok_or_else(|| {
                    DomError::Orphan(format!("parent {} not found", header.prev_hash))
                })?;
            let parent = BlockHeader::from_bytes(&parent_bytes)?;
            let expected_height = parent
                .height
                .checked_next()
                .ok_or_else(|| DomError::Invalid("block height overflow".into()))?;
            if header.height != expected_height {
                return Err(DomError::Invalid(format!(
                    "height mismatch: expected {expected_height}, got {}",
                    header.height
                )));
            }
            validate_parent_timestamp_progression(header, &parent)?;
            let ancestors = self.get_recent_timestamps(header.prev_hash, 11)?;
            validate_median_time_past(header, &ancestors)?;
            Some(parent)
        } else {
            None
        };

        validate_future_timestamp_with_limit(header, now, self.max_future_block_time())?;
        let seed = self.compute_randomx_seed_branch_aware(header.height.0, header.prev_hash)?;
        validate_pow_for_network(self.network_magic, header, &seed)?;

        if let Some(parent_header) = parent.as_ref() {
            self.validate_expected_target(header, parent_header)?;
        }

        let parent_difficulty = parent
            .as_ref()
            .map(|header| header.total_difficulty)
            .unwrap_or_else(U256::zero);

        let block_diff = target_to_difficulty_for_network_height(
            self.network_magic,
            header.height,
            &header
                .target
                .to_target()
                .map_err(|e| DomError::Invalid(format!("invalid target: {e}")))?,
        );
        let expected_total = checked_accumulated_difficulty(parent_difficulty, block_diff?)?;
        if header.total_difficulty != expected_total {
            return Err(DomError::Invalid(format!(
                "total_difficulty mismatch: expected {expected_total}, got {}",
                header.total_difficulty
            )));
        }

        let chain_id = derive_chain_id(self.network_magic, &self.genesis_hash);
        let ctx = ValidationContext {
            current_height: header.height,
            chain_id: *chain_id.as_bytes(),
            now,
        };

        validate_block_for_network(block, &ctx, self.network_magic).map_err(|e| {
            DomError::Invalid(format!(
                "block validation failed: hash={block_hash}, error={e}"
            ))
        })?;

        // Serialize full block body for IBD responses (peers ask for bodies by hash).
        let block_body_bytes = block.to_bytes()?;
        let kernel_excesses = extract_kernel_excesses(block, block_hash);

        let is_direct_extension =
            header.height == BlockHeight::GENESIS || header.prev_hash == self.tip_hash;
        let extends_best_chain = is_better_fork_choice_tip(
            header.total_difficulty,
            block_hash,
            self.tip_difficulty,
            self.tip_hash,
        );

        if is_direct_extension {
            if !extends_best_chain {
                return Err(DomError::Invalid(format!(
                    "direct extension did not improve fork choice: new_total={} current_total={} new_hash={} current_hash={}",
                    header.total_difficulty, self.tip_difficulty, block_hash, self.tip_hash
                )));
            }
            let (new_utxos, spent_utxos) = build_utxo_changeset(block);
            self.validate_direct_extension_inputs(block)?;

            // R-06: explicit kernel/output uniqueness against ALREADY-PERSISTED
            // chain state, on the direct connect path, returning Invalid so a
            // replaying peer is ban-scored (DomError::increases_ban_score). The
            // storage layer's NO_OVERWRITE guard in dom-store::commit_block maps
            // the same duplicate to DomError::Internal, which does NOT raise ban
            // score; the reorg path (apply_connect) already rejects this as
            // Invalid. Mirror that wording here (swap "reorg" -> "direct").
            //
            // This runs BEFORE commit_block, so the block being connected is not
            // yet persisted and therefore cannot collide with itself; intra-block
            // duplicate outputs/inputs are already rejected by validate_block, so
            // this only catches collisions against prior persisted state. The
            // direct path has no pending overlay, so plain store lookups suffice.
            for output in std::iter::once(&block.coinbase.output)
                .chain(block.transactions.iter().flat_map(|tx| tx.outputs.iter()))
            {
                let commitment = *output.commitment.as_bytes();
                if self.store.get_utxo(&commitment)?.is_some() {
                    return Err(DomError::Invalid(format!(
                        "direct connect duplicate output commitment {}",
                        hex::encode(commitment)
                    )));
                }
            }
            for (excess, _) in &kernel_excesses {
                if self.store.get_kernel_block(excess)?.is_some() {
                    return Err(DomError::Invalid(format!(
                        "direct connect kernel replay detected: excess={}",
                        hex::encode(excess)
                    )));
                }
            }

            self.store.commit_block(
                block_hash.as_bytes(),
                header.height.0,
                &header_bytes,
                &block_body_bytes,
                &new_utxos,
                &spent_utxos,
                &kernel_excesses,
            )?;
            self.tip_hash = block_hash;
            self.tip_height = header.height;
            self.tip_difficulty = header.total_difficulty;
            prune_retained_side_chains(&self.store, self.tip_height, *self.tip_hash.as_bytes())?;
            info!(
                "New chain tip: height={}, hash={}",
                header.height, block_hash
            );
            Ok(ConnectResult::BestChain)
        } else {
            // DOM-FINAL-006: side-chain quarantine is intentionally persisted
            // after full block validation but before contextual input checks.
            // `validate_block` above already verified cryptography, balance,
            // range proofs, kernel signatures, cut-through, and weight. Input
            // existence/maturity must be checked against the candidate branch
            // UTXO set, which is reconstructed during promotion; doing that for
            // every retained side block would turn branch spam into CPU work.
            // Retention is bounded by `prune_retained_side_chains`, and invalid
            // branch inputs still fail closed in `promote_heavier_known_tip`.
            self.store.store_known_block(
                block_hash.as_bytes(),
                &header_bytes,
                &block_body_bytes,
            )?;
            prune_retained_side_chains(&self.store, self.tip_height, *self.tip_hash.as_bytes())?;
            if extends_best_chain {
                let reorg = self.promote_heavier_known_tip(block_hash, now)?;
                return Ok(ConnectResult::Reorg(reorg));
            }
            debug!(
                "Side chain block: height={}, hash={}",
                header.height, block_hash
            );
            Ok(ConnectResult::SideChain)
        }
    }

    /// Validate and atomically connect one native-USDOM version-4 package as a
    /// direct Regtest extension. This explicit research entry point is absent
    /// unless `native-usdom-v4-poc` is enabled and never accepts side branches
    /// or public-network activation.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn connect_usdom_v4_package_regtest(
        &mut self,
        package_bytes: &[u8],
        now: Timestamp,
        current_usdom_state: &mut dom_usdom_state::NativeUsdomState,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: Option<&dom_usdom_privacy::verifier::SpendVerifier>,
    ) -> Result<ConnectResult, DomError> {
        if self.network_magic != dom_core::NETWORK_MAGIC_REGTEST {
            return Err(DomError::PolicyRejected(
                "native USDOM block v4 is available only on explicit Regtest".into(),
            ));
        }
        let schedule = crate::native_usdom_v4_regtest_activation_schedule(bridge)?;
        self.connect_usdom_v4_package_for_schedule_inner(
            package_bytes,
            now,
            current_usdom_state,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifier,
            schedule,
            None,
        )
        .map(|(outcome, _)| outcome)
    }

    /// Validate and atomically connect one direct native-USDOM v4 extension
    /// under an exact ratified activation schedule and bridge-committed proof
    /// verifier. This method does not select a schedule and does not handle
    /// side branches; those require separately scheduled ingress.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn connect_usdom_v4_package_for_schedule(
        &mut self,
        package_bytes: &[u8],
        now: Timestamp,
        current_usdom_state: &mut dom_usdom_state::NativeUsdomState,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: &dom_usdom_privacy::verifier::SpendVerifier,
        schedule: crate::NativeUsdomV4ActivationSchedule,
    ) -> Result<ConnectResult, DomError> {
        self.connect_usdom_v4_package_for_schedule_inner(
            package_bytes,
            now,
            current_usdom_state,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            Some(spend_verifier),
            schedule,
            None,
        )
        .map(|(outcome, _)| outcome)
    }

    /// Atomically connect the final V1 block and install the derived V2
    /// migration marker in the same store transaction. The activation parent
    /// hash and both state roots are derived from the verified block rather
    /// than supplied after it has already become canonical.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn connect_usdom_v4_package_and_activate_v2_for_schedule(
        &mut self,
        package_bytes: &[u8],
        now: Timestamp,
        current_usdom_state: &mut dom_usdom_state::NativeUsdomState,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: &dom_usdom_privacy::verifier::SpendVerifier,
        v1_schedule: crate::NativeUsdomV4ActivationSchedule,
        first_v2_height: u64,
    ) -> Result<(ConnectResult, crate::NativeUsdomV2ActivationSchedule), DomError> {
        let (outcome, activated) = self.connect_usdom_v4_package_for_schedule_inner(
            package_bytes,
            now,
            current_usdom_state,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            Some(spend_verifier),
            v1_schedule,
            Some(first_v2_height),
        )?;
        let schedule = activated.ok_or_else(|| {
            DomError::Internal("native USDOM V2 activation schedule was not returned".into())
        })?;
        Ok((outcome, schedule))
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    fn connect_usdom_v4_package_for_schedule_inner(
        &mut self,
        package_bytes: &[u8],
        now: Timestamp,
        current_usdom_state: &mut dom_usdom_state::NativeUsdomState,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: Option<&dom_usdom_privacy::verifier::SpendVerifier>,
        schedule: crate::NativeUsdomV4ActivationSchedule,
        v2_activation_height: Option<u64>,
    ) -> Result<
        (
            ConnectResult,
            Option<crate::NativeUsdomV2ActivationSchedule>,
        ),
        DomError,
    > {
        let chain_id = derive_chain_id(self.network_magic, &self.genesis_hash);
        if schedule.network_magic() != self.network_magic || schedule.chain_id() != chain_id {
            return Err(DomError::PolicyRejected(
                "native USDOM direct extension does not match the ratified schedule".into(),
            ));
        }
        self.ensure_checkpoint_floor()?;
        let persisted = crate::restore_persisted_usdom_v4_state_for_schedule(
            &self.store,
            self.network_magic,
            bridge,
            self.tip_hash,
            schedule,
        )?;
        if persisted.state_root() != current_usdom_state.state_root()
            || persisted.export_entries() != current_usdom_state.export_entries()
        {
            return Err(DomError::Internal(
                "caller native USDOM state diverges from canonical persistence".into(),
            ));
        }

        let package = crate::UsdomV4BlockPackage::from_bytes(package_bytes)?;
        let block = package.block();
        let header = &block.header;
        let header_bytes = header.to_bytes()?;
        let block_hash = compute_block_identifier(self.network_magic, &header_bytes)?;

        if self
            .store
            .get_block_header(block_hash.as_bytes())?
            .is_some()
        {
            let stored = crate::load_persisted_usdom_v4_package(
                &self.store,
                self.network_magic,
                block_hash,
            )?
            .ok_or_else(|| {
                DomError::Internal(
                    "known native USDOM v4 block is missing its persisted package".into(),
                )
            })?;
            if stored != package_bytes {
                return Err(DomError::Internal(
                    "known native USDOM v4 block package bytes changed".into(),
                ));
            }
            if let Some(first_v2_height) = v2_activation_height {
                let expected_height = header.height.0.checked_add(1).ok_or_else(|| {
                    DomError::Invalid("native USDOM V2 activation height overflow".into())
                })?;
                if first_v2_height != expected_height || self.tip_hash != block_hash {
                    return Err(DomError::PolicyRejected(
                        "known V1 block is not the selected canonical V2 activation parent".into(),
                    ));
                }
                let activated = crate::NativeUsdomV2ActivationSchedule::new(
                    self.network_magic,
                    chain_id,
                    first_v2_height,
                    block_hash,
                    current_usdom_state,
                )?;
                crate::restore_persisted_usdom_v2_activation(
                    &self.store,
                    self.network_magic,
                    block_hash,
                    bridge,
                    activated,
                )?;
                return Ok((ConnectResult::AlreadyHave, Some(activated)));
            }
            return Ok((ConnectResult::AlreadyHave, None));
        }

        if crate::load_persisted_usdom_v2_activation_schedule(&self.store)?.is_some() {
            return Err(DomError::PolicyRejected(
                "native USDOM V1 ingress is disabled after candidate-v2 activation".into(),
            ));
        }

        if header.height == BlockHeight::GENESIS
            || header.prev_hash != self.tip_hash
            || header.height
                != self.tip_height.checked_next().ok_or_else(|| {
                    DomError::Invalid("native USDOM direct-extension height overflow".into())
                })?
        {
            return Err(DomError::PolicyRejected(
                "native USDOM v4 POC accepts only the next canonical direct extension".into(),
            ));
        }
        let parent_bytes = self
            .store
            .get_block_header(header.prev_hash.as_bytes())?
            .ok_or_else(|| DomError::Orphan(format!("parent {} not found", header.prev_hash)))?;
        let parent = BlockHeader::from_bytes(&parent_bytes)?;
        validate_parent_timestamp_progression(header, &parent)?;
        let ancestors = self.get_recent_timestamps(header.prev_hash, 11)?;
        validate_median_time_past(header, &ancestors)?;
        validate_future_timestamp_with_limit(header, now, self.max_future_block_time())?;
        let seed = self.compute_randomx_seed_branch_aware(header.height.0, header.prev_hash)?;
        validate_pow_for_network(self.network_magic, header, &seed)?;
        self.validate_expected_target(header, &parent)?;

        let block_diff = target_to_difficulty_for_network_height(
            self.network_magic,
            header.height,
            &header
                .target
                .to_target()
                .map_err(|error| DomError::Invalid(format!("invalid target: {error}")))?,
        )?;
        let expected_total = checked_accumulated_difficulty(parent.total_difficulty, block_diff)?;
        if header.total_difficulty != expected_total {
            return Err(DomError::Invalid(format!(
                "total_difficulty mismatch: expected {expected_total}, got {}",
                header.total_difficulty
            )));
        }
        if !is_better_fork_choice_tip(
            header.total_difficulty,
            block_hash,
            self.tip_difficulty,
            self.tip_hash,
        ) {
            return Err(DomError::Invalid(
                "native USDOM direct extension did not improve fork choice".into(),
            ));
        }

        let validation_context = ValidationContext {
            current_height: header.height,
            chain_id: *chain_id.as_bytes(),
            now,
        };
        let verified =
            crate::native_usdom_v4::verify_usdom_v4_serialized_candidate_for_schedule_inner(
                package_bytes,
                &validation_context,
                self.network_magic,
                current_usdom_state,
                bridge,
                checkpoint_policy,
                deposit_policy,
                closure_policy,
                spend_verifier,
                schedule,
            )?;
        if verified.block_identifier() != block_hash {
            return Err(DomError::Internal(
                "verified native USDOM block identifier mismatch".into(),
            ));
        }

        self.validate_direct_extension_inputs(block)?;
        let kernel_excesses = extract_kernel_excesses(block, block_hash);
        for output in std::iter::once(&block.coinbase.output)
            .chain(block.transactions.iter().flat_map(|tx| tx.outputs.iter()))
        {
            let commitment = *output.commitment.as_bytes();
            if self.store.get_utxo(&commitment)?.is_some() {
                return Err(DomError::Invalid(format!(
                    "native USDOM direct connect duplicate output commitment {}",
                    hex::encode(commitment)
                )));
            }
        }
        for (excess, _) in &kernel_excesses {
            if self.store.get_kernel_block(excess)?.is_some() {
                return Err(DomError::Invalid(format!(
                    "native USDOM direct connect kernel replay detected: excess={}",
                    hex::encode(excess)
                )));
            }
        }

        let next_usdom_state = verified.next_state().clone();
        let activated_schedule = if let Some(first_v2_height) = v2_activation_height {
            let expected_height = header.height.0.checked_add(1).ok_or_else(|| {
                DomError::Invalid("native USDOM V2 activation height overflow".into())
            })?;
            if first_v2_height != expected_height {
                return Err(DomError::PolicyRejected(
                    "V2 activation must immediately follow the verified V1 parent".into(),
                ));
            }
            Some(crate::NativeUsdomV2ActivationSchedule::new(
                self.network_magic,
                chain_id,
                first_v2_height,
                block_hash,
                &next_usdom_state,
            )?)
        } else {
            None
        };
        let mut consensus_updates =
            verified.consensus_state_updates(current_usdom_state, package_bytes)?;
        if let Some(update) = crate::native_usdom_v4::native_usdom_v4_undo_retention_update(
            &self.store,
            header.height.0,
        )? {
            consensus_updates.push(update);
        }
        if let Some(v2_schedule) = activated_schedule {
            consensus_updates.extend(crate::native_usdom_v2_activation_updates(
                &next_usdom_state,
                v2_schedule,
                block_hash,
                header.height.0,
            )?);
        }
        let mut committed_checkpoint = None;
        if let Some(checkpoint_capability) = verified.verified_checkpoint() {
            let asserted = crate::ethereum_checkpoint_poc::decode_test_oracle_v2(
                checkpoint_capability.record(),
            )?;
            if asserted.height > self.tip_height.0
                || self.store.get_hash_at_height(asserted.height)?
                    != Some(*asserted.dom_block.as_bytes())
            {
                return Err(DomError::Invalid(
                    "native USDOM checkpoint target is not in the carrier ancestry".into(),
                ));
            }
            let target_state = if asserted.dom_block == self.tip_hash {
                current_usdom_state.clone()
            } else {
                crate::rewind_persisted_usdom_v4_state_to_ancestor_for_schedule(
                    &self.store,
                    self.network_magic,
                    bridge,
                    self.tip_hash,
                    asserted.dom_block,
                    schedule,
                )?
            };
            let (checkpoint, update) = crate::native_usdom_v4::native_checkpoint_floor_update(
                checkpoint_capability,
                self.network_magic,
                bridge,
                crate::native_usdom_v4::NativeCheckpointTarget {
                    carrier_height: header.height.0,
                    height: asserted.height,
                    block: asserted.dom_block,
                    state_root: target_state.state_root(),
                },
                self.checkpoint_floor,
            )?;
            if let Some(update) = update {
                consensus_updates.push(update);
            }
            committed_checkpoint = Some(checkpoint);
        }
        dom_store::validate_consensus_state_updates(&consensus_updates)?;
        let (new_utxos, spent_utxos) = build_utxo_changeset(block);
        let block_body_bytes = block.to_bytes()?;
        self.store.commit_block_with_consensus_state(
            block_hash.as_bytes(),
            header.height.0,
            &header_bytes,
            &block_body_bytes,
            &new_utxos,
            &spent_utxos,
            &kernel_excesses,
            &consensus_updates,
        )?;
        self.tip_hash = block_hash;
        self.tip_height = header.height;
        self.tip_difficulty = header.total_difficulty;
        *current_usdom_state = next_usdom_state;
        if let Some(checkpoint) = committed_checkpoint {
            self.checkpoint_floor = Some(checkpoint);
        }
        prune_retained_side_chains(&self.store, self.tip_height, *self.tip_hash.as_bytes())?;
        info!(
            "New scheduled native USDOM v4 tip: height={}, hash={}, network=0x{:08x}",
            header.height, block_hash, self.network_magic
        );
        Ok((ConnectResult::BestChain, activated_schedule))
    }

    /// Validate and atomically connect one candidate-v2 direct extension under
    /// an exact persisted migration schedule. Package proofs, bounded state
    /// witnesses, DOM fork choice, ordinary UTXOs and candidate-v2 recovery
    /// records commit together or all abort.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn connect_usdom_v2_package_for_schedule(
        &mut self,
        package_bytes: &[u8],
        witness_bundle: &crate::UsdomV2ExecutionWitnesses,
        now: Timestamp,
        current_usdom_state: &mut dom_usdom_state::StateCommitmentV2,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: &dom_usdom_privacy::verifier::SpendVerifier,
        schedule: crate::NativeUsdomV2ActivationSchedule,
    ) -> Result<ConnectResult, DomError> {
        let chain_id = derive_chain_id(self.network_magic, &self.genesis_hash);
        if schedule.network_magic() != self.network_magic || schedule.chain_id() != chain_id {
            return Err(DomError::PolicyRejected(
                "native USDOM v2 direct extension does not match the ratified schedule".into(),
            ));
        }
        self.ensure_checkpoint_floor()?;
        let persisted = crate::restore_persisted_usdom_v2_state_for_schedule(
            &self.store,
            self.network_magic,
            self.tip_hash,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifier,
            schedule,
        )?;
        if persisted != *current_usdom_state {
            return Err(DomError::Internal(
                "caller native USDOM v2 state diverges from canonical persistence".into(),
            ));
        }

        let package = crate::UsdomV4BlockPackage::from_bytes(package_bytes)?;
        let block = package.block();
        let header = &block.header;
        let header_bytes = header.to_bytes()?;
        let block_hash = compute_block_identifier(self.network_magic, &header_bytes)?;

        if self
            .store
            .get_block_header(block_hash.as_bytes())?
            .is_some()
        {
            let stored_package = crate::load_persisted_usdom_v4_package(
                &self.store,
                self.network_magic,
                block_hash,
            )?
            .ok_or_else(|| {
                DomError::Internal(
                    "known native USDOM v2 block is missing its persisted package".into(),
                )
            })?;
            let stored_witnesses =
                crate::load_persisted_usdom_v2_execution_witnesses(&self.store, block_hash)?
                    .ok_or_else(|| {
                        DomError::Internal(
                            "known native USDOM v2 block is missing its persisted witnesses".into(),
                        )
                    })?;
            if stored_package != package_bytes
                || stored_witnesses.to_bytes()? != witness_bundle.to_bytes()?
            {
                return Err(DomError::Internal(
                    "known native USDOM v2 block recovery bytes changed".into(),
                ));
            }
            return Ok(ConnectResult::AlreadyHave);
        }

        if header.height == BlockHeight::GENESIS
            || header.prev_hash != self.tip_hash
            || header.height
                != self.tip_height.checked_next().ok_or_else(|| {
                    DomError::Invalid("native USDOM v2 direct-extension height overflow".into())
                })?
            || header.height.0 < schedule.first_v2_height()
        {
            return Err(DomError::PolicyRejected(
                "native USDOM v2 ingress accepts only the next scheduled canonical extension"
                    .into(),
            ));
        }
        let parent_bytes = self
            .store
            .get_block_header(header.prev_hash.as_bytes())?
            .ok_or_else(|| DomError::Orphan(format!("parent {} not found", header.prev_hash)))?;
        let parent = BlockHeader::from_bytes(&parent_bytes)?;
        validate_parent_timestamp_progression(header, &parent)?;
        let ancestors = self.get_recent_timestamps(header.prev_hash, 11)?;
        validate_median_time_past(header, &ancestors)?;
        validate_future_timestamp_with_limit(header, now, self.max_future_block_time())?;
        let seed = self.compute_randomx_seed_branch_aware(header.height.0, header.prev_hash)?;
        validate_pow_for_network(self.network_magic, header, &seed)?;
        self.validate_expected_target(header, &parent)?;

        let block_diff = target_to_difficulty_for_network_height(
            self.network_magic,
            header.height,
            &header
                .target
                .to_target()
                .map_err(|error| DomError::Invalid(format!("invalid target: {error}")))?,
        )?;
        let expected_total = checked_accumulated_difficulty(parent.total_difficulty, block_diff)?;
        if header.total_difficulty != expected_total {
            return Err(DomError::Invalid(format!(
                "total_difficulty mismatch: expected {expected_total}, got {}",
                header.total_difficulty
            )));
        }
        if !is_better_fork_choice_tip(
            header.total_difficulty,
            block_hash,
            self.tip_difficulty,
            self.tip_hash,
        ) {
            return Err(DomError::Invalid(
                "native USDOM v2 direct extension did not improve fork choice".into(),
            ));
        }

        let validation_context = ValidationContext {
            current_height: header.height,
            chain_id: *chain_id.as_bytes(),
            now,
        };
        let verified = crate::verify_usdom_v4_serialized_transition_batch_for_v2_schedule(
            package_bytes,
            &validation_context,
            self.network_magic,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifier,
            schedule,
        )?;
        let candidate = verified.execute_v2(
            &validation_context,
            current_usdom_state.root(),
            *current_usdom_state,
            witness_bundle.witnesses(),
        )?;
        if candidate.block_identifier() != block_hash {
            return Err(DomError::Internal(
                "verified native USDOM v2 block identifier mismatch".into(),
            ));
        }

        self.validate_direct_extension_inputs(block)?;
        let kernel_excesses = extract_kernel_excesses(block, block_hash);
        for output in std::iter::once(&block.coinbase.output)
            .chain(block.transactions.iter().flat_map(|tx| tx.outputs.iter()))
        {
            let commitment = *output.commitment.as_bytes();
            if self.store.get_utxo(&commitment)?.is_some() {
                return Err(DomError::Invalid(format!(
                    "native USDOM v2 direct connect duplicate output commitment {}",
                    hex::encode(commitment)
                )));
            }
        }
        for (excess, _) in &kernel_excesses {
            if self.store.get_kernel_block(excess)?.is_some() {
                return Err(DomError::Invalid(format!(
                    "native USDOM v2 direct connect kernel replay detected: excess={}",
                    hex::encode(excess)
                )));
            }
        }

        let mut consensus_updates = candidate.consensus_state_updates(
            schedule,
            *current_usdom_state,
            package_bytes,
            witness_bundle,
        )?;
        let mut committed_checkpoint = None;
        if let Some(checkpoint_capability) = verified.verified_checkpoint() {
            let asserted = crate::ethereum_checkpoint_poc::decode_test_oracle_v2(
                checkpoint_capability.record(),
            )?;
            if asserted.height > self.tip_height.0
                || self.store.get_hash_at_height(asserted.height)?
                    != Some(*asserted.dom_block.as_bytes())
            {
                return Err(DomError::Invalid(
                    "native USDOM v2 checkpoint target is not in the carrier ancestry".into(),
                ));
            }
            let target_state = if asserted.dom_block == self.tip_hash {
                *current_usdom_state
            } else {
                crate::native_usdom_v4::rewind_persisted_usdom_v2_state_to_ancestor(
                    &self.store,
                    self.tip_hash,
                    *current_usdom_state,
                    asserted.dom_block,
                    schedule,
                )?
            };
            let (checkpoint, update) = crate::native_usdom_v4::native_checkpoint_floor_update(
                checkpoint_capability,
                self.network_magic,
                bridge,
                crate::native_usdom_v4::NativeCheckpointTarget {
                    carrier_height: header.height.0,
                    height: asserted.height,
                    block: asserted.dom_block,
                    state_root: target_state.root(),
                },
                self.checkpoint_floor,
            )?;
            if let Some(update) = update {
                consensus_updates.push(update);
            }
            committed_checkpoint = Some(checkpoint);
        }
        if let Some(floor) = committed_checkpoint.or(self.checkpoint_floor) {
            consensus_updates.extend(
                crate::native_usdom_v4::native_usdom_v2_history_compaction_updates(
                    &self.store,
                    schedule,
                    header.height.0,
                    floor.height,
                )?,
            );
        }
        dom_store::validate_consensus_state_updates(&consensus_updates)?;
        let next_usdom_state = candidate.next_state();
        let (new_utxos, spent_utxos) = build_utxo_changeset(block);
        let block_body_bytes = block.to_bytes()?;
        self.store.commit_block_with_consensus_state(
            block_hash.as_bytes(),
            header.height.0,
            &header_bytes,
            &block_body_bytes,
            &new_utxos,
            &spent_utxos,
            &kernel_excesses,
            &consensus_updates,
        )?;
        self.tip_hash = block_hash;
        self.tip_height = header.height;
        self.tip_difficulty = header.total_difficulty;
        *current_usdom_state = next_usdom_state;
        if let Some(checkpoint) = committed_checkpoint {
            self.checkpoint_floor = Some(checkpoint);
        }
        prune_retained_side_chains(&self.store, self.tip_height, *self.tip_hash.as_bytes())?;
        info!(
            "New scheduled native USDOM v2 tip: height={}, hash={}, network=0x{:08x}",
            header.height, block_hash, self.network_magic
        );
        Ok(ConnectResult::BestChain)
    }

    /// Fully validate and retain one non-canonical native-USDOM v4 package and
    /// its proof envelope. This does not promote a heavier branch; promotion is
    /// a separate atomic operation so partially implemented reorg semantics
    /// cannot mutate canonical state.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn store_usdom_v4_side_package_regtest(
        &mut self,
        package_bytes: &[u8],
        now: Timestamp,
        current_usdom_state: &dom_usdom_state::NativeUsdomState,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: Option<&dom_usdom_privacy::verifier::SpendVerifier>,
    ) -> Result<Hash256, DomError> {
        if self.network_magic != dom_core::NETWORK_MAGIC_REGTEST {
            return Err(DomError::PolicyRejected(
                "native USDOM side packages are available only on explicit Regtest".into(),
            ));
        }
        let schedule = crate::native_usdom_v4_regtest_activation_schedule(bridge)?;
        self.store_usdom_v4_side_package_for_schedule_inner(
            package_bytes,
            now,
            current_usdom_state,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifier,
            schedule,
        )
    }

    /// Fully validate and retain one non-canonical native-USDOM v4 package
    /// under an exact activation schedule. Retention grants no promotion;
    /// scheduled fork choice must separately replay and atomically promote it.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn store_usdom_v4_side_package_for_schedule(
        &mut self,
        package_bytes: &[u8],
        now: Timestamp,
        current_usdom_state: &dom_usdom_state::NativeUsdomState,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: &dom_usdom_privacy::verifier::SpendVerifier,
        schedule: crate::NativeUsdomV4ActivationSchedule,
    ) -> Result<Hash256, DomError> {
        self.store_usdom_v4_side_package_for_schedule_inner(
            package_bytes,
            now,
            current_usdom_state,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            Some(spend_verifier),
            schedule,
        )
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    fn store_usdom_v4_side_package_for_schedule_inner(
        &mut self,
        package_bytes: &[u8],
        now: Timestamp,
        current_usdom_state: &dom_usdom_state::NativeUsdomState,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: Option<&dom_usdom_privacy::verifier::SpendVerifier>,
        schedule: crate::NativeUsdomV4ActivationSchedule,
    ) -> Result<Hash256, DomError> {
        let chain_id = derive_chain_id(self.network_magic, &self.genesis_hash);
        if schedule.network_magic() != self.network_magic || schedule.chain_id() != chain_id {
            return Err(DomError::PolicyRejected(
                "native USDOM side package does not match the ratified schedule".into(),
            ));
        }
        let persisted = crate::restore_persisted_usdom_v4_state_for_schedule(
            &self.store,
            self.network_magic,
            bridge,
            self.tip_hash,
            schedule,
        )?;
        if persisted.state_root() != current_usdom_state.state_root()
            || persisted.export_entries() != current_usdom_state.export_entries()
        {
            return Err(DomError::Internal(
                "caller native USDOM state diverges from canonical persistence".into(),
            ));
        }
        let package = crate::UsdomV4BlockPackage::from_bytes(package_bytes)?;
        let block = package.block();
        let header = &block.header;
        if header.height == BlockHeight::GENESIS || header.prev_hash == self.tip_hash {
            return Err(DomError::PolicyRejected(
                "native USDOM side-package entry requires a non-canonical parent".into(),
            ));
        }
        let header_bytes = header.to_bytes()?;
        let block_hash = compute_block_identifier(self.network_magic, &header_bytes)?;
        if self
            .store
            .get_block_header(block_hash.as_bytes())?
            .is_some()
        {
            let stored_sidecar = self
                .store
                .get_block_sidecar(block_hash.as_bytes())?
                .ok_or_else(|| DomError::Internal("known side block is missing sidecar".into()))?;
            if stored_sidecar != package.proof_envelope().to_bytes()? {
                return Err(DomError::Internal(
                    "known side block has different native USDOM sidecar bytes".into(),
                ));
            }
            return Ok(block_hash);
        }
        let parent_bytes = self
            .store
            .get_block_header(header.prev_hash.as_bytes())?
            .ok_or_else(|| DomError::Orphan(format!("parent {} not found", header.prev_hash)))?;
        let parent = BlockHeader::from_bytes(&parent_bytes)?;
        let expected_height = parent
            .height
            .checked_next()
            .ok_or_else(|| DomError::Invalid("side-package height overflow".into()))?;
        if header.height != expected_height {
            return Err(DomError::Invalid(format!(
                "side-package height mismatch: expected {expected_height}, got {}",
                header.height
            )));
        }
        validate_parent_timestamp_progression(header, &parent)?;
        let ancestors = self.get_recent_timestamps(header.prev_hash, 11)?;
        validate_median_time_past(header, &ancestors)?;
        validate_future_timestamp_with_limit(header, now, self.max_future_block_time())?;
        let seed = self.compute_randomx_seed_branch_aware(header.height.0, header.prev_hash)?;
        validate_pow_for_network(self.network_magic, header, &seed)?;
        self.validate_expected_target(header, &parent)?;
        let block_diff = target_to_difficulty_for_network_height(
            self.network_magic,
            header.height,
            &header
                .target
                .to_target()
                .map_err(|error| DomError::Invalid(format!("invalid target: {error}")))?,
        )?;
        let expected_total = checked_accumulated_difficulty(parent.total_difficulty, block_diff)?;
        if header.total_difficulty != expected_total {
            return Err(DomError::Invalid(format!(
                "side-package total_difficulty mismatch: expected {expected_total}, got {}",
                header.total_difficulty
            )));
        }

        let ancestor = find_common_ancestor(&self.store, self.tip_hash, header.prev_hash)?
            .filter(|value| *value != Hash256::ZERO)
            .ok_or_else(|| {
                DomError::Invalid("native USDOM side branch has no common ancestor".into())
            })?;
        let mut branch_state = crate::rewind_persisted_usdom_v4_state_to_ancestor_for_schedule(
            &self.store,
            self.network_magic,
            bridge,
            self.tip_hash,
            ancestor,
            schedule,
        )?;
        let mut prior_side_blocks = collect_branch_blocks(&self.store, header.prev_hash, ancestor)?;
        prior_side_blocks.reverse();
        for (prior_hash, prior_block) in prior_side_blocks {
            let proof_bytes = self
                .store
                .get_block_sidecar(prior_hash.as_bytes())?
                .ok_or_else(|| DomError::Internal("native USDOM sidecar is missing".into()))?;
            let proof_envelope = crate::UsdomV4ProofEnvelope::from_bytes(&proof_bytes)?;
            let prior_package =
                crate::UsdomV4BlockPackage::new(prior_block.clone(), proof_envelope)?.to_bytes()?;
            let context = ValidationContext {
                current_height: prior_block.header.height,
                chain_id: *chain_id.as_bytes(),
                now,
            };
            let verified =
                crate::native_usdom_v4::verify_usdom_v4_serialized_candidate_for_schedule_inner(
                    &prior_package,
                    &context,
                    self.network_magic,
                    &branch_state,
                    bridge,
                    checkpoint_policy,
                    deposit_policy,
                    closure_policy,
                    spend_verifier,
                    schedule,
                )?;
            branch_state = verified.next_state().clone();
        }
        let context = ValidationContext {
            current_height: header.height,
            chain_id: *chain_id.as_bytes(),
            now,
        };
        let verified =
            crate::native_usdom_v4::verify_usdom_v4_serialized_candidate_for_schedule_inner(
                package_bytes,
                &context,
                self.network_magic,
                &branch_state,
                bridge,
                checkpoint_policy,
                deposit_policy,
                closure_policy,
                spend_verifier,
                schedule,
            )?;
        if verified.block_identifier() != block_hash {
            return Err(DomError::Internal(
                "verified native USDOM side block identifier mismatch".into(),
            ));
        }
        let block_body_bytes = block.to_bytes()?;
        let proof_bytes = package.proof_envelope().to_bytes()?;
        self.store.store_known_block_with_sidecar(
            block_hash.as_bytes(),
            &header_bytes,
            &block_body_bytes,
            &proof_bytes,
        )?;
        prune_retained_side_chains(&self.store, self.tip_height, *self.tip_hash.as_bytes())?;
        Ok(block_hash)
    }

    /// Fully validate and retain one non-canonical candidate-v2 package and
    /// its exact proof-and-witness sidecar under the ratified migration
    /// schedule. Retention never mutates canonical state.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn store_usdom_v2_side_package_for_schedule(
        &mut self,
        package_bytes: &[u8],
        witness_bundle: &crate::UsdomV2ExecutionWitnesses,
        now: Timestamp,
        current_usdom_state: &dom_usdom_state::StateCommitmentV2,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: &dom_usdom_privacy::verifier::SpendVerifier,
        schedule: crate::NativeUsdomV2ActivationSchedule,
    ) -> Result<Hash256, DomError> {
        let chain_id = derive_chain_id(self.network_magic, &self.genesis_hash);
        if schedule.network_magic() != self.network_magic || schedule.chain_id() != chain_id {
            return Err(DomError::PolicyRejected(
                "native USDOM v2 side package does not match the ratified schedule".into(),
            ));
        }
        let persisted = crate::restore_persisted_usdom_v2_state_for_schedule(
            &self.store,
            self.network_magic,
            self.tip_hash,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifier,
            schedule,
        )?;
        if persisted != *current_usdom_state {
            return Err(DomError::Internal(
                "caller native USDOM v2 state diverges from canonical persistence".into(),
            ));
        }
        let package = crate::UsdomV4BlockPackage::from_bytes(package_bytes)?;
        let block = package.block();
        let header = &block.header;
        if header.height == BlockHeight::GENESIS
            || header.height.0 < schedule.first_v2_height()
            || header.prev_hash == self.tip_hash
        {
            return Err(DomError::PolicyRejected(
                "native USDOM v2 side-package entry requires a scheduled non-canonical parent"
                    .into(),
            ));
        }
        let header_bytes = header.to_bytes()?;
        let block_hash = compute_block_identifier(self.network_magic, &header_bytes)?;
        let sidecar = crate::UsdomV2BlockSidecar::new(
            package.proof_envelope().clone(),
            witness_bundle.clone(),
        )?;
        let sidecar_bytes = sidecar.to_bytes()?;
        if self
            .store
            .get_block_header(block_hash.as_bytes())?
            .is_some()
        {
            let stored_sidecar = self
                .store
                .get_block_sidecar(block_hash.as_bytes())?
                .ok_or_else(|| {
                    DomError::Internal("known v2 side block is missing sidecar".into())
                })?;
            if stored_sidecar != sidecar_bytes {
                return Err(DomError::Internal(
                    "known v2 side block has different recovery bytes".into(),
                ));
            }
            return Ok(block_hash);
        }
        let parent_bytes = self
            .store
            .get_block_header(header.prev_hash.as_bytes())?
            .ok_or_else(|| DomError::Orphan(format!("parent {} not found", header.prev_hash)))?;
        let parent = BlockHeader::from_bytes(&parent_bytes)?;
        let expected_height = parent
            .height
            .checked_next()
            .ok_or_else(|| DomError::Invalid("v2 side-package height overflow".into()))?;
        if header.height != expected_height {
            return Err(DomError::Invalid(format!(
                "v2 side-package height mismatch: expected {expected_height}, got {}",
                header.height
            )));
        }
        validate_parent_timestamp_progression(header, &parent)?;
        let ancestors = self.get_recent_timestamps(header.prev_hash, 11)?;
        validate_median_time_past(header, &ancestors)?;
        validate_future_timestamp_with_limit(header, now, self.max_future_block_time())?;
        let seed = self.compute_randomx_seed_branch_aware(header.height.0, header.prev_hash)?;
        validate_pow_for_network(self.network_magic, header, &seed)?;
        self.validate_expected_target(header, &parent)?;
        let block_diff = target_to_difficulty_for_network_height(
            self.network_magic,
            header.height,
            &header
                .target
                .to_target()
                .map_err(|error| DomError::Invalid(format!("invalid target: {error}")))?,
        )?;
        let expected_total = checked_accumulated_difficulty(parent.total_difficulty, block_diff)?;
        if header.total_difficulty != expected_total {
            return Err(DomError::Invalid(format!(
                "v2 side-package total_difficulty mismatch: expected {expected_total}, got {}",
                header.total_difficulty
            )));
        }

        let ancestor = find_common_ancestor(&self.store, self.tip_hash, header.prev_hash)?
            .filter(|value| *value != Hash256::ZERO)
            .ok_or_else(|| {
                DomError::Invalid("native USDOM v2 side branch has no common ancestor".into())
            })?;
        let ancestor_header = self
            .store
            .get_block_header(ancestor.as_bytes())?
            .ok_or_else(|| DomError::Internal("native USDOM v2 ancestor is missing".into()))
            .and_then(|bytes| BlockHeader::from_bytes(&bytes))?;
        if ancestor_header.height.0
            < schedule
                .first_v2_height()
                .checked_sub(1)
                .ok_or_else(|| DomError::Invalid("invalid v2 activation height".into()))?
        {
            return Err(DomError::PolicyRejected(
                "native USDOM v2 side branch crosses below activation".into(),
            ));
        }
        let mut branch_state = crate::native_usdom_v4::rewind_persisted_usdom_v2_state_to_ancestor(
            &self.store,
            self.tip_hash,
            *current_usdom_state,
            ancestor,
            schedule,
        )?;
        let mut prior_side_blocks = collect_branch_blocks(&self.store, header.prev_hash, ancestor)?;
        prior_side_blocks.reverse();
        for (prior_hash, prior_block) in prior_side_blocks {
            let prior_package = crate::load_persisted_usdom_v4_package(
                &self.store,
                self.network_magic,
                prior_hash,
            )?
            .ok_or_else(|| DomError::Internal("native USDOM v2 side package is missing".into()))?;
            let prior_witnesses =
                crate::load_persisted_usdom_v2_execution_witnesses(&self.store, prior_hash)?
                    .ok_or_else(|| {
                        DomError::Internal("native USDOM v2 side witnesses are missing".into())
                    })?;
            let context = ValidationContext {
                current_height: prior_block.header.height,
                chain_id: *chain_id.as_bytes(),
                now,
            };
            let verified = crate::verify_usdom_v4_serialized_transition_batch_for_v2_schedule(
                &prior_package,
                &context,
                self.network_magic,
                bridge,
                checkpoint_policy,
                deposit_policy,
                closure_policy,
                spend_verifier,
                schedule,
            )?;
            let candidate = verified.execute_v2(
                &context,
                branch_state.root(),
                branch_state,
                prior_witnesses.witnesses(),
            )?;
            if candidate.block_identifier() != prior_hash {
                return Err(DomError::Internal(
                    "verified native USDOM v2 prior side block identifier mismatch".into(),
                ));
            }
            branch_state = candidate.next_state();
        }
        let context = ValidationContext {
            current_height: header.height,
            chain_id: *chain_id.as_bytes(),
            now,
        };
        let verified = crate::verify_usdom_v4_serialized_transition_batch_for_v2_schedule(
            package_bytes,
            &context,
            self.network_magic,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifier,
            schedule,
        )?;
        let candidate = verified.execute_v2(
            &context,
            branch_state.root(),
            branch_state,
            witness_bundle.witnesses(),
        )?;
        if candidate.block_identifier() != block_hash {
            return Err(DomError::Internal(
                "verified native USDOM v2 side block identifier mismatch".into(),
            ));
        }
        self.store.store_known_block_with_sidecar(
            block_hash.as_bytes(),
            &header_bytes,
            &block.to_bytes()?,
            &sidecar_bytes,
        )?;
        prune_retained_side_chains(&self.store, self.tip_height, *self.tip_hash.as_bytes())?;
        Ok(block_hash)
    }

    /// Fully replay and atomically promote a retained native-USDOM v4 Regtest
    /// branch. Canonical pointers, UTXOs, kernels, native state, per-block
    /// undos and sidecars for the disconnected branch change in one LMDB
    /// transaction. The caller state changes only after that commit succeeds.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn promote_usdom_v4_known_tip_regtest(
        &mut self,
        new_tip_hash: Hash256,
        now: Timestamp,
        current_usdom_state: &mut dom_usdom_state::NativeUsdomState,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: Option<&dom_usdom_privacy::verifier::SpendVerifier>,
    ) -> Result<ReorgDelta, DomError> {
        if self.network_magic != dom_core::NETWORK_MAGIC_REGTEST {
            return Err(DomError::PolicyRejected(
                "native USDOM branch promotion is available only on explicit Regtest".into(),
            ));
        }
        let schedule = crate::native_usdom_v4_regtest_activation_schedule(bridge)?;
        self.promote_usdom_v4_known_tip_for_schedule_inner(
            new_tip_hash,
            now,
            current_usdom_state,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifier,
            schedule,
        )
    }

    /// Fully replay and atomically promote a retained native-USDOM v4 branch
    /// under an exact activation schedule and committed private-spend verifier.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn promote_usdom_v4_known_tip_for_schedule(
        &mut self,
        new_tip_hash: Hash256,
        now: Timestamp,
        current_usdom_state: &mut dom_usdom_state::NativeUsdomState,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: &dom_usdom_privacy::verifier::SpendVerifier,
        schedule: crate::NativeUsdomV4ActivationSchedule,
    ) -> Result<ReorgDelta, DomError> {
        self.promote_usdom_v4_known_tip_for_schedule_inner(
            new_tip_hash,
            now,
            current_usdom_state,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            Some(spend_verifier),
            schedule,
        )
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    fn promote_usdom_v4_known_tip_for_schedule_inner(
        &mut self,
        new_tip_hash: Hash256,
        now: Timestamp,
        current_usdom_state: &mut dom_usdom_state::NativeUsdomState,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: Option<&dom_usdom_privacy::verifier::SpendVerifier>,
        schedule: crate::NativeUsdomV4ActivationSchedule,
    ) -> Result<ReorgDelta, DomError> {
        let chain_id = derive_chain_id(self.network_magic, &self.genesis_hash);
        if schedule.network_magic() != self.network_magic || schedule.chain_id() != chain_id {
            return Err(DomError::PolicyRejected(
                "native USDOM branch promotion does not match the ratified schedule".into(),
            ));
        }
        self.ensure_checkpoint_floor()?;
        let persisted = crate::restore_persisted_usdom_v4_state_for_schedule(
            &self.store,
            self.network_magic,
            bridge,
            self.tip_hash,
            schedule,
        )?;
        if persisted.state_root() != current_usdom_state.state_root()
            || persisted.export_entries() != current_usdom_state.export_entries()
        {
            return Err(DomError::Internal(
                "caller native USDOM state diverges from canonical persistence".into(),
            ));
        }
        if new_tip_hash == self.tip_hash {
            return Err(DomError::PolicyRejected(
                "native USDOM reorg target is already canonical".into(),
            ));
        }
        let new_tip_header = self
            .store
            .get_block_header(new_tip_hash.as_bytes())?
            .ok_or_else(|| DomError::Internal("native USDOM reorg target is missing".into()))
            .and_then(|bytes| BlockHeader::from_bytes(&bytes))?;
        let ancestor = find_common_ancestor(&self.store, self.tip_hash, new_tip_hash)?
            .filter(|hash| *hash != Hash256::ZERO)
            .ok_or_else(|| {
                DomError::Invalid("native USDOM branch has no common ancestor".into())
            })?;
        let ancestor_header = self
            .store
            .get_block_header(ancestor.as_bytes())?
            .ok_or_else(|| DomError::Internal("native USDOM reorg ancestor is missing".into()))
            .and_then(|bytes| BlockHeader::from_bytes(&bytes))?;
        let ancestor_height = ancestor_header.height.0;
        crate::ethereum_checkpoint_poc::check_reorg(
            &self.store,
            self.tip_height.0,
            ancestor_height,
        )?;
        if !is_better_fork_choice_tip(
            new_tip_header.total_difficulty,
            new_tip_hash,
            self.tip_difficulty,
            self.tip_hash,
        ) {
            return Err(DomError::PolicyRejected(
                "native USDOM reorg target does not improve fork choice".into(),
            ));
        }
        let reorg_depth = self
            .tip_height
            .0
            .checked_sub(ancestor_height)
            .ok_or_else(|| DomError::Internal("native USDOM ancestor is above tip".into()))?;
        check_rolling_finality(self.tip_height.0, reorg_depth)?;
        check_reorg_depth(reorg_depth)?;

        let disconnect_blocks = collect_branch_blocks(&self.store, self.tip_hash, ancestor)?;
        if disconnect_blocks.len() as u64 != reorg_depth {
            return Err(DomError::Internal(
                "native USDOM disconnect depth does not match ancestry".into(),
            ));
        }
        let mut connect_blocks = collect_branch_blocks(&self.store, new_tip_hash, ancestor)?;
        connect_blocks.reverse();
        if connect_blocks.is_empty()
            || connect_blocks.len() as u64 > dom_core::MAX_REORG_DEPTH_POLICY
        {
            return Err(DomError::PolicyRejected(
                "native USDOM promoted branch length is outside policy".into(),
            ));
        }

        let mut expected_parent = ancestor;
        let mut expected_parent_header = ancestor_header;
        let mut branch_state = crate::rewind_persisted_usdom_v4_state_to_ancestor_for_schedule(
            &self.store,
            self.network_magic,
            bridge,
            self.tip_hash,
            ancestor,
            schedule,
        )?;
        let mut branch_targets: HashMap<Hash256, (u64, Hash256)> = HashMap::new();
        branch_targets.insert(ancestor, (ancestor_height, branch_state.state_root()));
        let mut promoted_checkpoint = self.checkpoint_floor;
        let mut consensus_overlay: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        for (block_hash, block) in &connect_blocks {
            let header = &block.header;
            let header_bytes = header.to_bytes()?;
            if compute_block_identifier(self.network_magic, &header_bytes)? != *block_hash
                || header.prev_hash != expected_parent
                || header.height
                    != expected_parent_header
                        .height
                        .checked_next()
                        .ok_or_else(|| {
                            DomError::Invalid("native USDOM promoted height overflow".into())
                        })?
            {
                return Err(DomError::Invalid(
                    "native USDOM promoted branch linkage mismatch".into(),
                ));
            }
            validate_parent_timestamp_progression(header, &expected_parent_header)?;
            let ancestors = self.get_recent_timestamps(header.prev_hash, 11)?;
            validate_median_time_past(header, &ancestors)?;
            validate_future_timestamp_with_limit(header, now, self.max_future_block_time())?;
            let seed = self.compute_randomx_seed_branch_aware(header.height.0, header.prev_hash)?;
            validate_pow_for_network(self.network_magic, header, &seed)?;
            self.validate_expected_target(header, &expected_parent_header)?;
            let block_diff = target_to_difficulty_for_network_height(
                self.network_magic,
                header.height,
                &header
                    .target
                    .to_target()
                    .map_err(|error| DomError::Invalid(format!("invalid target: {error}")))?,
            )?;
            let expected_total = checked_accumulated_difficulty(
                expected_parent_header.total_difficulty,
                block_diff,
            )?;
            if header.total_difficulty != expected_total {
                return Err(DomError::Invalid(
                    "native USDOM promoted total difficulty mismatch".into(),
                ));
            }

            let proof_bytes = self
                .store
                .get_block_sidecar(block_hash.as_bytes())?
                .ok_or_else(|| {
                    DomError::Internal("native USDOM promoted sidecar is missing".into())
                })?;
            let proof_envelope = crate::UsdomV4ProofEnvelope::from_bytes(&proof_bytes)?;
            let package_bytes =
                crate::UsdomV4BlockPackage::new(block.clone(), proof_envelope)?.to_bytes()?;
            let context = ValidationContext {
                current_height: header.height,
                chain_id: *chain_id.as_bytes(),
                now,
            };
            let verified =
                crate::native_usdom_v4::verify_usdom_v4_serialized_candidate_for_schedule_inner(
                    &package_bytes,
                    &context,
                    self.network_magic,
                    &branch_state,
                    bridge,
                    checkpoint_policy,
                    deposit_policy,
                    closure_policy,
                    spend_verifier,
                    schedule,
                )?;
            if verified.block_identifier() != *block_hash {
                return Err(DomError::Internal(
                    "verified native USDOM promoted block identifier mismatch".into(),
                ));
            }
            if let Some(checkpoint_capability) = verified.verified_checkpoint() {
                let asserted = crate::ethereum_checkpoint_poc::decode_test_oracle_v2(
                    checkpoint_capability.record(),
                )?;
                let target_state_root = if let Some((height, root)) =
                    branch_targets.get(&asserted.dom_block).copied()
                {
                    if height != asserted.height {
                        return Err(DomError::Invalid(
                            "native USDOM branch checkpoint height mismatch".into(),
                        ));
                    }
                    root
                } else if asserted.height <= ancestor_height
                    && self.store.get_hash_at_height(asserted.height)?
                        == Some(*asserted.dom_block.as_bytes())
                {
                    crate::rewind_persisted_usdom_v4_state_to_ancestor_for_schedule(
                        &self.store,
                        self.network_magic,
                        bridge,
                        self.tip_hash,
                        asserted.dom_block,
                        schedule,
                    )?
                    .state_root()
                } else {
                    return Err(DomError::Invalid(
                        "native USDOM checkpoint target is not in the promoted ancestry".into(),
                    ));
                };
                let (checkpoint, update) = crate::native_usdom_v4::native_checkpoint_floor_update(
                    checkpoint_capability,
                    self.network_magic,
                    bridge,
                    crate::native_usdom_v4::NativeCheckpointTarget {
                        carrier_height: header.height.0,
                        height: asserted.height,
                        block: asserted.dom_block,
                        state_root: target_state_root,
                    },
                    promoted_checkpoint,
                )?;
                if let Some(update) = update {
                    consensus_overlay.insert(update.key, update.value);
                }
                promoted_checkpoint = Some(checkpoint);
            }
            for update in verified.sidecar_reorg_persistence_updates(&package_bytes)? {
                consensus_overlay.insert(update.key, update.value);
            }
            branch_state = verified.next_state().clone();
            branch_targets.insert(*block_hash, (header.height.0, branch_state.state_root()));
            expected_parent = *block_hash;
            expected_parent_header = header.clone();
        }
        for update in branch_state
            .storage_delta_from(current_usdom_state)
            .map_err(|error| {
                DomError::Invalid(format!("native USDOM reorg delta failed: {error}"))
            })?
        {
            consensus_overlay.insert(update.key, update.value);
        }
        for (block_hash, _) in &disconnect_blocks {
            consensus_overlay.insert(
                crate::native_usdom_v4::native_usdom_v4_undo_key(*block_hash),
                None,
            );
            for update in
                crate::native_usdom_v4::native_usdom_v4_disconnected_package_deletion_updates(
                    &self.store,
                    *block_hash,
                )?
            {
                consensus_overlay.insert(update.key, update.value);
            }
        }
        let promoted_prune_hash = new_tip_header
            .height
            .0
            .checked_sub(crate::reorg::MAX_REORG_DEPTH)
            .and_then(|prune_height| {
                connect_blocks
                    .iter()
                    .find(|(_, block)| block.header.height.0 == prune_height)
                    .map(|(block_hash, _)| *block_hash)
            });
        if let Some(update) = native_usdom_v4_reorg_retention_update(
            &self.store,
            new_tip_header.height.0,
            promoted_prune_hash,
        )? {
            consensus_overlay.insert(update.key, update.value);
        }
        let consensus_updates: Vec<dom_store::ConsensusStateUpdate> = consensus_overlay
            .into_iter()
            .map(|(key, value)| dom_store::ConsensusStateUpdate { key, value })
            .collect();
        dom_store::validate_consensus_state_updates(&consensus_updates)?;

        let reorg_delta = ReorgDelta {
            common_ancestor_height: ancestor_height,
            disconnected_blocks: disconnect_blocks
                .iter()
                .map(|(block_hash, block)| ReorgBlockDelta {
                    block_hash: *block_hash.as_bytes(),
                    block_height: block.header.height.0,
                    transactions: block.transactions.clone(),
                })
                .collect(),
            connected_blocks: connect_blocks
                .iter()
                .map(|(block_hash, block)| ReorgBlockDelta {
                    block_hash: *block_hash.as_bytes(),
                    block_height: block.header.height.0,
                    transactions: block.transactions.clone(),
                })
                .collect(),
            disconnected_txs: disconnect_blocks
                .iter()
                .flat_map(|(_, block)| block.transactions.clone())
                .collect(),
            connected_txs: connect_blocks
                .iter()
                .flat_map(|(_, block)| block.transactions.clone())
                .collect(),
        };
        let mut disconnect_output_index = HashMap::new();
        for (_, block) in &disconnect_blocks {
            record_block_outputs(block, &mut disconnect_output_index);
        }
        let mut utxo_overlay: BTreeMap<[u8; 33], Option<UtxoEntry>> = BTreeMap::new();
        let mut kernel_overlay: BTreeMap<[u8; 33], Option<[u8; 32]>> = BTreeMap::new();
        for (block_hash, block) in &disconnect_blocks {
            apply_disconnect(
                &self.store,
                &mut utxo_overlay,
                &mut kernel_overlay,
                *block_hash,
                block,
                ancestor_height,
                &disconnect_output_index,
            )?;
        }
        for (block_hash, block) in &connect_blocks {
            apply_connect(
                &self.store,
                &mut utxo_overlay,
                &mut kernel_overlay,
                *block_hash,
                block,
                self.coinbase_maturity,
            )?;
        }
        let mut height_updates = BTreeMap::new();
        for height in (ancestor_height + 1)..=self.tip_height.0 {
            height_updates.insert(height, None);
        }
        for (block_hash, block) in &connect_blocks {
            height_updates.insert(block.header.height.0, Some(*block_hash.as_bytes()));
        }
        let height_updates: Vec<(u64, Option<[u8; 32]>)> = height_updates.into_iter().collect();
        let utxo_updates = build_utxo_updates(&self.store, &utxo_overlay)?;
        let kernel_updates = build_kernel_updates(&self.store, &kernel_overlay)?;

        let mut disconnected_sidecars = Vec::with_capacity(disconnect_blocks.len());
        for (block_hash, _) in &disconnect_blocks {
            let package_bytes = crate::load_persisted_usdom_v4_package(
                &self.store,
                self.network_magic,
                *block_hash,
            )?
            .ok_or_else(|| {
                DomError::Internal("disconnected native USDOM package is missing".into())
            })?;
            let package = crate::UsdomV4BlockPackage::from_bytes(&package_bytes)?;
            disconnected_sidecars
                .push((*block_hash.as_bytes(), package.proof_envelope().to_bytes()?));
        }

        self.store.apply_reorg_with_consensus_state_and_sidecars(
            new_tip_hash.as_bytes(),
            &height_updates,
            &utxo_updates,
            &kernel_updates,
            &consensus_updates,
            &disconnected_sidecars,
        )?;
        self.tip_hash = new_tip_hash;
        self.tip_height = new_tip_header.height;
        self.tip_difficulty = new_tip_header.total_difficulty;
        *current_usdom_state = branch_state;
        self.checkpoint_floor = promoted_checkpoint;
        prune_retained_side_chains(&self.store, self.tip_height, *self.tip_hash.as_bytes())?;
        info!(
            "Native USDOM v4 reorg applied: new tip height={}, hash={}, ancestor={}",
            self.tip_height, self.tip_hash, ancestor
        );
        Ok(reorg_delta)
    }

    /// Fully replay and atomically promote a retained candidate-v2 branch.
    /// Every package and witness sidecar is reverified before canonical
    /// pointers, ordinary UTXOs/kernels, V2 records and checkpoint floor change
    /// in one transaction.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn promote_usdom_v2_known_tip_for_schedule(
        &mut self,
        new_tip_hash: Hash256,
        now: Timestamp,
        current_usdom_state: &mut dom_usdom_state::StateCommitmentV2,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: &dom_usdom_privacy::verifier::SpendVerifier,
        schedule: crate::NativeUsdomV2ActivationSchedule,
    ) -> Result<ReorgDelta, DomError> {
        let chain_id = derive_chain_id(self.network_magic, &self.genesis_hash);
        if schedule.network_magic() != self.network_magic || schedule.chain_id() != chain_id {
            return Err(DomError::PolicyRejected(
                "native USDOM v2 branch promotion does not match the ratified schedule".into(),
            ));
        }
        self.ensure_checkpoint_floor()?;
        let persisted = crate::restore_persisted_usdom_v2_state_for_schedule(
            &self.store,
            self.network_magic,
            self.tip_hash,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifier,
            schedule,
        )?;
        if persisted != *current_usdom_state {
            return Err(DomError::Internal(
                "caller native USDOM v2 state diverges from canonical persistence".into(),
            ));
        }
        if new_tip_hash == self.tip_hash {
            return Err(DomError::PolicyRejected(
                "native USDOM v2 reorg target is already canonical".into(),
            ));
        }
        let new_tip_header = self
            .store
            .get_block_header(new_tip_hash.as_bytes())?
            .ok_or_else(|| DomError::Internal("native USDOM v2 reorg target is missing".into()))
            .and_then(|bytes| BlockHeader::from_bytes(&bytes))?;
        let ancestor = find_common_ancestor(&self.store, self.tip_hash, new_tip_hash)?
            .filter(|hash| *hash != Hash256::ZERO)
            .ok_or_else(|| {
                DomError::Invalid("native USDOM v2 branch has no common ancestor".into())
            })?;
        let ancestor_header = self
            .store
            .get_block_header(ancestor.as_bytes())?
            .ok_or_else(|| DomError::Internal("native USDOM v2 reorg ancestor is missing".into()))
            .and_then(|bytes| BlockHeader::from_bytes(&bytes))?;
        let ancestor_height = ancestor_header.height.0;
        let minimum_height = schedule
            .first_v2_height()
            .checked_sub(1)
            .ok_or_else(|| DomError::Invalid("invalid v2 activation height".into()))?;
        if ancestor_height < minimum_height {
            return Err(DomError::PolicyRejected(
                "native USDOM v2 reorg crosses below activation".into(),
            ));
        }
        crate::ethereum_checkpoint_poc::check_reorg(
            &self.store,
            self.tip_height.0,
            ancestor_height,
        )?;
        if !is_better_fork_choice_tip(
            new_tip_header.total_difficulty,
            new_tip_hash,
            self.tip_difficulty,
            self.tip_hash,
        ) {
            return Err(DomError::PolicyRejected(
                "native USDOM v2 reorg target does not improve fork choice".into(),
            ));
        }
        let reorg_depth = self
            .tip_height
            .0
            .checked_sub(ancestor_height)
            .ok_or_else(|| DomError::Internal("native USDOM v2 ancestor is above tip".into()))?;
        check_rolling_finality(self.tip_height.0, reorg_depth)?;
        check_reorg_depth(reorg_depth)?;

        let disconnect_blocks = collect_branch_blocks(&self.store, self.tip_hash, ancestor)?;
        if disconnect_blocks.len() as u64 != reorg_depth {
            return Err(DomError::Internal(
                "native USDOM v2 disconnect depth does not match ancestry".into(),
            ));
        }
        let mut connect_blocks = collect_branch_blocks(&self.store, new_tip_hash, ancestor)?;
        connect_blocks.reverse();
        if connect_blocks.is_empty()
            || connect_blocks.len() as u64 > dom_core::MAX_REORG_DEPTH_POLICY
        {
            return Err(DomError::PolicyRejected(
                "native USDOM v2 promoted branch length is outside policy".into(),
            ));
        }

        let mut expected_parent = ancestor;
        let mut expected_parent_header = ancestor_header;
        let mut branch_state = crate::native_usdom_v4::rewind_persisted_usdom_v2_state_to_ancestor(
            &self.store,
            self.tip_hash,
            *current_usdom_state,
            ancestor,
            schedule,
        )?;
        let mut branch_targets: HashMap<Hash256, (u64, Hash256)> = HashMap::new();
        branch_targets.insert(ancestor, (ancestor_height, branch_state.root()));
        let mut promoted_checkpoint = self.checkpoint_floor;
        let mut consensus_overlay: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        let mut disconnected_sidecars = Vec::with_capacity(disconnect_blocks.len());
        for (block_hash, _) in &disconnect_blocks {
            let package_bytes = crate::load_persisted_usdom_v4_package(
                &self.store,
                self.network_magic,
                *block_hash,
            )?
            .ok_or_else(|| {
                DomError::Internal(
                    "disconnected native USDOM V2 package is missing during archive rollback"
                        .into(),
                )
            })?;
            let package = crate::UsdomV4BlockPackage::from_bytes(&package_bytes)?;
            let witnesses =
                crate::load_persisted_usdom_v2_execution_witnesses(&self.store, *block_hash)?
                    .ok_or_else(|| {
                        DomError::Internal(
                            "disconnected native USDOM V2 witnesses are missing during rollback"
                                .into(),
                        )
                    })?;
            let sidecar =
                crate::UsdomV2BlockSidecar::new(package.proof_envelope().clone(), witnesses)?;
            disconnected_sidecars.push((*block_hash.as_bytes(), sidecar.to_bytes()?));
            for update in
                crate::native_usdom_v4::native_usdom_v2_disconnected_replay_deletion_updates(
                    &self.store,
                    *block_hash,
                )?
            {
                consensus_overlay.insert(update.key, update.value);
            }
            for burn in package.proof_envelope().public_burn_records()? {
                consensus_overlay.insert(
                    crate::native_usdom_v4::v2_burn_archive_delete_key(burn.burn_id),
                    None,
                );
            }
        }
        for (block_hash, block) in &connect_blocks {
            let header = &block.header;
            let header_bytes = header.to_bytes()?;
            if compute_block_identifier(self.network_magic, &header_bytes)? != *block_hash
                || header.prev_hash != expected_parent
                || header.height
                    != expected_parent_header
                        .height
                        .checked_next()
                        .ok_or_else(|| {
                            DomError::Invalid("native USDOM v2 promoted height overflow".into())
                        })?
            {
                return Err(DomError::Invalid(
                    "native USDOM v2 promoted branch linkage mismatch".into(),
                ));
            }
            validate_parent_timestamp_progression(header, &expected_parent_header)?;
            let ancestors = self.get_recent_timestamps(header.prev_hash, 11)?;
            validate_median_time_past(header, &ancestors)?;
            validate_future_timestamp_with_limit(header, now, self.max_future_block_time())?;
            let seed = self.compute_randomx_seed_branch_aware(header.height.0, header.prev_hash)?;
            validate_pow_for_network(self.network_magic, header, &seed)?;
            self.validate_expected_target(header, &expected_parent_header)?;
            let block_diff = target_to_difficulty_for_network_height(
                self.network_magic,
                header.height,
                &header
                    .target
                    .to_target()
                    .map_err(|error| DomError::Invalid(format!("invalid target: {error}")))?,
            )?;
            let expected_total = checked_accumulated_difficulty(
                expected_parent_header.total_difficulty,
                block_diff,
            )?;
            if header.total_difficulty != expected_total {
                return Err(DomError::Invalid(
                    "native USDOM v2 promoted total difficulty mismatch".into(),
                ));
            }

            let package_bytes = crate::load_persisted_usdom_v4_package(
                &self.store,
                self.network_magic,
                *block_hash,
            )?
            .ok_or_else(|| {
                DomError::Internal("native USDOM v2 promoted package is missing".into())
            })?;
            let witnesses =
                crate::load_persisted_usdom_v2_execution_witnesses(&self.store, *block_hash)?
                    .ok_or_else(|| {
                        DomError::Internal("native USDOM v2 promoted witnesses are missing".into())
                    })?;
            let context = ValidationContext {
                current_height: header.height,
                chain_id: *chain_id.as_bytes(),
                now,
            };
            let verified = crate::verify_usdom_v4_serialized_transition_batch_for_v2_schedule(
                &package_bytes,
                &context,
                self.network_magic,
                bridge,
                checkpoint_policy,
                deposit_policy,
                closure_policy,
                spend_verifier,
                schedule,
            )?;
            let previous_state = branch_state;
            let candidate = verified.execute_v2(
                &context,
                previous_state.root(),
                previous_state,
                witnesses.witnesses(),
            )?;
            if candidate.block_identifier() != *block_hash {
                return Err(DomError::Internal(
                    "verified native USDOM v2 promoted block identifier mismatch".into(),
                ));
            }
            if let Some(checkpoint_capability) = verified.verified_checkpoint() {
                let asserted = crate::ethereum_checkpoint_poc::decode_test_oracle_v2(
                    checkpoint_capability.record(),
                )?;
                let target_state_root = if let Some((height, root)) =
                    branch_targets.get(&asserted.dom_block).copied()
                {
                    if height != asserted.height {
                        return Err(DomError::Invalid(
                            "native USDOM v2 branch checkpoint height mismatch".into(),
                        ));
                    }
                    root
                } else if asserted.height <= ancestor_height
                    && self.store.get_hash_at_height(asserted.height)?
                        == Some(*asserted.dom_block.as_bytes())
                {
                    crate::native_usdom_v4::rewind_persisted_usdom_v2_state_to_ancestor(
                        &self.store,
                        self.tip_hash,
                        *current_usdom_state,
                        asserted.dom_block,
                        schedule,
                    )?
                    .root()
                } else {
                    return Err(DomError::Invalid(
                        "native USDOM v2 checkpoint target is not in promoted ancestry".into(),
                    ));
                };
                let (checkpoint, update) = crate::native_usdom_v4::native_checkpoint_floor_update(
                    checkpoint_capability,
                    self.network_magic,
                    bridge,
                    crate::native_usdom_v4::NativeCheckpointTarget {
                        carrier_height: header.height.0,
                        height: asserted.height,
                        block: asserted.dom_block,
                        state_root: target_state_root,
                    },
                    promoted_checkpoint,
                )?;
                if let Some(update) = update {
                    consensus_overlay.insert(update.key, update.value);
                }
                promoted_checkpoint = Some(checkpoint);
            }
            for update in candidate.sidecar_reorg_persistence_updates(
                schedule,
                previous_state,
                &package_bytes,
                &witnesses,
            )? {
                consensus_overlay.insert(update.key, update.value);
            }
            branch_state = candidate.next_state();
            branch_targets.insert(*block_hash, (header.height.0, branch_state.root()));
            expected_parent = *block_hash;
            expected_parent_header = header.clone();
        }
        let consensus_updates: Vec<dom_store::ConsensusStateUpdate> = consensus_overlay
            .into_iter()
            .map(|(key, value)| dom_store::ConsensusStateUpdate { key, value })
            .collect();
        dom_store::validate_consensus_state_updates(&consensus_updates)?;

        let reorg_delta = ReorgDelta {
            common_ancestor_height: ancestor_height,
            disconnected_blocks: disconnect_blocks
                .iter()
                .map(|(block_hash, block)| ReorgBlockDelta {
                    block_hash: *block_hash.as_bytes(),
                    block_height: block.header.height.0,
                    transactions: block.transactions.clone(),
                })
                .collect(),
            connected_blocks: connect_blocks
                .iter()
                .map(|(block_hash, block)| ReorgBlockDelta {
                    block_hash: *block_hash.as_bytes(),
                    block_height: block.header.height.0,
                    transactions: block.transactions.clone(),
                })
                .collect(),
            disconnected_txs: disconnect_blocks
                .iter()
                .flat_map(|(_, block)| block.transactions.clone())
                .collect(),
            connected_txs: connect_blocks
                .iter()
                .flat_map(|(_, block)| block.transactions.clone())
                .collect(),
        };
        let mut disconnect_output_index = HashMap::new();
        for (_, block) in &disconnect_blocks {
            record_block_outputs(block, &mut disconnect_output_index);
        }
        let mut utxo_overlay: BTreeMap<[u8; 33], Option<UtxoEntry>> = BTreeMap::new();
        let mut kernel_overlay: BTreeMap<[u8; 33], Option<[u8; 32]>> = BTreeMap::new();
        for (block_hash, block) in &disconnect_blocks {
            apply_disconnect(
                &self.store,
                &mut utxo_overlay,
                &mut kernel_overlay,
                *block_hash,
                block,
                ancestor_height,
                &disconnect_output_index,
            )?;
        }
        for (block_hash, block) in &connect_blocks {
            apply_connect(
                &self.store,
                &mut utxo_overlay,
                &mut kernel_overlay,
                *block_hash,
                block,
                self.coinbase_maturity,
            )?;
        }
        let mut height_updates = BTreeMap::new();
        for height in (ancestor_height + 1)..=self.tip_height.0 {
            height_updates.insert(height, None);
        }
        for (block_hash, block) in &connect_blocks {
            height_updates.insert(block.header.height.0, Some(*block_hash.as_bytes()));
        }
        let height_updates: Vec<(u64, Option<[u8; 32]>)> = height_updates.into_iter().collect();
        let utxo_updates = build_utxo_updates(&self.store, &utxo_overlay)?;
        let kernel_updates = build_kernel_updates(&self.store, &kernel_overlay)?;

        let promoted_sidecar_deletes: Vec<[u8; 32]> = connect_blocks
            .iter()
            .map(|(block_hash, _)| *block_hash.as_bytes())
            .collect();
        self.store
            .apply_reorg_with_consensus_state_and_sidecar_changes(
                new_tip_hash.as_bytes(),
                &height_updates,
                &utxo_updates,
                &kernel_updates,
                &consensus_updates,
                dom_store::ReorgSidecarChanges {
                    inserts: &disconnected_sidecars,
                    deletes: &promoted_sidecar_deletes,
                },
            )?;
        self.tip_hash = new_tip_hash;
        self.tip_height = new_tip_header.height;
        self.tip_difficulty = new_tip_header.total_difficulty;
        *current_usdom_state = branch_state;
        self.checkpoint_floor = promoted_checkpoint;
        prune_retained_side_chains(&self.store, self.tip_height, *self.tip_hash.as_bytes())?;
        info!(
            "Native USDOM v2 reorg applied: new tip height={}, hash={}, ancestor={}",
            self.tip_height, self.tip_hash, ancestor
        );
        Ok(reorg_delta)
    }

    /// Ingest one candidate-v2 package and its exact execution witnesses under
    /// the ratified migration schedule. This is the single fork-choice entry:
    /// direct extensions commit atomically, weaker branches are retained, and
    /// a better retained tip is fully replayed before an atomic reorganization.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn ingest_usdom_v2_package_for_schedule(
        &mut self,
        package_bytes: &[u8],
        witness_bundle: &crate::UsdomV2ExecutionWitnesses,
        now: Timestamp,
        current_usdom_state: &mut dom_usdom_state::StateCommitmentV2,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: &dom_usdom_privacy::verifier::SpendVerifier,
        schedule: crate::NativeUsdomV2ActivationSchedule,
    ) -> Result<ConnectResult, DomError> {
        let chain_id = derive_chain_id(self.network_magic, &self.genesis_hash);
        if schedule.network_magic() != self.network_magic || schedule.chain_id() != chain_id {
            return Err(DomError::PolicyRejected(
                "native USDOM v2 package ingress does not match the ratified schedule".into(),
            ));
        }
        let persisted = crate::restore_persisted_usdom_v2_state_for_schedule(
            &self.store,
            self.network_magic,
            self.tip_hash,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifier,
            schedule,
        )?;
        if persisted != *current_usdom_state {
            return Err(DomError::Internal(
                "caller native USDOM v2 state diverges from canonical persistence".into(),
            ));
        }

        let package = crate::UsdomV4BlockPackage::from_bytes(package_bytes)?;
        let block = package.block();
        let header_bytes = block.header.to_bytes()?;
        let block_hash = compute_block_identifier(self.network_magic, &header_bytes)?;
        let known = self
            .store
            .get_block_header(block_hash.as_bytes())?
            .is_some();
        if known {
            let stored_package = crate::load_persisted_usdom_v4_package(
                &self.store,
                self.network_magic,
                block_hash,
            )?
            .ok_or_else(|| {
                DomError::Internal("known native USDOM v2 block package is missing".into())
            })?;
            let stored_witnesses =
                crate::load_persisted_usdom_v2_execution_witnesses(&self.store, block_hash)?
                    .ok_or_else(|| {
                        DomError::Internal(
                            "known native USDOM v2 block witnesses are missing".into(),
                        )
                    })?;
            if stored_package != package_bytes
                || stored_witnesses.to_bytes()? != witness_bundle.to_bytes()?
            {
                return Err(DomError::Internal(
                    "known native USDOM v2 recovery bytes changed".into(),
                ));
            }
            if self.store.get_hash_at_height(block.header.height.0)? == Some(*block_hash.as_bytes())
            {
                return Ok(ConnectResult::AlreadyHave);
            }
        }

        if !known && block.header.prev_hash == self.tip_hash {
            return self.connect_usdom_v2_package_for_schedule(
                package_bytes,
                witness_bundle,
                now,
                current_usdom_state,
                bridge,
                checkpoint_policy,
                deposit_policy,
                closure_policy,
                spend_verifier,
                schedule,
            );
        }
        if !known {
            self.store_usdom_v2_side_package_for_schedule(
                package_bytes,
                witness_bundle,
                now,
                current_usdom_state,
                bridge,
                checkpoint_policy,
                deposit_policy,
                closure_policy,
                spend_verifier,
                schedule,
            )?;
        }
        if is_better_fork_choice_tip(
            block.header.total_difficulty,
            block_hash,
            self.tip_difficulty,
            self.tip_hash,
        ) {
            let reorg = self.promote_usdom_v2_known_tip_for_schedule(
                block_hash,
                now,
                current_usdom_state,
                bridge,
                checkpoint_policy,
                deposit_policy,
                closure_policy,
                spend_verifier,
                schedule,
            )?;
            return Ok(ConnectResult::Reorg(reorg));
        }
        if known {
            Ok(ConnectResult::AlreadyHave)
        } else {
            Ok(ConnectResult::SideChain)
        }
    }

    /// Single Regtest ingress for a canonical native-v4 package. It performs
    /// exact duplicate detection, routes direct extensions through the atomic
    /// connect path, retains side branches, and promotes a side tip only when
    /// the ordinary DOM fork-choice rule selects it.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn ingest_usdom_v4_package_regtest(
        &mut self,
        package_bytes: &[u8],
        now: Timestamp,
        current_usdom_state: &mut dom_usdom_state::NativeUsdomState,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: Option<&dom_usdom_privacy::verifier::SpendVerifier>,
    ) -> Result<ConnectResult, DomError> {
        if self.network_magic != dom_core::NETWORK_MAGIC_REGTEST {
            return Err(DomError::PolicyRejected(
                "native USDOM package ingress is available only on explicit Regtest".into(),
            ));
        }
        let schedule = crate::native_usdom_v4_regtest_activation_schedule(bridge)?;
        self.ingest_usdom_v4_package_for_schedule_inner(
            package_bytes,
            now,
            current_usdom_state,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifier,
            schedule,
        )
    }

    /// Ingest one canonical native-v4 package under an exact activation
    /// schedule, retaining or promoting side branches through the same
    /// schedule and bridge-committed proof verifier.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn ingest_usdom_v4_package_for_schedule(
        &mut self,
        package_bytes: &[u8],
        now: Timestamp,
        current_usdom_state: &mut dom_usdom_state::NativeUsdomState,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: &dom_usdom_privacy::verifier::SpendVerifier,
        schedule: crate::NativeUsdomV4ActivationSchedule,
    ) -> Result<ConnectResult, DomError> {
        self.ingest_usdom_v4_package_for_schedule_inner(
            package_bytes,
            now,
            current_usdom_state,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            Some(spend_verifier),
            schedule,
        )
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    fn ingest_usdom_v4_package_for_schedule_inner(
        &mut self,
        package_bytes: &[u8],
        now: Timestamp,
        current_usdom_state: &mut dom_usdom_state::NativeUsdomState,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: &usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: &usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            &usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifier: Option<&dom_usdom_privacy::verifier::SpendVerifier>,
        schedule: crate::NativeUsdomV4ActivationSchedule,
    ) -> Result<ConnectResult, DomError> {
        let chain_id = derive_chain_id(self.network_magic, &self.genesis_hash);
        if schedule.network_magic() != self.network_magic || schedule.chain_id() != chain_id {
            return Err(DomError::PolicyRejected(
                "native USDOM package ingress does not match the ratified schedule".into(),
            ));
        }
        if crate::load_persisted_usdom_v2_activation_schedule(&self.store)?.is_some() {
            return Err(DomError::PolicyRejected(
                "native USDOM V1 branch ingress is disabled after candidate-v2 activation".into(),
            ));
        }
        let persisted = crate::restore_persisted_usdom_v4_state_for_schedule(
            &self.store,
            self.network_magic,
            bridge,
            self.tip_hash,
            schedule,
        )?;
        if persisted.state_root() != current_usdom_state.state_root()
            || persisted.export_entries() != current_usdom_state.export_entries()
        {
            return Err(DomError::Internal(
                "caller native USDOM state diverges from canonical persistence".into(),
            ));
        }
        let package = crate::UsdomV4BlockPackage::from_bytes(package_bytes)?;
        let block = package.block();
        let header_bytes = block.header.to_bytes()?;
        let block_hash = compute_block_identifier(self.network_magic, &header_bytes)?;
        let known = self
            .store
            .get_block_header(block_hash.as_bytes())?
            .is_some();
        if known {
            let persisted = crate::load_persisted_usdom_v4_package(
                &self.store,
                self.network_magic,
                block_hash,
            )?
            .ok_or_else(|| {
                DomError::Internal("known native USDOM block package is missing".into())
            })?;
            if persisted != package_bytes {
                return Err(DomError::Internal(
                    "known native USDOM package bytes changed".into(),
                ));
            }
            if self.store.get_hash_at_height(block.header.height.0)? == Some(*block_hash.as_bytes())
            {
                return Ok(ConnectResult::AlreadyHave);
            }
        }

        if block.header.prev_hash == self.tip_hash {
            return self
                .connect_usdom_v4_package_for_schedule_inner(
                    package_bytes,
                    now,
                    current_usdom_state,
                    bridge,
                    checkpoint_policy,
                    deposit_policy,
                    closure_policy,
                    spend_verifier,
                    schedule,
                    None,
                )
                .map(|(outcome, _)| outcome);
        }
        if !known {
            self.store_usdom_v4_side_package_for_schedule_inner(
                package_bytes,
                now,
                current_usdom_state,
                bridge,
                checkpoint_policy,
                deposit_policy,
                closure_policy,
                spend_verifier,
                schedule,
            )?;
        }
        if is_better_fork_choice_tip(
            block.header.total_difficulty,
            block_hash,
            self.tip_difficulty,
            self.tip_hash,
        ) {
            let reorg = self.promote_usdom_v4_known_tip_for_schedule_inner(
                block_hash,
                now,
                current_usdom_state,
                bridge,
                checkpoint_policy,
                deposit_policy,
                closure_policy,
                spend_verifier,
                schedule,
            )?;
            return Ok(ConnectResult::Reorg(reorg));
        }
        if known {
            Ok(ConnectResult::AlreadyHave)
        } else {
            Ok(ConnectResult::SideChain)
        }
    }

    /// Validate an inbound IBD header batch before requesting any block bodies.
    ///
    /// This is a non-mutating prefilter for the live headers-first path:
    /// every header must decode, link contiguously within the batch, attach to
    /// a known parent (or genesis), and satisfy the same header-only consensus
    /// rules `connect_block` will later enforce once the full block body arrives.
    ///
    /// Returns only the hashes we do not already know, preserving duplicate
    /// suppression while ensuring malformed or discontinuous batches are rejected
    /// before they can trigger body downloads.
    pub fn validate_ibd_headers_batch(
        &self,
        raw_headers: &[Vec<u8>],
        now: Timestamp,
    ) -> Result<Vec<[u8; 32]>, DomError> {
        self.validate_ibd_headers_batch_with_mode(raw_headers, now, IbdHeaderMode::Ordinary)
    }

    /// Validate a fresh IBD header batch under the reserved Regtest-only
    /// native-USDOM v4 syntax. Keeping this as one bounded batch preserves the
    /// normal IBD path's linear validation and single persisted transition.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn validate_native_usdom_v4_ibd_headers_batch_regtest(
        &self,
        raw_headers: &[Vec<u8>],
        now: Timestamp,
    ) -> Result<Vec<[u8; 32]>, DomError> {
        if self.network_magic != dom_core::NETWORK_MAGIC_REGTEST {
            return Err(DomError::PolicyRejected(
                "native USDOM v4 IBD headers are available only on explicit Regtest".into(),
            ));
        }
        let schedule = crate::native_usdom_v4::persisted_usdom_v4_activation_schedule(&self.store)?;
        if schedule.network_magic() != dom_core::NETWORK_MAGIC_REGTEST {
            return Err(DomError::PolicyRejected(
                "persisted native USDOM activation schedule is not Regtest".into(),
            ));
        }
        self.require_native_usdom_v4_ibd_schedule(schedule)?;
        self.validate_ibd_headers_batch_with_mode(
            raw_headers,
            now,
            IbdHeaderMode::NativeUsdomV4 {
                first_v4_height: schedule.first_v4_height(),
            },
        )
    }

    /// Validate a fresh native-v4 IBD header batch against the exact schedule
    /// atomically installed in this canonical database.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn validate_native_usdom_v4_ibd_headers_batch_for_schedule(
        &self,
        raw_headers: &[Vec<u8>],
        now: Timestamp,
        schedule: crate::NativeUsdomV4ActivationSchedule,
    ) -> Result<Vec<[u8; 32]>, DomError> {
        self.require_native_usdom_v4_ibd_schedule(schedule)?;
        self.validate_ibd_headers_batch_with_mode(
            raw_headers,
            now,
            IbdHeaderMode::NativeUsdomV4 {
                first_v4_height: schedule.first_v4_height(),
            },
        )
    }

    /// Validate candidate-V2 IBD headers only after the exact migration
    /// schedule has been atomically persisted in this database.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn validate_native_usdom_v2_ibd_headers_batch_for_schedule(
        &self,
        raw_headers: &[Vec<u8>],
        now: Timestamp,
        schedule: crate::NativeUsdomV2ActivationSchedule,
    ) -> Result<Vec<[u8; 32]>, DomError> {
        self.require_native_usdom_v2_ibd_schedule(schedule)?;
        self.validate_ibd_headers_batch_with_mode(
            raw_headers,
            now,
            IbdHeaderMode::NativeUsdomV2 {
                first_v2_height: schedule.first_v2_height(),
            },
        )
    }

    fn validate_ibd_headers_batch_with_mode(
        &self,
        raw_headers: &[Vec<u8>],
        now: Timestamp,
        mode: IbdHeaderMode,
    ) -> Result<Vec<[u8; 32]>, DomError> {
        #[cfg(feature = "ethereum-checkpoint-poc")]
        self.ensure_checkpoint_floor_readonly()?;
        let mut decoded = Vec::with_capacity(raw_headers.len());
        for header_bytes in raw_headers {
            let header = BlockHeader::from_bytes(header_bytes)?;
            let hash = compute_block_identifier(self.network_magic, header_bytes)?;
            let is_known = self.store.get_block_header(hash.as_bytes())?.is_some();
            decoded.push((header, hash, is_known));
        }

        let mut missing_hashes = Vec::with_capacity(decoded.len());
        let mut prior_headers: Vec<BlockHeader> = Vec::with_capacity(decoded.len());

        for (idx, (header, hash, is_known)) in decoded.iter().enumerate() {
            if idx == 0 {
                if header.height != BlockHeight::GENESIS
                    && self
                        .store
                        .get_block_header(header.prev_hash.as_bytes())?
                        .is_none()
                {
                    return Err(DomError::Orphan(format!(
                        "IBD header batch starts at unknown parent {}",
                        header.prev_hash
                    )));
                }
            } else {
                let (prev_header, prev_hash, _) = &decoded[idx - 1];
                let expected_height = prev_header
                    .height
                    .checked_next()
                    .ok_or_else(|| DomError::Invalid("block height overflow".into()))?;
                if header.height != expected_height {
                    return Err(DomError::Invalid(format!(
                        "IBD header gap: expected height {expected_height}, got {}",
                        header.height
                    )));
                }
                if header.prev_hash != *prev_hash {
                    return Err(DomError::Invalid(format!(
                        "IBD header prev_hash mismatch at height {}: expected {}, got {}",
                        header.height, prev_hash, header.prev_hash
                    )));
                }
            }

            if !is_known {
                if let Some(first_native_height) = mode.native_first_height() {
                    if header.height.0 < first_native_height {
                        return Err(DomError::PolicyRejected(
                            "native USDOM IBD header predates the selected activation height"
                                .into(),
                        ));
                    }
                    dom_consensus::block::validate_header_syntax_v4_scheduled(
                        header,
                        self.network_magic,
                    )?;
                } else {
                    #[cfg(feature = "native-usdom-v4-poc")]
                    self.reject_ordinary_block_after_native_usdom_v4_activation()?;
                    validate_header_syntax(header, self.network_magic)?;
                }
                self.validate_genesis_identity(header, *hash)?;

                if header.height != BlockHeight::GENESIS {
                    let parent = if idx == 0 {
                        let parent_bytes = self
                            .store
                            .get_block_header(header.prev_hash.as_bytes())?
                            .ok_or_else(|| {
                                DomError::Internal(
                                    "parent missing after IBD parent precheck".into(),
                                )
                            })?;
                        BlockHeader::from_bytes(&parent_bytes)?
                    } else {
                        decoded[idx - 1].0.clone()
                    };
                    validate_parent_timestamp_progression(header, &parent)?;
                    let ancestors =
                        self.collect_ibd_ancestor_timestamps(header.height.0, &prior_headers, 11)?;
                    validate_median_time_past(header, &ancestors)?;
                }

                validate_future_timestamp_with_limit(header, now, self.max_future_block_time())?;
                let seed = self.compute_randomx_seed_with_batch(header.height.0, &decoded)?;
                validate_pow_for_network(self.network_magic, header, &seed)?;

                if let Some(parent_header) =
                    self.batch_parent_for_index(&decoded, idx, &prior_headers)?
                {
                    self.validate_expected_target(header, &parent_header)?;
                }

                let parent_difficulty = if header.height == BlockHeight::GENESIS {
                    U256::zero()
                } else if idx == 0 {
                    let parent_bytes = self
                        .store
                        .get_block_header(header.prev_hash.as_bytes())?
                        .ok_or_else(|| {
                            DomError::Internal("parent missing after IBD parent precheck".into())
                        })?;
                    BlockHeader::from_bytes(&parent_bytes)?.total_difficulty
                } else {
                    decoded[idx - 1].0.total_difficulty
                };

                let block_diff = target_to_difficulty_for_network_height(
                    self.network_magic,
                    header.height,
                    &header
                        .target
                        .to_target()
                        .map_err(|e| DomError::Invalid(format!("invalid target: {e}")))?,
                );
                let expected_total =
                    checked_accumulated_difficulty(parent_difficulty, block_diff?)?;
                if header.total_difficulty != expected_total {
                    return Err(DomError::Invalid(format!(
                        "total_difficulty mismatch: expected {expected_total}, got {}",
                        header.total_difficulty
                    )));
                }

                missing_hashes.push(*hash.as_bytes());
            }

            prior_headers.push(header.clone());
        }

        Ok(missing_hashes)
    }

    /// Validate exactly one persisted IBD header step without re-validating the
    /// previously verified prefix.
    ///
    /// `verified_header_count` is the number of headers in `raw_headers` whose
    /// ordering and consensus checks have already completed and whose resulting
    /// missing-block hashes are recorded in `prior_missing_hashes`.
    ///
    /// This method re-decodes the ordered prefix only to confirm that the
    /// persisted queue still matches the saved deterministic checkpoint. It
    /// then applies the full header-only consensus checks to the next header at
    /// `verified_header_count`, returning the updated missing-block queue and
    /// the validated header height.
    pub fn validate_ibd_header_step(
        &self,
        raw_headers: &[Vec<u8>],
        verified_header_count: usize,
        prior_missing_hashes: &[[u8; 32]],
        now: Timestamp,
    ) -> Result<(u64, Vec<[u8; 32]>), DomError> {
        self.validate_ibd_header_step_with_mode(
            raw_headers,
            verified_header_count,
            prior_missing_hashes,
            now,
            IbdHeaderMode::Ordinary,
        )
    }

    /// Validate one persisted IBD header under the reserved Regtest-only
    /// native-USDOM v4 syntax. Full package validation remains mandatory when
    /// the body is fetched; this method only authenticates header continuity,
    /// timing, target, accumulated work and PoW for an already negotiated
    /// native runtime.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn validate_native_usdom_v4_ibd_header_step_regtest(
        &self,
        raw_headers: &[Vec<u8>],
        verified_header_count: usize,
        prior_missing_hashes: &[[u8; 32]],
        now: Timestamp,
    ) -> Result<(u64, Vec<[u8; 32]>), DomError> {
        if self.network_magic != dom_core::NETWORK_MAGIC_REGTEST {
            return Err(DomError::PolicyRejected(
                "native USDOM v4 IBD headers are available only on explicit Regtest".into(),
            ));
        }
        let schedule = crate::native_usdom_v4::persisted_usdom_v4_activation_schedule(&self.store)?;
        if schedule.network_magic() != dom_core::NETWORK_MAGIC_REGTEST {
            return Err(DomError::PolicyRejected(
                "persisted native USDOM activation schedule is not Regtest".into(),
            ));
        }
        self.require_native_usdom_v4_ibd_schedule(schedule)?;
        self.validate_ibd_header_step_with_mode(
            raw_headers,
            verified_header_count,
            prior_missing_hashes,
            now,
            IbdHeaderMode::NativeUsdomV4 {
                first_v4_height: schedule.first_v4_height(),
            },
        )
    }

    /// Validate one resumed native-v4 IBD header under the exact schedule
    /// installed in this canonical database.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn validate_native_usdom_v4_ibd_header_step_for_schedule(
        &self,
        raw_headers: &[Vec<u8>],
        verified_header_count: usize,
        prior_missing_hashes: &[[u8; 32]],
        now: Timestamp,
        schedule: crate::NativeUsdomV4ActivationSchedule,
    ) -> Result<(u64, Vec<[u8; 32]>), DomError> {
        self.require_native_usdom_v4_ibd_schedule(schedule)?;
        self.validate_ibd_header_step_with_mode(
            raw_headers,
            verified_header_count,
            prior_missing_hashes,
            now,
            IbdHeaderMode::NativeUsdomV4 {
                first_v4_height: schedule.first_v4_height(),
            },
        )
    }

    /// Resume one candidate-V2 IBD header cursor under the exact persisted
    /// migration schedule.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn validate_native_usdom_v2_ibd_header_step_for_schedule(
        &self,
        raw_headers: &[Vec<u8>],
        verified_header_count: usize,
        prior_missing_hashes: &[[u8; 32]],
        now: Timestamp,
        schedule: crate::NativeUsdomV2ActivationSchedule,
    ) -> Result<(u64, Vec<[u8; 32]>), DomError> {
        self.require_native_usdom_v2_ibd_schedule(schedule)?;
        self.validate_ibd_header_step_with_mode(
            raw_headers,
            verified_header_count,
            prior_missing_hashes,
            now,
            IbdHeaderMode::NativeUsdomV2 {
                first_v2_height: schedule.first_v2_height(),
            },
        )
    }

    fn validate_ibd_header_step_with_mode(
        &self,
        raw_headers: &[Vec<u8>],
        verified_header_count: usize,
        prior_missing_hashes: &[[u8; 32]],
        now: Timestamp,
        mode: IbdHeaderMode,
    ) -> Result<(u64, Vec<[u8; 32]>), DomError> {
        #[cfg(feature = "ethereum-checkpoint-poc")]
        self.ensure_checkpoint_floor_readonly()?;
        if verified_header_count >= raw_headers.len() {
            return Err(DomError::PolicyRejected(format!(
                "persisted header cursor {} exceeds pending header count {}",
                verified_header_count,
                raw_headers.len()
            )));
        }

        let mut decoded_prefix: Vec<(BlockHeader, Hash256, bool)> =
            Vec::with_capacity(verified_header_count.saturating_add(1));
        let mut observed_missing = Vec::with_capacity(prior_missing_hashes.len().saturating_add(1));

        for (idx, header_bytes) in raw_headers
            .iter()
            .take(verified_header_count.saturating_add(1))
            .enumerate()
        {
            let header = BlockHeader::from_bytes(header_bytes)?;
            let hash = compute_block_identifier(self.network_magic, header_bytes)?;
            let is_known = self.store.get_block_header(hash.as_bytes())?.is_some();

            if idx == 0 {
                if header.height != BlockHeight::GENESIS
                    && self
                        .store
                        .get_block_header(header.prev_hash.as_bytes())?
                        .is_none()
                {
                    return Err(DomError::Orphan(format!(
                        "IBD header batch starts at unknown parent {}",
                        header.prev_hash
                    )));
                }
            } else {
                let (prev_header, prev_hash, _) = &decoded_prefix[idx - 1];
                let expected_height = prev_header
                    .height
                    .checked_next()
                    .ok_or_else(|| DomError::Invalid("block height overflow".into()))?;
                if header.height != expected_height {
                    return Err(DomError::Invalid(format!(
                        "IBD header gap: expected height {expected_height}, got {}",
                        header.height
                    )));
                }
                if header.prev_hash != *prev_hash {
                    return Err(DomError::Invalid(format!(
                        "IBD header prev_hash mismatch at height {}: expected {}, got {}",
                        header.height, prev_hash, header.prev_hash
                    )));
                }
            }

            if idx < verified_header_count {
                if !is_known {
                    observed_missing.push(*hash.as_bytes());
                }
                decoded_prefix.push((header, hash, is_known));
                continue;
            }

            if !is_known && matches!(mode, IbdHeaderMode::Ordinary) {
                #[cfg(feature = "native-usdom-v4-poc")]
                self.reject_ordinary_block_after_native_usdom_v4_activation()?;
            }

            // A persisted missing-block queue is a checkpoint, not an immutable
            // consensus fact. Between checkpoint and resume another accepted
            // path (or an earlier body from the same resumed page) may have
            // stored one of those blocks. Reconcile only entries that are still
            // missing before comparing the deterministic prefix. This preserves
            // strict order/hash checking while accepting the legitimate
            // `observed N-1, expected N` transition.
            let mut still_missing = Vec::with_capacity(prior_missing_hashes.len());
            for hash in prior_missing_hashes {
                if self.store.get_block_header(hash)?.is_none() {
                    still_missing.push(*hash);
                }
            }
            if still_missing.len() != prior_missing_hashes.len() {
                debug!(
                    "reconciled {} now-known hashes from persisted IBD header prefix",
                    prior_missing_hashes.len() - still_missing.len()
                );
            }
            if observed_missing != still_missing {
                return Err(DomError::PolicyRejected(format!(
                    "persisted IBD header prefix mismatch: observed {} missing hashes, expected {}",
                    observed_missing.len(),
                    still_missing.len()
                )));
            }

            if !is_known {
                if let Some(first_native_height) = mode.native_first_height() {
                    if header.height.0 < first_native_height {
                        return Err(DomError::PolicyRejected(
                            "native USDOM IBD header predates the selected activation height"
                                .into(),
                        ));
                    }
                    dom_consensus::block::validate_header_syntax_v4_scheduled(
                        &header,
                        self.network_magic,
                    )?;
                } else {
                    validate_header_syntax(&header, self.network_magic)?;
                }
                self.validate_genesis_identity(&header, hash)?;

                if header.height != BlockHeight::GENESIS {
                    let parent = if decoded_prefix.is_empty() {
                        let parent_bytes = self
                            .store
                            .get_block_header(header.prev_hash.as_bytes())?
                            .ok_or_else(|| {
                                DomError::Internal(
                                    "parent missing after IBD parent precheck".into(),
                                )
                            })?;
                        BlockHeader::from_bytes(&parent_bytes)?
                    } else {
                        decoded_prefix
                            .last()
                            .ok_or_else(|| {
                                DomError::Internal(
                                    "decoded IBD prefix disappeared during parent lookup".into(),
                                )
                            })?
                            .0
                            .clone()
                    };
                    validate_parent_timestamp_progression(&header, &parent)?;
                    let prior_headers: Vec<BlockHeader> = decoded_prefix
                        .iter()
                        .map(|(prior_header, _, _)| prior_header.clone())
                        .collect();
                    let ancestors =
                        self.collect_ibd_ancestor_timestamps(header.height.0, &prior_headers, 11)?;
                    validate_median_time_past(&header, &ancestors)?;
                }

                validate_future_timestamp_with_limit(&header, now, self.max_future_block_time())?;
                let seed =
                    self.compute_randomx_seed_with_batch(header.height.0, &decoded_prefix)?;
                validate_pow_for_network(self.network_magic, &header, &seed)?;

                if let Some(parent_header) =
                    self.batch_parent_for_decoded_prefix(&header, &decoded_prefix)?
                {
                    self.validate_expected_target(&header, &parent_header)?;
                }

                let parent_difficulty = if header.height == BlockHeight::GENESIS {
                    U256::zero()
                } else if decoded_prefix.is_empty() {
                    let parent_bytes = self
                        .store
                        .get_block_header(header.prev_hash.as_bytes())?
                        .ok_or_else(|| {
                            DomError::Internal("parent missing after IBD parent precheck".into())
                        })?;
                    BlockHeader::from_bytes(&parent_bytes)?.total_difficulty
                } else {
                    decoded_prefix
                        .last()
                        .ok_or_else(|| {
                            DomError::Internal(
                                "decoded IBD prefix disappeared during difficulty lookup".into(),
                            )
                        })?
                        .0
                        .total_difficulty
                };

                let block_diff = target_to_difficulty_for_network_height(
                    self.network_magic,
                    header.height,
                    &header
                        .target
                        .to_target()
                        .map_err(|e| DomError::Invalid(format!("invalid target: {e}")))?,
                );
                let expected_total =
                    checked_accumulated_difficulty(parent_difficulty, block_diff?)?;
                if header.total_difficulty != expected_total {
                    return Err(DomError::Invalid(format!(
                        "total_difficulty mismatch: expected {expected_total}, got {}",
                        header.total_difficulty
                    )));
                }

                observed_missing.push(*hash.as_bytes());
            }

            return Ok((header.height.0, observed_missing));
        }

        Err(DomError::Internal(
            "IBD header step finished without validating a header".into(),
        ))
    }

    pub fn validate_header_only(
        &self,
        header: &BlockHeader,
        now: Timestamp,
    ) -> Result<(), DomError> {
        #[cfg(feature = "ethereum-checkpoint-poc")]
        self.ensure_checkpoint_floor_readonly()?;
        // DOM-IBD-DUP-001 defense: short-circuit if we already have this header.
        // Avoids re-running RandomX (expensive ~10ms) for known-good headers.
        // Currently this function has no production callers (verified via grep),
        // but the early-return is added as defense-in-depth for any future
        // IBD/sync codepath that adopts header-first validation.
        let header_bytes = header.to_bytes()?;
        let header_hash = compute_block_identifier(self.network_magic, &header_bytes)?;
        if self
            .store
            .get_block_header(header_hash.as_bytes())?
            .is_some()
        {
            return Ok(());
        }

        #[cfg(feature = "native-usdom-v4-poc")]
        self.reject_ordinary_block_after_native_usdom_v4_activation()?;

        validate_header_syntax(header, self.network_magic)?;
        self.validate_genesis_identity(header, header_hash)?;
        validate_future_timestamp_with_limit(header, now, self.max_future_block_time())?;
        if header.height != BlockHeight::GENESIS {
            let parent_bytes = self
                .store
                .get_block_header(header.prev_hash.as_bytes())?
                .ok_or_else(|| {
                    DomError::Orphan(format!("parent {} not found", header.prev_hash))
                })?;
            let parent = BlockHeader::from_bytes(&parent_bytes)?;
            validate_parent_timestamp_progression(header, &parent)?;
            let ancestors = self.get_recent_timestamps(header.prev_hash, 11)?;
            validate_median_time_past(header, &ancestors)?;
            self.validate_expected_target(header, &parent)?;

            let block_diff = target_to_difficulty_for_network_height(
                self.network_magic,
                header.height,
                &header
                    .target
                    .to_target()
                    .map_err(|e| DomError::Invalid(format!("invalid target: {e}")))?,
            );
            let expected_total =
                checked_accumulated_difficulty(parent.total_difficulty, block_diff?)?;
            if header.total_difficulty != expected_total {
                return Err(DomError::Invalid(format!(
                    "total_difficulty mismatch: expected {expected_total}, got {}",
                    header.total_difficulty
                )));
            }
        }
        let seed = self.compute_randomx_seed_branch_aware(header.height.0, header.prev_hash)?;
        validate_pow_for_network(self.network_magic, header, &seed)?;
        Ok(())
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    fn require_native_usdom_v4_ibd_schedule(
        &self,
        schedule: crate::NativeUsdomV4ActivationSchedule,
    ) -> Result<(), DomError> {
        let chain_id = derive_chain_id(self.network_magic, &self.genesis_hash);
        if schedule.network_magic() != self.network_magic || schedule.chain_id() != chain_id {
            return Err(DomError::PolicyRejected(
                "native USDOM v4 IBD schedule does not match this chain".into(),
            ));
        }
        crate::native_usdom_v4::require_persisted_usdom_v4_activation_for_schedule(
            &self.store,
            self.tip_hash,
            schedule,
        )
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    fn require_native_usdom_v2_ibd_schedule(
        &self,
        schedule: crate::NativeUsdomV2ActivationSchedule,
    ) -> Result<(), DomError> {
        let chain_id = derive_chain_id(self.network_magic, &self.genesis_hash);
        if schedule.network_magic() != self.network_magic || schedule.chain_id() != chain_id {
            return Err(DomError::PolicyRejected(
                "native USDOM V2 IBD schedule does not match this chain".into(),
            ));
        }
        match crate::load_persisted_usdom_v2_activation_schedule(&self.store)? {
            Some(persisted) if persisted == schedule => Ok(()),
            Some(_) => Err(DomError::PolicyRejected(
                "persisted native USDOM V2 IBD schedule differs from the selected schedule".into(),
            )),
            None => Err(DomError::PolicyRejected(
                "native USDOM V2 IBD requires its atomic activation marker".into(),
            )),
        }
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    fn reject_ordinary_block_after_native_usdom_v4_activation(&self) -> Result<(), DomError> {
        if self.native_usdom_v4_activation_initialized()? {
            return Err(DomError::PolicyRejected(
                "ordinary block ingress is disabled after native USDOM v4 activation; an exact authenticated v4 package is required"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Return whether native USDOM has been atomically initialized. Before V2,
    /// the V1 marker must follow the canonical tip. After V2 activation the V1
    /// marker intentionally remains pinned to the migration parent; the V2
    /// marker is parsed here and fully authenticated by V2 runtime restore.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn native_usdom_v4_activation_initialized(&self) -> Result<bool, DomError> {
        if crate::load_persisted_usdom_v2_activation_schedule(&self.store)?.is_some() {
            return Ok(true);
        }
        let Some(native_tip) = crate::native_usdom_v4::native_usdom_v4_activation_tip(&self.store)?
        else {
            return Ok(false);
        };
        if native_tip != self.tip_hash {
            return Err(DomError::Internal(
                "persisted native USDOM tip does not match the canonical chain tip".into(),
            ));
        }
        Ok(true)
    }

    fn validate_genesis_identity(
        &self,
        header: &BlockHeader,
        header_hash: Hash256,
    ) -> Result<(), DomError> {
        if header.height != BlockHeight::GENESIS {
            return Ok(());
        }

        if self.network_magic == dom_core::NETWORK_MAGIC_MAINNET {
            return Err(DomError::Invalid(
                "Mainnet genesis is accepted only through the canonical identity-envelope bootstrap path"
                    .into(),
            ));
        }

        if self.genesis_hash != Hash256::ZERO && header_hash != self.genesis_hash {
            return Err(DomError::Invalid(format!(
                "genesis hash mismatch: expected {}, got {}",
                self.genesis_hash, header_hash
            )));
        }

        if let Some(existing) = self.store.get_hash_at_height(BlockHeight::GENESIS.0)? {
            if existing != *header_hash.as_bytes() {
                return Err(DomError::Invalid(format!(
                    "alternate genesis block rejected: canonical genesis already exists as {}",
                    hex::encode(existing)
                )));
            }
        }

        Ok(())
    }

    /// Require the exact frozen legacy genesis body whenever this chain is
    /// configured with a production network identity. Synthetic tests that use
    /// an explicitly zero or non-production genesis hash retain their local
    /// fixture behavior.
    fn validate_genesis_body_identity(&self, block: &Block) -> Result<(), DomError> {
        if block.header.height != BlockHeight::GENESIS
            || self.network_magic == dom_core::NETWORK_MAGIC_MAINNET
        {
            return Ok(());
        }

        let configured = dom_core::configured_genesis_hash_for_network_magic(self.network_magic)?;
        if self.genesis_hash != configured {
            return Ok(());
        }

        let chain_id = derive_chain_id(self.network_magic, &configured);
        let canonical = crate::build_canonical_genesis(self.network_magic, chain_id.as_bytes())?;
        let actual = block.to_bytes()?;
        if actual != canonical.block_bytes {
            return Err(DomError::Invalid(
                "genesis body mismatch: configured network requires the exact frozen canonical body"
                    .into(),
            ));
        }
        Ok(())
    }

    fn max_future_block_time(&self) -> u64 {
        if self.network_magic == dom_core::NETWORK_MAGIC_TESTNET {
            dom_core::TESTNET_MAX_FUTURE_BLOCK_TIME
        } else {
            dom_core::MAX_FUTURE_BLOCK_TIME
        }
    }

    pub fn next_block_target(&self) -> Result<ExpectedTarget, DomError> {
        #[cfg(feature = "ethereum-checkpoint-poc")]
        self.ensure_checkpoint_floor_readonly()?;
        if self.tip_hash == Hash256::ZERO && self.tip_height == BlockHeight::GENESIS {
            let target = compute_expected_target(
                self.network_magic,
                self.asert_anchor.timestamp,
                BlockHeight::GENESIS,
            )?;
            return Ok(ExpectedTarget {
                previous_target: target,
                next_target: target,
                height_delta: 0,
                actual_elapsed_secs: 0,
                expected_elapsed_secs: 0,
            });
        }

        let tip_bytes = self
            .store
            .get_block_header(self.tip_hash.as_bytes())?
            .ok_or_else(|| DomError::Internal("chain tip header missing".into()))?;
        let tip = BlockHeader::from_bytes(&tip_bytes)?;
        let next_height = tip
            .height
            .checked_next()
            .ok_or_else(|| DomError::Invalid("block height overflow".into()))?;
        let params = pow_params_for_network_at_height(self.network_magic, next_height)?;
        let next_timestamp = tip
            .timestamp
            .checked_add_secs(params.target_spacing)
            .ok_or_else(|| DomError::Invalid("next block timestamp overflow".into()))?;
        self.expected_target_for_child(&tip, next_timestamp, next_height)
    }

    /// Compute the RandomX seed for a block at `height`, consulting the
    /// committed store only.
    ///
    /// Seed = hash of block at `randomx_seed_height(height)`. Used by the
    /// non-IBD paths (`connect_block`, `validate_header_only`) where the chain
    /// up to the parent is already fully committed, so the seed block is always
    /// present in the height index.
    ///
    /// Epoch 0 (`seed_height == 0`): genesis is used as the seed by convention
    /// (RFC-0011); the `[0u8; 32]` fallback covers the narrow bootstrap window
    /// before genesis is indexed. For epoch > 0 a missing seed block means the
    /// committed store is corrupt — surface it as an error rather than silently
    /// hashing against a zero seed, which would reject an otherwise valid block.
    fn compute_randomx_seed(&self, height: u64) -> Result<[u8; 32], DomError> {
        let seed_height = randomx_seed_height(height);
        match self.store.get_hash_at_height(seed_height)? {
            Some(hash) => {
                let header_bytes = self.store.get_block_header(&hash)?.ok_or_else(|| {
                    DomError::Internal(format!(
                        "RandomX seed height {seed_height} points to missing header {}",
                        hex::encode(hash)
                    ))
                })?;
                let header = BlockHeader::from_bytes(&header_bytes).map_err(|error| {
                    DomError::Internal(format!(
                        "RandomX seed header at height {seed_height} is malformed: {error}"
                    ))
                })?;
                if header.height.0 != seed_height {
                    return Err(DomError::Internal(format!(
                        "RandomX seed height index mismatch: key {seed_height}, header {}",
                        header.height.0
                    )));
                }
                Ok(hash)
            }
            None if seed_height == 0 => Ok([0u8; 32]),
            None => Err(DomError::Internal(format!(
                "RandomX seed block at height {seed_height} missing from \
                 committed store (needed for block at height {height})"
            ))),
        }
    }

    /// Resolve the RandomX seed for a block at `height` whose parent is
    /// `parent_hash`, using the block's OWN branch history (A2-004).
    ///
    /// Decided rule (RFC-0011): the seed is the block hash at
    /// `randomx_seed_height(height)` on the block's own branch, not on whatever
    /// chain is currently canonical. `compute_randomx_seed` (canonical index) is
    /// correct only when the block extends the canonical chain; for a side-branch
    /// block validated during a reorg that crosses an epoch boundary, the
    /// canonical index can point at a different seed block, splitting consensus.
    ///
    /// Efficient in the common case: walks the parent chain backward only until
    /// it reaches a block already on the canonical chain (shared prefix), then
    /// defers to the canonical index. For a block that extends the canonical tip
    /// this returns on the first iteration and is byte-identical to
    /// `compute_randomx_seed`.
    fn compute_randomx_seed_branch_aware(
        &self,
        height: u64,
        parent_hash: Hash256,
    ) -> Result<[u8; 32], DomError> {
        let seed_height = randomx_seed_height(height);

        // Case 4 - epoch 0: the seed block is the genesis (or the zero fallback
        // before genesis is indexed). All branches share the genesis, so
        // branch-awareness adds nothing at epoch 0; defer to the canonical
        // resolver, which returns the genesis hash when indexed and the zero
        // fallback otherwise — exactly matching pre-fix behaviour. The offset
        // guarantees seed_height < height for epoch > 0, so for those epochs the
        // seed block always lies in the parent's history; it is never the block
        // itself.
        if seed_height == 0 {
            return self.compute_randomx_seed(height);
        }

        let max_walk = dom_core::MAX_REORG_DEPTH_POLICY;
        let mut cursor = parent_hash;
        let mut steps: u64 = 0;

        loop {
            let header_bytes =
                self.store
                    .get_block_header(cursor.as_bytes())?
                    .ok_or_else(|| {
                        DomError::Internal(format!(
                            "randomx seed walk: missing header {}",
                            hex::encode(cursor.as_bytes())
                        ))
                    })?;
            let cursor_header = BlockHeader::from_bytes(&header_bytes)?;
            let cursor_height = cursor_header.height.0;

            // Ramo (a) - shared prefix: if this cursor is the canonical block at
            // its height, all its ancestors are canonical too (the canonical
            // chain is linear). Defer to the canonical index for seed_height.
            // Covers direct extension (case 6) and branches diverging above
            // seed_height (cases 2, 5); byte-identical to the pre-fix result.
            if self.store.get_hash_at_height(cursor_height)? == Some(*cursor.as_bytes()) {
                return self.compute_randomx_seed(height);
            }

            // Ramo (b) - divergent seed block: reached seed_height on the branch
            // itself before hitting canonical. This branch's own block at
            // seed_height is the seed (cases 1, 3).
            if cursor_height == seed_height {
                return Ok(*cursor.as_bytes());
            }

            // Defensive: (a) or (b) must trigger before passing below seed_height.
            if cursor_height < seed_height {
                return Err(DomError::Internal(format!(
                    "randomx seed walk underran seed_height {seed_height} at height {cursor_height}"
                )));
            }

            steps += 1;
            if steps > max_walk {
                // Decision B1: a divergence deeper than the reorg limit is already
                // unpromotable; refuse rather than fall back to the canonical seed.
                return Err(DomError::Invalid(format!(
                    "randomx seed walk exceeded max reorg depth {max_walk} for block at height {height}"
                )));
            }
            cursor = cursor_header.prev_hash;
        }
    }

    /// Compute the RandomX seed for a block at `height` during header-first
    /// IBD, where the seed block may still be inside the in-memory header
    /// batch (not yet committed to the store).
    ///
    /// Resolution order:
    ///   1. the in-memory `batch` of headers being validated (not yet committed),
    ///   2. the committed store (headers from earlier, committed batches),
    ///   3. epoch 0 only: genesis fallback (`[0u8; 32]`).
    ///
    /// For epoch > 0, absence from both the batch and the store is a data bug
    /// and is surfaced as an error instead of silently falling back to a zero
    /// seed (the original cause of the IBD PoW split at the epoch boundary).
    fn compute_randomx_seed_with_batch(
        &self,
        height: u64,
        batch: &[(BlockHeader, Hash256, bool)],
    ) -> Result<[u8; 32], DomError> {
        let seed_height = randomx_seed_height(height);

        // 1. In-memory batch (headers validated but not yet committed).
        if let Some((_, hash, _)) = batch.iter().find(|(h, _, _)| h.height.0 == seed_height) {
            return Ok(*hash.as_bytes());
        }

        // 2. Committed store (headers from earlier batches).
        if self.store.get_hash_at_height(seed_height)?.is_some() {
            return self.compute_randomx_seed(height);
        }

        // 3. Epoch 0: genesis used as seed by convention (RFC-0011).
        if seed_height == 0 {
            return Ok([0u8; 32]);
        }

        Err(DomError::Internal(format!(
            "RandomX seed block at height {seed_height} not available \
             (needed for block at height {height})"
        )))
    }

    fn validate_expected_target(
        &self,
        header: &BlockHeader,
        parent: &BlockHeader,
    ) -> Result<(), DomError> {
        let expected = self.expected_target_for_child(parent, header.timestamp, header.height)?;
        let actual_target = header
            .target
            .to_target()
            .map_err(|e| DomError::Invalid(format!("invalid target: {e}")))?;
        if actual_target != expected.next_target {
            return Err(DomError::Invalid(format!(
                "target mismatch at height {}: expected={} got={} height_delta={} actual_elapsed={} expected_elapsed={}",
                header.height.0,
                hex::encode(expected.next_target),
                hex::encode(actual_target),
                expected.height_delta,
                expected.actual_elapsed_secs,
                expected.expected_elapsed_secs,
            )));
        }
        Ok(())
    }

    fn expected_target_for_child(
        &self,
        parent: &BlockHeader,
        child_timestamp: Timestamp,
        child_height: BlockHeight,
    ) -> Result<ExpectedTarget, DomError> {
        let previous_target = parent
            .target
            .to_target()
            .map_err(|e| DomError::Invalid(format!("invalid target: {e}")))?;
        let next_target =
            compute_expected_target(self.network_magic, child_timestamp, child_height)?;
        let params = pow_params_for_network_at_height(self.network_magic, child_height)?;
        let anchor = asert_anchor_for_network_height(self.network_magic, child_height)?;
        let height_delta = child_height
            .0
            .checked_sub(anchor.height.0)
            .ok_or_else(|| DomError::Invalid("height before ASERT anchor".into()))?;
        let actual_elapsed_secs = child_timestamp
            .0
            .checked_sub(anchor.timestamp.0)
            .ok_or_else(|| DomError::Invalid("timestamp before ASERT anchor".into()))?;
        let expected_elapsed_secs = params
            .target_spacing
            .checked_mul(height_delta)
            .ok_or_else(|| DomError::Invalid("ASERT expected elapsed overflow".into()))?;

        Ok(ExpectedTarget {
            previous_target,
            next_target,
            height_delta,
            actual_elapsed_secs,
            expected_elapsed_secs,
        })
    }

    fn batch_parent_for_index(
        &self,
        decoded: &[(BlockHeader, Hash256, bool)],
        idx: usize,
        prior_headers: &[BlockHeader],
    ) -> Result<Option<BlockHeader>, DomError> {
        if decoded[idx].0.height == BlockHeight::GENESIS {
            return Ok(None);
        }
        if idx > 0 {
            return Ok(Some(decoded[idx - 1].0.clone()));
        }
        let parent_bytes = self
            .store
            .get_block_header(decoded[idx].0.prev_hash.as_bytes())?
            .ok_or_else(|| DomError::Internal("parent missing after IBD parent precheck".into()))?;
        let parent = BlockHeader::from_bytes(&parent_bytes)?;
        let _ = prior_headers;
        Ok(Some(parent))
    }

    fn batch_parent_for_decoded_prefix(
        &self,
        header: &BlockHeader,
        decoded_prefix: &[(BlockHeader, Hash256, bool)],
    ) -> Result<Option<BlockHeader>, DomError> {
        if header.height == BlockHeight::GENESIS {
            return Ok(None);
        }
        if let Some((parent, _, _)) = decoded_prefix.last() {
            return Ok(Some(parent.clone()));
        }
        let parent_bytes = self
            .store
            .get_block_header(header.prev_hash.as_bytes())?
            .ok_or_else(|| DomError::Internal("parent missing after IBD parent precheck".into()))?;
        Ok(Some(BlockHeader::from_bytes(&parent_bytes)?))
    }

    fn collect_ibd_ancestor_timestamps(
        &self,
        current_height: u64,
        prior_headers: &[BlockHeader],
        count: usize,
    ) -> Result<Vec<Timestamp>, DomError> {
        let mut timestamps = Vec::with_capacity(count);

        for header in prior_headers.iter().rev().take(count) {
            timestamps.push(header.timestamp);
        }

        if timestamps.len() == count {
            return Ok(timestamps);
        }

        let mut h = current_height.saturating_sub(prior_headers.len() as u64 + 1);
        loop {
            if let Some(hash) = self.store.get_hash_at_height(h)? {
                if let Some(header_bytes) = self.store.get_block_header(&hash)? {
                    if let Ok(header) = BlockHeader::from_bytes(&header_bytes) {
                        timestamps.push(header.timestamp);
                        if timestamps.len() == count {
                            break;
                        }
                    }
                }
            }
            if h == 0 {
                break;
            }
            h -= 1;
        }

        Ok(timestamps)
    }

    /// Collect the timestamps of the `count` blocks preceding a block whose
    /// parent is `parent_hash`, walking the block's OWN branch (A2-005).
    ///
    /// Mirrors the seed-resolution rule (RFC-0011 §6, applied to MTP): the
    /// median-time-past window is taken from the block's own ancestry, not from
    /// whatever chain is currently canonical. Walks back from the parent via
    /// prev_hash. For a block extending the canonical tip the parent and its
    /// ancestors are canonical, so the collected timestamps are identical to the
    /// previous canonical-index behaviour. For a side-branch block during a
    /// reorg it uses the branch's own ancestors, and always finds a full window
    /// (of length `count`, unless the chain is genuinely shorter) instead of
    /// silently returning a short window that would disable the MTP check.
    fn get_recent_timestamps(
        &self,
        parent_hash: Hash256,
        count: usize,
    ) -> Result<Vec<Timestamp>, DomError> {
        let mut timestamps = Vec::with_capacity(count);
        let mut cursor = parent_hash;

        while timestamps.len() < count {
            // Genesis has prev_hash == ZERO; stop once we walk past the root.
            if cursor == Hash256::ZERO {
                break;
            }
            let header_bytes = match self.store.get_block_header(cursor.as_bytes())? {
                Some(b) => b,
                None => break, // ancestry not fully present (early chain)
            };
            let header = BlockHeader::from_bytes(&header_bytes)?;
            timestamps.push(header.timestamp);
            cursor = header.prev_hash;
        }

        Ok(timestamps)
    }

    pub fn is_synced(&self, best_peer_height: u64) -> bool {
        self.tip_height.0 + 10 >= best_peer_height
    }

    /// Promote a previously-known heavier side-chain tip into the canonical chain.
    ///
    /// The tip and every ancestor block up to the fork point MUST already be
    /// present in the store via `commit_block` or `store_known_block`.
    pub fn promote_heavier_known_tip(
        &mut self,
        new_tip_hash: Hash256,
        now: Timestamp,
    ) -> Result<ReorgDelta, DomError> {
        #[cfg(feature = "ethereum-checkpoint-poc")]
        self.ensure_checkpoint_floor()?;
        let new_tip_header = self
            .store
            .get_block_header(new_tip_hash.as_bytes())?
            .ok_or_else(|| {
                DomError::Internal(format!(
                    "reorg target header missing: {}",
                    hex::encode(new_tip_hash.as_bytes())
                ))
            })
            .and_then(|bytes| BlockHeader::from_bytes(&bytes))?;

        let ancestor = find_common_ancestor(&self.store, self.tip_hash, new_tip_hash)?
            .filter(|h| *h != Hash256::ZERO)
            .ok_or_else(|| DomError::Invalid("heavier side chain has no common ancestor".into()))?;

        let ancestor_height = if ancestor == self.tip_hash {
            self.tip_height.0
        } else {
            let ancestor_bytes = self
                .store
                .get_block_header(ancestor.as_bytes())?
                .ok_or_else(|| {
                    DomError::Internal(format!(
                        "reorg ancestor header missing: {}",
                        hex::encode(ancestor.as_bytes())
                    ))
                })?;
            BlockHeader::from_bytes(&ancestor_bytes)?.height.0
        };

        validate_branch_header_syntax(&self.store, new_tip_hash, ancestor, self.network_magic)?;

        #[cfg(feature = "ethereum-checkpoint-poc")]
        crate::ethereum_checkpoint_poc::check_reorg(
            &self.store,
            self.tip_height.0,
            ancestor_height,
        )?;

        if !is_better_fork_choice_tip(
            new_tip_header.total_difficulty,
            new_tip_hash,
            self.tip_difficulty,
            self.tip_hash,
        ) {
            return Err(DomError::PolicyRejected(format!(
                "reorg target is not heavier or tie-preferred: new_total={} current_total={} new_hash={} current_hash={}",
                new_tip_header.total_difficulty, self.tip_difficulty, new_tip_hash, self.tip_hash
            )));
        }

        let reorg_depth = self
            .tip_height
            .0
            .checked_sub(ancestor_height)
            .ok_or_else(|| DomError::Internal("reorg ancestor is above local tip".into()))?;
        if let Err(error) = check_rolling_finality(self.tip_height.0, reorg_depth) {
            warn!(
                depth = reorg_depth,
                local_tip = %self.tip_hash,
                rejected_tip = %new_tip_hash,
                "rolling finality rejected deep reorg"
            );
            return Err(error);
        }
        check_reorg_depth(reorg_depth)?;
        let disconnect_blocks = collect_branch_blocks(&self.store, self.tip_hash, ancestor)?;
        if disconnect_blocks.len() as u64 != reorg_depth {
            return Err(DomError::Internal(format!(
                "reorg depth mismatch: height-derived={reorg_depth}, collected={}",
                disconnect_blocks.len()
            )));
        }
        let mut connect_blocks = collect_branch_blocks(&self.store, new_tip_hash, ancestor)?;
        connect_blocks.reverse();
        let chain_id = derive_chain_id(self.network_magic, &self.genesis_hash);
        for (block_hash, block) in &connect_blocks {
            validate_future_timestamp_with_limit(&block.header, now, self.max_future_block_time())?;
            let ctx = ValidationContext {
                current_height: block.header.height,
                chain_id: *chain_id.as_bytes(),
                now,
            };
            validate_block_for_network(block, &ctx, self.network_magic).map_err(|e| {
                DomError::Invalid(format!(
                    "reorg candidate block validation failed: hash={}, error={e}",
                    block_hash
                ))
            })?;
        }
        let reorg_delta = ReorgDelta {
            common_ancestor_height: ancestor_height,
            disconnected_blocks: disconnect_blocks
                .iter()
                .map(|(block_hash, block)| ReorgBlockDelta {
                    block_hash: *block_hash.as_bytes(),
                    block_height: block.header.height.0,
                    transactions: block.transactions.clone(),
                })
                .collect(),
            connected_blocks: connect_blocks
                .iter()
                .map(|(block_hash, block)| ReorgBlockDelta {
                    block_hash: *block_hash.as_bytes(),
                    block_height: block.header.height.0,
                    transactions: block.transactions.clone(),
                })
                .collect(),
            disconnected_txs: disconnect_blocks
                .iter()
                .flat_map(|(_, block)| block.transactions.clone())
                .collect(),
            connected_txs: connect_blocks
                .iter()
                .flat_map(|(_, block)| block.transactions.clone())
                .collect(),
        };

        let mut disconnect_output_index = HashMap::new();
        for (_, block) in &disconnect_blocks {
            record_block_outputs(block, &mut disconnect_output_index);
        }

        let mut utxo_overlay: BTreeMap<[u8; 33], Option<UtxoEntry>> = BTreeMap::new();
        let mut kernel_overlay: BTreeMap<[u8; 33], Option<[u8; 32]>> = BTreeMap::new();

        for (block_hash, block) in &disconnect_blocks {
            apply_disconnect(
                &self.store,
                &mut utxo_overlay,
                &mut kernel_overlay,
                *block_hash,
                block,
                ancestor_height,
                &disconnect_output_index,
            )?;
        }

        for (block_hash, block) in &connect_blocks {
            apply_connect(
                &self.store,
                &mut utxo_overlay,
                &mut kernel_overlay,
                *block_hash,
                block,
                self.coinbase_maturity,
            )?;
        }

        let mut height_updates = BTreeMap::new();
        for height in (ancestor_height + 1)..=self.tip_height.0 {
            height_updates.insert(height, None);
        }
        for (block_hash, block) in &connect_blocks {
            height_updates.insert(block.header.height.0, Some(*block_hash.as_bytes()));
        }
        let height_updates: Vec<(u64, Option<[u8; 32]>)> = height_updates.into_iter().collect();

        let utxo_updates = build_utxo_updates(&self.store, &utxo_overlay)?;
        let kernel_updates = build_kernel_updates(&self.store, &kernel_overlay)?;

        self.store.apply_reorg(
            new_tip_hash.as_bytes(),
            &height_updates,
            &utxo_updates,
            &kernel_updates,
        )?;

        self.tip_hash = new_tip_hash;
        self.tip_height = new_tip_header.height;
        self.tip_difficulty = new_tip_header.total_difficulty;
        prune_retained_side_chains(&self.store, self.tip_height, *self.tip_hash.as_bytes())?;
        info!(
            "Reorg applied: new tip height={}, hash={}, ancestor={}",
            self.tip_height, self.tip_hash, ancestor
        );
        Ok(reorg_delta)
    }

    fn validate_direct_extension_inputs(&self, block: &Block) -> Result<(), DomError> {
        let header = &block.header;
        for tx in &block.transactions {
            for input in &tx.inputs {
                let commitment_bytes = input.commitment.as_bytes();
                let entry = self.store.get_utxo(commitment_bytes)?.ok_or_else(|| {
                    DomError::Invalid(format!(
                        "input commitment not found in UTXO set: {}",
                        hex::encode(commitment_bytes)
                    ))
                })?;
                if entry.is_coinbase
                    && !entry.is_mature_for(header.height.0, self.coinbase_maturity)
                {
                    return Err(DomError::Invalid(format!(
                        "immature coinbase spend at height {} (created at {}, maturity {})",
                        header.height.0, entry.block_height, self.coinbase_maturity
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Select the V1 undo that falls out of the rolling window in the canonical
/// view produced by a pending reorganization. The store's height index still
/// names the old branch until the atomic reorg transaction commits, so a
/// prune height present in the promoted blocks must use that promoted hash.
#[cfg(feature = "native-usdom-v4-poc")]
fn native_usdom_v4_reorg_retention_update(
    store: &DomStore,
    new_tip_height: u64,
    promoted_prune_hash: Option<Hash256>,
) -> Result<Option<dom_store::ConsensusStateUpdate>, DomError> {
    if new_tip_height
        .checked_sub(crate::reorg::MAX_REORG_DEPTH)
        .is_none()
    {
        return Ok(None);
    }
    if let Some(block_hash) = promoted_prune_hash {
        return Ok(Some(dom_store::ConsensusStateUpdate {
            key: crate::native_usdom_v4::native_usdom_v4_undo_key(block_hash),
            value: None,
        }));
    }
    crate::native_usdom_v4::native_usdom_v4_undo_retention_update(store, new_tip_height)
}

#[cfg(all(test, feature = "native-usdom-v4-poc"))]
mod native_usdom_reorg_retention_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn promoted_branch_hash_wins_over_stale_canonical_height_index() {
        let directory = TempDir::new().unwrap();
        let store = DomStore::open_with_map_size(directory.path(), 64 << 20).unwrap();
        let promoted = Hash256::from_bytes([0xA5; 32]);
        let stale_canonical = Hash256::from_bytes([0x5A; 32]);
        let prune_height = 1;

        let update = native_usdom_v4_reorg_retention_update(
            &store,
            crate::reorg::MAX_REORG_DEPTH + prune_height,
            Some(promoted),
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            update.key,
            crate::native_usdom_v4::native_usdom_v4_undo_key(promoted)
        );
        assert_ne!(
            update.key,
            crate::native_usdom_v4::native_usdom_v4_undo_key(stale_canonical)
        );
        assert_eq!(update.value, None);
    }
}

/// Verify the persisted UTXO set against the canonical set reconstructed from
/// committed block history.
///
/// FIX-020 — safety contract: if the two diverge, this is either on-disk
/// corruption (torn write, bit-rot) or deliberate tampering with the UTXO
/// database. A node MUST NOT silently continue on a divergent set, so the
/// default (`allow_utxo_repair == false`) refuses to open with a fatal
/// `CHAIN_CORRUPT_SENTINEL` error logged at ERROR level. The old auto-heal
/// (`replace_utxo_set`) remains available ONLY as an explicit operator opt-in
/// (`allow_utxo_repair == true`, reached via `ChainState::open_with_utxo_repair`).
/// The reconstruction logic itself is unchanged; only *when* it runs.
fn ensure_canonical_utxo_set(
    store: &DomStore,
    tip_height: BlockHeight,
    network_magic: u32,
    allow_utxo_repair: bool,
) -> Result<(), DomError> {
    let canonical = reconstruct_canonical_utxo_set(store, tip_height, network_magic)?;
    let canonical_digest = digest_utxo_entries(&canonical);
    let persisted = store.read_all_utxos_raw()?;
    let persisted_digest = store.get_metadata(METADATA_UTXO_SET_DIGEST_KEY)?;
    let canonical_raw: BTreeMap<Vec<u8>, Vec<u8>> = canonical
        .iter()
        .map(|(commitment, entry)| (commitment.to_vec(), entry.clone()))
        .collect();

    if persisted == canonical_raw {
        if persisted_digest.as_deref() != Some(canonical_digest.as_slice()) {
            store.persist_utxo_set_digest(&canonical_digest)?;
        }
        return Ok(());
    }

    if !allow_utxo_repair {
        error!(
            "{CHAIN_CORRUPT_SENTINEL}: persisted UTXO set diverges from canonical reconstruction on reopen \
             (persisted_entries={}, canonical_entries={}); possible disk corruption or tampering — refusing to open",
            persisted.len(),
            canonical.len()
        );
        return Err(DomError::Internal(format!(
            "{CHAIN_CORRUPT_SENTINEL}: persisted UTXO set diverges from the canonical set \
             reconstructed from block history (persisted_entries={}, canonical_entries={}). \
             This indicates disk corruption or tampering of the UTXO database. The node refuses \
             to open on a divergent UTXO set rather than silently healing it. To rebuild the UTXO \
             set from canonical block history, restart in the explicit operator UTXO-repair mode \
             (ChainState::open_with_utxo_repair).",
            persisted.len(),
            canonical.len()
        )));
    }

    info!(
        "Operator UTXO-repair mode: persisted UTXO set diverged on reopen; rebuilding from canonical reconstruction (persisted_entries={}, canonical_entries={})",
        persisted.len(),
        canonical.len()
    );
    store.replace_utxo_set(&canonical, &canonical_digest)
}

fn reconstruct_canonical_utxo_set(
    store: &DomStore,
    tip_height: BlockHeight,
    network_magic: u32,
) -> Result<BTreeMap<[u8; 33], Vec<u8>>, DomError> {
    let mut utxos = BTreeMap::new();
    for h in 0..=tip_height.0 {
        let hash = store.get_hash_at_height(h)?.ok_or_else(|| {
            DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: missing canonical height_index entry at height {h} during UTXO rebuild"
            ))
        })?;
        let body = store.get_block_body(&hash)?.ok_or_else(|| {
            DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: canonical block {} has no body during UTXO rebuild",
                hex::encode(hash)
            ))
        })?;
        if h == BlockHeight::GENESIS.0
            && network_magic == dom_core::NETWORK_MAGIC_MAINNET
            && crate::validate_mainnet_genesis_identity(&body).is_ok()
        {
            continue;
        }
        let block = Block::from_bytes(&body).map_err(|e| {
            DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: canonical block {} body decode failed during UTXO rebuild: {e}",
                hex::encode(hash)
            ))
        })?;
        let header_bytes = block.header.to_bytes()?;
        let computed = compute_block_identifier(network_magic, &header_bytes)?;
        if computed.as_bytes() != &hash {
            return Err(DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: canonical block body/header hash mismatch at height {h} during UTXO rebuild: height_index={} body_header={}",
                hex::encode(hash),
                computed
            )));
        }

        let coinbase_commitment = *block.coinbase.output.commitment.as_bytes();
        let coinbase_entry = UtxoEntry {
            block_height: block.header.height.0,
            is_coinbase: true,
            proof: block.coinbase.output.proof.clone(),
        };
        if utxos
            .insert(coinbase_commitment, coinbase_entry.to_bytes())
            .is_some()
        {
            return Err(DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: duplicate coinbase UTXO commitment {} at height {} during UTXO rebuild",
                hex::encode(coinbase_commitment),
                h
            )));
        }

        for tx in &block.transactions {
            for input in &tx.inputs {
                let commitment = *input.commitment.as_bytes();
                if utxos.remove(&commitment).is_none() {
                    return Err(DomError::Internal(format!(
                        "{CHAIN_CORRUPT_SENTINEL}: canonical spend references missing UTXO {} at height {} during UTXO rebuild",
                        hex::encode(commitment),
                        h
                    )));
                }
            }
            for output in &tx.outputs {
                let commitment = *output.commitment.as_bytes();
                let entry = UtxoEntry {
                    block_height: block.header.height.0,
                    is_coinbase: false,
                    proof: output.proof.clone(),
                };
                if utxos.insert(commitment, entry.to_bytes()).is_some() {
                    return Err(DomError::Internal(format!(
                        "{CHAIN_CORRUPT_SENTINEL}: duplicate output UTXO commitment {} at height {} during UTXO rebuild",
                        hex::encode(commitment),
                        h
                    )));
                }
            }
        }
    }
    Ok(utxos)
}

fn digest_utxo_entries(utxos: &BTreeMap<[u8; 33], Vec<u8>>) -> [u8; 32] {
    type B2b256 = Blake2b<U32>;
    let mut hasher = B2b256::new();
    hasher.update(UTXO_SET_DIGEST_DOMAIN);
    for (commitment, entry) in utxos {
        hasher.update(commitment);
        hasher.update((entry.len() as u32).to_le_bytes());
        hasher.update(entry);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn rebuild_kernel_index_from_canonical_chain(
    store: &DomStore,
    tip_height: BlockHeight,
    network_magic: u32,
) -> Result<(), DomError> {
    for h in 0..=tip_height.0 {
        let hash = store.get_hash_at_height(h)?.ok_or_else(|| {
            DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: missing canonical height_index entry at height {h}"
            ))
        })?;
        let body = store.get_block_body(&hash)?.ok_or_else(|| {
            DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: canonical block {} has no body",
                hex::encode(hash)
            ))
        })?;
        if h == BlockHeight::GENESIS.0
            && network_magic == dom_core::NETWORK_MAGIC_MAINNET
            && crate::validate_mainnet_genesis_identity(&body).is_ok()
        {
            continue;
        }
        let block = Block::from_bytes(&body).map_err(|e| {
            DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: canonical block {} body decode failed during kernel-index rebuild: {e}",
                hex::encode(hash)
            ))
        })?;
        let header_bytes = block.header.to_bytes()?;
        let computed = compute_block_identifier(network_magic, &header_bytes)?;
        if computed.as_bytes() != &hash {
            return Err(DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: canonical block body/header hash mismatch at height {h}: height_index={} body_header={}",
                hex::encode(hash),
                computed
            )));
        }
        let kernel_excesses = extract_kernel_excesses(&block, computed);
        store.ensure_kernel_indices(&kernel_excesses)?;
    }
    Ok(())
}

fn extract_kernel_excesses(block: &Block, block_hash: Hash256) -> Vec<KernelExcess> {
    let mut out = Vec::with_capacity(
        1 + block
            .transactions
            .iter()
            .map(|tx| tx.kernels.len())
            .sum::<usize>(),
    );
    out.push((
        *block.coinbase.kernel.excess.as_bytes(),
        *block_hash.as_bytes(),
    ));
    for tx in &block.transactions {
        for kernel in &tx.kernels {
            out.push((*kernel.excess.as_bytes(), *block_hash.as_bytes()));
        }
    }
    out
}

/// Canonical persistence changeset for the genesis block.
///
/// DOM-AUDIT-001: `create_genesis_block` (dom-node) MUST persist exactly the
/// changeset that the reopen path reconstructs — `reconstruct_canonical_utxo_set`
/// (UTXO) and `rebuild_kernel_index_from_canonical_chain` (kernel index). If the
/// two diverge for the spendable genesis coinbase, a freshly-created node and a
/// reopened node hold different UTXO sets, risking a chain split when the genesis
/// coinbase is spent.
///
/// This wrapper routes the create path through the *same* helpers the
/// connect/reopen paths use (`build_utxo_changeset` + `extract_kernel_excesses`),
/// so `create == reopen` holds by construction rather than by a hand-maintained
/// duplicate. Returns `(new_utxos, spent_utxos, kernel_excesses)` in the exact
/// shape `DomStore::commit_block` expects.
///
/// `block_hash` must be the canonical genesis identifier supplied by the sole
/// genesis authority. For legacy Testnet and Regtest this is Blake2b-256 of
/// the serialized header; Mainnet has an empty economic body and therefore
/// does not use this coinbase changeset helper.
pub fn genesis_canonical_changeset(
    block: &Block,
    block_hash: Hash256,
) -> (Vec<UtxoBytes>, Vec<SpentCommitment>, Vec<KernelExcess>) {
    let (new_utxos, spent_utxos) = build_utxo_changeset(block);
    let kernel_excesses = extract_kernel_excesses(block, block_hash);
    (new_utxos, spent_utxos, kernel_excesses)
}

fn build_utxo_changeset(block: &Block) -> (Vec<UtxoBytes>, Vec<SpentCommitment>) {
    let header = &block.header;
    let mut new_utxos: Vec<([u8; 33], Vec<u8>)> = Vec::new();
    let coinbase_entry = UtxoEntry {
        block_height: header.height.0,
        is_coinbase: true,
        proof: block.coinbase.output.proof.clone(),
    };
    new_utxos.push((
        *block.coinbase.output.commitment.as_bytes(),
        coinbase_entry.to_bytes(),
    ));

    let mut spent_utxos: Vec<[u8; 33]> = Vec::new();
    for tx in &block.transactions {
        for input in &tx.inputs {
            spent_utxos.push(*input.commitment.as_bytes());
        }
        for output in &tx.outputs {
            let entry = UtxoEntry {
                block_height: header.height.0,
                is_coinbase: false,
                proof: output.proof.clone(),
            };
            new_utxos.push((*output.commitment.as_bytes(), entry.to_bytes()));
        }
    }
    (new_utxos, spent_utxos)
}

fn validate_branch_header_syntax(
    store: &DomStore,
    branch_tip: Hash256,
    ancestor: Hash256,
    network_magic: u32,
) -> Result<(), DomError> {
    let mut cursor = branch_tip;
    while cursor != ancestor {
        let header_bytes = store.get_block_header(cursor.as_bytes())?.ok_or_else(|| {
            DomError::Internal(format!(
                "reorg candidate header missing during validation: {cursor}"
            ))
        })?;
        let header = BlockHeader::from_bytes(&header_bytes)?;
        validate_header_syntax(&header, network_magic).map_err(|error| {
            DomError::Invalid(format!(
                "reorg candidate header validation failed: hash={cursor}, error={error}"
            ))
        })?;
        cursor = header.prev_hash;
    }
    Ok(())
}

fn collect_branch_blocks(
    store: &DomStore,
    mut tip: Hash256,
    ancestor: Hash256,
) -> Result<Vec<(Hash256, Block)>, DomError> {
    let mut out = Vec::new();
    while tip != ancestor {
        let body = store.get_block_body(tip.as_bytes())?.ok_or_else(|| {
            DomError::Internal(format!(
                "reorg block body missing: {}",
                hex::encode(tip.as_bytes())
            ))
        })?;
        let block = Block::from_bytes(&body).map_err(|e| {
            DomError::Internal(format!(
                "reorg block body decode failed for {}: {e}",
                hex::encode(tip.as_bytes())
            ))
        })?;
        tip = block.header.prev_hash;
        out.push((compute_block_hash(&block.header.to_bytes()?), block));
    }
    Ok(out)
}

fn record_block_outputs(block: &Block, out: &mut HashMap<[u8; 33], UtxoEntry>) {
    out.insert(
        *block.coinbase.output.commitment.as_bytes(),
        UtxoEntry {
            block_height: block.header.height.0,
            is_coinbase: true,
            proof: block.coinbase.output.proof.clone(),
        },
    );
    for tx in &block.transactions {
        for output in &tx.outputs {
            out.insert(
                *output.commitment.as_bytes(),
                UtxoEntry {
                    block_height: block.header.height.0,
                    is_coinbase: false,
                    proof: output.proof.clone(),
                },
            );
        }
    }
}

fn apply_disconnect(
    store: &DomStore,
    utxo_overlay: &mut BTreeMap<[u8; 33], Option<UtxoEntry>>,
    kernel_overlay: &mut BTreeMap<[u8; 33], Option<[u8; 32]>>,
    block_hash: Hash256,
    block: &Block,
    ancestor_height: u64,
    disconnect_output_index: &HashMap<[u8; 33], UtxoEntry>,
) -> Result<(), DomError> {
    utxo_overlay.insert(*block.coinbase.output.commitment.as_bytes(), None);
    for tx in &block.transactions {
        for output in &tx.outputs {
            utxo_overlay.insert(*output.commitment.as_bytes(), None);
        }
    }

    for tx in &block.transactions {
        for input in &tx.inputs {
            let commitment = *input.commitment.as_bytes();
            let resurrected = disconnect_output_index
                .get(&commitment)
                .cloned()
                .or(find_canonical_output_entry(
                    store,
                    ancestor_height,
                    &commitment,
                )?)
                .ok_or_else(|| {
                    DomError::Internal(format!(
                        "reorg disconnect could not resurrect spent output {}",
                        hex::encode(commitment)
                    ))
                })?;
            utxo_overlay.insert(commitment, Some(resurrected));
        }
    }

    for (excess, _) in extract_kernel_excesses(block, block_hash) {
        kernel_overlay.insert(excess, None);
    }
    Ok(())
}

fn apply_connect(
    store: &DomStore,
    utxo_overlay: &mut BTreeMap<[u8; 33], Option<UtxoEntry>>,
    kernel_overlay: &mut BTreeMap<[u8; 33], Option<[u8; 32]>>,
    block_hash: Hash256,
    block: &Block,
    coinbase_maturity: u64,
) -> Result<(), DomError> {
    for tx in &block.transactions {
        for input in &tx.inputs {
            let commitment = *input.commitment.as_bytes();
            let entry = lookup_utxo(store, utxo_overlay, &commitment)?.ok_or_else(|| {
                DomError::Invalid(format!(
                    "reorg connect missing input commitment {}",
                    hex::encode(commitment)
                ))
            })?;
            if entry.is_coinbase && !entry.is_mature_for(block.header.height.0, coinbase_maturity) {
                return Err(DomError::Invalid(format!(
                    "reorg connect spends immature coinbase at height {} (created at {}, maturity {})",
                    block.header.height.0, entry.block_height, coinbase_maturity
                )));
            }
            utxo_overlay.insert(commitment, None);
        }
    }

    let coinbase_commitment = *block.coinbase.output.commitment.as_bytes();
    if lookup_utxo(store, utxo_overlay, &coinbase_commitment)?.is_some() {
        return Err(DomError::Invalid(format!(
            "reorg connect duplicate output commitment {}",
            hex::encode(coinbase_commitment)
        )));
    }
    utxo_overlay.insert(
        coinbase_commitment,
        Some(UtxoEntry {
            block_height: block.header.height.0,
            is_coinbase: true,
            proof: block.coinbase.output.proof.clone(),
        }),
    );

    for tx in &block.transactions {
        for output in &tx.outputs {
            let commitment = *output.commitment.as_bytes();
            if lookup_utxo(store, utxo_overlay, &commitment)?.is_some() {
                return Err(DomError::Invalid(format!(
                    "reorg connect duplicate output commitment {}",
                    hex::encode(commitment)
                )));
            }
            utxo_overlay.insert(
                commitment,
                Some(UtxoEntry {
                    block_height: block.header.height.0,
                    is_coinbase: false,
                    proof: output.proof.clone(),
                }),
            );
        }
    }

    for (excess, indexed_block) in extract_kernel_excesses(block, block_hash) {
        if lookup_kernel(store, kernel_overlay, &excess)?.is_some() {
            return Err(DomError::Invalid(format!(
                "reorg connect kernel replay detected: excess={}",
                hex::encode(excess)
            )));
        }
        kernel_overlay.insert(excess, Some(indexed_block));
    }

    Ok(())
}

fn lookup_utxo(
    store: &DomStore,
    overlay: &BTreeMap<[u8; 33], Option<UtxoEntry>>,
    commitment: &[u8; 33],
) -> Result<Option<UtxoEntry>, DomError> {
    if let Some(entry) = overlay.get(commitment) {
        return Ok(entry.clone());
    }
    store.get_utxo(commitment)
}

fn lookup_kernel(
    store: &DomStore,
    overlay: &BTreeMap<[u8; 33], Option<[u8; 32]>>,
    excess: &[u8; 33],
) -> Result<Option<[u8; 32]>, DomError> {
    if let Some(entry) = overlay.get(excess) {
        return Ok(*entry);
    }
    store.get_kernel_block(excess)
}

fn find_canonical_output_entry(
    store: &DomStore,
    ancestor_height: u64,
    commitment: &[u8; 33],
) -> Result<Option<UtxoEntry>, DomError> {
    for height in (0..=ancestor_height).rev() {
        let Some(hash) = store.get_hash_at_height(height)? else {
            continue;
        };
        let Some(body) = store.get_block_body(&hash)? else {
            continue;
        };
        if height == BlockHeight::GENESIS.0
            && crate::validate_mainnet_genesis_identity(&body).is_ok()
        {
            continue;
        }
        let block = Block::from_bytes(&body).map_err(|e| {
            DomError::Internal(format!(
                "decode canonical block {} while resurrecting {}: {e}",
                hex::encode(hash),
                hex::encode(commitment)
            ))
        })?;
        if block.coinbase.output.commitment.as_bytes() == commitment {
            return Ok(Some(UtxoEntry {
                block_height: block.header.height.0,
                is_coinbase: true,
                proof: block.coinbase.output.proof.clone(),
            }));
        }
        for tx in &block.transactions {
            for output in &tx.outputs {
                if output.commitment.as_bytes() == commitment {
                    return Ok(Some(UtxoEntry {
                        block_height: block.header.height.0,
                        is_coinbase: false,
                        proof: output.proof.clone(),
                    }));
                }
            }
        }
    }
    Ok(None)
}

fn build_utxo_updates(
    store: &DomStore,
    overlay: &BTreeMap<[u8; 33], Option<UtxoEntry>>,
) -> Result<Vec<UtxoUpdate>, DomError> {
    let mut out = Vec::new();
    for (commitment, desired) in overlay {
        let current = store.get_utxo(commitment)?;
        match (current, desired) {
            (Some(current), Some(desired)) if current.to_bytes() == desired.to_bytes() => {}
            // A2-001: apply_connect (the consensus layer of the reorg) has already
            // validated this transition — apply_disconnect released the shared output to
            // None and apply_connect re-admitted it past its duplicate-output guard. The
            // overlay therefore encodes an approved re-homing, and build_utxo_updates only
            // translates the overlay into store writes; it executes the approved change
            // rather than re-judging it. Re-homing is consensus-neutral: block_height is
            // only read for coinbase maturity (is_mature_for short-circuits to true for
            // non-coinbase), and coinbase maturity is enforced in apply_connect and at
            // spend time, not here. A divergence in proof or is_coinbase is NOT something
            // apply_connect can emit, so it would signal an internal bug — that still fails
            // closed.
            (Some(current), Some(desired))
                if current.proof == desired.proof && current.is_coinbase == desired.is_coinbase =>
            {
                out.push((*commitment, Some(desired.to_bytes())));
            }
            (Some(current), Some(desired)) => {
                return Err(DomError::Internal(format!(
                    "reorg utxo mismatch for existing commitment {}: current_height={} desired_height={}",
                    hex::encode(commitment),
                    current.block_height,
                    desired.block_height
                )));
            }
            (None, Some(desired)) => out.push((*commitment, Some(desired.to_bytes()))),
            (Some(_), None) => out.push((*commitment, None)),
            (None, None) => {}
        }
    }
    Ok(out)
}

fn build_kernel_updates(
    store: &DomStore,
    overlay: &BTreeMap<[u8; 33], Option<[u8; 32]>>,
) -> Result<Vec<KernelUpdate>, DomError> {
    let mut out = Vec::new();
    for (excess, desired) in overlay {
        let current = store.get_kernel_block(excess)?;
        if current != *desired {
            out.push((*excess, *desired));
        }
    }
    Ok(out)
}

#[derive(Debug, Clone)]
struct RetainedSideTip {
    hash: [u8; 32],
    height: u64,
    total_difficulty: U256,
}

fn prune_retained_side_chains(
    store: &DomStore,
    canonical_tip_height: BlockHeight,
    canonical_tip_hash: [u8; 32],
) -> Result<(), DomError> {
    let headers = store.read_all_block_headers_raw()?;
    if headers.is_empty() {
        return Ok(());
    }

    let canonical_hashes = canonical_hashes(store, canonical_tip_height)?;
    let noncanonical: BTreeMap<[u8; 32], BlockHeader> = headers
        .iter()
        .filter_map(|(hash, bytes)| {
            if canonical_hashes.contains(hash) {
                return None;
            }
            Some((hash, bytes))
        })
        .map(|(hash, bytes)| Ok((*hash, BlockHeader::from_bytes(bytes)?)))
        .collect::<Result<_, DomError>>()?;

    if noncanonical.is_empty() {
        return Ok(());
    }

    let mut child_parents = BTreeSet::new();
    for header in noncanonical.values() {
        child_parents.insert(*header.prev_hash.as_bytes());
    }

    let mut candidate_tips = Vec::new();
    for (hash, header) in &noncanonical {
        if child_parents.contains(hash) {
            continue;
        }
        let Some(common_ancestor) = find_common_ancestor(
            store,
            Hash256::from_bytes(canonical_tip_hash),
            Hash256::from_bytes(*hash),
        )?
        else {
            continue;
        };
        if common_ancestor == Hash256::from_bytes(*hash) {
            continue;
        }
        let ancestor_height = if common_ancestor == Hash256::ZERO {
            0
        } else {
            let Some(ancestor_header) =
                load_retention_header(store, &headers, common_ancestor.as_bytes())?
            else {
                continue;
            };
            ancestor_header.height.0
        };
        let disconnect_depth = canonical_tip_height.0.saturating_sub(ancestor_height);
        let branch_length = header.height.0.saturating_sub(ancestor_height);
        if disconnect_depth > MAX_RETAINED_SIDE_BRANCH_REORG_DEPTH
            || branch_length > MAX_RETAINED_SIDE_BRANCH_LENGTH
        {
            continue;
        }
        candidate_tips.push(RetainedSideTip {
            hash: *hash,
            height: header.height.0,
            total_difficulty: header.total_difficulty,
        });
    }

    candidate_tips.sort_by(|left, right| {
        right
            .total_difficulty
            .cmp(&left.total_difficulty)
            .then_with(|| left.hash.as_slice().cmp(right.hash.as_slice()))
            .then_with(|| right.height.cmp(&left.height))
    });
    candidate_tips.truncate(MAX_RETAINED_SIDE_BRANCH_TIPS);

    let mut keep_hashes = canonical_hashes;
    for tip in candidate_tips {
        let mut cursor = Hash256::from_bytes(tip.hash);
        let mut walked = 0u64;
        loop {
            if keep_hashes.contains(cursor.as_bytes()) {
                break;
            }
            keep_hashes.insert(*cursor.as_bytes());
            walked = walked.saturating_add(1);
            if walked > MAX_RETAINED_SIDE_BRANCH_LENGTH {
                break;
            }
            let Some(header) = load_retention_header(store, &headers, cursor.as_bytes())? else {
                break;
            };
            if header.prev_hash == Hash256::ZERO {
                break;
            }
            cursor = header.prev_hash;
        }
    }

    let prune_hashes: BTreeSet<[u8; 32]> = noncanonical
        .keys()
        .filter(|hash| !keep_hashes.contains(*hash))
        .copied()
        .collect();
    store.prune_known_blocks(&prune_hashes)
}

fn canonical_hashes(
    store: &DomStore,
    canonical_tip_height: BlockHeight,
) -> Result<BTreeSet<[u8; 32]>, DomError> {
    let mut out = BTreeSet::new();
    for height in 0..=canonical_tip_height.0 {
        let Some(hash) = store.get_hash_at_height(height)? else {
            continue;
        };
        out.insert(hash);
    }
    Ok(out)
}

fn load_retention_header(
    store: &DomStore,
    cached_headers: &BTreeMap<[u8; 32], Vec<u8>>,
    hash: &[u8; 32],
) -> Result<Option<BlockHeader>, DomError> {
    if let Some(bytes) = cached_headers.get(hash) {
        return Ok(Some(BlockHeader::from_bytes(bytes)?));
    }
    match store.get_block_header(hash)? {
        Some(bytes) => Ok(Some(BlockHeader::from_bytes(&bytes)?)),
        None => Ok(None),
    }
}

/// Outcome of attempting to connect a block to the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectResult {
    /// Block extended the best chain — new tip. Caller should rebroadcast.
    BestChain,
    /// Block promoted a heavier known side branch into the canonical chain.
    Reorg(ReorgDelta),
    /// Block is valid but on a side chain (lower or equal total difficulty).
    /// Caller should NOT rebroadcast — would cause network amplification.
    SideChain,
    /// Block was already known (hash already in store). No-op.
    /// Caller MUST NOT rebroadcast or re-validate. Critical for preventing
    /// relay loops (DOM-SEC-RELAY-LOOP, 2026-05-23).
    AlreadyHave,
}

fn validate_persisted_genesis_identity(
    store: &DomStore,
    configured_genesis_hash: Hash256,
) -> Result<(), DomError> {
    let Some(stored_genesis_hash) = store.get_hash_at_height(BlockHeight::GENESIS.0)? else {
        return Ok(());
    };

    if configured_genesis_hash != Hash256::ZERO
        && stored_genesis_hash != *configured_genesis_hash.as_bytes()
    {
        return Err(DomError::Invalid(format!(
            "stored genesis hash mismatch: expected {}, got {}",
            configured_genesis_hash,
            hex::encode(stored_genesis_hash)
        )));
    }

    Ok(())
}

fn compute_block_hash(header_bytes: &[u8]) -> Hash256 {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    h.update(header_bytes);
    let result = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    Hash256::from_bytes(arr)
}

fn compute_block_identifier(network_magic: u32, header_bytes: &[u8]) -> Result<Hash256, DomError> {
    crate::canonical_header_identifier(network_magic, header_bytes)
}

#[cfg(test)]
mod randomx_seed_tests {
    //! Unit tests for RandomX seed resolution in the header-first IBD path.
    //!
    //! Regression coverage for the IBD PoW consensus split at the epoch
    //! boundary: `compute_randomx_seed` used to fall back silently to a zero
    //! seed for epoch > 0 blocks whose seed-height block was not yet committed
    //! to the store (the normal state during header sync). The validator then
    //! hashed against `[0u8; 32]` while the miner used the real seed, producing
    //! a "proof-of-work invalid" rejection on otherwise valid blocks.
    use super::*;
    use dom_consensus::block::ProofOfWork;
    use dom_core::BLOCK_VERSION_LEGACY;
    use dom_pow::CompactTarget;

    const TEST_LMDB_MAP_SIZE: usize = 64 << 20; // 64 MiB

    fn empty_chain() -> (tempfile::TempDir, ChainState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store =
            DomStore::open_with_map_size(dir.path(), TEST_LMDB_MAP_SIZE).expect("store open");
        let chain = ChainState::open(store, Hash256::ZERO, dom_core::NETWORK_MAGIC_REGTEST)
            .expect("chain open");
        (dir, chain)
    }

    fn synth_header(height: u64) -> BlockHeader {
        BlockHeader {
            version: BLOCK_VERSION_LEGACY,
            height: BlockHeight(height),
            prev_hash: Hash256::ZERO,
            timestamp: Timestamp(1_704_067_200 + height),
            output_root: Hash256::ZERO,
            kernel_root: Hash256::ZERO,
            rangeproof_root: Hash256::ZERO,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(0x1f00_ffff),
            total_difficulty: U256::one(),
            pow: ProofOfWork {
                nonce: 0,
                randomx_hash: Hash256::ZERO,
            },
        }
    }

    /// Epoch 1 (height 2048, seed_height 1984): the seed block lives in the
    /// in-memory batch, not the store. The seed MUST be resolved from the batch
    /// rather than silently falling back to a zero seed.
    #[test]
    fn ibd_pow_seed_resolved_from_batch() {
        let (_dir, chain) = empty_chain();

        // seed_height for height 2048 is 2048 - 64 = 1984.
        assert_eq!(randomx_seed_height(2048), 1984);

        let expected = [7u8; 32];
        // Synthetic batch including the seed-height header (1984) with a known
        // hash; the store is empty (no commits yet), mirroring header sync.
        let batch: Vec<(BlockHeader, Hash256, bool)> = vec![
            (synth_header(1983), Hash256::from_bytes([1u8; 32]), false),
            (synth_header(1984), Hash256::from_bytes(expected), false),
            (synth_header(2048), Hash256::from_bytes([2u8; 32]), false),
        ];

        let seed = chain
            .compute_randomx_seed_with_batch(2048, &batch)
            .expect("seed resolves from batch");
        assert_eq!(seed, expected, "seed must come from the in-memory batch");
        assert_ne!(seed, [0u8; 32], "must not fall back to zero seed");
    }

    /// Focused transition matrix for the blocks immediately around two seed
    /// intervals. The same batch resolver is used by header synchronization;
    /// miner and branch-aware validator paths share `randomx_seed_height`.
    #[test]
    fn focused_randomx_seed_boundaries_select_exact_branch_hashes() {
        let (_dir, chain) = empty_chain();
        let genesis = Hash256::from_bytes([0x10; 32]);
        let epoch_one = Hash256::from_bytes([0x11; 32]);
        let epoch_two = Hash256::from_bytes([0x12; 32]);
        let batch = vec![
            (synth_header(0), genesis, false),
            (synth_header(1984), epoch_one, false),
            (synth_header(4032), epoch_two, false),
        ];

        for (candidate, expected_height, expected_hash) in [
            (2047, 0, genesis),
            (2048, 1984, epoch_one),
            (2049, 1984, epoch_one),
            (4095, 1984, epoch_one),
            (4096, 4032, epoch_two),
            (4097, 4032, epoch_two),
        ] {
            assert_eq!(randomx_seed_height(candidate), expected_height);
            assert_eq!(
                chain
                    .compute_randomx_seed_with_batch(candidate, &batch)
                    .expect("boundary seed resolves"),
                *expected_hash.as_bytes(),
                "candidate height {candidate} selected the wrong branch seed"
            );
        }
    }

    /// Epoch 0 (height 100, seed_height 0): with an empty batch and an
    /// un-indexed genesis, the genesis fallback `[0u8; 32]` is correct and must
    /// NOT be promoted to an error.
    #[test]
    fn ibd_pow_seed_epoch0_uses_zero_fallback() {
        let (_dir, chain) = empty_chain();

        assert_eq!(randomx_seed_height(100), 0);

        let seed = chain
            .compute_randomx_seed_with_batch(100, &[])
            .expect("epoch 0 falls back to genesis without error");
        assert_eq!(seed, [0u8; 32]);
    }

    /// Epoch 1 on the committed-store path: a store missing the seed block at
    /// height 1984 is data corruption and MUST surface as an error rather than
    /// silently hashing against a zero seed.
    #[test]
    fn ibd_pow_seed_epoch1_missing_errors() {
        let (_dir, chain) = empty_chain();

        let result = chain.compute_randomx_seed(2048);
        assert!(
            matches!(result, Err(DomError::Internal(_))),
            "missing epoch>0 seed block must error, got {result:?}"
        );
    }

    /// A2-004: the RandomX seed for PoW validation is resolved by
    /// `compute_randomx_seed` from the CANONICAL height index (get_hash_at_height),
    /// which knows only the height — not which branch the block being validated
    /// belongs to. `connect_block` (line ~273) and `validate_header_only`
    /// (line ~762) both use this canonical path.
    ///
    /// During a reorg that crosses a RandomX epoch boundary, a side-branch block
    /// whose OWN history has a different block at seed_height is nonetheless
    /// validated against the canonical seed. If the branches differ at that
    /// seed_height, the block is validated against the wrong seed — a consensus
    /// split (a valid block rejected, or nodes disagreeing on validity).
    ///
    /// DECIDED RULE (Soren Planck): the seed comes from the block's OWN history,
    /// not the canonical chain. The branch-aware path
    /// (`compute_randomx_seed_with_batch`), already used by IBD, implements that
    /// rule. This detector pins the divergence at the resolution level: for the
    /// same block height at an epoch boundary, the canonical path and the
    /// branch-aware path return DIFFERENT seeds. The fix must make connect_block
    /// resolve the seed branch-aware; when it does, connect_block will yield the
    /// branch-aware value for a side-branch block instead of the canonical one.
    ///
    /// NOTE: mechanism-level detector (documents the resolution divergence, the
    /// root cause). It PASSES today — it asserts that the two resolution paths
    /// diverge, which is true now. Executable documentation of A2-004, not a
    /// red-until-fixed alarm.
    #[test]
    fn a2_004_seed_resolution_is_branch_blind_at_epoch_boundary() {
        let (_dir, chain) = empty_chain();

        // First block of epoch 1 is height 2048; its seed_height is 1984.
        let height = 2048;
        assert_eq!(randomx_seed_height(height), 1984);

        // Populate the CANONICAL height index at seed_height 1984 with a known
        // block hash (CANON). commit_block accepts opaque bytes for header/body —
        // dom-store does not parse them — so a minimal synthetic block suffices.
        let canon_seed_hash = [0xAAu8; 32];
        let opaque_header = synth_header(1984).to_bytes().expect("seed header bytes");
        let opaque_body = vec![0xBBu8; 32];
        chain
            .store
            .commit_block(
                &canon_seed_hash,
                1984,
                &opaque_header,
                &opaque_body,
                &[],
                &[],
                &[],
            )
            .expect("commit canonical seed block at 1984");

        // CANONICAL path: resolves the seed for height 2048 from the height
        // index, yielding CANON. It receives only the height; it cannot know
        // any branch.
        let canonical_seed = chain
            .compute_randomx_seed(height)
            .expect("canonical seed resolves from the committed height index");
        assert_eq!(
            canonical_seed, canon_seed_hash,
            "canonical path returns the canonical block at seed_height"
        );

        // BRANCH-AWARE path: given a batch representing a SIDE branch whose own
        // block at 1984 is SIDE (!= CANON), it resolves the seed to SIDE — the
        // seed from that block's own history, per the decided rule.
        let side_seed_hash = [0xBBu8; 32];
        let side_branch: Vec<(BlockHeader, Hash256, bool)> = vec![(
            synth_header(1984),
            Hash256::from_bytes(side_seed_hash),
            false,
        )];
        let branch_aware_seed = chain
            .compute_randomx_seed_with_batch(height, &side_branch)
            .expect("branch-aware seed resolves from the side branch's own history");
        assert_eq!(
            branch_aware_seed, side_seed_hash,
            "branch-aware path uses the side branch's own seed block"
        );

        // A2-004: for the SAME block height at the epoch boundary, the canonical
        // path (which connect_block uses) and the branch-aware path (the decided
        // rule) return DIFFERENT seeds. A side-branch block would therefore be
        // validated against CANON when it must be validated against SIDE. The
        // fix must make connect_block resolve the seed from the block's own
        // history.
        assert_ne!(
            canonical_seed, branch_aware_seed,
            "A2-004: connect_block's canonical seed path validates a side-branch \
             block against the wrong seed at a RandomX epoch boundary"
        );
    }

    /// Header at height `h` with the given prev_hash and nonce; returns
    /// (header, hash). The nonce distinguishes same-height blocks on different
    /// branches (canonical vs side), yielding different hashes.
    fn header_at(h: u64, prev: Hash256, nonce: u64) -> (BlockHeader, Hash256) {
        let mut hdr = synth_header(h);
        hdr.prev_hash = prev;
        hdr.pow.nonce = nonce;
        let bytes = hdr.to_bytes().expect("serialize header");
        let hash = compute_block_hash(&bytes);
        (hdr, hash)
    }

    /// Insert a header as CANONICAL (populates the height index via commit_block;
    /// body/utxo/kernel are opaque — dom-store does not parse them).
    fn commit_canonical(chain: &ChainState, hdr: &BlockHeader, hash: Hash256) {
        let bytes = hdr.to_bytes().expect("serialize");
        chain
            .store
            .commit_block(
                hash.as_bytes(),
                hdr.height.0,
                &bytes,
                &[0xBB; 4],
                &[],
                &[],
                &[],
            )
            .expect("commit canonical");
    }

    /// Insert a header as a BRANCH block (header+body in the store, NO height
    /// index — exactly as connect_block does for side-chain quarantine).
    fn store_branch(chain: &ChainState, hdr: &BlockHeader, hash: Hash256) {
        let bytes = hdr.to_bytes().expect("serialize");
        chain
            .store
            .store_known_block(hash.as_bytes(), &bytes, &[0xCC; 4])
            .expect("store branch");
    }

    /// A2-004 FIX (main): a side-branch block whose own history has a different
    /// seed block than canonical must be validated against ITS OWN seed, not the
    /// canonical one. Would fail on the pre-fix canonical path; passes with the
    /// branch-aware resolution.
    #[test]
    fn a2_004_fix_branch_aware_uses_own_seed() {
        let (_dir, chain) = empty_chain();
        assert_eq!(randomx_seed_height(2048), 1984);

        // Canonical block at seed_height 1984 (CANON).
        let (c_hdr, canon_1984) = header_at(1984, Hash256::ZERO, 0xA0);
        commit_canonical(&chain, &c_hdr, canon_1984);

        // Side branch 1984..=2047, chained; block 1984 is SIDE (!= CANON),
        // diverging at the seed_height.
        let (b1984_hdr, side_1984) = header_at(1984, Hash256::ZERO, 0xB0);
        store_branch(&chain, &b1984_hdr, side_1984);
        let mut prev = side_1984;
        for h in 1985..=2047 {
            let (nh, nhash) = header_at(h, prev, 0xB0);
            store_branch(&chain, &nh, nhash);
            prev = nhash;
        }
        let parent_lateral = prev; // block 2047 of the side branch

        // The fix resolves the seed from the branch's own history => SIDE.
        let branch_aware = chain
            .compute_randomx_seed_branch_aware(2048, parent_lateral)
            .expect("branch-aware resolves");
        assert_eq!(
            branch_aware,
            *side_1984.as_bytes(),
            "fix: side-branch block must use its OWN seed block (SIDE)"
        );

        // The canonical path (old bug) would resolve to CANON — the divergence
        // the fix corrects.
        let canonical = chain
            .compute_randomx_seed(2048)
            .expect("canonical resolves");
        assert_eq!(canonical, *canon_1984.as_bytes());
        assert_ne!(
            branch_aware, canonical,
            "A2-004: the fix diverges from the canonical path exactly where the bug was"
        );
    }

    /// A2-004 FIX (case 6, non-regression): a block extending the canonical tip
    /// gets the SAME seed as the canonical index. The fix must not change the
    /// common path.
    #[test]
    fn a2_004_fix_direct_extension_matches_canonical() {
        let (_dir, chain) = empty_chain();

        let (c1984, canon_1984) = header_at(1984, Hash256::ZERO, 0xA0);
        commit_canonical(&chain, &c1984, canon_1984);
        let (c2047, canon_2047) = header_at(2047, Hash256::ZERO, 0xA7);
        commit_canonical(&chain, &c2047, canon_2047);

        // Canonical parent => ramo (a) fires on the first iteration => canonical
        // index. Must equal compute_randomx_seed exactly.
        let branch_aware = chain
            .compute_randomx_seed_branch_aware(2048, canon_2047)
            .expect("branch-aware resolves");
        let canonical = chain
            .compute_randomx_seed(2048)
            .expect("canonical resolves");
        assert_eq!(
            branch_aware, canonical,
            "case 6: direct extension must match the canonical seed exactly"
        );
        assert_eq!(branch_aware, *canon_1984.as_bytes());
    }

    /// A2-004 FIX (case 4, epoch 0): a height-1 block (seed_height 0) must
    /// resolve to the genesis hash once genesis is indexed — NOT the zero
    /// fallback. Regression guard for the epoch-0 blind spot: the branch-aware
    /// resolver must match the canonical resolver at epoch 0, where all branches
    /// share the genesis. (Before the case-4 fix, this returned [0u8; 32],
    /// breaking PoW validation for the entire first epoch.)
    #[test]
    fn a2_004_fix_epoch0_resolves_genesis_not_zero() {
        let (_dir, chain) = empty_chain();

        // Before genesis is indexed: both resolvers give the zero fallback.
        assert_eq!(randomx_seed_height(1), 0);
        let bare = chain
            .compute_randomx_seed_branch_aware(1, Hash256::ZERO)
            .expect("bare epoch-0 resolves");
        assert_eq!(bare, [0u8; 32], "before genesis is indexed, zero fallback");

        // After genesis is committed (indexed at height 0):
        let (g_hdr, genesis_hash) = header_at(0, Hash256::ZERO, 0x01);
        commit_canonical(&chain, &g_hdr, genesis_hash);

        let branch_aware = chain
            .compute_randomx_seed_branch_aware(1, genesis_hash)
            .expect("epoch-0 branch-aware resolves");
        let canonical = chain
            .compute_randomx_seed(1)
            .expect("epoch-0 canonical resolves");

        // Both must be the genesis hash, and must agree (epoch 0 has no branch
        // divergence — all chains share the genesis).
        assert_eq!(
            branch_aware,
            *genesis_hash.as_bytes(),
            "epoch-0 seed must be the genesis hash once indexed, not zero"
        );
        assert_eq!(
            branch_aware, canonical,
            "epoch-0 branch-aware must match canonical exactly"
        );
    }
}

#[cfg(test)]
mod mtp_branch_tests {
    //! A2-005: get_recent_timestamps must collect the median-time-past window
    //! from the block's OWN branch (via prev_hash), not the canonical height
    //! index. The pre-fix version used get_hash_at_height, which returned
    //! nothing for non-canonical (side-branch) ancestors — silently yielding a
    //! short window that disables the MTP check, and (when it did resolve)
    //! taking timestamps from a competing branch.
    use super::*;
    use dom_consensus::block::ProofOfWork;
    use dom_core::BLOCK_VERSION_LEGACY;
    use dom_pow::CompactTarget;

    const TEST_LMDB_MAP_SIZE: usize = 64 << 20;

    fn chain() -> (tempfile::TempDir, ChainState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = DomStore::open_with_map_size(dir.path(), TEST_LMDB_MAP_SIZE).expect("store");
        let c =
            ChainState::open(store, Hash256::ZERO, dom_core::NETWORK_MAGIC_REGTEST).expect("chain");
        (dir, c)
    }

    /// Build a header at height `h`, parent `prev`, with an explicit timestamp.
    fn hdr(h: u64, prev: Hash256, ts: u64) -> (BlockHeader, Hash256) {
        let header = BlockHeader {
            version: BLOCK_VERSION_LEGACY,
            height: BlockHeight(h),
            prev_hash: prev,
            timestamp: Timestamp(ts),
            output_root: Hash256::ZERO,
            kernel_root: Hash256::ZERO,
            rangeproof_root: Hash256::ZERO,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(0x1f00_ffff),
            total_difficulty: U256::one(),
            pow: ProofOfWork {
                nonce: h,
                randomx_hash: Hash256::ZERO,
            },
        };
        let bytes = header.to_bytes().expect("serialize");
        let hash = compute_block_hash(&bytes);
        (header, hash)
    }

    /// Store a header as a NON-canonical branch block (no height index) — the
    /// exact state of a side-branch block during a reorg.
    fn store_branch(chain: &ChainState, h: &BlockHeader, hash: Hash256) {
        let bytes = h.to_bytes().expect("serialize");
        chain
            .store
            .store_known_block(hash.as_bytes(), &bytes, &[0xCC; 4])
            .expect("store branch");
    }

    /// A2-005: a side-branch chain of 11 blocks (NONE canonical) must still
    /// yield a full 11-timestamp window walked via prev_hash. The pre-fix
    /// canonical-index version would return an EMPTY window here (none of these
    /// blocks are in the height index), disabling the MTP check for the branch.
    #[test]
    fn a2_005_mtp_window_walks_branch_not_canonical_index() {
        let (_dir, chain) = chain();

        // Chain 12 side-branch blocks (heights 0..=11), each with a distinct
        // timestamp, linked by prev_hash. NONE are committed to the height index.
        let mut prev = Hash256::ZERO;
        let mut hashes = Vec::new();
        for h in 0..=11u64 {
            let ts = 1_000 + h * 100; // distinct, increasing
            let (header, hash) = hdr(h, prev, ts);
            store_branch(&chain, &header, hash);
            hashes.push(hash);
            prev = hash;
        }

        // Parent of a hypothetical block at height 12 is the height-11 tip.
        let parent = hashes[11];
        let window = chain
            .get_recent_timestamps(parent, 11)
            .expect("collect window");

        // The fix walks prev_hash and finds all 11 — even though none are
        // canonical. Pre-fix (canonical index) would find zero.
        assert_eq!(
            window.len(),
            11,
            "A2-005: MTP window must be walked from the branch, not the canonical index"
        );

        // And they must be the BRANCH's timestamps (heights 11 down to 1), in
        // walk order (parent first).
        let got: Vec<u64> = window.iter().map(|t| t.0).collect();
        let want: Vec<u64> = (1..=11u64).rev().map(|h| 1_000 + h * 100).collect();
        assert_eq!(got, want, "window must contain the branch's own timestamps");
    }

    /// A2-005 non-regression: fewer than `count` blocks in the ancestry returns
    /// a short window (genuinely early chain), which validate_median_time_past
    /// legitimately skips. The walk must stop cleanly at genesis (prev ZERO).
    #[test]
    fn a2_005_short_chain_stops_at_genesis() {
        let (_dir, chain) = chain();
        let mut prev = Hash256::ZERO;
        let mut last = Hash256::ZERO;
        for h in 0..=3u64 {
            let (header, hash) = hdr(h, prev, 1_000 + h * 100);
            store_branch(&chain, &header, hash);
            prev = hash;
            last = hash;
        }
        let window = chain.get_recent_timestamps(last, 11).expect("collect");
        // Only 4 blocks exist (heights 0..=3); parent is height 3, walk yields
        // heights 3,2,1,0 = 4 timestamps, then stops at ZERO.
        assert_eq!(
            window.len(),
            4,
            "short chain yields a short window, walk stops at genesis"
        );
    }
}

#[cfg(test)]
mod xdiff_hash_parity_tests {
    //! dom-shield XDIFF — the two private header-hash functions in this crate
    //! MUST agree byte-for-byte. `chain_state::compute_block_hash` is used by
    //! the live connect/validate path and `ibd::compute_hash` by the headers-
    //! first IBD path. If they ever diverged (e.g. one switched digest, domain,
    //! or input framing), an IBD-validated header would map to a different block
    //! hash than the same header connected live: duplicate suppression, parent
    //! linkage and reorg ancestry would silently split between the two paths.
    use super::compute_block_hash;
    use crate::ibd::compute_hash_probe;

    fn check(bytes: &[u8]) {
        assert_eq!(
            compute_block_hash(bytes).as_bytes(),
            &compute_hash_probe(bytes),
            "ibd::compute_hash and chain_state::compute_block_hash diverged for input len {}",
            bytes.len()
        );
    }

    #[test]
    fn empty_input_parity() {
        check(&[]);
    }

    #[test]
    fn header_sized_and_varied_inputs_parity() {
        // A spread of lengths and byte patterns, including a realistic header
        // length and adversarial all-zero / all-0xFF buffers.
        check(&[0u8; 1]);
        check(&[0xFFu8; 32]);
        check(&[0xABu8; 200]);
        let ramp: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        check(&ramp);
        let mut x = 0x9E3779B97F4A7C15u64;
        let pseudo: Vec<u8> = (0..512)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        check(&pseudo);
    }
}
