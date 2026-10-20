//! Native USDOM consensus-state transition core.
//!
//! This crate owns monetary replay protection and authenticated state shape. It
//! deliberately does not contain a fake privacy verifier: production transition
//! capabilities must be created by reviewed deposit and zero-knowledge proof
//! verifiers. The state machine then enforces one-time deposits, note uniqueness,
//! nullifier uniqueness, burn uniqueness, supply bounds, accepted note anchors,
//! deterministic roots, and exact undo.

#![deny(unsafe_code)]
#![deny(missing_docs)]

mod sparse;
pub use sparse::{
    sparse_root, SparseMerkleProof, SparseMerkleTree, SparseProofError, MAX_SPARSE_PROOF_BYTES,
    MAX_SPARSE_TREE_SNAPSHOT_BYTES,
};

#[cfg(all(feature = "unsafe-test-oracle", not(debug_assertions)))]
compile_error!("unsafe-test-oracle is forbidden in release builds");

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use dom_core::{blake2b_256_tagged, Hash256, MAX_FUTURE_BLOCK_TIME};
use dom_pmmr::{Pmmr, PmmrFrontier, MAX_FRONTIER_BYTES};
#[cfg(feature = "ethereum-finality")]
use dom_usdom_privacy::privacy_policy_hash;
use dom_usdom_privacy::{
    chain_scalar as privacy_chain_scalar, circuit::SpendStatement, effect_scalar, issuance_rho,
    memo_scalar, verifier::SpendVerifier, NoteOpening, NOTE_ORIGIN_ISSUANCE,
};
use dom_usdom_privacy::{
    IncrementalNoteTree, Scalar as PrivacyScalar, MAX_NOTE_TREE_FRONTIER_BYTES,
};
use sha3::{Digest, Keccak256};
use thiserror::Error;

#[cfg(feature = "ethereum-finality")]
use usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint;
#[cfg(feature = "ethereum-finality")]
use usdom_ethereum_finality_experiment::deposits::VerifiedDeposit;

const TAG_STATE: &str = "DOM:usdom-state:v1";
const TAG_STATE_V2: &str = "DOM:usdom-state:v2";
const TAG_SET_EMPTY: &str = "DOM:usdom-set-empty:v1";
const TAG_SET_LEAF: &str = "DOM:usdom-set-leaf:v1";
const TAG_SET_NODE: &str = "DOM:usdom-set-node:v1";
const TAG_ANCHOR_LEAF: &str = "DOM:usdom-anchor-leaf:v1";
const TAG_NOTE_PAYLOAD: &str = "DOM:usdom-note-payload:v1";
const TAG_TRANSITION: &str = "DOM:usdom-transition:v2";
const TAG_PRIVATE_TRANSFER_PAYLOAD: &str = "DOM:usdom-wallet-private-transfer:v1";
const TAG_PRIVATE_BURN_PAYLOAD: &str = "DOM:usdom-wallet-private-burn:v1";
const TAG_BATCH_EMPTY: &str = "DOM:usdom-batch-empty:v1";
const TAG_BATCH_LEAF: &str = "DOM:usdom-batch-leaf:v1";
const TAG_BATCH_NODE: &str = "DOM:usdom-batch-node:v1";
const TAG_BATCH_COMMITMENT: &str = "DOM:usdom-batch-commitment:v2";
const TAG_BATCH_COMMITMENT_V2_STATE: &str = "DOM:usdom-batch-commitment:v3";
const BATCH_UNDO_MAGIC: &[u8; 8] = b"USDBAT03";
const TRANSITION_PROJECTION_MAGIC: &[u8; 8] = b"UDPRJ001";
const BURN_WITNESS_MAGIC: &[u8; 8] = b"USDBRN03";
const PRIVATE_TRANSFER_MAGIC: &[u8; 8] = b"UDSPTR01";
const PRIVATE_BURN_MAGIC: &[u8; 8] = b"UDSPBR01";
const SPARSE_NOTE_SET: u8 = 1;
const SPARSE_NULLIFIER_SET: u8 = 2;
const SPARSE_DEPOSIT_SET: u8 = 3;
const SPARSE_BURN_SET: u8 = 4;
const SPARSE_BURN_REQUEST_SET: u8 = 5;
const SPARSE_EXECUTION_ANCHOR_SET: u8 = 6;
const SPARSE_BEACON_ANCHOR_SET: u8 = 7;
const ACCUMULATOR_WITNESS_MAGIC: &[u8; 8] = b"UDAFRT01";
const ACCUMULATOR_WITNESS_HEADER_BYTES: usize = 8 + 2 + 2 + 2;
const SET_TRANSITION_WITNESS_MAGIC: &[u8; 8] = b"UDNSET01";
const NATIVE_TRANSITION_WITNESS_MAGIC: &[u8; 8] = b"UDNVW001";
const STATE_COMMITMENT_V2_MAGIC: &[u8; 8] = b"UDSTV002";
const STATE_COMMITMENT_V2_VERSION: u16 = 2;
const STATE_COMMITMENT_V2_BASE_BYTES: usize = 727;
const MAX_SET_EFFECTS_PER_TRANSITION: usize = 6;
const GROTH16_PROOF_BYTES: usize = 128;
const PRIVATE_PAYLOAD_HEADER_BYTES: usize = 8 + 32 + 8 + 1 + 1 + 2;
const BURN_RECORD_BYTES: usize = 184;
/// Maximum encrypted wallet memo committed by one private spend proof.
pub const MAX_PRIVATE_MEMO_BYTES: usize = 32 * 1024;
/// Solidity-compatible type used by the native burn and reserve verifier.
pub const BURN_INTENT_TYPE: &str = "BurnIntent(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 validUntil,uint256 ethereumChainId,address reserve)";
/// Canonical type used to derive a burn identifier from authenticated private
/// spend nullifiers and the immutable payout target.
pub const PRIVATE_BURN_ID_TYPE: &str = "PrivateBurnId(bytes32 domDomain,bytes32 privacyPolicyHash,bytes32 verifierConfigHash,uint256 ethereumChainId,address reserve,address recipient,uint64 amount,uint64 validUntil,bytes32 nullifier0,bytes32 nullifier1)";

/// Maximum private input nullifiers in one verified transition.
pub const MAX_INPUT_NULLIFIERS: usize = 2;
/// Maximum output note commitments in one verified transition.
pub const MAX_OUTPUT_NOTES: usize = 2;
/// Maximum canonical private-transfer payload accepted before proof parsing.
pub const MAX_PRIVATE_TRANSFER_PAYLOAD_BYTES: usize = PRIVATE_PAYLOAD_HEADER_BYTES
    + MAX_INPUT_NULLIFIERS * 32
    + MAX_OUTPUT_NOTES * 32
    + MAX_PRIVATE_MEMO_BYTES
    + GROTH16_PROOF_BYTES;
/// Maximum canonical private-burn payload accepted before proof parsing.
pub const MAX_PRIVATE_BURN_PAYLOAD_BYTES: usize =
    MAX_PRIVATE_TRANSFER_PAYLOAD_BYTES + BURN_RECORD_BYTES;
/// Number of recent note-tree anchors accepted by the state machine.
pub const NOTE_ANCHOR_HISTORY: usize = 256;

/// Stable identifier of the exact canonical private-transfer payload bytes.
///
/// This is an observation and reconciliation identifier, not proof authority:
/// callers must still parse and verify the payload before accepting any state
/// transition. Randomized proofs intentionally give independently constructed
/// spends distinct identifiers even when they consume the same notes.
pub fn private_transfer_payload_id(payload: &[u8]) -> Hash256 {
    blake2b_256_tagged(TAG_PRIVATE_TRANSFER_PAYLOAD, payload)
}
/// Stable identifier of the exact canonical private-burn payload bytes.
///
/// This identifier is domain-separated from transfers and grants no proof or
/// consensus authority by itself.
pub fn private_burn_payload_id(payload: &[u8]) -> Hash256 {
    blake2b_256_tagged(TAG_PRIVATE_BURN_PAYLOAD, payload)
}
/// Maximum canonical encoded undo size for one transition.
pub const MAX_UNDO_BYTES: usize = 16 * 1024;
/// Maximum proof-verified USDOM transitions committed by one DOM block.
pub const MAX_TRANSITIONS_PER_BATCH: usize = 1_024;
/// Canonical consensus-commitment encoding. Version 2 binds the private memo
/// commitment proven by every transfer and burn into the DOM block header.
pub const TRANSITION_COMMITMENT_VERSION: u16 = 2;
/// Canonical transition-batch/header commitment encoding. It advances with
/// transition version 2 so receipts cannot mislabel memo-bound batches as v1.
pub const TRANSITION_BATCH_VERSION: u16 = 2;
/// Candidate batch version that explicitly commits state-root version 2.
pub const CANDIDATE_V2_TRANSITION_BATCH_VERSION: u16 = 3;
/// Maximum persisted exact-undo payload for one transition batch.
pub const MAX_BATCH_UNDO_BYTES: usize =
    MAX_TRANSITIONS_PER_BATCH * (MAX_UNDO_BYTES + MAX_TRANSITION_PROJECTION_BYTES + 8) + 128;
/// Maximum canonical byte length of one public transition-commitment preimage.
pub const MAX_TRANSITION_PROJECTION_BYTES: usize = 512;
/// Maximum sibling hashes in a burn-set inclusion path. The bound covers every
/// possible `u64` leaf count and keeps future witness encodings predictable.
pub const MAX_BURN_INCLUSION_SIBLINGS: usize = 64;
/// Maximum canonical byte length of one native burn-state prover witness.
pub const MAX_BURN_STATE_WITNESS_BYTES: usize = 2_878;
/// Maximum canonical byte length of the two note frontiers and retained
/// anchor-history opening used by a stateless transition verifier.
pub const MAX_ACCUMULATOR_WITNESS_BYTES: usize = ACCUMULATOR_WITNESS_HEADER_BYTES
    + MAX_FRONTIER_BYTES
    + MAX_NOTE_TREE_FRONTIER_BYTES
    + NOTE_ANCHOR_HISTORY * 40;
/// Maximum canonical sparse-set witness for one native transition.
pub const MAX_SET_TRANSITION_WITNESS_BYTES: usize =
    8 + 1 + 1 + MAX_SET_EFFECTS_PER_TRANSITION * (2 + MAX_SPARSE_PROOF_BYTES);
/// Maximum canonical byte length of one complete candidate-v2 transition
/// opening, including both note frontiers and every sparse path.
pub const MAX_NATIVE_TRANSITION_WITNESS_BYTES: usize =
    8 + 4 + 4 + MAX_ACCUMULATOR_WITNESS_BYTES + MAX_SET_TRANSITION_WITNESS_BYTES;
/// Maximum canonical byte length of one persisted candidate-v2 state
/// commitment, including its optional authenticated Ethereum anchor.
pub const MAX_STATE_COMMITMENT_V2_BYTES: usize = STATE_COMMITMENT_V2_BASE_BYTES + 120;
/// Must equal `USDOMProofReserve.MIN_EXECUTION_WINDOW` for protocol v1.
pub const RESERVE_MIN_EXECUTION_WINDOW_SECS: u64 = 60 * 60;
/// Must equal `USDOMProofReserve.MAX_CERTIFICATE_LIFETIME` for protocol v1.
pub const RESERVE_MAX_CERTIFICATE_LIFETIME_SECS: u64 = 7 * 24 * 60 * 60;

/// Native USDOM state-transition failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UsdomStateError {
    /// A required identity, amount, or domain was zero.
    #[error("zero USDOM transition identity")]
    ZeroIdentity,
    /// A transition capability belongs to another USDOM protocol domain.
    #[error("USDOM transition domain mismatch")]
    DomainMismatch,
    /// A burn targets an EVM chain or reserve other than the immutable bridge
    /// identity committed by this native USDOM state.
    #[error("USDOM bridge identity mismatch")]
    BridgeIdentityMismatch,
    /// The DOM block timestamp is zero or cannot support deterministic burn
    /// deadline validation.
    #[error("invalid USDOM block context")]
    InvalidBlockContext,
    /// A burn expires too early for safe relay/execution or too far in the
    /// future for the immutable reserve certificate policy.
    #[error("invalid USDOM burn deadline")]
    InvalidBurnWindow,
    /// A finalized deposit occurrence was already consumed.
    #[error("USDOM deposit already consumed")]
    DepositAlreadyConsumed,
    /// A note commitment already exists or repeats inside the transition.
    #[error("duplicate USDOM note commitment")]
    DuplicateNote,
    /// A nullifier already exists or repeats inside the transition.
    #[error("USDOM nullifier already spent")]
    NullifierAlreadySpent,
    /// A burn identifier already exists.
    #[error("USDOM burn identifier already exists")]
    BurnAlreadyExists,
    /// A withdrawal request identifier already exists on another burn.
    #[error("USDOM burn request identifier already exists")]
    BurnRequestAlreadyExists,
    /// The supplied public obligation is not the canonical Ethereum-compatible
    /// commitment to the native burn intent.
    #[error("USDOM burn intent commitment mismatch")]
    BurnIntentMismatch,
    /// The proof used a note-tree anchor outside the retained consensus window.
    #[error("USDOM note anchor is not retained")]
    UnknownNoteAnchor,
    /// Input/output cardinality is outside the frozen transition bounds.
    #[error("invalid USDOM transition shape")]
    InvalidShape,
    /// Set-like public inputs were not encoded in their unique canonical order.
    #[error("noncanonical USDOM transition ordering")]
    NonCanonicalOrder,
    /// A monetary counter overflowed.
    #[error("USDOM monetary counter overflow")]
    MonetaryOverflow,
    /// A burn would exceed all issued, unburned USDOM.
    #[error("USDOM burn exceeds outstanding supply")]
    BurnExceedsSupply,
    /// Ethereum anchors conflict at one height or regress inconsistently.
    #[error("conflicting Ethereum finality anchor")]
    EthereumAnchorConflict,
    /// An authenticated checkpoint did not strictly advance finalized
    /// Ethereum consensus time.
    #[error("Ethereum finality anchor did not advance")]
    EthereumAnchorNotAdvanced,
    /// Undo does not apply to the exact current state.
    #[error("USDOM undo does not match current state")]
    UndoMismatch,
    /// Persisted undo bytes are malformed or noncanonical.
    #[error("malformed USDOM undo")]
    MalformedUndo,
    /// Persisted canonical state entries are incomplete or malformed.
    #[error("malformed USDOM persisted state")]
    MalformedPersistedState,
    /// A native burn-state prover witness is truncated, oversized,
    /// noncanonical, or internally inconsistent.
    #[error("malformed USDOM burn-state witness")]
    MalformedBurnWitness,
    /// A transported PMMR/Poseidon/anchor-history opening was malformed.
    #[error("malformed USDOM accumulator witness")]
    MalformedAccumulatorWitness,
    /// A transported native sparse-set transition witness was malformed.
    #[error("malformed USDOM sparse-set transition witness")]
    MalformedSetWitness,
    /// A candidate-v2 state decomposition violates its committed invariants.
    #[error("invalid candidate-v2 native state commitment")]
    InvalidV2Commitment,
    /// Persisted state bytes do not reproduce their committed state root.
    #[error("USDOM persisted state root mismatch")]
    PersistedStateRootMismatch,
    /// The authenticated note accumulator rejected an internal operation.
    #[error("USDOM note accumulator failure: {0}")]
    NoteAccumulator(String),
    /// An experimental authenticated-set cache violated its invariants.
    #[error("USDOM authenticated-set cache failure: {0}")]
    AuthenticatedSetCache(String),
    /// A note commitment was not a canonical nonzero BN254 scalar.
    #[error("noncanonical USDOM private note commitment")]
    InvalidPrivacyCommitment,
    /// A nullifier was not a canonical nonzero BN254 scalar.
    #[error("noncanonical USDOM private nullifier")]
    InvalidPrivacyNullifier,
    /// A private transfer or burn proof was malformed or did not verify.
    #[error("invalid USDOM private spend proof")]
    InvalidPrivacyProof,
    /// A block attempted to commit more USDOM transitions than the consensus
    /// envelope permits.
    #[error("too many USDOM transitions in one batch")]
    BatchTooLarge,
}

/// Ethereum execution/beacon identity authenticated by the finality verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthereumAnchor {
    /// Ethereum consensus-chain identity fixed by the Beacon genesis.
    pub genesis_validators_root: [u8; 32],
    /// Finalized execution block number.
    pub execution_block_number: u64,
    /// Finalized execution block hash.
    pub execution_block_hash: [u8; 32],
    /// Timestamp committed by the finalized Ethereum execution payload.
    pub execution_block_timestamp: u64,
    /// Beacon slot of the finalized checkpoint authenticating this execution
    /// block, which may be later than the block containing the deposit.
    pub beacon_slot: u64,
    /// Root of that finalized Beacon checkpoint.
    pub beacon_root: [u8; 32],
}

/// Immutable EVM payout identity for one native USDOM state domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeIdentity {
    /// Protocol/domain separator shared with the reserve proof statement.
    pub dom_domain: [u8; 32],
    /// Ethereum Beacon genesis validators root; unlike chain ID, this pins the
    /// exact consensus chain whose finality proofs may authorize issuance.
    pub ethereum_genesis_validators_root: [u8; 32],
    /// Target EVM chain identifier as a canonical uint256 big-endian word.
    pub ethereum_chain_id: [u8; 32],
    /// Domain-separated commitment to the immutable Ethereum checkpoint trust
    /// policy: bootstrap, forks, registry, runtime and configuration identity.
    /// The per-block maximum slot is derived from the DOM timestamp and is not
    /// part of this immutable value.
    pub ethereum_checkpoint_policy_hash: [u8; 32],
    /// Domain-separated commitment to the immutable Ethereum deposit verifier
    /// policy, including finality bootstrap, reserve runtime and amount cap.
    pub ethereum_deposit_policy_hash: [u8; 32],
    /// Immutable native note/accumulator cryptographic policy.
    pub privacy_policy_hash: [u8; 32],
    /// Immutable Groth16 spend-verifier configuration.
    pub privacy_verifier_config_hash: [u8; 32],
    /// Immutable proof reserve deployed on that chain.
    pub reserve: [u8; 20],
    /// Deadline policy that must equal the immutable reserve rules and include
    /// conservative cross-chain relay/clock margins.
    pub burn_timing: BurnTimingPolicy,
}

/// Immutable native admission policy for Ethereum redemption deadlines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BurnTimingPolicy {
    /// Delay enforced by the Ethereum reserve after proof admission.
    pub withdrawal_delay_secs: u64,
    /// Minimum execution window required by the Ethereum reserve.
    pub min_execution_window_secs: u64,
    /// Maximum certificate lifetime accepted by the Ethereum reserve.
    pub max_certificate_lifetime_secs: u64,
    /// Time reserved for finality proof generation and Ethereum admission.
    pub relay_safety_margin_secs: u64,
    /// Maximum age of the latest authenticated Ethereum execution timestamp
    /// relative to the DOM block admitting a burn.
    pub max_ethereum_anchor_age_secs: u64,
    /// Maximum permitted lead of the DOM block timestamp over Ethereum time.
    pub max_dom_clock_lead_secs: u64,
}

impl BurnTimingPolicy {
    fn validate(self) -> Result<(), UsdomStateError> {
        if self.withdrawal_delay_secs == 0
            || self.min_execution_window_secs == 0
            || self.max_certificate_lifetime_secs == 0
            || self.relay_safety_margin_secs == 0
            || self.max_ethereum_anchor_age_secs == 0
            || self.max_dom_clock_lead_secs == 0
        {
            return Err(UsdomStateError::ZeroIdentity);
        }
        if self.min_execution_window_secs != RESERVE_MIN_EXECUTION_WINDOW_SECS
            || self.max_certificate_lifetime_secs != RESERVE_MAX_CERTIFICATE_LIFETIME_SECS
            || self.max_dom_clock_lead_secs < MAX_FUTURE_BLOCK_TIME
            || self.relay_safety_margin_secs < self.max_ethereum_anchor_age_secs
        {
            return Err(UsdomStateError::InvalidBurnWindow);
        }
        let minimum = self
            .withdrawal_delay_secs
            .checked_add(self.min_execution_window_secs)
            .and_then(|value| value.checked_add(self.relay_safety_margin_secs))
            .ok_or(UsdomStateError::InvalidBurnWindow)?;
        let maximum = self
            .max_certificate_lifetime_secs
            .checked_sub(self.max_dom_clock_lead_secs)
            .ok_or(UsdomStateError::InvalidBurnWindow)?;
        if minimum > maximum {
            return Err(UsdomStateError::InvalidBurnWindow);
        }
        Ok(())
    }
}

/// Consensus context shared by every USDOM transition in one DOM block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockContext {
    /// Authenticated DOM block timestamp in Unix seconds.
    pub timestamp: u64,
}

impl BridgeIdentity {
    fn validate(self) -> Result<(), UsdomStateError> {
        if self.dom_domain == [0; 32]
            || self.ethereum_genesis_validators_root == [0; 32]
            || self.ethereum_chain_id == [0; 32]
            || self.ethereum_checkpoint_policy_hash == [0; 32]
            || self.ethereum_deposit_policy_hash == [0; 32]
            || self.privacy_policy_hash == [0; 32]
            || self.privacy_verifier_config_hash == [0; 32]
            || self.reserve == [0; 20]
        {
            return Err(UsdomStateError::ZeroIdentity);
        }
        self.burn_timing.validate()?;
        Ok(())
    }
}

impl EthereumAnchor {
    fn validate(self) -> Result<(), UsdomStateError> {
        if self.genesis_validators_root == [0; 32]
            || self.execution_block_number == 0
            || self.execution_block_hash == [0; 32]
            || self.execution_block_timestamp == 0
            || self.beacon_slot == 0
            || self.beacon_root == [0; 32]
        {
            return Err(UsdomStateError::ZeroIdentity);
        }
        Ok(())
    }
}

/// A note-tree root and the exact number of committed leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteAnchor {
    /// Fixed-depth Poseidon root over canonical note commitments.
    pub root: Hash256,
    /// Number of note leaves covered by `root`.
    pub leaf_count: u64,
}

/// Public burn obligation committed by native consensus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BurnRecord {
    /// Unique bridge obligation identifier.
    pub burn_id: [u8; 32],
    /// Globally unique reserve request identifier. Ethereum reserves reject a
    /// reused request even when the burn identifier differs.
    pub request_id: [u8; 32],
    /// Amount removed from native circulation, in six-decimal base units.
    pub amount: u64,
    /// Immutable Ethereum recipient.
    pub recipient: [u8; 20],
    /// Target EVM chain identifier as one canonical uint256 big-endian word.
    pub ethereum_chain_id: [u8; 32],
    /// Immutable reserve contract on the target EVM chain.
    pub reserve: [u8; 20],
    /// Last Ethereum timestamp at which this intent may be admitted.
    pub valid_until: u64,
    /// Domain-separated commitment consumed by the Ethereum verifier.
    pub obligation_commitment: [u8; 32],
}

impl BurnRecord {
    /// Compute `keccak256(abi.encode(BURN_INTENT_TYPEHASH, ...))` exactly as the
    /// immutable Ethereum reserve does. DOM block/finality identity is added by
    /// the separate finalized-burn statement after this native intent exists.
    pub fn expected_obligation_commitment(&self, dom_domain: [u8; 32]) -> [u8; 32] {
        let type_hash: [u8; 32] = Keccak256::digest(BURN_INTENT_TYPE.as_bytes()).into();
        let mut encoded = Vec::with_capacity(9 * 32);
        encoded.extend_from_slice(&type_hash);
        encoded.extend_from_slice(&self.burn_id);
        encoded.extend_from_slice(&self.request_id);
        encoded.extend_from_slice(&[0; 12]);
        encoded.extend_from_slice(&self.recipient);
        encoded.extend_from_slice(&[0; 24]);
        encoded.extend_from_slice(&self.amount.to_be_bytes());
        encoded.extend_from_slice(&dom_domain);
        encoded.extend_from_slice(&[0; 24]);
        encoded.extend_from_slice(&self.valid_until.to_be_bytes());
        encoded.extend_from_slice(&self.ethereum_chain_id);
        encoded.extend_from_slice(&[0; 12]);
        encoded.extend_from_slice(&self.reserve);
        Keccak256::digest(encoded).into()
    }
}

/// Derive the unique native burn identifier from canonical proof inputs and
/// the immutable payout destination. A relayer cannot choose or replace this
/// identifier independently of the nullifiers authenticated by the spend
/// proof. One-input burns use zero for the absent second nullifier slot.
pub fn derive_private_burn_id(
    bridge: BridgeIdentity,
    nullifiers: &[[u8; 32]],
    recipient: [u8; 20],
    amount: u64,
    valid_until: u64,
) -> Result<[u8; 32], UsdomStateError> {
    bridge.validate()?;
    if recipient == [0; 20]
        || amount == 0
        || valid_until == 0
        || nullifiers.is_empty()
        || nullifiers.len() > MAX_INPUT_NULLIFIERS
        || !strictly_sorted(nullifiers)
    {
        return Err(UsdomStateError::BurnIntentMismatch);
    }
    for nullifier in nullifiers {
        let value = PrivacyScalar::from_bytes(*nullifier)
            .map_err(|_| UsdomStateError::BurnIntentMismatch)?;
        if value.is_zero() {
            return Err(UsdomStateError::BurnIntentMismatch);
        }
    }

    let type_hash: [u8; 32] = Keccak256::digest(PRIVATE_BURN_ID_TYPE.as_bytes()).into();
    let mut encoded = Vec::with_capacity(11 * 32);
    encoded.extend_from_slice(&type_hash);
    encoded.extend_from_slice(&bridge.dom_domain);
    encoded.extend_from_slice(&bridge.privacy_policy_hash);
    encoded.extend_from_slice(&bridge.privacy_verifier_config_hash);
    encoded.extend_from_slice(&bridge.ethereum_chain_id);
    encoded.extend_from_slice(&[0; 12]);
    encoded.extend_from_slice(&bridge.reserve);
    encoded.extend_from_slice(&[0; 12]);
    encoded.extend_from_slice(&recipient);
    encoded.extend_from_slice(&[0; 24]);
    encoded.extend_from_slice(&amount.to_be_bytes());
    encoded.extend_from_slice(&[0; 24]);
    encoded.extend_from_slice(&valid_until.to_be_bytes());
    encoded.extend_from_slice(&nullifiers[0]);
    encoded.extend_from_slice(nullifiers.get(1).unwrap_or(&[0; 32]));
    let identifier: [u8; 32] = Keccak256::digest(encoded).into();
    if identifier == [0; 32] {
        return Err(UsdomStateError::BurnIntentMismatch);
    }
    Ok(identifier)
}

/// Validate one public burn obligation against the immutable bridge and
/// derive the exact scalar committed by the frozen private-spend circuit.
pub fn private_burn_effect_scalar(
    bridge: BridgeIdentity,
    record: BurnRecord,
) -> Result<PrivacyScalar, UsdomStateError> {
    bridge.validate()?;
    if !valid_burn_record(&record)
        || record.ethereum_chain_id != bridge.ethereum_chain_id
        || record.reserve != bridge.reserve
        || record.expected_obligation_commitment(bridge.dom_domain) != record.obligation_commitment
    {
        return Err(UsdomStateError::BurnIntentMismatch);
    }
    let mut effect_bytes = Vec::with_capacity(BURN_RECORD_BYTES);
    encode_burn_record(&mut effect_bytes, record);
    effect_scalar(&effect_bytes).map_err(|_| UsdomStateError::InvalidPrivacyProof)
}

/// Merkle inclusion path for one public burn obligation in the canonical,
/// burn-id-ordered native USDOM burn set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnSetInclusionProof {
    /// Exact public burn record committed by native consensus.
    pub record: BurnRecord,
    /// Zero-based position in the burn-id-ordered leaf set.
    pub leaf_index: u64,
    /// Total leaves committed by the burn-set root.
    pub leaf_count: u64,
    /// Sibling hashes consumed from leaf level toward the root. Odd unpaired
    /// leaves are promoted without adding a sibling.
    pub siblings: Vec<Hash256>,
}

impl BurnSetInclusionProof {
    /// Verify this path against one independently authenticated burn-set root.
    pub fn verify(&self, expected_root: Hash256) -> bool {
        verify_burn_inclusion(self, expected_root)
    }
}

/// Complete public decomposition of one native USDOM composite state root.
/// A proving system may keep any fields private; exposing this Rust value alone
/// does not authenticate a DOM block or establish finality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateCommitment {
    /// Native USDOM protocol domain.
    pub domain: [u8; 32],
    /// Ethereum Beacon chain identity.
    pub ethereum_genesis_validators_root: [u8; 32],
    /// Target EVM chain identifier.
    pub ethereum_chain_id: [u8; 32],
    /// Immutable reserve address.
    pub reserve: [u8; 20],
    /// Immutable Ethereum-checkpoint verification policy.
    pub ethereum_checkpoint_policy_hash: [u8; 32],
    /// Immutable Ethereum deposit-verification policy.
    pub ethereum_deposit_policy_hash: [u8; 32],
    /// Immutable native note/accumulator cryptographic policy.
    pub privacy_policy_hash: [u8; 32],
    /// Immutable Groth16 spend-verifier configuration.
    pub privacy_verifier_config_hash: [u8; 32],
    /// Immutable burn timing policy.
    pub burn_timing: BurnTimingPolicy,
    /// PMMR root of all note commitments.
    pub notes_root: Hash256,
    /// ZK-friendly fixed-depth Poseidon note-tree root.
    pub privacy_notes_root: [u8; 32],
    /// Number of note leaves covered by `notes_root`.
    pub note_count: u64,
    /// Canonical set root of note commitments.
    pub note_set_root: Hash256,
    /// Number of unique note commitments.
    pub note_set_count: u64,
    /// Canonical set root of spent nullifiers.
    pub nullifier_root: Hash256,
    /// Number of spent nullifiers.
    pub nullifier_count: u64,
    /// Canonical set root of consumed Ethereum deposits.
    pub deposit_root: Hash256,
    /// Number of consumed deposits.
    pub deposit_count: u64,
    /// Canonical set root of native burn obligations.
    pub burn_root: Hash256,
    /// Number of native burn obligations.
    pub burn_count: u64,
    /// Root of the retained note-anchor history.
    pub anchor_root: Hash256,
    /// Number of retained note anchors.
    pub anchor_count: u64,
    /// Total deposit-backed USDOM issuance.
    pub total_issued: u128,
    /// Total USDOM removed through native burns.
    pub total_burned: u128,
    /// Latest authenticated Ethereum finality anchor, when initialized.
    pub ethereum_anchor: Option<EthereumAnchor>,
}

impl StateCommitment {
    /// Recompute the exact native USDOM composite state root.
    pub fn root(&self) -> Hash256 {
        state_commitment_root(self)
    }
}

/// Candidate version-2 native state commitment with updateable sparse sets.
///
/// This type is deliberately distinct from [`StateCommitment`]. Constructing
/// or hashing it does not activate v2 consensus; an activation schedule must
/// explicitly select its root semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateCommitmentV2 {
    /// Native USDOM protocol domain.
    pub domain: [u8; 32],
    /// Ethereum Beacon chain identity.
    pub ethereum_genesis_validators_root: [u8; 32],
    /// Target EVM chain identifier.
    pub ethereum_chain_id: [u8; 32],
    /// Immutable reserve address.
    pub reserve: [u8; 20],
    /// Immutable Ethereum checkpoint verification policy.
    pub ethereum_checkpoint_policy_hash: [u8; 32],
    /// Immutable Ethereum deposit verification policy.
    pub ethereum_deposit_policy_hash: [u8; 32],
    /// Immutable native privacy policy.
    pub privacy_policy_hash: [u8; 32],
    /// Immutable spend-verifier configuration.
    pub privacy_verifier_config_hash: [u8; 32],
    /// Immutable burn timing policy.
    pub burn_timing: BurnTimingPolicy,
    /// PMMR root of all note commitments.
    pub notes_root: Hash256,
    /// Poseidon note-tree root.
    pub privacy_notes_root: [u8; 32],
    /// Number of appended notes.
    pub note_count: u64,
    /// Sparse root of unique note commitments.
    pub note_set_root: Hash256,
    /// Number of unique note commitments.
    pub note_set_count: u64,
    /// Sparse root of spent nullifiers.
    pub nullifier_root: Hash256,
    /// Number of spent nullifiers.
    pub nullifier_count: u64,
    /// Sparse root of consumed deposits and issuance records.
    pub deposit_root: Hash256,
    /// Number of consumed deposits.
    pub deposit_count: u64,
    /// Sparse root of native burn records.
    pub burn_root: Hash256,
    /// Number of native burn records.
    pub burn_count: u64,
    /// Sparse root of unique withdrawal request identifiers.
    pub burn_request_root: Hash256,
    /// Number of unique withdrawal request identifiers.
    pub burn_request_count: u64,
    /// Sparse root of finalized execution identities by block number.
    pub execution_anchor_root: Hash256,
    /// Number of unique finalized execution heights used by issuance.
    pub execution_anchor_count: u64,
    /// Sparse root of finalized Beacon identities by slot.
    pub beacon_anchor_root: Hash256,
    /// Number of unique finalized Beacon slots used by issuance.
    pub beacon_anchor_count: u64,
    /// Root of the retained note-anchor history.
    pub anchor_root: Hash256,
    /// Number of retained note anchors.
    pub anchor_count: u64,
    /// Total deposit-backed issuance.
    pub total_issued: u128,
    /// Total native burns.
    pub total_burned: u128,
    /// Latest authenticated Ethereum anchor.
    pub ethereum_anchor: Option<EthereumAnchor>,
}

impl StateCommitmentV2 {
    /// Recompute the domain-separated candidate v2 root.
    pub fn root(&self) -> Hash256 {
        state_commitment_v2_root(self)
    }

    /// Encode the complete candidate-v2 state commitment in one fixed-order,
    /// versioned form suitable for atomic consensus persistence.
    pub fn to_bytes(&self) -> Result<Vec<u8>, UsdomStateError> {
        validate_v2_commitment(self)?;
        let mut bytes = Vec::with_capacity(MAX_STATE_COMMITMENT_V2_BYTES);
        bytes.extend_from_slice(STATE_COMMITMENT_V2_MAGIC);
        encode_state_commitment_v2_body(&mut bytes, self);
        debug_assert!(matches!(
            bytes.len(),
            STATE_COMMITMENT_V2_BASE_BYTES | MAX_STATE_COMMITMENT_V2_BYTES
        ));
        Ok(bytes)
    }

    /// Decode, validate and canonically re-encode one persisted candidate-v2
    /// commitment. Truncation, trailing bytes and invalid state invariants are
    /// rejected before the value can become a trusted chain tip.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, UsdomStateError> {
        if !matches!(
            bytes.len(),
            STATE_COMMITMENT_V2_BASE_BYTES | MAX_STATE_COMMITMENT_V2_BYTES
        ) || bytes.get(..8) != Some(STATE_COMMITMENT_V2_MAGIC.as_slice())
        {
            return Err(UsdomStateError::InvalidV2Commitment);
        }
        let decoded = (|| {
            let mut reader = UndoReader::new(&bytes[8..]);
            if u16::from_be_bytes(reader.array()?) != STATE_COMMITMENT_V2_VERSION {
                return Err(UsdomStateError::InvalidV2Commitment);
            }
            let state = Self {
                domain: reader.array()?,
                ethereum_genesis_validators_root: reader.array()?,
                ethereum_chain_id: reader.array()?,
                reserve: reader.array()?,
                ethereum_checkpoint_policy_hash: reader.array()?,
                ethereum_deposit_policy_hash: reader.array()?,
                privacy_policy_hash: reader.array()?,
                privacy_verifier_config_hash: reader.array()?,
                burn_timing: BurnTimingPolicy {
                    withdrawal_delay_secs: u64::from_be_bytes(reader.array()?),
                    min_execution_window_secs: u64::from_be_bytes(reader.array()?),
                    max_certificate_lifetime_secs: u64::from_be_bytes(reader.array()?),
                    relay_safety_margin_secs: u64::from_be_bytes(reader.array()?),
                    max_ethereum_anchor_age_secs: u64::from_be_bytes(reader.array()?),
                    max_dom_clock_lead_secs: u64::from_be_bytes(reader.array()?),
                },
                notes_root: Hash256::from_bytes(reader.array()?),
                privacy_notes_root: reader.array()?,
                note_count: u64::from_be_bytes(reader.array()?),
                note_set_root: Hash256::from_bytes(reader.array()?),
                note_set_count: u64::from_be_bytes(reader.array()?),
                nullifier_root: Hash256::from_bytes(reader.array()?),
                nullifier_count: u64::from_be_bytes(reader.array()?),
                deposit_root: Hash256::from_bytes(reader.array()?),
                deposit_count: u64::from_be_bytes(reader.array()?),
                burn_root: Hash256::from_bytes(reader.array()?),
                burn_count: u64::from_be_bytes(reader.array()?),
                burn_request_root: Hash256::from_bytes(reader.array()?),
                burn_request_count: u64::from_be_bytes(reader.array()?),
                execution_anchor_root: Hash256::from_bytes(reader.array()?),
                execution_anchor_count: u64::from_be_bytes(reader.array()?),
                beacon_anchor_root: Hash256::from_bytes(reader.array()?),
                beacon_anchor_count: u64::from_be_bytes(reader.array()?),
                anchor_root: Hash256::from_bytes(reader.array()?),
                anchor_count: u64::from_be_bytes(reader.array()?),
                total_issued: u128::from_be_bytes(reader.array()?),
                total_burned: u128::from_be_bytes(reader.array()?),
                ethereum_anchor: match reader.byte()? {
                    0 => None,
                    1 => Some(decode_ethereum_anchor(&mut reader)?),
                    _ => return Err(UsdomStateError::InvalidV2Commitment),
                },
            };
            if !reader.is_empty() {
                return Err(UsdomStateError::InvalidV2Commitment);
            }
            Ok(state)
        })()
        .map_err(|_| UsdomStateError::InvalidV2Commitment)?;
        validate_v2_commitment(&decoded).map_err(|_| UsdomStateError::InvalidV2Commitment)?;
        if decoded.to_bytes()?.as_slice() != bytes {
            return Err(UsdomStateError::InvalidV2Commitment);
        }
        Ok(decoded)
    }

    /// Sparse component roots in the order used by transition witnesses.
    pub const fn authenticated_set_roots(&self) -> NativeAuthenticatedSetRoots {
        NativeAuthenticatedSetRoots {
            notes: self.note_set_root,
            nullifiers: self.nullifier_root,
            deposits: self.deposit_root,
            burns: self.burn_root,
            burn_requests: self.burn_request_root,
            execution_anchors: self.execution_anchor_root,
            beacon_anchors: self.beacon_anchor_root,
        }
    }
}

/// Candidate roots for a future versioned native authenticated-set migration.
///
/// These roots mirror current state updates but are deliberately excluded from
/// the v1 native consensus root until persistence, witness and activation rules
/// are complete and independently reviewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeAuthenticatedSetRoots {
    /// Unique native note commitments.
    pub notes: Hash256,
    /// Spent private nullifiers.
    pub nullifiers: Hash256,
    /// Consumed Ethereum deposit identifiers and issuance records.
    pub deposits: Hash256,
    /// Native public burn records.
    pub burns: Hash256,
    /// Unique Ethereum withdrawal request identifiers.
    pub burn_requests: Hash256,
    /// Finalized execution identities keyed by block number.
    pub execution_anchors: Hash256,
    /// Finalized Beacon identities keyed by slot.
    pub beacon_anchors: Hash256,
}

/// Bounded private opening of both append-only note accumulators and the
/// retained anchor-history root in one native state commitment.
#[derive(Debug, Clone)]
pub struct NativeAccumulatorWitness {
    pmmr: PmmrFrontier,
    privacy_notes: IncrementalNoteTree,
    anchors: VecDeque<NoteAnchor>,
}

/// Canonical sequential nonmembership proofs for every insert-only set effect
/// of one proof-verified native transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSetTransitionWitness {
    proofs: Vec<SparseMerkleProof>,
    existing: Vec<bool>,
}

/// Complete bounded opening needed to advance one candidate-v2 native state
/// after the transition capability itself has been cryptographically verified.
#[derive(Debug, Clone)]
pub struct NativeTransitionWitness {
    accumulators: NativeAccumulatorWitness,
    sets: NativeSetTransitionWitness,
}

#[derive(Debug, Clone, Copy)]
struct NativeSetEffect {
    kind: u8,
    key: [u8; 32],
    leaf: Hash256,
    allow_existing: bool,
}

impl NativeSetTransitionWitness {
    /// Number of authenticated insertions in this transition.
    pub fn effect_count(&self) -> usize {
        self.proofs.len()
    }

    /// Apply the exact transition effects to a candidate v2 commitment.
    /// Accumulator roots, monetary counters and Ethereum anchors are advanced
    /// separately by the complete transition relation.
    pub fn apply_sets(
        &self,
        previous: StateCommitmentV2,
        transition: &VerifiedTransition,
    ) -> Result<StateCommitmentV2, UsdomStateError> {
        if transition_domain(transition) != previous.domain {
            return Err(UsdomStateError::DomainMismatch);
        }
        let effects = native_set_effects(transition);
        if effects.len() != self.proofs.len()
            || effects.len() != self.existing.len()
            || effects.len() > MAX_SET_EFFECTS_PER_TRANSITION
        {
            return Err(UsdomStateError::MalformedSetWitness);
        }
        let mut candidate = previous;
        for ((proof, existing), effect) in self.proofs.iter().zip(&self.existing).zip(effects) {
            if proof.kind() != effect.kind || proof.key() != effect.key {
                return Err(UsdomStateError::MalformedSetWitness);
            }
            let (root, count) = v2_sparse_component_mut(&mut candidate, effect.kind)?;
            if *existing && !effect.allow_existing {
                return Err(UsdomStateError::MalformedSetWitness);
            }
            *root = proof
                .update_root(*root, existing.then_some(effect.leaf), Some(effect.leaf))
                .map_err(|_| UsdomStateError::MalformedSetWitness)?;
            if !existing {
                *count = count
                    .checked_add(1)
                    .ok_or(UsdomStateError::MonetaryOverflow)?;
            }
        }
        Ok(candidate)
    }

    /// Encode the unique bounded `UDNSET01` witness.
    pub fn to_bytes(&self) -> Result<Vec<u8>, UsdomStateError> {
        if self.proofs.len() != self.existing.len()
            || self.proofs.len() > MAX_SET_EFFECTS_PER_TRANSITION
        {
            return Err(UsdomStateError::MalformedSetWitness);
        }
        let count: u8 = self
            .proofs
            .len()
            .try_into()
            .map_err(|_| UsdomStateError::MalformedSetWitness)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SET_TRANSITION_WITNESS_MAGIC);
        bytes.push(count);
        let mut existing_flags = 0u8;
        for (index, existing) in self.existing.iter().enumerate() {
            if *existing {
                existing_flags |= 1 << index;
            }
        }
        bytes.push(existing_flags);
        for proof in &self.proofs {
            let encoded = proof
                .to_bytes()
                .map_err(|_| UsdomStateError::MalformedSetWitness)?;
            let length: u16 = encoded
                .len()
                .try_into()
                .map_err(|_| UsdomStateError::MalformedSetWitness)?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(&encoded);
        }
        if bytes.len() > MAX_SET_TRANSITION_WITNESS_BYTES {
            return Err(UsdomStateError::MalformedSetWitness);
        }
        Ok(bytes)
    }

    /// Decode and canonically re-encode one `UDNSET01` witness.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, UsdomStateError> {
        if bytes.len() < 10
            || bytes.len() > MAX_SET_TRANSITION_WITNESS_BYTES
            || &bytes[..8] != SET_TRANSITION_WITNESS_MAGIC
        {
            return Err(UsdomStateError::MalformedSetWitness);
        }
        let count = usize::from(bytes[8]);
        let existing_flags = bytes[9];
        if count > MAX_SET_EFFECTS_PER_TRANSITION {
            return Err(UsdomStateError::MalformedSetWitness);
        }
        let permitted_flags = if count == 0 { 0 } else { (1u8 << count) - 1 };
        if existing_flags & !permitted_flags != 0 {
            return Err(UsdomStateError::MalformedSetWitness);
        }
        let mut cursor = 10usize;
        let mut proofs = Vec::with_capacity(count);
        let mut existing = Vec::with_capacity(count);
        for _ in 0..count {
            let length = usize::from(u16::from_be_bytes(
                bytes
                    .get(cursor..cursor + 2)
                    .ok_or(UsdomStateError::MalformedSetWitness)?
                    .try_into()
                    .map_err(|_| UsdomStateError::MalformedSetWitness)?,
            ));
            cursor = cursor
                .checked_add(2)
                .ok_or(UsdomStateError::MalformedSetWitness)?;
            let end = cursor
                .checked_add(length)
                .ok_or(UsdomStateError::MalformedSetWitness)?;
            let proof = SparseMerkleProof::from_bytes(
                bytes
                    .get(cursor..end)
                    .ok_or(UsdomStateError::MalformedSetWitness)?,
            )
            .map_err(|_| UsdomStateError::MalformedSetWitness)?;
            proofs.push(proof);
            existing.push(existing_flags & (1 << existing.len()) != 0);
            cursor = end;
        }
        if cursor != bytes.len() {
            return Err(UsdomStateError::MalformedSetWitness);
        }
        let witness = Self { proofs, existing };
        if witness.to_bytes()?.as_slice() != bytes {
            return Err(UsdomStateError::MalformedSetWitness);
        }
        Ok(witness)
    }
}

impl NativeTransitionWitness {
    /// Apply one proof-authorized transition without access to historical
    /// notes or complete replay-protection sets.
    pub fn apply_v2(
        &self,
        expected_previous_root: Hash256,
        context: BlockContext,
        previous: StateCommitmentV2,
        transition: &VerifiedTransition,
    ) -> Result<StateCommitmentV2, UsdomStateError> {
        if expected_previous_root == Hash256::ZERO || previous.root() != expected_previous_root {
            return Err(UsdomStateError::InvalidV2Commitment);
        }
        validate_v2_commitment(&previous)?;
        if context.timestamp == 0 {
            return Err(UsdomStateError::InvalidBlockContext);
        }
        if !self.accumulators.verify_v2(&previous) {
            return Err(UsdomStateError::MalformedAccumulatorWitness);
        }
        let mut candidate = self.sets.apply_sets(previous, transition)?;
        let mut accumulators = self.accumulators.clone();
        match transition {
            VerifiedTransition::Issue(value) => {
                value.ethereum_anchor.validate()?;
                if value.ethereum_anchor.genesis_validators_root
                    != previous.ethereum_genesis_validators_root
                {
                    return Err(UsdomStateError::BridgeIdentityMismatch);
                }
                if value.deposit_id == [0; 32]
                    || value.note_commitment == [0; 32]
                    || value.amount == 0
                {
                    return Err(UsdomStateError::ZeroIdentity);
                }
                candidate.total_issued = previous
                    .total_issued
                    .checked_add(u128::from(value.amount))
                    .ok_or(UsdomStateError::MonetaryOverflow)?;
                candidate.ethereum_anchor =
                    merge_ethereum_anchor(previous.ethereum_anchor, Some(value.ethereum_anchor))?;
                accumulators.append_transition(previous.domain, &[value.note_commitment])?;
            }
            VerifiedTransition::Transfer(value) => {
                validate_shape(&value.nullifiers, &value.output_notes, false)?;
                if !accumulators.anchors.contains(&value.anchor) {
                    return Err(UsdomStateError::UnknownNoteAnchor);
                }
                accumulators.append_transition(previous.domain, &value.output_notes)?;
            }
            VerifiedTransition::Burn(value) => {
                validate_stateless_burn(context, &previous, &accumulators, value)?;
                candidate.total_burned = previous
                    .total_burned
                    .checked_add(u128::from(value.record.amount))
                    .ok_or(UsdomStateError::MonetaryOverflow)?;
                if candidate.total_burned > previous.total_issued {
                    return Err(UsdomStateError::BurnExceedsSupply);
                }
                accumulators.append_transition(previous.domain, &value.change_notes)?;
            }
            VerifiedTransition::EthereumCheckpoint(value) => {
                value.anchor.validate()?;
                if value.anchor.genesis_validators_root != previous.ethereum_genesis_validators_root
                {
                    return Err(UsdomStateError::BridgeIdentityMismatch);
                }
                let next = merge_ethereum_anchor(previous.ethereum_anchor, Some(value.anchor))?;
                if next == previous.ethereum_anchor {
                    return Err(UsdomStateError::EthereumAnchorNotAdvanced);
                }
                candidate.ethereum_anchor = next;
                accumulators.append_transition(previous.domain, &[])?;
            }
        }
        candidate = accumulators.update_v2(candidate)?;
        validate_v2_commitment(&candidate)?;
        Ok(candidate)
    }

    /// Sparse-set portion of this complete witness.
    pub const fn set_witness(&self) -> &NativeSetTransitionWitness {
        &self.sets
    }

    /// Encode the unique bounded `UDNVW001` composite witness.
    pub fn to_bytes(&self) -> Result<Vec<u8>, UsdomStateError> {
        let accumulators = self.accumulators.to_bytes()?;
        let sets = self.sets.to_bytes()?;
        let accumulator_length: u32 = accumulators
            .len()
            .try_into()
            .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?;
        let set_length: u32 = sets
            .len()
            .try_into()
            .map_err(|_| UsdomStateError::MalformedSetWitness)?;
        let mut bytes = Vec::with_capacity(16 + accumulators.len() + sets.len());
        bytes.extend_from_slice(NATIVE_TRANSITION_WITNESS_MAGIC);
        bytes.extend_from_slice(&accumulator_length.to_be_bytes());
        bytes.extend_from_slice(&set_length.to_be_bytes());
        bytes.extend_from_slice(&accumulators);
        bytes.extend_from_slice(&sets);
        if bytes.len() > MAX_NATIVE_TRANSITION_WITNESS_BYTES {
            return Err(UsdomStateError::MalformedAccumulatorWitness);
        }
        Ok(bytes)
    }

    /// Decode and canonically re-encode one `UDNVW001` witness.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, UsdomStateError> {
        if bytes.len() < 16
            || bytes.len() > MAX_NATIVE_TRANSITION_WITNESS_BYTES
            || &bytes[..8] != NATIVE_TRANSITION_WITNESS_MAGIC
        {
            return Err(UsdomStateError::MalformedAccumulatorWitness);
        }
        let accumulator_length = usize::try_from(u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?,
        ))
        .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?;
        let set_length = usize::try_from(u32::from_be_bytes(
            bytes[12..16]
                .try_into()
                .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?,
        ))
        .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?;
        let accumulator_end = 16usize
            .checked_add(accumulator_length)
            .ok_or(UsdomStateError::MalformedAccumulatorWitness)?;
        let end = accumulator_end
            .checked_add(set_length)
            .ok_or(UsdomStateError::MalformedAccumulatorWitness)?;
        if end != bytes.len() {
            return Err(UsdomStateError::MalformedAccumulatorWitness);
        }
        let witness = Self {
            accumulators: NativeAccumulatorWitness::from_bytes(&bytes[16..accumulator_end])?,
            sets: NativeSetTransitionWitness::from_bytes(&bytes[accumulator_end..end])?,
        };
        if witness.to_bytes()?.as_slice() != bytes {
            return Err(UsdomStateError::MalformedAccumulatorWitness);
        }
        Ok(witness)
    }
}

/// Execute one bounded ordered transition batch from an authenticated
/// candidate-v2 root using only per-transition bounded witnesses.
pub fn apply_v2_transition_batch(
    expected_previous_root: Hash256,
    context: BlockContext,
    previous: StateCommitmentV2,
    transitions: &[VerifiedTransition],
    witnesses: &[NativeTransitionWitness],
) -> Result<StateCommitmentV2, UsdomStateError> {
    if transitions.len() > MAX_TRANSITIONS_PER_BATCH {
        return Err(UsdomStateError::BatchTooLarge);
    }
    if transitions.len() != witnesses.len() {
        return Err(UsdomStateError::MalformedSetWitness);
    }
    let mut state = previous;
    let mut expected = expected_previous_root;
    for (transition, witness) in transitions.iter().zip(witnesses) {
        state = witness.apply_v2(expected, context, state, transition)?;
        expected = state.root();
    }
    if transitions.is_empty() {
        validate_v2_commitment(&state)?;
        if expected == Hash256::ZERO || state.root() != expected {
            return Err(UsdomStateError::InvalidV2Commitment);
        }
    }
    Ok(state)
}

/// Execute a candidate-v2 batch and derive the version-3 header commitment.
/// The explicit state-version word prevents v1 and v2 roots from sharing one
/// batch-commitment interpretation.
pub fn apply_v2_transition_batch_with_receipt(
    expected_previous_root: Hash256,
    context: BlockContext,
    previous: StateCommitmentV2,
    transitions: &[VerifiedTransition],
    witnesses: &[NativeTransitionWitness],
) -> Result<(StateCommitmentV2, TransitionBatchReceipt), UsdomStateError> {
    let next = apply_v2_transition_batch(
        expected_previous_root,
        context,
        previous,
        transitions,
        witnesses,
    )?;
    let commitments: Vec<_> = transitions
        .iter()
        .map(VerifiedTransition::consensus_commitment)
        .collect::<Result<_, _>>()?;
    let transitions_root = transition_batch_root(previous.domain, &commitments)?;
    let transition_count: u32 = transitions
        .len()
        .try_into()
        .map_err(|_| UsdomStateError::BatchTooLarge)?;
    let mut bytes = Vec::with_capacity(144);
    bytes.extend_from_slice(&CANDIDATE_V2_TRANSITION_BATCH_VERSION.to_be_bytes());
    bytes.extend_from_slice(&2u16.to_be_bytes());
    bytes.extend_from_slice(&previous.domain);
    bytes.extend_from_slice(&transition_count.to_be_bytes());
    bytes.extend_from_slice(&context.timestamp.to_be_bytes());
    bytes.extend_from_slice(transitions_root.as_bytes());
    bytes.extend_from_slice(expected_previous_root.as_bytes());
    bytes.extend_from_slice(next.root().as_bytes());
    let receipt = TransitionBatchReceipt {
        version: CANDIDATE_V2_TRANSITION_BATCH_VERSION,
        transition_count,
        block_timestamp: context.timestamp,
        transitions_root,
        previous_state_root: expected_previous_root,
        new_state_root: next.root(),
        header_commitment: blake2b_256_tagged(TAG_BATCH_COMMITMENT_V2_STATE, &bytes),
    };
    Ok((next, receipt))
}

impl NativeAccumulatorWitness {
    /// Verify this complete opening against an independently authenticated
    /// native state commitment.
    pub fn verify(&self, state: &StateCommitment) -> bool {
        self.validate().is_ok()
            && self.pmmr.leaf_count() == state.note_count
            && self.pmmr.root() == state.notes_root
            && self.privacy_notes.leaf_count() == state.note_count
            && self.privacy_notes.root().to_bytes() == state.privacy_notes_root
            && self.anchors.len() as u64 == state.anchor_count
            && anchor_history_root(&self.anchors) == state.anchor_root
            && self.anchors.back()
                == Some(&NoteAnchor {
                    root: Hash256::from_bytes(state.privacy_notes_root),
                    leaf_count: state.note_count,
                })
    }

    /// Verify this opening against the accumulator fields of candidate v2.
    pub fn verify_v2(&self, state: &StateCommitmentV2) -> bool {
        self.validate().is_ok()
            && self.pmmr.leaf_count() == state.note_count
            && self.pmmr.root() == state.notes_root
            && self.privacy_notes.leaf_count() == state.note_count
            && self.privacy_notes.root().to_bytes() == state.privacy_notes_root
            && self.anchors.len() as u64 == state.anchor_count
            && anchor_history_root(&self.anchors) == state.anchor_root
    }

    /// Append every note created by one transition, then retain its new anchor.
    pub fn append_transition(
        &mut self,
        domain: [u8; 32],
        notes: &[[u8; 32]],
    ) -> Result<(), UsdomStateError> {
        if domain == [0; 32] {
            return Err(UsdomStateError::ZeroIdentity);
        }
        let mut unique = BTreeSet::new();
        for note in notes {
            let scalar = PrivacyScalar::from_bytes(*note)
                .map_err(|_| UsdomStateError::InvalidPrivacyCommitment)?;
            if scalar.is_zero() || !unique.insert(*note) {
                return Err(UsdomStateError::InvalidPrivacyCommitment);
            }
        }
        for note in notes {
            let mut payload = Vec::with_capacity(64);
            payload.extend_from_slice(&domain);
            payload.extend_from_slice(note);
            let leaf = blake2b_256_tagged(TAG_NOTE_PAYLOAD, &payload);
            self.pmmr
                .push(leaf.as_bytes())
                .map_err(|error| UsdomStateError::NoteAccumulator(error.to_string()))?;
            self.privacy_notes
                .append(
                    PrivacyScalar::from_bytes(*note)
                        .map_err(|_| UsdomStateError::InvalidPrivacyCommitment)?,
                )
                .map_err(|_| UsdomStateError::InvalidPrivacyCommitment)?;
        }
        let anchor = NoteAnchor {
            root: Hash256::from_bytes(self.privacy_notes.root().to_bytes()),
            leaf_count: self.privacy_notes.leaf_count(),
        };
        if self.anchors.back() != Some(&anchor) {
            self.anchors.push_back(anchor);
            while self.anchors.len() > NOTE_ANCHOR_HISTORY {
                self.anchors.pop_front();
            }
        }
        self.validate()
    }

    /// Copy the verified current frontier roots into a candidate v2 value.
    pub fn update_v2(
        &self,
        previous: StateCommitmentV2,
    ) -> Result<StateCommitmentV2, UsdomStateError> {
        let mut candidate = previous;
        candidate.notes_root = self.pmmr.root();
        candidate.note_count = self.pmmr.leaf_count();
        candidate.privacy_notes_root = self.privacy_notes.root().to_bytes();
        candidate.anchor_root = anchor_history_root(&self.anchors);
        candidate.anchor_count = self.anchors.len() as u64;
        if candidate.note_count != candidate.note_set_count {
            return Err(UsdomStateError::MalformedAccumulatorWitness);
        }
        Ok(candidate)
    }

    /// Current PMMR root and note count.
    pub fn notes_root_and_count(&self) -> (Hash256, u64) {
        (self.pmmr.root(), self.pmmr.leaf_count())
    }

    /// Current Poseidon note-tree root.
    pub fn privacy_notes_root(&self) -> [u8; 32] {
        self.privacy_notes.root().to_bytes()
    }

    /// Current retained anchor-history root and count.
    pub fn anchor_root_and_count(&self) -> (Hash256, u64) {
        (
            anchor_history_root(&self.anchors),
            self.anchors.len() as u64,
        )
    }

    /// Encode the unique bounded `UDAFRT01` witness.
    pub fn to_bytes(&self) -> Result<Vec<u8>, UsdomStateError> {
        self.validate()?;
        let pmmr = self
            .pmmr
            .to_bytes()
            .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?;
        let privacy = self
            .privacy_notes
            .to_frontier_bytes()
            .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?;
        let pmmr_len: u16 = pmmr
            .len()
            .try_into()
            .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?;
        let privacy_len: u16 = privacy
            .len()
            .try_into()
            .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?;
        let anchor_count: u16 = self
            .anchors
            .len()
            .try_into()
            .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?;
        let mut bytes = Vec::with_capacity(
            ACCUMULATOR_WITNESS_HEADER_BYTES + pmmr.len() + privacy.len() + self.anchors.len() * 40,
        );
        bytes.extend_from_slice(ACCUMULATOR_WITNESS_MAGIC);
        bytes.extend_from_slice(&pmmr_len.to_be_bytes());
        bytes.extend_from_slice(&privacy_len.to_be_bytes());
        bytes.extend_from_slice(&anchor_count.to_be_bytes());
        bytes.extend_from_slice(&pmmr);
        bytes.extend_from_slice(&privacy);
        for anchor in &self.anchors {
            bytes.extend_from_slice(anchor.root.as_bytes());
            bytes.extend_from_slice(&anchor.leaf_count.to_be_bytes());
        }
        if bytes.len() > MAX_ACCUMULATOR_WITNESS_BYTES {
            return Err(UsdomStateError::MalformedAccumulatorWitness);
        }
        Ok(bytes)
    }

    /// Decode and canonically re-encode one `UDAFRT01` witness.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, UsdomStateError> {
        if bytes.len() < ACCUMULATOR_WITNESS_HEADER_BYTES
            || bytes.len() > MAX_ACCUMULATOR_WITNESS_BYTES
            || &bytes[..8] != ACCUMULATOR_WITNESS_MAGIC
        {
            return Err(UsdomStateError::MalformedAccumulatorWitness);
        }
        let pmmr_len = usize::from(u16::from_be_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?,
        ));
        let privacy_len = usize::from(u16::from_be_bytes(
            bytes[10..12]
                .try_into()
                .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?,
        ));
        let anchor_count = usize::from(u16::from_be_bytes(
            bytes[12..14]
                .try_into()
                .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?,
        ));
        if pmmr_len > MAX_FRONTIER_BYTES
            || privacy_len > MAX_NOTE_TREE_FRONTIER_BYTES
            || anchor_count == 0
            || anchor_count > NOTE_ANCHOR_HISTORY
        {
            return Err(UsdomStateError::MalformedAccumulatorWitness);
        }
        let pmmr_end = ACCUMULATOR_WITNESS_HEADER_BYTES
            .checked_add(pmmr_len)
            .ok_or(UsdomStateError::MalformedAccumulatorWitness)?;
        let privacy_end = pmmr_end
            .checked_add(privacy_len)
            .ok_or(UsdomStateError::MalformedAccumulatorWitness)?;
        let expected = privacy_end
            .checked_add(
                anchor_count
                    .checked_mul(40)
                    .ok_or(UsdomStateError::MalformedAccumulatorWitness)?,
            )
            .ok_or(UsdomStateError::MalformedAccumulatorWitness)?;
        if expected != bytes.len() {
            return Err(UsdomStateError::MalformedAccumulatorWitness);
        }
        let pmmr = PmmrFrontier::from_bytes(&bytes[14..pmmr_end])
            .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?;
        let privacy_notes = IncrementalNoteTree::from_frontier_bytes(&bytes[pmmr_end..privacy_end])
            .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?;
        let mut anchors = VecDeque::with_capacity(anchor_count);
        let mut cursor = privacy_end;
        for _ in 0..anchor_count {
            let root = Hash256::from_bytes(
                bytes[cursor..cursor + 32]
                    .try_into()
                    .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?,
            );
            let leaf_count = u64::from_be_bytes(
                bytes[cursor + 32..cursor + 40]
                    .try_into()
                    .map_err(|_| UsdomStateError::MalformedAccumulatorWitness)?,
            );
            anchors.push_back(NoteAnchor { root, leaf_count });
            cursor += 40;
        }
        let witness = Self {
            pmmr,
            privacy_notes,
            anchors,
        };
        witness.validate()?;
        if witness.to_bytes()?.as_slice() != bytes {
            return Err(UsdomStateError::MalformedAccumulatorWitness);
        }
        Ok(witness)
    }

    fn validate(&self) -> Result<(), UsdomStateError> {
        if self.anchors.is_empty()
            || self.anchors.len() > NOTE_ANCHOR_HISTORY
            || self.pmmr.leaf_count() != self.privacy_notes.leaf_count()
            || self.anchors.back()
                != Some(&NoteAnchor {
                    root: Hash256::from_bytes(self.privacy_notes.root().to_bytes()),
                    leaf_count: self.privacy_notes.leaf_count(),
                })
            || self.anchors.iter().any(|anchor| {
                anchor.root == Hash256::ZERO
                    || PrivacyScalar::from_bytes(*anchor.root.as_bytes()).is_err()
                    || anchor.leaf_count > self.privacy_notes.leaf_count()
            })
            || self
                .anchors
                .iter()
                .zip(self.anchors.iter().skip(1))
                .any(|(left, right)| left.leaf_count >= right.leaf_count)
        {
            return Err(UsdomStateError::MalformedAccumulatorWitness);
        }
        Ok(())
    }
}

/// Read-only prover input binding one burn record to one complete native state
/// commitment. Consensus/finality authentication remains a separate proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnStateWitness {
    /// Complete decomposition of the claimed native state root.
    pub state: StateCommitment,
    /// Inclusion of the public burn record under `state.burn_root`.
    pub burn: BurnSetInclusionProof,
}

impl BurnStateWitness {
    /// Verify the internal state-root and burn-set relations. This intentionally
    /// does not claim that a DOM header is valid or finalized.
    pub fn verify(&self, expected_state_root: Hash256) -> bool {
        valid_state_commitment(&self.state)
            && valid_burn_record(&self.burn.record)
            && self.state.root() == expected_state_root
            && self.state.burn_count == self.burn.leaf_count
            && self.state.total_burned <= self.state.total_issued
            && u128::from(self.burn.record.amount) <= self.state.total_burned
            && self.burn.record.ethereum_chain_id == self.state.ethereum_chain_id
            && self.burn.record.reserve == self.state.reserve
            && self
                .burn
                .record
                .expected_obligation_commitment(self.state.domain)
                == self.burn.record.obligation_commitment
            && self.burn.verify(self.state.burn_root)
    }

    /// Encode the witness in the unique bounded `USDBRN03` prover-input form.
    pub fn to_bytes(&self) -> Result<Vec<u8>, UsdomStateError> {
        if !self.verify(self.state.root()) {
            return Err(UsdomStateError::MalformedBurnWitness);
        }
        let sibling_count: u8 = self
            .burn
            .siblings
            .len()
            .try_into()
            .map_err(|_| UsdomStateError::MalformedBurnWitness)?;
        let mut bytes = Vec::with_capacity(MAX_BURN_STATE_WITNESS_BYTES);
        bytes.extend_from_slice(BURN_WITNESS_MAGIC);
        encode_state_commitment(&mut bytes, &self.state);
        encode_burn_record(&mut bytes, self.burn.record);
        bytes.extend_from_slice(&self.burn.leaf_index.to_be_bytes());
        bytes.extend_from_slice(&self.burn.leaf_count.to_be_bytes());
        bytes.push(sibling_count);
        for sibling in &self.burn.siblings {
            bytes.extend_from_slice(sibling.as_bytes());
        }
        if bytes.len() > MAX_BURN_STATE_WITNESS_BYTES {
            return Err(UsdomStateError::MalformedBurnWitness);
        }
        Ok(bytes)
    }

    /// Decode and canonically revalidate one `USDBRN03` prover witness.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, UsdomStateError> {
        decode_burn_state_witness(bytes)
    }
}

/// Finalized Ethereum deposit occurrence consumed by native issuance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuanceRecord {
    /// Unique reserve deposit identifier within the immutable bridge domain.
    pub deposit_id: [u8; 32],
    /// Note commitment bound to the public deposit amount by the proof verifier.
    pub note_commitment: [u8; 32],
    /// Issued amount in six-decimal base units.
    pub amount: u64,
    /// Ethereum finality identity that authenticated the deposit event.
    pub ethereum_anchor: EthereumAnchor,
}

/// Public finalized deposit fields that deterministically derive its unique
/// issuance note. The same canonical encoding is used by consensus and wallet
/// pre-registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthereumDepositOccurrence {
    /// Beacon genesis root pinning the exact Ethereum consensus chain.
    pub genesis_validators_root: [u8; 32],
    /// Execution block containing the reserve deposit log.
    pub block_hash: [u8; 32],
    /// Execution block number containing the log.
    pub block_number: u64,
    /// Transaction position inside the execution block.
    pub transaction_index: u64,
    /// Receipt log position inside the transaction receipt.
    pub receipt_log_index: u64,
    /// Unique deposit identifier emitted by the reserve.
    pub deposit_id: [u8; 32],
    /// Public Ethereum account that funded the deposit.
    pub funder: [u8; 20],
    /// Exact six-decimal amount emitted by the reserve event.
    pub amount: u64,
    /// Recipient owner commitment supplied to the reserve deposit call.
    pub receiving_commitment: [u8; 32],
}

impl EthereumDepositOccurrence {
    /// Derive the deterministic randomness used only by the issuance-origin
    /// commitment namespace.
    pub fn issuance_rho(self) -> Result<PrivacyScalar, UsdomStateError> {
        if self.genesis_validators_root == [0; 32]
            || self.block_hash == [0; 32]
            || self.block_number == 0
            || self.deposit_id == [0; 32]
            || self.funder == [0; 20]
            || self.amount == 0
        {
            return Err(UsdomStateError::ZeroIdentity);
        }
        let mut encoded = Vec::with_capacity(220);
        encoded.extend_from_slice(&1u16.to_be_bytes());
        encoded.extend_from_slice(&self.genesis_validators_root);
        encoded.extend_from_slice(&self.block_hash);
        encoded.extend_from_slice(&self.block_number.to_be_bytes());
        encoded.extend_from_slice(&self.transaction_index.to_be_bytes());
        encoded.extend_from_slice(&self.receipt_log_index.to_be_bytes());
        encoded.extend_from_slice(&self.deposit_id);
        encoded.extend_from_slice(&self.funder);
        encoded.extend_from_slice(&self.amount.to_be_bytes());
        issuance_rho(&encoded).map_err(|_| UsdomStateError::InvalidPrivacyCommitment)
    }
}

/// Derive the origin-separated issuance opening from one exact public deposit
/// occurrence. Matching its commitment to a verified issuance is sufficient
/// for a wallet to recognize ownership without a public recipient address.
pub fn ethereum_deposit_note_opening(
    bridge: BridgeIdentity,
    occurrence: EthereumDepositOccurrence,
) -> Result<NoteOpening, UsdomStateError> {
    bridge.validate()?;
    if occurrence.genesis_validators_root != bridge.ethereum_genesis_validators_root
        || occurrence.block_hash == [0; 32]
        || occurrence.block_number == 0
        || occurrence.deposit_id == [0; 32]
        || occurrence.funder == [0; 20]
        || occurrence.amount == 0
    {
        return Err(UsdomStateError::BridgeIdentityMismatch);
    }
    let owner = PrivacyScalar::from_bytes(occurrence.receiving_commitment)
        .map_err(|_| UsdomStateError::InvalidPrivacyCommitment)?;
    if owner.is_zero() {
        return Err(UsdomStateError::InvalidPrivacyCommitment);
    }
    Ok(NoteOpening {
        chain: privacy_chain_scalar(bridge.dom_domain, bridge.privacy_policy_hash),
        origin: NOTE_ORIGIN_ISSUANCE,
        value: occurrence.amount,
        owner,
        rho: occurrence.issuance_rho()?,
    })
}

/// Opaque capability proving a finalized deposit and its private-note binding.
///
/// ```compile_fail
/// use dom_usdom_state::VerifiedIssuance;
/// fn forge() -> VerifiedIssuance {
///     VerifiedIssuance { domain: [1; 32], deposit_id: [2; 32],
///         note_commitment: [3; 32], amount: 1, ethereum_anchor: todo!() }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIssuance {
    domain: [u8; 32],
    deposit_id: [u8; 32],
    note_commitment: [u8; 32],
    amount: u64,
    ethereum_anchor: EthereumAnchor,
}

/// Opaque capability proving ownership, membership, range and conservation for
/// one private transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTransfer {
    domain: [u8; 32],
    anchor: NoteAnchor,
    nullifiers: Vec<[u8; 32]>,
    output_notes: Vec<[u8; 32]>,
    memo_commitment: [u8; 32],
}

/// Opaque capability proving a private spend and public burn obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBurn {
    domain: [u8; 32],
    anchor: NoteAnchor,
    nullifiers: Vec<[u8; 32]>,
    change_notes: Vec<[u8; 32]>,
    memo_commitment: [u8; 32],
    record: BurnRecord,
}

/// Opaque capability proving one authenticated Ethereum finality advancement.
/// Ordinary callers cannot construct it; a reviewed finality-verifier adapter
/// or the explicitly unsafe debug-only fixture must create it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEthereumCheckpoint {
    domain: [u8; 32],
    anchor: EthereumAnchor,
}

/// Convert the repository-local opaque Ethereum checkpoint proof into the only
/// capability that may advance native USDOM Ethereum time.
///
/// The public v2 handoff is checked against the immutable bridge identity and
/// the opaque verifier result. Decoded handoff bytes alone cannot call this
/// function because they cannot construct [`VerifiedCheckpoint`].
#[cfg(feature = "ethereum-finality")]
pub fn ethereum_checkpoint_transition(
    bridge: BridgeIdentity,
    checkpoint: &VerifiedCheckpoint,
) -> Result<VerifiedTransition, UsdomStateError> {
    bridge.validate()?;
    let record = checkpoint.record();
    if record[0] != 2
        || record[353..385] != bridge.dom_domain
        || record[229..261] != bridge.ethereum_genesis_validators_root
        || checkpoint.trust_policy_hash().as_slice() != bridge.ethereum_checkpoint_policy_hash
    {
        return Err(UsdomStateError::BridgeIdentityMismatch);
    }
    let chain_id = u64::from_be_bytes(
        record[77..85]
            .try_into()
            .map_err(|_| UsdomStateError::BridgeIdentityMismatch)?,
    );
    let mut chain_id_word = [0u8; 32];
    chain_id_word[24..].copy_from_slice(&chain_id.to_be_bytes());
    if chain_id_word != bridge.ethereum_chain_id {
        return Err(UsdomStateError::BridgeIdentityMismatch);
    }
    let finalized = checkpoint.finalized_execution();
    let anchor = EthereumAnchor {
        genesis_validators_root: bridge.ethereum_genesis_validators_root,
        execution_block_number: finalized.block_number,
        execution_block_hash: finalized.block_hash.into(),
        execution_block_timestamp: finalized.timestamp,
        beacon_slot: finalized.beacon_slot,
        beacon_root: finalized.beacon_root.into(),
    };
    anchor.validate()?;
    Ok(VerifiedTransition::EthereumCheckpoint(
        VerifiedEthereumCheckpoint {
            domain: bridge.dom_domain,
            anchor,
        },
    ))
}

/// Convert an opaque, replay-verified Ethereum reserve deposit into one exact
/// native issuance. The initial note commitment is derived by consensus from
/// the authenticated occurrence, amount, and receiver commitment; neither a
/// relayer nor an issuer key can substitute a different amount or note.
#[cfg(feature = "ethereum-finality")]
pub fn ethereum_deposit_transition(
    bridge: BridgeIdentity,
    deposit: &VerifiedDeposit,
) -> Result<VerifiedTransition, UsdomStateError> {
    bridge.validate()?;
    if deposit.bridge_domain().as_slice() != bridge.dom_domain
        || deposit.reserve().as_slice() != bridge.reserve
        || deposit.locator().genesis_validators_root.as_slice()
            != bridge.ethereum_genesis_validators_root
        || deposit.trust_policy_hash().as_slice() != bridge.ethereum_deposit_policy_hash
        || privacy_policy_hash().as_bytes() != &bridge.privacy_policy_hash
    {
        return Err(UsdomStateError::BridgeIdentityMismatch);
    }
    let finalized = deposit.finalized_execution();
    let anchor = EthereumAnchor {
        genesis_validators_root: bridge.ethereum_genesis_validators_root,
        execution_block_number: finalized.block_number,
        execution_block_hash: finalized.block_hash.into(),
        execution_block_timestamp: finalized.timestamp,
        beacon_slot: finalized.beacon_slot,
        beacon_root: finalized.beacon_root.into(),
    };
    anchor.validate()?;

    let locator = deposit.locator();
    let occurrence = EthereumDepositOccurrence {
        genesis_validators_root: locator.genesis_validators_root.into(),
        block_hash: locator.block_hash.into(),
        block_number: locator.block_number,
        transaction_index: u64::from(locator.transaction_index),
        receipt_log_index: u64::from(locator.receipt_log_index),
        deposit_id: deposit.deposit_id().into(),
        funder: deposit.funder().into(),
        amount: deposit.amount(),
        receiving_commitment: deposit.receiving_commitment().into(),
    };
    let note_commitment = ethereum_deposit_note_opening(bridge, occurrence)?
        .commitment()
        .map_err(|_| UsdomStateError::InvalidPrivacyCommitment)?
        .to_bytes();
    Ok(VerifiedTransition::Issue(VerifiedIssuance {
        domain: bridge.dom_domain,
        deposit_id: deposit.deposit_id().into(),
        note_commitment,
        amount: deposit.amount(),
        ethereum_anchor: anchor,
    }))
}

/// Verify a private transfer proof and convert it into the only opaque
/// transition capability accepted by native consensus.
pub fn private_transfer_transition(
    bridge: BridgeIdentity,
    verifier: &SpendVerifier,
    anchor: NoteAnchor,
    nullifiers: &[[u8; 32]],
    output_notes: &[[u8; 32]],
    encrypted_memo: &[u8],
    proof: &[u8],
) -> Result<VerifiedTransition, UsdomStateError> {
    bridge.validate()?;
    if verifier.config_hash().as_bytes() != &bridge.privacy_verifier_config_hash {
        return Err(UsdomStateError::BridgeIdentityMismatch);
    }
    validate_shape(nullifiers, output_notes, false)?;
    let statement = private_spend_statement(
        bridge,
        anchor,
        nullifiers,
        output_notes,
        0,
        PrivacyScalar::ZERO,
        encrypted_memo,
    )?;
    verifier
        .verify(statement, proof)
        .map_err(|_| UsdomStateError::InvalidPrivacyProof)?;
    Ok(VerifiedTransition::Transfer(VerifiedTransfer {
        domain: bridge.dom_domain,
        anchor,
        nullifiers: nullifiers.to_vec(),
        output_notes: output_notes.to_vec(),
        memo_commitment: statement.memo.to_bytes(),
    }))
}

/// Borrowed inputs authenticated by one private burn proof.
pub struct PrivateBurnProofInput<'a> {
    /// Retained note-tree anchor used by every hidden input.
    pub anchor: NoteAnchor,
    /// Canonically ordered public nullifiers.
    pub nullifiers: &'a [[u8; 32]],
    /// New private change-note commitments.
    pub change_notes: &'a [[u8; 32]],
    /// Exact public Ethereum reserve obligation.
    pub record: BurnRecord,
    /// Encrypted output memo bytes committed by the proof.
    pub encrypted_memo: &'a [u8],
    /// Canonical compressed Groth16 proof.
    pub proof: &'a [u8],
}

/// Public output commitments and encrypted memo parsed from an untrusted
/// private-proof payload. This view grants no proof, transition, or consensus
/// authority; wallets must consume it only from an independently authenticated
/// canonical block and must recompute every decrypted note commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedPrivateOutputMemo<'a> {
    /// Public spent-note nullifiers in their proof-statement order.
    pub nullifiers: Vec<[u8; 32]>,
    /// Public note commitments in their proof-statement order.
    pub output_notes: Vec<[u8; 32]>,
    /// Exact encrypted memo bytes committed by the proof statement.
    pub encrypted_memo: &'a [u8],
}

struct DecodedPrivateTransfer<'a> {
    anchor: NoteAnchor,
    nullifiers: Vec<[u8; 32]>,
    outputs: Vec<[u8; 32]>,
    memo: &'a [u8],
    proof: &'a [u8],
}

struct DecodedPrivateBurn<'a> {
    anchor: NoteAnchor,
    nullifiers: Vec<[u8; 32]>,
    outputs: Vec<[u8; 32]>,
    record: BurnRecord,
    memo: &'a [u8],
    proof: &'a [u8],
}

/// Verify a private burn proof bound to one exact public reserve obligation.
pub fn private_burn_transition(
    bridge: BridgeIdentity,
    verifier: &SpendVerifier,
    input: PrivateBurnProofInput<'_>,
) -> Result<VerifiedTransition, UsdomStateError> {
    if verifier.config_hash().as_bytes() != &bridge.privacy_verifier_config_hash {
        return Err(UsdomStateError::BridgeIdentityMismatch);
    }
    validate_shape(input.nullifiers, input.change_notes, true)?;
    if derive_private_burn_id(
        bridge,
        input.nullifiers,
        input.record.recipient,
        input.record.amount,
        input.record.valid_until,
    )? != input.record.burn_id
    {
        return Err(UsdomStateError::BurnIntentMismatch);
    }
    let effect = private_burn_effect_scalar(bridge, input.record)?;
    let statement = private_spend_statement(
        bridge,
        input.anchor,
        input.nullifiers,
        input.change_notes,
        input.record.amount,
        effect,
        input.encrypted_memo,
    )?;
    verifier
        .verify(statement, input.proof)
        .map_err(|_| UsdomStateError::InvalidPrivacyProof)?;
    Ok(VerifiedTransition::Burn(VerifiedBurn {
        domain: bridge.dom_domain,
        anchor: input.anchor,
        nullifiers: input.nullifiers.to_vec(),
        change_notes: input.change_notes.to_vec(),
        memo_commitment: statement.memo.to_bytes(),
        record: input.record,
    }))
}

/// Decode and verify one canonical private-transfer proof payload.
pub fn verify_private_transfer_payload(
    bridge: BridgeIdentity,
    verifier: &SpendVerifier,
    payload: &[u8],
) -> Result<VerifiedTransition, UsdomStateError> {
    let decoded = decode_private_transfer_payload(payload).and_then(|decoded| {
        private_transfer_transition(
            bridge,
            verifier,
            decoded.anchor,
            &decoded.nullifiers,
            &decoded.outputs,
            decoded.memo,
            decoded.proof,
        )
    });
    decoded.map_err(|error| match error {
        UsdomStateError::BridgeIdentityMismatch => error,
        _ => UsdomStateError::InvalidPrivacyProof,
    })
}

/// Decode and verify one canonical private-burn proof payload.
pub fn verify_private_burn_payload(
    bridge: BridgeIdentity,
    verifier: &SpendVerifier,
    payload: &[u8],
) -> Result<VerifiedTransition, UsdomStateError> {
    let decoded = decode_private_burn_payload(payload).and_then(|decoded| {
        private_burn_transition(
            bridge,
            verifier,
            PrivateBurnProofInput {
                anchor: decoded.anchor,
                nullifiers: &decoded.nullifiers,
                change_notes: &decoded.outputs,
                record: decoded.record,
                encrypted_memo: decoded.memo,
                proof: decoded.proof,
            },
        )
    });
    decoded.map_err(|error| match error {
        UsdomStateError::BridgeIdentityMismatch => error,
        _ => UsdomStateError::InvalidPrivacyProof,
    })
}

fn decode_private_transfer_payload(
    payload: &[u8],
) -> Result<DecodedPrivateTransfer<'_>, UsdomStateError> {
    if payload.len() > MAX_PRIVATE_TRANSFER_PAYLOAD_BYTES {
        return Err(UsdomStateError::InvalidPrivacyProof);
    }
    let mut reader = WitnessReader::new(payload);
    if reader.take(8)? != PRIVATE_TRANSFER_MAGIC {
        return Err(UsdomStateError::InvalidPrivacyProof);
    }
    let anchor = NoteAnchor {
        root: Hash256::from_bytes(reader.array()?),
        leaf_count: u64::from_be_bytes(reader.array()?),
    };
    let nullifier_count = usize::from(reader.byte()?);
    let output_count = usize::from(reader.byte()?);
    let memo_len = usize::from(u16::from_be_bytes(reader.array()?));
    if nullifier_count == 0
        || nullifier_count > MAX_INPUT_NULLIFIERS
        || output_count == 0
        || output_count > MAX_OUTPUT_NOTES
        || memo_len == 0
        || memo_len > MAX_PRIVATE_MEMO_BYTES
    {
        return Err(UsdomStateError::InvalidPrivacyProof);
    }
    let nullifiers = (0..nullifier_count)
        .map(|_| reader.array())
        .collect::<Result<Vec<[u8; 32]>, _>>()?;
    let outputs = (0..output_count)
        .map(|_| reader.array())
        .collect::<Result<Vec<[u8; 32]>, _>>()?;
    let memo = reader.take(memo_len)?;
    let proof = reader.take(GROTH16_PROOF_BYTES)?;
    if !reader.is_empty() {
        return Err(UsdomStateError::InvalidPrivacyProof);
    }
    Ok(DecodedPrivateTransfer {
        anchor,
        nullifiers,
        outputs,
        memo,
        proof,
    })
}

fn decode_private_burn_payload(payload: &[u8]) -> Result<DecodedPrivateBurn<'_>, UsdomStateError> {
    if payload.len() > MAX_PRIVATE_BURN_PAYLOAD_BYTES {
        return Err(UsdomStateError::InvalidPrivacyProof);
    }
    let mut reader = WitnessReader::new(payload);
    if reader.take(8)? != PRIVATE_BURN_MAGIC {
        return Err(UsdomStateError::InvalidPrivacyProof);
    }
    let anchor = NoteAnchor {
        root: Hash256::from_bytes(reader.array()?),
        leaf_count: u64::from_be_bytes(reader.array()?),
    };
    let nullifier_count = usize::from(reader.byte()?);
    let output_count = usize::from(reader.byte()?);
    let memo_len = usize::from(u16::from_be_bytes(reader.array()?));
    if nullifier_count == 0
        || nullifier_count > MAX_INPUT_NULLIFIERS
        || output_count > MAX_OUTPUT_NOTES
        || memo_len > MAX_PRIVATE_MEMO_BYTES
        || (output_count == 0) != (memo_len == 0)
    {
        return Err(UsdomStateError::InvalidPrivacyProof);
    }
    let nullifiers = (0..nullifier_count)
        .map(|_| reader.array())
        .collect::<Result<Vec<[u8; 32]>, _>>()?;
    let outputs = (0..output_count)
        .map(|_| reader.array())
        .collect::<Result<Vec<[u8; 32]>, _>>()?;
    let record = decode_burn_record(&mut reader)?;
    let memo = reader.take(memo_len)?;
    let proof = reader.take(GROTH16_PROOF_BYTES)?;
    if !reader.is_empty() {
        return Err(UsdomStateError::InvalidPrivacyProof);
    }
    Ok(DecodedPrivateBurn {
        anchor,
        nullifiers,
        outputs,
        record,
        memo,
        proof,
    })
}

/// Parse transfer output commitments and memo without granting proof authority.
pub fn inspect_private_transfer_outputs(
    payload: &[u8],
) -> Result<UntrustedPrivateOutputMemo<'_>, UsdomStateError> {
    let decoded = decode_private_transfer_payload(payload)?;
    Ok(UntrustedPrivateOutputMemo {
        nullifiers: decoded.nullifiers,
        output_notes: decoded.outputs,
        encrypted_memo: decoded.memo,
    })
}

/// Parse burn change-note commitments and memo without granting proof authority.
pub fn inspect_private_burn_outputs(
    payload: &[u8],
) -> Result<UntrustedPrivateOutputMemo<'_>, UsdomStateError> {
    let decoded = decode_private_burn_payload(payload)?;
    Ok(UntrustedPrivateOutputMemo {
        nullifiers: decoded.nullifiers,
        output_notes: decoded.outputs,
        encrypted_memo: decoded.memo,
    })
}

/// Parse the exact public burn obligation without granting proof authority.
pub fn inspect_private_burn_record(payload: &[u8]) -> Result<BurnRecord, UsdomStateError> {
    Ok(decode_private_burn_payload(payload)?.record)
}

/// Encode the unique bounded private-transfer proof transport.
pub fn encode_private_transfer_payload(
    anchor: NoteAnchor,
    nullifiers: &[[u8; 32]],
    outputs: &[[u8; 32]],
    encrypted_memo: &[u8],
    proof: &[u8],
) -> Result<Vec<u8>, UsdomStateError> {
    if nullifiers.is_empty()
        || nullifiers.len() > MAX_INPUT_NULLIFIERS
        || outputs.is_empty()
        || outputs.len() > MAX_OUTPUT_NOTES
        || encrypted_memo.is_empty()
        || encrypted_memo.len() > MAX_PRIVATE_MEMO_BYTES
        || proof.len() != GROTH16_PROOF_BYTES
    {
        return Err(UsdomStateError::InvalidPrivacyProof);
    }
    encode_private_payload(
        PRIVATE_TRANSFER_MAGIC,
        anchor,
        nullifiers,
        outputs,
        None,
        encrypted_memo,
        proof,
    )
}

/// Encode the unique bounded private-burn proof transport.
pub fn encode_private_burn_payload(
    anchor: NoteAnchor,
    nullifiers: &[[u8; 32]],
    outputs: &[[u8; 32]],
    record: BurnRecord,
    encrypted_memo: &[u8],
    proof: &[u8],
) -> Result<Vec<u8>, UsdomStateError> {
    if nullifiers.is_empty()
        || nullifiers.len() > MAX_INPUT_NULLIFIERS
        || outputs.len() > MAX_OUTPUT_NOTES
        || encrypted_memo.len() > MAX_PRIVATE_MEMO_BYTES
        || (outputs.is_empty() != encrypted_memo.is_empty())
        || proof.len() != GROTH16_PROOF_BYTES
    {
        return Err(UsdomStateError::InvalidPrivacyProof);
    }
    encode_private_payload(
        PRIVATE_BURN_MAGIC,
        anchor,
        nullifiers,
        outputs,
        Some(record),
        encrypted_memo,
        proof,
    )
}

fn encode_private_payload(
    magic: &[u8; 8],
    anchor: NoteAnchor,
    nullifiers: &[[u8; 32]],
    outputs: &[[u8; 32]],
    record: Option<BurnRecord>,
    encrypted_memo: &[u8],
    proof: &[u8],
) -> Result<Vec<u8>, UsdomStateError> {
    let nullifier_count: u8 = nullifiers
        .len()
        .try_into()
        .map_err(|_| UsdomStateError::InvalidPrivacyProof)?;
    let output_count: u8 = outputs
        .len()
        .try_into()
        .map_err(|_| UsdomStateError::InvalidPrivacyProof)?;
    let memo_len: u16 = encrypted_memo
        .len()
        .try_into()
        .map_err(|_| UsdomStateError::InvalidPrivacyProof)?;
    let mut payload = Vec::with_capacity(
        52 + (nullifiers.len() + outputs.len()) * 32
            + record.map_or(0, |_| BURN_RECORD_BYTES)
            + encrypted_memo.len()
            + proof.len(),
    );
    payload.extend_from_slice(magic);
    encode_note_anchor(&mut payload, anchor);
    payload.push(nullifier_count);
    payload.push(output_count);
    payload.extend_from_slice(&memo_len.to_be_bytes());
    for value in nullifiers.iter().chain(outputs) {
        payload.extend_from_slice(value);
    }
    if let Some(record) = record {
        encode_burn_record(&mut payload, record);
    }
    payload.extend_from_slice(encrypted_memo);
    payload.extend_from_slice(proof);
    Ok(payload)
}

/// One proof-verified native USDOM transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedTransition {
    /// Mint exactly one note from one finalized, unconsumed deposit.
    Issue(VerifiedIssuance),
    /// Privately spend notes into new private notes.
    Transfer(VerifiedTransfer),
    /// Privately spend notes while removing a public amount from circulation.
    Burn(VerifiedBurn),
    /// Advance the Ethereum finality/time anchor without issuing USDOM.
    EthereumCheckpoint(VerifiedEthereumCheckpoint),
}

/// Public, non-authoritative preimage of one versioned transition commitment.
///
/// This projection contains no proof bytes or secret note openings. It is safe
/// to transport to a wallet only together with an authenticated batch/header
/// commitment. Constructing or hashing it never grants state-transition
/// authority; only [`VerifiedTransition`] can be applied to native state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionCommitmentProjection {
    /// Deposit-backed issuance fields authenticated by the deposit verifier.
    Issue {
        /// Immutable native USDOM domain.
        domain: [u8; 32],
        /// Exact finalized deposit, note and Ethereum anchor.
        record: IssuanceRecord,
    },
    /// Public fields authenticated by one private-transfer proof.
    Transfer {
        /// Immutable native USDOM domain.
        domain: [u8; 32],
        /// Retained note-tree anchor used by the proof.
        anchor: NoteAnchor,
        /// Canonically ordered spent-note nullifiers.
        nullifiers: Vec<[u8; 32]>,
        /// Output note commitments in statement order.
        output_notes: Vec<[u8; 32]>,
        /// Proof-authenticated field element derived from the encrypted memo.
        memo_commitment: [u8; 32],
    },
    /// Public fields authenticated by one private-burn proof.
    Burn {
        /// Immutable native USDOM domain.
        domain: [u8; 32],
        /// Retained note-tree anchor used by the proof.
        anchor: NoteAnchor,
        /// Canonically ordered spent-note nullifiers.
        nullifiers: Vec<[u8; 32]>,
        /// Private change-note commitments in statement order.
        change_notes: Vec<[u8; 32]>,
        /// Proof-authenticated memo field, or zero for an exact burn.
        memo_commitment: [u8; 32],
        /// Exact public Ethereum payout obligation.
        record: BurnRecord,
    },
    /// Public fields authenticated by one Ethereum checkpoint witness.
    EthereumCheckpoint {
        /// Immutable native USDOM domain.
        domain: [u8; 32],
        /// Exact monotonically advancing Ethereum finality anchor.
        anchor: EthereumAnchor,
    },
}

/// Recomputed commitment summary for one transported public transition batch.
///
/// This authenticates canonical projections against roots supplied by a DOM
/// header proof. It grants no authority to mutate native state and performs no
/// proof verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedTransitionProjectionBatch {
    /// Number of ordered projections authenticated into the batch.
    pub transition_count: u32,
    /// Ordered Merkle root of the versioned transition commitments.
    pub transitions_root: Hash256,
    /// Commitment to count, timestamp, transition root and adjacent state roots.
    pub header_commitment: Hash256,
}

/// Recompute the exact versioned roots for transported wallet history.
///
/// Callers must separately prove `header_commitment` is bound into an exact
/// trusted DOM header. The returned value never authorizes a state transition.
pub fn authenticate_transition_projection_batch(
    domain: [u8; 32],
    block_timestamp: u64,
    previous_state_root: Hash256,
    new_state_root: Hash256,
    projections: &[TransitionCommitmentProjection],
) -> Result<AuthenticatedTransitionProjectionBatch, UsdomStateError> {
    require_projection_domain(domain)?;
    if block_timestamp == 0
        || previous_state_root == Hash256::ZERO
        || new_state_root == Hash256::ZERO
        || projections.len() > MAX_TRANSITIONS_PER_BATCH
    {
        return Err(UsdomStateError::MalformedUndo);
    }
    let transition_count =
        u32::try_from(projections.len()).map_err(|_| UsdomStateError::MalformedUndo)?;
    let commitments = projections
        .iter()
        .map(|projection| {
            if projection.domain() != domain {
                return Err(UsdomStateError::BridgeIdentityMismatch);
            }
            projection.consensus_commitment()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let transitions_root = transition_batch_root(domain, &commitments)?;
    let header_commitment = batch_header_commitment(
        domain,
        transition_count,
        block_timestamp,
        transitions_root,
        previous_state_root,
        new_state_root,
    );
    Ok(AuthenticatedTransitionProjectionBatch {
        transition_count,
        transitions_root,
        header_commitment,
    })
}

impl TransitionCommitmentProjection {
    /// Immutable native USDOM domain included in this commitment preimage.
    pub fn domain(&self) -> [u8; 32] {
        match self {
            Self::Issue { domain, .. }
            | Self::Transfer { domain, .. }
            | Self::Burn { domain, .. }
            | Self::EthereumCheckpoint { domain, .. } => *domain,
        }
    }

    /// Recompute the exact version-2 consensus commitment after validating the
    /// canonical public shape. This authenticates a projection against a batch
    /// root; it does not prove the underlying transition or permit application.
    pub fn consensus_commitment(&self) -> Result<Hash256, UsdomStateError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TRANSITION_COMMITMENT_VERSION.to_be_bytes());
        match self {
            Self::Issue { domain, record } => {
                require_projection_domain(*domain)?;
                if record.deposit_id == [0; 32]
                    || record.note_commitment == [0; 32]
                    || record.amount == 0
                {
                    return Err(UsdomStateError::ZeroIdentity);
                }
                let note = PrivacyScalar::from_bytes(record.note_commitment)
                    .map_err(|_| UsdomStateError::InvalidPrivacyCommitment)?;
                if note.is_zero() {
                    return Err(UsdomStateError::InvalidPrivacyCommitment);
                }
                record.ethereum_anchor.validate()?;
                bytes.push(TransitionKind::Issue.discriminator());
                bytes.extend_from_slice(domain);
                bytes.extend_from_slice(&record.deposit_id);
                bytes.extend_from_slice(&record.note_commitment);
                bytes.extend_from_slice(&record.amount.to_be_bytes());
                encode_ethereum_anchor(&mut bytes, record.ethereum_anchor);
            }
            Self::Transfer {
                domain,
                anchor,
                nullifiers,
                output_notes,
                memo_commitment,
            } => {
                require_projection_domain(*domain)?;
                validate_projection_anchor(*anchor)?;
                validate_shape(nullifiers, output_notes, false)?;
                validate_projection_scalars(nullifiers, output_notes)?;
                validate_projection_memo(output_notes, *memo_commitment)?;
                bytes.push(TransitionKind::Transfer.discriminator());
                bytes.extend_from_slice(domain);
                encode_note_anchor(&mut bytes, *anchor);
                encode_hash_list(&mut bytes, nullifiers)?;
                encode_hash_list(&mut bytes, output_notes)?;
                bytes.extend_from_slice(memo_commitment);
            }
            Self::Burn {
                domain,
                anchor,
                nullifiers,
                change_notes,
                memo_commitment,
                record,
            } => {
                require_projection_domain(*domain)?;
                validate_projection_anchor(*anchor)?;
                validate_shape(nullifiers, change_notes, true)?;
                validate_projection_scalars(nullifiers, change_notes)?;
                validate_projection_memo(change_notes, *memo_commitment)?;
                if record.burn_id == [0; 32]
                    || record.request_id == [0; 32]
                    || record.recipient == [0; 20]
                    || record.ethereum_chain_id == [0; 32]
                    || record.reserve == [0; 20]
                    || record.amount == 0
                    || record.valid_until == 0
                    || record.obligation_commitment
                        != record.expected_obligation_commitment(*domain)
                {
                    return Err(UsdomStateError::BurnIntentMismatch);
                }
                bytes.push(TransitionKind::Burn.discriminator());
                bytes.extend_from_slice(domain);
                encode_note_anchor(&mut bytes, *anchor);
                encode_hash_list(&mut bytes, nullifiers)?;
                encode_hash_list(&mut bytes, change_notes)?;
                bytes.extend_from_slice(memo_commitment);
                encode_burn_record(&mut bytes, *record);
            }
            Self::EthereumCheckpoint { domain, anchor } => {
                require_projection_domain(*domain)?;
                anchor.validate()?;
                bytes.push(TransitionKind::EthereumCheckpoint.discriminator());
                bytes.extend_from_slice(domain);
                encode_ethereum_anchor(&mut bytes, *anchor);
            }
        }
        Ok(blake2b_256_tagged(TAG_TRANSITION, &bytes))
    }

    /// Wallet-visible note, nullifier and memo effects authenticated when this
    /// projection's commitment is proven under the corresponding batch root.
    pub fn public_effects(&self) -> TransitionPublicEffects {
        match self {
            Self::Issue { record, .. } => TransitionPublicEffects {
                kind: TransitionKind::Issue,
                nullifiers: Vec::new(),
                note_commitments: vec![record.note_commitment],
                memo_commitment: None,
            },
            Self::Transfer {
                nullifiers,
                output_notes,
                memo_commitment,
                ..
            } => TransitionPublicEffects {
                kind: TransitionKind::Transfer,
                nullifiers: nullifiers.clone(),
                note_commitments: output_notes.clone(),
                memo_commitment: Some(*memo_commitment),
            },
            Self::Burn {
                nullifiers,
                change_notes,
                memo_commitment,
                ..
            } => TransitionPublicEffects {
                kind: TransitionKind::Burn,
                nullifiers: nullifiers.clone(),
                note_commitments: change_notes.clone(),
                memo_commitment: Some(*memo_commitment),
            },
            Self::EthereumCheckpoint { .. } => TransitionPublicEffects {
                kind: TransitionKind::EthereumCheckpoint,
                nullifiers: Vec::new(),
                note_commitments: Vec::new(),
                memo_commitment: None,
            },
        }
    }

    /// Canonical bounded transport encoding for authenticated history export.
    pub fn to_bytes(&self) -> Result<Vec<u8>, UsdomStateError> {
        self.consensus_commitment()?;
        let mut bytes = Vec::with_capacity(MAX_TRANSITION_PROJECTION_BYTES);
        bytes.extend_from_slice(TRANSITION_PROJECTION_MAGIC);
        match self {
            Self::Issue { domain, record } => {
                bytes.push(TransitionKind::Issue.discriminator());
                bytes.extend_from_slice(domain);
                bytes.extend_from_slice(&record.deposit_id);
                bytes.extend_from_slice(&record.note_commitment);
                bytes.extend_from_slice(&record.amount.to_be_bytes());
                encode_ethereum_anchor(&mut bytes, record.ethereum_anchor);
            }
            Self::Transfer {
                domain,
                anchor,
                nullifiers,
                output_notes,
                memo_commitment,
            } => {
                bytes.push(TransitionKind::Transfer.discriminator());
                bytes.extend_from_slice(domain);
                encode_note_anchor(&mut bytes, *anchor);
                encode_projection_hashes(&mut bytes, nullifiers)?;
                encode_projection_hashes(&mut bytes, output_notes)?;
                bytes.extend_from_slice(memo_commitment);
            }
            Self::Burn {
                domain,
                anchor,
                nullifiers,
                change_notes,
                memo_commitment,
                record,
            } => {
                bytes.push(TransitionKind::Burn.discriminator());
                bytes.extend_from_slice(domain);
                encode_note_anchor(&mut bytes, *anchor);
                encode_projection_hashes(&mut bytes, nullifiers)?;
                encode_projection_hashes(&mut bytes, change_notes)?;
                bytes.extend_from_slice(memo_commitment);
                encode_burn_record(&mut bytes, *record);
            }
            Self::EthereumCheckpoint { domain, anchor } => {
                bytes.push(TransitionKind::EthereumCheckpoint.discriminator());
                bytes.extend_from_slice(domain);
                encode_ethereum_anchor(&mut bytes, *anchor);
            }
        }
        if bytes.len() > MAX_TRANSITION_PROJECTION_BYTES {
            return Err(UsdomStateError::MalformedUndo);
        }
        Ok(bytes)
    }

    /// Decode a canonical public projection. The result remains
    /// non-authoritative until its recomputed commitment is authenticated by a
    /// transition-batch root and DOM header.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, UsdomStateError> {
        if bytes.len() < 8 + 1 + 32 || bytes.len() > MAX_TRANSITION_PROJECTION_BYTES {
            return Err(UsdomStateError::MalformedUndo);
        }
        let mut reader = UndoReader::new(bytes);
        if reader.take(8)? != TRANSITION_PROJECTION_MAGIC {
            return Err(UsdomStateError::MalformedUndo);
        }
        let kind = TransitionKind::from_discriminator(reader.byte()?)?;
        let domain = reader.array()?;
        let projection = match kind {
            TransitionKind::Issue => Self::Issue {
                domain,
                record: IssuanceRecord {
                    deposit_id: reader.array()?,
                    note_commitment: reader.array()?,
                    amount: u64::from_be_bytes(reader.array()?),
                    ethereum_anchor: decode_ethereum_anchor(&mut reader)?,
                },
            },
            TransitionKind::Transfer => Self::Transfer {
                domain,
                anchor: decode_projection_note_anchor(&mut reader)?,
                nullifiers: decode_projection_hashes(&mut reader)?,
                output_notes: decode_projection_hashes(&mut reader)?,
                memo_commitment: reader.array()?,
            },
            TransitionKind::Burn => Self::Burn {
                domain,
                anchor: decode_projection_note_anchor(&mut reader)?,
                nullifiers: decode_projection_hashes(&mut reader)?,
                change_notes: decode_projection_hashes(&mut reader)?,
                memo_commitment: reader.array()?,
                record: decode_projection_burn_record(&mut reader)?,
            },
            TransitionKind::EthereumCheckpoint => Self::EthereumCheckpoint {
                domain,
                anchor: decode_ethereum_anchor(&mut reader)?,
            },
        };
        if !reader.is_empty()
            || projection.consensus_commitment().is_err()
            || projection.to_bytes()?.as_slice() != bytes
        {
            return Err(UsdomStateError::MalformedUndo);
        }
        Ok(projection)
    }
}

impl VerifiedTransition {
    /// Deterministic consensus commitment to every public effect of this
    /// proof-verified transition. Proof bytes and secret note openings are
    /// deliberately excluded; the verifier must construct this opaque value
    /// only after authenticating them.
    pub fn consensus_commitment(&self) -> Result<Hash256, UsdomStateError> {
        self.commitment_projection().consensus_commitment()
    }

    /// Export the public preimage needed to authenticate historical wallet
    /// effects against the transition-batch root. The result grants no proof
    /// or state-transition authority.
    pub fn commitment_projection(&self) -> TransitionCommitmentProjection {
        match self {
            Self::Issue(value) => TransitionCommitmentProjection::Issue {
                domain: value.domain,
                record: IssuanceRecord {
                    deposit_id: value.deposit_id,
                    note_commitment: value.note_commitment,
                    amount: value.amount,
                    ethereum_anchor: value.ethereum_anchor,
                },
            },
            Self::Transfer(value) => TransitionCommitmentProjection::Transfer {
                domain: value.domain,
                anchor: value.anchor,
                nullifiers: value.nullifiers.clone(),
                output_notes: value.output_notes.clone(),
                memo_commitment: value.memo_commitment,
            },
            Self::Burn(value) => TransitionCommitmentProjection::Burn {
                domain: value.domain,
                anchor: value.anchor,
                nullifiers: value.nullifiers.clone(),
                change_notes: value.change_notes.clone(),
                memo_commitment: value.memo_commitment,
                record: value.record,
            },
            Self::EthereumCheckpoint(value) => TransitionCommitmentProjection::EthereumCheckpoint {
                domain: value.domain,
                anchor: value.anchor,
            },
        }
    }

    /// Public note/nullifier effects needed by an authenticated wallet scanner.
    /// This discloses only values already carried by the verified transition
    /// and does not expose note openings or grant state-transition authority.
    pub fn public_effects(&self) -> TransitionPublicEffects {
        match self {
            Self::Issue(value) => TransitionPublicEffects {
                kind: TransitionKind::Issue,
                nullifiers: Vec::new(),
                note_commitments: vec![value.note_commitment],
                memo_commitment: None,
            },
            Self::Transfer(value) => TransitionPublicEffects {
                kind: TransitionKind::Transfer,
                nullifiers: value.nullifiers.clone(),
                note_commitments: value.output_notes.clone(),
                memo_commitment: Some(value.memo_commitment),
            },
            Self::Burn(value) => TransitionPublicEffects {
                kind: TransitionKind::Burn,
                nullifiers: value.nullifiers.clone(),
                note_commitments: value.change_notes.clone(),
                memo_commitment: Some(value.memo_commitment),
            },
            Self::EthereumCheckpoint(_) => TransitionPublicEffects {
                kind: TransitionKind::EthereumCheckpoint,
                nullifiers: Vec::new(),
                note_commitments: Vec::new(),
                memo_commitment: None,
            },
        }
    }
}

/// Wallet-visible public effects extracted only from a proof-verified transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionPublicEffects {
    /// Verified transition class.
    pub kind: TransitionKind,
    /// Public spent-note nullifiers in canonical order.
    pub nullifiers: Vec<[u8; 32]>,
    /// Public appended note commitments in canonical order.
    pub note_commitments: Vec<[u8; 32]>,
    /// Proof-authenticated encrypted-memo scalar for private spends. Exact
    /// burns without change use `Some([0; 32])`; non-spend transitions use
    /// `None`.
    pub memo_commitment: Option<[u8; 32]>,
}

/// Kind of transition applied to native state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionKind {
    /// Deposit-backed issuance.
    Issue,
    /// Private value-conserving transfer.
    Transfer,
    /// Private spend with public burn obligation.
    Burn,
    /// Authenticated Ethereum finality advancement.
    EthereumCheckpoint,
}

impl TransitionKind {
    fn discriminator(self) -> u8 {
        match self {
            Self::Issue => 1,
            Self::Transfer => 2,
            Self::Burn => 3,
            Self::EthereumCheckpoint => 4,
        }
    }

    fn from_discriminator(value: u8) -> Result<Self, UsdomStateError> {
        match value {
            1 => Ok(Self::Issue),
            2 => Ok(Self::Transfer),
            3 => Ok(Self::Burn),
            4 => Ok(Self::EthereumCheckpoint),
            _ => Err(UsdomStateError::MalformedUndo),
        }
    }
}

/// Versioned commitment produced after an ordered block batch has been fully
/// validated and applied. A DOM header can commit `header_commitment` without
/// exposing private note openings or transfer history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionBatchReceipt {
    /// Consensus envelope version.
    pub version: u16,
    /// Number of ordered transitions in the block batch.
    pub transition_count: u32,
    /// DOM block timestamp used to validate every burn deadline.
    pub block_timestamp: u64,
    /// Merkle root of the ordered, proof-verified transition commitments.
    pub transitions_root: Hash256,
    /// Native USDOM state root before the block batch.
    pub previous_state_root: Hash256,
    /// Native USDOM state root after the block batch.
    pub new_state_root: Hash256,
    /// Single domain-separated value intended for a future DOM block header.
    pub header_commitment: Hash256,
}

/// Public result of an accepted state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionReceipt {
    /// Transition class.
    pub kind: TransitionKind,
    /// Composite native state root before applying the transition.
    pub previous_state_root: Hash256,
    /// Composite native state root after applying the transition.
    pub new_state_root: Hash256,
    /// Note-tree anchor after the transition.
    pub note_anchor: NoteAnchor,
    /// Total deposit-backed issuance after the transition.
    pub total_issued: u128,
    /// Total native burns after the transition.
    pub total_burned: u128,
}

/// One canonical storage mutation derived from two fully verified states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalStateUpdate {
    /// Versioned USDOM state key.
    pub key: Vec<u8>,
    /// New canonical value, or `None` when rollback removes the key.
    pub value: Option<Vec<u8>>,
}

/// Exact in-memory inverse for one accepted transition. Fields are private so
/// callers cannot fabricate a rollback target.
#[derive(Debug, Clone)]
pub struct StateUndo {
    before_root: Hash256,
    after_root: Hash256,
    prior_note_count: u64,
    inserted_notes: Vec<[u8; 32]>,
    inserted_nullifiers: Vec<[u8; 32]>,
    inserted_deposit: Option<[u8; 32]>,
    inserted_burn: Option<[u8; 32]>,
    prior_total_issued: u128,
    prior_total_burned: u128,
    prior_ethereum_anchor: Option<EthereumAnchor>,
    prior_note_anchors: VecDeque<NoteAnchor>,
}

/// Exact inverse for one atomically applied ordered transition batch. Its
/// internals are private so a caller cannot replace or reorder individual undo
/// records while retaining a valid public batch commitment.
#[derive(Debug, Clone)]
pub struct BatchUndo {
    before_root: Hash256,
    after_root: Hash256,
    transitions_root: Hash256,
    block_timestamp: u64,
    undos: Vec<StateUndo>,
    projections: Vec<TransitionCommitmentProjection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExecutionAnchorReference {
    block_hash: [u8; 32],
    timestamp: u64,
    references: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BeaconAnchorReference {
    anchor: EthereumAnchor,
    references: u64,
}

/// Canonical native USDOM state. Secret note openings and ownership never enter
/// this structure; only commitments, nullifiers and public bridge obligations do.
#[derive(Debug, Clone)]
pub struct NativeUsdomState {
    domain: [u8; 32],
    ethereum_genesis_validators_root: [u8; 32],
    ethereum_chain_id: [u8; 32],
    ethereum_checkpoint_policy_hash: [u8; 32],
    ethereum_deposit_policy_hash: [u8; 32],
    privacy_policy_hash: [u8; 32],
    privacy_verifier_config_hash: [u8; 32],
    reserve: [u8; 20],
    burn_timing: BurnTimingPolicy,
    notes: Pmmr,
    privacy_notes: IncrementalNoteTree,
    note_order: Vec<[u8; 32]>,
    note_commitments: BTreeSet<[u8; 32]>,
    nullifiers: BTreeSet<[u8; 32]>,
    consumed_deposits: BTreeMap<[u8; 32], IssuanceRecord>,
    burns: BTreeMap<[u8; 32], BurnRecord>,
    burn_request_ids: BTreeSet<[u8; 32]>,
    sparse_note_set: SparseMerkleTree,
    sparse_nullifier_set: SparseMerkleTree,
    sparse_deposit_set: SparseMerkleTree,
    sparse_burn_set: SparseMerkleTree,
    sparse_burn_request_set: SparseMerkleTree,
    sparse_execution_anchor_set: SparseMerkleTree,
    sparse_beacon_anchor_set: SparseMerkleTree,
    execution_anchor_references: BTreeMap<u64, ExecutionAnchorReference>,
    beacon_anchor_references: BTreeMap<u64, BeaconAnchorReference>,
    note_anchors: VecDeque<NoteAnchor>,
    total_issued: u128,
    total_burned: u128,
    ethereum_anchor: Option<EthereumAnchor>,
    state_root: Hash256,
}

impl NativeUsdomState {
    /// Create the empty state for one immutable bridge/protocol identity.
    pub fn new(bridge: BridgeIdentity) -> Result<Self, UsdomStateError> {
        bridge.validate()?;
        let notes = Pmmr::new();
        let privacy_notes = IncrementalNoteTree::new();
        let empty_anchor = NoteAnchor {
            root: Hash256::from_bytes(privacy_notes.root().to_bytes()),
            leaf_count: 0,
        };
        let mut state = Self {
            domain: bridge.dom_domain,
            ethereum_genesis_validators_root: bridge.ethereum_genesis_validators_root,
            ethereum_chain_id: bridge.ethereum_chain_id,
            ethereum_checkpoint_policy_hash: bridge.ethereum_checkpoint_policy_hash,
            ethereum_deposit_policy_hash: bridge.ethereum_deposit_policy_hash,
            privacy_policy_hash: bridge.privacy_policy_hash,
            privacy_verifier_config_hash: bridge.privacy_verifier_config_hash,
            reserve: bridge.reserve,
            burn_timing: bridge.burn_timing,
            notes,
            privacy_notes,
            note_order: Vec::new(),
            note_commitments: BTreeSet::new(),
            nullifiers: BTreeSet::new(),
            consumed_deposits: BTreeMap::new(),
            burns: BTreeMap::new(),
            burn_request_ids: BTreeSet::new(),
            sparse_note_set: SparseMerkleTree::new(SPARSE_NOTE_SET)
                .map_err(map_sparse_state_error)?,
            sparse_nullifier_set: SparseMerkleTree::new(SPARSE_NULLIFIER_SET)
                .map_err(map_sparse_state_error)?,
            sparse_deposit_set: SparseMerkleTree::new(SPARSE_DEPOSIT_SET)
                .map_err(map_sparse_state_error)?,
            sparse_burn_set: SparseMerkleTree::new(SPARSE_BURN_SET)
                .map_err(map_sparse_state_error)?,
            sparse_burn_request_set: SparseMerkleTree::new(SPARSE_BURN_REQUEST_SET)
                .map_err(map_sparse_state_error)?,
            sparse_execution_anchor_set: SparseMerkleTree::new(SPARSE_EXECUTION_ANCHOR_SET)
                .map_err(map_sparse_state_error)?,
            sparse_beacon_anchor_set: SparseMerkleTree::new(SPARSE_BEACON_ANCHOR_SET)
                .map_err(map_sparse_state_error)?,
            execution_anchor_references: BTreeMap::new(),
            beacon_anchor_references: BTreeMap::new(),
            note_anchors: VecDeque::from([empty_anchor]),
            total_issued: 0,
            total_burned: 0,
            ethereum_anchor: None,
            state_root: Hash256::ZERO,
        };
        state.state_root = state.compute_state_root()?;
        Ok(state)
    }

    /// Immutable bridge/protocol domain.
    pub fn domain(&self) -> [u8; 32] {
        self.domain
    }

    /// Immutable EVM payout identity enforced for every native burn.
    pub fn bridge_identity(&self) -> BridgeIdentity {
        BridgeIdentity {
            dom_domain: self.domain,
            ethereum_genesis_validators_root: self.ethereum_genesis_validators_root,
            ethereum_chain_id: self.ethereum_chain_id,
            ethereum_checkpoint_policy_hash: self.ethereum_checkpoint_policy_hash,
            ethereum_deposit_policy_hash: self.ethereum_deposit_policy_hash,
            privacy_policy_hash: self.privacy_policy_hash,
            privacy_verifier_config_hash: self.privacy_verifier_config_hash,
            reserve: self.reserve,
            burn_timing: self.burn_timing,
        }
    }

    /// Current composite state root.
    pub fn state_root(&self) -> Hash256 {
        self.state_root
    }

    /// Export the candidate v2 decomposition. This does not change the active
    /// v1 state root or grant activation authority.
    pub fn state_commitment_v2(&self) -> Result<StateCommitmentV2, UsdomStateError> {
        let v1 = self.state_commitment()?;
        let sparse = self.experimental_authenticated_set_roots();
        Ok(StateCommitmentV2 {
            domain: v1.domain,
            ethereum_genesis_validators_root: v1.ethereum_genesis_validators_root,
            ethereum_chain_id: v1.ethereum_chain_id,
            reserve: v1.reserve,
            ethereum_checkpoint_policy_hash: v1.ethereum_checkpoint_policy_hash,
            ethereum_deposit_policy_hash: v1.ethereum_deposit_policy_hash,
            privacy_policy_hash: v1.privacy_policy_hash,
            privacy_verifier_config_hash: v1.privacy_verifier_config_hash,
            burn_timing: v1.burn_timing,
            notes_root: v1.notes_root,
            privacy_notes_root: v1.privacy_notes_root,
            note_count: v1.note_count,
            note_set_root: sparse.notes,
            note_set_count: self.note_commitments.len() as u64,
            nullifier_root: sparse.nullifiers,
            nullifier_count: self.nullifiers.len() as u64,
            deposit_root: sparse.deposits,
            deposit_count: self.consumed_deposits.len() as u64,
            burn_root: sparse.burns,
            burn_count: self.burns.len() as u64,
            burn_request_root: sparse.burn_requests,
            burn_request_count: self.burn_request_ids.len() as u64,
            execution_anchor_root: sparse.execution_anchors,
            execution_anchor_count: self.execution_anchor_references.len() as u64,
            beacon_anchor_root: sparse.beacon_anchors,
            beacon_anchor_count: self.beacon_anchor_references.len() as u64,
            anchor_root: v1.anchor_root,
            anchor_count: v1.anchor_count,
            total_issued: v1.total_issued,
            total_burned: v1.total_burned,
            ethereum_anchor: v1.ethereum_anchor,
        })
    }

    /// Read the parallel, non-consensus sparse roots used to validate the
    /// bounded migration and rollback implementation.
    pub fn experimental_authenticated_set_roots(&self) -> NativeAuthenticatedSetRoots {
        NativeAuthenticatedSetRoots {
            notes: self.sparse_note_set.root(),
            nullifiers: self.sparse_nullifier_set.root(),
            deposits: self.sparse_deposit_set.root(),
            burns: self.sparse_burn_set.root(),
            burn_requests: self.sparse_burn_request_set.root(),
            execution_anchors: self.sparse_execution_anchor_set.root(),
            beacon_anchors: self.sparse_beacon_anchor_set.root(),
        }
    }

    /// Export the bounded PMMR, Poseidon and retained-anchor opening for the
    /// current native state root.
    pub fn accumulator_witness(&self) -> Result<NativeAccumulatorWitness, UsdomStateError> {
        let witness = NativeAccumulatorWitness {
            pmmr: self
                .notes
                .frontier()
                .map_err(|error| UsdomStateError::NoteAccumulator(error.to_string()))?,
            privacy_notes: self.privacy_notes.clone(),
            anchors: self.note_anchors.clone(),
        };
        if !witness.verify(&self.state_commitment()?) {
            return Err(UsdomStateError::MalformedAccumulatorWitness);
        }
        Ok(witness)
    }

    /// Generate sequential sparse nonmembership paths for one already
    /// proof-verified transition against the candidate v2 roots.
    pub fn set_transition_witness(
        &self,
        transition: &VerifiedTransition,
    ) -> Result<NativeSetTransitionWitness, UsdomStateError> {
        if transition_domain(transition) != self.domain {
            return Err(UsdomStateError::DomainMismatch);
        }
        let mut notes = self.sparse_note_set.clone();
        let mut nullifiers = self.sparse_nullifier_set.clone();
        let mut deposits = self.sparse_deposit_set.clone();
        let mut burns = self.sparse_burn_set.clone();
        let mut requests = self.sparse_burn_request_set.clone();
        let mut execution_anchors = self.sparse_execution_anchor_set.clone();
        let mut beacon_anchors = self.sparse_beacon_anchor_set.clone();
        let mut proofs = Vec::new();
        let mut existing = Vec::new();
        for effect in native_set_effects(transition) {
            let tree = sparse_tree_for_kind_mut(
                effect.kind,
                &mut notes,
                &mut nullifiers,
                &mut deposits,
                &mut burns,
                &mut requests,
                &mut execution_anchors,
                &mut beacon_anchors,
            )?;
            let current = tree
                .leaf(effect.key)
                .map_err(|_| UsdomStateError::MalformedSetWitness)?;
            let is_existing = match current {
                Some(leaf) if effect.allow_existing && leaf == effect.leaf => true,
                Some(_) if effect.allow_existing => {
                    return Err(UsdomStateError::EthereumAnchorConflict)
                }
                Some(_) => return Err(UsdomStateError::MalformedSetWitness),
                None => false,
            };
            proofs.push(
                tree.prove(effect.key)
                    .map_err(|_| UsdomStateError::MalformedSetWitness)?,
            );
            existing.push(is_existing);
            if !is_existing {
                tree.insert(effect.key, effect.leaf)
                    .map_err(|_| UsdomStateError::MalformedSetWitness)?;
            }
        }
        let witness = NativeSetTransitionWitness { proofs, existing };
        witness.apply_sets(self.state_commitment_v2()?, transition)?;
        Ok(witness)
    }

    /// Export both bounded openings required by the candidate-v2 stateless
    /// executor for one already proof-verified transition.
    pub fn transition_witness(
        &self,
        context: BlockContext,
        transition: &VerifiedTransition,
    ) -> Result<NativeTransitionWitness, UsdomStateError> {
        let witness = NativeTransitionWitness {
            accumulators: self.accumulator_witness()?,
            sets: self.set_transition_witness(transition)?,
        };
        let previous = self.state_commitment_v2()?;
        witness.apply_v2(previous.root(), context, previous, transition)?;
        Ok(witness)
    }

    /// Generate the ordered bounded witnesses for one candidate-v2 block
    /// batch while checking the same atomic transition sequence as full state.
    pub fn transition_batch_witnesses(
        &self,
        context: BlockContext,
        transitions: &[VerifiedTransition],
    ) -> Result<Vec<NativeTransitionWitness>, UsdomStateError> {
        if transitions.len() > MAX_TRANSITIONS_PER_BATCH {
            return Err(UsdomStateError::BatchTooLarge);
        }
        let mut candidate = self.clone();
        let mut witnesses = Vec::with_capacity(transitions.len());
        for transition in transitions {
            witnesses.push(candidate.transition_witness(context, transition)?);
            candidate.apply(context, transition)?;
        }
        Ok(witnesses)
    }

    /// Current note-tree anchor.
    pub fn note_anchor(&self) -> NoteAnchor {
        NoteAnchor {
            root: Hash256::from_bytes(self.privacy_notes.root().to_bytes()),
            leaf_count: self.privacy_notes.leaf_count(),
        }
    }

    /// Total deposit-backed USDOM ever issued.
    pub fn total_issued(&self) -> u128 {
        self.total_issued
    }

    /// Total USDOM removed from circulation by native burns.
    pub fn total_burned(&self) -> u128 {
        self.total_burned
    }

    /// Issued supply that has not been burned.
    pub fn outstanding(&self) -> u128 {
        self.total_issued - self.total_burned
    }

    /// Most recent authenticated Ethereum anchor observed by issuance.
    pub fn ethereum_anchor(&self) -> Option<EthereumAnchor> {
        self.ethereum_anchor
    }

    /// Whether a finalized deposit occurrence has already authorized issuance.
    pub fn has_consumed_deposit(&self, deposit_id: &[u8; 32]) -> bool {
        self.consumed_deposits.contains_key(deposit_id)
    }

    /// Return one consumed deposit/issuance record.
    pub fn issuance(&self, deposit_id: &[u8; 32]) -> Option<IssuanceRecord> {
        self.consumed_deposits.get(deposit_id).copied()
    }

    /// Whether a nullifier has already been accepted.
    pub fn has_nullifier(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.contains(nullifier)
    }

    /// Return one committed public burn obligation.
    pub fn burn(&self, burn_id: &[u8; 32]) -> Option<BurnRecord> {
        self.burns.get(burn_id).copied()
    }

    /// Export the exact decomposition whose hash equals [`Self::state_root`].
    /// This is prover input, not evidence that any DOM block is finalized.
    pub fn state_commitment(&self) -> Result<StateCommitment, UsdomStateError> {
        let notes_root = self
            .notes
            .root()
            .map_err(|error| UsdomStateError::NoteAccumulator(error.to_string()))?;
        Ok(StateCommitment {
            domain: self.domain,
            ethereum_genesis_validators_root: self.ethereum_genesis_validators_root,
            ethereum_chain_id: self.ethereum_chain_id,
            reserve: self.reserve,
            ethereum_checkpoint_policy_hash: self.ethereum_checkpoint_policy_hash,
            ethereum_deposit_policy_hash: self.ethereum_deposit_policy_hash,
            privacy_policy_hash: self.privacy_policy_hash,
            privacy_verifier_config_hash: self.privacy_verifier_config_hash,
            burn_timing: self.burn_timing,
            notes_root,
            privacy_notes_root: self.privacy_notes.root().to_bytes(),
            note_count: self.notes.leaf_count(),
            note_set_root: fixed_set_root(1, self.note_commitments.iter().copied()),
            note_set_count: self.note_commitments.len() as u64,
            nullifier_root: fixed_set_root(2, self.nullifiers.iter().copied()),
            nullifier_count: self.nullifiers.len() as u64,
            deposit_root: issuance_set_root(&self.consumed_deposits),
            deposit_count: self.consumed_deposits.len() as u64,
            burn_root: burn_set_root(&self.burns),
            burn_count: self.burns.len() as u64,
            anchor_root: anchor_history_root(&self.note_anchors),
            anchor_count: self.note_anchors.len() as u64,
            total_issued: self.total_issued,
            total_burned: self.total_burned,
            ethereum_anchor: self.ethereum_anchor,
        })
    }

    /// Build a logarithmic inclusion path for one committed burn. The path is
    /// generated from the same ordered leaves used by the consensus state root.
    pub fn burn_inclusion_proof(&self, burn_id: &[u8; 32]) -> Option<BurnSetInclusionProof> {
        let record = self.burns.get(burn_id).copied()?;
        let leaf_index = self.burns.keys().position(|id| id == burn_id)?;
        let mut level: Vec<Hash256> = self.burns.values().copied().map(burn_leaf_hash).collect();
        let leaf_count = level.len();
        let mut index = leaf_index;
        let mut siblings = Vec::with_capacity(usize::BITS as usize);
        let mut depth = 0u32;
        while level.len() > 1 {
            if index % 2 == 1 {
                siblings.push(level[index - 1]);
            } else if index + 1 < level.len() {
                siblings.push(level[index + 1]);
            }
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                next.push(if pair.len() == 1 {
                    pair[0]
                } else {
                    set_node_hash(depth, pair[0], pair[1])
                });
            }
            level = next;
            index /= 2;
            depth += 1;
        }
        Some(BurnSetInclusionProof {
            record,
            leaf_index: leaf_index as u64,
            leaf_count: leaf_count as u64,
            siblings,
        })
    }

    /// Export the read-only state and inclusion inputs needed by a future
    /// finalized-burn proving program.
    pub fn burn_state_witness(
        &self,
        burn_id: &[u8; 32],
    ) -> Result<Option<BurnStateWitness>, UsdomStateError> {
        let Some(burn) = self.burn_inclusion_proof(burn_id) else {
            return Ok(None);
        };
        Ok(Some(BurnStateWitness {
            state: self.state_commitment()?,
            burn,
        }))
    }

    /// Whether a reserve request identifier has already been committed by a
    /// native burn, including a burn that has already been redeemed.
    pub fn has_burn_request(&self, request_id: &[u8; 32]) -> bool {
        self.burn_request_ids.contains(request_id)
    }

    /// Export the complete canonical key/value view for storage, snapshotting,
    /// startup verification, and deterministic diff construction.
    ///
    /// Secret note data is never included. Keys are versioned and ordered by
    /// `BTreeMap`; unknown keys are rejected by [`Self::restore_entries`].
    pub fn export_entries(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let mut entries = BTreeMap::new();
        entries.insert(state_key(b"meta/domain"), self.domain.to_vec());
        let mut bridge = Vec::with_capacity(260);
        bridge.extend_from_slice(&self.ethereum_genesis_validators_root);
        bridge.extend_from_slice(&self.ethereum_chain_id);
        bridge.extend_from_slice(&self.reserve);
        bridge.extend_from_slice(&self.ethereum_checkpoint_policy_hash);
        bridge.extend_from_slice(&self.ethereum_deposit_policy_hash);
        bridge.extend_from_slice(&self.privacy_policy_hash);
        bridge.extend_from_slice(&self.privacy_verifier_config_hash);
        encode_burn_timing_policy(&mut bridge, self.burn_timing);
        entries.insert(state_key(b"meta/bridge"), bridge);
        entries.insert(state_key(b"meta/root"), self.state_root.as_bytes().to_vec());
        let mut totals = Vec::with_capacity(32);
        totals.extend_from_slice(&self.total_issued.to_be_bytes());
        totals.extend_from_slice(&self.total_burned.to_be_bytes());
        entries.insert(state_key(b"meta/totals"), totals);
        if let Some(anchor) = self.ethereum_anchor {
            let mut encoded = Vec::with_capacity(120);
            encode_ethereum_anchor(&mut encoded, anchor);
            entries.insert(state_key(b"meta/ethereum"), encoded);
        }
        for (index, note) in self.note_order.iter().enumerate() {
            let mut key = state_key(b"note/");
            key.extend_from_slice(&(index as u64).to_be_bytes());
            entries.insert(key, note.to_vec());
        }
        for nullifier in &self.nullifiers {
            let mut key = state_key(b"nullifier/");
            key.extend_from_slice(nullifier);
            entries.insert(key, vec![1]);
        }
        for issuance in self.consumed_deposits.values() {
            let mut key = state_key(b"deposit/");
            key.extend_from_slice(&issuance.deposit_id);
            let mut value = Vec::with_capacity(160);
            value.extend_from_slice(&issuance.note_commitment);
            value.extend_from_slice(&issuance.amount.to_be_bytes());
            encode_ethereum_anchor(&mut value, issuance.ethereum_anchor);
            entries.insert(key, value);
        }
        for burn in self.burns.values() {
            let mut key = state_key(b"burn/");
            key.extend_from_slice(&burn.burn_id);
            let mut value = Vec::with_capacity(152);
            value.extend_from_slice(&burn.amount.to_be_bytes());
            value.extend_from_slice(&burn.recipient);
            value.extend_from_slice(&burn.request_id);
            value.extend_from_slice(&burn.ethereum_chain_id);
            value.extend_from_slice(&burn.reserve);
            value.extend_from_slice(&burn.valid_until.to_be_bytes());
            value.extend_from_slice(&burn.obligation_commitment);
            entries.insert(key, value);
        }
        for anchor in &self.note_anchors {
            let mut key = state_key(b"anchor/");
            key.extend_from_slice(&anchor.leaf_count.to_be_bytes());
            entries.insert(key, anchor.root.as_bytes().to_vec());
        }
        entries
    }

    /// Rebuild and fully verify native state from canonical persisted entries.
    ///
    /// Totals, note PMMR roots, retained anchors, issuance/burn records,
    /// Ethereum high-water identity, and the composite state root are all
    /// recomputed. A stored root or counter is never trusted by itself.
    pub fn restore_entries(
        expected_bridge: BridgeIdentity,
        entries: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<Self, UsdomStateError> {
        expected_bridge.validate()?;
        let domain = exact_entry(entries, b"meta/domain")?;
        if domain != expected_bridge.dom_domain {
            return Err(UsdomStateError::DomainMismatch);
        }
        let stored_bridge = entries
            .get(state_key(b"meta/bridge").as_slice())
            .ok_or(UsdomStateError::MalformedPersistedState)?;
        if stored_bridge.len() != 260
            || stored_bridge[..32] != expected_bridge.ethereum_genesis_validators_root
            || stored_bridge[32..64] != expected_bridge.ethereum_chain_id
            || stored_bridge[64..84] != expected_bridge.reserve
            || stored_bridge[84..116] != expected_bridge.ethereum_checkpoint_policy_hash
            || stored_bridge[116..148] != expected_bridge.ethereum_deposit_policy_hash
            || stored_bridge[148..180] != expected_bridge.privacy_policy_hash
            || stored_bridge[180..212] != expected_bridge.privacy_verifier_config_hash
            || stored_bridge[212..] != encode_burn_timing_policy_bytes(expected_bridge.burn_timing)
        {
            return Err(UsdomStateError::BridgeIdentityMismatch);
        }
        let committed_root = Hash256::from_bytes(exact_entry(entries, b"meta/root")?);
        let totals = exact_entry(entries, b"meta/totals")?;
        let total_issued = u128::from_be_bytes(
            totals[..16]
                .try_into()
                .map_err(|_| UsdomStateError::MalformedPersistedState)?,
        );
        let total_burned = u128::from_be_bytes(
            totals[16..]
                .try_into()
                .map_err(|_| UsdomStateError::MalformedPersistedState)?,
        );
        if total_burned > total_issued {
            return Err(UsdomStateError::MalformedPersistedState);
        }

        let mut notes_by_index = BTreeMap::new();
        let mut nullifiers = BTreeSet::new();
        let mut consumed_deposits = BTreeMap::new();
        let mut burns = BTreeMap::new();
        let mut burn_request_ids = BTreeSet::new();
        let mut stored_anchors = BTreeMap::new();
        let mut seen_keys = BTreeSet::new();
        for (key, value) in entries {
            if !key.starts_with(b"usdom/v3/") || !seen_keys.insert(key.as_slice()) {
                return Err(UsdomStateError::MalformedPersistedState);
            }
            let suffix = &key[b"usdom/v3/".len()..];
            if matches!(
                suffix,
                b"meta/domain" | b"meta/bridge" | b"meta/root" | b"meta/totals"
            ) {
                continue;
            }
            if suffix == b"meta/ethereum" {
                if value.len() != 120 {
                    return Err(UsdomStateError::MalformedPersistedState);
                }
                continue;
            }
            if let Some(raw_index) = suffix.strip_prefix(b"note/") {
                if raw_index.len() != 8 || value.len() != 32 {
                    return Err(UsdomStateError::MalformedPersistedState);
                }
                let index = u64::from_be_bytes(
                    raw_index
                        .try_into()
                        .map_err(|_| UsdomStateError::MalformedPersistedState)?,
                );
                let note: [u8; 32] = value
                    .as_slice()
                    .try_into()
                    .map_err(|_| UsdomStateError::MalformedPersistedState)?;
                if note == [0; 32]
                    || PrivacyScalar::from_bytes(note).is_err()
                    || notes_by_index.insert(index, note).is_some()
                {
                    return Err(UsdomStateError::MalformedPersistedState);
                }
                continue;
            }
            if let Some(raw_nullifier) = suffix.strip_prefix(b"nullifier/") {
                if raw_nullifier.len() != 32 || value.as_slice() != [1] {
                    return Err(UsdomStateError::MalformedPersistedState);
                }
                let nullifier: [u8; 32] = raw_nullifier
                    .try_into()
                    .map_err(|_| UsdomStateError::MalformedPersistedState)?;
                if nullifier == [0; 32]
                    || PrivacyScalar::from_bytes(nullifier).is_err()
                    || !nullifiers.insert(nullifier)
                {
                    return Err(UsdomStateError::MalformedPersistedState);
                }
                continue;
            }
            if let Some(raw_deposit) = suffix.strip_prefix(b"deposit/") {
                let deposit_id: [u8; 32] = raw_deposit
                    .try_into()
                    .map_err(|_| UsdomStateError::MalformedPersistedState)?;
                if deposit_id == [0; 32] || value.len() != 160 {
                    return Err(UsdomStateError::MalformedPersistedState);
                }
                let note_commitment = value[..32]
                    .try_into()
                    .map_err(|_| UsdomStateError::MalformedPersistedState)?;
                let amount = u64::from_be_bytes(
                    value[32..40]
                        .try_into()
                        .map_err(|_| UsdomStateError::MalformedPersistedState)?,
                );
                let mut reader = UndoReader::new(&value[40..]);
                let ethereum_anchor = decode_ethereum_anchor(&mut reader)?;
                ethereum_anchor.validate()?;
                if note_commitment == [0; 32]
                    || amount == 0
                    || !reader.is_empty()
                    || consumed_deposits
                        .insert(
                            deposit_id,
                            IssuanceRecord {
                                deposit_id,
                                note_commitment,
                                amount,
                                ethereum_anchor,
                            },
                        )
                        .is_some()
                {
                    return Err(UsdomStateError::MalformedPersistedState);
                }
                continue;
            }
            if let Some(raw_burn) = suffix.strip_prefix(b"burn/") {
                let burn_id: [u8; 32] = raw_burn
                    .try_into()
                    .map_err(|_| UsdomStateError::MalformedPersistedState)?;
                if burn_id == [0; 32] || value.len() != 152 {
                    return Err(UsdomStateError::MalformedPersistedState);
                }
                let record = BurnRecord {
                    burn_id,
                    amount: u64::from_be_bytes(
                        value[..8]
                            .try_into()
                            .map_err(|_| UsdomStateError::MalformedPersistedState)?,
                    ),
                    recipient: value[8..28]
                        .try_into()
                        .map_err(|_| UsdomStateError::MalformedPersistedState)?,
                    request_id: value[28..60]
                        .try_into()
                        .map_err(|_| UsdomStateError::MalformedPersistedState)?,
                    ethereum_chain_id: value[60..92]
                        .try_into()
                        .map_err(|_| UsdomStateError::MalformedPersistedState)?,
                    reserve: value[92..112]
                        .try_into()
                        .map_err(|_| UsdomStateError::MalformedPersistedState)?,
                    valid_until: u64::from_be_bytes(
                        value[112..120]
                            .try_into()
                            .map_err(|_| UsdomStateError::MalformedPersistedState)?,
                    ),
                    obligation_commitment: value[120..152]
                        .try_into()
                        .map_err(|_| UsdomStateError::MalformedPersistedState)?,
                };
                if record.amount == 0
                    || record.recipient == [0; 20]
                    || record.request_id == [0; 32]
                    || record.ethereum_chain_id == [0; 32]
                    || record.reserve == [0; 20]
                    || record.valid_until == 0
                    || record.obligation_commitment == [0; 32]
                    || record.ethereum_chain_id != expected_bridge.ethereum_chain_id
                    || record.reserve != expected_bridge.reserve
                    || record.expected_obligation_commitment(expected_bridge.dom_domain)
                        != record.obligation_commitment
                    || !burn_request_ids.insert(record.request_id)
                    || burns.insert(burn_id, record).is_some()
                {
                    return Err(UsdomStateError::MalformedPersistedState);
                }
                continue;
            }
            if let Some(raw_count) = suffix.strip_prefix(b"anchor/") {
                if raw_count.len() != 8 || value.len() != 32 {
                    return Err(UsdomStateError::MalformedPersistedState);
                }
                let count = u64::from_be_bytes(
                    raw_count
                        .try_into()
                        .map_err(|_| UsdomStateError::MalformedPersistedState)?,
                );
                let root = Hash256::from_bytes(
                    value
                        .as_slice()
                        .try_into()
                        .map_err(|_| UsdomStateError::MalformedPersistedState)?,
                );
                if root == Hash256::ZERO || stored_anchors.insert(count, root).is_some() {
                    return Err(UsdomStateError::MalformedPersistedState);
                }
                continue;
            }
            return Err(UsdomStateError::MalformedPersistedState);
        }

        let mut state = Self::new(expected_bridge)?;
        state.note_anchors.clear();
        let mut roots_by_count = BTreeMap::from([(0, state.note_anchor().root)]);
        for (expected_index, (index, note)) in notes_by_index.into_iter().enumerate() {
            if index != expected_index as u64 || !state.note_commitments.insert(note) {
                return Err(UsdomStateError::MalformedPersistedState);
            }
            let mut payload = Vec::with_capacity(64);
            payload.extend_from_slice(&state.domain);
            payload.extend_from_slice(&note);
            let leaf = blake2b_256_tagged(TAG_NOTE_PAYLOAD, &payload);
            state
                .notes
                .push(leaf.as_bytes())
                .map_err(|error| UsdomStateError::NoteAccumulator(error.to_string()))?;
            state
                .privacy_notes
                .append(
                    PrivacyScalar::from_bytes(note)
                        .map_err(|_| UsdomStateError::MalformedPersistedState)?,
                )
                .map_err(|_| UsdomStateError::MalformedPersistedState)?;
            state.note_order.push(note);
            roots_by_count.insert(state.privacy_notes.leaf_count(), state.note_anchor().root);
        }
        if stored_anchors.is_empty() || stored_anchors.len() > NOTE_ANCHOR_HISTORY {
            return Err(UsdomStateError::MalformedPersistedState);
        }
        for (count, root) in stored_anchors {
            if roots_by_count.get(&count) != Some(&root) {
                return Err(UsdomStateError::MalformedPersistedState);
            }
            state.note_anchors.push_back(NoteAnchor {
                root,
                leaf_count: count,
            });
        }
        if state.note_anchors.back() != Some(&state.note_anchor()) {
            return Err(UsdomStateError::MalformedPersistedState);
        }
        state.nullifiers = nullifiers;
        state.consumed_deposits = consumed_deposits;
        state.burns = burns;
        state.burn_request_ids = burn_request_ids;
        state.rebuild_sparse_set_caches()?;
        if state
            .consumed_deposits
            .values()
            .any(|issuance| !state.note_commitments.contains(&issuance.note_commitment))
        {
            return Err(UsdomStateError::MalformedPersistedState);
        }
        let computed_issued = state
            .consumed_deposits
            .values()
            .try_fold(0u128, |sum, issuance| {
                sum.checked_add(u128::from(issuance.amount))
            })
            .ok_or(UsdomStateError::MonetaryOverflow)?;
        let computed_burned = state
            .burns
            .values()
            .try_fold(0u128, |sum, burn| sum.checked_add(u128::from(burn.amount)))
            .ok_or(UsdomStateError::MonetaryOverflow)?;
        if computed_issued != total_issued || computed_burned != total_burned {
            return Err(UsdomStateError::MalformedPersistedState);
        }
        state.total_issued = total_issued;
        state.total_burned = total_burned;
        let issuance_high_water = derive_ethereum_high_water(&state.consumed_deposits)?;
        let stored_ethereum = entries.get(state_key(b"meta/ethereum").as_slice());
        state.ethereum_anchor = match stored_ethereum {
            None if issuance_high_water.is_none() => None,
            Some(bytes) if bytes.len() == 120 => {
                let mut reader = UndoReader::new(bytes);
                let decoded = decode_ethereum_anchor(&mut reader)?;
                decoded.validate()?;
                if !reader.is_empty()
                    || decoded.genesis_validators_root
                        != expected_bridge.ethereum_genesis_validators_root
                    || merge_ethereum_anchor(issuance_high_water, Some(decoded))? != Some(decoded)
                {
                    return Err(UsdomStateError::MalformedPersistedState);
                }
                Some(decoded)
            }
            _ => return Err(UsdomStateError::MalformedPersistedState),
        };
        state.state_root = state.compute_state_root()?;
        if state.state_root != committed_root {
            return Err(UsdomStateError::PersistedStateRootMismatch);
        }
        if state.export_entries() != *entries {
            return Err(UsdomStateError::MalformedPersistedState);
        }
        Ok(state)
    }

    /// Produce the bytewise minimal deterministic storage delta from `previous`
    /// to this state. Both complete states must belong to the same domain.
    pub fn storage_delta_from(
        &self,
        previous: &Self,
    ) -> Result<Vec<CanonicalStateUpdate>, UsdomStateError> {
        if self.bridge_identity() != previous.bridge_identity() {
            return Err(UsdomStateError::BridgeIdentityMismatch);
        }
        let before = previous.export_entries();
        let after = self.export_entries();
        let keys: BTreeSet<Vec<u8>> = before.keys().chain(after.keys()).cloned().collect();
        let mut updates = Vec::new();
        for key in keys {
            if before.get(&key) != after.get(&key) {
                updates.push(CanonicalStateUpdate {
                    value: after.get(&key).cloned(),
                    key,
                });
            }
        }
        Ok(updates)
    }

    /// Validate and apply one proof-verified transition atomically in memory.
    /// On failure, `self` is unchanged.
    pub fn apply(
        &mut self,
        context: BlockContext,
        transition: &VerifiedTransition,
    ) -> Result<(TransitionReceipt, StateUndo), UsdomStateError> {
        if context.timestamp == 0 {
            return Err(UsdomStateError::InvalidBlockContext);
        }
        let previous = self.clone();
        let mut candidate = self.clone();
        let kind = match transition {
            VerifiedTransition::Issue(value) => {
                candidate.apply_issuance(value)?;
                TransitionKind::Issue
            }
            VerifiedTransition::Transfer(value) => {
                candidate.apply_transfer(value)?;
                TransitionKind::Transfer
            }
            VerifiedTransition::Burn(value) => {
                candidate.apply_burn(context, value)?;
                TransitionKind::Burn
            }
            VerifiedTransition::EthereumCheckpoint(value) => {
                candidate.apply_ethereum_checkpoint(value)?;
                TransitionKind::EthereumCheckpoint
            }
        };
        candidate.refresh_note_anchor()?;
        candidate.state_root = candidate.compute_state_root()?;
        let undo = StateUndo::between(&previous, &candidate);
        let receipt = TransitionReceipt {
            kind,
            previous_state_root: previous.state_root,
            new_state_root: candidate.state_root,
            note_anchor: candidate.note_anchor(),
            total_issued: candidate.total_issued,
            total_burned: candidate.total_burned,
        };
        *self = candidate;
        Ok((receipt, undo))
    }

    /// Atomically validate and apply the ordered USDOM transitions carried by
    /// one future DOM block envelope. Failure at any position leaves `self`
    /// unchanged. Empty batches are valid so every block can commit a unique
    /// before/after state pair without inventing a synthetic transition.
    pub fn apply_batch(
        &mut self,
        context: BlockContext,
        transitions: &[VerifiedTransition],
    ) -> Result<(TransitionBatchReceipt, BatchUndo), UsdomStateError> {
        if context.timestamp == 0 {
            return Err(UsdomStateError::InvalidBlockContext);
        }
        if transitions.len() > MAX_TRANSITIONS_PER_BATCH {
            return Err(UsdomStateError::BatchTooLarge);
        }
        let previous_state_root = self.state_root;
        let projections: Vec<_> = transitions
            .iter()
            .map(VerifiedTransition::commitment_projection)
            .collect();
        let commitments: Vec<_> = projections
            .iter()
            .map(|projection| projection.consensus_commitment())
            .collect::<Result<_, _>>()?;
        let transitions_root = transition_batch_root(self.domain, &commitments)?;
        let mut candidate = self.clone();
        let mut undos = Vec::with_capacity(transitions.len());
        for transition in transitions {
            let (_, undo) = candidate.apply(context, transition)?;
            undos.push(undo);
        }
        let transition_count: u32 = transitions
            .len()
            .try_into()
            .map_err(|_| UsdomStateError::BatchTooLarge)?;
        let header_commitment = batch_header_commitment(
            self.domain,
            transition_count,
            context.timestamp,
            transitions_root,
            previous_state_root,
            candidate.state_root,
        );
        let receipt = TransitionBatchReceipt {
            version: TRANSITION_BATCH_VERSION,
            transition_count,
            block_timestamp: context.timestamp,
            transitions_root,
            previous_state_root,
            new_state_root: candidate.state_root,
            header_commitment,
        };
        let undo = BatchUndo {
            before_root: previous_state_root,
            after_root: candidate.state_root,
            transitions_root,
            block_timestamp: context.timestamp,
            undos,
            projections,
        };
        *self = candidate;
        Ok((receipt, undo))
    }

    /// Revert the exact latest ordered block batch. All inverse transitions are
    /// checked on a clone before the live state is replaced. The expected
    /// commitment must come from the authenticated DOM block header; persisted
    /// undo bytes never authorize their own rollback.
    pub fn revert_batch(
        &mut self,
        undo: &BatchUndo,
        expected_header_commitment: Hash256,
    ) -> Result<(), UsdomStateError> {
        if self.state_root != undo.after_root
            || undo.undos.len() > MAX_TRANSITIONS_PER_BATCH
            || validate_batch_projection_root(undo, self.domain).is_err()
            || expected_header_commitment == Hash256::ZERO
            || expected_header_commitment
                != batch_header_commitment(
                    self.domain,
                    undo.undos
                        .len()
                        .try_into()
                        .map_err(|_| UsdomStateError::UndoMismatch)?,
                    undo.block_timestamp,
                    undo.transitions_root,
                    undo.before_root,
                    undo.after_root,
                )
        {
            return Err(UsdomStateError::UndoMismatch);
        }
        let mut candidate = self.clone();
        for transition_undo in undo.undos.iter().rev() {
            candidate.revert(transition_undo)?;
        }
        if candidate.state_root != undo.before_root {
            return Err(UsdomStateError::UndoMismatch);
        }
        *self = candidate;
        Ok(())
    }

    /// Revert the exact latest transition represented by `undo`.
    pub fn revert(&mut self, undo: &StateUndo) -> Result<(), UsdomStateError> {
        if self.state_root != undo.after_root {
            return Err(UsdomStateError::UndoMismatch);
        }
        let mut candidate = self.clone();
        candidate
            .notes
            .rewind(undo.prior_note_count)
            .map_err(|error| UsdomStateError::NoteAccumulator(error.to_string()))?;
        let prior_note_count: usize = undo
            .prior_note_count
            .try_into()
            .map_err(|_| UsdomStateError::UndoMismatch)?;
        if candidate.note_order.len() < prior_note_count {
            return Err(UsdomStateError::UndoMismatch);
        }
        let removed_suffix: BTreeSet<[u8; 32]> = candidate.note_order[prior_note_count..]
            .iter()
            .copied()
            .collect();
        if removed_suffix != undo.inserted_notes.iter().copied().collect() {
            return Err(UsdomStateError::UndoMismatch);
        }
        candidate.note_order.truncate(prior_note_count);
        candidate.privacy_notes = IncrementalNoteTree::new();
        for note in &candidate.note_order {
            candidate
                .privacy_notes
                .append(
                    PrivacyScalar::from_bytes(*note).map_err(|_| UsdomStateError::UndoMismatch)?,
                )
                .map_err(|_| UsdomStateError::UndoMismatch)?;
        }
        for note in &undo.inserted_notes {
            if !candidate.note_commitments.remove(note) {
                return Err(UsdomStateError::UndoMismatch);
            }
            candidate
                .sparse_note_set
                .remove(*note, sparse_fixed_leaf(SPARSE_NOTE_SET, *note))
                .map_err(|_| UsdomStateError::UndoMismatch)?;
        }
        for nullifier in &undo.inserted_nullifiers {
            if !candidate.nullifiers.remove(nullifier) {
                return Err(UsdomStateError::UndoMismatch);
            }
            candidate
                .sparse_nullifier_set
                .remove(
                    *nullifier,
                    sparse_fixed_leaf(SPARSE_NULLIFIER_SET, *nullifier),
                )
                .map_err(|_| UsdomStateError::UndoMismatch)?;
        }
        if let Some(deposit) = undo.inserted_deposit {
            let issuance = candidate
                .consumed_deposits
                .remove(&deposit)
                .ok_or(UsdomStateError::UndoMismatch)?;
            candidate
                .sparse_deposit_set
                .remove(deposit, sparse_issuance_leaf(issuance))
                .map_err(|_| UsdomStateError::UndoMismatch)?;
            candidate
                .remove_issuance_anchor_references(issuance.ethereum_anchor)
                .map_err(|_| UsdomStateError::UndoMismatch)?;
        }
        if let Some(burn) = undo.inserted_burn {
            let record = candidate
                .burns
                .remove(&burn)
                .ok_or(UsdomStateError::UndoMismatch)?;
            if !candidate.burn_request_ids.remove(&record.request_id) {
                return Err(UsdomStateError::UndoMismatch);
            }
            candidate
                .sparse_burn_set
                .remove(burn, burn_leaf_hash(record))
                .map_err(|_| UsdomStateError::UndoMismatch)?;
            candidate
                .sparse_burn_request_set
                .remove(
                    record.request_id,
                    sparse_fixed_leaf(SPARSE_BURN_REQUEST_SET, record.request_id),
                )
                .map_err(|_| UsdomStateError::UndoMismatch)?;
        }
        candidate.total_issued = undo.prior_total_issued;
        candidate.total_burned = undo.prior_total_burned;
        candidate.ethereum_anchor = undo.prior_ethereum_anchor;
        candidate.note_anchors = undo.prior_note_anchors.clone();
        candidate.state_root = candidate.compute_state_root()?;
        if candidate.state_root != undo.before_root {
            return Err(UsdomStateError::UndoMismatch);
        }
        *self = candidate;
        Ok(())
    }

    fn apply_issuance(&mut self, value: &VerifiedIssuance) -> Result<(), UsdomStateError> {
        self.require_domain(value.domain)?;
        value.ethereum_anchor.validate()?;
        if value.ethereum_anchor.genesis_validators_root != self.ethereum_genesis_validators_root {
            return Err(UsdomStateError::BridgeIdentityMismatch);
        }
        if value.deposit_id == [0; 32] || value.note_commitment == [0; 32] || value.amount == 0 {
            return Err(UsdomStateError::ZeroIdentity);
        }
        if self.consumed_deposits.contains_key(&value.deposit_id) {
            return Err(UsdomStateError::DepositAlreadyConsumed);
        }
        self.insert_notes(std::slice::from_ref(&value.note_commitment))?;
        let issuance = IssuanceRecord {
            deposit_id: value.deposit_id,
            note_commitment: value.note_commitment,
            amount: value.amount,
            ethereum_anchor: value.ethereum_anchor,
        };
        self.insert_issuance_anchor_references(value.ethereum_anchor)?;
        self.sparse_deposit_set
            .insert(value.deposit_id, sparse_issuance_leaf(issuance))
            .map_err(map_sparse_state_error)?;
        self.consumed_deposits.insert(value.deposit_id, issuance);
        self.total_issued = self
            .total_issued
            .checked_add(u128::from(value.amount))
            .ok_or(UsdomStateError::MonetaryOverflow)?;
        // Re-derive all execution/checkpoint identity constraints after every
        // issuance. Historical deposits can share one later finalized Beacon
        // checkpoint, so execution height and checkpoint slot are deliberately
        // not treated as a one-to-one sequence.
        let issuance_high_water = derive_ethereum_high_water(&self.consumed_deposits)?;
        self.ethereum_anchor = merge_ethereum_anchor(self.ethereum_anchor, issuance_high_water)?;
        Ok(())
    }

    fn insert_issuance_anchor_references(
        &mut self,
        anchor: EthereumAnchor,
    ) -> Result<(), UsdomStateError> {
        use std::collections::btree_map::Entry;

        match self
            .execution_anchor_references
            .entry(anchor.execution_block_number)
        {
            Entry::Vacant(entry) => {
                self.sparse_execution_anchor_set
                    .insert(
                        sparse_u64_key(anchor.execution_block_number),
                        sparse_execution_anchor_leaf(anchor),
                    )
                    .map_err(map_sparse_state_error)?;
                entry.insert(ExecutionAnchorReference {
                    block_hash: anchor.execution_block_hash,
                    timestamp: anchor.execution_block_timestamp,
                    references: 1,
                });
            }
            Entry::Occupied(mut entry) => {
                let current = entry.get_mut();
                if current.block_hash != anchor.execution_block_hash
                    || current.timestamp != anchor.execution_block_timestamp
                {
                    return Err(UsdomStateError::EthereumAnchorConflict);
                }
                current.references = current
                    .references
                    .checked_add(1)
                    .ok_or(UsdomStateError::MonetaryOverflow)?;
            }
        }
        match self.beacon_anchor_references.entry(anchor.beacon_slot) {
            Entry::Vacant(entry) => {
                self.sparse_beacon_anchor_set
                    .insert(
                        sparse_u64_key(anchor.beacon_slot),
                        sparse_beacon_anchor_leaf(anchor),
                    )
                    .map_err(map_sparse_state_error)?;
                entry.insert(BeaconAnchorReference {
                    anchor,
                    references: 1,
                });
            }
            Entry::Occupied(mut entry) => {
                let current = entry.get_mut();
                if current.anchor != anchor {
                    return Err(UsdomStateError::EthereumAnchorConflict);
                }
                current.references = current
                    .references
                    .checked_add(1)
                    .ok_or(UsdomStateError::MonetaryOverflow)?;
            }
        }
        Ok(())
    }

    fn remove_issuance_anchor_references(
        &mut self,
        anchor: EthereumAnchor,
    ) -> Result<(), UsdomStateError> {
        use std::collections::btree_map::Entry;

        match self
            .execution_anchor_references
            .entry(anchor.execution_block_number)
        {
            Entry::Occupied(mut entry)
                if entry.get().block_hash == anchor.execution_block_hash
                    && entry.get().timestamp == anchor.execution_block_timestamp
                    && entry.get().references > 1 =>
            {
                entry.get_mut().references -= 1;
            }
            Entry::Occupied(entry)
                if entry.get().block_hash == anchor.execution_block_hash
                    && entry.get().timestamp == anchor.execution_block_timestamp
                    && entry.get().references == 1 =>
            {
                entry.remove();
                self.sparse_execution_anchor_set
                    .remove(
                        sparse_u64_key(anchor.execution_block_number),
                        sparse_execution_anchor_leaf(anchor),
                    )
                    .map_err(map_sparse_state_error)?;
            }
            _ => {
                return Err(UsdomStateError::AuthenticatedSetCache(
                    "execution anchor reference mismatch".into(),
                ))
            }
        }
        match self.beacon_anchor_references.entry(anchor.beacon_slot) {
            Entry::Occupied(mut entry)
                if entry.get().anchor == anchor && entry.get().references > 1 =>
            {
                entry.get_mut().references -= 1;
            }
            Entry::Occupied(entry)
                if entry.get().anchor == anchor && entry.get().references == 1 =>
            {
                entry.remove();
                self.sparse_beacon_anchor_set
                    .remove(
                        sparse_u64_key(anchor.beacon_slot),
                        sparse_beacon_anchor_leaf(anchor),
                    )
                    .map_err(map_sparse_state_error)?;
            }
            _ => {
                return Err(UsdomStateError::AuthenticatedSetCache(
                    "beacon anchor reference mismatch".into(),
                ))
            }
        }
        Ok(())
    }

    fn apply_ethereum_checkpoint(
        &mut self,
        value: &VerifiedEthereumCheckpoint,
    ) -> Result<(), UsdomStateError> {
        self.require_domain(value.domain)?;
        value.anchor.validate()?;
        if value.anchor.genesis_validators_root != self.ethereum_genesis_validators_root {
            return Err(UsdomStateError::BridgeIdentityMismatch);
        }
        let next = merge_ethereum_anchor(self.ethereum_anchor, Some(value.anchor))?;
        if next == self.ethereum_anchor {
            return Err(UsdomStateError::EthereumAnchorNotAdvanced);
        }
        self.ethereum_anchor = next;
        Ok(())
    }

    fn apply_transfer(&mut self, value: &VerifiedTransfer) -> Result<(), UsdomStateError> {
        self.require_domain(value.domain)?;
        self.require_anchor(value.anchor)?;
        validate_shape(&value.nullifiers, &value.output_notes, false)?;
        self.insert_nullifiers(&value.nullifiers)?;
        self.insert_notes(&value.output_notes)
    }

    fn apply_burn(
        &mut self,
        context: BlockContext,
        value: &VerifiedBurn,
    ) -> Result<(), UsdomStateError> {
        self.require_domain(value.domain)?;
        self.require_anchor(value.anchor)?;
        validate_shape(&value.nullifiers, &value.change_notes, true)?;
        if value.record.burn_id == [0; 32]
            || value.record.request_id == [0; 32]
            || value.record.amount == 0
            || value.record.recipient == [0; 20]
            || value.record.ethereum_chain_id == [0; 32]
            || value.record.reserve == [0; 20]
            || value.record.valid_until == 0
            || value.record.obligation_commitment == [0; 32]
        {
            return Err(UsdomStateError::ZeroIdentity);
        }
        if self.burns.contains_key(&value.record.burn_id) {
            return Err(UsdomStateError::BurnAlreadyExists);
        }
        if self.burn_request_ids.contains(&value.record.request_id) {
            return Err(UsdomStateError::BurnRequestAlreadyExists);
        }
        if value.record.ethereum_chain_id != self.ethereum_chain_id
            || value.record.reserve != self.reserve
        {
            return Err(UsdomStateError::BridgeIdentityMismatch);
        }
        if derive_private_burn_id(
            self.bridge_identity(),
            &value.nullifiers,
            value.record.recipient,
            value.record.amount,
            value.record.valid_until,
        )? != value.record.burn_id
        {
            return Err(UsdomStateError::BurnIntentMismatch);
        }
        let ethereum_anchor = self
            .ethereum_anchor
            .ok_or(UsdomStateError::InvalidBurnWindow)?;
        let latest_fresh_dom_timestamp = ethereum_anchor
            .execution_block_timestamp
            .checked_add(self.burn_timing.max_ethereum_anchor_age_secs)
            .ok_or(UsdomStateError::InvalidBurnWindow)?;
        let freshness_reference = context
            .timestamp
            .saturating_sub(self.burn_timing.max_dom_clock_lead_secs);
        if freshness_reference > latest_fresh_dom_timestamp {
            return Err(UsdomStateError::InvalidBurnWindow);
        }
        // Use whichever authenticated clock is later for the minimum.  The
        // maximum is based only on finalized Ethereum time, so a DOM clock
        // cannot create a certificate that exceeds the reserve's seven-day
        // admission bound.  The reserve independently rechecks both bounds at
        // queue time and therefore fails closed if relaying takes too long.
        let reference_timestamp = context
            .timestamp
            .max(ethereum_anchor.execution_block_timestamp);
        let earliest = reference_timestamp
            .checked_add(self.burn_timing.withdrawal_delay_secs)
            .and_then(|value| value.checked_add(self.burn_timing.min_execution_window_secs))
            .and_then(|value| value.checked_add(self.burn_timing.relay_safety_margin_secs))
            .ok_or(UsdomStateError::InvalidBurnWindow)?;
        let latest = ethereum_anchor
            .execution_block_timestamp
            .checked_add(self.burn_timing.max_certificate_lifetime_secs)
            .ok_or(UsdomStateError::InvalidBurnWindow)?;
        if value.record.valid_until < earliest || value.record.valid_until > latest {
            return Err(UsdomStateError::InvalidBurnWindow);
        }
        if value.record.expected_obligation_commitment(self.domain)
            != value.record.obligation_commitment
        {
            return Err(UsdomStateError::BurnIntentMismatch);
        }
        let next_burned = self
            .total_burned
            .checked_add(u128::from(value.record.amount))
            .ok_or(UsdomStateError::MonetaryOverflow)?;
        if next_burned > self.total_issued {
            return Err(UsdomStateError::BurnExceedsSupply);
        }
        self.insert_nullifiers(&value.nullifiers)?;
        self.insert_notes(&value.change_notes)?;
        self.sparse_burn_set
            .insert(value.record.burn_id, burn_leaf_hash(value.record))
            .map_err(map_sparse_state_error)?;
        self.sparse_burn_request_set
            .insert(
                value.record.request_id,
                sparse_fixed_leaf(SPARSE_BURN_REQUEST_SET, value.record.request_id),
            )
            .map_err(map_sparse_state_error)?;
        self.burns.insert(value.record.burn_id, value.record);
        self.burn_request_ids.insert(value.record.request_id);
        self.total_burned = next_burned;
        Ok(())
    }

    fn require_domain(&self, domain: [u8; 32]) -> Result<(), UsdomStateError> {
        if domain != self.domain {
            return Err(UsdomStateError::DomainMismatch);
        }
        Ok(())
    }

    fn require_anchor(&self, anchor: NoteAnchor) -> Result<(), UsdomStateError> {
        if !self.note_anchors.contains(&anchor) {
            return Err(UsdomStateError::UnknownNoteAnchor);
        }
        Ok(())
    }

    fn insert_notes(&mut self, notes: &[[u8; 32]]) -> Result<(), UsdomStateError> {
        let mut transition_unique = BTreeSet::new();
        for note in notes {
            if *note == [0; 32]
                || !transition_unique.insert(*note)
                || self.note_commitments.contains(note)
            {
                return Err(UsdomStateError::DuplicateNote);
            }
            PrivacyScalar::from_bytes(*note)
                .map_err(|_| UsdomStateError::InvalidPrivacyCommitment)?;
        }
        for note in notes {
            let mut payload = Vec::with_capacity(64);
            payload.extend_from_slice(&self.domain);
            payload.extend_from_slice(note);
            let leaf = blake2b_256_tagged(TAG_NOTE_PAYLOAD, &payload);
            self.notes
                .push(leaf.as_bytes())
                .map_err(|error| UsdomStateError::NoteAccumulator(error.to_string()))?;
            self.privacy_notes
                .append(
                    PrivacyScalar::from_bytes(*note)
                        .map_err(|_| UsdomStateError::InvalidPrivacyCommitment)?,
                )
                .map_err(|_| UsdomStateError::InvalidPrivacyCommitment)?;
            self.note_order.push(*note);
            self.sparse_note_set
                .insert(*note, sparse_fixed_leaf(SPARSE_NOTE_SET, *note))
                .map_err(map_sparse_state_error)?;
            self.note_commitments.insert(*note);
        }
        Ok(())
    }

    fn insert_nullifiers(&mut self, nullifiers: &[[u8; 32]]) -> Result<(), UsdomStateError> {
        let mut transition_unique = BTreeSet::new();
        for nullifier in nullifiers {
            if *nullifier == [0; 32]
                || !transition_unique.insert(*nullifier)
                || self.nullifiers.contains(nullifier)
            {
                return Err(UsdomStateError::NullifierAlreadySpent);
            }
            PrivacyScalar::from_bytes(*nullifier)
                .map_err(|_| UsdomStateError::InvalidPrivacyNullifier)?;
        }
        for nullifier in nullifiers {
            self.sparse_nullifier_set
                .insert(
                    *nullifier,
                    sparse_fixed_leaf(SPARSE_NULLIFIER_SET, *nullifier),
                )
                .map_err(map_sparse_state_error)?;
            self.nullifiers.insert(*nullifier);
        }
        Ok(())
    }

    fn refresh_note_anchor(&mut self) -> Result<(), UsdomStateError> {
        let anchor = self.note_anchor();
        if self.note_anchors.back() != Some(&anchor) {
            self.note_anchors.push_back(anchor);
            while self.note_anchors.len() > NOTE_ANCHOR_HISTORY {
                self.note_anchors.pop_front();
            }
        }
        Ok(())
    }

    fn rebuild_sparse_set_caches(&mut self) -> Result<(), UsdomStateError> {
        let mut notes = SparseMerkleTree::new(SPARSE_NOTE_SET).map_err(map_sparse_state_error)?;
        for note in &self.note_commitments {
            notes
                .insert(*note, sparse_fixed_leaf(SPARSE_NOTE_SET, *note))
                .map_err(map_sparse_state_error)?;
        }
        let mut nullifiers =
            SparseMerkleTree::new(SPARSE_NULLIFIER_SET).map_err(map_sparse_state_error)?;
        for nullifier in &self.nullifiers {
            nullifiers
                .insert(
                    *nullifier,
                    sparse_fixed_leaf(SPARSE_NULLIFIER_SET, *nullifier),
                )
                .map_err(map_sparse_state_error)?;
        }
        let mut deposits =
            SparseMerkleTree::new(SPARSE_DEPOSIT_SET).map_err(map_sparse_state_error)?;
        for issuance in self.consumed_deposits.values().copied() {
            deposits
                .insert(issuance.deposit_id, sparse_issuance_leaf(issuance))
                .map_err(map_sparse_state_error)?;
        }
        let mut burns = SparseMerkleTree::new(SPARSE_BURN_SET).map_err(map_sparse_state_error)?;
        for burn in self.burns.values().copied() {
            burns
                .insert(burn.burn_id, burn_leaf_hash(burn))
                .map_err(map_sparse_state_error)?;
        }
        let mut requests =
            SparseMerkleTree::new(SPARSE_BURN_REQUEST_SET).map_err(map_sparse_state_error)?;
        for request in &self.burn_request_ids {
            requests
                .insert(
                    *request,
                    sparse_fixed_leaf(SPARSE_BURN_REQUEST_SET, *request),
                )
                .map_err(map_sparse_state_error)?;
        }
        let mut execution_anchors =
            SparseMerkleTree::new(SPARSE_EXECUTION_ANCHOR_SET).map_err(map_sparse_state_error)?;
        let mut beacon_anchors =
            SparseMerkleTree::new(SPARSE_BEACON_ANCHOR_SET).map_err(map_sparse_state_error)?;
        let mut execution_anchor_references = BTreeMap::new();
        let mut beacon_anchor_references = BTreeMap::new();
        for issuance in self.consumed_deposits.values() {
            let anchor = issuance.ethereum_anchor;
            match execution_anchor_references.entry(anchor.execution_block_number) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    execution_anchors
                        .insert(
                            sparse_u64_key(anchor.execution_block_number),
                            sparse_execution_anchor_leaf(anchor),
                        )
                        .map_err(map_sparse_state_error)?;
                    entry.insert(ExecutionAnchorReference {
                        block_hash: anchor.execution_block_hash,
                        timestamp: anchor.execution_block_timestamp,
                        references: 1,
                    });
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let current = entry.get_mut();
                    if current.block_hash != anchor.execution_block_hash
                        || current.timestamp != anchor.execution_block_timestamp
                    {
                        return Err(UsdomStateError::EthereumAnchorConflict);
                    }
                    current.references = current
                        .references
                        .checked_add(1)
                        .ok_or(UsdomStateError::MonetaryOverflow)?;
                }
            }
            match beacon_anchor_references.entry(anchor.beacon_slot) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    beacon_anchors
                        .insert(
                            sparse_u64_key(anchor.beacon_slot),
                            sparse_beacon_anchor_leaf(anchor),
                        )
                        .map_err(map_sparse_state_error)?;
                    entry.insert(BeaconAnchorReference {
                        anchor,
                        references: 1,
                    });
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let current = entry.get_mut();
                    if current.anchor != anchor {
                        return Err(UsdomStateError::EthereumAnchorConflict);
                    }
                    current.references = current
                        .references
                        .checked_add(1)
                        .ok_or(UsdomStateError::MonetaryOverflow)?;
                }
            }
        }
        self.sparse_note_set = notes;
        self.sparse_nullifier_set = nullifiers;
        self.sparse_deposit_set = deposits;
        self.sparse_burn_set = burns;
        self.sparse_burn_request_set = requests;
        self.sparse_execution_anchor_set = execution_anchors;
        self.sparse_beacon_anchor_set = beacon_anchors;
        self.execution_anchor_references = execution_anchor_references;
        self.beacon_anchor_references = beacon_anchor_references;
        Ok(())
    }

    fn compute_state_root(&self) -> Result<Hash256, UsdomStateError> {
        if self.sparse_note_set.leaf_count() != self.note_commitments.len() as u64
            || self.sparse_nullifier_set.leaf_count() != self.nullifiers.len() as u64
            || self.sparse_deposit_set.leaf_count() != self.consumed_deposits.len() as u64
            || self.sparse_burn_set.leaf_count() != self.burns.len() as u64
            || self.sparse_burn_request_set.leaf_count() != self.burn_request_ids.len() as u64
            || self.sparse_execution_anchor_set.leaf_count()
                != self.execution_anchor_references.len() as u64
            || self.sparse_beacon_anchor_set.leaf_count()
                != self.beacon_anchor_references.len() as u64
        {
            return Err(UsdomStateError::AuthenticatedSetCache(
                "sparse cache count mismatch".into(),
            ));
        }
        Ok(self.state_commitment()?.root())
    }
}

impl BatchUndo {
    /// State root restored by this batch rollback.
    pub fn before_root(&self) -> Hash256 {
        self.before_root
    }

    /// State root expected before this batch rollback.
    pub fn after_root(&self) -> Hash256 {
        self.after_root
    }

    /// Ordered transition root committed by the corresponding block envelope.
    pub fn transitions_root(&self) -> Hash256 {
        self.transitions_root
    }

    /// DOM block timestamp bound by the corresponding header commitment.
    pub fn block_timestamp(&self) -> u64 {
        self.block_timestamp
    }

    /// Number of transition inverses in this batch.
    pub fn transition_count(&self) -> usize {
        self.undos.len()
    }

    /// Ordered public preimages whose recomputed commitments form
    /// [`Self::transitions_root`]. These values grant no transition authority.
    pub fn transition_projections(&self) -> &[TransitionCommitmentProjection] {
        &self.projections
    }

    /// Recompute the batch header commitment described by this undo record.
    /// This value is not self-authorizing: rollback callers must bind it to the
    /// independently authenticated DOM block header before calling
    /// [`NativeUsdomState::revert_batch`].
    pub fn header_commitment(&self, domain: [u8; 32]) -> Result<Hash256, UsdomStateError> {
        validate_batch_undo_chain(self)?;
        validate_batch_projection_root(self, domain)?;
        let transition_count: u32 = self
            .undos
            .len()
            .try_into()
            .map_err(|_| UsdomStateError::MalformedUndo)?;
        Ok(batch_header_commitment(
            domain,
            transition_count,
            self.block_timestamp,
            self.transitions_root,
            self.before_root,
            self.after_root,
        ))
    }

    /// Canonical bounded encoding for atomic persistence beside one DOM block.
    pub fn to_bytes(&self) -> Result<Vec<u8>, UsdomStateError> {
        validate_batch_undo_chain(self)?;
        let count: u32 = self
            .undos
            .len()
            .try_into()
            .map_err(|_| UsdomStateError::MalformedUndo)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(BATCH_UNDO_MAGIC);
        bytes.extend_from_slice(self.before_root.as_bytes());
        bytes.extend_from_slice(self.after_root.as_bytes());
        bytes.extend_from_slice(self.transitions_root.as_bytes());
        bytes.extend_from_slice(&self.block_timestamp.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        for undo in &self.undos {
            let encoded = undo.to_bytes()?;
            let length: u32 = encoded
                .len()
                .try_into()
                .map_err(|_| UsdomStateError::MalformedUndo)?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(&encoded);
        }
        for projection in &self.projections {
            let encoded = projection.to_bytes()?;
            let length: u32 = encoded
                .len()
                .try_into()
                .map_err(|_| UsdomStateError::MalformedUndo)?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(&encoded);
        }
        if bytes.len() > MAX_BATCH_UNDO_BYTES {
            return Err(UsdomStateError::MalformedUndo);
        }
        Ok(bytes)
    }

    /// Decode a canonical batch undo and validate the complete root chain.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, UsdomStateError> {
        if bytes.len() < 116 || bytes.len() > MAX_BATCH_UNDO_BYTES {
            return Err(UsdomStateError::MalformedUndo);
        }
        let mut reader = UndoReader::new(bytes);
        if reader.take(8)? != BATCH_UNDO_MAGIC {
            return Err(UsdomStateError::MalformedUndo);
        }
        let before_root = Hash256::from_bytes(reader.array()?);
        let after_root = Hash256::from_bytes(reader.array()?);
        let transitions_root = Hash256::from_bytes(reader.array()?);
        let block_timestamp = u64::from_be_bytes(reader.array()?);
        let count = usize::try_from(u32::from_be_bytes(reader.array()?))
            .map_err(|_| UsdomStateError::MalformedUndo)?;
        if count > MAX_TRANSITIONS_PER_BATCH {
            return Err(UsdomStateError::MalformedUndo);
        }
        let mut undos = Vec::with_capacity(count);
        for _ in 0..count {
            let length = usize::try_from(u32::from_be_bytes(reader.array()?))
                .map_err(|_| UsdomStateError::MalformedUndo)?;
            if length == 0 || length > MAX_UNDO_BYTES {
                return Err(UsdomStateError::MalformedUndo);
            }
            undos.push(StateUndo::from_bytes(reader.take(length)?)?);
        }
        let mut projections = Vec::with_capacity(count);
        for _ in 0..count {
            let length = usize::try_from(u32::from_be_bytes(reader.array()?))
                .map_err(|_| UsdomStateError::MalformedUndo)?;
            if length == 0 || length > MAX_TRANSITION_PROJECTION_BYTES {
                return Err(UsdomStateError::MalformedUndo);
            }
            projections.push(TransitionCommitmentProjection::from_bytes(
                reader.take(length)?,
            )?);
        }
        if !reader.is_empty() {
            return Err(UsdomStateError::MalformedUndo);
        }
        let undo = Self {
            before_root,
            after_root,
            transitions_root,
            block_timestamp,
            undos,
            projections,
        };
        validate_batch_undo_chain(&undo)?;
        if undo.to_bytes()?.as_slice() != bytes {
            return Err(UsdomStateError::MalformedUndo);
        }
        Ok(undo)
    }
}

impl StateUndo {
    fn between(before: &NativeUsdomState, after: &NativeUsdomState) -> Self {
        Self {
            before_root: before.state_root,
            after_root: after.state_root,
            prior_note_count: before.notes.leaf_count(),
            inserted_notes: after
                .note_commitments
                .difference(&before.note_commitments)
                .copied()
                .collect(),
            inserted_nullifiers: after
                .nullifiers
                .difference(&before.nullifiers)
                .copied()
                .collect(),
            inserted_deposit: after
                .consumed_deposits
                .keys()
                .find(|key| !before.consumed_deposits.contains_key(*key))
                .copied(),
            inserted_burn: after
                .burns
                .keys()
                .find(|key| !before.burns.contains_key(*key))
                .copied(),
            prior_total_issued: before.total_issued,
            prior_total_burned: before.total_burned,
            prior_ethereum_anchor: before.ethereum_anchor,
            prior_note_anchors: before.note_anchors.clone(),
        }
    }

    /// State root this undo expects before rollback.
    pub fn after_root(&self) -> Hash256 {
        self.after_root
    }

    /// State root restored by a successful rollback.
    pub fn before_root(&self) -> Hash256 {
        self.before_root
    }

    /// Canonical bounded encoding suitable for atomic persistence beside the
    /// block that caused this transition.
    pub fn to_bytes(&self) -> Result<Vec<u8>, UsdomStateError> {
        if self.inserted_notes.len() > MAX_OUTPUT_NOTES
            || self.inserted_nullifiers.len() > MAX_INPUT_NULLIFIERS
            || self.prior_note_anchors.is_empty()
            || self.prior_note_anchors.len() > NOTE_ANCHOR_HISTORY
            || self.before_root == Hash256::ZERO
            || self.after_root == Hash256::ZERO
            || !strictly_sorted(&self.inserted_notes)
            || !strictly_sorted(&self.inserted_nullifiers)
        {
            return Err(UsdomStateError::MalformedUndo);
        }
        let mut bytes = Vec::with_capacity(256 + self.prior_note_anchors.len() * 40);
        bytes.extend_from_slice(b"UDOMUN01");
        bytes.extend_from_slice(self.before_root.as_bytes());
        bytes.extend_from_slice(self.after_root.as_bytes());
        bytes.extend_from_slice(&self.prior_note_count.to_be_bytes());
        bytes.push(self.inserted_notes.len() as u8);
        bytes.push(self.inserted_nullifiers.len() as u8);
        encode_optional_id(&mut bytes, self.inserted_deposit);
        encode_optional_id(&mut bytes, self.inserted_burn);
        bytes.extend_from_slice(&self.prior_total_issued.to_be_bytes());
        bytes.extend_from_slice(&self.prior_total_burned.to_be_bytes());
        match self.prior_ethereum_anchor {
            Some(anchor) => {
                bytes.push(1);
                encode_ethereum_anchor(&mut bytes, anchor);
            }
            None => bytes.push(0),
        }
        let anchor_count: u16 = self
            .prior_note_anchors
            .len()
            .try_into()
            .map_err(|_| UsdomStateError::MalformedUndo)?;
        bytes.extend_from_slice(&anchor_count.to_be_bytes());
        for anchor in &self.prior_note_anchors {
            bytes.extend_from_slice(anchor.root.as_bytes());
            bytes.extend_from_slice(&anchor.leaf_count.to_be_bytes());
        }
        for note in &self.inserted_notes {
            bytes.extend_from_slice(note);
        }
        for nullifier in &self.inserted_nullifiers {
            bytes.extend_from_slice(nullifier);
        }
        if bytes.len() > MAX_UNDO_BYTES {
            return Err(UsdomStateError::MalformedUndo);
        }
        Ok(bytes)
    }

    /// Decode canonical persisted undo bytes. Applying the result still requires
    /// an exact match to the current state root and recomputed prior root.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, UsdomStateError> {
        if bytes.len() > MAX_UNDO_BYTES || bytes.len() < 8 + 32 + 32 + 8 + 2 + 2 + 32 + 1 + 2 {
            return Err(UsdomStateError::MalformedUndo);
        }
        let mut reader = UndoReader::new(bytes);
        if reader.take(8)? != b"UDOMUN01" {
            return Err(UsdomStateError::MalformedUndo);
        }
        let before_root = Hash256::from_bytes(reader.array()?);
        let after_root = Hash256::from_bytes(reader.array()?);
        let prior_note_count = u64::from_be_bytes(reader.array()?);
        let note_count = usize::from(reader.byte()?);
        let nullifier_count = usize::from(reader.byte()?);
        if note_count > MAX_OUTPUT_NOTES || nullifier_count > MAX_INPUT_NULLIFIERS {
            return Err(UsdomStateError::MalformedUndo);
        }
        let inserted_deposit = decode_optional_id(&mut reader)?;
        let inserted_burn = decode_optional_id(&mut reader)?;
        let prior_total_issued = u128::from_be_bytes(reader.array()?);
        let prior_total_burned = u128::from_be_bytes(reader.array()?);
        if prior_total_burned > prior_total_issued {
            return Err(UsdomStateError::MalformedUndo);
        }
        let prior_ethereum_anchor = match reader.byte()? {
            0 => None,
            1 => {
                let anchor = decode_ethereum_anchor(&mut reader)?;
                anchor.validate()?;
                Some(anchor)
            }
            _ => return Err(UsdomStateError::MalformedUndo),
        };
        let anchor_count = usize::from(u16::from_be_bytes(reader.array()?));
        if anchor_count == 0 || anchor_count > NOTE_ANCHOR_HISTORY {
            return Err(UsdomStateError::MalformedUndo);
        }
        let mut prior_note_anchors = VecDeque::with_capacity(anchor_count);
        for _ in 0..anchor_count {
            let anchor = NoteAnchor {
                root: Hash256::from_bytes(reader.array()?),
                leaf_count: u64::from_be_bytes(reader.array()?),
            };
            if anchor.root == Hash256::ZERO
                || prior_note_anchors
                    .back()
                    .is_some_and(|previous: &NoteAnchor| anchor.leaf_count <= previous.leaf_count)
            {
                return Err(UsdomStateError::MalformedUndo);
            }
            prior_note_anchors.push_back(anchor);
        }
        let mut inserted_notes = Vec::with_capacity(note_count);
        for _ in 0..note_count {
            inserted_notes.push(reader.array()?);
        }
        let mut inserted_nullifiers = Vec::with_capacity(nullifier_count);
        for _ in 0..nullifier_count {
            inserted_nullifiers.push(reader.array()?);
        }
        if !reader.is_empty()
            || before_root == Hash256::ZERO
            || after_root == Hash256::ZERO
            || has_zero_or_duplicates(&inserted_notes)
            || has_zero_or_duplicates(&inserted_nullifiers)
            || !strictly_sorted(&inserted_notes)
            || !strictly_sorted(&inserted_nullifiers)
        {
            return Err(UsdomStateError::MalformedUndo);
        }
        let undo = Self {
            before_root,
            after_root,
            prior_note_count,
            inserted_notes,
            inserted_nullifiers,
            inserted_deposit,
            inserted_burn,
            prior_total_issued,
            prior_total_burned,
            prior_ethereum_anchor,
            prior_note_anchors,
        };
        if undo.to_bytes()?.as_slice() != bytes {
            return Err(UsdomStateError::MalformedUndo);
        }
        Ok(undo)
    }
}

fn state_key(suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(b"usdom/v3/".len() + suffix.len());
    key.extend_from_slice(b"usdom/v3/");
    key.extend_from_slice(suffix);
    key
}

fn exact_entry(
    entries: &BTreeMap<Vec<u8>, Vec<u8>>,
    suffix: &[u8],
) -> Result<[u8; 32], UsdomStateError> {
    entries
        .get(state_key(suffix).as_slice())
        .ok_or(UsdomStateError::MalformedPersistedState)?
        .as_slice()
        .try_into()
        .map_err(|_| UsdomStateError::MalformedPersistedState)
}

fn derive_ethereum_high_water(
    issuances: &BTreeMap<[u8; 32], IssuanceRecord>,
) -> Result<Option<EthereumAnchor>, UsdomStateError> {
    let mut execution_headers = BTreeMap::new();
    let mut beacon_anchors = BTreeMap::new();
    let mut genesis_validators_root = None;
    let mut high_water = None;
    for issuance in issuances.values() {
        let anchor = issuance.ethereum_anchor;
        anchor.validate()?;
        match genesis_validators_root {
            None => genesis_validators_root = Some(anchor.genesis_validators_root),
            Some(expected) if expected != anchor.genesis_validators_root => {
                return Err(UsdomStateError::EthereumAnchorConflict);
            }
            Some(_) => {}
        }
        match execution_headers.insert(
            anchor.execution_block_number,
            (
                anchor.execution_block_hash,
                anchor.execution_block_timestamp,
            ),
        ) {
            Some(existing)
                if existing
                    != (
                        anchor.execution_block_hash,
                        anchor.execution_block_timestamp,
                    ) =>
            {
                return Err(UsdomStateError::EthereumAnchorConflict);
            }
            _ => {}
        }
        match beacon_anchors.insert(anchor.beacon_slot, anchor) {
            Some(existing) if existing != anchor => {
                return Err(UsdomStateError::EthereumAnchorConflict);
            }
            _ => {}
        }
        high_water = merge_ethereum_anchor(high_water, Some(anchor))?;
    }
    Ok(high_water)
}

fn merge_ethereum_anchor(
    current: Option<EthereumAnchor>,
    candidate: Option<EthereumAnchor>,
) -> Result<Option<EthereumAnchor>, UsdomStateError> {
    let (Some(current), Some(candidate)) = (current, candidate) else {
        return Ok(current.or(candidate));
    };
    if current.genesis_validators_root != candidate.genesis_validators_root {
        return Err(UsdomStateError::EthereumAnchorConflict);
    }
    if current.beacon_slot == candidate.beacon_slot {
        if current != candidate {
            return Err(UsdomStateError::EthereumAnchorConflict);
        }
        return Ok(Some(current));
    }
    let (older, newer) = if current.beacon_slot < candidate.beacon_slot {
        (current, candidate)
    } else {
        (candidate, current)
    };
    if newer.execution_block_number < older.execution_block_number
        || newer.execution_block_timestamp < older.execution_block_timestamp
    {
        return Err(UsdomStateError::EthereumAnchorConflict);
    }
    Ok(Some(newer))
}

fn validate_v2_commitment(state: &StateCommitmentV2) -> Result<(), UsdomStateError> {
    BridgeIdentity {
        dom_domain: state.domain,
        ethereum_genesis_validators_root: state.ethereum_genesis_validators_root,
        ethereum_chain_id: state.ethereum_chain_id,
        ethereum_checkpoint_policy_hash: state.ethereum_checkpoint_policy_hash,
        ethereum_deposit_policy_hash: state.ethereum_deposit_policy_hash,
        privacy_policy_hash: state.privacy_policy_hash,
        privacy_verifier_config_hash: state.privacy_verifier_config_hash,
        reserve: state.reserve,
        burn_timing: state.burn_timing,
    }
    .validate()?;
    if state.note_count != state.note_set_count
        || state.burn_count != state.burn_request_count
        || state.total_burned > state.total_issued
        || state.anchor_count == 0
        || state.anchor_count > NOTE_ANCHOR_HISTORY as u64
        || state.execution_anchor_count > state.deposit_count
        || state.beacon_anchor_count > state.deposit_count
        || (state.deposit_count == 0
            && (state.execution_anchor_count != 0 || state.beacon_anchor_count != 0))
        || (state.deposit_count != 0
            && (state.execution_anchor_count == 0 || state.beacon_anchor_count == 0))
        || [
            state.notes_root,
            Hash256::from_bytes(state.privacy_notes_root),
            state.note_set_root,
            state.nullifier_root,
            state.deposit_root,
            state.burn_root,
            state.burn_request_root,
            state.execution_anchor_root,
            state.beacon_anchor_root,
            state.anchor_root,
        ]
        .contains(&Hash256::ZERO)
    {
        return Err(UsdomStateError::InvalidV2Commitment);
    }
    if let Some(anchor) = state.ethereum_anchor {
        anchor.validate()?;
        if anchor.genesis_validators_root != state.ethereum_genesis_validators_root {
            return Err(UsdomStateError::BridgeIdentityMismatch);
        }
    }
    Ok(())
}

fn validate_stateless_burn(
    context: BlockContext,
    state: &StateCommitmentV2,
    accumulators: &NativeAccumulatorWitness,
    value: &VerifiedBurn,
) -> Result<(), UsdomStateError> {
    if !accumulators.anchors.contains(&value.anchor) {
        return Err(UsdomStateError::UnknownNoteAnchor);
    }
    validate_shape(&value.nullifiers, &value.change_notes, true)?;
    if value.record.burn_id == [0; 32]
        || value.record.request_id == [0; 32]
        || value.record.amount == 0
        || value.record.recipient == [0; 20]
        || value.record.ethereum_chain_id == [0; 32]
        || value.record.reserve == [0; 20]
        || value.record.valid_until == 0
        || value.record.obligation_commitment == [0; 32]
    {
        return Err(UsdomStateError::ZeroIdentity);
    }
    if value.record.ethereum_chain_id != state.ethereum_chain_id
        || value.record.reserve != state.reserve
    {
        return Err(UsdomStateError::BridgeIdentityMismatch);
    }
    let bridge = BridgeIdentity {
        dom_domain: state.domain,
        ethereum_genesis_validators_root: state.ethereum_genesis_validators_root,
        ethereum_chain_id: state.ethereum_chain_id,
        ethereum_checkpoint_policy_hash: state.ethereum_checkpoint_policy_hash,
        ethereum_deposit_policy_hash: state.ethereum_deposit_policy_hash,
        privacy_policy_hash: state.privacy_policy_hash,
        privacy_verifier_config_hash: state.privacy_verifier_config_hash,
        reserve: state.reserve,
        burn_timing: state.burn_timing,
    };
    if derive_private_burn_id(
        bridge,
        &value.nullifiers,
        value.record.recipient,
        value.record.amount,
        value.record.valid_until,
    )? != value.record.burn_id
    {
        return Err(UsdomStateError::BurnIntentMismatch);
    }
    let ethereum_anchor = state
        .ethereum_anchor
        .ok_or(UsdomStateError::InvalidBurnWindow)?;
    let latest_fresh = ethereum_anchor
        .execution_block_timestamp
        .checked_add(state.burn_timing.max_ethereum_anchor_age_secs)
        .ok_or(UsdomStateError::InvalidBurnWindow)?;
    if context
        .timestamp
        .saturating_sub(state.burn_timing.max_dom_clock_lead_secs)
        > latest_fresh
    {
        return Err(UsdomStateError::InvalidBurnWindow);
    }
    let reference_timestamp = context
        .timestamp
        .max(ethereum_anchor.execution_block_timestamp);
    let earliest = reference_timestamp
        .checked_add(state.burn_timing.withdrawal_delay_secs)
        .and_then(|value| value.checked_add(state.burn_timing.min_execution_window_secs))
        .and_then(|value| value.checked_add(state.burn_timing.relay_safety_margin_secs))
        .ok_or(UsdomStateError::InvalidBurnWindow)?;
    let latest = ethereum_anchor
        .execution_block_timestamp
        .checked_add(state.burn_timing.max_certificate_lifetime_secs)
        .ok_or(UsdomStateError::InvalidBurnWindow)?;
    if value.record.valid_until < earliest || value.record.valid_until > latest {
        return Err(UsdomStateError::InvalidBurnWindow);
    }
    if value.record.expected_obligation_commitment(state.domain)
        != value.record.obligation_commitment
    {
        return Err(UsdomStateError::BurnIntentMismatch);
    }
    Ok(())
}

struct UndoReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> UndoReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], UsdomStateError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(UsdomStateError::MalformedUndo)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(UsdomStateError::MalformedUndo)?;
        self.cursor = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], UsdomStateError> {
        self.take(N)?
            .try_into()
            .map_err(|_| UsdomStateError::MalformedUndo)
    }

    fn byte(&mut self) -> Result<u8, UsdomStateError> {
        Ok(self.array::<1>()?[0])
    }

    fn is_empty(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

struct WitnessReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> WitnessReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], UsdomStateError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(UsdomStateError::MalformedBurnWitness)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(UsdomStateError::MalformedBurnWitness)?;
        self.cursor = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], UsdomStateError> {
        self.take(N)?
            .try_into()
            .map_err(|_| UsdomStateError::MalformedBurnWitness)
    }

    fn byte(&mut self) -> Result<u8, UsdomStateError> {
        Ok(self.array::<1>()?[0])
    }

    fn is_empty(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

fn encode_optional_id(bytes: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        Some(id) => {
            bytes.push(1);
            bytes.extend_from_slice(&id);
        }
        None => bytes.push(0),
    }
}

fn encode_projection_hashes(
    bytes: &mut Vec<u8>,
    values: &[[u8; 32]],
) -> Result<(), UsdomStateError> {
    let count: u8 = values
        .len()
        .try_into()
        .map_err(|_| UsdomStateError::MalformedUndo)?;
    bytes.push(count);
    for value in values {
        bytes.extend_from_slice(value);
    }
    Ok(())
}

fn decode_projection_hashes(reader: &mut UndoReader<'_>) -> Result<Vec<[u8; 32]>, UsdomStateError> {
    let count = usize::from(reader.byte()?);
    if count > MAX_INPUT_NULLIFIERS.max(MAX_OUTPUT_NOTES) {
        return Err(UsdomStateError::MalformedUndo);
    }
    (0..count).map(|_| reader.array()).collect()
}

fn decode_projection_note_anchor(
    reader: &mut UndoReader<'_>,
) -> Result<NoteAnchor, UsdomStateError> {
    Ok(NoteAnchor {
        root: Hash256::from_bytes(reader.array()?),
        leaf_count: u64::from_be_bytes(reader.array()?),
    })
}

fn decode_projection_burn_record(
    reader: &mut UndoReader<'_>,
) -> Result<BurnRecord, UsdomStateError> {
    Ok(BurnRecord {
        burn_id: reader.array()?,
        request_id: reader.array()?,
        amount: u64::from_be_bytes(reader.array()?),
        recipient: reader.array()?,
        ethereum_chain_id: reader.array()?,
        reserve: reader.array()?,
        valid_until: u64::from_be_bytes(reader.array()?),
        obligation_commitment: reader.array()?,
    })
}

fn decode_optional_id(reader: &mut UndoReader<'_>) -> Result<Option<[u8; 32]>, UsdomStateError> {
    match reader.byte()? {
        0 => Ok(None),
        1 => {
            let id = reader.array()?;
            if id == [0; 32] {
                return Err(UsdomStateError::MalformedUndo);
            }
            Ok(Some(id))
        }
        _ => Err(UsdomStateError::MalformedUndo),
    }
}

fn decode_ethereum_anchor(reader: &mut UndoReader<'_>) -> Result<EthereumAnchor, UsdomStateError> {
    Ok(EthereumAnchor {
        genesis_validators_root: reader.array()?,
        execution_block_number: u64::from_be_bytes(reader.array()?),
        execution_block_hash: reader.array()?,
        execution_block_timestamp: u64::from_be_bytes(reader.array()?),
        beacon_slot: u64::from_be_bytes(reader.array()?),
        beacon_root: reader.array()?,
    })
}

fn has_zero_or_duplicates(values: &[[u8; 32]]) -> bool {
    values.contains(&[0; 32])
        || values.iter().copied().collect::<BTreeSet<_>>().len() != values.len()
}

fn strictly_sorted(values: &[[u8; 32]]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn require_projection_domain(domain: [u8; 32]) -> Result<(), UsdomStateError> {
    if domain == [0; 32] {
        return Err(UsdomStateError::ZeroIdentity);
    }
    Ok(())
}

fn validate_projection_anchor(anchor: NoteAnchor) -> Result<(), UsdomStateError> {
    let root = PrivacyScalar::from_bytes(*anchor.root.as_bytes())
        .map_err(|_| UsdomStateError::InvalidPrivacyProof)?;
    if root.is_zero() || anchor.leaf_count == 0 {
        return Err(UsdomStateError::InvalidPrivacyProof);
    }
    Ok(())
}

fn validate_projection_scalars(
    nullifiers: &[[u8; 32]],
    outputs: &[[u8; 32]],
) -> Result<(), UsdomStateError> {
    if outputs.iter().copied().collect::<BTreeSet<_>>().len() != outputs.len() {
        return Err(UsdomStateError::DuplicateNote);
    }
    for value in nullifiers {
        let scalar = PrivacyScalar::from_bytes(*value)
            .map_err(|_| UsdomStateError::InvalidPrivacyNullifier)?;
        if scalar.is_zero() {
            return Err(UsdomStateError::InvalidPrivacyNullifier);
        }
    }
    for value in outputs {
        let scalar = PrivacyScalar::from_bytes(*value)
            .map_err(|_| UsdomStateError::InvalidPrivacyCommitment)?;
        if scalar.is_zero() {
            return Err(UsdomStateError::InvalidPrivacyCommitment);
        }
    }
    Ok(())
}

fn validate_projection_memo(
    outputs: &[[u8; 32]],
    memo_commitment: [u8; 32],
) -> Result<(), UsdomStateError> {
    let memo = PrivacyScalar::from_bytes(memo_commitment)
        .map_err(|_| UsdomStateError::InvalidPrivacyProof)?;
    if outputs.is_empty() != memo.is_zero() {
        return Err(UsdomStateError::InvalidPrivacyProof);
    }
    Ok(())
}

fn validate_shape(
    nullifiers: &[[u8; 32]],
    outputs: &[[u8; 32]],
    burn: bool,
) -> Result<(), UsdomStateError> {
    if nullifiers.is_empty()
        || nullifiers.len() > MAX_INPUT_NULLIFIERS
        || outputs.len() > MAX_OUTPUT_NOTES
        || (!burn && outputs.is_empty())
    {
        return Err(UsdomStateError::InvalidShape);
    }
    // Nullifiers form a set in consensus state. Requiring their bytewise order
    // removes an otherwise free transaction malleability vector where two
    // encodings produce the same state transition and state root.
    if !strictly_sorted(nullifiers) {
        return Err(UsdomStateError::NonCanonicalOrder);
    }
    Ok(())
}

fn private_spend_statement(
    bridge: BridgeIdentity,
    anchor: NoteAnchor,
    nullifiers: &[[u8; 32]],
    outputs: &[[u8; 32]],
    burn_amount: u64,
    effect: PrivacyScalar,
    encrypted_memo: &[u8],
) -> Result<SpendStatement, UsdomStateError> {
    if bridge.privacy_policy_hash != *dom_usdom_privacy::privacy_policy_hash().as_bytes()
        || anchor.leaf_count == 0
    {
        return Err(UsdomStateError::BridgeIdentityMismatch);
    }
    let anchor_scalar = PrivacyScalar::from_bytes(*anchor.root.as_bytes())
        .map_err(|_| UsdomStateError::InvalidPrivacyProof)?;
    if anchor_scalar.is_zero() {
        return Err(UsdomStateError::InvalidPrivacyProof);
    }
    let mut statement_nullifiers = [PrivacyScalar::ZERO; MAX_INPUT_NULLIFIERS];
    for (slot, value) in nullifiers.iter().enumerate() {
        let scalar = PrivacyScalar::from_bytes(*value)
            .map_err(|_| UsdomStateError::InvalidPrivacyNullifier)?;
        if scalar.is_zero() {
            return Err(UsdomStateError::InvalidPrivacyNullifier);
        }
        statement_nullifiers[slot] = scalar;
    }
    let mut statement_outputs = [PrivacyScalar::ZERO; MAX_OUTPUT_NOTES];
    for (slot, value) in outputs.iter().enumerate() {
        let scalar = PrivacyScalar::from_bytes(*value)
            .map_err(|_| UsdomStateError::InvalidPrivacyCommitment)?;
        if scalar.is_zero() {
            return Err(UsdomStateError::InvalidPrivacyCommitment);
        }
        statement_outputs[slot] = scalar;
    }
    let memo = if outputs.is_empty() {
        if !encrypted_memo.is_empty() {
            return Err(UsdomStateError::InvalidPrivacyProof);
        }
        PrivacyScalar::ZERO
    } else {
        memo_scalar(encrypted_memo).map_err(|_| UsdomStateError::InvalidPrivacyProof)?
    };
    if (burn_amount == 0) != effect.is_zero() {
        return Err(UsdomStateError::InvalidPrivacyProof);
    }
    Ok(SpendStatement {
        chain: privacy_chain_scalar(bridge.dom_domain, bridge.privacy_policy_hash),
        anchor: anchor_scalar,
        nullifiers: statement_nullifiers,
        output_notes: statement_outputs,
        burn_amount,
        effect,
        memo,
    })
}

fn fixed_set_root(kind: u8, values: impl Iterator<Item = [u8; 32]>) -> Hash256 {
    merkle_root(
        values
            .map(|value| {
                let mut bytes = Vec::with_capacity(33);
                bytes.push(kind);
                bytes.extend_from_slice(&value);
                blake2b_256_tagged(TAG_SET_LEAF, &bytes)
            })
            .collect(),
    )
}

fn sparse_fixed_leaf(kind: u8, value: [u8; 32]) -> Hash256 {
    let mut bytes = Vec::with_capacity(33);
    bytes.push(kind);
    bytes.extend_from_slice(&value);
    blake2b_256_tagged(TAG_SET_LEAF, &bytes)
}

fn sparse_issuance_leaf(issuance: IssuanceRecord) -> Hash256 {
    let mut bytes = Vec::with_capacity(185);
    bytes.push(SPARSE_DEPOSIT_SET);
    bytes.extend_from_slice(&issuance.deposit_id);
    bytes.extend_from_slice(&issuance.note_commitment);
    bytes.extend_from_slice(&issuance.amount.to_be_bytes());
    encode_ethereum_anchor(&mut bytes, issuance.ethereum_anchor);
    blake2b_256_tagged(TAG_SET_LEAF, &bytes)
}

fn sparse_u64_key(value: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[24..].copy_from_slice(&value.to_be_bytes());
    key
}

fn sparse_execution_anchor_leaf(anchor: EthereumAnchor) -> Hash256 {
    let mut bytes = Vec::with_capacity(1 + 8 + 32 + 8);
    bytes.push(SPARSE_EXECUTION_ANCHOR_SET);
    bytes.extend_from_slice(&anchor.execution_block_number.to_be_bytes());
    bytes.extend_from_slice(&anchor.execution_block_hash);
    bytes.extend_from_slice(&anchor.execution_block_timestamp.to_be_bytes());
    blake2b_256_tagged(TAG_SET_LEAF, &bytes)
}

fn sparse_beacon_anchor_leaf(anchor: EthereumAnchor) -> Hash256 {
    let mut bytes = Vec::with_capacity(1 + 120);
    bytes.push(SPARSE_BEACON_ANCHOR_SET);
    encode_ethereum_anchor(&mut bytes, anchor);
    blake2b_256_tagged(TAG_SET_LEAF, &bytes)
}

fn map_sparse_state_error(error: SparseProofError) -> UsdomStateError {
    UsdomStateError::AuthenticatedSetCache(error.to_string())
}

fn transition_domain(transition: &VerifiedTransition) -> [u8; 32] {
    match transition {
        VerifiedTransition::Issue(value) => value.domain,
        VerifiedTransition::Transfer(value) => value.domain,
        VerifiedTransition::Burn(value) => value.domain,
        VerifiedTransition::EthereumCheckpoint(value) => value.domain,
    }
}

fn native_set_effects(transition: &VerifiedTransition) -> Vec<NativeSetEffect> {
    let mut effects = Vec::with_capacity(MAX_SET_EFFECTS_PER_TRANSITION);
    match transition {
        VerifiedTransition::Issue(value) => {
            effects.push(NativeSetEffect {
                kind: SPARSE_NOTE_SET,
                key: value.note_commitment,
                leaf: sparse_fixed_leaf(SPARSE_NOTE_SET, value.note_commitment),
                allow_existing: false,
            });
            let issuance = IssuanceRecord {
                deposit_id: value.deposit_id,
                note_commitment: value.note_commitment,
                amount: value.amount,
                ethereum_anchor: value.ethereum_anchor,
            };
            effects.push(NativeSetEffect {
                kind: SPARSE_DEPOSIT_SET,
                key: value.deposit_id,
                leaf: sparse_issuance_leaf(issuance),
                allow_existing: false,
            });
            effects.push(NativeSetEffect {
                kind: SPARSE_EXECUTION_ANCHOR_SET,
                key: sparse_u64_key(value.ethereum_anchor.execution_block_number),
                leaf: sparse_execution_anchor_leaf(value.ethereum_anchor),
                allow_existing: true,
            });
            effects.push(NativeSetEffect {
                kind: SPARSE_BEACON_ANCHOR_SET,
                key: sparse_u64_key(value.ethereum_anchor.beacon_slot),
                leaf: sparse_beacon_anchor_leaf(value.ethereum_anchor),
                allow_existing: true,
            });
        }
        VerifiedTransition::Transfer(value) => {
            for nullifier in &value.nullifiers {
                effects.push(NativeSetEffect {
                    kind: SPARSE_NULLIFIER_SET,
                    key: *nullifier,
                    leaf: sparse_fixed_leaf(SPARSE_NULLIFIER_SET, *nullifier),
                    allow_existing: false,
                });
            }
            for note in &value.output_notes {
                effects.push(NativeSetEffect {
                    kind: SPARSE_NOTE_SET,
                    key: *note,
                    leaf: sparse_fixed_leaf(SPARSE_NOTE_SET, *note),
                    allow_existing: false,
                });
            }
        }
        VerifiedTransition::Burn(value) => {
            for nullifier in &value.nullifiers {
                effects.push(NativeSetEffect {
                    kind: SPARSE_NULLIFIER_SET,
                    key: *nullifier,
                    leaf: sparse_fixed_leaf(SPARSE_NULLIFIER_SET, *nullifier),
                    allow_existing: false,
                });
            }
            for note in &value.change_notes {
                effects.push(NativeSetEffect {
                    kind: SPARSE_NOTE_SET,
                    key: *note,
                    leaf: sparse_fixed_leaf(SPARSE_NOTE_SET, *note),
                    allow_existing: false,
                });
            }
            effects.push(NativeSetEffect {
                kind: SPARSE_BURN_SET,
                key: value.record.burn_id,
                leaf: burn_leaf_hash(value.record),
                allow_existing: false,
            });
            effects.push(NativeSetEffect {
                kind: SPARSE_BURN_REQUEST_SET,
                key: value.record.request_id,
                leaf: sparse_fixed_leaf(SPARSE_BURN_REQUEST_SET, value.record.request_id),
                allow_existing: false,
            });
        }
        VerifiedTransition::EthereumCheckpoint(_) => {}
    }
    effects
}

fn v2_sparse_component_mut(
    state: &mut StateCommitmentV2,
    kind: u8,
) -> Result<(&mut Hash256, &mut u64), UsdomStateError> {
    match kind {
        SPARSE_NOTE_SET => Ok((&mut state.note_set_root, &mut state.note_set_count)),
        SPARSE_NULLIFIER_SET => Ok((&mut state.nullifier_root, &mut state.nullifier_count)),
        SPARSE_DEPOSIT_SET => Ok((&mut state.deposit_root, &mut state.deposit_count)),
        SPARSE_BURN_SET => Ok((&mut state.burn_root, &mut state.burn_count)),
        SPARSE_BURN_REQUEST_SET => {
            Ok((&mut state.burn_request_root, &mut state.burn_request_count))
        }
        SPARSE_EXECUTION_ANCHOR_SET => Ok((
            &mut state.execution_anchor_root,
            &mut state.execution_anchor_count,
        )),
        SPARSE_BEACON_ANCHOR_SET => Ok((
            &mut state.beacon_anchor_root,
            &mut state.beacon_anchor_count,
        )),
        _ => Err(UsdomStateError::MalformedSetWitness),
    }
}

#[allow(clippy::too_many_arguments)]
fn sparse_tree_for_kind_mut<'a>(
    kind: u8,
    notes: &'a mut SparseMerkleTree,
    nullifiers: &'a mut SparseMerkleTree,
    deposits: &'a mut SparseMerkleTree,
    burns: &'a mut SparseMerkleTree,
    requests: &'a mut SparseMerkleTree,
    execution_anchors: &'a mut SparseMerkleTree,
    beacon_anchors: &'a mut SparseMerkleTree,
) -> Result<&'a mut SparseMerkleTree, UsdomStateError> {
    match kind {
        SPARSE_NOTE_SET => Ok(notes),
        SPARSE_NULLIFIER_SET => Ok(nullifiers),
        SPARSE_DEPOSIT_SET => Ok(deposits),
        SPARSE_BURN_SET => Ok(burns),
        SPARSE_BURN_REQUEST_SET => Ok(requests),
        SPARSE_EXECUTION_ANCHOR_SET => Ok(execution_anchors),
        SPARSE_BEACON_ANCHOR_SET => Ok(beacon_anchors),
        _ => Err(UsdomStateError::MalformedSetWitness),
    }
}

fn issuance_set_root(issuances: &BTreeMap<[u8; 32], IssuanceRecord>) -> Hash256 {
    merkle_root(
        issuances
            .values()
            .map(|issuance| {
                let mut bytes = Vec::with_capacity(185);
                bytes.push(3);
                bytes.extend_from_slice(&issuance.deposit_id);
                bytes.extend_from_slice(&issuance.note_commitment);
                bytes.extend_from_slice(&issuance.amount.to_be_bytes());
                encode_ethereum_anchor(&mut bytes, issuance.ethereum_anchor);
                blake2b_256_tagged(TAG_SET_LEAF, &bytes)
            })
            .collect(),
    )
}

fn burn_set_root(burns: &BTreeMap<[u8; 32], BurnRecord>) -> Hash256 {
    merkle_root(burns.values().copied().map(burn_leaf_hash).collect())
}

fn burn_leaf_hash(burn: BurnRecord) -> Hash256 {
    let mut bytes = Vec::with_capacity(185);
    bytes.push(4);
    bytes.extend_from_slice(&burn.burn_id);
    bytes.extend_from_slice(&burn.request_id);
    bytes.extend_from_slice(&burn.amount.to_be_bytes());
    bytes.extend_from_slice(&burn.recipient);
    bytes.extend_from_slice(&burn.ethereum_chain_id);
    bytes.extend_from_slice(&burn.reserve);
    bytes.extend_from_slice(&burn.valid_until.to_be_bytes());
    bytes.extend_from_slice(&burn.obligation_commitment);
    blake2b_256_tagged(TAG_SET_LEAF, &bytes)
}

fn set_node_hash(depth: u32, left: Hash256, right: Hash256) -> Hash256 {
    let mut bytes = Vec::with_capacity(68);
    bytes.extend_from_slice(&depth.to_be_bytes());
    bytes.extend_from_slice(left.as_bytes());
    bytes.extend_from_slice(right.as_bytes());
    blake2b_256_tagged(TAG_SET_NODE, &bytes)
}

fn verify_burn_inclusion(proof: &BurnSetInclusionProof, expected_root: Hash256) -> bool {
    if proof.leaf_count == 0
        || proof.leaf_index >= proof.leaf_count
        || proof.siblings.len() > MAX_BURN_INCLUSION_SIBLINGS
    {
        return false;
    }
    let mut current = burn_leaf_hash(proof.record);
    let mut index = proof.leaf_index;
    let mut width = proof.leaf_count;
    let mut siblings = proof.siblings.iter();
    let mut depth = 0u32;
    while width > 1 {
        if index % 2 == 1 {
            let Some(sibling) = siblings.next() else {
                return false;
            };
            current = set_node_hash(depth, *sibling, current);
        } else if index + 1 < width {
            let Some(sibling) = siblings.next() else {
                return false;
            };
            current = set_node_hash(depth, current, *sibling);
        }
        index /= 2;
        width = width.div_ceil(2);
        depth += 1;
    }
    siblings.next().is_none() && current == expected_root
}

fn valid_burn_record(record: &BurnRecord) -> bool {
    record.burn_id != [0; 32]
        && record.request_id != [0; 32]
        && record.amount != 0
        && record.recipient != [0; 20]
        && record.ethereum_chain_id != [0; 32]
        && record.reserve != [0; 20]
        && record.valid_until != 0
        && record.obligation_commitment != [0; 32]
}

fn valid_state_commitment(value: &StateCommitment) -> bool {
    let bridge = BridgeIdentity {
        dom_domain: value.domain,
        ethereum_genesis_validators_root: value.ethereum_genesis_validators_root,
        ethereum_chain_id: value.ethereum_chain_id,
        ethereum_checkpoint_policy_hash: value.ethereum_checkpoint_policy_hash,
        ethereum_deposit_policy_hash: value.ethereum_deposit_policy_hash,
        privacy_policy_hash: value.privacy_policy_hash,
        privacy_verifier_config_hash: value.privacy_verifier_config_hash,
        reserve: value.reserve,
        burn_timing: value.burn_timing,
    };
    bridge.validate().is_ok()
        && value.note_count == value.note_set_count
        && value.anchor_count > 0
        && value.anchor_count <= NOTE_ANCHOR_HISTORY as u64
        && value.total_burned <= value.total_issued
        && value.notes_root != Hash256::ZERO
        && PrivacyScalar::from_bytes(value.privacy_notes_root).is_ok()
        && value.privacy_notes_root != [0; 32]
        && value.note_set_root != Hash256::ZERO
        && value.nullifier_root != Hash256::ZERO
        && value.deposit_root != Hash256::ZERO
        && value.burn_root != Hash256::ZERO
        && value.anchor_root != Hash256::ZERO
        && value.ethereum_anchor.is_some_and(|anchor| {
            anchor.validate().is_ok()
                && anchor.genesis_validators_root == value.ethereum_genesis_validators_root
        })
}

fn state_commitment_root(value: &StateCommitment) -> Hash256 {
    let mut bytes = Vec::with_capacity(32 * 14 + 156);
    bytes.extend_from_slice(&value.domain);
    bytes.extend_from_slice(&value.ethereum_genesis_validators_root);
    bytes.extend_from_slice(&value.ethereum_chain_id);
    bytes.extend_from_slice(&value.reserve);
    bytes.extend_from_slice(&value.ethereum_checkpoint_policy_hash);
    bytes.extend_from_slice(&value.ethereum_deposit_policy_hash);
    bytes.extend_from_slice(&value.privacy_policy_hash);
    bytes.extend_from_slice(&value.privacy_verifier_config_hash);
    encode_burn_timing_policy(&mut bytes, value.burn_timing);
    bytes.extend_from_slice(value.notes_root.as_bytes());
    bytes.extend_from_slice(&value.privacy_notes_root);
    bytes.extend_from_slice(&value.note_count.to_be_bytes());
    bytes.extend_from_slice(value.note_set_root.as_bytes());
    bytes.extend_from_slice(&value.note_set_count.to_be_bytes());
    bytes.extend_from_slice(value.nullifier_root.as_bytes());
    bytes.extend_from_slice(&value.nullifier_count.to_be_bytes());
    bytes.extend_from_slice(value.deposit_root.as_bytes());
    bytes.extend_from_slice(&value.deposit_count.to_be_bytes());
    bytes.extend_from_slice(value.burn_root.as_bytes());
    bytes.extend_from_slice(&value.burn_count.to_be_bytes());
    bytes.extend_from_slice(value.anchor_root.as_bytes());
    bytes.extend_from_slice(&value.anchor_count.to_be_bytes());
    bytes.extend_from_slice(&value.total_issued.to_be_bytes());
    bytes.extend_from_slice(&value.total_burned.to_be_bytes());
    match value.ethereum_anchor {
        Some(anchor) => {
            bytes.push(1);
            encode_ethereum_anchor(&mut bytes, anchor);
        }
        None => bytes.push(0),
    }
    blake2b_256_tagged(TAG_STATE, &bytes)
}

fn state_commitment_v2_root(value: &StateCommitmentV2) -> Hash256 {
    let mut bytes = Vec::with_capacity(MAX_STATE_COMMITMENT_V2_BYTES - 8);
    encode_state_commitment_v2_body(&mut bytes, value);
    blake2b_256_tagged(TAG_STATE_V2, &bytes)
}

fn encode_state_commitment_v2_body(bytes: &mut Vec<u8>, value: &StateCommitmentV2) {
    bytes.extend_from_slice(&STATE_COMMITMENT_V2_VERSION.to_be_bytes());
    bytes.extend_from_slice(&value.domain);
    bytes.extend_from_slice(&value.ethereum_genesis_validators_root);
    bytes.extend_from_slice(&value.ethereum_chain_id);
    bytes.extend_from_slice(&value.reserve);
    bytes.extend_from_slice(&value.ethereum_checkpoint_policy_hash);
    bytes.extend_from_slice(&value.ethereum_deposit_policy_hash);
    bytes.extend_from_slice(&value.privacy_policy_hash);
    bytes.extend_from_slice(&value.privacy_verifier_config_hash);
    encode_burn_timing_policy(bytes, value.burn_timing);
    bytes.extend_from_slice(value.notes_root.as_bytes());
    bytes.extend_from_slice(&value.privacy_notes_root);
    bytes.extend_from_slice(&value.note_count.to_be_bytes());
    for (root, count) in [
        (value.note_set_root, value.note_set_count),
        (value.nullifier_root, value.nullifier_count),
        (value.deposit_root, value.deposit_count),
        (value.burn_root, value.burn_count),
        (value.burn_request_root, value.burn_request_count),
        (value.execution_anchor_root, value.execution_anchor_count),
        (value.beacon_anchor_root, value.beacon_anchor_count),
        (value.anchor_root, value.anchor_count),
    ] {
        bytes.extend_from_slice(root.as_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
    }
    bytes.extend_from_slice(&value.total_issued.to_be_bytes());
    bytes.extend_from_slice(&value.total_burned.to_be_bytes());
    match value.ethereum_anchor {
        Some(anchor) => {
            bytes.push(1);
            encode_ethereum_anchor(bytes, anchor);
        }
        None => bytes.push(0),
    }
}

fn anchor_history_root(anchors: &VecDeque<NoteAnchor>) -> Hash256 {
    merkle_root(
        anchors
            .iter()
            .enumerate()
            .map(|(index, anchor)| {
                let mut bytes = Vec::with_capacity(48);
                bytes.extend_from_slice(&(index as u64).to_be_bytes());
                bytes.extend_from_slice(anchor.root.as_bytes());
                bytes.extend_from_slice(&anchor.leaf_count.to_be_bytes());
                blake2b_256_tagged(TAG_ANCHOR_LEAF, &bytes)
            })
            .collect(),
    )
}

fn encode_ethereum_anchor(bytes: &mut Vec<u8>, anchor: EthereumAnchor) {
    bytes.extend_from_slice(&anchor.genesis_validators_root);
    bytes.extend_from_slice(&anchor.execution_block_number.to_be_bytes());
    bytes.extend_from_slice(&anchor.execution_block_hash);
    bytes.extend_from_slice(&anchor.execution_block_timestamp.to_be_bytes());
    bytes.extend_from_slice(&anchor.beacon_slot.to_be_bytes());
    bytes.extend_from_slice(&anchor.beacon_root);
}

fn encode_note_anchor(bytes: &mut Vec<u8>, anchor: NoteAnchor) {
    bytes.extend_from_slice(anchor.root.as_bytes());
    bytes.extend_from_slice(&anchor.leaf_count.to_be_bytes());
}

fn encode_hash_list(bytes: &mut Vec<u8>, values: &[[u8; 32]]) -> Result<(), UsdomStateError> {
    let count: u64 = values
        .len()
        .try_into()
        .map_err(|_| UsdomStateError::MalformedUndo)?;
    bytes.extend_from_slice(&count.to_be_bytes());
    for value in values {
        bytes.extend_from_slice(value);
    }
    Ok(())
}

fn encode_burn_record(bytes: &mut Vec<u8>, record: BurnRecord) {
    bytes.extend_from_slice(&record.burn_id);
    bytes.extend_from_slice(&record.request_id);
    bytes.extend_from_slice(&record.amount.to_be_bytes());
    bytes.extend_from_slice(&record.recipient);
    bytes.extend_from_slice(&record.ethereum_chain_id);
    bytes.extend_from_slice(&record.reserve);
    bytes.extend_from_slice(&record.valid_until.to_be_bytes());
    bytes.extend_from_slice(&record.obligation_commitment);
}

fn decode_burn_record(reader: &mut WitnessReader<'_>) -> Result<BurnRecord, UsdomStateError> {
    Ok(BurnRecord {
        burn_id: reader.array()?,
        request_id: reader.array()?,
        amount: u64::from_be_bytes(reader.array()?),
        recipient: reader.array()?,
        ethereum_chain_id: reader.array()?,
        reserve: reader.array()?,
        valid_until: u64::from_be_bytes(reader.array()?),
        obligation_commitment: reader.array()?,
    })
}

fn encode_state_commitment(bytes: &mut Vec<u8>, value: &StateCommitment) {
    bytes.extend_from_slice(&value.domain);
    bytes.extend_from_slice(&value.ethereum_genesis_validators_root);
    bytes.extend_from_slice(&value.ethereum_chain_id);
    bytes.extend_from_slice(&value.reserve);
    bytes.extend_from_slice(&value.ethereum_checkpoint_policy_hash);
    bytes.extend_from_slice(&value.ethereum_deposit_policy_hash);
    bytes.extend_from_slice(&value.privacy_policy_hash);
    bytes.extend_from_slice(&value.privacy_verifier_config_hash);
    encode_burn_timing_policy(bytes, value.burn_timing);
    bytes.extend_from_slice(&value.privacy_notes_root);
    for (root, count) in [
        (value.notes_root, value.note_count),
        (value.note_set_root, value.note_set_count),
        (value.nullifier_root, value.nullifier_count),
        (value.deposit_root, value.deposit_count),
        (value.burn_root, value.burn_count),
        (value.anchor_root, value.anchor_count),
    ] {
        bytes.extend_from_slice(root.as_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
    }
    bytes.extend_from_slice(&value.total_issued.to_be_bytes());
    bytes.extend_from_slice(&value.total_burned.to_be_bytes());
    match value.ethereum_anchor {
        Some(anchor) => {
            bytes.push(1);
            encode_ethereum_anchor(bytes, anchor);
        }
        None => bytes.push(0),
    }
}

fn decode_state_commitment(
    reader: &mut WitnessReader<'_>,
) -> Result<StateCommitment, UsdomStateError> {
    let domain = reader.array()?;
    let ethereum_genesis_validators_root = reader.array()?;
    let ethereum_chain_id = reader.array()?;
    let reserve = reader.array()?;
    let ethereum_checkpoint_policy_hash = reader.array()?;
    let ethereum_deposit_policy_hash = reader.array()?;
    let privacy_policy_hash = reader.array()?;
    let privacy_verifier_config_hash = reader.array()?;
    let burn_timing = BurnTimingPolicy {
        withdrawal_delay_secs: u64::from_be_bytes(reader.array()?),
        min_execution_window_secs: u64::from_be_bytes(reader.array()?),
        max_certificate_lifetime_secs: u64::from_be_bytes(reader.array()?),
        relay_safety_margin_secs: u64::from_be_bytes(reader.array()?),
        max_ethereum_anchor_age_secs: u64::from_be_bytes(reader.array()?),
        max_dom_clock_lead_secs: u64::from_be_bytes(reader.array()?),
    };
    let privacy_notes_root = reader.array()?;
    let mut root_and_count = || -> Result<(Hash256, u64), UsdomStateError> {
        Ok((
            Hash256::from_bytes(reader.array()?),
            u64::from_be_bytes(reader.array()?),
        ))
    };
    let (notes_root, note_count) = root_and_count()?;
    let (note_set_root, note_set_count) = root_and_count()?;
    let (nullifier_root, nullifier_count) = root_and_count()?;
    let (deposit_root, deposit_count) = root_and_count()?;
    let (burn_root, burn_count) = root_and_count()?;
    let (anchor_root, anchor_count) = root_and_count()?;
    let total_issued = u128::from_be_bytes(reader.array()?);
    let total_burned = u128::from_be_bytes(reader.array()?);
    let ethereum_anchor = match reader.byte()? {
        0 => None,
        1 => Some(EthereumAnchor {
            genesis_validators_root: reader.array()?,
            execution_block_number: u64::from_be_bytes(reader.array()?),
            execution_block_hash: reader.array()?,
            execution_block_timestamp: u64::from_be_bytes(reader.array()?),
            beacon_slot: u64::from_be_bytes(reader.array()?),
            beacon_root: reader.array()?,
        }),
        _ => return Err(UsdomStateError::MalformedBurnWitness),
    };
    Ok(StateCommitment {
        domain,
        ethereum_genesis_validators_root,
        ethereum_chain_id,
        reserve,
        ethereum_checkpoint_policy_hash,
        ethereum_deposit_policy_hash,
        privacy_policy_hash,
        privacy_verifier_config_hash,
        burn_timing,
        notes_root,
        privacy_notes_root,
        note_count,
        note_set_root,
        note_set_count,
        nullifier_root,
        nullifier_count,
        deposit_root,
        deposit_count,
        burn_root,
        burn_count,
        anchor_root,
        anchor_count,
        total_issued,
        total_burned,
        ethereum_anchor,
    })
}

fn decode_burn_state_witness(bytes: &[u8]) -> Result<BurnStateWitness, UsdomStateError> {
    if bytes.len() > MAX_BURN_STATE_WITNESS_BYTES {
        return Err(UsdomStateError::MalformedBurnWitness);
    }
    let mut reader = WitnessReader::new(bytes);
    if reader.take(BURN_WITNESS_MAGIC.len())? != BURN_WITNESS_MAGIC {
        return Err(UsdomStateError::MalformedBurnWitness);
    }
    let state = decode_state_commitment(&mut reader)?;
    let record = decode_burn_record(&mut reader)?;
    let leaf_index = u64::from_be_bytes(reader.array()?);
    let leaf_count = u64::from_be_bytes(reader.array()?);
    let sibling_count = usize::from(reader.byte()?);
    if sibling_count > MAX_BURN_INCLUSION_SIBLINGS {
        return Err(UsdomStateError::MalformedBurnWitness);
    }
    let mut siblings = Vec::with_capacity(sibling_count);
    for _ in 0..sibling_count {
        siblings.push(Hash256::from_bytes(reader.array()?));
    }
    let witness = BurnStateWitness {
        state,
        burn: BurnSetInclusionProof {
            record,
            leaf_index,
            leaf_count,
            siblings,
        },
    };
    if !reader.is_empty()
        || !witness.verify(witness.state.root())
        || witness.to_bytes()?.as_slice() != bytes
    {
        return Err(UsdomStateError::MalformedBurnWitness);
    }
    Ok(witness)
}

fn encode_burn_timing_policy(bytes: &mut Vec<u8>, policy: BurnTimingPolicy) {
    bytes.extend_from_slice(&policy.withdrawal_delay_secs.to_be_bytes());
    bytes.extend_from_slice(&policy.min_execution_window_secs.to_be_bytes());
    bytes.extend_from_slice(&policy.max_certificate_lifetime_secs.to_be_bytes());
    bytes.extend_from_slice(&policy.relay_safety_margin_secs.to_be_bytes());
    bytes.extend_from_slice(&policy.max_ethereum_anchor_age_secs.to_be_bytes());
    bytes.extend_from_slice(&policy.max_dom_clock_lead_secs.to_be_bytes());
}

fn encode_burn_timing_policy_bytes(policy: BurnTimingPolicy) -> [u8; 48] {
    let mut bytes = [0u8; 48];
    bytes[0..8].copy_from_slice(&policy.withdrawal_delay_secs.to_be_bytes());
    bytes[8..16].copy_from_slice(&policy.min_execution_window_secs.to_be_bytes());
    bytes[16..24].copy_from_slice(&policy.max_certificate_lifetime_secs.to_be_bytes());
    bytes[24..32].copy_from_slice(&policy.relay_safety_margin_secs.to_be_bytes());
    bytes[32..40].copy_from_slice(&policy.max_ethereum_anchor_age_secs.to_be_bytes());
    bytes[40..48].copy_from_slice(&policy.max_dom_clock_lead_secs.to_be_bytes());
    bytes
}

fn transition_batch_root(
    domain: [u8; 32],
    commitments: &[Hash256],
) -> Result<Hash256, UsdomStateError> {
    if commitments.is_empty() {
        return Ok(blake2b_256_tagged(TAG_BATCH_EMPTY, &domain));
    }
    let mut level: Vec<Hash256> = commitments
        .iter()
        .enumerate()
        .map(|(index, commitment)| {
            let index: u32 = index
                .try_into()
                .map_err(|_| UsdomStateError::BatchTooLarge)?;
            let mut bytes = Vec::with_capacity(68);
            bytes.extend_from_slice(&domain);
            bytes.extend_from_slice(&index.to_be_bytes());
            bytes.extend_from_slice(commitment.as_bytes());
            Ok(blake2b_256_tagged(TAG_BATCH_LEAF, &bytes))
        })
        .collect::<Result<_, UsdomStateError>>()?;
    let mut depth = 0u32;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 1 {
                next.push(pair[0]);
            } else {
                let mut bytes = Vec::with_capacity(68);
                bytes.extend_from_slice(&depth.to_be_bytes());
                bytes.extend_from_slice(pair[0].as_bytes());
                bytes.extend_from_slice(pair[1].as_bytes());
                next.push(blake2b_256_tagged(TAG_BATCH_NODE, &bytes));
            }
        }
        level = next;
        depth = depth.saturating_add(1);
    }
    Ok(level[0])
}

fn batch_header_commitment(
    domain: [u8; 32],
    transition_count: u32,
    block_timestamp: u64,
    transitions_root: Hash256,
    previous_state_root: Hash256,
    new_state_root: Hash256,
) -> Hash256 {
    let mut bytes = Vec::with_capacity(142);
    bytes.extend_from_slice(&TRANSITION_BATCH_VERSION.to_be_bytes());
    bytes.extend_from_slice(&domain);
    bytes.extend_from_slice(&transition_count.to_be_bytes());
    bytes.extend_from_slice(&block_timestamp.to_be_bytes());
    bytes.extend_from_slice(transitions_root.as_bytes());
    bytes.extend_from_slice(previous_state_root.as_bytes());
    bytes.extend_from_slice(new_state_root.as_bytes());
    blake2b_256_tagged(TAG_BATCH_COMMITMENT, &bytes)
}

fn validate_batch_undo_chain(undo: &BatchUndo) -> Result<(), UsdomStateError> {
    if undo.undos.len() > MAX_TRANSITIONS_PER_BATCH
        || undo.projections.len() != undo.undos.len()
        || undo.before_root == Hash256::ZERO
        || undo.after_root == Hash256::ZERO
        || undo.transitions_root == Hash256::ZERO
        || undo.block_timestamp == 0
    {
        return Err(UsdomStateError::MalformedUndo);
    }
    for projection in &undo.projections {
        projection
            .consensus_commitment()
            .map_err(|_| UsdomStateError::MalformedUndo)?;
    }
    if let Some(first) = undo.projections.first() {
        validate_batch_projection_root(undo, first.domain())?;
    }
    if undo.undos.is_empty() {
        if undo.before_root != undo.after_root {
            return Err(UsdomStateError::MalformedUndo);
        }
        return Ok(());
    }
    if undo.undos.first().map(StateUndo::before_root) != Some(undo.before_root)
        || undo.undos.last().map(StateUndo::after_root) != Some(undo.after_root)
        || undo
            .undos
            .windows(2)
            .any(|pair| pair[0].after_root() != pair[1].before_root())
    {
        return Err(UsdomStateError::MalformedUndo);
    }
    Ok(())
}

fn validate_batch_projection_root(
    undo: &BatchUndo,
    domain: [u8; 32],
) -> Result<(), UsdomStateError> {
    require_projection_domain(domain).map_err(|_| UsdomStateError::MalformedUndo)?;
    let mut commitments = Vec::with_capacity(undo.projections.len());
    for projection in &undo.projections {
        if projection.domain() != domain {
            return Err(UsdomStateError::MalformedUndo);
        }
        commitments.push(
            projection
                .consensus_commitment()
                .map_err(|_| UsdomStateError::MalformedUndo)?,
        );
    }
    if transition_batch_root(domain, &commitments)? != undo.transitions_root {
        return Err(UsdomStateError::MalformedUndo);
    }
    Ok(())
}

fn merkle_root(mut level: Vec<Hash256>) -> Hash256 {
    if level.is_empty() {
        return blake2b_256_tagged(TAG_SET_EMPTY, &[]);
    }
    let mut depth = 0u32;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 1 {
                next.push(pair[0]);
            } else {
                next.push(set_node_hash(depth, pair[0], pair[1]));
            }
        }
        level = next;
        depth = depth.saturating_add(1);
    }
    level[0]
}

#[cfg(feature = "unsafe-test-oracle")]
/// Build fixture issuance without proof verification. Debug/test builds only.
pub fn unsafe_test_only_issuance(
    domain: [u8; 32],
    deposit_id: [u8; 32],
    note_commitment: [u8; 32],
    amount: u64,
    ethereum_anchor: EthereumAnchor,
) -> VerifiedIssuance {
    VerifiedIssuance {
        domain,
        deposit_id,
        note_commitment,
        amount,
        ethereum_anchor,
    }
}

#[cfg(feature = "unsafe-test-oracle")]
/// Build fixture transfer without proof verification. Debug/test builds only.
pub fn unsafe_test_only_transfer(
    domain: [u8; 32],
    anchor: NoteAnchor,
    nullifiers: Vec<[u8; 32]>,
    output_notes: Vec<[u8; 32]>,
    memo_commitment: [u8; 32],
) -> VerifiedTransfer {
    VerifiedTransfer {
        domain,
        anchor,
        nullifiers,
        output_notes,
        memo_commitment,
    }
}

#[cfg(feature = "unsafe-test-oracle")]
/// Build fixture burn without proof verification. Debug/test builds only.
pub fn unsafe_test_only_burn(
    domain: [u8; 32],
    anchor: NoteAnchor,
    nullifiers: Vec<[u8; 32]>,
    change_notes: Vec<[u8; 32]>,
    memo_commitment: [u8; 32],
    record: BurnRecord,
) -> VerifiedBurn {
    VerifiedBurn {
        domain,
        anchor,
        nullifiers,
        change_notes,
        memo_commitment,
        record,
    }
}

#[cfg(feature = "unsafe-test-oracle")]
/// Build a fixture Ethereum checkpoint without finality verification.
/// Debug/test builds only.
pub fn unsafe_test_only_ethereum_checkpoint(
    domain: [u8; 32],
    anchor: EthereumAnchor,
) -> VerifiedEthereumCheckpoint {
    VerifiedEthereumCheckpoint { domain, anchor }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: [u8; 32] = [0x11; 32];
    const BLOCK_TIMESTAMP: u64 = 1_800_000_000;

    fn context() -> BlockContext {
        BlockContext {
            timestamp: BLOCK_TIMESTAMP,
        }
    }

    fn bridge(domain: [u8; 32]) -> BridgeIdentity {
        let mut ethereum_chain_id = [0; 32];
        ethereum_chain_id[30..].copy_from_slice(&31337u16.to_be_bytes());
        BridgeIdentity {
            dom_domain: domain,
            ethereum_genesis_validators_root: [0x42; 32],
            ethereum_chain_id,
            ethereum_checkpoint_policy_hash: [0x43; 32],
            ethereum_deposit_policy_hash: [0x44; 32],
            privacy_policy_hash: *dom_usdom_privacy::privacy_policy_hash().as_bytes(),
            privacy_verifier_config_hash: [0x45; 32],
            reserve: [0x66; 20],
            burn_timing: BurnTimingPolicy {
                withdrawal_delay_secs: 86_400,
                min_execution_window_secs: 3_600,
                max_certificate_lifetime_secs: 604_800,
                relay_safety_margin_secs: 3_600,
                max_ethereum_anchor_age_secs: 1_800,
                max_dom_clock_lead_secs: MAX_FUTURE_BLOCK_TIME,
            },
        }
    }

    fn eth(number: u64) -> EthereumAnchor {
        EthereumAnchor {
            genesis_validators_root: [0x42; 32],
            execution_block_number: number,
            execution_block_hash: [number as u8; 32],
            execution_block_timestamp: BLOCK_TIMESTAMP - 300 + number,
            beacon_slot: number + 100,
            beacon_root: [(number + 1) as u8; 32],
        }
    }

    fn issue(deposit: u8, note: u8, amount: u64, block: u64) -> VerifiedTransition {
        VerifiedTransition::Issue(VerifiedIssuance {
            domain: DOMAIN,
            deposit_id: [deposit; 32],
            note_commitment: [note; 32],
            amount,
            ethereum_anchor: eth(block),
        })
    }

    fn checkpoint(anchor: EthereumAnchor) -> VerifiedTransition {
        VerifiedTransition::EthereumCheckpoint(VerifiedEthereumCheckpoint {
            domain: DOMAIN,
            anchor,
        })
    }

    fn assert_projection_roundtrip(transition: &VerifiedTransition) {
        let projection = transition.commitment_projection();
        assert_eq!(
            projection.consensus_commitment().unwrap(),
            transition.consensus_commitment().unwrap()
        );
        let encoded = projection.to_bytes().unwrap();
        for end in 0..encoded.len() {
            assert!(
                TransitionCommitmentProjection::from_bytes(&encoded[..end]).is_err(),
                "projection prefix {end}"
            );
        }
        assert_eq!(
            TransitionCommitmentProjection::from_bytes(&encoded).unwrap(),
            projection
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert!(TransitionCommitmentProjection::from_bytes(&trailing).is_err());
    }

    #[test]
    fn every_native_state_decoder_rejects_hostile_bounded_bytes_without_panicking() {
        fn hostile(length: usize, seed: u8, magic: &[u8]) -> Vec<u8> {
            let mut bytes = (0..length)
                .map(|index| seed.wrapping_add((index as u8).wrapping_mul(73)))
                .collect::<Vec<_>>();
            let prefix = magic.len().min(bytes.len());
            bytes[..prefix].copy_from_slice(&magic[..prefix]);
            bytes
        }

        for length in 0..=4_096 {
            for seed in [0u8, 0x5a, 0xff] {
                let bytes = hostile(length, seed, STATE_COMMITMENT_V2_MAGIC);
                let _ = StateCommitmentV2::from_bytes(&bytes);

                let bytes = hostile(length, seed, SET_TRANSITION_WITNESS_MAGIC);
                let _ = NativeSetTransitionWitness::from_bytes(&bytes);

                let bytes = hostile(length, seed, NATIVE_TRANSITION_WITNESS_MAGIC);
                let _ = NativeTransitionWitness::from_bytes(&bytes);

                let bytes = hostile(length, seed, ACCUMULATOR_WITNESS_MAGIC);
                let _ = NativeAccumulatorWitness::from_bytes(&bytes);

                let bytes = hostile(length, seed, BURN_WITNESS_MAGIC);
                let _ = BurnStateWitness::from_bytes(&bytes);

                let bytes = hostile(length, seed, TRANSITION_PROJECTION_MAGIC);
                let _ = TransitionCommitmentProjection::from_bytes(&bytes);

                let bytes = hostile(length, seed, BATCH_UNDO_MAGIC);
                let _ = BatchUndo::from_bytes(&bytes);

                let bytes = hostile(length, seed, b"UDOMUN01");
                let _ = StateUndo::from_bytes(&bytes);
            }
        }
    }

    fn transfer(state: &NativeUsdomState, nullifiers: &[u8], notes: &[u8]) -> VerifiedTransition {
        VerifiedTransition::Transfer(VerifiedTransfer {
            domain: DOMAIN,
            anchor: state.note_anchor(),
            nullifiers: nullifiers.iter().map(|byte| [*byte; 32]).collect(),
            output_notes: notes.iter().map(|byte| [*byte; 32]).collect(),
            memo_commitment: [0x0b; 32],
        })
    }

    fn burn(
        state: &NativeUsdomState,
        nullifier: u8,
        change: &[u8],
        id: u8,
        request: u8,
        amount: u64,
    ) -> VerifiedTransition {
        let nullifiers = vec![[nullifier; 32]];
        let recipient = [id; 20];
        let bridge = bridge(DOMAIN);
        VerifiedTransition::Burn(VerifiedBurn {
            domain: DOMAIN,
            anchor: state.note_anchor(),
            nullifiers: nullifiers.clone(),
            change_notes: change.iter().map(|byte| [*byte; 32]).collect(),
            memo_commitment: if change.is_empty() {
                [0; 32]
            } else {
                [0x0c; 32]
            },
            record: {
                let mut record = BurnRecord {
                    burn_id: derive_private_burn_id(
                        bridge,
                        &nullifiers,
                        recipient,
                        amount,
                        1_800_600_000,
                    )
                    .unwrap(),
                    request_id: [request; 32],
                    amount,
                    recipient,
                    ethereum_chain_id: bridge.ethereum_chain_id,
                    reserve: bridge.reserve,
                    valid_until: 1_800_600_000,
                    obligation_commitment: [0; 32],
                };
                record.obligation_commitment = record.expected_obligation_commitment(DOMAIN);
                record
            },
        })
    }

    #[test]
    fn parallel_sparse_set_caches_follow_apply_restore_and_exact_rollback() {
        let mut state = NativeUsdomState::new(bridge(DOMAIN)).expect("state");
        let genesis = state.experimental_authenticated_set_roots();

        let (_, issue_undo) = state
            .apply(context(), &issue(1, 2, 1_000, 100))
            .expect("issue");
        let issued = state.experimental_authenticated_set_roots();
        assert_ne!(issued.notes, genesis.notes);
        assert_ne!(issued.deposits, genesis.deposits);
        assert_eq!(issued.nullifiers, genesis.nullifiers);
        assert_eq!(issued.burns, genesis.burns);
        assert_eq!(issued.burn_requests, genesis.burn_requests);

        let transfer = transfer(&state, &[3], &[4]);
        let (_, transfer_undo) = state.apply(context(), &transfer).expect("transfer");
        let transferred = state.experimental_authenticated_set_roots();
        assert_ne!(transferred.notes, issued.notes);
        assert_ne!(transferred.nullifiers, issued.nullifiers);
        assert_eq!(transferred.deposits, issued.deposits);

        let burn = burn(&state, 5, &[6], 7, 8, 10);
        let (_, burn_undo) = state.apply(context(), &burn).expect("burn");
        let burned = state.experimental_authenticated_set_roots();
        assert_ne!(burned.notes, transferred.notes);
        assert_ne!(burned.nullifiers, transferred.nullifiers);
        assert_ne!(burned.burns, transferred.burns);
        assert_ne!(burned.burn_requests, transferred.burn_requests);

        let restored = NativeUsdomState::restore_entries(bridge(DOMAIN), &state.export_entries())
            .expect("restore");
        assert_eq!(restored.experimental_authenticated_set_roots(), burned);
        assert_eq!(restored.state_root(), state.state_root());

        state.revert(&burn_undo).expect("revert burn");
        assert_eq!(state.experimental_authenticated_set_roots(), transferred);
        state.revert(&transfer_undo).expect("revert transfer");
        assert_eq!(state.experimental_authenticated_set_roots(), issued);
        state.revert(&issue_undo).expect("revert issue");
        assert_eq!(state.experimental_authenticated_set_roots(), genesis);
    }

    #[test]
    fn accumulator_witness_advances_without_historical_notes() {
        let mut state = NativeUsdomState::new(bridge(DOMAIN)).expect("state");
        let mut witness = state.accumulator_witness().expect("initial witness");
        assert!(witness.verify(&state.state_commitment().expect("commitment")));

        let issuance = issue(1, 2, 1_000, 100);
        witness
            .append_transition(DOMAIN, &[[2; 32]])
            .expect("witness issue");
        state.apply(context(), &issuance).expect("state issue");
        assert!(witness.verify(&state.state_commitment().expect("issued state")));

        let transfer = transfer(&state, &[3], &[4, 5]);
        witness
            .append_transition(DOMAIN, &[[4; 32], [5; 32]])
            .expect("witness transfer");
        state.apply(context(), &transfer).expect("state transfer");
        assert!(witness.verify(&state.state_commitment().expect("transfer state")));

        let burn = burn(&state, 6, &[7], 8, 9, 10);
        witness
            .append_transition(DOMAIN, &[[7; 32]])
            .expect("witness burn");
        state.apply(context(), &burn).expect("state burn");
        let commitment = state.state_commitment().expect("burn state");
        assert!(witness.verify(&commitment));
        assert_eq!(
            witness.notes_root_and_count(),
            (commitment.notes_root, commitment.note_count)
        );
        assert_eq!(witness.privacy_notes_root(), commitment.privacy_notes_root);
        assert_eq!(
            witness.anchor_root_and_count(),
            (commitment.anchor_root, commitment.anchor_count)
        );

        let bytes = witness.to_bytes().expect("encode");
        assert!(bytes.len() <= MAX_ACCUMULATOR_WITNESS_BYTES);
        let decoded = NativeAccumulatorWitness::from_bytes(&bytes).expect("decode");
        assert!(decoded.verify(&commitment));
        assert_eq!(decoded.to_bytes().expect("re-encode"), bytes);
        assert_eq!(
            hex::encode(Keccak256::digest(&bytes)),
            "1bd96279176d3f18b1c83a4a78c1b92614a7b5dc9265a15789138f429234a290"
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            NativeAccumulatorWitness::from_bytes(&trailing).unwrap_err(),
            UsdomStateError::MalformedAccumulatorWitness
        );
    }

    #[test]
    fn candidate_v2_sparse_and_accumulator_witnesses_match_full_transitions() {
        let mut state = NativeUsdomState::new(bridge(DOMAIN)).expect("state");
        assert_ne!(
            state.state_commitment_v2().expect("empty v2").root(),
            state.state_root()
        );

        let transitions = [issue(1, 2, 1_000, 100), transfer(&state, &[3], &[4])];
        for transition in transitions {
            let previous = state.state_commitment_v2().expect("previous v2");
            let set_witness = state
                .set_transition_witness(&transition)
                .expect("set witness");
            let mut accumulator = state.accumulator_witness().expect("accumulator");
            assert!(accumulator.verify_v2(&previous));
            let set_next = set_witness
                .apply_sets(previous, &transition)
                .expect("apply sets");
            let notes: Vec<_> = match &transition {
                VerifiedTransition::Issue(value) => vec![value.note_commitment],
                VerifiedTransition::Transfer(value) => value.output_notes.clone(),
                _ => unreachable!(),
            };
            accumulator
                .append_transition(DOMAIN, &notes)
                .expect("append accumulators");
            let witnessed = accumulator.update_v2(set_next).expect("update v2");
            state
                .apply(context(), &transition)
                .expect("full transition");
            let actual = state.state_commitment_v2().expect("actual v2");
            assert_eq!(
                witnessed.authenticated_set_roots(),
                actual.authenticated_set_roots()
            );
            assert_eq!(witnessed.note_set_count, actual.note_set_count);
            assert_eq!(witnessed.nullifier_count, actual.nullifier_count);
            assert_eq!(witnessed.deposit_count, actual.deposit_count);
            assert_eq!(witnessed.notes_root, actual.notes_root);
            assert_eq!(witnessed.privacy_notes_root, actual.privacy_notes_root);
            assert_eq!(witnessed.note_count, actual.note_count);
            assert_eq!(witnessed.anchor_root, actual.anchor_root);
            assert_eq!(witnessed.anchor_count, actual.anchor_count);
        }

        let burn = burn(&state, 5, &[6], 7, 8, 10);
        let previous = state.state_commitment_v2().expect("pre-burn v2");
        let set_witness = state.set_transition_witness(&burn).expect("burn witness");
        assert_eq!(set_witness.effect_count(), 4);
        let bytes = set_witness.to_bytes().expect("encode set witness");
        assert_eq!(
            NativeSetTransitionWitness::from_bytes(&bytes)
                .expect("decode")
                .to_bytes()
                .expect("re-encode"),
            bytes
        );
        assert_eq!(
            hex::encode(Keccak256::digest(&bytes)),
            "ca28e857bc63a31044b7f9b86302f4bdaa72d9c45ef97c718e33517664c0ba93"
        );
        let set_next = set_witness
            .apply_sets(previous, &burn)
            .expect("apply burn sets");
        let mut accumulator = state.accumulator_witness().expect("burn accumulator");
        assert!(accumulator.verify_v2(&previous));
        accumulator
            .append_transition(DOMAIN, &[[6; 32]])
            .expect("append burn change");
        let witnessed = accumulator.update_v2(set_next).expect("combined roots");
        state.apply(context(), &burn).expect("full burn");
        let actual = state.state_commitment_v2().expect("post-burn v2");
        assert_eq!(
            witnessed.authenticated_set_roots(),
            actual.authenticated_set_roots()
        );
        assert_eq!(witnessed.notes_root, actual.notes_root);
        assert_eq!(witnessed.privacy_notes_root, actual.privacy_notes_root);
        assert_eq!(witnessed.anchor_root, actual.anchor_root);
        assert_eq!(
            actual.burn_count, actual.burn_request_count,
            "every burn must reserve one unique request id"
        );
        assert_eq!(
            actual.root().to_string(),
            "fceaa6fdd22ee1e50ac9737cb1ae536f077c14e243df6912b31c4bbb8b41d39b"
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            NativeSetTransitionWitness::from_bytes(&trailing),
            Err(UsdomStateError::MalformedSetWitness)
        );
        let mut excessive_count = bytes.clone();
        excessive_count[8] = u8::MAX;
        assert_eq!(
            NativeSetTransitionWitness::from_bytes(&excessive_count),
            Err(UsdomStateError::MalformedSetWitness)
        );
        let mut noncanonical_flags = bytes.clone();
        noncanonical_flags[9] |= 1 << 7;
        assert_eq!(
            NativeSetTransitionWitness::from_bytes(&noncanonical_flags),
            Err(UsdomStateError::MalformedSetWitness)
        );
        let restored = NativeUsdomState::restore_entries(bridge(DOMAIN), &state.export_entries())
            .expect("restore");
        assert_eq!(restored.state_commitment_v2().expect("restored v2"), actual);
    }

    #[test]
    fn issuance_anchor_indexes_accept_exact_reuse_reject_conflicts_and_revert() {
        let mut state = NativeUsdomState::new(bridge(DOMAIN)).expect("state");
        let first = issue(1, 2, 100, 100);
        let (_, first_undo) = state.apply(context(), &first).expect("first issuance");
        let after_first = state.state_commitment_v2().expect("first v2");

        let mut second = issue(3, 4, 200, 101);
        let VerifiedTransition::Issue(second_value) = &mut second else {
            unreachable!()
        };
        second_value.ethereum_anchor = eth(100);
        let witness = state
            .set_transition_witness(&second)
            .expect("same-anchor witness");
        assert_eq!(witness.existing, vec![false, false, true, true]);
        let encoded_witness = witness.to_bytes().expect("encode shared-anchor witness");
        assert_eq!(
            NativeSetTransitionWitness::from_bytes(&encoded_witness).expect("decode witness"),
            witness
        );
        assert_eq!(
            hex::encode(Keccak256::digest(&encoded_witness)),
            "c6e24aa9ffd2d5c106d4b7590fb6151b21b521543ad7bc4213be20d31772b832"
        );
        let witnessed = witness
            .apply_sets(after_first, &second)
            .expect("same-anchor update");
        assert_eq!(
            witnessed.execution_anchor_root,
            after_first.execution_anchor_root
        );
        assert_eq!(witnessed.beacon_anchor_root, after_first.beacon_anchor_root);
        assert_eq!(witnessed.execution_anchor_count, 1);
        assert_eq!(witnessed.beacon_anchor_count, 1);
        let (_, second_undo) = state.apply(context(), &second).expect("second issuance");
        let after_second = state.state_commitment_v2().expect("second v2");
        assert_eq!(
            after_second.execution_anchor_root,
            after_first.execution_anchor_root
        );
        assert_eq!(
            after_second.beacon_anchor_root,
            after_first.beacon_anchor_root
        );
        assert_eq!(after_second.execution_anchor_count, 1);
        assert_eq!(after_second.beacon_anchor_count, 1);

        state.revert(&second_undo).expect("revert shared reference");
        assert_eq!(
            state.state_commitment_v2().expect("reverted v2"),
            after_first
        );

        let mut conflict = issue(5, 6, 300, 102);
        let VerifiedTransition::Issue(conflicting_value) = &mut conflict else {
            unreachable!()
        };
        conflicting_value.ethereum_anchor.execution_block_number = 100;
        conflicting_value.ethereum_anchor.execution_block_hash = [0x99; 32];
        assert_eq!(
            state.set_transition_witness(&conflict).unwrap_err(),
            UsdomStateError::EthereumAnchorConflict
        );
        let before_conflict = state.state_root();
        assert_eq!(
            state.apply(context(), &conflict).unwrap_err(),
            UsdomStateError::EthereumAnchorConflict
        );
        assert_eq!(state.state_root(), before_conflict);

        state.revert(&first_undo).expect("revert final reference");
        let empty = NativeUsdomState::new(bridge(DOMAIN)).expect("empty");
        assert_eq!(
            state.experimental_authenticated_set_roots(),
            empty.experimental_authenticated_set_roots()
        );
    }

    #[test]
    fn complete_v2_stateless_executor_matches_full_state_for_every_transition_kind() {
        fn apply_both(state: &mut NativeUsdomState, transition: &VerifiedTransition) {
            let previous = state.state_commitment_v2().expect("previous v2");
            let witness = state
                .transition_witness(context(), transition)
                .expect("complete witness");
            let predicted = witness
                .apply_v2(previous.root(), context(), previous, transition)
                .expect("stateless apply");
            state
                .apply(context(), transition)
                .expect("full-state apply");
            assert_eq!(predicted, state.state_commitment_v2().expect("actual v2"));
            assert_eq!(
                predicted.root(),
                state.state_commitment_v2().unwrap().root()
            );
        }

        let mut state = NativeUsdomState::new(bridge(DOMAIN)).expect("state");
        let issuance = issue(1, 2, 1_000, 100);
        let initial_witness = state
            .transition_witness(context(), &issuance)
            .expect("initial witness");
        let encoded = initial_witness.to_bytes().expect("encode composite");
        assert!(encoded.len() <= MAX_NATIVE_TRANSITION_WITNESS_BYTES);
        assert_eq!(
            NativeTransitionWitness::from_bytes(&encoded)
                .expect("decode composite")
                .to_bytes()
                .expect("re-encode composite"),
            encoded
        );
        assert_eq!(
            hex::encode(Keccak256::digest(&encoded)),
            "af43c6bc5675031cdd5a8844ec89cebe07dd8e444d3f45876ea4f58b4f310487"
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(NativeTransitionWitness::from_bytes(&trailing).is_err());
        let mut bad_length = encoded.clone();
        bad_length[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(NativeTransitionWitness::from_bytes(&bad_length).is_err());
        apply_both(&mut state, &issuance);
        apply_both(&mut state, &checkpoint(eth(101)));
        let transfer = transfer(&state, &[3], &[4]);
        apply_both(&mut state, &transfer);
        let burn = burn(&state, 5, &[6], 7, 8, 10);
        let witness = state
            .transition_witness(context(), &burn)
            .expect("burn witness");
        let previous = state.state_commitment_v2().expect("pre-burn v2");
        assert_eq!(
            witness
                .apply_v2(Hash256::ZERO, context(), previous, &burn)
                .unwrap_err(),
            UsdomStateError::InvalidV2Commitment
        );
        assert_eq!(
            witness
                .apply_v2(
                    previous.root(),
                    BlockContext { timestamp: 0 },
                    previous,
                    &burn,
                )
                .unwrap_err(),
            UsdomStateError::InvalidBlockContext
        );
        apply_both(&mut state, &burn);

        let mut malformed = state.state_commitment_v2().expect("final v2");
        malformed.burn_request_count += 1;
        assert_eq!(
            validate_v2_commitment(&malformed).unwrap_err(),
            UsdomStateError::InvalidV2Commitment
        );
    }

    #[test]
    fn state_commitment_v2_persistence_roundtrips_and_rejects_noncanonical_bytes() {
        let mut state = NativeUsdomState::new(bridge(DOMAIN)).expect("state");
        let empty = state.state_commitment_v2().expect("empty v2");
        let empty_bytes = empty.to_bytes().expect("encode empty v2");
        assert_eq!(empty_bytes.len(), STATE_COMMITMENT_V2_BASE_BYTES);
        assert_eq!(
            StateCommitmentV2::from_bytes(&empty_bytes).expect("decode empty v2"),
            empty
        );

        state
            .apply(context(), &issue(1, 2, 1_000, 100))
            .expect("apply issuance");
        let populated = state.state_commitment_v2().expect("populated v2");
        let populated_bytes = populated.to_bytes().expect("encode populated v2");
        assert_eq!(populated_bytes.len(), MAX_STATE_COMMITMENT_V2_BYTES);
        let restored =
            StateCommitmentV2::from_bytes(&populated_bytes).expect("decode populated v2");
        assert_eq!(restored, populated);
        assert_eq!(restored.root(), populated.root());

        let mut wrong_magic = populated_bytes.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            StateCommitmentV2::from_bytes(&wrong_magic),
            Err(UsdomStateError::InvalidV2Commitment)
        );
        let mut wrong_version = populated_bytes.clone();
        wrong_version[8..10].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            StateCommitmentV2::from_bytes(&wrong_version),
            Err(UsdomStateError::InvalidV2Commitment)
        );
        let mut zero_domain = populated_bytes.clone();
        zero_domain[10..42].fill(0);
        assert_eq!(
            StateCommitmentV2::from_bytes(&zero_domain),
            Err(UsdomStateError::InvalidV2Commitment)
        );
        let mut invalid_anchor_flag = populated_bytes.clone();
        invalid_anchor_flag[STATE_COMMITMENT_V2_BASE_BYTES - 1] = 2;
        assert_eq!(
            StateCommitmentV2::from_bytes(&invalid_anchor_flag),
            Err(UsdomStateError::InvalidV2Commitment)
        );
        assert_eq!(
            StateCommitmentV2::from_bytes(&populated_bytes[..populated_bytes.len() - 1]),
            Err(UsdomStateError::InvalidV2Commitment)
        );
    }

    #[test]
    fn ordered_v2_stateless_batch_matches_atomic_full_state_batch() {
        let state = NativeUsdomState::new(bridge(DOMAIN)).expect("state");
        let mut planning = state.clone();
        let issuance = issue(1, 2, 1_000, 100);
        planning.apply(context(), &issuance).expect("plan issue");
        let checkpoint = checkpoint(eth(101));
        planning
            .apply(context(), &checkpoint)
            .expect("plan checkpoint");
        let transfer = transfer(&planning, &[3], &[4]);
        planning.apply(context(), &transfer).expect("plan transfer");
        let burn = burn(&planning, 5, &[6], 7, 8, 10);
        let transitions = vec![issuance, checkpoint, transfer, burn];

        let previous = state.state_commitment_v2().expect("previous");
        let witnesses = state
            .transition_batch_witnesses(context(), &transitions)
            .expect("batch witnesses");
        let (predicted, v2_receipt) = apply_v2_transition_batch_with_receipt(
            previous.root(),
            context(),
            previous,
            &transitions,
            &witnesses,
        )
        .expect("stateless batch");
        let mut full = state;
        let (v1_receipt, _) = full
            .apply_batch(context(), &transitions)
            .expect("full batch");
        assert_eq!(predicted, full.state_commitment_v2().expect("actual"));
        assert_eq!(v2_receipt.version, CANDIDATE_V2_TRANSITION_BATCH_VERSION);
        assert_eq!(v2_receipt.previous_state_root, previous.root());
        assert_eq!(v2_receipt.new_state_root, predicted.root());
        assert_ne!(v2_receipt.header_commitment, v1_receipt.header_commitment);

        assert_eq!(
            apply_v2_transition_batch(
                previous.root(),
                context(),
                previous,
                &transitions,
                &witnesses[..witnesses.len() - 1],
            )
            .unwrap_err(),
            UsdomStateError::MalformedSetWitness
        );
        let mut reordered = witnesses;
        reordered.swap(0, 1);
        assert!(apply_v2_transition_batch(
            previous.root(),
            context(),
            previous,
            &transitions,
            &reordered,
        )
        .is_err());
    }

    #[test]
    fn issuance_transfer_burn_and_exact_reverse_preserve_monetary_state() {
        let mut state = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        let genesis = state.state_root();
        let (_, undo_issue) = state
            .apply(context(), &issue(1, 2, 1_000_000, 100))
            .unwrap();
        let issued = state.state_root();
        assert_eq!(state.total_issued(), 1_000_000);
        assert_eq!(state.outstanding(), 1_000_000);
        assert!(state.has_consumed_deposit(&[1; 32]));

        let tx = transfer(&state, &[3], &[4, 5]);
        let (_, undo_transfer) = state.apply(context(), &tx).unwrap();
        let transferred = state.state_root();
        assert_ne!(issued, transferred);
        assert_eq!(state.outstanding(), 1_000_000);

        let burn_tx = burn(&state, 6, &[7], 8, 9, 250_000);
        let burn_id = match &burn_tx {
            VerifiedTransition::Burn(value) => value.record.burn_id,
            _ => unreachable!(),
        };
        let (_, undo_burn) = state.apply(context(), &burn_tx).unwrap();
        assert_eq!(state.total_burned(), 250_000);
        assert_eq!(state.outstanding(), 750_000);
        assert_eq!(state.burn(&burn_id).unwrap().amount, 250_000);
        assert!(state.has_burn_request(&[9; 32]));

        let burn_undo_bytes = undo_burn.to_bytes().unwrap();
        let restored_burn_undo = StateUndo::from_bytes(&burn_undo_bytes).unwrap();
        assert_eq!(restored_burn_undo.before_root(), undo_burn.before_root());
        assert_eq!(restored_burn_undo.after_root(), undo_burn.after_root());
        state.revert(&restored_burn_undo).unwrap();
        assert_eq!(state.state_root(), transferred);
        assert_eq!(state.burn(&burn_id), None);
        assert!(!state.has_burn_request(&[9; 32]));
        state.revert(&undo_transfer).unwrap();
        assert_eq!(state.state_root(), issued);
        state.revert(&undo_issue).unwrap();
        assert_eq!(state.state_root(), genesis);
        assert_eq!(state.total_issued(), 0);
        assert_eq!(state.outstanding(), 0);
    }

    #[test]
    fn burn_state_witness_binds_every_ordered_set_shape_and_state_component() {
        for burn_count in 1u8..=17 {
            let mut state = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
            state.apply(context(), &issue(1, 2, 1_000, 100)).unwrap();
            let mut burn_ids = Vec::new();
            for ordinal in 1..=burn_count {
                let transition = burn(&state, ordinal + 20, &[], ordinal, ordinal + 40, 1);
                burn_ids.push(match &transition {
                    VerifiedTransition::Burn(value) => value.record.burn_id,
                    _ => unreachable!(),
                });
                state.apply(context(), &transition).unwrap();
            }

            let state_root = state.state_root();
            let commitment = state.state_commitment().unwrap();
            assert_eq!(commitment.root(), state_root);
            assert_eq!(commitment.burn_count, u64::from(burn_count));
            assert_eq!(commitment.total_burned, u128::from(burn_count));
            assert_eq!(state.burn_state_witness(&[0; 32]).unwrap(), None);

            for (index, burn_id) in burn_ids.into_iter().enumerate() {
                let witness = state.burn_state_witness(&burn_id).unwrap().unwrap();
                assert!(witness.verify(state_root));
                assert_eq!(witness.burn.leaf_count, u64::from(burn_count));
                assert!(witness.burn.siblings.len() <= MAX_BURN_INCLUSION_SIBLINGS);
                let encoded = witness.to_bytes().unwrap();
                assert!(encoded.len() <= MAX_BURN_STATE_WITNESS_BYTES);
                assert_eq!(BurnStateWitness::from_bytes(&encoded).unwrap(), witness);

                let mut wrong_record = witness.clone();
                wrong_record.burn.record.amount += 1;
                assert!(!wrong_record.verify(state_root));

                let mut wrong_state = witness.clone();
                wrong_state.state.total_burned += 1;
                assert!(!wrong_state.verify(state_root));

                let mut wrong_count = witness.clone();
                wrong_count.burn.leaf_count += 1;
                assert!(!wrong_count.verify(state_root));

                let mut extra_sibling = witness.clone();
                extra_sibling
                    .burn
                    .siblings
                    .push(Hash256::from_bytes([0x99; 32]));
                assert!(!extra_sibling.verify(state_root));

                if let Some(first) = witness.burn.siblings.first() {
                    let mut wrong_path = witness.clone();
                    wrong_path.burn.siblings[0] =
                        Hash256::from_bytes([first.as_bytes()[0] ^ 1; 32]);
                    assert!(!wrong_path.verify(state_root));
                }

                if burn_count == 17 && index == 16 {
                    for truncated in 0..encoded.len() {
                        assert_eq!(
                            BurnStateWitness::from_bytes(&encoded[..truncated]).unwrap_err(),
                            UsdomStateError::MalformedBurnWitness
                        );
                    }
                    let mut trailing = encoded.clone();
                    trailing.push(0);
                    assert_eq!(
                        BurnStateWitness::from_bytes(&trailing).unwrap_err(),
                        UsdomStateError::MalformedBurnWitness
                    );
                    let mut bad_magic = encoded.clone();
                    bad_magic[0] ^= 1;
                    assert_eq!(
                        BurnStateWitness::from_bytes(&bad_magic).unwrap_err(),
                        UsdomStateError::MalformedBurnWitness
                    );
                }
            }

            let restored =
                NativeUsdomState::restore_entries(bridge(DOMAIN), &state.export_entries()).unwrap();
            assert_eq!(restored.state_commitment().unwrap(), commitment);
            assert_eq!(
                restored.burn_state_witness(&[burn_count; 32]).unwrap(),
                state.burn_state_witness(&[burn_count; 32]).unwrap()
            );
        }
    }

    #[test]
    fn replay_double_spend_duplicate_note_and_overburn_fail_without_mutation() {
        let mut state = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        state.apply(context(), &issue(1, 2, 100, 100)).unwrap();
        let after_issue = state.state_root();
        assert_eq!(
            state.apply(context(), &issue(1, 9, 100, 100)).unwrap_err(),
            UsdomStateError::DepositAlreadyConsumed
        );
        assert_eq!(state.state_root(), after_issue);
        assert_eq!(
            state.apply(context(), &issue(9, 2, 100, 101)).unwrap_err(),
            UsdomStateError::DuplicateNote
        );
        assert_eq!(state.state_root(), after_issue);

        state
            .apply(context(), &transfer(&state, &[3], &[4]))
            .unwrap();
        let after_spend = state.state_root();
        assert_eq!(
            state
                .apply(context(), &transfer(&state, &[3], &[5]))
                .unwrap_err(),
            UsdomStateError::NullifierAlreadySpent
        );
        assert_eq!(state.state_root(), after_spend);
        assert_eq!(
            state
                .apply(context(), &burn(&state, 6, &[], 7, 8, 101))
                .unwrap_err(),
            UsdomStateError::BurnExceedsSupply
        );
        assert_eq!(state.state_root(), after_spend);

        let noncanonical = transfer(&state, &[9, 8], &[10]);
        assert_eq!(
            state.apply(context(), &noncanonical).unwrap_err(),
            UsdomStateError::NonCanonicalOrder
        );
        assert_eq!(state.state_root(), after_spend);
    }

    #[test]
    fn duplicate_burn_request_is_rejected_and_rollback_releases_the_request() {
        let mut state = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        state.apply(context(), &issue(1, 2, 100, 100)).unwrap();
        let (_, undo) = state
            .apply(context(), &burn(&state, 3, &[], 4, 5, 10))
            .unwrap();
        assert!(state.has_burn_request(&[5; 32]));
        let after_first_burn = state.state_root();

        let duplicate_request = burn(&state, 6, &[], 7, 5, 10);
        let duplicate_burn_id = match &duplicate_request {
            VerifiedTransition::Burn(value) => value.record.burn_id,
            _ => unreachable!(),
        };
        assert_eq!(
            state.apply(context(), &duplicate_request).unwrap_err(),
            UsdomStateError::BurnRequestAlreadyExists
        );
        assert_eq!(state.state_root(), after_first_burn);
        assert!(!state.has_nullifier(&[6; 32]));
        assert_eq!(state.burn(&duplicate_burn_id), None);

        let restored =
            NativeUsdomState::restore_entries(bridge(DOMAIN), &state.export_entries()).unwrap();
        assert!(restored.has_burn_request(&[5; 32]));
        state.revert(&undo).unwrap();
        assert!(!state.has_burn_request(&[5; 32]));
        state.apply(context(), &duplicate_request).unwrap();
    }

    #[test]
    fn burn_intent_matches_solidity_abi_vector_and_rejects_substitution() {
        let mut state = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        state.apply(context(), &issue(1, 2, 1_000, 100)).unwrap();
        let transition = burn(&state, 6, &[7], 8, 9, 250);
        let verified = match &transition {
            VerifiedTransition::Burn(value) => value,
            _ => unreachable!(),
        };
        assert_eq!(
            verified.record.obligation_commitment,
            [
                0x4f, 0x9a, 0x72, 0x14, 0xfb, 0x6b, 0x57, 0x01, 0xfe, 0x35, 0x8a, 0x82, 0x95, 0x24,
                0x62, 0xbc, 0x17, 0x2f, 0x22, 0x07, 0x21, 0xa7, 0x2b, 0x26, 0x4e, 0x4b, 0x73, 0x85,
                0x58, 0xa1, 0xd8, 0x42,
            ]
        );
        assert_eq!(
            verified.record.burn_id,
            [
                0xd0, 0xb8, 0xff, 0xc2, 0xdc, 0x96, 0x68, 0xfc, 0x6d, 0x73, 0xbe, 0xe4, 0x3e, 0xbc,
                0x97, 0x9e, 0xd6, 0x9e, 0x5c, 0xd0, 0xd2, 0xd8, 0xd1, 0x65, 0x6d, 0x75, 0x35, 0x39,
                0x81, 0x6b, 0x76, 0x2b,
            ]
        );

        let mut substituted = verified.clone();
        substituted.record.recipient = [0x45; 20];
        let stable = state.state_root();
        assert_eq!(
            state
                .apply(context(), &VerifiedTransition::Burn(substituted))
                .unwrap_err(),
            UsdomStateError::BurnIntentMismatch
        );
        assert_eq!(state.state_root(), stable);
        assert!(!state.has_nullifier(&[6; 32]));

        let mut foreign_reserve = verified.clone();
        foreign_reserve.record.reserve = [0x67; 20];
        foreign_reserve.record.obligation_commitment = foreign_reserve
            .record
            .expected_obligation_commitment(DOMAIN);
        assert_eq!(
            state
                .apply(context(), &VerifiedTransition::Burn(foreign_reserve))
                .unwrap_err(),
            UsdomStateError::BridgeIdentityMismatch
        );
        let mut foreign_chain = verified.clone();
        foreign_chain.record.ethereum_chain_id[31] ^= 1;
        foreign_chain.record.obligation_commitment =
            foreign_chain.record.expected_obligation_commitment(DOMAIN);
        assert_eq!(
            state
                .apply(context(), &VerifiedTransition::Burn(foreign_chain))
                .unwrap_err(),
            UsdomStateError::BridgeIdentityMismatch
        );
        assert_eq!(state.state_root(), stable);
        assert!(!state.has_nullifier(&[6; 32]));
        state.apply(context(), &transition).unwrap();
    }

    #[test]
    fn transition_commitment_binds_kind_domain_and_every_public_effect() {
        let issuance = issue(1, 2, 1_000, 100);
        assert_projection_roundtrip(&issuance);
        let original = issuance.consensus_commitment().unwrap();
        assert_eq!(
            issuance
                .commitment_projection()
                .consensus_commitment()
                .unwrap(),
            original
        );
        let mut changed = match issuance.clone() {
            VerifiedTransition::Issue(value) => value,
            _ => unreachable!(),
        };
        changed.amount += 1;
        assert_ne!(
            original,
            VerifiedTransition::Issue(changed)
                .consensus_commitment()
                .unwrap()
        );

        let mut state = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        state.apply(context(), &issuance).unwrap();
        let transfer = transfer(&state, &[3, 4], &[5, 6]);
        assert_projection_roundtrip(&transfer);
        let transfer_commitment = transfer.consensus_commitment().unwrap();
        assert_eq!(
            transfer
                .commitment_projection()
                .consensus_commitment()
                .unwrap(),
            transfer_commitment
        );
        let mut reordered = match transfer.clone() {
            VerifiedTransition::Transfer(value) => value,
            _ => unreachable!(),
        };
        reordered.output_notes.swap(0, 1);
        assert_ne!(
            transfer_commitment,
            VerifiedTransition::Transfer(reordered)
                .consensus_commitment()
                .unwrap()
        );
        let mut changed_memo = match transfer.clone() {
            VerifiedTransition::Transfer(value) => value,
            _ => unreachable!(),
        };
        changed_memo.memo_commitment[31] ^= 1;
        assert_ne!(
            transfer_commitment,
            VerifiedTransition::Transfer(changed_memo)
                .consensus_commitment()
                .unwrap()
        );
        let mut wrong_domain = match transfer {
            VerifiedTransition::Transfer(value) => value,
            _ => unreachable!(),
        };
        wrong_domain.domain = [0x22; 32];
        assert_ne!(
            transfer_commitment,
            VerifiedTransition::Transfer(wrong_domain)
                .consensus_commitment()
                .unwrap()
        );

        let burn_transition = burn(&state, 7, &[8], 9, 10, 100);
        assert_projection_roundtrip(&burn_transition);
        let burn_commitment = burn_transition.consensus_commitment().unwrap();
        assert_eq!(
            burn_transition
                .commitment_projection()
                .consensus_commitment()
                .unwrap(),
            burn_commitment
        );
        let mut substituted = match burn_transition {
            VerifiedTransition::Burn(value) => value,
            _ => unreachable!(),
        };
        substituted.record.recipient[0] ^= 1;
        substituted.record.obligation_commitment =
            substituted.record.expected_obligation_commitment(DOMAIN);
        assert_ne!(
            burn_commitment,
            VerifiedTransition::Burn(substituted)
                .consensus_commitment()
                .unwrap()
        );
        let mut substituted_memo = match burn(&state, 7, &[8], 9, 10, 100) {
            VerifiedTransition::Burn(value) => value,
            _ => unreachable!(),
        };
        substituted_memo.memo_commitment[31] ^= 1;
        assert_ne!(
            burn_commitment,
            VerifiedTransition::Burn(substituted_memo)
                .consensus_commitment()
                .unwrap()
        );
        let checkpoint = checkpoint(eth(101));
        assert_projection_roundtrip(&checkpoint);
        assert_eq!(
            checkpoint
                .commitment_projection()
                .consensus_commitment()
                .unwrap(),
            checkpoint.consensus_commitment().unwrap()
        );
        assert_ne!(original, transfer_commitment);
    }

    #[test]
    fn ordered_batch_is_atomic_committed_and_exactly_reversible() {
        let mut state = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        let genesis = state.state_root();
        let issuance = issue(1, 2, 1_000, 100);
        let mut post_issuance = state.clone();
        post_issuance.apply(context(), &issuance).unwrap();
        let transitions = vec![
            issuance,
            VerifiedTransition::Transfer(VerifiedTransfer {
                domain: DOMAIN,
                anchor: post_issuance.note_anchor(),
                nullifiers: vec![[3; 32]],
                // Note order is meaningful and need not be lexicographically sorted.
                output_notes: vec![[9; 32], [8; 32]],
                memo_commitment: [0x0d; 32],
            }),
        ];
        let (receipt, undo) = state.apply_batch(context(), &transitions).unwrap();
        assert_eq!(
            transitions[0].consensus_commitment().unwrap().to_string(),
            "c5f9863d4306b495eb4e1851f056c5fe8dea36c941dba08c542571d80b5ad521"
        );
        assert_eq!(
            transitions[1].consensus_commitment().unwrap().to_string(),
            "7d40d28d60ef60903328a96d721e73d1ec64ebb28664ac17b1260d8ed6c857e5"
        );
        assert_eq!(
            receipt.transitions_root.to_string(),
            "5d72070c0feb9822ecb852c526e868e4a7f81fcbf1d15bbc218546f607de2014"
        );
        assert_eq!(
            receipt.header_commitment.to_string(),
            "bd6654824ed54f492a4e6dab4f830a1273fea6389ea413c9877f1ee58d7c4558"
        );
        assert_eq!(receipt.version, TRANSITION_BATCH_VERSION);
        assert_eq!(receipt.transition_count, 2);
        assert_eq!(receipt.block_timestamp, BLOCK_TIMESTAMP);
        assert_eq!(receipt.previous_state_root, genesis);
        assert_eq!(receipt.new_state_root, state.state_root());
        assert_ne!(receipt.transitions_root, Hash256::ZERO);
        assert_ne!(receipt.header_commitment, Hash256::ZERO);
        assert_eq!(undo.transitions_root(), receipt.transitions_root);

        let encoded = undo.to_bytes().unwrap();
        for end in 0..encoded.len() {
            assert!(
                BatchUndo::from_bytes(&encoded[..end]).is_err(),
                "prefix {end}"
            );
        }
        let decoded = BatchUndo::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.before_root(), genesis);
        assert_eq!(decoded.after_root(), state.state_root());
        assert_eq!(decoded.transition_count(), 2);
        assert_eq!(
            decoded.transition_projections(),
            transitions
                .iter()
                .map(VerifiedTransition::commitment_projection)
                .collect::<Vec<_>>()
        );
        assert_eq!(decoded.block_timestamp(), BLOCK_TIMESTAMP);
        assert_eq!(
            decoded.header_commitment(DOMAIN).unwrap(),
            receipt.header_commitment
        );
        assert_eq!(
            state.revert_batch(&decoded, Hash256::from_bytes([0xaa; 32])),
            Err(UsdomStateError::UndoMismatch)
        );
        let mut wrong_timestamp = decoded.clone();
        wrong_timestamp.block_timestamp += 1;
        assert_eq!(
            state.revert_batch(&wrong_timestamp, receipt.header_commitment),
            Err(UsdomStateError::UndoMismatch)
        );
        assert_eq!(state.state_root(), receipt.new_state_root);
        let mut substituted_projection = decoded.clone();
        match &mut substituted_projection.projections[1] {
            TransitionCommitmentProjection::Transfer {
                memo_commitment, ..
            } => memo_commitment[31] ^= 1,
            _ => unreachable!(),
        }
        assert_eq!(
            substituted_projection.header_commitment(DOMAIN),
            Err(UsdomStateError::MalformedUndo)
        );
        assert_eq!(
            substituted_projection.to_bytes(),
            Err(UsdomStateError::MalformedUndo)
        );
        state
            .revert_batch(&decoded, receipt.header_commitment)
            .unwrap();
        assert_eq!(state.state_root(), genesis);

        let mut corrupted = encoded;
        corrupted[0] ^= 1;
        assert_eq!(
            BatchUndo::from_bytes(&corrupted).unwrap_err(),
            UsdomStateError::MalformedUndo
        );
        let mut trailing = undo.to_bytes().unwrap();
        trailing.push(0);
        assert_eq!(
            BatchUndo::from_bytes(&trailing).unwrap_err(),
            UsdomStateError::MalformedUndo
        );
    }

    #[test]
    fn batch_order_empty_envelope_failure_and_limit_are_deterministic() {
        let first = issue(1, 2, 100, 100);
        let second = issue(3, 4, 200, 101);
        let mut forward = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        let (forward_receipt, _) = forward
            .apply_batch(context(), &[first.clone(), second.clone()])
            .unwrap();
        let mut reverse = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        let (reverse_receipt, _) = reverse
            .apply_batch(context(), &[second, first.clone()])
            .unwrap();
        assert_ne!(
            forward_receipt.transitions_root,
            reverse_receipt.transitions_root
        );
        assert_ne!(
            forward_receipt.header_commitment,
            reverse_receipt.header_commitment
        );

        let mut empty = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        let root = empty.state_root();
        assert_eq!(empty.total_issued(), 0);
        let (empty_receipt, empty_undo) = empty.apply_batch(context(), &[]).unwrap();
        assert_eq!(empty_receipt.transition_count, 0);
        assert_eq!(empty_receipt.previous_state_root, root);
        assert_eq!(empty_receipt.new_state_root, root);
        assert_eq!(empty.total_issued(), 0);
        let decoded = BatchUndo::from_bytes(&empty_undo.to_bytes().unwrap()).unwrap();
        empty
            .revert_batch(&decoded, empty_receipt.header_commitment)
            .unwrap();
        assert_eq!(empty.state_root(), root);

        let mut atomic = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        let duplicate_note = issue(2, 2, 100, 101);
        assert_eq!(
            atomic
                .apply_batch(context(), &[first.clone(), duplicate_note])
                .unwrap_err(),
            UsdomStateError::DuplicateNote
        );
        assert_eq!(atomic.state_root(), root);
        assert!(!atomic.has_consumed_deposit(&[1; 32]));

        let oversized = vec![first; MAX_TRANSITIONS_PER_BATCH + 1];
        assert_eq!(
            atomic.apply_batch(context(), &oversized).unwrap_err(),
            UsdomStateError::BatchTooLarge
        );
        assert_eq!(atomic.state_root(), root);
    }

    #[test]
    fn burn_deadline_policy_is_exact_overflow_safe_and_committed() {
        let mut state = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        state.apply(context(), &issue(1, 2, 1_000, 100)).unwrap();
        let stable = state.state_root();
        let policy = bridge(DOMAIN).burn_timing;
        let earliest = BLOCK_TIMESTAMP
            + policy.withdrawal_delay_secs
            + policy.min_execution_window_secs
            + policy.relay_safety_margin_secs;
        let latest = state.ethereum_anchor().unwrap().execution_block_timestamp
            + policy.max_certificate_lifetime_secs;

        let with_deadline = |current: &NativeUsdomState, deadline| {
            let mut value = match burn(current, 3, &[], 4, 5, 10) {
                VerifiedTransition::Burn(value) => value,
                _ => unreachable!(),
            };
            value.record.valid_until = deadline;
            value.record.burn_id = derive_private_burn_id(
                bridge(DOMAIN),
                &value.nullifiers,
                value.record.recipient,
                value.record.amount,
                deadline,
            )
            .unwrap();
            value.record.obligation_commitment =
                value.record.expected_obligation_commitment(DOMAIN);
            VerifiedTransition::Burn(value)
        };
        assert_eq!(
            state
                .apply(context(), &with_deadline(&state, earliest - 1))
                .unwrap_err(),
            UsdomStateError::InvalidBurnWindow
        );
        assert_eq!(
            state
                .apply(context(), &with_deadline(&state, latest + 1))
                .unwrap_err(),
            UsdomStateError::InvalidBurnWindow
        );
        assert_eq!(state.state_root(), stable);
        let (_, earliest_undo) = state
            .apply(context(), &with_deadline(&state, earliest))
            .unwrap();
        state.revert(&earliest_undo).unwrap();
        let (_, latest_undo) = state
            .apply(context(), &with_deadline(&state, latest))
            .unwrap();
        state.revert(&latest_undo).unwrap();
        assert_eq!(state.state_root(), stable);

        let anchor_timestamp = state.ethereum_anchor().unwrap().execution_block_timestamp;
        let freshness_boundary = BlockContext {
            timestamp: anchor_timestamp
                + policy.max_ethereum_anchor_age_secs
                + policy.max_dom_clock_lead_secs,
        };
        let boundary_deadline = freshness_boundary.timestamp
            + policy.withdrawal_delay_secs
            + policy.min_execution_window_secs
            + policy.relay_safety_margin_secs;
        let (_, boundary_undo) = state
            .apply(
                freshness_boundary,
                &with_deadline(&state, boundary_deadline),
            )
            .unwrap();
        state.revert(&boundary_undo).unwrap();
        assert_eq!(state.state_root(), stable);
        assert_eq!(
            state
                .apply(
                    BlockContext {
                        timestamp: freshness_boundary.timestamp + 1,
                    },
                    &with_deadline(&state, latest),
                )
                .unwrap_err(),
            UsdomStateError::InvalidBurnWindow
        );
        assert_eq!(state.state_root(), stable);

        assert_eq!(
            state
                .apply(
                    BlockContext {
                        timestamp: u64::MAX,
                    },
                    &with_deadline(&state, latest),
                )
                .unwrap_err(),
            UsdomStateError::InvalidBurnWindow
        );
        let empty = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        let empty_root = empty.state_root();
        let mut empty = empty;
        assert_eq!(
            empty
                .apply(BlockContext { timestamp: 0 }, &issue(8, 9, 1, 101))
                .unwrap_err(),
            UsdomStateError::InvalidBlockContext
        );
        assert_eq!(empty.state_root(), empty_root);

        let mut different_policy = bridge(DOMAIN);
        different_policy.burn_timing.relay_safety_margin_secs += 1;
        assert_ne!(
            NativeUsdomState::new(different_policy)
                .unwrap()
                .state_root(),
            NativeUsdomState::new(bridge(DOMAIN)).unwrap().state_root()
        );
        let mut impossible = bridge(DOMAIN);
        impossible.burn_timing.max_certificate_lifetime_secs = 1;
        assert_eq!(
            NativeUsdomState::new(impossible).unwrap_err(),
            UsdomStateError::InvalidBurnWindow
        );
        let mut short_clock_margin = bridge(DOMAIN);
        short_clock_margin.burn_timing.max_dom_clock_lead_secs = MAX_FUTURE_BLOCK_TIME - 1;
        assert_eq!(
            NativeUsdomState::new(short_clock_margin).unwrap_err(),
            UsdomStateError::InvalidBurnWindow
        );
        let mut insufficient_relay_margin = bridge(DOMAIN);
        insufficient_relay_margin
            .burn_timing
            .relay_safety_margin_secs = insufficient_relay_margin
            .burn_timing
            .max_ethereum_anchor_age_secs
            - 1;
        assert_eq!(
            NativeUsdomState::new(insufficient_relay_margin).unwrap_err(),
            UsdomStateError::InvalidBurnWindow
        );
        let mut mismatched_reserve_constant = bridge(DOMAIN);
        mismatched_reserve_constant
            .burn_timing
            .min_execution_window_secs += 1;
        assert_eq!(
            NativeUsdomState::new(mismatched_reserve_constant).unwrap_err(),
            UsdomStateError::InvalidBurnWindow
        );
    }

    #[test]
    fn authenticated_checkpoint_advances_without_issuance_and_never_regresses() {
        let mut state = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        let empty_root = state.state_root();
        let first = eth(100);
        let (receipt, undo) = state.apply(context(), &checkpoint(first)).unwrap();
        assert_eq!(receipt.kind, TransitionKind::EthereumCheckpoint);
        assert_eq!(state.ethereum_anchor(), Some(first));
        assert_eq!(state.total_issued(), 0);
        assert_eq!(state.note_anchor().leaf_count, 0);
        assert_ne!(state.state_root(), empty_root);

        let persisted = state.export_entries();
        let restored = NativeUsdomState::restore_entries(bridge(DOMAIN), &persisted).unwrap();
        assert_eq!(restored.state_root(), state.state_root());
        assert_eq!(restored.ethereum_anchor(), Some(first));

        let stable = state.state_root();
        assert_eq!(
            state.apply(context(), &checkpoint(first)).unwrap_err(),
            UsdomStateError::EthereumAnchorNotAdvanced
        );
        assert_eq!(state.state_root(), stable);

        let older = eth(99);
        assert_eq!(
            state.apply(context(), &checkpoint(older)).unwrap_err(),
            UsdomStateError::EthereumAnchorNotAdvanced
        );
        let mut inconsistent = eth(101);
        inconsistent.execution_block_timestamp = first.execution_block_timestamp - 1;
        assert_eq!(
            state
                .apply(context(), &checkpoint(inconsistent))
                .unwrap_err(),
            UsdomStateError::EthereumAnchorConflict
        );
        assert_eq!(state.state_root(), stable);

        let newer = eth(200);
        let (_, newer_undo) = state.apply(context(), &checkpoint(newer)).unwrap();
        assert_eq!(state.ethereum_anchor(), Some(newer));
        // A later-issued historical deposit remains valid but cannot lower the
        // independently authenticated finality/time high-water mark.
        state.apply(context(), &issue(1, 2, 100, 100)).unwrap();
        assert_eq!(state.ethereum_anchor(), Some(newer));
        assert_eq!(
            NativeUsdomState::restore_entries(bridge(DOMAIN), &state.export_entries())
                .unwrap()
                .ethereum_anchor(),
            Some(newer)
        );

        let mut checkpoint_only = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        checkpoint_only
            .apply(context(), &checkpoint(first))
            .unwrap();
        checkpoint_only.revert(&undo).unwrap();
        assert_eq!(checkpoint_only.state_root(), empty_root);
        assert_eq!(checkpoint_only.ethereum_anchor(), None);

        // Undo is tied to the exact immediate state and cannot skip the
        // issuance that followed this checkpoint.
        assert_eq!(
            state.revert(&newer_undo).unwrap_err(),
            UsdomStateError::UndoMismatch
        );
    }

    #[cfg(feature = "ethereum-finality")]
    #[test]
    fn opaque_finality_checkpoint_converts_only_under_exact_bridge_identity() {
        use usdom_ethereum_finality_experiment::checkpoints::{
            unsafe_test_only_verified_checkpoint,
            unsafe_test_only_verified_checkpoint_with_finality, CHECKPOINT_RECORD_LENGTH,
        };

        let bridge = bridge(DOMAIN);
        let anchor = eth(100);
        let mut record = [0u8; CHECKPOINT_RECORD_LENGTH];
        record[0] = 2;
        record[77..85].copy_from_slice(&31337u64.to_be_bytes());
        record[85..93].copy_from_slice(&anchor.execution_block_number.to_be_bytes());
        record[93..125].copy_from_slice(&anchor.execution_block_hash);
        record[125..157].copy_from_slice(&[0x31; 32]);
        record[157..189].copy_from_slice(&[0x32; 32]);
        record[189..197].copy_from_slice(&anchor.beacon_slot.to_be_bytes());
        record[197..229].copy_from_slice(&anchor.beacon_root);
        record[229..261].copy_from_slice(&anchor.genesis_validators_root);
        record[353..385].copy_from_slice(&DOMAIN);
        let event_checkpoint = unsafe_test_only_verified_checkpoint(
            record,
            anchor.execution_block_timestamp,
            bridge.ethereum_checkpoint_policy_hash.into(),
        );
        let finality_anchor = eth(200);
        let mut finality_head = event_checkpoint.finalized_execution().clone();
        finality_head.block_number = finality_anchor.execution_block_number;
        finality_head.block_hash = finality_anchor.execution_block_hash.into();
        finality_head.timestamp = finality_anchor.execution_block_timestamp;
        finality_head.beacon_slot = finality_anchor.beacon_slot;
        finality_head.beacon_root = finality_anchor.beacon_root.into();
        let verified = unsafe_test_only_verified_checkpoint_with_finality(
            record,
            finality_head,
            bridge.ethereum_checkpoint_policy_hash.into(),
        );
        let transition = ethereum_checkpoint_transition(bridge, &verified).unwrap();
        assert_eq!(
            transition.consensus_commitment(),
            checkpoint(finality_anchor).consensus_commitment()
        );
        let mut state = NativeUsdomState::new(bridge).unwrap();
        state.apply(context(), &transition).unwrap();
        assert_eq!(state.ethereum_anchor(), Some(finality_anchor));

        let mut wrong_domain = bridge;
        wrong_domain.dom_domain[0] ^= 1;
        assert_eq!(
            ethereum_checkpoint_transition(wrong_domain, &verified).unwrap_err(),
            UsdomStateError::BridgeIdentityMismatch
        );
        let mut wrong_chain = bridge;
        wrong_chain.ethereum_chain_id[31] ^= 1;
        assert_eq!(
            ethereum_checkpoint_transition(wrong_chain, &verified).unwrap_err(),
            UsdomStateError::BridgeIdentityMismatch
        );
        let mut wrong_policy = bridge;
        wrong_policy.ethereum_checkpoint_policy_hash[0] ^= 1;
        assert_eq!(
            ethereum_checkpoint_transition(wrong_policy, &verified).unwrap_err(),
            UsdomStateError::BridgeIdentityMismatch
        );
    }

    #[cfg(feature = "ethereum-finality")]
    #[test]
    fn finalized_deposit_derives_exact_issuerless_note_and_binds_policy() {
        use usdom_ethereum_finality_experiment::deposits::{
            unsafe_test_only_verified_deposit, UnsafeTestDeposit,
        };

        let bridge = bridge(DOMAIN);
        let fixture = |receiver: [u8; 32]| UnsafeTestDeposit {
            genesis_validators_root: bridge.ethereum_genesis_validators_root,
            block_hash: [0x51; 32],
            block_number: 20_000_000,
            transaction_index: 7,
            receipt_log_index: 2,
            reserve: bridge.reserve,
            runtime_code_hash: [0x52; 32],
            bridge_domain: DOMAIN,
            deposit_id: [0x53; 32],
            funder: [0x54; 20],
            amount: 1_000_000,
            receiving_commitment: receiver,
            finality_beacon_slot: 16_000_010,
            finality_beacon_root: [0x55; 32],
            finality_execution_block_number: 20_000_010,
            finality_execution_block_hash: [0x56; 32],
            finality_execution_timestamp: 1_700_000_000,
            trust_policy_hash: bridge.ethereum_deposit_policy_hash,
        };
        let verified = unsafe_test_only_verified_deposit(fixture([0x17; 32]));
        let first = ethereum_deposit_transition(bridge, &verified).unwrap();
        let second = ethereum_deposit_transition(bridge, &verified).unwrap();
        assert_eq!(first.consensus_commitment(), second.consensus_commitment());

        let changed = unsafe_test_only_verified_deposit(fixture([0x18; 32]));
        assert_ne!(
            first.consensus_commitment(),
            ethereum_deposit_transition(bridge, &changed)
                .unwrap()
                .consensus_commitment()
        );

        let mut state = NativeUsdomState::new(bridge).unwrap();
        state.apply(context(), &first).unwrap();
        let issuance = state.issuance(&[0x53; 32]).unwrap();
        assert_eq!(issuance.amount, 1_000_000);
        assert_eq!(state.total_issued(), 1_000_000);

        let mut wrong_policy = bridge;
        wrong_policy.ethereum_deposit_policy_hash[0] ^= 1;
        assert_eq!(
            ethereum_deposit_transition(wrong_policy, &verified).unwrap_err(),
            UsdomStateError::BridgeIdentityMismatch
        );
    }

    #[test]
    fn groth16_burn_adapter_binds_key_anchor_effect_memo_and_state_transition() {
        use ark_bn254::Bn254;
        use ark_groth16::Groth16;
        use ark_serialize::CanonicalSerialize;
        use dom_usdom_privacy::{
            circuit::{InputWitness, OutputWitness, SpendCircuit},
            empty_subtree_roots, owner_commitment, NoteOpening, NOTE_TREE_DEPTH,
        };
        use rand::{rngs::StdRng, SeedableRng};

        // Test-only toxic waste. No generated key leaves this test process.
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_5354);
        let parameters = Groth16::<Bn254>::generate_random_parameters_with_reduction(
            SpendCircuit::default(),
            &mut rng,
        )
        .unwrap();
        let mut key_bytes = Vec::new();
        parameters.vk.serialize_compressed(&mut key_bytes).unwrap();
        let verifier = SpendVerifier::from_bytes(&key_bytes).unwrap();
        let mut bridge = bridge(DOMAIN);
        bridge.privacy_verifier_config_hash = *verifier.config_hash().as_bytes();
        let chain = privacy_chain_scalar(DOMAIN, bridge.privacy_policy_hash);
        let owner_secret = PrivacyScalar::from_bytes({
            let mut bytes = [0u8; 32];
            bytes[31] = 7;
            bytes
        })
        .unwrap();
        let input = NoteOpening {
            chain,
            origin: dom_usdom_privacy::NOTE_ORIGIN_PRIVATE,
            value: 10,
            owner: owner_commitment(chain, owner_secret).unwrap(),
            rho: PrivacyScalar::from_bytes({
                let mut bytes = [0u8; 32];
                bytes[31] = 8;
                bytes
            })
            .unwrap(),
        };
        let input_commitment = input.commitment().unwrap().to_bytes();
        let mut state = NativeUsdomState::new(bridge).unwrap();
        state
            .apply(
                context(),
                &VerifiedTransition::Issue(VerifiedIssuance {
                    domain: DOMAIN,
                    deposit_id: [0x21; 32],
                    note_commitment: input_commitment,
                    amount: 10,
                    ethereum_anchor: eth(100),
                }),
            )
            .unwrap();
        let anchor = state.note_anchor();
        let output = OutputWitness {
            enabled: true,
            value: 7,
            owner: PrivacyScalar::from_bytes({
                let mut bytes = [0u8; 32];
                bytes[31] = 9;
                bytes
            })
            .unwrap(),
            rho: PrivacyScalar::from_bytes({
                let mut bytes = [0u8; 32];
                bytes[31] = 10;
                bytes
            })
            .unwrap(),
        };
        let output_commitment = NoteOpening {
            chain,
            origin: dom_usdom_privacy::NOTE_ORIGIN_PRIVATE,
            value: output.value,
            owner: output.owner,
            rho: output.rho,
        }
        .commitment()
        .unwrap()
        .to_bytes();
        let nullifier = input.nullifier(owner_secret).unwrap().to_bytes();
        let mut record = BurnRecord {
            burn_id: derive_private_burn_id(bridge, &[nullifier], [0x24; 20], 3, 1_800_600_000)
                .unwrap(),
            request_id: [0x23; 32],
            amount: 3,
            recipient: [0x24; 20],
            ethereum_chain_id: bridge.ethereum_chain_id,
            reserve: bridge.reserve,
            valid_until: 1_800_600_000,
            obligation_commitment: [0; 32],
        };
        record.obligation_commitment = record.expected_obligation_commitment(DOMAIN);
        let memo = b"encrypted output memo";
        let mut effect_bytes = Vec::new();
        encode_burn_record(&mut effect_bytes, record);
        let statement = private_spend_statement(
            bridge,
            anchor,
            &[nullifier],
            &[output_commitment],
            record.amount,
            effect_scalar(&effect_bytes).unwrap(),
            memo,
        )
        .unwrap();
        let circuit = SpendCircuit {
            statement,
            inputs: [
                InputWitness {
                    enabled: true,
                    origin: input.origin,
                    value: input.value,
                    owner_secret,
                    rho: input.rho,
                    leaf_index: 0,
                    siblings: empty_subtree_roots()[..NOTE_TREE_DEPTH].try_into().unwrap(),
                },
                InputWitness::default(),
            ],
            outputs: [output, OutputWitness::default()],
        };
        let proof =
            Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &parameters, &mut rng)
                .unwrap();
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        let payload = encode_private_burn_payload(
            anchor,
            &[nullifier],
            &[output_commitment],
            record,
            memo,
            &proof_bytes,
        )
        .unwrap();
        let transition = verify_private_burn_payload(bridge, &verifier, &payload).unwrap();
        state.apply(context(), &transition).unwrap();
        assert_eq!(state.total_burned(), 3);
        assert!(state.has_nullifier(&nullifier));
        for end in [0, 7, 8, 47, payload.len() - 1] {
            assert_eq!(
                verify_private_burn_payload(bridge, &verifier, &payload[..end]),
                Err(UsdomStateError::InvalidPrivacyProof)
            );
        }
        let mut trailing = payload.clone();
        trailing.push(0);
        assert_eq!(
            verify_private_burn_payload(bridge, &verifier, &trailing),
            Err(UsdomStateError::InvalidPrivacyProof)
        );
        assert_eq!(
            verify_private_burn_payload(
                bridge,
                &verifier,
                &vec![0; MAX_PRIVATE_BURN_PAYLOAD_BYTES + 1],
            ),
            Err(UsdomStateError::InvalidPrivacyProof)
        );
        assert_eq!(
            verify_private_transfer_payload(
                bridge,
                &verifier,
                &vec![0; MAX_PRIVATE_TRANSFER_PAYLOAD_BYTES + 1],
            ),
            Err(UsdomStateError::InvalidPrivacyProof)
        );

        let mut substituted = record;
        substituted.recipient[0] ^= 1;
        substituted.obligation_commitment = substituted.expected_obligation_commitment(DOMAIN);
        assert_eq!(
            private_burn_transition(
                bridge,
                &verifier,
                PrivateBurnProofInput {
                    anchor,
                    nullifiers: &[nullifier],
                    change_notes: &[output_commitment],
                    record: substituted,
                    encrypted_memo: memo,
                    proof: &proof_bytes,
                },
            ),
            Err(UsdomStateError::BurnIntentMismatch)
        );
        substituted.burn_id = derive_private_burn_id(
            bridge,
            &[nullifier],
            substituted.recipient,
            substituted.amount,
            substituted.valid_until,
        )
        .unwrap();
        substituted.obligation_commitment = substituted.expected_obligation_commitment(DOMAIN);
        assert_eq!(
            private_burn_transition(
                bridge,
                &verifier,
                PrivateBurnProofInput {
                    anchor,
                    nullifiers: &[nullifier],
                    change_notes: &[output_commitment],
                    record: substituted,
                    encrypted_memo: memo,
                    proof: &proof_bytes,
                },
            ),
            Err(UsdomStateError::InvalidPrivacyProof)
        );
        let mut wrong_key = bridge;
        wrong_key.privacy_verifier_config_hash[0] ^= 1;
        assert_eq!(
            private_burn_transition(
                wrong_key,
                &verifier,
                PrivateBurnProofInput {
                    anchor,
                    nullifiers: &[nullifier],
                    change_notes: &[output_commitment],
                    record,
                    encrypted_memo: memo,
                    proof: &proof_bytes,
                },
            ),
            Err(UsdomStateError::BridgeIdentityMismatch)
        );
    }

    #[test]
    fn domain_anchor_shape_and_ethereum_conflicts_fail_closed() {
        let mut state = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        state.apply(context(), &issue(1, 2, 100, 100)).unwrap();
        let stable = state.state_root();
        let mut wrong_domain = match transfer(&state, &[3], &[4]) {
            VerifiedTransition::Transfer(value) => value,
            _ => unreachable!(),
        };
        wrong_domain.domain = [0x99; 32];
        assert_eq!(
            state
                .apply(context(), &VerifiedTransition::Transfer(wrong_domain))
                .unwrap_err(),
            UsdomStateError::DomainMismatch
        );
        let mut stale = match transfer(&state, &[3], &[4]) {
            VerifiedTransition::Transfer(value) => value,
            _ => unreachable!(),
        };
        stale.anchor.root = Hash256::from_bytes([0xaa; 32]);
        assert_eq!(
            state
                .apply(context(), &VerifiedTransition::Transfer(stale))
                .unwrap_err(),
            UsdomStateError::UnknownNoteAnchor
        );
        assert_eq!(state.state_root(), stable);

        let conflict = VerifiedTransition::Issue(VerifiedIssuance {
            domain: DOMAIN,
            deposit_id: [9; 32],
            note_commitment: [9; 32],
            amount: 1,
            ethereum_anchor: EthereumAnchor {
                execution_block_hash: [0xee; 32],
                ..eth(100)
            },
        });
        assert_eq!(
            state.apply(context(), &conflict).unwrap_err(),
            UsdomStateError::EthereumAnchorConflict
        );
        assert_eq!(state.state_root(), stable);

        let timestamp_conflict = VerifiedTransition::Issue(VerifiedIssuance {
            domain: DOMAIN,
            deposit_id: [14; 32],
            note_commitment: [14; 32],
            amount: 1,
            ethereum_anchor: EthereumAnchor {
                execution_block_timestamp: eth(100).execution_block_timestamp + 1,
                ..eth(100)
            },
        });
        assert_eq!(
            state.apply(context(), &timestamp_conflict).unwrap_err(),
            UsdomStateError::EthereumAnchorConflict
        );
        assert_eq!(state.state_root(), stable);

        // Deposits may arrive out of event-block order. Their capabilities use
        // the exact finalized execution head, so several historical deposits
        // authenticated by one checkpoint share one identical anchor.
        let historical = VerifiedTransition::Issue(VerifiedIssuance {
            domain: DOMAIN,
            deposit_id: [10; 32],
            note_commitment: [10; 32],
            amount: 1,
            ethereum_anchor: eth(100),
        });
        state.apply(context(), &historical).unwrap();
        let after_historical = state.state_root();
        assert!(state.has_consumed_deposit(&[10; 32]));
        assert_eq!(state.ethereum_anchor(), Some(eth(100)));

        let shared_checkpoint = VerifiedTransition::Issue(VerifiedIssuance {
            domain: DOMAIN,
            deposit_id: [12; 32],
            note_commitment: [12; 32],
            amount: 1,
            ethereum_anchor: eth(100),
        });
        state.apply(context(), &shared_checkpoint).unwrap();
        let after_shared_checkpoint = state.state_root();
        assert_eq!(state.ethereum_anchor(), Some(eth(100)));

        let mut impossible_same_slot = eth(101);
        impossible_same_slot.beacon_slot = eth(100).beacon_slot;
        impossible_same_slot.beacon_root = eth(100).beacon_root;
        let same_slot_different_execution = VerifiedTransition::Issue(VerifiedIssuance {
            domain: DOMAIN,
            deposit_id: [15; 32],
            note_commitment: [15; 32],
            amount: 1,
            ethereum_anchor: impossible_same_slot,
        });
        assert_eq!(
            state
                .apply(context(), &same_slot_different_execution)
                .unwrap_err(),
            UsdomStateError::EthereumAnchorConflict
        );
        assert_eq!(state.state_root(), after_shared_checkpoint);

        state.apply(context(), &issue(16, 16, 1, 101)).unwrap();
        let after_later_finality = state.state_root();
        assert_eq!(state.ethereum_anchor(), Some(eth(101)));

        let conflicting_checkpoint_root = VerifiedTransition::Issue(VerifiedIssuance {
            domain: DOMAIN,
            deposit_id: [13; 32],
            note_commitment: [13; 32],
            amount: 1,
            ethereum_anchor: EthereumAnchor {
                beacon_root: [0x97; 32],
                ..state.ethereum_anchor().unwrap()
            },
        });
        assert_eq!(
            state
                .apply(context(), &conflicting_checkpoint_root)
                .unwrap_err(),
            UsdomStateError::EthereumAnchorConflict
        );
        assert_eq!(state.state_root(), after_later_finality);

        let foreign_consensus_chain = VerifiedTransition::Issue(VerifiedIssuance {
            domain: DOMAIN,
            deposit_id: [11; 32],
            note_commitment: [11; 32],
            amount: 1,
            ethereum_anchor: EthereumAnchor {
                genesis_validators_root: [0x43; 32],
                ..eth(101)
            },
        });
        assert_eq!(
            state
                .apply(context(), &foreign_consensus_chain)
                .unwrap_err(),
            UsdomStateError::BridgeIdentityMismatch
        );
        assert_eq!(state.state_root(), after_later_finality);
        assert!(!state.has_consumed_deposit(&[11; 32]));
        assert_ne!(after_historical, stable);
        assert_eq!(
            NativeUsdomState::restore_entries(bridge(DOMAIN), &state.export_entries())
                .unwrap()
                .state_root(),
            state.state_root()
        );
    }

    #[test]
    fn roots_are_deterministic_and_sensitive_to_ordered_history() {
        let mut a = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        let mut b = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        for transition in [issue(1, 2, 10, 100), issue(3, 4, 20, 101)] {
            a.apply(context(), &transition).unwrap();
            b.apply(context(), &transition).unwrap();
        }
        assert_eq!(a.state_root(), b.state_root());
        assert_eq!(a.note_anchor(), b.note_anchor());
        assert_ne!(
            a.state_root(),
            NativeUsdomState::new(bridge([0x12; 32]))
                .unwrap()
                .state_root()
        );
        let mut other_chain = bridge(DOMAIN);
        other_chain.ethereum_chain_id[31] ^= 1;
        assert_ne!(
            a.state_root(),
            NativeUsdomState::new(other_chain).unwrap().state_root()
        );
        let mut other_reserve = bridge(DOMAIN);
        other_reserve.reserve[0] ^= 1;
        assert_ne!(
            a.state_root(),
            NativeUsdomState::new(other_reserve).unwrap().state_root()
        );
        let mut other_checkpoint_policy = bridge(DOMAIN);
        other_checkpoint_policy.ethereum_checkpoint_policy_hash[0] ^= 1;
        assert_ne!(
            a.state_root(),
            NativeUsdomState::new(other_checkpoint_policy)
                .unwrap()
                .state_root()
        );
        let mut other_genesis = bridge(DOMAIN);
        other_genesis.ethereum_genesis_validators_root[0] ^= 1;
        assert_ne!(
            a.state_root(),
            NativeUsdomState::new(other_genesis).unwrap().state_root()
        );
        let mut zero_chain = bridge(DOMAIN);
        zero_chain.ethereum_chain_id = [0; 32];
        assert_eq!(
            NativeUsdomState::new(zero_chain).unwrap_err(),
            UsdomStateError::ZeroIdentity
        );
        let mut zero_genesis = bridge(DOMAIN);
        zero_genesis.ethereum_genesis_validators_root = [0; 32];
        assert_eq!(
            NativeUsdomState::new(zero_genesis).unwrap_err(),
            UsdomStateError::ZeroIdentity
        );
        let mut zero_checkpoint_policy = bridge(DOMAIN);
        zero_checkpoint_policy.ethereum_checkpoint_policy_hash = [0; 32];
        assert_eq!(
            NativeUsdomState::new(zero_checkpoint_policy).unwrap_err(),
            UsdomStateError::ZeroIdentity
        );
    }

    #[test]
    fn persisted_entries_roundtrip_and_any_uncommitted_change_fails_closed() {
        let mut state = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        state.apply(context(), &issue(1, 2, 1_000, 100)).unwrap();
        state
            .apply(context(), &transfer(&state, &[3], &[4, 5]))
            .unwrap();
        state
            .apply(context(), &burn(&state, 6, &[7], 8, 9, 250))
            .unwrap();
        let entries = state.export_entries();
        let restored = NativeUsdomState::restore_entries(bridge(DOMAIN), &entries).unwrap();
        assert_eq!(restored.state_root(), state.state_root());
        assert_eq!(restored.note_anchor(), state.note_anchor());
        assert_eq!(restored.total_issued(), 1_000);
        assert_eq!(restored.total_burned(), 250);
        assert_eq!(restored.bridge_identity(), bridge(DOMAIN));
        assert_eq!(restored.export_entries(), entries);

        let mut wrong_bridge = entries.clone();
        wrong_bridge
            .get_mut(b"usdom/v3/meta/bridge".as_slice())
            .unwrap()[51] ^= 1;
        assert_eq!(
            NativeUsdomState::restore_entries(bridge(DOMAIN), &wrong_bridge).unwrap_err(),
            UsdomStateError::BridgeIdentityMismatch
        );
        let mut wrong_timing = entries.clone();
        wrong_timing
            .get_mut(b"usdom/v3/meta/bridge".as_slice())
            .unwrap()[123] ^= 1;
        assert_eq!(
            NativeUsdomState::restore_entries(bridge(DOMAIN), &wrong_timing).unwrap_err(),
            UsdomStateError::BridgeIdentityMismatch
        );
        let mut wrong_checkpoint_policy = entries.clone();
        wrong_checkpoint_policy
            .get_mut(b"usdom/v3/meta/bridge".as_slice())
            .unwrap()[84] ^= 1;
        assert_eq!(
            NativeUsdomState::restore_entries(bridge(DOMAIN), &wrong_checkpoint_policy)
                .unwrap_err(),
            UsdomStateError::BridgeIdentityMismatch
        );

        let mut wrong_root = entries.clone();
        wrong_root
            .get_mut(b"usdom/v3/meta/root".as_slice())
            .unwrap()[0] ^= 1;
        assert_eq!(
            NativeUsdomState::restore_entries(bridge(DOMAIN), &wrong_root).unwrap_err(),
            UsdomStateError::PersistedStateRootMismatch
        );

        let mut wrong_total = entries.clone();
        wrong_total
            .get_mut(b"usdom/v3/meta/totals".as_slice())
            .unwrap()[15] ^= 1;
        assert_eq!(
            NativeUsdomState::restore_entries(bridge(DOMAIN), &wrong_total).unwrap_err(),
            UsdomStateError::MalformedPersistedState
        );

        let mut unknown = entries.clone();
        unknown.insert(b"usdom/v3/uncommitted".to_vec(), vec![1]);
        assert_eq!(
            NativeUsdomState::restore_entries(bridge(DOMAIN), &unknown).unwrap_err(),
            UsdomStateError::MalformedPersistedState
        );

        let mut missing_note = entries.clone();
        let note_key = missing_note
            .keys()
            .find(|key| key.starts_with(b"usdom/v3/note/"))
            .unwrap()
            .clone();
        missing_note.remove(&note_key);
        assert_eq!(
            NativeUsdomState::restore_entries(bridge(DOMAIN), &missing_note).unwrap_err(),
            UsdomStateError::MalformedPersistedState
        );
    }

    #[test]
    fn forward_and_reverse_storage_deltas_reproduce_exact_states() {
        let before = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        let mut after = before.clone();
        after.apply(context(), &issue(1, 2, 1_000, 100)).unwrap();

        let mut entries = before.export_entries();
        let forward = after.storage_delta_from(&before).unwrap();
        assert!(!forward.is_empty());
        for update in forward {
            match update.value {
                Some(value) => {
                    entries.insert(update.key, value);
                }
                None => {
                    entries.remove(&update.key);
                }
            }
        }
        assert_eq!(entries, after.export_entries());
        assert_eq!(
            NativeUsdomState::restore_entries(bridge(DOMAIN), &entries)
                .unwrap()
                .state_root(),
            after.state_root()
        );

        for update in before.storage_delta_from(&after).unwrap() {
            match update.value {
                Some(value) => {
                    entries.insert(update.key, value);
                }
                None => {
                    entries.remove(&update.key);
                }
            }
        }
        assert_eq!(entries, before.export_entries());
    }

    #[test]
    fn wrong_or_reused_undo_cannot_mutate_state() {
        let mut state = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        let (_, first) = state.apply(context(), &issue(1, 2, 10, 100)).unwrap();
        let (_, second) = state.apply(context(), &issue(3, 4, 20, 101)).unwrap();
        let current = state.state_root();
        assert_eq!(state.revert(&first), Err(UsdomStateError::UndoMismatch));
        assert_eq!(state.state_root(), current);
        state.revert(&second).unwrap();
        let after_second = state.state_root();
        assert_eq!(state.revert(&second), Err(UsdomStateError::UndoMismatch));
        assert_eq!(state.state_root(), after_second);
    }

    #[test]
    fn undo_codec_rejects_every_truncation_trailing_data_and_noncanonical_order() {
        let mut state = NativeUsdomState::new(bridge(DOMAIN)).unwrap();
        state.apply(context(), &issue(1, 2, 100, 100)).unwrap();
        let transition = transfer(&state, &[3, 4], &[5, 6]);
        let (_, undo) = state.apply(context(), &transition).unwrap();
        let bytes = undo.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_UNDO_BYTES);
        assert_eq!(
            StateUndo::from_bytes(&bytes).unwrap().to_bytes().unwrap(),
            bytes
        );
        for end in 0..bytes.len() {
            assert!(
                StateUndo::from_bytes(&bytes[..end]).is_err(),
                "prefix {end}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            StateUndo::from_bytes(&trailing).unwrap_err(),
            UsdomStateError::MalformedUndo
        );
        let mut wrong_magic = bytes.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            StateUndo::from_bytes(&wrong_magic).unwrap_err(),
            UsdomStateError::MalformedUndo
        );

        let mut noncanonical = undo.clone();
        noncanonical.inserted_notes.reverse();
        assert_eq!(
            noncanonical.to_bytes().unwrap_err(),
            UsdomStateError::MalformedUndo
        );
    }
}
