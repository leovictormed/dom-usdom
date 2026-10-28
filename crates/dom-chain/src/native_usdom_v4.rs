//! Isolated native-USDOM block-v4 composition boundary.
//!
//! This module decodes a canonical bounded proof envelope, accepts only opaque
//! transitions produced by real proof verifiers, recomputes their ordered state
//! transition on a clone, derives the sole admissible batch commitment, and
//! validates the block body under an explicitly selected activation schedule.
//! The node can propagate an explicitly supplied schedule through restore,
//! IBD and package ingress. Production activation still requires a separately
//! ratified schedule and release configuration.

use dom_consensus::{
    bind_usdom_batch_commitment, compute_block_pmmr_roots, validate_block_v4_scheduled, Block,
    UsdomV4Commitment, ValidationContext,
};
use dom_core::{
    DomError, Timestamp, BLOCK_VERSION_V4, MAX_BLOCK_SERIALIZED_SIZE, NETWORK_MAGIC_REGTEST,
    TAG_USDOM_BLOCK_PACKAGE_V4,
};
use dom_crypto::blake2b_256_tagged;
use dom_serialization::{DomDeserialize, DomSerialize, Reader};
use dom_store::{
    validate_consensus_state_updates, ConsensusStateUpdate, DomStore,
    MAX_CONSENSUS_STATE_VALUE_BYTES,
};
use dom_usdom_privacy::verifier::SpendVerifier;
use dom_usdom_privacy::{memo_scalar, privacy_policy_hash};
use dom_usdom_state::{
    apply_v2_transition_batch_with_receipt, ethereum_checkpoint_transition,
    ethereum_deposit_transition, ethereum_issuance_closure_transition,
    graceful_shutdown_transition, inspect_private_burn_outputs, inspect_private_burn_record,
    inspect_private_transfer_outputs, verify_private_burn_payload, verify_private_transfer_payload,
    BatchUndo, BlockContext, BridgeIdentity, BurnRecord, BurnStateWitness, BurnStateWitnessV2,
    NativeTransitionWitness, NativeUsdomState, StateCommitmentV2, TransitionBatchReceipt,
    TransitionCommitmentProjection, TransitionKind, VerifiedTransition, MAX_BATCH_UNDO_BYTES,
    MAX_BURN_STATE_WITNESS_BYTES, MAX_NATIVE_TRANSITION_WITNESS_BYTES,
    MAX_PRIVATE_BURN_PAYLOAD_BYTES, MAX_PRIVATE_TRANSFER_PAYLOAD_BYTES, MAX_TRANSITIONS_PER_BATCH,
};
use rayon::prelude::*;
use sha3::{Digest, Keccak256};
use std::collections::{BTreeSet, VecDeque};
use usdom_ethereum_finality_experiment::checkpoints::{
    checkpoint_trust_policy_hash, verify_checkpoint_witness, CheckpointTrustPolicy,
    StaticCheckpointTrustPolicy, MAX_CHECKPOINT_WITNESS_BYTES,
};
use usdom_ethereum_finality_experiment::closures::{
    verify_issuance_closure_witness, IssuanceClosureTrustPolicy, StaticIssuanceClosureTrustPolicy,
    MAX_ISSUANCE_CLOSURE_WITNESS_BYTES,
};
use usdom_ethereum_finality_experiment::deposits::{
    verify_deposit_witness, DepositTrustPolicy, StaticDepositTrustPolicy, MAX_DEPOSIT_WITNESS_BYTES,
};

const USDOM_V4_ENVELOPE_MAGIC: &[u8; 8] = b"USDOMV41";
const USDOM_V4_ENVELOPE_VERSION: u16 = 1;
const USDOM_V4_ENVELOPE_HEADER_BYTES: usize = 14;
const MAX_CHECKPOINTS_PER_ENVELOPE: usize = 1;
const MAX_ISSUANCES_PER_ENVELOPE: usize = 4;
const MAX_ISSUANCE_CLOSURES_PER_ENVELOPE: usize = 1;
const MAX_PRIVATE_SPENDS_PER_ENVELOPE: usize = 16;
const USDOM_V4_BLOCK_MAGIC: &[u8; 8] = b"USDOMBL4";
const USDOM_V4_BLOCK_FRAMING_VERSION: u16 = 1;
const USDOM_V4_BLOCK_HEADER_BYTES: usize = 18;
const ETHEREUM_MAINNET_GENESIS_TIME: u64 = 1_606_824_023;
const ETHEREUM_SECONDS_PER_SLOT: u64 = 12;
const USDOM_V4_PERSISTENCE_VERSION: u16 = 1;
const USDOM_V4_PACKAGE_META_BYTES: usize = 40;
const USDOM_V4_PACKAGE_META_PREFIX: &[u8] = b"usdom-v4/package/meta/";
const USDOM_V4_PACKAGE_CHUNK_PREFIX: &[u8] = b"usdom-v4/package/chunk/";
const USDOM_V4_UNDO_PREFIX: &[u8] = b"usdom-v4/undo/";
const USDOM_V4_TIP_KEY: &[u8] = b"usdom-v4/tip";
const USDOM_V4_TIP_BYTES: usize = 96;
const USDOM_V4_ACTIVATION_KEY: &[u8] = b"usdom-v4/activation";
const USDOM_V4_ACTIVATION_MAGIC: &[u8; 8] = b"UDACTV01";
const USDOM_V4_ACTIVATION_VERSION: u16 = 1;
const USDOM_V4_ACTIVATION_SCHEDULE_BYTES: usize = 86;
const USDOM_V4_ACTIVATION_RECORD_BYTES: usize = USDOM_V4_ACTIVATION_SCHEDULE_BYTES + 32;
const TAG_USDOM_V4_ACTIVATION_SCHEDULE: &str = "DOM:usdom-v4-activation-schedule:v1";
const TAG_USDOM_V4_ACTIVATION_RECORD: &str = "DOM:usdom-v4-activation-record:v1";
const USDOM_V2_ACTIVATION_MAGIC: &[u8; 8] = b"UDACTV02";
const USDOM_V2_ACTIVATION_VERSION: u16 = 2;
const USDOM_V2_STATE_VERSION: u16 = 2;
const USDOM_V2_ACTIVATION_KEY: &[u8] = b"usdom-v2/activation";
const USDOM_V2_TIP_KEY: &[u8] = b"usdom-v2/tip";
const USDOM_V2_TIP_BYTES: usize = 128;
const USDOM_V2_WITNESS_BUNDLE_MAGIC: &[u8; 8] = b"UDV2W001";
const USDOM_V2_WITNESS_BUNDLE_VERSION: u16 = 1;
const USDOM_V2_WITNESS_BUNDLE_HEADER_BYTES: usize = 14;
const TAG_USDOM_V2_WITNESS_BUNDLE: &str = "DOM:usdom-v2-witness-bundle:v1";
const USDOM_V2_BLOCK_SIDECAR_MAGIC: &[u8; 8] = b"UDV2SC01";
const USDOM_V2_BLOCK_SIDECAR_VERSION: u16 = 1;
const USDOM_V2_BLOCK_SIDECAR_HEADER_BYTES: usize = 18;
const USDOM_V2_PERSISTENCE_VERSION: u16 = 2;
const USDOM_V2_RUNTIME_TIP_MAGIC: &[u8; 8] = b"UDV2TIP1";
const USDOM_V2_BLOCK_RECORD_MAGIC: &[u8; 8] = b"UDV2BL01";
const USDOM_V2_BLOCK_RECORD_PREFIX: &[u8] = b"usdom-v2/block/";
const USDOM_V2_BURN_ARCHIVE_PREFIX: &[u8] = b"usdom-v2/burn/";
const USDOM_V2_BURN_ARCHIVE_MAGIC: &[u8; 8] = b"UDBURN01";
const USDOM_V2_BURN_ARCHIVE_BYTES: usize = 8 + 8 + 32 + 184;
const USDOM_V2_PRUNE_CURSOR_KEY: &[u8] = b"usdom-v2/prune-cursor/v1";
const USDOM_V2_PRUNE_CURSOR_MAGIC: &[u8; 8] = b"UDPRUN01";
const USDOM_V2_PRUNE_BATCH_BLOCKS: u64 = 64;
const USDOM_V2_WITNESS_META_PREFIX: &[u8] = b"usdom-v2/witness/meta/";
const USDOM_V2_WITNESS_CHUNK_PREFIX: &[u8] = b"usdom-v2/witness/chunk/";
const USDOM_V2_WITNESS_META_BYTES: usize = 40;
/// Exact byte length of one `UDACTV02` migration schedule.
pub const USDOM_V2_ACTIVATION_SCHEDULE_BYTES: usize = 154;
/// Maximum canonical witness bundle persisted for one candidate-v2 block.
/// Proof envelopes and witness openings therefore remain within the store's
/// aggregate 16-MiB atomic consensus-state batch limit.
pub const MAX_USDOM_V2_WITNESS_BUNDLE_BYTES: usize = 4 * 1024 * 1024;
const TAG_USDOM_V2_ACTIVATION_SCHEDULE: &str = "DOM:usdom-v2-activation-schedule:v1";
const USDOM_V4_SNAPSHOT_MAGIC: &[u8; 8] = b"UDSNAP01";
const USDOM_V4_SNAPSHOT_VERSION: u16 = 5;
const USDOM_V4_SNAPSHOT_HEADER_BYTES: usize = 291;
const USDOM_V4_SNAPSHOT_BLOCK_BYTES: usize = 140;
const TAG_USDOM_V4_SNAPSHOT_STATE: &str = "DOM:usdom-v4-snapshot-state:v1";
const TAG_USDOM_V4_SNAPSHOT_UNDO: &str = "DOM:usdom-v4-snapshot-undo:v1";
const TAG_USDOM_V4_SNAPSHOT_MANIFEST: &str = "DOM:usdom-v4-snapshot-manifest:v5";
const TAG_USDOM_V4_SNAPSHOT_CHECKPOINT: &str = "DOM:usdom-v4-snapshot-checkpoint:v1";
const USDOM_V4_BURN_PROVER_MAGIC: &[u8; 8] = b"UDBBLK02";
const USDOM_V4_BURN_PROVER_VERSION: u16 = 2;
const USDOM_V4_BURN_PROVER_HEADER_BYTES: usize =
    8 + 2 + USDOM_V4_ACTIVATION_SCHEDULE_BYTES + 32 + 4 + 4 + 4;

/// Exact Solidity ABI type consumed by `USDOMProofReserve.burnStatementHash`.
/// `finalityBeaconSlot` is the latest authenticated finalized Beacon slot, not
/// a loosely defined epoch or a DOM-local counter.
pub const FINALIZED_BURN_STATEMENT_TYPE: &str = "FinalizedBurn(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 finalityBeaconSlot,uint64 validUntil,uint256 ethereumChainId,address reserve,bytes32 activationScheduleCommitment)";

/// Maximum canonical native USDOM proof envelope carried by one future block.
/// This leaves half of the current 16 MiB block byte ceiling for the ordinary
/// economic body and framing. The live block decoder must enforce the combined
/// limit again when the envelope becomes part of `Block`.
pub const MAX_USDOM_V4_ENVELOPE_BYTES: usize = dom_core::MAX_BLOCK_SERIALIZED_SIZE / 2;

/// Maximum payload for one proof entry. The authenticated checkpoint witness
/// verifier currently has the same independent four-MiB ceiling.
pub const MAX_USDOM_V4_PROOF_BYTES: usize = MAX_CHECKPOINT_WITNESS_BYTES;

/// Immutable consensus schedule that must be ratified before native USDOM v4
/// can be activated on a network.
///
/// The schedule binds the DOM network and chain identity, the first height at
/// which v4 is mandatory, and the canonical empty native-state root. That root
/// commits the complete bridge identity, Ethereum policies and privacy
/// verifier configuration through `NativeUsdomState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeUsdomV4ActivationSchedule {
    network_magic: u32,
    chain_id: dom_core::Hash256,
    first_v4_height: u64,
    empty_state_root: dom_core::Hash256,
}

impl NativeUsdomV4ActivationSchedule {
    /// Construct and validate one exact schedule from a bridge identity.
    pub fn new(
        network_magic: u32,
        chain_id: dom_core::Hash256,
        first_v4_height: u64,
        bridge: BridgeIdentity,
    ) -> Result<Self, DomError> {
        if !matches!(
            network_magic,
            dom_core::NETWORK_MAGIC_MAINNET
                | dom_core::NETWORK_MAGIC_TESTNET
                | dom_core::NETWORK_MAGIC_REGTEST
        ) || chain_id == dom_core::Hash256::ZERO
            || first_v4_height == 0
        {
            return Err(DomError::Invalid(
                "invalid native USDOM activation schedule identity".into(),
            ));
        }
        validate_native_usdom_privacy_policy(bridge)?;
        let empty_state_root = NativeUsdomState::new(bridge)
            .map_err(|error| {
                DomError::Invalid(format!(
                    "native USDOM activation bridge identity failed: {error}"
                ))
            })?
            .state_root();
        let schedule = Self {
            network_magic,
            chain_id,
            first_v4_height,
            empty_state_root,
        };
        schedule.validate()?;
        Ok(schedule)
    }

    /// DOM network magic selected by this schedule.
    pub fn network_magic(self) -> u32 {
        self.network_magic
    }

    /// Consensus chain identifier selected by this schedule.
    pub fn chain_id(self) -> dom_core::Hash256 {
        self.chain_id
    }

    /// First block height that must use native USDOM v4 semantics.
    pub fn first_v4_height(self) -> u64 {
        self.first_v4_height
    }

    /// Canonical empty native-state root committed at activation.
    pub fn empty_state_root(self) -> dom_core::Hash256 {
        self.empty_state_root
    }

    /// Domain-separated commitment to the exact canonical schedule bytes.
    pub fn commitment(self) -> dom_core::Hash256 {
        blake2b_256_tagged(TAG_USDOM_V4_ACTIVATION_SCHEDULE, &self.to_bytes())
    }

    /// Encode the canonical fixed-width schedule.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(USDOM_V4_ACTIVATION_SCHEDULE_BYTES);
        out.extend_from_slice(USDOM_V4_ACTIVATION_MAGIC);
        out.extend_from_slice(&USDOM_V4_ACTIVATION_VERSION.to_be_bytes());
        out.extend_from_slice(&self.network_magic.to_be_bytes());
        out.extend_from_slice(self.chain_id.as_bytes());
        out.extend_from_slice(&self.first_v4_height.to_be_bytes());
        out.extend_from_slice(self.empty_state_root.as_bytes());
        out
    }

    /// Decode and validate one exact canonical schedule.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        if bytes.len() != USDOM_V4_ACTIVATION_SCHEDULE_BYTES {
            return Err(DomError::Invalid(
                "invalid native USDOM activation schedule encoding".into(),
            ));
        }
        let mut reader = Reader::new(bytes);
        if reader.read_bytes(8)? != USDOM_V4_ACTIVATION_MAGIC
            || reader.read_u16_be()? != USDOM_V4_ACTIVATION_VERSION
        {
            return Err(DomError::Invalid(
                "invalid native USDOM activation schedule encoding".into(),
            ));
        }
        let schedule = Self {
            network_magic: reader.read_u32_be()?,
            chain_id: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
            first_v4_height: reader.read_u64_be()?,
            empty_state_root: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
        };
        reader.finish()?;
        schedule.validate()?;
        if schedule.to_bytes() != bytes {
            return Err(DomError::Invalid(
                "noncanonical native USDOM activation schedule".into(),
            ));
        }
        Ok(schedule)
    }

    fn validate(self) -> Result<(), DomError> {
        if !matches!(
            self.network_magic,
            dom_core::NETWORK_MAGIC_MAINNET
                | dom_core::NETWORK_MAGIC_TESTNET
                | dom_core::NETWORK_MAGIC_REGTEST
        ) || self.chain_id == dom_core::Hash256::ZERO
            || self.first_v4_height == 0
            || self.empty_state_root == dom_core::Hash256::ZERO
        {
            return Err(DomError::Invalid(
                "invalid native USDOM activation schedule fields".into(),
            ));
        }
        Ok(())
    }
}

/// Ratified migration from one exact active-v1 snapshot to candidate state-v2
/// and transition-batch-v3 semantics at the following block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeUsdomV2ActivationSchedule {
    network_magic: u32,
    chain_id: dom_core::Hash256,
    first_v2_height: u64,
    activation_parent: dom_core::Hash256,
    previous_v1_state_root: dom_core::Hash256,
    initial_v2_state_root: dom_core::Hash256,
}

impl NativeUsdomV2ActivationSchedule {
    /// Construct the migration from one fully verified native state snapshot.
    pub fn new(
        network_magic: u32,
        chain_id: dom_core::Hash256,
        first_v2_height: u64,
        activation_parent: dom_core::Hash256,
        state: &NativeUsdomState,
    ) -> Result<Self, DomError> {
        let schedule = Self {
            network_magic,
            chain_id,
            first_v2_height,
            activation_parent,
            previous_v1_state_root: state.state_root(),
            initial_v2_state_root: state
                .state_commitment_v2()
                .map_err(|error| {
                    DomError::Invalid(format!("invalid v2 activation state: {error}"))
                })?
                .root(),
        };
        schedule.validate()?;
        Ok(schedule)
    }

    /// First block interpreted under state-v2/batch-v3 rules.
    pub const fn first_v2_height(self) -> u64 {
        self.first_v2_height
    }

    /// DOM network selected by the ratified migration.
    pub const fn network_magic(self) -> u32 {
        self.network_magic
    }

    /// Consensus chain identity selected by the ratified migration.
    pub const fn chain_id(self) -> dom_core::Hash256 {
        self.chain_id
    }

    /// Exact activation-parent block ratified with the snapshot.
    pub const fn activation_parent(self) -> dom_core::Hash256 {
        self.activation_parent
    }

    /// Active v1 root opened by the ratified snapshot.
    pub const fn previous_v1_state_root(self) -> dom_core::Hash256 {
        self.previous_v1_state_root
    }

    /// Candidate v2 root derived from the same ratified snapshot.
    pub const fn initial_v2_state_root(self) -> dom_core::Hash256 {
        self.initial_v2_state_root
    }

    /// Commitment to the canonical migration schedule.
    pub fn commitment(self) -> dom_core::Hash256 {
        blake2b_256_tagged(TAG_USDOM_V2_ACTIVATION_SCHEDULE, &self.to_bytes())
    }

    /// Encode the unique `UDACTV02` schedule.
    pub fn to_bytes(self) -> [u8; USDOM_V2_ACTIVATION_SCHEDULE_BYTES] {
        let mut bytes = [0u8; USDOM_V2_ACTIVATION_SCHEDULE_BYTES];
        bytes[..8].copy_from_slice(USDOM_V2_ACTIVATION_MAGIC);
        bytes[8..10].copy_from_slice(&USDOM_V2_ACTIVATION_VERSION.to_be_bytes());
        bytes[10..12].copy_from_slice(&USDOM_V2_STATE_VERSION.to_be_bytes());
        bytes[12..14]
            .copy_from_slice(&dom_usdom_state::CANDIDATE_V2_TRANSITION_BATCH_VERSION.to_be_bytes());
        bytes[14..18].copy_from_slice(&self.network_magic.to_be_bytes());
        bytes[18..50].copy_from_slice(self.chain_id.as_bytes());
        bytes[50..58].copy_from_slice(&self.first_v2_height.to_be_bytes());
        bytes[58..90].copy_from_slice(self.activation_parent.as_bytes());
        bytes[90..122].copy_from_slice(self.previous_v1_state_root.as_bytes());
        bytes[122..154].copy_from_slice(self.initial_v2_state_root.as_bytes());
        bytes
    }

    /// Decode and re-encode one exact `UDACTV02` migration schedule.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        if bytes.len() != USDOM_V2_ACTIVATION_SCHEDULE_BYTES {
            return Err(DomError::Invalid(
                "invalid native USDOM v2 activation encoding".into(),
            ));
        }
        let mut reader = Reader::new(bytes);
        if reader.read_bytes(8)? != USDOM_V2_ACTIVATION_MAGIC
            || reader.read_u16_be()? != USDOM_V2_ACTIVATION_VERSION
            || reader.read_u16_be()? != USDOM_V2_STATE_VERSION
            || reader.read_u16_be()? != dom_usdom_state::CANDIDATE_V2_TRANSITION_BATCH_VERSION
        {
            return Err(DomError::Invalid(
                "invalid native USDOM v2 activation encoding".into(),
            ));
        }
        let schedule = Self {
            network_magic: reader.read_u32_be()?,
            chain_id: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
            first_v2_height: reader.read_u64_be()?,
            activation_parent: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
            previous_v1_state_root: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
            initial_v2_state_root: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
        };
        reader.finish()?;
        schedule.validate()?;
        if schedule.to_bytes().as_slice() != bytes {
            return Err(DomError::Invalid(
                "noncanonical native USDOM v2 activation schedule".into(),
            ));
        }
        Ok(schedule)
    }

    fn validate(self) -> Result<(), DomError> {
        if !matches!(
            self.network_magic,
            dom_core::NETWORK_MAGIC_MAINNET
                | dom_core::NETWORK_MAGIC_TESTNET
                | dom_core::NETWORK_MAGIC_REGTEST
        ) || self.chain_id == dom_core::Hash256::ZERO
            || self.first_v2_height == 0
            || self.activation_parent == dom_core::Hash256::ZERO
            || self.previous_v1_state_root == dom_core::Hash256::ZERO
            || self.initial_v2_state_root == dom_core::Hash256::ZERO
        {
            return Err(DomError::Invalid(
                "invalid native USDOM v2 activation schedule".into(),
            ));
        }
        Ok(())
    }
}

fn v2_activation_tip_value(schedule: NativeUsdomV2ActivationSchedule) -> Vec<u8> {
    let mut value = Vec::with_capacity(USDOM_V2_TIP_BYTES);
    value.extend_from_slice(schedule.activation_parent.as_bytes());
    value.extend_from_slice(schedule.previous_v1_state_root.as_bytes());
    value.extend_from_slice(schedule.initial_v2_state_root.as_bytes());
    value.extend_from_slice(schedule.commitment().as_bytes());
    debug_assert_eq!(value.len(), USDOM_V2_TIP_BYTES);
    value
}

/// Load the persisted candidate-v2 migration identity without trusting it as
/// canonical state. A partial or internally inconsistent marker pair is store
/// corruption and never degrades to "not activated".
pub fn load_persisted_usdom_v2_activation_schedule(
    store: &DomStore,
) -> Result<Option<NativeUsdomV2ActivationSchedule>, DomError> {
    let record = store.get_consensus_state(USDOM_V2_ACTIVATION_KEY)?;
    let marker = store.get_consensus_state(USDOM_V2_TIP_KEY)?;
    let (record, marker) = match (record, marker) {
        (None, None) => return Ok(None),
        (Some(record), Some(marker)) => (record, marker),
        _ => {
            return Err(DomError::Internal(
                "persisted native USDOM V2 activation marker/record mismatch".into(),
            ))
        }
    };
    let schedule = NativeUsdomV2ActivationSchedule::from_bytes(&record).map_err(|error| {
        DomError::Internal(format!(
            "persisted native USDOM V2 activation record is corrupt: {error}"
        ))
    })?;
    if marker != v2_activation_tip_value(schedule) {
        let runtime_tip = PersistedUsdomV2RuntimeTip::from_bytes(&marker).map_err(|error| {
            DomError::Internal(format!(
                "persisted native USDOM V2 runtime marker is corrupt: {error}"
            ))
        })?;
        if runtime_tip.schedule_commitment != schedule.commitment() {
            return Err(DomError::Internal(
                "persisted native USDOM V2 runtime marker uses another schedule".into(),
            ));
        }
    }
    Ok(Some(schedule))
}

/// Produce the atomic marker pair for one ratified V1-to-V2 migration snapshot.
///
/// The caller must combine these updates with the V1 state updates of the exact
/// canonical activation parent in one database transaction. The marker grants
/// no transition authority by itself: restoration independently reconstructs
/// the complete V1 state and derives its V2 commitment before accepting it.
pub fn native_usdom_v2_activation_updates(
    state: &NativeUsdomState,
    schedule: NativeUsdomV2ActivationSchedule,
    activation_parent: dom_core::Hash256,
    activation_parent_height: u64,
) -> Result<Vec<ConsensusStateUpdate>, DomError> {
    schedule.validate()?;
    let first_v2_height = activation_parent_height
        .checked_add(1)
        .ok_or_else(|| DomError::Invalid("native USDOM v2 activation height overflow".into()))?;
    let v2 = state
        .state_commitment_v2()
        .map_err(|error| DomError::Invalid(format!("invalid v2 activation snapshot: {error}")))?;
    if activation_parent == dom_core::Hash256::ZERO
        || schedule.activation_parent != activation_parent
        || schedule.first_v2_height != first_v2_height
        || schedule.previous_v1_state_root != state.state_root()
        || schedule.initial_v2_state_root != v2.root()
    {
        return Err(DomError::PolicyRejected(
            "native USDOM v2 activation does not match the ratified parent snapshot".into(),
        ));
    }
    let mut updates = vec![
        ConsensusStateUpdate {
            key: USDOM_V2_ACTIVATION_KEY.to_vec(),
            value: Some(schedule.to_bytes().to_vec()),
        },
        ConsensusStateUpdate {
            key: USDOM_V2_TIP_KEY.to_vec(),
            value: Some(v2_activation_tip_value(schedule)),
        },
        ConsensusStateUpdate {
            key: USDOM_V2_PRUNE_CURSOR_KEY.to_vec(),
            value: Some(v2_prune_cursor_value(schedule.first_v2_height())),
        },
    ];
    for burn in state.burn_records() {
        updates.push(v2_burn_archive_update(
            activation_parent_height,
            activation_parent,
            burn,
        )?);
    }
    validate_consensus_state_updates(&updates)?;
    Ok(updates)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PersistedUsdomV4Tip {
    block_identifier: dom_core::Hash256,
    state_root: dom_core::Hash256,
    package_commitment: dom_core::Hash256,
}

fn decode_persisted_usdom_v4_tip(
    bytes: &[u8],
    label: &str,
) -> Result<PersistedUsdomV4Tip, DomError> {
    if bytes.len() != USDOM_V4_TIP_BYTES {
        return Err(DomError::Internal(format!(
            "persisted native USDOM {label} has an invalid width"
        )));
    }
    let mut reader = Reader::new(bytes);
    let decoded = (|| {
        Ok(PersistedUsdomV4Tip {
            block_identifier: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
            state_root: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
            package_commitment: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
        })
    })()
    .and_then(|tip| {
        reader.finish()?;
        Ok(tip)
    })
    .map_err(|error: DomError| {
        DomError::Internal(format!(
            "persisted native USDOM {label} is malformed: {error}"
        ))
    })?;
    Ok(decoded)
}

fn restore_persisted_usdom_v2_activation_state_at_tip(
    store: &DomStore,
    network_magic: u32,
    expected_current_tip: dom_core::Hash256,
    expected_bridge: BridgeIdentity,
    expected_schedule: NativeUsdomV2ActivationSchedule,
) -> Result<(NativeUsdomState, NativeUsdomV4ActivationSchedule), DomError> {
    expected_schedule.validate()?;
    if network_magic != expected_schedule.network_magic {
        return Err(DomError::PolicyRejected(
            "persisted native USDOM v2 activation belongs to another network".into(),
        ));
    }
    let parent_height = expected_schedule
        .first_v2_height
        .checked_sub(1)
        .ok_or_else(|| DomError::Invalid("native USDOM v2 activation height underflow".into()))?;
    let snapshot = store.read_canonical_consensus_snapshot(parent_height)?;
    if snapshot.chain_tip != Some(*expected_current_tip.as_bytes())
        || snapshot.requested_height_hash != Some(*expected_schedule.activation_parent.as_bytes())
    {
        return Err(DomError::Internal(
            "persisted native USDOM v2 activation parent is not on the expected canonical chain"
                .into(),
        ));
    }
    let record = snapshot.consensus_state.get(USDOM_V2_ACTIVATION_KEY);
    let marker = snapshot.consensus_state.get(USDOM_V2_TIP_KEY);
    let (record, marker) = match (record, marker) {
        (Some(record), Some(marker)) => (record, marker),
        _ => {
            return Err(DomError::Internal(
                "persisted native USDOM v2 activation marker/record mismatch".into(),
            ));
        }
    };
    let persisted_schedule = NativeUsdomV2ActivationSchedule::from_bytes(record).map_err(|_| {
        DomError::Internal("persisted native USDOM v2 activation record is corrupt".into())
    })?;
    if persisted_schedule != expected_schedule || marker.len() < USDOM_V2_TIP_BYTES {
        return Err(DomError::PolicyRejected(
            "persisted native USDOM v2 activation is not the ratified schedule".into(),
        ));
    }
    if expected_current_tip == expected_schedule.activation_parent {
        if marker.as_slice() != v2_activation_tip_value(expected_schedule) {
            return Err(DomError::PolicyRejected(
                "persisted native USDOM v2 activation marker is not current".into(),
            ));
        }
    } else {
        let runtime_tip = PersistedUsdomV2RuntimeTip::from_bytes(marker).map_err(|error| {
            DomError::Internal(format!(
                "persisted native USDOM v2 runtime marker is corrupt: {error}"
            ))
        })?;
        if runtime_tip.schedule_commitment != expected_schedule.commitment()
            || runtime_tip.block_identifier != expected_current_tip
        {
            return Err(DomError::PolicyRejected(
                "persisted native USDOM v2 runtime marker is not the expected ratified tip".into(),
            ));
        }
    }

    let v1_activation = snapshot
        .consensus_state
        .get(USDOM_V4_ACTIVATION_KEY)
        .ok_or_else(|| {
            DomError::Internal("persisted native USDOM v1 activation record is missing".into())
        })?;
    let (v1_schedule, _) = parse_activation_record(v1_activation)?;
    if v1_schedule.network_magic != network_magic
        || v1_schedule.chain_id != expected_schedule.chain_id
    {
        return Err(DomError::PolicyRejected(
            "persisted native USDOM V1 and V2 activation identities disagree".into(),
        ));
    }
    let v1_tip = snapshot
        .consensus_state
        .get(USDOM_V4_TIP_KEY)
        .ok_or_else(|| DomError::Internal("persisted native USDOM v1 tip is missing".into()))?;
    let v1_tip = decode_persisted_usdom_v4_tip(v1_tip, "v1 activation tip")?;
    if v1_tip.block_identifier != expected_schedule.activation_parent
        || v1_tip.state_root != expected_schedule.previous_v1_state_root
    {
        return Err(DomError::Internal(
            "persisted native USDOM v1 tip does not open the V2 activation snapshot".into(),
        ));
    }

    let state_entries = snapshot
        .consensus_state
        .iter()
        .filter(|(key, _)| key.starts_with(b"usdom/v3/"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let state =
        NativeUsdomState::restore_entries(expected_bridge, &state_entries).map_err(|error| {
            DomError::Internal(format!("persisted v2 activation state is corrupt: {error}"))
        })?;
    let v2 = state.state_commitment_v2().map_err(|error| {
        DomError::Internal(format!(
            "persisted v2 activation commitment is invalid: {error}"
        ))
    })?;
    if state.state_root() != expected_schedule.previous_v1_state_root
        || v2.root() != expected_schedule.initial_v2_state_root
    {
        return Err(DomError::Internal(
            "persisted native USDOM state does not match the V2 activation roots".into(),
        ));
    }
    Ok((state, v1_schedule))
}

/// Restore and verify the exact V1 snapshot selected by a persisted UDACTV02
/// marker pair, returning only its derived V2 commitment.
///
/// The canonical parent, active V1 marker, complete state entries, both state
/// roots and schedule commitment must all agree. Missing, partial, malformed or
/// substituted migration metadata fails closed after restart.
pub fn restore_persisted_usdom_v2_activation(
    store: &DomStore,
    network_magic: u32,
    expected_chain_tip: dom_core::Hash256,
    expected_bridge: BridgeIdentity,
    expected_schedule: NativeUsdomV2ActivationSchedule,
) -> Result<StateCommitmentV2, DomError> {
    if expected_chain_tip != expected_schedule.activation_parent() {
        return Err(DomError::Invalid(
            "native USDOM v2 activation restore requires the activation parent as tip".into(),
        ));
    }
    let (state, _) = restore_persisted_usdom_v2_activation_state_at_tip(
        store,
        network_magic,
        expected_chain_tip,
        expected_bridge,
        expected_schedule,
    )?;
    state.state_commitment_v2().map_err(|error| {
        DomError::Internal(format!(
            "persisted v2 activation commitment is invalid: {error}"
        ))
    })
}

fn v2_state_matches_bridge(state: StateCommitmentV2, bridge: BridgeIdentity) -> bool {
    state.domain == bridge.dom_domain
        && state.ethereum_genesis_validators_root == bridge.ethereum_genesis_validators_root
        && state.ethereum_chain_id == bridge.ethereum_chain_id
        && state.reserve == bridge.reserve
        && state.ethereum_checkpoint_policy_hash == bridge.ethereum_checkpoint_policy_hash
        && state.ethereum_deposit_policy_hash == bridge.ethereum_deposit_policy_hash
        && state.privacy_policy_hash == bridge.privacy_policy_hash
        && state.privacy_verifier_config_hash == bridge.privacy_verifier_config_hash
        && state.burn_timing == bridge.burn_timing
}

/// Restore the canonical candidate-v2 tip and independently replay its exact
/// proof-bearing package through the persisted bounded witness bundle.
///
/// The canonical tip, ratified schedule, package, previous and next
/// commitments, witness bytes, transition receipt and block-header commitment
/// must all agree. The activation parent is restored through
/// [`restore_persisted_usdom_v2_activation`].
#[allow(clippy::too_many_arguments)]
pub fn restore_persisted_usdom_v2_state_for_schedule(
    store: &DomStore,
    network_magic: u32,
    expected_chain_tip: dom_core::Hash256,
    expected_bridge: BridgeIdentity,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    closure_policy: Option<&StaticIssuanceClosureTrustPolicy>,
    spend_verifier: &SpendVerifier,
    expected_schedule: NativeUsdomV2ActivationSchedule,
) -> Result<StateCommitmentV2, DomError> {
    expected_schedule.validate()?;
    if expected_schedule.network_magic() != network_magic {
        return Err(DomError::PolicyRejected(
            "native USDOM v2 runtime schedule belongs to another network".into(),
        ));
    }
    if expected_chain_tip == expected_schedule.activation_parent() {
        return restore_persisted_usdom_v2_activation(
            store,
            network_magic,
            expected_chain_tip,
            expected_bridge,
            expected_schedule,
        );
    }
    let block_bytes = store
        .get_block_body(expected_chain_tip.as_bytes())?
        .ok_or_else(|| DomError::Internal("persisted v2 tip block body is missing".into()))?;
    let block = <Block as DomDeserialize>::from_bytes(&block_bytes).map_err(|error| {
        DomError::Internal(format!("persisted v2 tip block is corrupt: {error}"))
    })?;
    let header_bytes = DomSerialize::to_bytes(&block.header)?;
    if crate::canonical_header_identifier(network_magic, &header_bytes)? != expected_chain_tip
        || block.header.height.0 < expected_schedule.first_v2_height()
    {
        return Err(DomError::Internal(
            "persisted native USDOM v2 tip block identity is invalid".into(),
        ));
    }
    let snapshot = store.read_canonical_consensus_snapshot(block.header.height.0)?;
    if snapshot.chain_tip != Some(*expected_chain_tip.as_bytes())
        || snapshot.requested_height_hash != Some(*expected_chain_tip.as_bytes())
    {
        return Err(DomError::Internal(
            "persisted native USDOM v2 state was not read at the expected canonical tip".into(),
        ));
    }
    let activation = snapshot
        .consensus_state
        .get(USDOM_V2_ACTIVATION_KEY)
        .ok_or_else(|| DomError::Internal("persisted v2 activation record is missing".into()))?;
    let persisted_schedule =
        NativeUsdomV2ActivationSchedule::from_bytes(activation).map_err(|error| {
            DomError::Internal(format!(
                "persisted native USDOM v2 activation is corrupt: {error}"
            ))
        })?;
    if persisted_schedule != expected_schedule {
        return Err(DomError::PolicyRejected(
            "persisted native USDOM v2 runtime is not the ratified schedule".into(),
        ));
    }
    let tip = snapshot
        .consensus_state
        .get(USDOM_V2_TIP_KEY)
        .ok_or_else(|| DomError::Internal("persisted native USDOM v2 tip is missing".into()))?;
    let tip = PersistedUsdomV2RuntimeTip::from_bytes(tip).map_err(|error| {
        DomError::Internal(format!("persisted native USDOM v2 tip is corrupt: {error}"))
    })?;
    let record =
        load_persisted_usdom_v2_block_record(store, expected_chain_tip)?.ok_or_else(|| {
            DomError::Internal("persisted native USDOM v2 block record is missing".into())
        })?;
    if tip.schedule_commitment != expected_schedule.commitment()
        || tip.block_identifier != expected_chain_tip
        || tip.package_commitment != record.package_commitment
        || tip.witness_commitment != record.witness_commitment
        || tip.state != record.next_state
        || record.schedule_commitment != expected_schedule.commitment()
        || record.block_identifier != expected_chain_tip
        || record.parent != block.header.prev_hash
        || record.receipt.block_timestamp != block.header.timestamp.0
        || !v2_state_matches_bridge(record.previous_state, expected_bridge)
        || !v2_state_matches_bridge(record.next_state, expected_bridge)
        || (block.header.height.0 == expected_schedule.first_v2_height()
            && (record.parent != expected_schedule.activation_parent()
                || record.previous_state.root() != expected_schedule.initial_v2_state_root()))
    {
        return Err(DomError::Internal(
            "persisted native USDOM v2 tip and block record disagree".into(),
        ));
    }
    let package = load_persisted_usdom_v4_package(store, network_magic, expected_chain_tip)?
        .ok_or_else(|| DomError::Internal("persisted native USDOM v2 package is missing".into()))?;
    let witnesses = load_persisted_usdom_v2_execution_witnesses(store, expected_chain_tip)?
        .ok_or_else(|| {
            DomError::Internal("persisted native USDOM v2 witnesses are missing".into())
        })?;
    if blake2b_256_tagged(TAG_USDOM_BLOCK_PACKAGE_V4, &package) != record.package_commitment
        || witnesses.commitment()? != record.witness_commitment
    {
        return Err(DomError::Internal(
            "persisted native USDOM v2 recovery commitments disagree".into(),
        ));
    }
    let context = ValidationContext {
        current_height: block.header.height,
        chain_id: *expected_schedule.chain_id().as_bytes(),
        now: block.header.timestamp,
    };
    let verified = verify_usdom_v4_serialized_transition_batch_for_v2_schedule(
        &package,
        &context,
        network_magic,
        expected_bridge,
        checkpoint_policy,
        deposit_policy,
        closure_policy,
        spend_verifier,
        expected_schedule,
    )?;
    let candidate = verified.execute_v2(
        &context,
        record.previous_state.root(),
        record.previous_state,
        witnesses.witnesses(),
    )?;
    if candidate.block_identifier() != expected_chain_tip
        || candidate.package_commitment() != record.package_commitment
        || candidate.witness_commitment() != record.witness_commitment
        || candidate.next_state() != record.next_state
        || candidate.receipt() != record.receipt
    {
        return Err(DomError::Internal(
            "persisted native USDOM v2 tip replay diverged".into(),
        ));
    }
    Ok(record.next_state)
}

/// Reconstruct the candidate-v2 state at one canonical ancestor by applying
/// only authenticated persisted undo records.
///
/// The caller must supply the current canonical tip and its already restored
/// state. The rewind is bounded by the consensus reorganization limit and
/// rejects a record, schedule or activation-root mismatch.
pub fn rewind_persisted_usdom_v2_state_to_ancestor(
    store: &DomStore,
    canonical_tip: dom_core::Hash256,
    current_state: StateCommitmentV2,
    ancestor: dom_core::Hash256,
    schedule: NativeUsdomV2ActivationSchedule,
) -> Result<StateCommitmentV2, DomError> {
    schedule.validate()?;
    if canonical_tip == dom_core::Hash256::ZERO || ancestor == dom_core::Hash256::ZERO {
        return Err(DomError::Invalid(
            "native USDOM v2 rewind identity cannot be zero".into(),
        ));
    }
    let ancestor_header_bytes = store
        .get_block_header(ancestor.as_bytes())?
        .ok_or_else(|| DomError::Internal("native USDOM v2 rewind ancestor is missing".into()))?;
    let ancestor_header = dom_consensus::block::BlockHeader::from_bytes(&ancestor_header_bytes)
        .map_err(|error| {
            DomError::Internal(format!(
                "native USDOM v2 rewind ancestor is corrupt: {error}"
            ))
        })?;
    let minimum_ancestor_height = schedule
        .first_v2_height()
        .checked_sub(1)
        .ok_or_else(|| DomError::Invalid("invalid native USDOM v2 activation height".into()))?;
    if ancestor_header.height.0 < minimum_ancestor_height
        || crate::canonical_header_identifier(schedule.network_magic(), &ancestor_header_bytes)?
            != ancestor
        || store.get_hash_at_height(ancestor_header.height.0)? != Some(*ancestor.as_bytes())
    {
        return Err(DomError::Internal(
            "native USDOM v2 rewind ancestor is not canonical at its declared height".into(),
        ));
    }
    // The loop below authenticates every traversed record. When no traversal is
    // needed, authenticate the supplied tip explicitly so a persisted side-chain
    // package cannot be presented as a canonical ancestor by setting both
    // identities to the same hash.
    if canonical_tip == ancestor {
        if canonical_tip == schedule.activation_parent() {
            if current_state.root() != schedule.initial_v2_state_root() {
                return Err(DomError::Internal(
                    "native USDOM v2 rewind reached an invalid activation state".into(),
                ));
            }
            return Ok(current_state);
        }
        let record =
            load_persisted_usdom_v2_block_record(store, canonical_tip)?.ok_or_else(|| {
                DomError::Internal("native USDOM v2 rewind block record is missing".into())
            })?;
        if record.schedule_commitment != schedule.commitment()
            || record.block_identifier != canonical_tip
            || record.next_state != current_state
        {
            return Err(DomError::Internal(
                "native USDOM v2 rewind record does not match canonical state".into(),
            ));
        }
        authenticate_persisted_usdom_v2_rewind_record(
            store,
            schedule.network_magic(),
            canonical_tip,
            record,
        )?;
        return Ok(current_state);
    }
    let mut cursor = canonical_tip;
    let mut state = current_state;
    let mut steps = 0u64;
    while cursor != ancestor {
        steps = steps
            .checked_add(1)
            .ok_or_else(|| DomError::Invalid("native USDOM v2 rewind depth overflow".into()))?;
        if steps >= crate::reorg::MAX_REORG_DEPTH {
            return Err(DomError::PolicyRejected(
                "native USDOM v2 rewind exceeds maximum reorg depth".into(),
            ));
        }
        let record = load_persisted_usdom_v2_block_record(store, cursor)?.ok_or_else(|| {
            DomError::Internal("native USDOM v2 rewind block record is missing".into())
        })?;
        if record.schedule_commitment != schedule.commitment()
            || record.block_identifier != cursor
            || record.next_state != state
        {
            return Err(DomError::Internal(
                "native USDOM v2 rewind record does not match canonical state".into(),
            ));
        }
        authenticate_persisted_usdom_v2_rewind_record(
            store,
            schedule.network_magic(),
            cursor,
            record,
        )?;
        state = record.previous_state;
        cursor = record.parent;
    }
    if cursor == schedule.activation_parent() && state.root() != schedule.initial_v2_state_root() {
        return Err(DomError::Internal(
            "native USDOM v2 rewind reached an invalid activation state".into(),
        ));
    }
    Ok(state)
}

fn authenticate_persisted_usdom_v2_rewind_record(
    store: &DomStore,
    network_magic: u32,
    cursor: dom_core::Hash256,
    record: PersistedUsdomV2BlockRecord,
) -> Result<(), DomError> {
    let package_bytes = load_persisted_usdom_v4_package(store, network_magic, cursor)?
        .ok_or_else(|| DomError::Internal("native USDOM v2 rewind package is missing".into()))?;
    let package = UsdomV4BlockPackage::from_bytes(&package_bytes).map_err(|error| {
        DomError::Internal(format!(
            "native USDOM v2 rewind package is corrupt: {error}"
        ))
    })?;
    let block = package.block();
    let header_bytes = DomSerialize::to_bytes(&block.header)?;
    let computed = crate::canonical_header_identifier(network_magic, &header_bytes)?;
    if computed != cursor
        || record.block_identifier != cursor
        || record.parent != block.header.prev_hash
        || record.receipt.block_timestamp != block.header.timestamp.0
        || blake2b_256_tagged(TAG_USDOM_BLOCK_PACKAGE_V4, &package_bytes)
            != record.package_commitment
        || store.get_hash_at_height(block.header.height.0)? != Some(*cursor.as_bytes())
    {
        return Err(DomError::Internal(
            "native USDOM v2 rewind record is not bound to its canonical block".into(),
        ));
    }
    let (_, _, raw_rangeproof_root) =
        compute_block_pmmr_roots(block.header.height, &block.coinbase, &block.transactions)?;
    if bind_usdom_batch_commitment(raw_rangeproof_root, record.receipt.header_commitment)?
        != block.header.rangeproof_root
    {
        return Err(DomError::Internal(
            "native USDOM v2 rewind receipt is not authenticated by its block header".into(),
        ));
    }
    Ok(())
}

/// Return the fixed isolated Regtest schedule used by the current PoC runtime.
pub fn native_usdom_v4_regtest_activation_schedule(
    bridge: BridgeIdentity,
) -> Result<NativeUsdomV4ActivationSchedule, DomError> {
    let genesis = dom_core::configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST)?;
    let chain_id = dom_consensus::derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis);
    NativeUsdomV4ActivationSchedule::new(NETWORK_MAGIC_REGTEST, chain_id, 1, bridge)
}

fn activation_record(
    schedule: NativeUsdomV4ActivationSchedule,
    activation_parent: dom_core::Hash256,
) -> Result<Vec<u8>, DomError> {
    if activation_parent == dom_core::Hash256::ZERO {
        return Err(DomError::Invalid(
            "native USDOM activation parent cannot be zero".into(),
        ));
    }
    let mut value = schedule.to_bytes();
    value.extend_from_slice(activation_parent.as_bytes());
    Ok(value)
}

fn parse_activation_record(
    value: &[u8],
) -> Result<(NativeUsdomV4ActivationSchedule, dom_core::Hash256), DomError> {
    if value.len() != USDOM_V4_ACTIVATION_RECORD_BYTES {
        return Err(DomError::Internal(
            "persisted native USDOM activation record is corrupt".into(),
        ));
    }
    let schedule =
        NativeUsdomV4ActivationSchedule::from_bytes(&value[..USDOM_V4_ACTIVATION_SCHEDULE_BYTES])
            .map_err(|_| {
            DomError::Internal("persisted native USDOM activation schedule is corrupt".into())
        })?;
    let parent = dom_core::Hash256::from_bytes(
        value[USDOM_V4_ACTIVATION_SCHEDULE_BYTES..]
            .try_into()
            .map_err(|_| DomError::Internal("truncated native USDOM activation parent".into()))?,
    );
    if parent == dom_core::Hash256::ZERO {
        return Err(DomError::Internal(
            "persisted native USDOM activation parent is zero".into(),
        ));
    }
    Ok((schedule, parent))
}

/// Load the exact V1 activation schedule persisted by the atomic activation
/// transaction. Startup callers use this to ensure a hash-pinned manifest has
/// not been substituted after candidate-V2 activation.
pub fn persisted_usdom_v4_activation_schedule(
    store: &DomStore,
) -> Result<NativeUsdomV4ActivationSchedule, DomError> {
    let activation = store
        .get_consensus_state(USDOM_V4_ACTIVATION_KEY)?
        .ok_or_else(|| {
            DomError::PolicyRejected(
                "native USDOM v4 validation requires its atomically persisted activation marker/record"
                    .into(),
            )
        })?;
    parse_activation_record(&activation).map(|(schedule, _)| schedule)
}

/// Return whether the atomic native-USDOM activation marker exists.
///
/// Ordinary block ingress uses this as a consensus-path guard: once the
/// marker is installed, every unknown post-activation block must arrive as an
/// authenticated v4 package so the DOM and USDOM states cannot advance
/// independently. A malformed marker is storage corruption, not an inactive
/// runtime, and therefore fails closed.
pub(crate) fn native_usdom_v4_activation_tip(
    store: &DomStore,
) -> Result<Option<dom_core::Hash256>, DomError> {
    let marker = store.get_consensus_state(USDOM_V4_TIP_KEY)?;
    let activation = store.get_consensus_state(USDOM_V4_ACTIVATION_KEY)?;
    let (marker, activation) = match (marker, activation) {
        (None, None) => return Ok(None),
        (Some(marker), Some(activation)) => (marker, activation),
        _ => {
            return Err(DomError::Internal(
                "persisted native USDOM activation marker/record mismatch".into(),
            ));
        }
    };
    parse_activation_record(&activation)?;
    let marker = decode_persisted_usdom_v4_tip(&marker, "activation tip")?;
    if marker.block_identifier == dom_core::Hash256::ZERO
        || marker.state_root == dom_core::Hash256::ZERO
    {
        return Err(DomError::Internal(
            "persisted native USDOM activation marker is corrupt".into(),
        ));
    }
    Ok(Some(marker.block_identifier))
}

/// Require the canonical database to carry the exact activation schedule and
/// parent selected by the caller. This is the header-only counterpart to the
/// full native-state restore: IBD does not need a bridge object, but it must
/// never accept v4 headers under a schedule different from the one installed
/// atomically with the canonical activation parent.
pub(crate) fn require_persisted_usdom_v4_activation_for_schedule(
    store: &DomStore,
    expected_chain_tip: dom_core::Hash256,
    expected_schedule: NativeUsdomV4ActivationSchedule,
) -> Result<(), DomError> {
    let activation_parent_height = expected_schedule
        .first_v4_height
        .checked_sub(1)
        .ok_or_else(|| DomError::Invalid("native USDOM activation height underflow".into()))?;
    let snapshot = store.read_canonical_consensus_snapshot(activation_parent_height)?;
    if snapshot.chain_tip != Some(*expected_chain_tip.as_bytes()) {
        return Err(DomError::Internal(
            "native USDOM activation schedule was not read at the canonical chain tip".into(),
        ));
    }
    let activation = snapshot
        .consensus_state
        .get(USDOM_V4_ACTIVATION_KEY)
        .ok_or_else(|| {
            DomError::PolicyRejected(
                "native USDOM v4 validation requires its atomically persisted activation record"
                    .into(),
            )
        })?;
    let marker = snapshot
        .consensus_state
        .get(USDOM_V4_TIP_KEY)
        .ok_or_else(|| {
            DomError::PolicyRejected(
                "native USDOM v4 validation requires its atomically persisted activation marker"
                    .into(),
            )
        })?;
    let (persisted_schedule, activation_parent) = parse_activation_record(activation)?;
    if persisted_schedule != expected_schedule {
        return Err(DomError::PolicyRejected(
            "persisted native USDOM activation schedule is not the ratified schedule".into(),
        ));
    }
    if snapshot.requested_height_hash != Some(*activation_parent.as_bytes()) {
        return Err(DomError::Internal(
            "persisted native USDOM activation parent is not canonical".into(),
        ));
    }
    let marker = decode_persisted_usdom_v4_tip(marker, "scheduled activation tip")?;
    if marker.block_identifier != expected_chain_tip || marker.state_root == dom_core::Hash256::ZERO
    {
        return Err(DomError::Internal(
            "persisted native USDOM activation marker is corrupt or stale".into(),
        ));
    }
    Ok(())
}

/// Maximum number of locally submitted, already preverified envelopes retained
/// for Regtest mining. They receive no consensus authority from admission and
/// are verified again against the exact state and timestamp of every template.
pub const MAX_USDOM_V4_MINING_CANDIDATES: usize = 16;

/// Aggregate in-memory ceiling for locally submitted Regtest mining envelopes.
/// This is deliberately much smaller than `count * MAX_USDOM_V4_ENVELOPE_BYTES`.
pub const MAX_USDOM_V4_MINING_CANDIDATE_BYTES: usize = 16 * 1024 * 1024;

const TAG_USDOM_V4_MINING_CANDIDATE: &str = "DOM:usdom-v4-mining-candidate:v1";

/// Maximum canonical byte length of one block-bound native burn prover input.
/// It contains one already-bounded block package, one already-bounded batch
/// undo and one already-bounded burn-state witness plus fixed framing.
pub const MAX_NATIVE_BURN_BLOCK_PROVER_INPUT_BYTES: usize = USDOM_V4_BURN_PROVER_HEADER_BYTES
    + MAX_BLOCK_SERIALIZED_SIZE
    + MAX_BATCH_UNDO_BYTES
    + MAX_BURN_STATE_WITNESS_BYTES;

/// Commit every immutable Ethereum finality and checkpoint-registry policy
/// input used by the native USDOM verifier. `max_current_slot` is deliberately
/// excluded because it is recomputed from each authenticated DOM block time.
pub fn ethereum_checkpoint_policy_hash(policy: &CheckpointTrustPolicy) -> dom_core::Hash256 {
    dom_core::Hash256::from_bytes(checkpoint_trust_policy_hash(policy).into())
}

/// Return the exact frozen privacy-policy commitment required by native USDOM.
pub fn native_usdom_privacy_policy_hash() -> dom_core::Hash256 {
    privacy_policy_hash()
}

fn validate_native_usdom_privacy_policy(bridge: BridgeIdentity) -> Result<(), DomError> {
    if bridge.privacy_policy_hash != *privacy_policy_hash().as_bytes() {
        return Err(DomError::PolicyRejected(
            "native USDOM bridge privacy policy does not match this binary".into(),
        ));
    }
    Ok(())
}

fn validate_spend_verifier_identity(
    bridge: BridgeIdentity,
    verifier: &SpendVerifier,
) -> Result<(), DomError> {
    validate_native_usdom_privacy_policy(bridge)?;
    if verifier.config_hash().as_bytes() != &bridge.privacy_verifier_config_hash {
        return Err(DomError::PolicyRejected(
            "native USDOM spend verifier does not match the bridge commitment".into(),
        ));
    }
    Ok(())
}

/// Version-1 proof class discriminator. Decoding these bytes grants no
/// authority; the corresponding verifier must produce an opaque transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsdomV4ProofKind {
    /// Finalized Ethereum deposit and private note-binding proof.
    Issuance,
    /// Private ownership, membership, range and conservation proof.
    Transfer,
    /// Private spend and public burn-obligation proof.
    Burn,
    /// Authenticated Ethereum light-client checkpoint witness.
    EthereumCheckpoint,
    /// Finalized irreversible reserve issuance closure and authenticated post-state.
    IssuanceClosure,
    /// Deterministic orderly termination after issuance closure and full burn.
    GracefulShutdown,
}

impl UsdomV4ProofKind {
    fn discriminator(self) -> u8 {
        match self {
            Self::Issuance => 1,
            Self::Transfer => 2,
            Self::Burn => 3,
            Self::EthereumCheckpoint => 4,
            Self::IssuanceClosure => 5,
            Self::GracefulShutdown => 6,
        }
    }

    fn from_discriminator(value: u8) -> Result<Self, DomError> {
        match value {
            1 => Ok(Self::Issuance),
            2 => Ok(Self::Transfer),
            3 => Ok(Self::Burn),
            4 => Ok(Self::EthereumCheckpoint),
            5 => Ok(Self::IssuanceClosure),
            6 => Ok(Self::GracefulShutdown),
            _ => Err(DomError::Malformed(
                "unknown native USDOM v4 proof kind".into(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UsdomV4ProofEntry {
    kind: UsdomV4ProofKind,
    payload: Vec<u8>,
}

/// Canonical bounded, untrusted proof bytes proposed with one block-v4 body.
/// Parsing this type never creates a verified state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsdomV4ProofEnvelope {
    entries: Vec<UsdomV4ProofEntry>,
}

/// One header-authenticated public transition projection and its optional
/// encrypted wallet payload. The payload remains untrusted until a wallet
/// recomputes its memo commitment against `projection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedUsdomV4HistoryTransition {
    /// Public preimage whose versioned commitment is under the block batch root.
    pub projection: TransitionCommitmentProjection,
    /// Exact canonical private transfer/burn payload retained by the block
    /// sidecar. Issuance and checkpoint transitions carry `None`.
    pub private_payload: Option<Vec<u8>>,
}

/// Canonical native USDOM history recovered from persisted verified data and
/// reauthenticated against one current canonical DOM block header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedUsdomV4HistoryBlock {
    /// Canonical DOM block identifier recomputed from the exact header.
    pub block_identifier: dom_core::Hash256,
    /// Domain-separated identity of the exact canonical proof envelope. This
    /// binds an authenticated submission receipt to canonical inclusion.
    pub candidate_id: dom_core::Hash256,
    /// Exact canonical DOM header bytes whose identifier is `block_identifier`.
    pub header_bytes: Vec<u8>,
    /// Canonical DOM height.
    pub height: u64,
    /// Parent identifier used to validate contiguous trusted-anchor history.
    pub previous_block_identifier: dom_core::Hash256,
    /// DOM timestamp bound into the native batch commitment.
    pub block_timestamp: u64,
    /// Native state root immediately before this block.
    pub previous_state_root: dom_core::Hash256,
    /// Native state root immediately after this block.
    pub new_state_root: dom_core::Hash256,
    /// Ordered Merkle root of all transition commitments.
    pub transitions_root: dom_core::Hash256,
    /// Batch commitment proven equal to the value bound into the DOM header.
    pub batch_header_commitment: dom_core::Hash256,
    /// Ordinary body range-proof root used as the other v4 header-binding input.
    pub raw_rangeproof_root: dom_core::Hash256,
    /// Ordered public transitions and exact optional private payloads.
    pub transitions: Vec<AuthenticatedUsdomV4HistoryTransition>,
}

/// Canonical wire package carrying one ordinary DOM block and the
/// exact native USDOM proof envelope committed by its version-4 header.
///
/// Wire format: `USDOMBL4 || framing_version:u16BE || block_len:u32BE ||
/// proof_envelope_len:u32BE || block || proof_envelope`. The complete package,
/// including framing, is constrained by the existing 16-MiB block ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsdomV4BlockPackage {
    block: Block,
    proof_envelope: UsdomV4ProofEnvelope,
}

/// Canonical read-only input tying one native burn witness to the exact DOM
/// v4 block package and authenticated transition-batch undo that committed its
/// state root. This value proves only the encoded internal relations. A caller
/// must independently authenticate the returned block identifier and establish
/// the required DOM finality before treating the burn as redeemable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeBurnBlockProverInput {
    activation_schedule: NativeUsdomV4ActivationSchedule,
    block_identifier: dom_core::Hash256,
    package_bytes: Vec<u8>,
    undo_bytes: Vec<u8>,
    burn_witness_bytes: Vec<u8>,
}

/// Public values extracted only after every block, batch and burn-state
/// relation in [`NativeBurnBlockProverInput`] has been recomputed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeBurnBlockBinding {
    /// DOM network whose identifier domain was used.
    pub network_magic: u32,
    /// Exact DOM chain identifier ratified for native USDOM activation.
    pub chain_id: dom_core::Hash256,
    /// First height at which version-4 native USDOM semantics are mandatory.
    pub first_v4_height: u64,
    /// Empty native-state root that commits the bridge identity at activation.
    pub activation_empty_state_root: dom_core::Hash256,
    /// Domain-separated commitment to the complete activation schedule.
    pub activation_schedule_commitment: dom_core::Hash256,
    /// Canonical identifier recomputed from the exact serialized header.
    pub block_identifier: dom_core::Hash256,
    /// Declared height of the bound block.
    pub block_height: u64,
    /// Header timestamp also committed by the native transition batch.
    pub block_timestamp: u64,
    /// Native USDOM state root after the bound transition batch.
    pub state_root: dom_core::Hash256,
    /// Transition-batch commitment bound into the block rangeproof root.
    pub batch_header_commitment: dom_core::Hash256,
    /// Domain-separated commitment to every byte of the transported package.
    pub package_commitment: dom_core::Hash256,
    /// Native bridge domain committed by the bound state root.
    pub dom_domain: [u8; 32],
    /// Ethereum consensus identity committed by the bound state root.
    pub ethereum_genesis_validators_root: [u8; 32],
    /// Target Ethereum chain identifier committed by the bound state root.
    pub ethereum_chain_id: [u8; 32],
    /// Immutable reserve address committed by the bound state root.
    pub reserve: [u8; 20],
    /// Immutable Ethereum checkpoint-verifier policy committed by native state.
    pub ethereum_checkpoint_policy_hash: [u8; 32],
    /// Immutable Ethereum deposit-verifier policy committed by native state.
    pub ethereum_deposit_policy_hash: [u8; 32],
    /// Immutable native privacy and note-accumulator policy.
    pub privacy_policy_hash: [u8; 32],
    /// Immutable native spend-verifier configuration.
    pub privacy_verifier_config_hash: [u8; 32],
    /// Exact public burn obligation included in the bound state root.
    pub burn: BurnRecord,
}

/// Result of matching an opaque, cryptographically verified Ethereum
/// checkpoint event to the exact DOM block/state containing a native burn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeBurnCheckpointBinding {
    /// Fully recomputed native burn/block/batch relation.
    pub native: NativeBurnBlockBinding,
    /// Finalized Ethereum execution block that emitted the checkpoint event.
    pub checkpoint_event_execution_block: u64,
    /// Finalized Ethereum execution block hash carrying the event.
    pub checkpoint_event_execution_hash: dom_core::Hash256,
    /// Ethereum receipt position of the authenticated checkpoint log.
    pub checkpoint_transaction_index: u32,
    /// Log position inside the authenticated receipt.
    pub checkpoint_receipt_log_index: u32,
    /// Latest Ethereum-finalized execution block authenticated by the witness.
    pub ethereum_finality_execution_block: u64,
    /// Latest Ethereum-finalized execution block hash.
    pub ethereum_finality_execution_hash: dom_core::Hash256,
    /// Timestamp of the latest authenticated Ethereum-finalized execution.
    pub ethereum_finality_execution_timestamp: u64,
    /// Latest authenticated Ethereum-finalized Beacon slot.
    pub ethereum_finality_beacon_slot: u64,
    /// Latest authenticated Ethereum-finalized Beacon root.
    pub ethereum_finality_beacon_root: dom_core::Hash256,
    /// Digest of the exact authenticated checkpoint event statement.
    pub checkpoint_event_digest: dom_core::Hash256,
}

/// Exact public values hashed by the immutable Ethereum reserve after native
/// burn inclusion and Ethereum-finalized checkpoint authentication succeed.
/// This value exposes no note openings, sender, deposit link or transfer path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedBurnStatement {
    /// Native nullifier-derived burn identifier.
    pub burn_id: [u8; 32],
    /// Wallet-selected globally unique reserve request identifier.
    pub request_id: [u8; 32],
    /// Immutable Ethereum payout address.
    pub recipient: [u8; 20],
    /// Public payout amount in six-decimal base units.
    pub amount: u64,
    /// Native bridge domain committed by the activation state.
    pub dom_domain: [u8; 32],
    /// Height of the authenticated DOM block containing the burn.
    pub height: u64,
    /// Canonical DOM block identifier.
    pub block_hash: dom_core::Hash256,
    /// Native USDOM state root after the containing transition batch.
    pub state_root: dom_core::Hash256,
    /// Latest authenticated Ethereum-finalized Beacon slot.
    pub finality_beacon_slot: u64,
    /// Last Ethereum timestamp at which the reserve may admit the proof.
    pub valid_until: u64,
    /// Target EVM chain identifier as one uint256 big-endian ABI word.
    pub ethereum_chain_id: [u8; 32],
    /// Immutable target reserve address.
    pub reserve: [u8; 20],
    /// Exact UDACTV01 activation schedule selected by the verifier release.
    pub activation_schedule_commitment: dom_core::Hash256,
}

impl FinalizedBurnStatement {
    /// Derive the public statement only from a fully composed native burn and
    /// verified Ethereum checkpoint binding. Cross-domain substitutions fail.
    pub fn from_checkpoint_binding(
        binding: &NativeBurnCheckpointBinding,
    ) -> Result<Self, DomError> {
        let native = binding.native;
        let burn = native.burn;
        if native.dom_domain == [0; 32]
            || native.block_identifier == dom_core::Hash256::ZERO
            || native.state_root == dom_core::Hash256::ZERO
            || native.activation_schedule_commitment == dom_core::Hash256::ZERO
            || native.block_height == 0
            || binding.ethereum_finality_beacon_slot == 0
            || burn.burn_id == [0; 32]
            || burn.request_id == [0; 32]
            || burn.recipient == [0; 20]
            || burn.amount == 0
            || burn.valid_until == 0
            || burn.ethereum_chain_id != native.ethereum_chain_id
            || burn.reserve != native.reserve
            || burn.obligation_commitment != burn.expected_obligation_commitment(native.dom_domain)
        {
            return Err(DomError::Invalid(
                "finalized burn statement does not match the authenticated bridge obligation"
                    .into(),
            ));
        }
        Ok(Self {
            burn_id: burn.burn_id,
            request_id: burn.request_id,
            recipient: burn.recipient,
            amount: burn.amount,
            dom_domain: native.dom_domain,
            height: native.block_height,
            block_hash: native.block_identifier,
            state_root: native.state_root,
            finality_beacon_slot: binding.ethereum_finality_beacon_slot,
            valid_until: burn.valid_until,
            ethereum_chain_id: burn.ethereum_chain_id,
            reserve: burn.reserve,
            activation_schedule_commitment: native.activation_schedule_commitment,
        })
    }

    /// Compute `keccak256(abi.encode(...))` byte-for-byte as Solidity does.
    pub fn statement_hash(&self) -> dom_core::Hash256 {
        let type_hash = Keccak256::digest(FINALIZED_BURN_STATEMENT_TYPE.as_bytes());
        let mut encoded = Vec::with_capacity(14 * 32);
        encoded.extend_from_slice(&type_hash);
        encoded.extend_from_slice(&self.burn_id);
        encoded.extend_from_slice(&self.request_id);
        encoded.extend_from_slice(&[0; 12]);
        encoded.extend_from_slice(&self.recipient);
        encoded.extend_from_slice(&[0; 24]);
        encoded.extend_from_slice(&self.amount.to_be_bytes());
        encoded.extend_from_slice(&self.dom_domain);
        encoded.extend_from_slice(&[0; 24]);
        encoded.extend_from_slice(&self.height.to_be_bytes());
        encoded.extend_from_slice(self.block_hash.as_bytes());
        encoded.extend_from_slice(self.state_root.as_bytes());
        encoded.extend_from_slice(&[0; 24]);
        encoded.extend_from_slice(&self.finality_beacon_slot.to_be_bytes());
        encoded.extend_from_slice(&[0; 24]);
        encoded.extend_from_slice(&self.valid_until.to_be_bytes());
        encoded.extend_from_slice(&self.ethereum_chain_id);
        encoded.extend_from_slice(&[0; 12]);
        encoded.extend_from_slice(&self.reserve);
        encoded.extend_from_slice(self.activation_schedule_commitment.as_bytes());
        dom_core::Hash256::from_bytes(Keccak256::digest(encoded).into())
    }
}

impl NativeBurnBlockProverInput {
    fn new(
        activation_schedule: NativeUsdomV4ActivationSchedule,
        block_identifier: dom_core::Hash256,
        package_bytes: Vec<u8>,
        undo_bytes: Vec<u8>,
        burn_witness_bytes: Vec<u8>,
    ) -> Result<Self, DomError> {
        let input = Self {
            activation_schedule,
            block_identifier,
            package_bytes,
            undo_bytes,
            burn_witness_bytes,
        };
        input.verify_internal_relations()?;
        input.to_bytes()?;
        Ok(input)
    }

    /// Network identifier embedded in this transport. It is not self-authenticating.
    pub fn network_magic(&self) -> u32 {
        self.activation_schedule.network_magic()
    }

    /// Exact activation schedule embedded in the canonical transport.
    pub fn activation_schedule(&self) -> NativeUsdomV4ActivationSchedule {
        self.activation_schedule
    }

    /// DOM header identifier embedded in this transport. It is recomputed by
    /// [`Self::verify`] but still requires an independently trusted checkpoint.
    pub fn block_identifier(&self) -> dom_core::Hash256 {
        self.block_identifier
    }

    /// Exact canonical native-v4 package bytes supplied to the proving system.
    pub fn package_bytes(&self) -> &[u8] {
        &self.package_bytes
    }

    /// Exact canonical authenticated batch-undo bytes supplied to the prover.
    pub fn undo_bytes(&self) -> &[u8] {
        &self.undo_bytes
    }

    /// Exact canonical `USDBRN03` witness bytes supplied to the prover.
    pub fn burn_witness_bytes(&self) -> &[u8] {
        &self.burn_witness_bytes
    }

    /// Verify all internal relations and require an independently selected
    /// network and block identifier. This does not establish PoW fork choice or
    /// additional finality by itself.
    pub fn verify(
        &self,
        expected_schedule: NativeUsdomV4ActivationSchedule,
        expected_block_identifier: dom_core::Hash256,
    ) -> Result<NativeBurnBlockBinding, DomError> {
        if self.activation_schedule != expected_schedule
            || self.block_identifier != expected_block_identifier
        {
            return Err(DomError::Invalid(
                "native burn prover input does not match the trusted block identity".into(),
            ));
        }
        self.verify_internal_relations()
    }

    fn verify_internal_relations(&self) -> Result<NativeBurnBlockBinding, DomError> {
        self.activation_schedule.validate()?;
        let package = UsdomV4BlockPackage::from_bytes(&self.package_bytes)?;
        let block = package.block();
        if block.header.version != BLOCK_VERSION_V4
            || block.header.height.0 < self.activation_schedule.first_v4_height()
        {
            return Err(DomError::Invalid(
                "native burn prover block is outside its activation schedule".into(),
            ));
        }
        let header_bytes = DomSerialize::to_bytes(&block.header)?;
        let computed_identifier = crate::canonical_header_identifier(
            self.activation_schedule.network_magic(),
            &header_bytes,
        )?;
        if computed_identifier != self.block_identifier {
            return Err(DomError::Invalid(
                "native burn prover input block identifier mismatch".into(),
            ));
        }

        let undo = BatchUndo::from_bytes(&self.undo_bytes).map_err(|error| {
            DomError::Malformed(format!("native burn prover batch undo is invalid: {error}"))
        })?;
        if undo.to_bytes().map_err(|error| {
            DomError::Malformed(format!("native burn prover batch undo is invalid: {error}"))
        })? != self.undo_bytes
        {
            return Err(DomError::Malformed(
                "noncanonical native burn prover batch undo".into(),
            ));
        }
        if undo.transition_count() != package.proof_envelope().entries.len() {
            return Err(DomError::Invalid(
                "native burn prover package and batch transition counts differ".into(),
            ));
        }

        let witness = BurnStateWitness::from_bytes(&self.burn_witness_bytes).map_err(|error| {
            DomError::Malformed(format!("native burn-state witness is invalid: {error}"))
        })?;
        if witness.to_bytes().map_err(|error| {
            DomError::Malformed(format!("native burn-state witness is invalid: {error}"))
        })? != self.burn_witness_bytes
        {
            return Err(DomError::Malformed(
                "noncanonical native burn-state witness".into(),
            ));
        }
        let state_root = witness.state.root();
        if !witness.verify(state_root) || undo.after_root() != state_root {
            return Err(DomError::Invalid(
                "native burn witness is not included in the block batch state".into(),
            ));
        }
        let burn = witness.burn.record;
        if burn.ethereum_chain_id != witness.state.ethereum_chain_id
            || burn.reserve != witness.state.reserve
            || burn.obligation_commitment
                != burn.expected_obligation_commitment(witness.state.domain)
        {
            return Err(DomError::Invalid(
                "native burn witness obligation does not match its bridge identity".into(),
            ));
        }
        let witness_bridge = BridgeIdentity {
            dom_domain: witness.state.domain,
            ethereum_genesis_validators_root: witness.state.ethereum_genesis_validators_root,
            ethereum_chain_id: witness.state.ethereum_chain_id,
            ethereum_checkpoint_policy_hash: witness.state.ethereum_checkpoint_policy_hash,
            ethereum_deposit_policy_hash: witness.state.ethereum_deposit_policy_hash,
            privacy_policy_hash: witness.state.privacy_policy_hash,
            privacy_verifier_config_hash: witness.state.privacy_verifier_config_hash,
            reserve: witness.state.reserve,
            burn_timing: witness.state.burn_timing,
        };
        let empty_state = NativeUsdomState::new(witness_bridge).map_err(|error| {
            DomError::Invalid(format!(
                "native burn prover activation bridge is invalid: {error}"
            ))
        })?;
        if empty_state.state_root() != self.activation_schedule.empty_state_root() {
            return Err(DomError::Invalid(
                "native burn prover activation schedule does not commit its bridge identity".into(),
            ));
        }
        if undo.block_timestamp() != block.header.timestamp.0 {
            return Err(DomError::Invalid(
                "native burn batch timestamp does not match the DOM header".into(),
            ));
        }
        let (output_root, kernel_root, raw_rangeproof_root) =
            compute_block_pmmr_roots(block.header.height, &block.coinbase, &block.transactions)?;
        if output_root != block.header.output_root || kernel_root != block.header.kernel_root {
            return Err(DomError::Invalid(
                "native burn prover block body does not match the DOM header roots".into(),
            ));
        }
        let batch_header_commitment = undo
            .header_commitment(witness.state.domain)
            .map_err(|error| DomError::Invalid(format!("invalid native burn batch: {error}")))?;
        if bind_usdom_batch_commitment(raw_rangeproof_root, batch_header_commitment)?
            != block.header.rangeproof_root
        {
            return Err(DomError::Invalid(
                "native burn batch is not committed by the DOM header".into(),
            ));
        }
        validate_block_v4_scheduled(
            block,
            &ValidationContext {
                current_height: block.header.height,
                chain_id: *self.activation_schedule.chain_id().as_bytes(),
                now: Timestamp(u64::MAX),
            },
            self.activation_schedule.network_magic(),
            UsdomV4Commitment {
                batch_header_commitment,
                block_timestamp: block.header.timestamp,
            },
        )
        .map_err(|error| {
            DomError::Invalid(format!(
                "native burn prover block does not match its activation schedule: {error}"
            ))
        })?;

        Ok(NativeBurnBlockBinding {
            network_magic: self.activation_schedule.network_magic(),
            chain_id: self.activation_schedule.chain_id(),
            first_v4_height: self.activation_schedule.first_v4_height(),
            activation_empty_state_root: self.activation_schedule.empty_state_root(),
            activation_schedule_commitment: self.activation_schedule.commitment(),
            block_identifier: computed_identifier,
            block_height: block.header.height.0,
            block_timestamp: block.header.timestamp.0,
            state_root,
            batch_header_commitment,
            package_commitment: blake2b_256_tagged(TAG_USDOM_BLOCK_PACKAGE_V4, &self.package_bytes),
            dom_domain: witness.state.domain,
            ethereum_genesis_validators_root: witness.state.ethereum_genesis_validators_root,
            ethereum_chain_id: witness.state.ethereum_chain_id,
            reserve: witness.state.reserve,
            ethereum_checkpoint_policy_hash: witness.state.ethereum_checkpoint_policy_hash,
            ethereum_deposit_policy_hash: witness.state.ethereum_deposit_policy_hash,
            privacy_policy_hash: witness.state.privacy_policy_hash,
            privacy_verifier_config_hash: witness.state.privacy_verifier_config_hash,
            burn,
        })
    }

    /// Encode the unique bounded `UDBBLK02` transport.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DomError> {
        let package_len: u32 = self
            .package_bytes
            .len()
            .try_into()
            .map_err(|_| DomError::Malformed("native burn package length overflow".into()))?;
        let undo_len: u32 = self
            .undo_bytes
            .len()
            .try_into()
            .map_err(|_| DomError::Malformed("native burn undo length overflow".into()))?;
        let witness_len: u32 = self
            .burn_witness_bytes
            .len()
            .try_into()
            .map_err(|_| DomError::Malformed("native burn witness length overflow".into()))?;
        let total_len = USDOM_V4_BURN_PROVER_HEADER_BYTES
            .checked_add(self.package_bytes.len())
            .and_then(|value| value.checked_add(self.undo_bytes.len()))
            .and_then(|value| value.checked_add(self.burn_witness_bytes.len()))
            .ok_or_else(|| DomError::Malformed("native burn prover length overflow".into()))?;
        if total_len > MAX_NATIVE_BURN_BLOCK_PROVER_INPUT_BYTES {
            return Err(DomError::Malformed(
                "native burn prover input exceeds byte limit".into(),
            ));
        }
        let mut bytes = Vec::with_capacity(total_len);
        bytes.extend_from_slice(USDOM_V4_BURN_PROVER_MAGIC);
        bytes.extend_from_slice(&USDOM_V4_BURN_PROVER_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.activation_schedule.to_bytes());
        bytes.extend_from_slice(self.block_identifier.as_bytes());
        bytes.extend_from_slice(&package_len.to_be_bytes());
        bytes.extend_from_slice(&undo_len.to_be_bytes());
        bytes.extend_from_slice(&witness_len.to_be_bytes());
        bytes.extend_from_slice(&self.package_bytes);
        bytes.extend_from_slice(&self.undo_bytes);
        bytes.extend_from_slice(&self.burn_witness_bytes);
        Ok(bytes)
    }

    /// Decode, canonically re-encode and recompute every internal relation in
    /// one bounded `UDBBLK02` transport.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        if bytes.len() < USDOM_V4_BURN_PROVER_HEADER_BYTES
            || bytes.len() > MAX_NATIVE_BURN_BLOCK_PROVER_INPUT_BYTES
        {
            return Err(DomError::Malformed(
                "invalid native burn prover input framing".into(),
            ));
        }
        let mut reader = Reader::new(bytes);
        if reader.read_bytes(8)? != USDOM_V4_BURN_PROVER_MAGIC {
            return Err(DomError::Malformed(
                "invalid native burn prover input framing".into(),
            ));
        }
        if reader.read_u16_be()? != USDOM_V4_BURN_PROVER_VERSION {
            return Err(DomError::Malformed(
                "unsupported native burn prover input version".into(),
            ));
        }
        let activation_schedule = NativeUsdomV4ActivationSchedule::from_bytes(
            reader.read_bytes(USDOM_V4_ACTIVATION_SCHEDULE_BYTES)?,
        )?;
        let block_identifier = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let package_len = reader.read_u32_be()? as usize;
        let undo_len = reader.read_u32_be()? as usize;
        let witness_len = reader.read_u32_be()? as usize;
        if package_len > MAX_BLOCK_SERIALIZED_SIZE
            || undo_len > MAX_BATCH_UNDO_BYTES
            || witness_len > MAX_BURN_STATE_WITNESS_BYTES
        {
            return Err(DomError::Malformed(
                "native burn prover component exceeds byte limit".into(),
            ));
        }
        let package_bytes = reader.read_bytes(package_len)?.to_vec();
        let undo_bytes = reader.read_bytes(undo_len)?.to_vec();
        let burn_witness_bytes = reader.read_bytes(witness_len)?.to_vec();
        reader.finish()?;
        let input = Self {
            activation_schedule,
            block_identifier,
            package_bytes,
            undo_bytes,
            burn_witness_bytes,
        };
        input.verify_internal_relations()?;
        if input.to_bytes()?.as_slice() != bytes {
            return Err(DomError::Malformed(
                "noncanonical native burn prover input".into(),
            ));
        }
        Ok(input)
    }
}

/// Match one opaque Ethereum-checkpoint verifier result to the exact native
/// burn block/state. Callers cannot substitute decoded checkpoint bytes because
/// [`VerifiedCheckpoint`](usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint)
/// has private fields and is produced by the BLS/SSZ, ancestry, receipt, code
/// and storage verifier. This composition still does not enforce DOM fork
/// choice; consensus installation is a separate required step.
pub fn bind_verified_ethereum_checkpoint_to_native_burn(
    input: &NativeBurnBlockProverInput,
    expected_schedule: NativeUsdomV4ActivationSchedule,
    expected_block_identifier: dom_core::Hash256,
    checkpoint: &usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint,
) -> Result<NativeBurnCheckpointBinding, DomError> {
    let native = input.verify(expected_schedule, expected_block_identifier)?;
    let record = crate::ethereum_checkpoint_poc::decode_test_oracle_v2(checkpoint.record())?;
    let mut chain_id_word = [0u8; 32];
    chain_id_word[24..].copy_from_slice(&record.ethereum_chain_id.to_be_bytes());
    if record.height != native.block_height
        || record.dom_block != native.block_identifier
        || record.dom_state_root != native.state_root
        || record.dom_network_magic != native.network_magic
        || chain_id_word != native.ethereum_chain_id
        || record.ethereum_genesis_validators_root.as_bytes()
            != &native.ethereum_genesis_validators_root
        || record.bridge_domain.as_bytes() != &native.dom_domain
        || checkpoint.trust_policy_hash().as_slice()
            != native.ethereum_checkpoint_policy_hash.as_slice()
    {
        return Err(DomError::Invalid(
            "verified Ethereum checkpoint does not match the native burn block identity".into(),
        ));
    }
    let finalized = checkpoint.finalized_execution();
    if finalized.block_number < record.ethereum_block_number
        || finalized.beacon_slot < record.ethereum_beacon_slot
        || finalized
            .block_hash
            .as_slice()
            .iter()
            .all(|byte| *byte == 0)
        || finalized
            .beacon_root
            .as_slice()
            .iter()
            .all(|byte| *byte == 0)
        || finalized.timestamp == 0
    {
        return Err(DomError::Invalid(
            "verified Ethereum checkpoint has an invalid finality identity".into(),
        ));
    }
    Ok(NativeBurnCheckpointBinding {
        native,
        checkpoint_event_execution_block: record.ethereum_block_number,
        checkpoint_event_execution_hash: record.ethereum_block,
        checkpoint_transaction_index: record.transaction_index,
        checkpoint_receipt_log_index: record.receipt_log_index,
        ethereum_finality_execution_block: finalized.block_number,
        ethereum_finality_execution_hash: dom_core::Hash256::from_bytes(
            finalized.block_hash.into(),
        ),
        ethereum_finality_execution_timestamp: finalized.timestamp,
        ethereum_finality_beacon_slot: finalized.beacon_slot,
        ethereum_finality_beacon_root: dom_core::Hash256::from_bytes(finalized.beacon_root.into()),
        checkpoint_event_digest: record.checkpoint_event_digest,
    })
}

/// Bind a checkpoint verifier capability to a state root independently
/// reconstructed from the carrier's DOM ancestry, then derive the monotonic
/// consensus-state write that must commit atomically with that carrier.
pub(crate) struct NativeCheckpointTarget {
    pub carrier_height: u64,
    pub height: u64,
    pub block: dom_core::Hash256,
    pub state_root: dom_core::Hash256,
}

pub(crate) fn native_checkpoint_floor_update(
    verified: &usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint,
    network_magic: u32,
    bridge: BridgeIdentity,
    target: NativeCheckpointTarget,
    current_floor: Option<crate::ethereum_checkpoint_poc::TestOracleCheckpoint>,
) -> Result<
    (
        crate::ethereum_checkpoint_poc::TestOracleCheckpoint,
        Option<ConsensusStateUpdate>,
    ),
    DomError,
> {
    let checkpoint = crate::ethereum_checkpoint_poc::decode_test_oracle_v2(verified.record())?;
    let mut ethereum_chain_id_word = [0u8; 32];
    ethereum_chain_id_word[24..].copy_from_slice(&checkpoint.ethereum_chain_id.to_be_bytes());
    if checkpoint.height != target.height
        || checkpoint.dom_block != target.block
        || checkpoint.dom_state_root != target.state_root
        || checkpoint.dom_network_magic != network_magic
        || checkpoint.height >= target.carrier_height
        || ethereum_chain_id_word != bridge.ethereum_chain_id
        || checkpoint.ethereum_genesis_validators_root.as_bytes()
            != &bridge.ethereum_genesis_validators_root
        || checkpoint.bridge_domain.as_bytes() != &bridge.dom_domain
        || verified.trust_policy_hash().as_slice()
            != bridge.ethereum_checkpoint_policy_hash.as_slice()
    {
        return Err(DomError::Invalid(
            "consensus-visible checkpoint does not match its DOM ancestry state".into(),
        ));
    }
    if let Some(old) = current_floor {
        if checkpoint == old {
            return Ok((checkpoint, None));
        }
        crate::ethereum_checkpoint_poc::validate_checkpoint_successor(old, checkpoint)?;
    }
    let value = crate::ethereum_checkpoint_poc::encode_test_oracle_v2(checkpoint)?;
    Ok((
        checkpoint,
        Some(ConsensusStateUpdate {
            key: crate::ethereum_checkpoint_poc::CONSENSUS_CHECKPOINT_KEY.to_vec(),
            value: Some(value),
        }),
    ))
}

impl UsdomV4BlockPackage {
    /// Construct a package from typed components and enforce all framing and
    /// combined-size invariants immediately.
    pub fn new(block: Block, proof_envelope: UsdomV4ProofEnvelope) -> Result<Self, DomError> {
        let package = Self {
            block,
            proof_envelope,
        };
        package.to_bytes()?;
        Ok(package)
    }

    /// The canonically decoded ordinary DOM block.
    pub fn block(&self) -> &Block {
        &self.block
    }

    /// The canonically decoded, still-untrusted native USDOM proof envelope.
    pub fn proof_envelope(&self) -> &UsdomV4ProofEnvelope {
        &self.proof_envelope
    }

    /// Encode the unique bounded version-1 package representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DomError> {
        if self.block.header.version != BLOCK_VERSION_V4 {
            return Err(DomError::Invalid(
                "native USDOM block package requires block version 4".into(),
            ));
        }
        let block_bytes = DomSerialize::to_bytes(&self.block)?;
        let proof_bytes = self.proof_envelope.to_bytes()?;
        let block_len: u32 = block_bytes
            .len()
            .try_into()
            .map_err(|_| DomError::Malformed("USDOM v4 block length overflow".into()))?;
        let proof_len: u32 = proof_bytes
            .len()
            .try_into()
            .map_err(|_| DomError::Malformed("USDOM v4 proof-envelope length overflow".into()))?;
        let total_len = USDOM_V4_BLOCK_HEADER_BYTES
            .checked_add(block_bytes.len())
            .and_then(|value| value.checked_add(proof_bytes.len()))
            .ok_or_else(|| DomError::Malformed("USDOM v4 package length overflow".into()))?;
        if total_len > MAX_BLOCK_SERIALIZED_SIZE {
            return Err(DomError::Malformed(
                "native USDOM v4 package exceeds block byte limit".into(),
            ));
        }

        let mut encoded = Vec::with_capacity(total_len);
        encoded.extend_from_slice(USDOM_V4_BLOCK_MAGIC);
        encoded.extend_from_slice(&USDOM_V4_BLOCK_FRAMING_VERSION.to_be_bytes());
        encoded.extend_from_slice(&block_len.to_be_bytes());
        encoded.extend_from_slice(&proof_len.to_be_bytes());
        encoded.extend_from_slice(&block_bytes);
        encoded.extend_from_slice(&proof_bytes);
        Ok(encoded)
    }

    /// Decode canonical framing, enforce the combined byte ceiling before any
    /// proof work, and reject legacy, trailing or ambiguously sized payloads.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        if bytes.len() < USDOM_V4_BLOCK_HEADER_BYTES || bytes.len() > MAX_BLOCK_SERIALIZED_SIZE {
            return Err(DomError::Malformed(
                "invalid native USDOM v4 block-package framing".into(),
            ));
        }
        let mut reader = Reader::new(bytes);
        if reader.read_bytes(8)? != USDOM_V4_BLOCK_MAGIC {
            return Err(DomError::Malformed(
                "invalid native USDOM v4 block-package framing".into(),
            ));
        }
        if reader.read_u16_be()? != USDOM_V4_BLOCK_FRAMING_VERSION {
            return Err(DomError::Malformed(
                "unsupported native USDOM v4 block-package version".into(),
            ));
        }
        let block_len = reader.read_u32_be()? as usize;
        let proof_len = reader.read_u32_be()? as usize;
        if block_len < <Block as DomDeserialize>::MIN_SERIALIZED_SIZE
            || !(USDOM_V4_ENVELOPE_HEADER_BYTES..=MAX_USDOM_V4_ENVELOPE_BYTES).contains(&proof_len)
        {
            return Err(DomError::Malformed(
                "native USDOM v4 package component outside byte limits".into(),
            ));
        }
        let block = <Block as DomDeserialize>::from_bytes(reader.read_bytes(block_len)?)?;
        if block.header.version != BLOCK_VERSION_V4 {
            return Err(DomError::Invalid(
                "native USDOM block package requires block version 4".into(),
            ));
        }
        let proof_envelope = UsdomV4ProofEnvelope::from_bytes(reader.read_bytes(proof_len)?)?;
        reader.finish()?;
        let package = Self {
            block,
            proof_envelope,
        };
        if package.to_bytes()?.as_slice() != bytes {
            return Err(DomError::Malformed(
                "noncanonical native USDOM v4 block package".into(),
            ));
        }
        Ok(package)
    }
}

impl UsdomV4ProofEnvelope {
    /// Canonical empty envelope. Empty batches still commit state continuity.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Read-only untrusted proof classes and payloads in canonical envelope
    /// order. Observing these bytes grants no transition authority; consumers
    /// must rely on the enclosing block's validated canonical-chain status.
    pub fn entries(
        &self,
    ) -> impl ExactSizeIterator<Item = (UsdomV4ProofKind, &[u8])> + DoubleEndedIterator + '_ {
        self.entries
            .iter()
            .map(|entry| (entry.kind, entry.payload.as_slice()))
    }

    /// Parse the public reserve obligations carried by burn entries.
    ///
    /// This grants no proof or transition authority. Callers must first bind
    /// the enclosing package to a verified canonical block and state root.
    pub fn public_burn_records(&self) -> Result<Vec<BurnRecord>, DomError> {
        self.entries
            .iter()
            .filter(|entry| entry.kind == UsdomV4ProofKind::Burn)
            .map(|entry| {
                inspect_private_burn_record(&entry.payload).map_err(|error| {
                    DomError::Malformed(format!(
                        "native USDOM burn payload record is malformed: {error}"
                    ))
                })
            })
            .collect()
    }

    fn single(kind: UsdomV4ProofKind, payload: Vec<u8>) -> Result<Self, DomError> {
        validate_entry_payload(kind, &payload)?;
        let envelope = Self {
            entries: vec![UsdomV4ProofEntry { kind, payload }],
        };
        envelope.to_bytes()?;
        Ok(envelope)
    }

    /// Wrap one untrusted finalized-deposit witness. Every node independently
    /// authenticates the Ethereum finality, receipt, reserve code and event.
    pub fn issuance_witness(witness: Vec<u8>) -> Result<Self, DomError> {
        Self::single(UsdomV4ProofKind::Issuance, witness)
    }

    /// Wrap one canonical private-transfer proof payload. Construction checks
    /// framing bounds only; Groth16 authority is granted during candidate
    /// verification with the bridge-committed key.
    pub fn private_transfer_proof(payload: Vec<u8>) -> Result<Self, DomError> {
        Self::single(UsdomV4ProofKind::Transfer, payload)
    }

    /// Wrap one canonical private-burn proof payload. Construction checks
    /// framing bounds only; the exact public burn obligation and Groth16 proof
    /// are verified during candidate validation.
    pub fn private_burn_proof(payload: Vec<u8>) -> Result<Self, DomError> {
        Self::single(UsdomV4ProofKind::Burn, payload)
    }

    /// Wrap one untrusted checkpoint witness. Cryptographic verification occurs
    /// only in [`verify_usdom_v4_serialized_candidate_regtest`].
    pub fn checkpoint_witness(witness: Vec<u8>) -> Result<Self, DomError> {
        Self::single(UsdomV4ProofKind::EthereumCheckpoint, witness)
    }

    /// Wrap one untrusted irreversible issuance-closure witness. Construction
    /// enforces only canonical envelope bounds; every node verifies Ethereum
    /// finality, the event and reserve post-state before granting authority.
    pub fn issuance_closure_witness(witness: Vec<u8>) -> Result<Self, DomError> {
        Self::single(UsdomV4ProofKind::IssuanceClosure, witness)
    }

    /// Wrap the exact native domain as an orderly-shutdown request. Consensus
    /// independently requires issuance closure and zero outstanding supply.
    pub fn graceful_shutdown(dom_domain: [u8; 32]) -> Result<Self, DomError> {
        Self::single(UsdomV4ProofKind::GracefulShutdown, dom_domain.to_vec())
    }

    /// Encode the unique version-1 wire representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DomError> {
        validate_envelope_entries(&self.entries)?;
        let count: u32 = self
            .entries
            .len()
            .try_into()
            .map_err(|_| DomError::Malformed("USDOM v4 envelope count overflow".into()))?;
        let mut encoded = Vec::with_capacity(USDOM_V4_ENVELOPE_HEADER_BYTES);
        encoded.extend_from_slice(USDOM_V4_ENVELOPE_MAGIC);
        encoded.extend_from_slice(&USDOM_V4_ENVELOPE_VERSION.to_be_bytes());
        encoded.extend_from_slice(&count.to_be_bytes());
        for entry in &self.entries {
            let payload_len: u32 = entry
                .payload
                .len()
                .try_into()
                .map_err(|_| DomError::Malformed("USDOM v4 proof length overflow".into()))?;
            encoded.push(entry.kind.discriminator());
            encoded.extend_from_slice(&payload_len.to_be_bytes());
            encoded.extend_from_slice(&entry.payload);
        }
        if encoded.len() > MAX_USDOM_V4_ENVELOPE_BYTES {
            return Err(DomError::Malformed(
                "native USDOM v4 envelope exceeds byte limit".into(),
            ));
        }
        Ok(encoded)
    }

    /// Decode only the canonical bounded framing. Proof payloads remain
    /// untrusted and receive no authority from this operation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        if bytes.len() < USDOM_V4_ENVELOPE_HEADER_BYTES || bytes.len() > MAX_USDOM_V4_ENVELOPE_BYTES
        {
            return Err(DomError::Malformed(
                "invalid native USDOM v4 envelope framing".into(),
            ));
        }
        let mut reader = Reader::new(bytes);
        if reader.read_bytes(8)? != USDOM_V4_ENVELOPE_MAGIC {
            return Err(DomError::Malformed(
                "invalid native USDOM v4 envelope framing".into(),
            ));
        }
        if reader.read_u16_be()? != USDOM_V4_ENVELOPE_VERSION {
            return Err(DomError::Malformed(
                "unsupported native USDOM v4 envelope version".into(),
            ));
        }
        let count = reader.read_u32_be()? as usize;
        if count > MAX_TRANSITIONS_PER_BATCH {
            return Err(DomError::Malformed(
                "too many native USDOM v4 proof entries".into(),
            ));
        }
        let minimum_len = USDOM_V4_ENVELOPE_HEADER_BYTES
            .checked_add(count.checked_mul(5).ok_or_else(|| {
                DomError::Malformed("native USDOM v4 proof count overflow".into())
            })?)
            .ok_or_else(|| DomError::Malformed("native USDOM v4 proof size overflow".into()))?;
        if bytes.len() < minimum_len {
            return Err(DomError::Malformed(
                "truncated native USDOM v4 proof entries".into(),
            ));
        }

        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = UsdomV4ProofKind::from_discriminator(reader.read_u8()?)?;
            let payload_len = reader.read_u32_be()? as usize;
            if payload_len == 0 || payload_len > MAX_USDOM_V4_PROOF_BYTES {
                return Err(DomError::Malformed(
                    "invalid native USDOM v4 proof length".into(),
                ));
            }
            let payload = reader.read_bytes(payload_len)?.to_vec();
            validate_entry_payload(kind, &payload)?;
            entries.push(UsdomV4ProofEntry { kind, payload });
        }
        reader.finish()?;
        validate_envelope_entries(&entries)?;
        let envelope = Self { entries };
        if envelope.to_bytes()?.as_slice() != bytes {
            return Err(DomError::Malformed(
                "noncanonical native USDOM v4 envelope".into(),
            ));
        }
        Ok(envelope)
    }
}

/// Canonical bounded collection of candidate-v2 state openings for one block.
///
/// These bytes grant no transition authority. They become meaningful only
/// after the corresponding proof envelope has produced opaque verified
/// transitions and the DOM header commits the resulting state-root receipt.
#[derive(Debug, Clone)]
pub struct UsdomV2ExecutionWitnesses {
    witnesses: Vec<NativeTransitionWitness>,
}

impl UsdomV2ExecutionWitnesses {
    /// Construct and size-check one ordered witness bundle.
    pub fn new(witnesses: Vec<NativeTransitionWitness>) -> Result<Self, DomError> {
        if witnesses.len() > MAX_TRANSITIONS_PER_BATCH {
            return Err(DomError::Invalid(
                "too many native USDOM v2 execution witnesses".into(),
            ));
        }
        let bundle = Self { witnesses };
        bundle.to_bytes()?;
        Ok(bundle)
    }

    /// Ordered witnesses consumed by the stateless transition executor.
    pub fn witnesses(&self) -> &[NativeTransitionWitness] {
        &self.witnesses
    }

    /// Commitment to the exact canonical witness bytes persisted for replay.
    pub fn commitment(&self) -> Result<dom_core::Hash256, DomError> {
        Ok(blake2b_256_tagged(
            TAG_USDOM_V2_WITNESS_BUNDLE,
            &self.to_bytes()?,
        ))
    }

    /// Encode the unique bounded `UDV2W001` witness bundle.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DomError> {
        if self.witnesses.len() > MAX_TRANSITIONS_PER_BATCH {
            return Err(DomError::Invalid(
                "too many native USDOM v2 execution witnesses".into(),
            ));
        }
        let count: u32 = self
            .witnesses
            .len()
            .try_into()
            .map_err(|_| DomError::Invalid("native USDOM v2 witness count overflow".into()))?;
        let mut bytes = Vec::with_capacity(USDOM_V2_WITNESS_BUNDLE_HEADER_BYTES);
        bytes.extend_from_slice(USDOM_V2_WITNESS_BUNDLE_MAGIC);
        bytes.extend_from_slice(&USDOM_V2_WITNESS_BUNDLE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        for witness in &self.witnesses {
            let encoded = witness.to_bytes().map_err(|error| {
                DomError::Invalid(format!("native USDOM v2 witness encoding failed: {error}"))
            })?;
            if encoded.is_empty() || encoded.len() > MAX_NATIVE_TRANSITION_WITNESS_BYTES {
                return Err(DomError::Invalid(
                    "native USDOM v2 witness exceeds its class limit".into(),
                ));
            }
            let length: u32 = encoded
                .len()
                .try_into()
                .map_err(|_| DomError::Invalid("native USDOM v2 witness length overflow".into()))?;
            let next_len = bytes
                .len()
                .checked_add(4)
                .and_then(|value| value.checked_add(encoded.len()))
                .ok_or_else(|| DomError::Invalid("native USDOM v2 witness size overflow".into()))?;
            if next_len > MAX_USDOM_V2_WITNESS_BUNDLE_BYTES {
                return Err(DomError::Invalid(
                    "native USDOM v2 witness bundle exceeds byte limit".into(),
                ));
            }
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(&encoded);
        }
        Ok(bytes)
    }

    /// Decode, validate and canonically re-encode one `UDV2W001` bundle.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        if bytes.len() < USDOM_V2_WITNESS_BUNDLE_HEADER_BYTES
            || bytes.len() > MAX_USDOM_V2_WITNESS_BUNDLE_BYTES
        {
            return Err(DomError::Malformed(
                "invalid native USDOM v2 witness bundle framing".into(),
            ));
        }
        let mut reader = Reader::new(bytes);
        if reader.read_bytes(8)? != USDOM_V2_WITNESS_BUNDLE_MAGIC
            || reader.read_u16_be()? != USDOM_V2_WITNESS_BUNDLE_VERSION
        {
            return Err(DomError::Malformed(
                "invalid native USDOM v2 witness bundle framing".into(),
            ));
        }
        let count = reader.read_u32_be()? as usize;
        if count > MAX_TRANSITIONS_PER_BATCH {
            return Err(DomError::Malformed(
                "too many native USDOM v2 execution witnesses".into(),
            ));
        }
        let minimum_len = USDOM_V2_WITNESS_BUNDLE_HEADER_BYTES
            .checked_add(count.checked_mul(5).ok_or_else(|| {
                DomError::Malformed("native USDOM v2 witness count overflow".into())
            })?)
            .ok_or_else(|| DomError::Malformed("native USDOM v2 witness size overflow".into()))?;
        if bytes.len() < minimum_len {
            return Err(DomError::Malformed(
                "truncated native USDOM v2 execution witnesses".into(),
            ));
        }
        let mut witnesses = Vec::with_capacity(count);
        for _ in 0..count {
            let length = reader.read_u32_be()? as usize;
            if length == 0 || length > MAX_NATIVE_TRANSITION_WITNESS_BYTES {
                return Err(DomError::Malformed(
                    "native USDOM v2 witness exceeds its class limit".into(),
                ));
            }
            let witness = NativeTransitionWitness::from_bytes(reader.read_bytes(length)?).map_err(
                |error| DomError::Malformed(format!("invalid native USDOM v2 witness: {error}")),
            )?;
            witnesses.push(witness);
        }
        reader.finish()?;
        let bundle = Self { witnesses };
        if bundle.to_bytes()?.as_slice() != bytes {
            return Err(DomError::Malformed(
                "noncanonical native USDOM v2 witness bundle".into(),
            ));
        }
        Ok(bundle)
    }
}

/// Immutable side-branch recovery bytes for one candidate-v2 block. The proof
/// envelope grants transition authority only after verification; the witness
/// bundle opens the independently authenticated previous V2 state.
#[derive(Debug, Clone)]
pub struct UsdomV2BlockSidecar {
    proof_envelope: UsdomV4ProofEnvelope,
    witnesses: UsdomV2ExecutionWitnesses,
}

impl UsdomV2BlockSidecar {
    /// Construct and bound one exact proof-and-witness sidecar.
    pub fn new(
        proof_envelope: UsdomV4ProofEnvelope,
        witnesses: UsdomV2ExecutionWitnesses,
    ) -> Result<Self, DomError> {
        let sidecar = Self {
            proof_envelope,
            witnesses,
        };
        sidecar.to_bytes()?;
        Ok(sidecar)
    }

    /// Untrusted proof envelope retained for package reconstruction.
    pub fn proof_envelope(&self) -> &UsdomV4ProofEnvelope {
        &self.proof_envelope
    }

    /// Ordered candidate-v2 state openings retained for deterministic replay.
    pub fn witnesses(&self) -> &UsdomV2ExecutionWitnesses {
        &self.witnesses
    }

    /// Encode the unique bounded `UDV2SC01` sidecar.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DomError> {
        let proof = self.proof_envelope.to_bytes()?;
        let witnesses = self.witnesses.to_bytes()?;
        let proof_len: u32 = proof
            .len()
            .try_into()
            .map_err(|_| DomError::Invalid("native USDOM v2 proof length overflow".into()))?;
        let witness_len: u32 = witnesses
            .len()
            .try_into()
            .map_err(|_| DomError::Invalid("native USDOM v2 witness length overflow".into()))?;
        let total = USDOM_V2_BLOCK_SIDECAR_HEADER_BYTES
            .checked_add(proof.len())
            .and_then(|value| value.checked_add(witnesses.len()))
            .ok_or_else(|| DomError::Invalid("native USDOM v2 sidecar length overflow".into()))?;
        if total > MAX_BLOCK_SERIALIZED_SIZE {
            return Err(DomError::Invalid(
                "native USDOM v2 sidecar exceeds block byte limit".into(),
            ));
        }
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(USDOM_V2_BLOCK_SIDECAR_MAGIC);
        bytes.extend_from_slice(&USDOM_V2_BLOCK_SIDECAR_VERSION.to_be_bytes());
        bytes.extend_from_slice(&proof_len.to_be_bytes());
        bytes.extend_from_slice(&witness_len.to_be_bytes());
        bytes.extend_from_slice(&proof);
        bytes.extend_from_slice(&witnesses);
        Ok(bytes)
    }

    /// Decode, validate and canonically re-encode one `UDV2SC01` sidecar.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        if bytes.len() < USDOM_V2_BLOCK_SIDECAR_HEADER_BYTES
            || bytes.len() > MAX_BLOCK_SERIALIZED_SIZE
        {
            return Err(DomError::Malformed(
                "invalid native USDOM v2 sidecar framing".into(),
            ));
        }
        let mut reader = Reader::new(bytes);
        if reader.read_bytes(8)? != USDOM_V2_BLOCK_SIDECAR_MAGIC
            || reader.read_u16_be()? != USDOM_V2_BLOCK_SIDECAR_VERSION
        {
            return Err(DomError::Malformed(
                "invalid native USDOM v2 sidecar framing".into(),
            ));
        }
        let proof_len = reader.read_u32_be()? as usize;
        let witness_len = reader.read_u32_be()? as usize;
        let sidecar = Self {
            proof_envelope: UsdomV4ProofEnvelope::from_bytes(reader.read_bytes(proof_len)?)?,
            witnesses: UsdomV2ExecutionWitnesses::from_bytes(reader.read_bytes(witness_len)?)?,
        };
        reader.finish()?;
        if sidecar.to_bytes()?.as_slice() != bytes {
            return Err(DomError::Malformed(
                "noncanonical native USDOM v2 sidecar".into(),
            ));
        }
        Ok(sidecar)
    }
}

fn validate_entry_payload(kind: UsdomV4ProofKind, payload: &[u8]) -> Result<(), DomError> {
    if payload.is_empty() || payload.len() > MAX_USDOM_V4_PROOF_BYTES {
        return Err(DomError::Malformed(
            "native USDOM v4 proof payload outside byte limits".into(),
        ));
    }
    if kind == UsdomV4ProofKind::GracefulShutdown && payload.len() != 32 {
        return Err(DomError::Malformed(
            "graceful shutdown payload must be the exact native domain".into(),
        ));
    }
    let class_limit = match kind {
        UsdomV4ProofKind::Issuance => MAX_DEPOSIT_WITNESS_BYTES,
        UsdomV4ProofKind::Transfer => MAX_PRIVATE_TRANSFER_PAYLOAD_BYTES,
        UsdomV4ProofKind::Burn => MAX_PRIVATE_BURN_PAYLOAD_BYTES,
        UsdomV4ProofKind::EthereumCheckpoint => MAX_CHECKPOINT_WITNESS_BYTES,
        UsdomV4ProofKind::IssuanceClosure => MAX_ISSUANCE_CLOSURE_WITNESS_BYTES,
        UsdomV4ProofKind::GracefulShutdown => 32,
    };
    if payload.len() > class_limit {
        return Err(DomError::Malformed(format!(
            "native USDOM {:?} payload exceeds its class byte limit",
            kind
        )));
    }
    Ok(())
}

fn validate_envelope_entries(entries: &[UsdomV4ProofEntry]) -> Result<(), DomError> {
    if entries.len() > MAX_TRANSITIONS_PER_BATCH {
        return Err(DomError::Malformed(
            "too many native USDOM v4 proof entries".into(),
        ));
    }
    let checkpoints = entries
        .iter()
        .filter(|entry| entry.kind == UsdomV4ProofKind::EthereumCheckpoint)
        .count();
    let issuances = entries
        .iter()
        .filter(|entry| entry.kind == UsdomV4ProofKind::Issuance)
        .count();
    let issuance_closures = entries
        .iter()
        .filter(|entry| entry.kind == UsdomV4ProofKind::IssuanceClosure)
        .count();
    let graceful_shutdowns = entries
        .iter()
        .filter(|entry| entry.kind == UsdomV4ProofKind::GracefulShutdown)
        .count();
    let private_spends = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.kind,
                UsdomV4ProofKind::Transfer | UsdomV4ProofKind::Burn
            )
        })
        .count();
    if checkpoints > MAX_CHECKPOINTS_PER_ENVELOPE {
        return Err(DomError::Malformed(
            "multiple Ethereum checkpoints in one USDOM v4 envelope".into(),
        ));
    }
    if issuances > MAX_ISSUANCES_PER_ENVELOPE {
        return Err(DomError::Malformed(
            "too many Ethereum deposit proofs in one USDOM v4 envelope".into(),
        ));
    }
    if issuance_closures > MAX_ISSUANCE_CLOSURES_PER_ENVELOPE {
        return Err(DomError::Malformed(
            "multiple issuance closures in one USDOM v4 envelope".into(),
        ));
    }
    if graceful_shutdowns > 1 {
        return Err(DomError::Malformed(
            "multiple graceful shutdowns in one USDOM v4 envelope".into(),
        ));
    }
    if private_spends > MAX_PRIVATE_SPENDS_PER_ENVELOPE {
        return Err(DomError::Malformed(
            "too many private spend proofs in one USDOM v4 envelope".into(),
        ));
    }
    // An exact repeated proof can never yield a second valid transition: an
    // issuance repeats its deposit, while a transfer/burn repeats nullifiers.
    // Reject it before any Ethereum or Groth16 verification. The borrowed
    // ordered key is allocation-free and deterministic across nodes.
    let mut unique_entries = BTreeSet::new();
    for entry in entries {
        validate_entry_payload(entry.kind, &entry.payload)?;
        if !unique_entries.insert((entry.kind.discriminator(), entry.payload.as_slice())) {
            return Err(DomError::Malformed(
                "duplicate native USDOM v4 proof entry".into(),
            ));
        }
    }
    Ok(())
}

/// Opaque result tying one body-valid Regtest v4 candidate to the exact native
/// USDOM state candidate, batch receipt and rollback record it commits.
///
/// ```compile_fail
/// use dom_chain::VerifiedUsdomV4Candidate;
/// fn forge() -> VerifiedUsdomV4Candidate {
///     VerifiedUsdomV4Candidate { next_state: todo!(), receipt: todo!(), undo: todo!() }
/// }
/// ```
#[derive(Debug)]
pub struct VerifiedUsdomV4Candidate {
    network_magic: u32,
    block_identifier: dom_core::Hash256,
    package_commitment: dom_core::Hash256,
    next_state: NativeUsdomState,
    receipt: TransitionBatchReceipt,
    undo: BatchUndo,
    verified_checkpoint:
        Option<usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint>,
}

impl VerifiedUsdomV4Candidate {
    /// Canonical DOM identifier of the exact block header that was validated.
    pub fn block_identifier(&self) -> dom_core::Hash256 {
        self.block_identifier
    }

    /// Domain-separated commitment to every byte of the canonical block
    /// package, including the proof envelope that created this capability.
    pub fn package_commitment(&self) -> dom_core::Hash256 {
        self.package_commitment
    }

    /// Derive the complete deterministic extension-state mutation set for an
    /// atomic block commit. The exact package that created this capability is
    /// required again and its envelope is chunked under the store's 4-MiB
    /// per-value ceiling so restart and future IBD can replay the proof bytes.
    pub(crate) fn consensus_state_updates(
        &self,
        current_state: &NativeUsdomState,
        package_bytes: &[u8],
    ) -> Result<Vec<ConsensusStateUpdate>, DomError> {
        if current_state.state_root() != self.receipt.previous_state_root
            || self.next_state.state_root() != self.receipt.new_state_root
            || blake2b_256_tagged(TAG_USDOM_BLOCK_PACKAGE_V4, package_bytes)
                != self.package_commitment
        {
            return Err(DomError::Invalid(
                "native USDOM verified capability does not match persistence input".into(),
            ));
        }
        let mut updates: Vec<_> = self
            .next_state
            .storage_delta_from(current_state)
            .map_err(|error| {
                DomError::Invalid(format!("native USDOM state delta failed: {error}"))
            })?
            .into_iter()
            .map(|update| ConsensusStateUpdate {
                key: update.key,
                value: update.value,
            })
            .collect();

        updates.extend(package_persistence_updates(
            self.network_magic,
            self.block_identifier,
            self.package_commitment,
            package_bytes,
        )?);
        updates.push(ConsensusStateUpdate {
            key: persistence_key(USDOM_V4_UNDO_PREFIX, self.block_identifier),
            value: Some(self.undo.to_bytes().map_err(|error| {
                DomError::Invalid(format!("native USDOM undo encoding failed: {error}"))
            })?),
        });
        updates.push(ConsensusStateUpdate {
            key: USDOM_V4_TIP_KEY.to_vec(),
            value: Some(tip_value(
                self.block_identifier,
                self.receipt.new_state_root,
                self.package_commitment,
            )),
        });
        validate_consensus_state_updates(&updates)?;
        Ok(updates)
    }

    /// Persist the authenticated undo and final tip marker for a package whose
    /// exact proof envelope already lives in the immutable block-sidecar
    /// relation. Reorg callers collapse the returned tip markers so only the
    /// promoted tip survives, and derive one final state delta from the old
    /// canonical state to the fully replayed branch state.
    pub(crate) fn sidecar_reorg_persistence_updates(
        &self,
        package_bytes: &[u8],
    ) -> Result<Vec<ConsensusStateUpdate>, DomError> {
        if self.next_state.state_root() != self.receipt.new_state_root
            || blake2b_256_tagged(TAG_USDOM_BLOCK_PACKAGE_V4, package_bytes)
                != self.package_commitment
        {
            return Err(DomError::Invalid(
                "native USDOM verified capability does not match sidecar persistence input".into(),
            ));
        }
        let package = UsdomV4BlockPackage::from_bytes(package_bytes)?;
        let header_bytes = DomSerialize::to_bytes(&package.block().header)?;
        if crate::canonical_header_identifier(self.network_magic, &header_bytes)?
            != self.block_identifier
        {
            return Err(DomError::Invalid(
                "native USDOM sidecar package block identifier changed before persistence".into(),
            ));
        }
        let updates = vec![
            ConsensusStateUpdate {
                key: persistence_key(USDOM_V4_UNDO_PREFIX, self.block_identifier),
                value: Some(self.undo.to_bytes().map_err(|error| {
                    DomError::Invalid(format!("native USDOM undo encoding failed: {error}"))
                })?),
            },
            ConsensusStateUpdate {
                key: USDOM_V4_TIP_KEY.to_vec(),
                value: Some(tip_value(
                    self.block_identifier,
                    self.receipt.new_state_root,
                    self.package_commitment,
                )),
            },
        ];
        validate_consensus_state_updates(&updates)?;
        Ok(updates)
    }

    /// Candidate state after the committed ordered batch.
    pub fn next_state(&self) -> &NativeUsdomState {
        &self.next_state
    }

    /// Authenticated transition-batch receipt bound into the DOM header.
    pub fn receipt(&self) -> TransitionBatchReceipt {
        self.receipt
    }

    /// Authenticated checkpoint carried by this exact block package, if any.
    /// The opaque verifier result remains inseparable from the candidate until
    /// ChainState validates its asserted DOM block/state and commits the floor.
    pub fn verified_checkpoint(
        &self,
    ) -> Option<&usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint> {
        self.verified_checkpoint.as_ref()
    }
}

fn persistence_key(prefix: &[u8], block_identifier: dom_core::Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 32);
    key.extend_from_slice(prefix);
    key.extend_from_slice(block_identifier.as_bytes());
    key
}

pub(crate) fn native_usdom_v4_undo_key(block_identifier: dom_core::Hash256) -> Vec<u8> {
    persistence_key(USDOM_V4_UNDO_PREFIX, block_identifier)
}

fn v2_burn_archive_key(burn_id: [u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(USDOM_V2_BURN_ARCHIVE_PREFIX.len() + burn_id.len());
    key.extend_from_slice(USDOM_V2_BURN_ARCHIVE_PREFIX);
    key.extend_from_slice(&burn_id);
    key
}

pub(crate) fn v2_burn_archive_delete_key(burn_id: [u8; 32]) -> Vec<u8> {
    v2_burn_archive_key(burn_id)
}

fn v2_burn_archive_update(
    block_height: u64,
    block_identifier: dom_core::Hash256,
    burn: BurnRecord,
) -> Result<ConsensusStateUpdate, DomError> {
    if block_identifier == dom_core::Hash256::ZERO || burn.burn_id == [0; 32] {
        return Err(DomError::Invalid(
            "invalid native USDOM V2 burn archive identity".into(),
        ));
    }
    let mut value = Vec::with_capacity(USDOM_V2_BURN_ARCHIVE_BYTES);
    value.extend_from_slice(USDOM_V2_BURN_ARCHIVE_MAGIC);
    value.extend_from_slice(&block_height.to_be_bytes());
    value.extend_from_slice(block_identifier.as_bytes());
    value.extend_from_slice(&burn.to_bytes());
    if value.len() != USDOM_V2_BURN_ARCHIVE_BYTES {
        return Err(DomError::Internal(
            "native USDOM V2 burn archive width changed".into(),
        ));
    }
    Ok(ConsensusStateUpdate {
        key: v2_burn_archive_key(burn.burn_id),
        value: Some(value),
    })
}

fn decode_v2_burn_archive_value(
    value: &[u8],
) -> Result<(u64, dom_core::Hash256, BurnRecord), DomError> {
    if value.len() != USDOM_V2_BURN_ARCHIVE_BYTES {
        return Err(DomError::Internal(
            "persisted native USDOM V2 burn archive is malformed".into(),
        ));
    }
    (|| {
        let mut reader = Reader::new(value);
        if reader.read_bytes(8)? != USDOM_V2_BURN_ARCHIVE_MAGIC {
            return Err(DomError::Malformed("invalid V2 burn archive magic".into()));
        }
        let height = reader.read_u64_be()?;
        let block = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let burn =
            BurnRecord::from_bytes(reader.read_bytes(USDOM_V2_BURN_ARCHIVE_BYTES - 8 - 8 - 32)?)
                .map_err(|error| {
                    DomError::Malformed(format!("invalid V2 burn archive record: {error}"))
                })?;
        reader.finish()?;
        Ok((height, block, burn))
    })()
    .map_err(|error: DomError| {
        DomError::Internal(format!(
            "persisted native USDOM V2 burn archive is malformed: {error}"
        ))
    })
}

fn load_v2_burn_archive_at_height(
    store: &DomStore,
    checkpoint_height: u64,
) -> Result<Vec<BurnRecord>, DomError> {
    let all = store.read_all_consensus_state_raw()?;
    let mut records = Vec::new();
    for (key, value) in all
        .range(USDOM_V2_BURN_ARCHIVE_PREFIX.to_vec()..)
        .take_while(|(key, _)| key.starts_with(USDOM_V2_BURN_ARCHIVE_PREFIX))
    {
        if key.len() != USDOM_V2_BURN_ARCHIVE_PREFIX.len() + 32 {
            return Err(DomError::Internal(
                "persisted native USDOM V2 burn archive key is malformed".into(),
            ));
        }
        let (height, block, burn) = decode_v2_burn_archive_value(value)?;
        if key[USDOM_V2_BURN_ARCHIVE_PREFIX.len()..] != burn.burn_id {
            return Err(DomError::Internal(
                "persisted native USDOM V2 burn archive key disagrees with its record".into(),
            ));
        }
        if height <= checkpoint_height {
            if store.get_hash_at_height(height)? != Some(*block.as_bytes()) {
                return Err(DomError::Internal(
                    "persisted native USDOM V2 burn archive is not canonical".into(),
                ));
            }
            records.push(burn);
        }
    }
    Ok(records)
}

/// Delete the one V1 rollback record that has just moved beyond the rolling
/// finality window. Packages remain available for proof/history recovery; only
/// mutable-state undo is bounded here. The update is intended to share the
/// atomic transaction that installs `new_tip_height`.
pub(crate) fn native_usdom_v4_undo_retention_update(
    store: &DomStore,
    new_tip_height: u64,
) -> Result<Option<ConsensusStateUpdate>, DomError> {
    let Some(prune_height) = new_tip_height.checked_sub(crate::reorg::MAX_REORG_DEPTH) else {
        return Ok(None);
    };
    let block_identifier = store.get_hash_at_height(prune_height)?.ok_or_else(|| {
        DomError::Internal(format!(
            "native USDOM undo-retention height {prune_height} is missing"
        ))
    })?;
    let key = persistence_key(
        USDOM_V4_UNDO_PREFIX,
        dom_core::Hash256::from_bytes(block_identifier),
    );
    if store.get_consensus_state(&key)?.is_none() {
        return Ok(None);
    }
    Ok(Some(ConsensusStateUpdate { key, value: None }))
}

fn v2_prune_cursor_value(next_height: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(16);
    value.extend_from_slice(USDOM_V2_PRUNE_CURSOR_MAGIC);
    value.extend_from_slice(&next_height.to_be_bytes());
    value
}

fn decode_v2_prune_cursor(value: &[u8]) -> Result<u64, DomError> {
    if value.len() != 16 {
        return Err(DomError::Internal(
            "persisted native USDOM V2 prune cursor is malformed".into(),
        ));
    }
    (|| {
        let mut reader = Reader::new(value);
        if reader.read_bytes(8)? != USDOM_V2_PRUNE_CURSOR_MAGIC {
            return Err(DomError::Malformed("invalid V2 prune cursor magic".into()));
        }
        let next_height = reader.read_u64_be()?;
        reader.finish()?;
        Ok(next_height)
    })()
    .map_err(|error: DomError| {
        DomError::Internal(format!(
            "persisted native USDOM V2 prune cursor is malformed: {error}"
        ))
    })
}

fn decode_persisted_chunk_metadata(
    meta: &[u8],
    expected_len: usize,
    expected_version: u16,
    label: &str,
) -> Result<(dom_core::Hash256, u32, u16), DomError> {
    if meta.len() != expected_len {
        return Err(DomError::Internal(format!(
            "malformed persisted native USDOM {label} metadata"
        )));
    }
    (|| {
        let mut reader = Reader::new(meta);
        if reader.read_u16_be()? != expected_version {
            return Err(DomError::Malformed(format!(
                "unsupported persisted USDOM {label} metadata version"
            )));
        }
        let commitment = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let payload_len = reader.read_u32_be()?;
        let chunk_count = reader.read_u16_be()?;
        reader.finish()?;
        Ok((commitment, payload_len, chunk_count))
    })()
    .map_err(|error: DomError| {
        DomError::Internal(format!(
            "malformed persisted native USDOM {label} metadata: {error}"
        ))
    })
}

fn chunk_count_from_meta(
    meta: &[u8],
    expected_len: usize,
    expected_version: u16,
    label: &str,
) -> Result<u16, DomError> {
    decode_persisted_chunk_metadata(meta, expected_len, expected_version, label)
        .map(|(_, _, chunk_count)| chunk_count)
}

/// Remove canonical package chunks when a block is disconnected after its
/// proof envelope has been copied into the immutable sidecar relation by the
/// same reorganization transaction.
pub(crate) fn native_usdom_v4_disconnected_package_deletion_updates(
    store: &DomStore,
    block: dom_core::Hash256,
) -> Result<Vec<ConsensusStateUpdate>, DomError> {
    let mut updates = Vec::new();
    let package_meta_key = persistence_key(USDOM_V4_PACKAGE_META_PREFIX, block);
    if let Some(meta) = store.get_consensus_state(&package_meta_key)? {
        let chunks = chunk_count_from_meta(
            &meta,
            USDOM_V4_PACKAGE_META_BYTES,
            USDOM_V4_PERSISTENCE_VERSION,
            "package",
        )?;
        updates.push(ConsensusStateUpdate {
            key: package_meta_key,
            value: None,
        });
        for index in 0..chunks {
            updates.push(ConsensusStateUpdate {
                key: package_chunk_key(block, index),
                value: None,
            });
        }
    }
    validate_consensus_state_updates(&updates)?;
    Ok(updates)
}

/// Remove canonical-only V2 replay keys when a block is disconnected after its
/// proof envelope and witnesses have been copied into the immutable sidecar
/// relation by the same reorganization transaction.
pub(crate) fn native_usdom_v2_disconnected_replay_deletion_updates(
    store: &DomStore,
    block: dom_core::Hash256,
) -> Result<Vec<ConsensusStateUpdate>, DomError> {
    let mut updates = native_usdom_v4_disconnected_package_deletion_updates(store, block)?;
    let witness_meta_key = persistence_key(USDOM_V2_WITNESS_META_PREFIX, block);
    if let Some(meta) = store.get_consensus_state(&witness_meta_key)? {
        let chunks = chunk_count_from_meta(
            &meta,
            USDOM_V2_WITNESS_META_BYTES,
            USDOM_V2_PERSISTENCE_VERSION,
            "witness",
        )?;
        updates.push(ConsensusStateUpdate {
            key: witness_meta_key,
            value: None,
        });
        for index in 0..chunks {
            updates.push(ConsensusStateUpdate {
                key: v2_witness_chunk_key(block, index),
                value: None,
            });
        }
    }
    updates.push(ConsensusStateUpdate {
        key: persistence_key(USDOM_V2_BLOCK_RECORD_PREFIX, block),
        value: None,
    });
    validate_consensus_state_updates(&updates)?;
    Ok(updates)
}

/// Produce a bounded atomic deletion batch for V2 replay data below both an
/// Ethereum-recognized DOM checkpoint and the local rolling-finality window.
/// The compact burn archive and the checkpoint block record remain available.
pub(crate) fn native_usdom_v2_history_compaction_updates(
    store: &DomStore,
    schedule: NativeUsdomV2ActivationSchedule,
    new_tip_height: u64,
    checkpoint_floor_height: u64,
) -> Result<Vec<ConsensusStateUpdate>, DomError> {
    schedule.validate()?;
    let Some(rolling_floor) = new_tip_height.checked_sub(crate::reorg::MAX_REORG_DEPTH) else {
        return Ok(Vec::new());
    };
    let Some(checkpoint_predecessor) = checkpoint_floor_height.checked_sub(1) else {
        return Ok(Vec::new());
    };
    let maximum_prunable = rolling_floor.min(checkpoint_predecessor);
    let cursor_value = store
        .get_consensus_state(USDOM_V2_PRUNE_CURSOR_KEY)?
        .ok_or_else(|| DomError::Internal("native USDOM V2 prune cursor is missing".into()))?;
    let mut cursor = decode_v2_prune_cursor(&cursor_value)?;
    if cursor < schedule.first_v2_height() {
        return Err(DomError::Internal(
            "native USDOM V2 prune cursor crossed activation".into(),
        ));
    }
    if cursor > maximum_prunable {
        return Ok(Vec::new());
    }

    let mut updates = Vec::new();
    let end = maximum_prunable.min(
        cursor
            .checked_add(USDOM_V2_PRUNE_BATCH_BLOCKS - 1)
            .ok_or_else(|| DomError::Invalid("native USDOM V2 prune range overflow".into()))?,
    );
    while cursor <= end {
        let block = store
            .get_hash_at_height(cursor)?
            .map(dom_core::Hash256::from_bytes)
            .ok_or_else(|| {
                DomError::Internal(format!(
                    "native USDOM V2 compaction height {cursor} is missing"
                ))
            })?;
        let package_meta_key = persistence_key(USDOM_V4_PACKAGE_META_PREFIX, block);
        if let Some(meta) = store.get_consensus_state(&package_meta_key)? {
            let chunks = chunk_count_from_meta(
                &meta,
                USDOM_V4_PACKAGE_META_BYTES,
                USDOM_V4_PERSISTENCE_VERSION,
                "package",
            )?;
            updates.push(ConsensusStateUpdate {
                key: package_meta_key,
                value: None,
            });
            for index in 0..chunks {
                updates.push(ConsensusStateUpdate {
                    key: package_chunk_key(block, index),
                    value: None,
                });
            }
        }
        let witness_meta_key = persistence_key(USDOM_V2_WITNESS_META_PREFIX, block);
        if let Some(meta) = store.get_consensus_state(&witness_meta_key)? {
            let chunks = chunk_count_from_meta(
                &meta,
                USDOM_V2_WITNESS_META_BYTES,
                USDOM_V2_PERSISTENCE_VERSION,
                "witness",
            )?;
            updates.push(ConsensusStateUpdate {
                key: witness_meta_key,
                value: None,
            });
            for index in 0..chunks {
                updates.push(ConsensusStateUpdate {
                    key: v2_witness_chunk_key(block, index),
                    value: None,
                });
            }
        }
        updates.push(ConsensusStateUpdate {
            key: persistence_key(USDOM_V2_BLOCK_RECORD_PREFIX, block),
            value: None,
        });
        cursor = cursor
            .checked_add(1)
            .ok_or_else(|| DomError::Invalid("native USDOM V2 prune cursor overflow".into()))?;
    }
    updates.push(ConsensusStateUpdate {
        key: USDOM_V2_PRUNE_CURSOR_KEY.to_vec(),
        value: Some(v2_prune_cursor_value(cursor)),
    });
    validate_consensus_state_updates(&updates)?;
    Ok(updates)
}

fn package_chunk_key(block_identifier: dom_core::Hash256, index: u16) -> Vec<u8> {
    let mut key = persistence_key(USDOM_V4_PACKAGE_CHUNK_PREFIX, block_identifier);
    key.extend_from_slice(&index.to_be_bytes());
    key
}

fn package_persistence_updates(
    network_magic: u32,
    block_identifier: dom_core::Hash256,
    package_commitment: dom_core::Hash256,
    package_bytes: &[u8],
) -> Result<Vec<ConsensusStateUpdate>, DomError> {
    if blake2b_256_tagged(TAG_USDOM_BLOCK_PACKAGE_V4, package_bytes) != package_commitment {
        return Err(DomError::Invalid(
            "native USDOM package commitment changed before persistence".into(),
        ));
    }
    let package = UsdomV4BlockPackage::from_bytes(package_bytes)?;
    let header_bytes = DomSerialize::to_bytes(&package.block().header)?;
    if crate::canonical_header_identifier(network_magic, &header_bytes)? != block_identifier {
        return Err(DomError::Invalid(
            "native USDOM package block identifier changed before persistence".into(),
        ));
    }
    let proof_bytes = package.proof_envelope().to_bytes()?;
    let chunks: Vec<&[u8]> = proof_bytes
        .chunks(MAX_CONSENSUS_STATE_VALUE_BYTES)
        .collect();
    let chunk_count: u16 = chunks
        .len()
        .try_into()
        .map_err(|_| DomError::Invalid("too many native USDOM proof chunks".into()))?;
    let proof_len: u32 = proof_bytes
        .len()
        .try_into()
        .map_err(|_| DomError::Invalid("native USDOM proof length overflow".into()))?;
    let mut meta = Vec::with_capacity(USDOM_V4_PACKAGE_META_BYTES);
    meta.extend_from_slice(&USDOM_V4_PERSISTENCE_VERSION.to_be_bytes());
    meta.extend_from_slice(package_commitment.as_bytes());
    meta.extend_from_slice(&proof_len.to_be_bytes());
    meta.extend_from_slice(&chunk_count.to_be_bytes());
    debug_assert_eq!(meta.len(), USDOM_V4_PACKAGE_META_BYTES);
    let mut updates = vec![ConsensusStateUpdate {
        key: persistence_key(USDOM_V4_PACKAGE_META_PREFIX, block_identifier),
        value: Some(meta),
    }];
    for (index, chunk) in chunks.into_iter().enumerate() {
        let index: u16 = index
            .try_into()
            .map_err(|_| DomError::Invalid("native USDOM chunk index overflow".into()))?;
        updates.push(ConsensusStateUpdate {
            key: package_chunk_key(block_identifier, index),
            value: Some(chunk.to_vec()),
        });
    }
    Ok(updates)
}

fn v2_witness_chunk_key(block_identifier: dom_core::Hash256, index: u16) -> Vec<u8> {
    let mut key = persistence_key(USDOM_V2_WITNESS_CHUNK_PREFIX, block_identifier);
    key.extend_from_slice(&index.to_be_bytes());
    key
}

fn v2_witness_persistence_updates(
    block_identifier: dom_core::Hash256,
    witness_commitment: dom_core::Hash256,
    witness_bytes: &[u8],
) -> Result<Vec<ConsensusStateUpdate>, DomError> {
    if witness_bytes.is_empty() || witness_bytes.len() > MAX_USDOM_V2_WITNESS_BUNDLE_BYTES {
        return Err(DomError::Invalid(
            "native USDOM v2 witness bytes exceed persistence bounds".into(),
        ));
    }
    let decoded = UsdomV2ExecutionWitnesses::from_bytes(witness_bytes)?;
    if decoded.commitment()? != witness_commitment {
        return Err(DomError::Invalid(
            "native USDOM v2 witness commitment changed before persistence".into(),
        ));
    }
    let chunks: Vec<&[u8]> = witness_bytes
        .chunks(MAX_CONSENSUS_STATE_VALUE_BYTES)
        .collect();
    let chunk_count: u16 = chunks
        .len()
        .try_into()
        .map_err(|_| DomError::Invalid("too many native USDOM v2 witness chunks".into()))?;
    let witness_len: u32 = witness_bytes
        .len()
        .try_into()
        .map_err(|_| DomError::Invalid("native USDOM v2 witness length overflow".into()))?;
    let mut meta = Vec::with_capacity(USDOM_V2_WITNESS_META_BYTES);
    meta.extend_from_slice(&USDOM_V2_PERSISTENCE_VERSION.to_be_bytes());
    meta.extend_from_slice(witness_commitment.as_bytes());
    meta.extend_from_slice(&witness_len.to_be_bytes());
    meta.extend_from_slice(&chunk_count.to_be_bytes());
    debug_assert_eq!(meta.len(), USDOM_V2_WITNESS_META_BYTES);
    let mut updates = vec![ConsensusStateUpdate {
        key: persistence_key(USDOM_V2_WITNESS_META_PREFIX, block_identifier),
        value: Some(meta),
    }];
    for (index, chunk) in chunks.into_iter().enumerate() {
        let index: u16 = index
            .try_into()
            .map_err(|_| DomError::Invalid("native USDOM v2 witness chunk overflow".into()))?;
        updates.push(ConsensusStateUpdate {
            key: v2_witness_chunk_key(block_identifier, index),
            value: Some(chunk.to_vec()),
        });
    }
    Ok(updates)
}

fn v2_runtime_tip_value(
    schedule: NativeUsdomV2ActivationSchedule,
    record: PersistedUsdomV2BlockRecord,
) -> Result<Vec<u8>, DomError> {
    record.validate()?;
    if record.schedule_commitment != schedule.commitment() {
        return Err(DomError::Invalid(
            "native USDOM v2 runtime tip schedule mismatch".into(),
        ));
    }
    let state = record.next_state.to_bytes().map_err(|error| {
        DomError::Invalid(format!("invalid native USDOM v2 runtime state: {error}"))
    })?;
    let state_len: u16 = state
        .len()
        .try_into()
        .map_err(|_| DomError::Invalid("native USDOM v2 runtime state too large".into()))?;
    let mut value = Vec::with_capacity(172 + state.len());
    value.extend_from_slice(USDOM_V2_RUNTIME_TIP_MAGIC);
    value.extend_from_slice(&USDOM_V2_PERSISTENCE_VERSION.to_be_bytes());
    value.extend_from_slice(record.schedule_commitment.as_bytes());
    value.extend_from_slice(record.block_identifier.as_bytes());
    value.extend_from_slice(record.next_state.root().as_bytes());
    value.extend_from_slice(record.package_commitment.as_bytes());
    value.extend_from_slice(record.witness_commitment.as_bytes());
    value.extend_from_slice(&state_len.to_be_bytes());
    value.extend_from_slice(&state);
    Ok(value)
}

fn tip_value(
    block_identifier: dom_core::Hash256,
    state_root: dom_core::Hash256,
    package_commitment: dom_core::Hash256,
) -> Vec<u8> {
    let mut tip = Vec::with_capacity(96);
    tip.extend_from_slice(block_identifier.as_bytes());
    tip.extend_from_slice(state_root.as_bytes());
    tip.extend_from_slice(package_commitment.as_bytes());
    tip
}

/// Produce the fixed Regtest empty-state activation batch tied to the canonical
/// genesis parent. Public-network callers must use
/// [`native_usdom_v4_activation_updates_for_schedule`] with a separately
/// ratified schedule.
pub fn native_usdom_v4_activation_updates(
    state: &NativeUsdomState,
    activation_block: dom_core::Hash256,
) -> Result<Vec<ConsensusStateUpdate>, DomError> {
    let schedule = native_usdom_v4_regtest_activation_schedule(state.bridge_identity())?;
    native_usdom_v4_activation_updates_for_schedule(state, schedule, activation_block, 0)
}

/// Produce one atomic empty-state activation batch for an exact ratified
/// schedule and canonical activation parent.
///
/// The caller must commit these updates in the same database transaction that
/// installs `activation_parent` at `activation_parent_height`. The first v4
/// height must be the immediate successor. A nonempty native monetary state,
/// mismatched bridge root or arithmetic overflow fails closed.
pub fn native_usdom_v4_activation_updates_for_schedule(
    state: &NativeUsdomState,
    schedule: NativeUsdomV4ActivationSchedule,
    activation_parent: dom_core::Hash256,
    activation_parent_height: u64,
) -> Result<Vec<ConsensusStateUpdate>, DomError> {
    validate_native_usdom_privacy_policy(state.bridge_identity())?;
    schedule.validate()?;
    let first_v4_height = activation_parent_height
        .checked_add(1)
        .ok_or_else(|| DomError::Invalid("native USDOM activation height overflow".into()))?;
    if first_v4_height != schedule.first_v4_height {
        return Err(DomError::PolicyRejected(
            "native USDOM activation parent does not match the ratified height".into(),
        ));
    }
    let empty = NativeUsdomState::new(state.bridge_identity()).map_err(|error| {
        DomError::Invalid(format!("native USDOM activation identity failed: {error}"))
    })?;
    if state.state_root() != empty.state_root() || state.export_entries() != empty.export_entries()
    {
        return Err(DomError::PolicyRejected(
            "native USDOM activation requires the canonical empty state".into(),
        ));
    }
    if schedule.empty_state_root != state.state_root() {
        return Err(DomError::PolicyRejected(
            "native USDOM activation schedule does not match the bridge state root".into(),
        ));
    }
    let mut updates: Vec<_> = state
        .export_entries()
        .into_iter()
        .map(|(key, value)| ConsensusStateUpdate {
            key,
            value: Some(value),
        })
        .collect();
    updates.push(ConsensusStateUpdate {
        key: USDOM_V4_ACTIVATION_KEY.to_vec(),
        value: Some(activation_record(schedule, activation_parent)?),
    });
    updates.push(ConsensusStateUpdate {
        key: USDOM_V4_TIP_KEY.to_vec(),
        value: Some(tip_value(
            activation_parent,
            state.state_root(),
            dom_core::Hash256::ZERO,
        )),
    });
    validate_consensus_state_updates(&updates)?;
    Ok(updates)
}

impl crate::chain_state::ChainState {
    /// Prepare the atomic native-state activation batch only when `schedule`
    /// exactly names this chain and the first v4 height immediately follows the
    /// current canonical tip.
    ///
    /// This is the production-oriented activation boundary. The returned batch
    /// still grants no authority by itself: the caller must commit it atomically
    /// with the already validated canonical parent represented by this state.
    pub fn prepare_native_usdom_v4_activation(
        &self,
        state: &NativeUsdomState,
        schedule: NativeUsdomV4ActivationSchedule,
    ) -> Result<Vec<ConsensusStateUpdate>, DomError> {
        schedule.validate()?;
        let chain_id = dom_consensus::derive_chain_id(self.network_magic, &self.genesis_hash);
        let expected_first_height =
            self.tip_height.0.checked_add(1).ok_or_else(|| {
                DomError::Invalid("native USDOM activation height overflow".into())
            })?;
        if schedule.network_magic != self.network_magic
            || schedule.chain_id != chain_id
            || schedule.first_v4_height != expected_first_height
        {
            return Err(DomError::PolicyRejected(
                "native USDOM activation schedule does not match the canonical chain tip".into(),
            ));
        }
        if native_usdom_v4_activation_tip(&self.store)?.is_some() {
            return Err(DomError::PolicyRejected(
                "native USDOM is already activated in this data directory".into(),
            ));
        }
        native_usdom_v4_activation_updates_for_schedule(
            state,
            schedule,
            self.tip_hash,
            self.tip_height.0,
        )
    }
}

/// Restore native state only when its persisted root, canonical chain tip and
/// exact tip package agree. The zero package commitment is reserved for the
/// canonical empty activation state before the first v4 package.
pub fn restore_persisted_usdom_v4_state(
    store: &DomStore,
    network_magic: u32,
    expected_bridge: BridgeIdentity,
    expected_chain_tip: dom_core::Hash256,
) -> Result<NativeUsdomState, DomError> {
    let schedule = if network_magic == NETWORK_MAGIC_REGTEST {
        native_usdom_v4_regtest_activation_schedule(expected_bridge)?
    } else {
        return Err(DomError::PolicyRejected(
            "public-network native USDOM restore requires an exact ratified activation schedule"
                .into(),
        ));
    };
    restore_persisted_usdom_v4_state_for_schedule(
        store,
        network_magic,
        expected_bridge,
        expected_chain_tip,
        schedule,
    )
}

/// Restore native state only when the persisted activation record exactly
/// matches a caller-supplied ratified schedule.
pub fn restore_persisted_usdom_v4_state_for_schedule(
    store: &DomStore,
    network_magic: u32,
    expected_bridge: BridgeIdentity,
    expected_chain_tip: dom_core::Hash256,
    expected_schedule: NativeUsdomV4ActivationSchedule,
) -> Result<NativeUsdomState, DomError> {
    validate_native_usdom_privacy_policy(expected_bridge)?;
    expected_schedule.validate()?;
    if expected_schedule.network_magic != network_magic {
        return Err(DomError::PolicyRejected(
            "native USDOM activation schedule belongs to another network".into(),
        ));
    }
    let expected_empty = NativeUsdomState::new(expected_bridge).map_err(|error| {
        DomError::Invalid(format!("native USDOM activation identity failed: {error}"))
    })?;
    if expected_schedule.empty_state_root != expected_empty.state_root() {
        return Err(DomError::PolicyRejected(
            "native USDOM activation schedule does not match the expected bridge".into(),
        ));
    }
    let activation_parent_height = expected_schedule
        .first_v4_height
        .checked_sub(1)
        .ok_or_else(|| DomError::Internal("invalid persisted activation height".into()))?;
    let snapshot = store.read_canonical_consensus_snapshot(activation_parent_height)?;
    if snapshot.chain_tip != Some(*expected_chain_tip.as_bytes()) {
        return Err(DomError::Internal(
            "persisted native USDOM state was not read at the expected canonical chain tip".into(),
        ));
    }
    let all_entries = snapshot.consensus_state;
    let activation = all_entries.get(USDOM_V4_ACTIVATION_KEY).ok_or_else(|| {
        DomError::Internal("persisted native USDOM activation record is missing".into())
    })?;
    let (persisted_schedule, activation_parent) = parse_activation_record(activation)?;
    if persisted_schedule != expected_schedule {
        return Err(DomError::PolicyRejected(
            "persisted native USDOM activation schedule is not the ratified schedule".into(),
        ));
    }
    if snapshot.requested_height_hash != Some(*activation_parent.as_bytes()) {
        return Err(DomError::Internal(
            "persisted native USDOM activation parent is not canonical".into(),
        ));
    }
    let state_entries = all_entries
        .iter()
        .filter(|(key, _)| key.starts_with(b"usdom/v3/"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let state =
        NativeUsdomState::restore_entries(expected_bridge, &state_entries).map_err(|error| {
            DomError::Internal(format!("persisted native USDOM state is corrupt: {error}"))
        })?;
    let tip = all_entries
        .get(USDOM_V4_TIP_KEY)
        .ok_or_else(|| DomError::Internal("persisted native USDOM tip is missing".into()))?;
    let tip = decode_persisted_usdom_v4_tip(tip, "canonical tip")?;
    if tip.block_identifier != expected_chain_tip || tip.state_root != state.state_root() {
        return Err(DomError::Internal(
            "persisted native USDOM tip does not match canonical chain/state".into(),
        ));
    }
    let package_commitment = tip.package_commitment;
    if package_commitment == dom_core::Hash256::ZERO {
        let empty = NativeUsdomState::new(expected_bridge).map_err(|error| {
            DomError::Internal(format!("native USDOM activation identity failed: {error}"))
        })?;
        if state.state_root() != empty.state_root() {
            return Err(DomError::Internal(
                "nonempty native USDOM state has activation-only tip".into(),
            ));
        }
    } else {
        let package = load_persisted_usdom_v4_package(store, network_magic, expected_chain_tip)?
            .ok_or_else(|| DomError::Internal("native USDOM tip package is missing".into()))?;
        if blake2b_256_tagged(TAG_USDOM_BLOCK_PACKAGE_V4, &package) != package_commitment {
            return Err(DomError::Internal(
                "native USDOM tip package does not match persisted tip".into(),
            ));
        }
        let package = UsdomV4BlockPackage::from_bytes(&package).map_err(|error| {
            DomError::Internal(format!(
                "persisted native USDOM tip package is corrupt: {error}"
            ))
        })?;
        let tip_height = package.block().header.height.0;
        if tip_height < expected_schedule.first_v4_height()
            || store.get_hash_at_height(tip_height)? != Some(*expected_chain_tip.as_bytes())
        {
            return Err(DomError::Internal(
                "persisted native USDOM tip is not canonical at its declared height".into(),
            ));
        }
    }
    Ok(state)
}

/// Result of authenticating the complete canonical native-v4 history needed
/// by the current reorganization window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeUsdomV4HistoryAudit {
    /// Canonical tip whose persisted state and package marker were checked.
    pub canonical_tip: dom_core::Hash256,
    /// Oldest hash reached after authenticating `audited_blocks` v4 blocks.
    pub oldest_audited_parent: dom_core::Hash256,
    /// Number of consecutive canonical v4 blocks authenticated from the tip.
    pub audited_blocks: u64,
    /// State root reconstructed at `oldest_audited_parent`.
    pub boundary_state_root: dom_core::Hash256,
    /// True when the walk reached the non-v4 activation parent and proved the
    /// reconstructed native state is the canonical empty state.
    pub reached_activation_boundary: bool,
}

/// One canonical native-v4 block covered by a portable snapshot manifest.
/// The manifest carries commitments rather than bulk package/undo bytes; those
/// bytes remain in the authenticated DOM store and must match on verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeUsdomV4SnapshotBlock {
    /// Canonical DOM block identifier.
    pub block_identifier: dom_core::Hash256,
    /// Canonical block height.
    pub height: u64,
    /// Parent identifier encoded by the committed header.
    pub prev_hash: dom_core::Hash256,
    /// Domain-separated commitment to the exact canonical package bytes.
    pub package_commitment: dom_core::Hash256,
    /// Domain-separated commitment to the exact authenticated undo bytes.
    pub undo_commitment: dom_core::Hash256,
    /// Exact package length used for bounded inventory and recovery planning.
    pub package_len: u32,
}

/// Compact, canonical inventory of every native-state artifact needed by the
/// current reorganization window. It is evidence only: decoding or possessing
/// a manifest grants no authority to mutate a store or import consensus state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeUsdomV4SnapshotManifest {
    /// Network whose canonical identifiers and packages were inventoried.
    pub network_magic: u32,
    /// Canonical DOM tip at export time.
    pub canonical_tip: dom_core::Hash256,
    /// Height of `canonical_tip`.
    pub canonical_height: u64,
    /// Fully recomputed native USDOM state root at the tip.
    pub state_root: dom_core::Hash256,
    /// Commitment to the complete ordered canonical native-state entries.
    pub state_entries_commitment: dom_core::Hash256,
    /// Oldest parent reached by the authenticated rewind audit.
    pub oldest_audited_parent: dom_core::Hash256,
    /// Recomputed native state root at `oldest_audited_parent`.
    pub boundary_state_root: dom_core::Hash256,
    /// True when the manifest reaches and verifies the empty activation state.
    pub reached_activation_boundary: bool,
    /// Commitment to the ratified network/chain/height/empty-state schedule.
    pub activation_schedule_commitment: dom_core::Hash256,
    /// Commitment to the persisted schedule plus original activation parent.
    pub activation_record_commitment: dom_core::Hash256,
    /// Commitment to the exact consensus-carried checkpoint floor, or zero
    /// before the first authenticated checkpoint carrier is canonical.
    pub checkpoint_floor_commitment: dom_core::Hash256,
    /// Tip-to-parent ordered native-v4 package/undo inventory.
    pub blocks: Vec<NativeUsdomV4SnapshotBlock>,
}

impl NativeUsdomV4SnapshotManifest {
    /// Encode the unique bounded version-5 representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DomError> {
        if !matches!(
            self.network_magic,
            dom_core::NETWORK_MAGIC_MAINNET
                | dom_core::NETWORK_MAGIC_TESTNET
                | dom_core::NETWORK_MAGIC_REGTEST
        ) || self.canonical_tip == dom_core::Hash256::ZERO
            || self.state_root == dom_core::Hash256::ZERO
            || self.state_entries_commitment == dom_core::Hash256::ZERO
            || self.oldest_audited_parent == dom_core::Hash256::ZERO
            || self.boundary_state_root == dom_core::Hash256::ZERO
            || self.activation_schedule_commitment == dom_core::Hash256::ZERO
            || self.activation_record_commitment == dom_core::Hash256::ZERO
            || self.blocks.len() as u64 > dom_core::MAX_REORG_DEPTH_POLICY
        {
            return Err(DomError::Invalid(
                "invalid native USDOM snapshot manifest identity or bounds".into(),
            ));
        }
        let block_count: u32 =
            self.blocks.len().try_into().map_err(|_| {
                DomError::Invalid("native USDOM snapshot block count overflow".into())
            })?;
        let audited_blocks = u64::from(block_count);
        let expected_len = USDOM_V4_SNAPSHOT_HEADER_BYTES
            .checked_add(
                self.blocks
                    .len()
                    .checked_mul(USDOM_V4_SNAPSHOT_BLOCK_BYTES)
                    .ok_or_else(|| DomError::Invalid("snapshot manifest length overflow".into()))?,
            )
            .ok_or_else(|| DomError::Invalid("snapshot manifest length overflow".into()))?;
        let mut out = Vec::with_capacity(expected_len);
        out.extend_from_slice(USDOM_V4_SNAPSHOT_MAGIC);
        out.extend_from_slice(&USDOM_V4_SNAPSHOT_VERSION.to_be_bytes());
        out.extend_from_slice(&self.network_magic.to_be_bytes());
        out.extend_from_slice(self.canonical_tip.as_bytes());
        out.extend_from_slice(&self.canonical_height.to_be_bytes());
        out.extend_from_slice(self.state_root.as_bytes());
        out.extend_from_slice(self.state_entries_commitment.as_bytes());
        out.extend_from_slice(self.oldest_audited_parent.as_bytes());
        out.extend_from_slice(&audited_blocks.to_be_bytes());
        out.extend_from_slice(self.boundary_state_root.as_bytes());
        out.push(u8::from(self.reached_activation_boundary));
        out.extend_from_slice(&block_count.to_be_bytes());
        out.extend_from_slice(self.activation_schedule_commitment.as_bytes());
        out.extend_from_slice(self.activation_record_commitment.as_bytes());
        out.extend_from_slice(self.checkpoint_floor_commitment.as_bytes());
        let mut expected_identifier = self.canonical_tip;
        let mut expected_height = self.canonical_height;
        for block in &self.blocks {
            if block.block_identifier != expected_identifier
                || block.height != expected_height
                || block.block_identifier == dom_core::Hash256::ZERO
                || block.prev_hash == dom_core::Hash256::ZERO
                || block.package_commitment == dom_core::Hash256::ZERO
                || block.undo_commitment == dom_core::Hash256::ZERO
                || block.package_len == 0
                || block.package_len as usize > dom_core::MAX_BLOCK_SERIALIZED_SIZE
            {
                return Err(DomError::Invalid(
                    "noncanonical native USDOM snapshot block inventory".into(),
                ));
            }
            out.extend_from_slice(block.block_identifier.as_bytes());
            out.extend_from_slice(&block.height.to_be_bytes());
            out.extend_from_slice(block.prev_hash.as_bytes());
            out.extend_from_slice(block.package_commitment.as_bytes());
            out.extend_from_slice(block.undo_commitment.as_bytes());
            out.extend_from_slice(&block.package_len.to_be_bytes());
            expected_identifier = block.prev_hash;
            expected_height = expected_height.checked_sub(1).ok_or_else(|| {
                DomError::Invalid("native USDOM snapshot height underflow".into())
            })?;
        }
        if expected_identifier != self.oldest_audited_parent || out.len() != expected_len {
            return Err(DomError::Invalid(
                "native USDOM snapshot boundary mismatch".into(),
            ));
        }
        Ok(out)
    }

    /// Decode the exact canonical representation with fixed per-block bounds.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        let mut reader = Reader::new(bytes);
        if reader.read_bytes(8)? != USDOM_V4_SNAPSHOT_MAGIC
            || reader.read_u16_be()? != USDOM_V4_SNAPSHOT_VERSION
        {
            return Err(DomError::Malformed(
                "invalid native USDOM snapshot manifest framing".into(),
            ));
        }
        let network_magic = reader.read_u32_be()?;
        let canonical_tip = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let canonical_height = reader.read_u64_be()?;
        let state_root = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let state_entries_commitment = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let oldest_audited_parent = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let audited_blocks = reader.read_u64_be()?;
        let boundary_state_root = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let reached_activation_boundary = match reader.read_u8()? {
            0 => false,
            1 => true,
            _ => {
                return Err(DomError::Malformed(
                    "invalid native USDOM snapshot boundary flag".into(),
                ))
            }
        };
        let block_count = reader.read_u32_be()? as usize;
        let activation_schedule_commitment =
            dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let activation_record_commitment =
            dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let checkpoint_floor_commitment = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        if block_count as u64 > dom_core::MAX_REORG_DEPTH_POLICY
            || audited_blocks != block_count as u64
        {
            return Err(DomError::Malformed(
                "native USDOM snapshot block count exceeds audit bounds".into(),
            ));
        }
        let mut blocks = Vec::with_capacity(block_count);
        for _ in 0..block_count {
            blocks.push(NativeUsdomV4SnapshotBlock {
                block_identifier: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
                height: reader.read_u64_be()?,
                prev_hash: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
                package_commitment: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
                undo_commitment: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
                package_len: reader.read_u32_be()?,
            });
        }
        reader.finish()?;
        let manifest = Self {
            network_magic,
            canonical_tip,
            canonical_height,
            state_root,
            state_entries_commitment,
            oldest_audited_parent,
            boundary_state_root,
            reached_activation_boundary,
            activation_schedule_commitment,
            activation_record_commitment,
            checkpoint_floor_commitment,
            blocks,
        };
        if manifest.to_bytes()?.as_slice() != bytes {
            return Err(DomError::Malformed(
                "noncanonical native USDOM snapshot manifest".into(),
            ));
        }
        Ok(manifest)
    }

    /// Domain-separated identity for transporting or signing this exact
    /// manifest outside the node.
    pub fn commitment(&self) -> Result<dom_core::Hash256, DomError> {
        Ok(blake2b_256_tagged(
            TAG_USDOM_V4_SNAPSHOT_MANIFEST,
            &self.to_bytes()?,
        ))
    }
}

fn native_usdom_state_entries_commitment(
    entries: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<dom_core::Hash256, DomError> {
    let count: u32 = entries
        .len()
        .try_into()
        .map_err(|_| DomError::Invalid("native USDOM snapshot state count overflow".into()))?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&count.to_be_bytes());
    for (key, value) in entries {
        let key_len: u16 = key
            .len()
            .try_into()
            .map_err(|_| DomError::Invalid("native USDOM snapshot key too long".into()))?;
        let value_len: u32 = value
            .len()
            .try_into()
            .map_err(|_| DomError::Invalid("native USDOM snapshot value too long".into()))?;
        encoded.extend_from_slice(&key_len.to_be_bytes());
        encoded.extend_from_slice(&value_len.to_be_bytes());
        encoded.extend_from_slice(key);
        encoded.extend_from_slice(value);
    }
    Ok(blake2b_256_tagged(TAG_USDOM_V4_SNAPSHOT_STATE, &encoded))
}

/// Export a compact canonical manifest after fully restoring and auditing the
/// native state and every package/undo in the current reorganization window.
pub fn export_native_usdom_v4_snapshot_manifest(
    store: &DomStore,
    network_magic: u32,
    expected_bridge: BridgeIdentity,
    canonical_tip: dom_core::Hash256,
) -> Result<NativeUsdomV4SnapshotManifest, DomError> {
    if network_magic != NETWORK_MAGIC_REGTEST || canonical_tip == dom_core::Hash256::ZERO {
        return Err(DomError::PolicyRejected(
            "native USDOM snapshot export is available only for a nonzero Regtest tip".into(),
        ));
    }
    let expected_schedule = native_usdom_v4_regtest_activation_schedule(expected_bridge)?;
    export_native_usdom_v4_snapshot_manifest_for_schedule(
        store,
        network_magic,
        expected_bridge,
        canonical_tip,
        expected_schedule,
    )
}

/// Export a compact canonical manifest for any recognized DOM network under
/// one exact ratified activation schedule.  Requiring the schedule explicitly
/// prevents a transported snapshot from selecting its own chain, activation
/// height or empty-state identity.
pub fn export_native_usdom_v4_snapshot_manifest_for_schedule(
    store: &DomStore,
    network_magic: u32,
    expected_bridge: BridgeIdentity,
    canonical_tip: dom_core::Hash256,
    expected_schedule: NativeUsdomV4ActivationSchedule,
) -> Result<NativeUsdomV4SnapshotManifest, DomError> {
    expected_schedule.validate()?;
    if !matches!(
        network_magic,
        dom_core::NETWORK_MAGIC_MAINNET
            | dom_core::NETWORK_MAGIC_TESTNET
            | dom_core::NETWORK_MAGIC_REGTEST
    ) || canonical_tip == dom_core::Hash256::ZERO
        || expected_schedule.network_magic() != network_magic
    {
        return Err(DomError::PolicyRejected(
            "native USDOM snapshot export does not match its ratified network schedule".into(),
        ));
    }
    let activation_parent_height = expected_schedule
        .first_v4_height()
        .checked_sub(1)
        .ok_or_else(|| DomError::Internal("invalid snapshot activation height".into()))?;
    let snapshot = store.read_canonical_consensus_snapshot(activation_parent_height)?;
    if snapshot.chain_tip != Some(*canonical_tip.as_bytes()) {
        return Err(DomError::Internal(
            "native USDOM snapshot was not read at the requested canonical tip".into(),
        ));
    }
    let all_entries = snapshot.consensus_state;
    let activation_record = all_entries.get(USDOM_V4_ACTIVATION_KEY).ok_or_else(|| {
        DomError::Internal("native USDOM snapshot activation record is missing".into())
    })?;
    let (activation_schedule, activation_parent) = parse_activation_record(activation_record)?;
    if activation_schedule != expected_schedule
        || snapshot.requested_height_hash != Some(*activation_parent.as_bytes())
    {
        return Err(DomError::Internal(
            "native USDOM snapshot activation identity is not canonical".into(),
        ));
    }
    let activation_schedule_commitment = activation_schedule.commitment();
    let activation_record_commitment =
        blake2b_256_tagged(TAG_USDOM_V4_ACTIVATION_RECORD, activation_record);
    let state_entries = all_entries
        .iter()
        .filter(|(key, _)| key.starts_with(b"usdom/v3/"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let state =
        NativeUsdomState::restore_entries(expected_bridge, &state_entries).map_err(|error| {
            DomError::Internal(format!("native USDOM snapshot state is corrupt: {error}"))
        })?;
    let persisted_tip = all_entries
        .get(USDOM_V4_TIP_KEY)
        .ok_or_else(|| DomError::Internal("native USDOM snapshot tip marker is missing".into()))?;
    let persisted_tip = decode_persisted_usdom_v4_tip(persisted_tip, "snapshot tip")?;
    if persisted_tip.block_identifier != canonical_tip
        || persisted_tip.state_root != state.state_root()
    {
        return Err(DomError::Internal(
            "native USDOM snapshot tip marker does not match its atomic state".into(),
        ));
    }
    let state_entries_commitment = native_usdom_state_entries_commitment(&state_entries)?;
    let checkpoint_floor_commitment =
        match all_entries.get(crate::ethereum_checkpoint_poc::CONSENSUS_CHECKPOINT_KEY) {
            Some(bytes) => {
                let checkpoint = crate::ethereum_checkpoint_poc::decode_test_oracle_v2(bytes)
                    .map_err(|error| {
                        DomError::Internal(format!(
                            "native USDOM snapshot checkpoint is corrupt: {error}"
                        ))
                    })?;
                blake2b_256_tagged(
                    TAG_USDOM_V4_SNAPSHOT_CHECKPOINT,
                    &crate::ethereum_checkpoint_poc::encode_test_oracle_v2(checkpoint)?,
                )
            }
            None => dom_core::Hash256::ZERO,
        };
    let audit = audit_persisted_usdom_v4_reorg_window_for_schedule(
        store,
        network_magic,
        expected_bridge,
        canonical_tip,
        expected_schedule,
    )?;
    let tip_header = store
        .get_block_header(canonical_tip.as_bytes())?
        .ok_or_else(|| DomError::Internal("native USDOM snapshot tip header is missing".into()))?;
    let tip_header =
        dom_consensus::block::BlockHeader::from_bytes(&tip_header).map_err(|error| {
            DomError::Internal(format!(
                "native USDOM snapshot tip header is corrupt: {error}"
            ))
        })?;
    if store.get_hash_at_height(tip_header.height.0)? != Some(*canonical_tip.as_bytes()) {
        return Err(DomError::Internal(
            "native USDOM snapshot tip is not canonical".into(),
        ));
    }
    let mut blocks = Vec::with_capacity(audit.audited_blocks as usize);
    let mut cursor = canonical_tip;
    for _ in 0..audit.audited_blocks {
        let package_bytes = load_persisted_usdom_v4_package(store, network_magic, cursor)?
            .ok_or_else(|| DomError::Internal("native USDOM snapshot package is missing".into()))?;
        let package = UsdomV4BlockPackage::from_bytes(&package_bytes).map_err(|error| {
            DomError::Internal(format!("native USDOM snapshot package is corrupt: {error}"))
        })?;
        let header_bytes = DomSerialize::to_bytes(&package.block().header)?;
        if crate::canonical_header_identifier(network_magic, &header_bytes)? != cursor
            || store.get_hash_at_height(package.block().header.height.0)?
                != Some(*cursor.as_bytes())
        {
            return Err(DomError::Internal(
                "native USDOM snapshot package is not canonical".into(),
            ));
        }
        let undo = store
            .get_consensus_state(&persistence_key(USDOM_V4_UNDO_PREFIX, cursor))?
            .ok_or_else(|| DomError::Internal("native USDOM snapshot undo is missing".into()))?;
        BatchUndo::from_bytes(&undo).map_err(|error| {
            DomError::Internal(format!("native USDOM snapshot undo is corrupt: {error}"))
        })?;
        blocks.push(NativeUsdomV4SnapshotBlock {
            block_identifier: cursor,
            height: package.block().header.height.0,
            prev_hash: package.block().header.prev_hash,
            package_commitment: blake2b_256_tagged(TAG_USDOM_BLOCK_PACKAGE_V4, &package_bytes),
            undo_commitment: blake2b_256_tagged(TAG_USDOM_V4_SNAPSHOT_UNDO, &undo),
            package_len: package_bytes
                .len()
                .try_into()
                .map_err(|_| DomError::Invalid("native USDOM package length overflow".into()))?,
        });
        cursor = package.block().header.prev_hash;
    }
    let manifest = NativeUsdomV4SnapshotManifest {
        network_magic,
        canonical_tip,
        canonical_height: tip_header.height.0,
        state_root: state.state_root(),
        state_entries_commitment,
        oldest_audited_parent: audit.oldest_audited_parent,
        boundary_state_root: audit.boundary_state_root,
        reached_activation_boundary: audit.reached_activation_boundary,
        activation_schedule_commitment,
        activation_record_commitment,
        checkpoint_floor_commitment,
        blocks,
    };
    manifest.to_bytes()?;
    if store.get_chain_tip()? != Some(*canonical_tip.as_bytes()) {
        return Err(DomError::Internal(
            "canonical chain changed during native USDOM snapshot export".into(),
        ));
    }
    Ok(manifest)
}

/// Verify that a transported manifest is canonical and exactly matches a
/// freshly restored/audited store. This function is read-only and deliberately
/// does not import bytes or modify consensus state.
pub fn verify_native_usdom_v4_snapshot_manifest(
    manifest_bytes: &[u8],
    store: &DomStore,
    expected_bridge: BridgeIdentity,
) -> Result<NativeUsdomV4SnapshotManifest, DomError> {
    let supplied = NativeUsdomV4SnapshotManifest::from_bytes(manifest_bytes)?;
    if supplied.network_magic != NETWORK_MAGIC_REGTEST {
        return Err(DomError::PolicyRejected(
            "non-Regtest native USDOM snapshot verification requires an explicit ratified schedule"
                .into(),
        ));
    }
    let expected_schedule = native_usdom_v4_regtest_activation_schedule(expected_bridge)?;
    verify_native_usdom_v4_snapshot_manifest_for_schedule(
        manifest_bytes,
        store,
        expected_bridge,
        expected_schedule,
    )
}

/// Verify a transported snapshot against the current audited store and an
/// independently supplied ratified schedule. The manifest may describe the
/// network, but it never gains authority to choose that schedule.
pub fn verify_native_usdom_v4_snapshot_manifest_for_schedule(
    manifest_bytes: &[u8],
    store: &DomStore,
    expected_bridge: BridgeIdentity,
    expected_schedule: NativeUsdomV4ActivationSchedule,
) -> Result<NativeUsdomV4SnapshotManifest, DomError> {
    let supplied = NativeUsdomV4SnapshotManifest::from_bytes(manifest_bytes)?;
    if supplied.network_magic != expected_schedule.network_magic() {
        return Err(DomError::PolicyRejected(
            "native USDOM snapshot belongs to another ratified network schedule".into(),
        ));
    }
    let current = export_native_usdom_v4_snapshot_manifest_for_schedule(
        store,
        supplied.network_magic,
        expected_bridge,
        supplied.canonical_tip,
        expected_schedule,
    )?;
    if current != supplied {
        return Err(DomError::Invalid(
            "native USDOM snapshot manifest does not match the audited store".into(),
        ));
    }
    Ok(supplied)
}

/// Runtime-owned native-v4 state and immutable Ethereum checkpoint policy.
/// Construction restores the exact canonical state and audits the complete
/// reorganizable history before any package can be ingested.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeUsdomV4MiningCandidate {
    id: dom_core::Hash256,
    encoded_len: usize,
    issuance_deposit_ids: Vec<[u8; 32]>,
    envelope: UsdomV4ProofEnvelope,
}

fn verified_issuance_deposit_ids(transitions: &[VerifiedTransition]) -> Vec<[u8; 32]> {
    transitions
        .iter()
        .filter_map(|transition| match transition.commitment_projection() {
            TransitionCommitmentProjection::Issue { record, .. } => Some(record.deposit_id),
            _ => None,
        })
        .collect()
}

fn has_issuance_deposit_overlap<'a>(
    queued: impl IntoIterator<Item = &'a [u8; 32]>,
    deposit_ids: &[[u8; 32]],
) -> bool {
    !deposit_ids.is_empty()
        && queued
            .into_iter()
            .any(|queued| deposit_ids.contains(queued))
}

fn conflicts_with_queued_issuance(
    candidates: &VecDeque<NativeUsdomV4MiningCandidate>,
    deposit_ids: &[[u8; 32]],
) -> bool {
    has_issuance_deposit_overlap(
        candidates
            .iter()
            .flat_map(|candidate| candidate.issuance_deposit_ids.iter()),
        deposit_ids,
    )
}

/// One fully revalidated native-v4 mining template. `candidate_id` is present
/// only for a nonempty locally queued envelope and lets the runtime remove the
/// exact item after its block becomes canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeUsdomV4MiningTemplate {
    batch_header_commitment: dom_core::Hash256,
    candidate_id: Option<dom_core::Hash256>,
    envelope: UsdomV4ProofEnvelope,
}

impl NativeUsdomV4MiningTemplate {
    /// Header commitment to bind with the ordinary rangeproof PMMR root.
    pub fn batch_header_commitment(&self) -> dom_core::Hash256 {
        self.batch_header_commitment
    }

    /// Exact untrusted envelope revalidated to derive this template.
    pub fn envelope(&self) -> &UsdomV4ProofEnvelope {
        &self.envelope
    }

    /// Local pool identity, absent for the canonical empty fallback.
    pub fn candidate_id(&self) -> Option<dom_core::Hash256> {
        self.candidate_id
    }

    /// Consume the template and return its exact canonical envelope.
    pub fn into_envelope(self) -> UsdomV4ProofEnvelope {
        self.envelope
    }
}

#[derive(Debug, Clone)]
struct NativeUsdomV2MiningCandidate {
    id: dom_core::Hash256,
    encoded_len: usize,
    issuance_deposit_ids: Vec<[u8; 32]>,
    envelope: UsdomV4ProofEnvelope,
    witnesses: UsdomV2ExecutionWitnesses,
}

/// One fully revalidated candidate-V2 mining template. The proof envelope and
/// ordered state witnesses remain inseparable through header construction and
/// final package ingress. `candidate_id` is absent for the canonical empty
/// fallback used to keep DOM block production independent of USDOM traffic.
#[derive(Debug, Clone)]
pub struct NativeUsdomV2MiningTemplate {
    batch_header_commitment: dom_core::Hash256,
    candidate_id: Option<dom_core::Hash256>,
    envelope: UsdomV4ProofEnvelope,
    witnesses: UsdomV2ExecutionWitnesses,
}

impl NativeUsdomV2MiningTemplate {
    /// Header commitment to bind with the ordinary DOM rangeproof PMMR root.
    pub const fn batch_header_commitment(&self) -> dom_core::Hash256 {
        self.batch_header_commitment
    }

    /// Local pool identity, absent for the canonical empty fallback.
    pub const fn candidate_id(&self) -> Option<dom_core::Hash256> {
        self.candidate_id
    }

    /// Consume the template without separating its proof and witness bytes.
    pub fn into_parts(self) -> (UsdomV4ProofEnvelope, UsdomV2ExecutionWitnesses) {
        (self.envelope, self.witnesses)
    }
}

/// Runtime-owned native-v4 state, immutable verification policy and bounded
/// volatile research mining candidates. Construction restores the exact
/// canonical state and audits the complete reorganizable history before any
/// package can be ingested.
pub struct NativeUsdomV4Runtime {
    network_magic: u32,
    schedule: NativeUsdomV4ActivationSchedule,
    bridge: BridgeIdentity,
    checkpoint_policy: StaticCheckpointTrustPolicy,
    deposit_policy: StaticDepositTrustPolicy,
    closure_policy: Option<StaticIssuanceClosureTrustPolicy>,
    spend_verifier: Option<SpendVerifier>,
    state: NativeUsdomState,
    startup_audit: NativeUsdomV4HistoryAudit,
    mining_candidates: VecDeque<NativeUsdomV4MiningCandidate>,
    mining_candidate_bytes: usize,
}

impl NativeUsdomV4Runtime {
    /// Restore and audit one Regtest chain. Policy/bridge mismatch fails even
    /// when the current package contains no Ethereum checkpoint transition.
    pub fn restore(
        chain: &crate::chain_state::ChainState,
        bridge: BridgeIdentity,
        checkpoint_policy: StaticCheckpointTrustPolicy,
        deposit_policy: StaticDepositTrustPolicy,
        closure_policy: Option<StaticIssuanceClosureTrustPolicy>,
    ) -> Result<Self, DomError> {
        let schedule = native_usdom_v4_regtest_activation_schedule(bridge)?;
        Self::restore_inner(
            chain,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            // This compatibility constructor deliberately has no authority to
            // accept private transfer/burn proofs.  Regtest callers that need
            // that authority must use `restore_with_spend_verifier`.
            None,
            schedule,
            true,
        )
    }

    /// Restore one Regtest runtime with the exact canonical Groth16 verifying
    /// key committed by `bridge`. Malformed, wrong-shape or mismatched key
    /// bytes fail before any package ingress becomes available.
    pub fn restore_with_spend_verifier(
        chain: &crate::chain_state::ChainState,
        bridge: BridgeIdentity,
        checkpoint_policy: StaticCheckpointTrustPolicy,
        deposit_policy: StaticDepositTrustPolicy,
        closure_policy: Option<StaticIssuanceClosureTrustPolicy>,
        spend_verifying_key: &[u8],
    ) -> Result<Self, DomError> {
        let verifier = SpendVerifier::from_bytes(spend_verifying_key).map_err(|error| {
            DomError::PolicyRejected(format!(
                "native USDOM spend verifying key is invalid: {error}"
            ))
        })?;
        Self::restore_inner(
            chain,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            Some(verifier),
            native_usdom_v4_regtest_activation_schedule(bridge)?,
            true,
        )
    }

    /// Restore a runtime for any recognized DOM network under an exact
    /// activation schedule and the bridge-committed production verifier.
    pub fn restore_for_schedule_with_spend_verifier(
        chain: &crate::chain_state::ChainState,
        bridge: BridgeIdentity,
        checkpoint_policy: StaticCheckpointTrustPolicy,
        deposit_policy: StaticDepositTrustPolicy,
        closure_policy: Option<StaticIssuanceClosureTrustPolicy>,
        spend_verifying_key: &[u8],
        schedule: NativeUsdomV4ActivationSchedule,
    ) -> Result<Self, DomError> {
        let verifier = SpendVerifier::from_bytes(spend_verifying_key).map_err(|error| {
            DomError::PolicyRejected(format!(
                "native USDOM spend verifying key is invalid: {error}"
            ))
        })?;
        Self::restore_inner(
            chain,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            Some(verifier),
            schedule,
            false,
        )
    }

    fn restore_inner(
        chain: &crate::chain_state::ChainState,
        bridge: BridgeIdentity,
        checkpoint_policy: StaticCheckpointTrustPolicy,
        deposit_policy: StaticDepositTrustPolicy,
        closure_policy: Option<StaticIssuanceClosureTrustPolicy>,
        spend_verifier: Option<SpendVerifier>,
        schedule: NativeUsdomV4ActivationSchedule,
        allow_missing_verifier_on_regtest: bool,
    ) -> Result<Self, DomError> {
        let chain_id = dom_consensus::derive_chain_id(chain.network_magic, &chain.genesis_hash);
        if schedule.network_magic() != chain.network_magic || schedule.chain_id() != chain_id {
            return Err(DomError::PolicyRejected(
                "native USDOM runtime schedule does not match this chain".into(),
            ));
        }
        if spend_verifier.is_none()
            && (!allow_missing_verifier_on_regtest || chain.network_magic != NETWORK_MAGIC_REGTEST)
        {
            return Err(DomError::PolicyRejected(
                "scheduled native USDOM runtime requires its bridge-committed spend verifier"
                    .into(),
            ));
        }
        validate_static_checkpoint_policy_identity(
            chain.network_magic,
            bridge,
            &checkpoint_policy,
        )?;
        validate_static_deposit_policy_identity(bridge, &deposit_policy)?;
        if let Some(policy) = closure_policy.as_ref() {
            validate_static_issuance_closure_policy_identity(chain.network_magic, bridge, policy)?;
        }
        if let Some(verifier) = spend_verifier.as_ref() {
            validate_spend_verifier_identity(bridge, verifier)?;
        }
        let state = restore_persisted_usdom_v4_state_for_schedule(
            &chain.store,
            chain.network_magic,
            bridge,
            chain.tip_hash,
            schedule,
        )?;
        if spend_verifier.is_none()
            && state
                .state_commitment()
                .map_err(|error| {
                    DomError::Internal(format!(
                        "native USDOM restored state decomposition failed: {error}"
                    ))
                })?
                .nullifier_count
                != 0
        {
            return Err(DomError::PolicyRejected(
                "native USDOM private-spend history requires its committed verifying key".into(),
            ));
        }
        let startup_audit = audit_persisted_usdom_v4_reorg_window_for_schedule(
            &chain.store,
            chain.network_magic,
            bridge,
            chain.tip_hash,
            schedule,
        )?;
        if let Some(verifier) = spend_verifier.as_ref() {
            audit_persisted_usdom_v4_proof_window(
                chain,
                bridge,
                &checkpoint_policy,
                &deposit_policy,
                closure_policy.as_ref(),
                verifier,
                &state,
                &startup_audit,
            )?;
        }
        Ok(Self {
            network_magic: chain.network_magic,
            schedule,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifier,
            state,
            startup_audit,
            mining_candidates: VecDeque::new(),
            mining_candidate_bytes: 0,
        })
    }

    /// Ingest one exact canonical package through automatic branch selection.
    pub fn ingest(
        &mut self,
        chain: &mut crate::chain_state::ChainState,
        package_bytes: &[u8],
        now: Timestamp,
    ) -> Result<crate::chain_state::ConnectResult, DomError> {
        if chain.network_magic != self.network_magic {
            return Err(DomError::Internal(
                "native USDOM runtime attached to a different network".into(),
            ));
        }
        let outcome = if let Some(verifier) = self.spend_verifier.as_ref() {
            chain.ingest_usdom_v4_package_for_schedule(
                package_bytes,
                now,
                &mut self.state,
                self.bridge,
                &self.checkpoint_policy,
                &self.deposit_policy,
                self.closure_policy.as_ref(),
                verifier,
                self.schedule,
            )?
        } else {
            chain.ingest_usdom_v4_package_regtest(
                package_bytes,
                now,
                &mut self.state,
                self.bridge,
                &self.checkpoint_policy,
                &self.deposit_policy,
                self.closure_policy.as_ref(),
                None,
            )?
        };
        // Peer/canonical ingress does not pass through the local miner's
        // `complete_mining_candidate` callback. Release every local envelope
        // whose issuance is now consumed by the resulting canonical state so
        // non-mining nodes cannot retain dead reservations and exhaust their
        // bounded volatile pool indefinitely.
        self.prune_consumed_issuance_candidates()?;
        Ok(outcome)
    }

    fn prune_consumed_issuance_candidates(&mut self) -> Result<usize, DomError> {
        let removed_bytes = self
            .mining_candidates
            .iter()
            .filter(|candidate| {
                candidate
                    .issuance_deposit_ids
                    .iter()
                    .any(|deposit_id| self.state.has_consumed_deposit(deposit_id))
            })
            .try_fold(0usize, |total, candidate| {
                total.checked_add(candidate.encoded_len).ok_or_else(|| {
                    DomError::Internal("mining candidate prune byte total overflow".into())
                })
            })?;
        let next_bytes = self
            .mining_candidate_bytes
            .checked_sub(removed_bytes)
            .ok_or_else(|| DomError::Internal("mining candidate prune byte underflow".into()))?;
        let before = self.mining_candidates.len();
        self.mining_candidates.retain(|candidate| {
            !candidate
                .issuance_deposit_ids
                .iter()
                .any(|deposit_id| self.state.has_consumed_deposit(deposit_id))
        });
        self.mining_candidate_bytes = next_bytes;
        Ok(before - self.mining_candidates.len())
    }

    fn verified_envelope_preview(
        &self,
        envelope: &UsdomV4ProofEnvelope,
        block_timestamp: Timestamp,
    ) -> Result<(dom_core::Hash256, VerifiedEnvelopeTransitions), DomError> {
        let verified = verify_envelope_transitions(
            self.network_magic,
            block_timestamp.0,
            self.bridge,
            &self.checkpoint_policy,
            &self.deposit_policy,
            self.closure_policy.as_ref(),
            self.spend_verifier.as_ref(),
            &envelope.entries,
        )?;
        let before = self.state.state_root();
        let mut preview = self.state.clone();
        let (receipt, _) = preview
            .apply_batch(
                BlockContext {
                    timestamp: block_timestamp.0,
                },
                &verified.transitions,
            )
            .map_err(|error| {
                DomError::Invalid(format!(
                    "native USDOM mining envelope state transition failed: {error}"
                ))
            })?;
        if receipt.previous_state_root != before || preview.state_root() != receipt.new_state_root {
            return Err(DomError::Internal(
                "native USDOM mining preview produced inconsistent state roots".into(),
            ));
        }
        Ok((receipt.header_commitment, verified))
    }

    fn envelope_header_commitment(
        &self,
        envelope: &UsdomV4ProofEnvelope,
        block_timestamp: Timestamp,
    ) -> Result<dom_core::Hash256, DomError> {
        self.verified_envelope_preview(envelope, block_timestamp)
            .map(|(commitment, _)| commitment)
    }

    /// Admit one canonical nonempty envelope to the bounded volatile
    /// mining pool. Admission verifies every proof against the current state at
    /// `candidate_timestamp`, but grants no lasting authority: template
    /// construction and final package ingress both verify it again.
    pub fn admit_mining_envelope(
        &mut self,
        envelope_bytes: &[u8],
        candidate_timestamp: Timestamp,
    ) -> Result<dom_core::Hash256, DomError> {
        if self.network_magic != NETWORK_MAGIC_REGTEST && self.spend_verifier.is_none() {
            return Err(DomError::PolicyRejected(
                "public-network native USDOM mining requires its committed spend verifier".into(),
            ));
        }
        if envelope_bytes.len() < USDOM_V4_ENVELOPE_HEADER_BYTES
            || envelope_bytes.len() > MAX_USDOM_V4_ENVELOPE_BYTES
        {
            return Err(DomError::Malformed(
                "invalid native USDOM v4 envelope framing".into(),
            ));
        }
        let id = blake2b_256_tagged(TAG_USDOM_V4_MINING_CANDIDATE, envelope_bytes);
        if self
            .mining_candidates
            .iter()
            .any(|candidate| candidate.id == id)
        {
            return Ok(id);
        }
        let next_bytes = self
            .mining_candidate_bytes
            .checked_add(envelope_bytes.len())
            .ok_or_else(|| {
                DomError::PolicyRejected("mining candidate byte total overflow".into())
            })?;
        if self.mining_candidates.len() >= MAX_USDOM_V4_MINING_CANDIDATES
            || next_bytes > MAX_USDOM_V4_MINING_CANDIDATE_BYTES
        {
            return Err(DomError::PolicyRejected(
                "native USDOM mining candidate pool is full".into(),
            ));
        }
        // Decode and allocate retained proof payloads only after cheap raw
        // bounds, exact retransmission and aggregate pool admission succeed.
        let envelope = UsdomV4ProofEnvelope::from_bytes(envelope_bytes)?;
        if envelope.entries.is_empty() {
            return Err(DomError::PolicyRejected(
                "empty native USDOM envelopes are generated internally".into(),
            ));
        }
        let (_, verified) = self.verified_envelope_preview(&envelope, candidate_timestamp)?;
        let issuance_deposit_ids = verified_issuance_deposit_ids(&verified.transitions);
        // Canonical state prevents a deposit from being issued twice, but the
        // volatile pool is not part of that state. Without this reservation,
        // distinct otherwise-valid envelopes could queue the same deposit,
        // consume every bounded candidate slot and create ambiguous status for
        // competing candidate IDs. Preserve the first verified candidate until
        // it is mined or evicted by normal template revalidation.
        if conflicts_with_queued_issuance(&self.mining_candidates, &issuance_deposit_ids) {
            return Err(DomError::PolicyRejected(
                "native USDOM issuance deposit already has a queued candidate".into(),
            ));
        }
        self.mining_candidates
            .push_back(NativeUsdomV4MiningCandidate {
                id,
                encoded_len: envelope_bytes.len(),
                issuance_deposit_ids,
                envelope,
            });
        self.mining_candidate_bytes = next_bytes;
        Ok(id)
    }

    /// Build a template from the oldest candidate still valid for the exact
    /// current state and timestamp. Permanently stale candidates are removed;
    /// retryable candidates rotate to the back. If none is usable, return the
    /// canonical empty envelope so chain progress never depends on USDOM flow.
    pub fn mining_batch_template(
        &mut self,
        block_timestamp: Timestamp,
    ) -> Result<NativeUsdomV4MiningTemplate, DomError> {
        let candidates = self.mining_candidates.len();
        for _ in 0..candidates {
            let candidate = self
                .mining_candidates
                .pop_front()
                .ok_or_else(|| DomError::Internal("mining candidate queue underflow".into()))?;
            self.mining_candidate_bytes = self
                .mining_candidate_bytes
                .checked_sub(candidate.encoded_len)
                .ok_or_else(|| DomError::Internal("mining candidate byte underflow".into()))?;
            match self.envelope_header_commitment(&candidate.envelope, block_timestamp) {
                Ok(batch_header_commitment) => {
                    self.mining_candidate_bytes = self
                        .mining_candidate_bytes
                        .checked_add(candidate.encoded_len)
                        .ok_or_else(|| {
                            DomError::Internal("mining candidate byte total overflow".into())
                        })?;
                    let template = NativeUsdomV4MiningTemplate {
                        batch_header_commitment,
                        candidate_id: Some(candidate.id),
                        envelope: candidate.envelope.clone(),
                    };
                    self.mining_candidates.push_front(candidate);
                    return Ok(template);
                }
                Err(error) if error.is_retryable() => {
                    self.mining_candidate_bytes = self
                        .mining_candidate_bytes
                        .checked_add(candidate.encoded_len)
                        .ok_or_else(|| {
                            DomError::Internal("mining candidate byte total overflow".into())
                        })?;
                    self.mining_candidates.push_back(candidate);
                }
                Err(DomError::Malformed(_))
                | Err(DomError::Invalid(_))
                | Err(DomError::PolicyRejected(_)) => {}
                Err(error) => {
                    self.mining_candidate_bytes = self
                        .mining_candidate_bytes
                        .checked_add(candidate.encoded_len)
                        .ok_or_else(|| {
                            DomError::Internal("mining candidate byte total overflow".into())
                        })?;
                    self.mining_candidates.push_front(candidate);
                    return Err(error);
                }
            }
        }
        let envelope = UsdomV4ProofEnvelope::empty();
        Ok(NativeUsdomV4MiningTemplate {
            batch_header_commitment: self.envelope_header_commitment(&envelope, block_timestamp)?,
            candidate_id: None,
            envelope,
        })
    }

    /// Remove exactly one candidate after the package carrying it became
    /// canonical. Side-chain races retain the candidate for another template.
    pub fn complete_mining_candidate(
        &mut self,
        candidate_id: dom_core::Hash256,
    ) -> Result<bool, DomError> {
        let Some(index) = self
            .mining_candidates
            .iter()
            .position(|candidate| candidate.id == candidate_id)
        else {
            return Ok(false);
        };
        let candidate = self
            .mining_candidates
            .remove(index)
            .ok_or_else(|| DomError::Internal("mining candidate disappeared".into()))?;
        self.mining_candidate_bytes = self
            .mining_candidate_bytes
            .checked_sub(candidate.encoded_len)
            .ok_or_else(|| DomError::Internal("mining candidate byte underflow".into()))?;
        Ok(true)
    }

    /// Current volatile candidate count and exact canonical byte total.
    pub fn mining_candidate_stats(&self) -> (usize, usize) {
        (self.mining_candidates.len(), self.mining_candidate_bytes)
    }

    /// Whether the bounded volatile pool contains this exact candidate and
    /// its proof-verified issuance set contains the supplied deposit. The
    /// method exposes no witness bytes or private note data.
    pub fn has_queued_issuance_candidate(
        &self,
        candidate_id: dom_core::Hash256,
        deposit_id: &[u8; 32],
    ) -> bool {
        candidate_id != dom_core::Hash256::ZERO
            && *deposit_id != [0; 32]
            && self.mining_candidates.iter().any(|candidate| {
                candidate.id == candidate_id && candidate.issuance_deposit_ids.contains(deposit_id)
            })
    }

    /// Derive the commitment for an empty native batch at one exact DOM block
    /// timestamp without mutating runtime state. Kept as a read-only helper for
    /// callers that explicitly need the no-transition commitment.
    pub fn empty_batch_header_commitment(
        &self,
        block_timestamp: Timestamp,
    ) -> Result<dom_core::Hash256, DomError> {
        self.envelope_header_commitment(&UsdomV4ProofEnvelope::empty(), block_timestamp)
    }

    /// Current canonical native state owned by this runtime.
    pub fn state(&self) -> &NativeUsdomState {
        &self.state
    }

    /// Immutable bridge identity bound into native state and checkpoint policy.
    pub fn bridge_identity(&self) -> BridgeIdentity {
        self.bridge
    }

    /// Exact activation schedule used by restore, audit and every ingress.
    pub fn activation_schedule(&self) -> NativeUsdomV4ActivationSchedule {
        self.schedule
    }

    /// Ingest the selected final V1 direct extension and atomically install
    /// the candidate-V2 migration marker with the resulting native state.
    /// Callers must switch protocol phases after this succeeds; subsequent V1
    /// ingress is rejected by persisted consensus state.
    #[allow(clippy::too_many_arguments)]
    pub fn ingest_and_activate_v2(
        &mut self,
        chain: &mut crate::chain_state::ChainState,
        package_bytes: &[u8],
        now: Timestamp,
        first_v2_height: u64,
    ) -> Result<
        (
            crate::chain_state::ConnectResult,
            NativeUsdomV2ActivationSchedule,
        ),
        DomError,
    > {
        let spend_verifier = self.spend_verifier.as_ref().ok_or_else(|| {
            DomError::PolicyRejected(
                "candidate-V2 migration requires the bridge-committed spend verifier".into(),
            )
        })?;
        chain.connect_usdom_v4_package_and_activate_v2_for_schedule(
            package_bytes,
            now,
            &mut self.state,
            self.bridge,
            &self.checkpoint_policy,
            &self.deposit_policy,
            self.closure_policy.as_ref(),
            spend_verifier,
            self.schedule,
            first_v2_height,
        )
    }

    /// Configuration hash of the loaded private-spend verifier, if enabled.
    /// `None` means transfer and burn proof kinds remain fail-closed.
    pub fn spend_verifier_config_hash(&self) -> Option<dom_core::Hash256> {
        self.spend_verifier.as_ref().map(SpendVerifier::config_hash)
    }

    /// Audit evidence obtained before the runtime accepted package ingress.
    pub fn startup_audit(&self) -> &NativeUsdomV4HistoryAudit {
        &self.startup_audit
    }
}

/// Runtime-owned candidate-v2 state and immutable verification authority.
/// Construction verifies the bridge, both Ethereum policies, the exact spend
/// key and the persisted migration/tip before any package can be ingested.
pub struct NativeUsdomV2Runtime {
    network_magic: u32,
    schedule: NativeUsdomV2ActivationSchedule,
    bridge: BridgeIdentity,
    checkpoint_policy: StaticCheckpointTrustPolicy,
    deposit_policy: StaticDepositTrustPolicy,
    closure_policy: Option<StaticIssuanceClosureTrustPolicy>,
    spend_verifier: SpendVerifier,
    spend_verifying_key: Vec<u8>,
    state: StateCommitmentV2,
    mining_candidates: VecDeque<NativeUsdomV2MiningCandidate>,
    mining_candidate_bytes: usize,
}

impl NativeUsdomV2Runtime {
    /// Restore one exact candidate-v2 runtime. Unlike the V1 Regtest research
    /// path, V2 never permits a missing private-spend verifier.
    pub fn restore_for_schedule_with_spend_verifier(
        chain: &crate::chain_state::ChainState,
        bridge: BridgeIdentity,
        checkpoint_policy: StaticCheckpointTrustPolicy,
        deposit_policy: StaticDepositTrustPolicy,
        closure_policy: Option<StaticIssuanceClosureTrustPolicy>,
        spend_verifying_key: &[u8],
        schedule: NativeUsdomV2ActivationSchedule,
    ) -> Result<Self, DomError> {
        let chain_id = dom_consensus::derive_chain_id(chain.network_magic, &chain.genesis_hash);
        if schedule.network_magic() != chain.network_magic || schedule.chain_id() != chain_id {
            return Err(DomError::PolicyRejected(
                "native USDOM V2 runtime schedule does not match this chain".into(),
            ));
        }
        validate_static_checkpoint_policy_identity(
            chain.network_magic,
            bridge,
            &checkpoint_policy,
        )?;
        validate_static_deposit_policy_identity(bridge, &deposit_policy)?;
        let spend_verifier = SpendVerifier::from_bytes(spend_verifying_key).map_err(|error| {
            DomError::PolicyRejected(format!(
                "native USDOM V2 spend verifying key is invalid: {error}"
            ))
        })?;
        validate_spend_verifier_identity(bridge, &spend_verifier)?;
        let state = restore_persisted_usdom_v2_state_for_schedule(
            &chain.store,
            chain.network_magic,
            chain.tip_hash,
            bridge,
            &checkpoint_policy,
            &deposit_policy,
            closure_policy.as_ref(),
            &spend_verifier,
            schedule,
        )?;
        Ok(Self {
            network_magic: chain.network_magic,
            schedule,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifier,
            spend_verifying_key: spend_verifying_key.to_vec(),
            state,
            mining_candidates: VecDeque::new(),
            mining_candidate_bytes: 0,
        })
    }

    /// Ingest one exact package/witness pair through the automatic candidate-v2
    /// branch-selection entry point.
    pub fn ingest(
        &mut self,
        chain: &mut crate::chain_state::ChainState,
        package_bytes: &[u8],
        witness_bundle: &UsdomV2ExecutionWitnesses,
        now: Timestamp,
    ) -> Result<crate::chain_state::ConnectResult, DomError> {
        if chain.network_magic != self.network_magic {
            return Err(DomError::Internal(
                "native USDOM V2 runtime attached to a different network".into(),
            ));
        }
        chain.ingest_usdom_v2_package_for_schedule(
            package_bytes,
            witness_bundle,
            now,
            &mut self.state,
            self.bridge,
            &self.checkpoint_policy,
            &self.deposit_policy,
            self.closure_policy.as_ref(),
            &self.spend_verifier,
            self.schedule,
        )
    }

    fn verified_mining_header_commitment(
        &self,
        envelope: &UsdomV4ProofEnvelope,
        witnesses: &UsdomV2ExecutionWitnesses,
        block_timestamp: Timestamp,
    ) -> Result<(dom_core::Hash256, Vec<[u8; 32]>), DomError> {
        let verified = verify_envelope_transitions(
            self.network_magic,
            block_timestamp.0,
            self.bridge,
            &self.checkpoint_policy,
            &self.deposit_policy,
            self.closure_policy.as_ref(),
            Some(&self.spend_verifier),
            &envelope.entries,
        )?;
        let issuance_deposit_ids = verified_issuance_deposit_ids(&verified.transitions);
        let (next, receipt) = apply_v2_transition_batch_with_receipt(
            self.state.root(),
            BlockContext {
                timestamp: block_timestamp.0,
            },
            self.state,
            &verified.transitions,
            witnesses.witnesses(),
        )
        .map_err(|error| {
            DomError::Invalid(format!("native USDOM V2 mining transition failed: {error}"))
        })?;
        if receipt.previous_state_root != self.state.root()
            || receipt.new_state_root != next.root()
            || usize::try_from(receipt.transition_count).ok() != Some(envelope.entries.len())
        {
            return Err(DomError::Internal(
                "native USDOM V2 mining preview produced inconsistent state roots".into(),
            ));
        }
        Ok((receipt.header_commitment, issuance_deposit_ids))
    }

    fn mining_header_commitment(
        &self,
        envelope: &UsdomV4ProofEnvelope,
        witnesses: &UsdomV2ExecutionWitnesses,
        block_timestamp: Timestamp,
    ) -> Result<dom_core::Hash256, DomError> {
        self.verified_mining_header_commitment(envelope, witnesses, block_timestamp)
            .map(|(commitment, _)| commitment)
    }

    /// Admit one canonical nonempty proof-and-witness pair to the bounded
    /// volatile V2 mining pool. Admission verifies every proof and stateless
    /// transition against the current state and candidate timestamp. Template
    /// construction and final package ingress perform the verification again.
    pub fn admit_mining_candidate(
        &mut self,
        envelope_bytes: &[u8],
        witness_bytes: &[u8],
        candidate_timestamp: Timestamp,
    ) -> Result<dom_core::Hash256, DomError> {
        let encoded_len = envelope_bytes
            .len()
            .checked_add(witness_bytes.len())
            .ok_or_else(|| DomError::PolicyRejected("V2 mining candidate size overflow".into()))?;
        let id = dom_core::Hash256::from_bytes(
            dom_usdom_rpc_protocol::candidate_id_v1(envelope_bytes, witness_bytes).map_err(
                |error| {
                    DomError::PolicyRejected(format!(
                        "invalid V2 mining candidate identity input: {error}"
                    ))
                },
            )?,
        );
        if self
            .mining_candidates
            .iter()
            .any(|candidate| candidate.id == id)
        {
            return Ok(id);
        }
        let next_bytes = self
            .mining_candidate_bytes
            .checked_add(encoded_len)
            .ok_or_else(|| DomError::PolicyRejected("V2 mining pool size overflow".into()))?;
        if self.mining_candidates.len() >= MAX_USDOM_V4_MINING_CANDIDATES
            || next_bytes > MAX_USDOM_V4_MINING_CANDIDATE_BYTES
        {
            return Err(DomError::PolicyRejected(
                "native USDOM V2 mining candidate pool is full".into(),
            ));
        }
        // Candidate identity validates the independent raw component ceilings.
        // Avoid parsing/copying either component until exact retransmission and
        // aggregate pool admission have succeeded.
        let envelope = UsdomV4ProofEnvelope::from_bytes(envelope_bytes)?;
        let witnesses = UsdomV2ExecutionWitnesses::from_bytes(witness_bytes)?;
        if envelope.entries.is_empty() {
            return Err(DomError::PolicyRejected(
                "empty native USDOM V2 candidates are generated internally".into(),
            ));
        }
        if envelope.entries.len() != witnesses.witnesses().len() {
            return Err(DomError::Invalid(
                "native USDOM V2 mining proof/witness count mismatch".into(),
            ));
        }
        let (_, issuance_deposit_ids) =
            self.verified_mining_header_commitment(&envelope, &witnesses, candidate_timestamp)?;
        if has_issuance_deposit_overlap(
            self.mining_candidates
                .iter()
                .flat_map(|candidate| candidate.issuance_deposit_ids.iter()),
            &issuance_deposit_ids,
        ) {
            return Err(DomError::PolicyRejected(
                "native USDOM V2 issuance deposit already has a queued candidate".into(),
            ));
        }
        self.mining_candidates
            .push_back(NativeUsdomV2MiningCandidate {
                id,
                encoded_len,
                issuance_deposit_ids,
                envelope,
                witnesses,
            });
        self.mining_candidate_bytes = next_bytes;
        Ok(id)
    }

    /// Revalidate the oldest usable V2 candidate for the exact state and
    /// timestamp. Invalid stale entries are discarded, retryable entries
    /// rotate, and an empty proof/witness pair preserves DOM chain liveness
    /// when no USDOM operation is ready.
    pub fn mining_batch_template(
        &mut self,
        block_timestamp: Timestamp,
    ) -> Result<NativeUsdomV2MiningTemplate, DomError> {
        let candidates = self.mining_candidates.len();
        for _ in 0..candidates {
            let candidate = self
                .mining_candidates
                .pop_front()
                .ok_or_else(|| DomError::Internal("V2 mining candidate queue underflow".into()))?;
            self.mining_candidate_bytes = self
                .mining_candidate_bytes
                .checked_sub(candidate.encoded_len)
                .ok_or_else(|| DomError::Internal("V2 mining byte counter underflow".into()))?;
            match self.mining_header_commitment(
                &candidate.envelope,
                &candidate.witnesses,
                block_timestamp,
            ) {
                Ok(batch_header_commitment) => {
                    self.mining_candidate_bytes = self
                        .mining_candidate_bytes
                        .checked_add(candidate.encoded_len)
                        .ok_or_else(|| {
                            DomError::Internal("V2 mining byte counter overflow".into())
                        })?;
                    let template = NativeUsdomV2MiningTemplate {
                        batch_header_commitment,
                        candidate_id: Some(candidate.id),
                        envelope: candidate.envelope.clone(),
                        witnesses: candidate.witnesses.clone(),
                    };
                    self.mining_candidates.push_front(candidate);
                    return Ok(template);
                }
                Err(error) if error.is_retryable() => {
                    self.mining_candidate_bytes = self
                        .mining_candidate_bytes
                        .checked_add(candidate.encoded_len)
                        .ok_or_else(|| {
                            DomError::Internal("V2 mining byte counter overflow".into())
                        })?;
                    self.mining_candidates.push_back(candidate);
                }
                Err(DomError::Malformed(_))
                | Err(DomError::Invalid(_))
                | Err(DomError::PolicyRejected(_)) => {}
                Err(error) => {
                    self.mining_candidate_bytes = self
                        .mining_candidate_bytes
                        .checked_add(candidate.encoded_len)
                        .ok_or_else(|| {
                            DomError::Internal("V2 mining byte counter overflow".into())
                        })?;
                    self.mining_candidates.push_front(candidate);
                    return Err(error);
                }
            }
        }
        let envelope = UsdomV4ProofEnvelope::empty();
        let witnesses = UsdomV2ExecutionWitnesses::new(Vec::new())?;
        Ok(NativeUsdomV2MiningTemplate {
            batch_header_commitment: self.mining_header_commitment(
                &envelope,
                &witnesses,
                block_timestamp,
            )?,
            candidate_id: None,
            envelope,
            witnesses,
        })
    }

    /// Remove exactly one V2 candidate after its package becomes canonical.
    pub fn complete_mining_candidate(
        &mut self,
        candidate_id: dom_core::Hash256,
    ) -> Result<bool, DomError> {
        let Some(index) = self
            .mining_candidates
            .iter()
            .position(|candidate| candidate.id == candidate_id)
        else {
            return Ok(false);
        };
        let candidate = self
            .mining_candidates
            .remove(index)
            .ok_or_else(|| DomError::Internal("V2 mining candidate disappeared".into()))?;
        self.mining_candidate_bytes = self
            .mining_candidate_bytes
            .checked_sub(candidate.encoded_len)
            .ok_or_else(|| DomError::Internal("V2 mining byte counter underflow".into()))?;
        Ok(true)
    }

    /// Current volatile candidate count and exact canonical byte total.
    pub fn mining_candidate_stats(&self) -> (usize, usize) {
        (self.mining_candidates.len(), self.mining_candidate_bytes)
    }

    /// Current canonical candidate-v2 commitment.
    pub const fn state(&self) -> StateCommitmentV2 {
        self.state
    }

    /// Exact persisted migration schedule used by every ingress.
    pub const fn activation_schedule(&self) -> NativeUsdomV2ActivationSchedule {
        self.schedule
    }

    /// Immutable bridge identity bound into the state and verifier policies.
    pub const fn bridge_identity(&self) -> BridgeIdentity {
        self.bridge
    }

    /// Configuration identity of the mandatory private-spend verifier.
    pub fn spend_verifier_config_hash(&self) -> dom_core::Hash256 {
        self.spend_verifier.config_hash()
    }

    /// Immutable checkpoint policy used by every candidate-v2 transition.
    pub const fn checkpoint_policy(&self) -> &StaticCheckpointTrustPolicy {
        &self.checkpoint_policy
    }

    /// Immutable reserve-deposit policy used by every candidate-v2 transition.
    pub const fn deposit_policy(&self) -> &StaticDepositTrustPolicy {
        &self.deposit_policy
    }

    /// Immutable issuance-closure verifier, absent for historical manifests.
    pub const fn issuance_closure_policy(&self) -> Option<&StaticIssuanceClosureTrustPolicy> {
        self.closure_policy.as_ref()
    }

    /// Exact canonical spend-verifying key needed by portable checkpoint
    /// execution.
    pub fn spend_verifying_key(&self) -> &[u8] {
        &self.spend_verifying_key
    }
}

fn revert_authenticated_persisted_usdom_v4_block(
    store: &DomStore,
    network_magic: u32,
    expected_bridge: BridgeIdentity,
    state: &mut NativeUsdomState,
    cursor: dom_core::Hash256,
) -> Result<dom_core::Hash256, DomError> {
    let package_bytes =
        load_persisted_usdom_v4_package(store, network_magic, cursor)?.ok_or_else(|| {
            DomError::Internal("canonical native USDOM block package is missing".into())
        })?;
    let package = UsdomV4BlockPackage::from_bytes(&package_bytes).map_err(|error| {
        DomError::Internal(format!(
            "canonical native USDOM rewind package is corrupt: {error}"
        ))
    })?;
    let block = package.block();
    let header_bytes = DomSerialize::to_bytes(&block.header)?;
    if crate::canonical_header_identifier(network_magic, &header_bytes)? != cursor {
        return Err(DomError::Internal(
            "canonical native USDOM rewind block identifier mismatch".into(),
        ));
    }
    if store.get_hash_at_height(block.header.height.0)? != Some(*cursor.as_bytes()) {
        return Err(DomError::Internal(
            "canonical native USDOM rewind block is absent from its declared height".into(),
        ));
    }
    let undo_bytes = store
        .get_consensus_state(&persistence_key(USDOM_V4_UNDO_PREFIX, cursor))?
        .ok_or_else(|| DomError::Internal("canonical native USDOM undo is missing".into()))?;
    let undo = BatchUndo::from_bytes(&undo_bytes).map_err(|error| {
        DomError::Internal(format!("canonical native USDOM undo is corrupt: {error}"))
    })?;
    if undo.after_root() != state.state_root() || undo.block_timestamp() != block.header.timestamp.0
    {
        return Err(DomError::Internal(
            "native USDOM undo does not match current state or block time".into(),
        ));
    }
    let (_, _, raw_rangeproof_root) =
        compute_block_pmmr_roots(block.header.height, &block.coinbase, &block.transactions)?;
    let batch_commitment = undo
        .header_commitment(expected_bridge.dom_domain)
        .map_err(|error| DomError::Internal(format!("invalid native USDOM undo: {error}")))?;
    let bound_root = bind_usdom_batch_commitment(raw_rangeproof_root, batch_commitment)?;
    if bound_root != block.header.rangeproof_root {
        return Err(DomError::Internal(
            "native USDOM undo is not authenticated by the canonical block header".into(),
        ));
    }
    state
        .revert_batch(&undo, batch_commitment)
        .map_err(|error| DomError::Internal(format!("native USDOM rewind failed: {error}")))?;
    Ok(block.header.prev_hash)
}

/// Audit every canonical native-v4 package and authenticated undo needed by
/// the maximum permitted reorganization window. If the activation boundary is
/// nearer, the reconstructed boundary state must be canonically empty.
pub fn audit_persisted_usdom_v4_reorg_window(
    store: &DomStore,
    network_magic: u32,
    expected_bridge: BridgeIdentity,
    canonical_tip: dom_core::Hash256,
) -> Result<NativeUsdomV4HistoryAudit, DomError> {
    if network_magic != NETWORK_MAGIC_REGTEST {
        return Err(DomError::PolicyRejected(
            "native USDOM history audit is available only on explicit Regtest".into(),
        ));
    }
    let schedule = native_usdom_v4_regtest_activation_schedule(expected_bridge)?;
    audit_persisted_usdom_v4_reorg_window_for_schedule(
        store,
        network_magic,
        expected_bridge,
        canonical_tip,
        schedule,
    )
}

/// Audit the canonical package/undo window against an exact ratified
/// activation schedule for any recognized DOM network.
pub fn audit_persisted_usdom_v4_reorg_window_for_schedule(
    store: &DomStore,
    network_magic: u32,
    expected_bridge: BridgeIdentity,
    canonical_tip: dom_core::Hash256,
    schedule: NativeUsdomV4ActivationSchedule,
) -> Result<NativeUsdomV4HistoryAudit, DomError> {
    schedule.validate()?;
    if schedule.network_magic() != network_magic || canonical_tip == dom_core::Hash256::ZERO {
        return Err(DomError::PolicyRejected(
            "native USDOM history audit does not match its activation schedule".into(),
        ));
    }
    let mut state = restore_persisted_usdom_v4_state_for_schedule(
        store,
        network_magic,
        expected_bridge,
        canonical_tip,
        schedule,
    )?;
    let mut cursor = canonical_tip;
    let mut audited_blocks = 0u64;
    let mut reached_activation_boundary = false;
    while audited_blocks < crate::reorg::MAX_REORG_DEPTH {
        let header_bytes = store.get_block_header(cursor.as_bytes())?.ok_or_else(|| {
            DomError::Internal("canonical native USDOM audit header is missing".into())
        })?;
        let header =
            dom_consensus::block::BlockHeader::from_bytes(&header_bytes).map_err(|error| {
                DomError::Internal(format!(
                    "canonical native USDOM audit header is corrupt: {error}"
                ))
            })?;
        if header.version != BLOCK_VERSION_V4 {
            let boundary_successor = header.height.0.checked_add(1).ok_or_else(|| {
                DomError::Internal("native USDOM activation boundary height overflow".into())
            })?;
            if boundary_successor != schedule.first_v4_height() {
                return Err(DomError::Internal(
                    "native USDOM audit reached a non-v4 block outside the activation boundary"
                        .into(),
                ));
            }
            reached_activation_boundary = true;
            break;
        }
        if header.height.0 < schedule.first_v4_height() {
            return Err(DomError::Internal(
                "native USDOM audit found v4 below the ratified activation height".into(),
            ));
        }
        if store.get_hash_at_height(header.height.0)? != Some(*cursor.as_bytes()) {
            return Err(DomError::Internal(
                "native USDOM audit block is not canonical at its declared height".into(),
            ));
        }
        cursor = revert_authenticated_persisted_usdom_v4_block(
            store,
            network_magic,
            expected_bridge,
            &mut state,
            cursor,
        )?;
        audited_blocks += 1;
    }
    if reached_activation_boundary {
        let empty = NativeUsdomState::new(expected_bridge).map_err(|error| {
            DomError::Internal(format!("native USDOM audit identity failed: {error}"))
        })?;
        if state.state_root() != empty.state_root()
            || state.export_entries() != empty.export_entries()
        {
            return Err(DomError::Internal(
                "native USDOM activation boundary is not the canonical empty state".into(),
            ));
        }
    }
    Ok(NativeUsdomV4HistoryAudit {
        canonical_tip,
        oldest_audited_parent: cursor,
        audited_blocks,
        boundary_state_root: state.state_root(),
        reached_activation_boundary,
    })
}

#[allow(clippy::too_many_arguments)]
fn audit_persisted_usdom_v4_proof_window(
    chain: &crate::chain_state::ChainState,
    expected_bridge: BridgeIdentity,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    closure_policy: Option<&StaticIssuanceClosureTrustPolicy>,
    spend_verifier: &SpendVerifier,
    tip_state: &NativeUsdomState,
    structural_audit: &NativeUsdomV4HistoryAudit,
) -> Result<(), DomError> {
    validate_spend_verifier_identity(expected_bridge, spend_verifier)?;
    let mut cursor = structural_audit.canonical_tip;
    let mut packages = Vec::with_capacity(structural_audit.audited_blocks as usize);
    for _ in 0..structural_audit.audited_blocks {
        let package_bytes =
            load_persisted_usdom_v4_package(&chain.store, chain.network_magic, cursor)?
                .ok_or_else(|| {
                    DomError::Internal("native USDOM proof-audit package is missing".into())
                })?;
        let package = UsdomV4BlockPackage::from_bytes(&package_bytes).map_err(|error| {
            DomError::Internal(format!(
                "native USDOM proof-audit package is corrupt: {error}"
            ))
        })?;
        let header_bytes = DomSerialize::to_bytes(&package.block().header)?;
        if crate::canonical_header_identifier(chain.network_magic, &header_bytes)? != cursor
            || chain
                .store
                .get_hash_at_height(package.block().header.height.0)?
                != Some(*cursor.as_bytes())
        {
            return Err(DomError::Internal(
                "native USDOM proof-audit package is not canonical".into(),
            ));
        }
        cursor = package.block().header.prev_hash;
        packages.push((package_bytes, package));
    }
    if cursor != structural_audit.oldest_audited_parent {
        return Err(DomError::Internal(
            "native USDOM proof-audit boundary mismatch".into(),
        ));
    }
    let mut replay_state = rewind_persisted_usdom_v4_state_to_ancestor(
        &chain.store,
        chain.network_magic,
        expected_bridge,
        structural_audit.canonical_tip,
        structural_audit.oldest_audited_parent,
    )?;
    if replay_state.state_root() != structural_audit.boundary_state_root {
        return Err(DomError::Internal(
            "native USDOM proof-audit boundary state mismatch".into(),
        ));
    }
    packages.reverse();
    let chain_id = dom_consensus::derive_chain_id(chain.network_magic, &chain.genesis_hash);
    for (package_bytes, package) in packages {
        let block = package.block();
        let context = ValidationContext {
            current_height: block.header.height,
            chain_id: *chain_id.as_bytes(),
            now: Timestamp(u64::MAX),
        };
        let verified = verify_usdom_v4_serialized_candidate_regtest_inner(
            &package_bytes,
            &context,
            chain.network_magic,
            &replay_state,
            expected_bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            Some(spend_verifier),
        )?;
        let stored_undo = chain
            .store
            .get_consensus_state(&persistence_key(
                USDOM_V4_UNDO_PREFIX,
                verified.block_identifier(),
            ))?
            .ok_or_else(|| DomError::Internal("native USDOM proof-audit undo is missing".into()))?;
        let verified_undo = verified.undo.to_bytes().map_err(|error| {
            DomError::Internal(format!(
                "native USDOM proof-audit undo encoding failed: {error}"
            ))
        })?;
        if stored_undo != verified_undo {
            return Err(DomError::Internal(
                "native USDOM proof-audit undo differs from verified transition".into(),
            ));
        }
        replay_state = verified.next_state;
    }
    if replay_state.state_root() != tip_state.state_root()
        || replay_state.export_entries() != tip_state.export_entries()
    {
        return Err(DomError::Internal(
            "native USDOM proof-audit replay differs from persisted tip state".into(),
        ));
    }
    Ok(())
}

/// Rewind canonical native state from `canonical_tip` to `ancestor`, accepting
/// an undo only after its derived batch commitment reproduces the exact
/// PoW-authenticated v4 header binding. The store is never mutated.
pub fn rewind_persisted_usdom_v4_state_to_ancestor(
    store: &DomStore,
    network_magic: u32,
    expected_bridge: BridgeIdentity,
    canonical_tip: dom_core::Hash256,
    ancestor: dom_core::Hash256,
) -> Result<NativeUsdomState, DomError> {
    if network_magic != NETWORK_MAGIC_REGTEST || ancestor == dom_core::Hash256::ZERO {
        return Err(DomError::PolicyRejected(
            "native USDOM state rewind is available only for a nonzero Regtest ancestor".into(),
        ));
    }
    let schedule = native_usdom_v4_regtest_activation_schedule(expected_bridge)?;
    rewind_persisted_usdom_v4_state_to_ancestor_for_schedule(
        store,
        network_magic,
        expected_bridge,
        canonical_tip,
        ancestor,
        schedule,
    )
}

/// Rewind authenticated native state under an exact activation schedule. The
/// store is read-only and the walk may not cross below the activation parent.
pub fn rewind_persisted_usdom_v4_state_to_ancestor_for_schedule(
    store: &DomStore,
    network_magic: u32,
    expected_bridge: BridgeIdentity,
    canonical_tip: dom_core::Hash256,
    ancestor: dom_core::Hash256,
    schedule: NativeUsdomV4ActivationSchedule,
) -> Result<NativeUsdomState, DomError> {
    schedule.validate()?;
    if schedule.network_magic() != network_magic
        || ancestor == dom_core::Hash256::ZERO
        || canonical_tip == dom_core::Hash256::ZERO
    {
        return Err(DomError::PolicyRejected(
            "native USDOM state rewind does not match its activation schedule".into(),
        ));
    }
    let ancestor_header_bytes = store
        .get_block_header(ancestor.as_bytes())?
        .ok_or_else(|| {
            DomError::Internal("native USDOM rewind ancestor header is missing".into())
        })?;
    let ancestor_header = dom_consensus::block::BlockHeader::from_bytes(&ancestor_header_bytes)
        .map_err(|error| {
            DomError::Internal(format!(
                "native USDOM rewind ancestor header is corrupt: {error}"
            ))
        })?;
    let minimum_ancestor_height = schedule
        .first_v4_height()
        .checked_sub(1)
        .ok_or_else(|| DomError::Internal("invalid native USDOM activation height".into()))?;
    if ancestor_header.height.0 < minimum_ancestor_height {
        return Err(DomError::PolicyRejected(
            "native USDOM rewind crossed below the activation parent".into(),
        ));
    }
    if crate::canonical_header_identifier(network_magic, &ancestor_header_bytes)? != ancestor
        || store.get_hash_at_height(ancestor_header.height.0)? != Some(*ancestor.as_bytes())
    {
        return Err(DomError::Internal(
            "native USDOM rewind ancestor is not canonical at its declared height".into(),
        ));
    }
    let mut state = restore_persisted_usdom_v4_state_for_schedule(
        store,
        network_magic,
        expected_bridge,
        canonical_tip,
        schedule,
    )?;
    let mut cursor = canonical_tip;
    let mut steps = 0u64;
    while cursor != ancestor {
        steps = steps
            .checked_add(1)
            .ok_or_else(|| DomError::Invalid("native USDOM rewind depth overflow".into()))?;
        if steps >= crate::reorg::MAX_REORG_DEPTH {
            return Err(DomError::PolicyRejected(
                "native USDOM rewind exceeds maximum reorg depth".into(),
            ));
        }
        cursor = revert_authenticated_persisted_usdom_v4_block(
            store,
            network_magic,
            expected_bridge,
            &mut state,
            cursor,
        )?;
    }
    Ok(state)
}

/// Reconstruct and authenticate the canonical candidate-v2 witness bundle
/// atomically persisted beside one canonical block.
pub fn load_persisted_usdom_v2_execution_witnesses(
    store: &DomStore,
    block_identifier: dom_core::Hash256,
) -> Result<Option<UsdomV2ExecutionWitnesses>, DomError> {
    let meta_key = persistence_key(USDOM_V2_WITNESS_META_PREFIX, block_identifier);
    let Some(meta) = store.get_consensus_state(&meta_key)? else {
        let Some(sidecar_bytes) = store.get_block_sidecar(block_identifier.as_bytes())? else {
            return Ok(None);
        };
        if sidecar_bytes.get(..8) != Some(USDOM_V2_BLOCK_SIDECAR_MAGIC.as_slice()) {
            return Ok(None);
        }
        return UsdomV2BlockSidecar::from_bytes(&sidecar_bytes)
            .map(|sidecar| Some(sidecar.witnesses))
            .map_err(|error| {
                DomError::Internal(format!(
                    "persisted native USDOM v2 sidecar is corrupt: {error}"
                ))
            });
    };
    let (expected_commitment, witness_len, chunk_count) = decode_persisted_chunk_metadata(
        &meta,
        USDOM_V2_WITNESS_META_BYTES,
        USDOM_V2_PERSISTENCE_VERSION,
        "v2 witness",
    )?;
    let witness_len = witness_len as usize;
    let chunk_count = chunk_count as usize;
    if !(USDOM_V2_WITNESS_BUNDLE_HEADER_BYTES..=MAX_USDOM_V2_WITNESS_BUNDLE_BYTES)
        .contains(&witness_len)
        || chunk_count == 0
        || chunk_count != witness_len.div_ceil(MAX_CONSENSUS_STATE_VALUE_BYTES)
    {
        return Err(DomError::Internal(
            "invalid persisted native USDOM v2 witness chunk metadata".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(witness_len);
    for index in 0..chunk_count {
        let index: u16 = index
            .try_into()
            .map_err(|_| DomError::Internal("persisted v2 witness chunk overflow".into()))?;
        let chunk = store
            .get_consensus_state(&v2_witness_chunk_key(block_identifier, index))?
            .ok_or_else(|| DomError::Internal("missing persisted v2 witness chunk".into()))?;
        if chunk.is_empty() || chunk.len() > MAX_CONSENSUS_STATE_VALUE_BYTES {
            return Err(DomError::Internal(
                "invalid persisted native USDOM v2 witness chunk".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() != witness_len {
        return Err(DomError::Internal(
            "persisted native USDOM v2 witness length mismatch".into(),
        ));
    }
    let bundle = UsdomV2ExecutionWitnesses::from_bytes(&bytes).map_err(|error| {
        DomError::Internal(format!(
            "persisted native USDOM v2 witnesses are corrupt: {error}"
        ))
    })?;
    if bundle.commitment()? != expected_commitment {
        return Err(DomError::Internal(
            "persisted native USDOM v2 witness commitment mismatch".into(),
        ));
    }
    Ok(Some(bundle))
}

fn load_persisted_usdom_v2_block_record(
    store: &DomStore,
    block_identifier: dom_core::Hash256,
) -> Result<Option<PersistedUsdomV2BlockRecord>, DomError> {
    let key = persistence_key(USDOM_V2_BLOCK_RECORD_PREFIX, block_identifier);
    let Some(bytes) = store.get_consensus_state(&key)? else {
        return Ok(None);
    };
    PersistedUsdomV2BlockRecord::from_bytes(&bytes)
        .map(Some)
        .map_err(|error| {
            DomError::Internal(format!(
                "persisted native USDOM v2 block is corrupt: {error}"
            ))
        })
}

/// Reconstruct and authenticate a persisted native-v4 package from the
/// ordinary block body plus its atomically stored proof-envelope chunks.
pub fn load_persisted_usdom_v4_package(
    store: &DomStore,
    network_magic: u32,
    block_identifier: dom_core::Hash256,
) -> Result<Option<Vec<u8>>, DomError> {
    let meta_key = persistence_key(USDOM_V4_PACKAGE_META_PREFIX, block_identifier);
    let Some(meta) = store.get_consensus_state(&meta_key)? else {
        let Some(proof_bytes) = store.get_block_sidecar(block_identifier.as_bytes())? else {
            return Ok(None);
        };
        let proof_envelope = if proof_bytes.get(..8)
            == Some(USDOM_V2_BLOCK_SIDECAR_MAGIC.as_slice())
        {
            UsdomV2BlockSidecar::from_bytes(&proof_bytes)
                .map_err(|error| {
                    DomError::Internal(format!("persisted USDOM v2 sidecar is corrupt: {error}"))
                })?
                .proof_envelope
        } else {
            UsdomV4ProofEnvelope::from_bytes(&proof_bytes).map_err(|error| {
                DomError::Internal(format!("persisted USDOM sidecar is corrupt: {error}"))
            })?
        };
        let block_bytes = store
            .get_block_body(block_identifier.as_bytes())?
            .ok_or_else(|| DomError::Internal("persisted USDOM block body is missing".into()))?;
        let block = <Block as DomDeserialize>::from_bytes(&block_bytes).map_err(|error| {
            DomError::Internal(format!("persisted USDOM block body is corrupt: {error}"))
        })?;
        let header_bytes = DomSerialize::to_bytes(&block.header)?;
        if crate::canonical_header_identifier(network_magic, &header_bytes)? != block_identifier {
            return Err(DomError::Internal(
                "persisted USDOM sidecar block identifier mismatch".into(),
            ));
        }
        return Ok(Some(
            UsdomV4BlockPackage::new(block, proof_envelope)?.to_bytes()?,
        ));
    };
    let (package_commitment, proof_len, chunk_count) = decode_persisted_chunk_metadata(
        &meta,
        USDOM_V4_PACKAGE_META_BYTES,
        USDOM_V4_PERSISTENCE_VERSION,
        "v4 package",
    )?;
    let proof_len = proof_len as usize;
    let chunk_count = chunk_count as usize;
    let expected_chunks = proof_len.div_ceil(MAX_CONSENSUS_STATE_VALUE_BYTES);
    if !(USDOM_V4_ENVELOPE_HEADER_BYTES..=MAX_USDOM_V4_ENVELOPE_BYTES).contains(&proof_len)
        || chunk_count == 0
        || chunk_count != expected_chunks
    {
        return Err(DomError::Internal(
            "invalid persisted native USDOM proof chunk metadata".into(),
        ));
    }
    let mut proof_bytes = Vec::with_capacity(proof_len);
    for index in 0..chunk_count {
        let index: u16 = index
            .try_into()
            .map_err(|_| DomError::Internal("persisted USDOM chunk index overflow".into()))?;
        let chunk = store
            .get_consensus_state(&package_chunk_key(block_identifier, index))?
            .ok_or_else(|| DomError::Internal("missing persisted USDOM proof chunk".into()))?;
        if chunk.is_empty() || chunk.len() > MAX_CONSENSUS_STATE_VALUE_BYTES {
            return Err(DomError::Internal(
                "invalid persisted USDOM proof chunk length".into(),
            ));
        }
        proof_bytes.extend_from_slice(&chunk);
    }
    if proof_bytes.len() != proof_len {
        return Err(DomError::Internal(
            "persisted USDOM proof chunks do not match declared length".into(),
        ));
    }
    let proof_envelope = UsdomV4ProofEnvelope::from_bytes(&proof_bytes).map_err(|error| {
        DomError::Internal(format!(
            "persisted USDOM proof envelope is corrupt: {error}"
        ))
    })?;
    let block_bytes = store
        .get_block_body(block_identifier.as_bytes())?
        .ok_or_else(|| DomError::Internal("persisted USDOM block body is missing".into()))?;
    let block = <Block as DomDeserialize>::from_bytes(&block_bytes).map_err(|error| {
        DomError::Internal(format!("persisted USDOM block body is corrupt: {error}"))
    })?;
    let header_bytes = DomSerialize::to_bytes(&block.header)?;
    if crate::canonical_header_identifier(network_magic, &header_bytes)? != block_identifier {
        return Err(DomError::Internal(
            "persisted USDOM block identifier mismatch".into(),
        ));
    }
    let package = UsdomV4BlockPackage::new(block, proof_envelope)?.to_bytes()?;
    if blake2b_256_tagged(TAG_USDOM_BLOCK_PACKAGE_V4, &package) != package_commitment {
        return Err(DomError::Internal(
            "persisted USDOM package commitment mismatch".into(),
        ));
    }
    Ok(Some(package))
}

/// Export one canonical native USDOM history block from already verified,
/// atomically persisted data. Every public projection is rehashed into the
/// stored transition root, the resulting batch commitment is checked against
/// the exact DOM header, and private memo payloads are matched to their
/// projection before return.
///
/// Callers must hold a stable chain snapshot while invoking this function and
/// must independently pin the returned ancestry to a trusted finalized DOM
/// block. Local canonicity alone is not a portable finality proof.
/// V1 rollback projections are retained only for the rolling-finality window;
/// archival history older than that window belongs in a separately verified
/// proof archive rather than the mutable consensus database.
pub fn load_authenticated_usdom_v4_history_block(
    store: &DomStore,
    network_magic: u32,
    expected_dom_domain: [u8; 32],
    block_identifier: dom_core::Hash256,
) -> Result<AuthenticatedUsdomV4HistoryBlock, DomError> {
    if !matches!(
        network_magic,
        dom_core::NETWORK_MAGIC_MAINNET
            | dom_core::NETWORK_MAGIC_TESTNET
            | dom_core::NETWORK_MAGIC_REGTEST
    ) || expected_dom_domain == [0; 32]
        || block_identifier == dom_core::Hash256::ZERO
    {
        return Err(DomError::PolicyRejected(
            "native USDOM history export requires a recognized network and nonzero identities"
                .into(),
        ));
    }
    let package_bytes = load_persisted_usdom_v4_package(store, network_magic, block_identifier)?
        .ok_or_else(|| DomError::Internal("native USDOM history package is missing".into()))?;
    let package = UsdomV4BlockPackage::from_bytes(&package_bytes).map_err(|error| {
        DomError::Internal(format!("native USDOM history package is corrupt: {error}"))
    })?;
    let envelope_bytes = package.proof_envelope().to_bytes().map_err(|error| {
        DomError::Internal(format!(
            "native USDOM history proof envelope is corrupt: {error}"
        ))
    })?;
    let candidate_id = blake2b_256_tagged(TAG_USDOM_V4_MINING_CANDIDATE, &envelope_bytes);
    let block = package.block();
    let header_bytes = DomSerialize::to_bytes(&block.header)?;
    if crate::canonical_header_identifier(network_magic, &header_bytes)? != block_identifier
        || store.get_hash_at_height(block.header.height.0)? != Some(*block_identifier.as_bytes())
    {
        return Err(DomError::Invalid(
            "native USDOM history block is not currently canonical".into(),
        ));
    }
    let undo_bytes = store
        .get_consensus_state(&persistence_key(USDOM_V4_UNDO_PREFIX, block_identifier))?
        .ok_or_else(|| DomError::Internal("native USDOM history undo is missing".into()))?;
    let undo = BatchUndo::from_bytes(&undo_bytes).map_err(|error| {
        DomError::Internal(format!("native USDOM history undo is corrupt: {error}"))
    })?;
    if undo.block_timestamp() != block.header.timestamp.0
        || undo.transition_count() != package.proof_envelope().entries.len()
    {
        return Err(DomError::Internal(
            "native USDOM history batch does not match its block envelope".into(),
        ));
    }
    let batch_header_commitment = undo
        .header_commitment(expected_dom_domain)
        .map_err(|error| {
            DomError::Internal(format!("invalid USDOM history projection: {error}"))
        })?;
    let (_, _, raw_rangeproof_root) =
        compute_block_pmmr_roots(block.header.height, &block.coinbase, &block.transactions)?;
    if bind_usdom_batch_commitment(raw_rangeproof_root, batch_header_commitment)?
        != block.header.rangeproof_root
    {
        return Err(DomError::Internal(
            "native USDOM history projection is not bound by the block header".into(),
        ));
    }

    let mut transitions = Vec::with_capacity(undo.transition_count());
    for ((kind, payload), projection) in package
        .proof_envelope()
        .entries()
        .zip(undo.transition_projections())
    {
        let effects = projection.public_effects();
        let private_payload = match (kind, effects.kind) {
            (UsdomV4ProofKind::Issuance, TransitionKind::Issue)
            | (UsdomV4ProofKind::EthereumCheckpoint, TransitionKind::EthereumCheckpoint)
            | (UsdomV4ProofKind::IssuanceClosure, TransitionKind::IssuanceClose)
            | (UsdomV4ProofKind::GracefulShutdown, TransitionKind::GracefulShutdown) => None,
            (UsdomV4ProofKind::Transfer, TransitionKind::Transfer) => {
                let observed = inspect_private_transfer_outputs(payload).map_err(|error| {
                    DomError::Internal(format!(
                        "persisted private-transfer history payload is corrupt: {error}"
                    ))
                })?;
                validate_history_private_effects(
                    &effects,
                    &observed.nullifiers,
                    &observed.output_notes,
                    observed.encrypted_memo,
                )?;
                Some(payload.to_vec())
            }
            (UsdomV4ProofKind::Burn, TransitionKind::Burn) => {
                let observed = inspect_private_burn_outputs(payload).map_err(|error| {
                    DomError::Internal(format!(
                        "persisted private-burn history payload is corrupt: {error}"
                    ))
                })?;
                validate_history_private_effects(
                    &effects,
                    &observed.nullifiers,
                    &observed.output_notes,
                    observed.encrypted_memo,
                )?;
                Some(payload.to_vec())
            }
            _ => {
                return Err(DomError::Internal(
                    "native USDOM history proof kind differs from committed projection".into(),
                ))
            }
        };
        transitions.push(AuthenticatedUsdomV4HistoryTransition {
            projection: projection.clone(),
            private_payload,
        });
    }
    Ok(AuthenticatedUsdomV4HistoryBlock {
        block_identifier,
        candidate_id,
        header_bytes,
        height: block.header.height.0,
        previous_block_identifier: block.header.prev_hash,
        block_timestamp: block.header.timestamp.0,
        previous_state_root: undo.before_root(),
        new_state_root: undo.after_root(),
        transitions_root: undo.transitions_root(),
        batch_header_commitment,
        raw_rangeproof_root,
        transitions,
    })
}

fn validate_history_private_effects(
    effects: &dom_usdom_state::TransitionPublicEffects,
    nullifiers: &[[u8; 32]],
    output_notes: &[[u8; 32]],
    encrypted_memo: &[u8],
) -> Result<(), DomError> {
    let memo_commitment = if output_notes.is_empty() {
        if !encrypted_memo.is_empty() {
            return Err(DomError::Internal(
                "empty native USDOM output set has a nonempty memo".into(),
            ));
        }
        [0; 32]
    } else {
        memo_scalar(encrypted_memo)
            .map_err(|error| DomError::Internal(format!("invalid USDOM history memo: {error}")))?
            .to_bytes()
    };
    if effects.nullifiers != nullifiers
        || effects.note_commitments != output_notes
        || effects.memo_commitment != Some(memo_commitment)
    {
        return Err(DomError::Internal(
            "native USDOM history payload differs from committed public effects".into(),
        ));
    }
    Ok(())
}

/// Export a burn-state witness bound to the exact current canonical block
/// package, its header-authenticated transition batch, and the ratified native
/// USDOM activation schedule. The complete retained reorganization window is
/// audited before export. This local-store canonicity check is evidence input;
/// it does not replace a portable PoW/fork-choice/finality proof or authorize a
/// reserve payout.
pub fn export_native_usdom_v4_burn_block_prover_input_for_schedule(
    store: &DomStore,
    network_magic: u32,
    expected_bridge: BridgeIdentity,
    canonical_tip: dom_core::Hash256,
    burn_id: [u8; 32],
    schedule: NativeUsdomV4ActivationSchedule,
) -> Result<NativeBurnBlockProverInput, DomError> {
    let state = restore_persisted_usdom_v4_state_for_schedule(
        store,
        network_magic,
        expected_bridge,
        canonical_tip,
        schedule,
    )?;
    audit_persisted_usdom_v4_reorg_window_for_schedule(
        store,
        network_magic,
        expected_bridge,
        canonical_tip,
        schedule,
    )?;
    let package_bytes = load_persisted_usdom_v4_package(store, network_magic, canonical_tip)?
        .ok_or_else(|| DomError::Invalid("canonical tip has no native USDOM v4 package".into()))?;
    let undo_bytes = store
        .get_consensus_state(&persistence_key(USDOM_V4_UNDO_PREFIX, canonical_tip))?
        .ok_or_else(|| DomError::Internal("canonical native USDOM batch undo is missing".into()))?;
    let burn_witness_bytes = state
        .burn_state_witness(&burn_id)
        .map_err(|error| DomError::Internal(format!("native burn witness export failed: {error}")))?
        .ok_or_else(|| DomError::Invalid("native burn is absent from canonical state".into()))?
        .to_bytes()
        .map_err(|error| {
            DomError::Internal(format!("native burn witness encoding failed: {error}"))
        })?;
    let input = NativeBurnBlockProverInput::new(
        schedule,
        canonical_tip,
        package_bytes,
        undo_bytes,
        burn_witness_bytes,
    )?;
    let binding = input.verify(schedule, canonical_tip)?;
    if binding.state_root != state.state_root() || binding.burn.burn_id != burn_id {
        return Err(DomError::Internal(
            "native burn prover export changed the audited state or burn identity".into(),
        ));
    }
    Ok(input)
}

/// Export the isolated Regtest proof input using its fixed activation schedule.
/// This compatibility wrapper has the same evidence-only semantics as the
/// schedule-bound exporter and does not establish finality or payout authority.
pub fn export_native_usdom_v4_burn_block_prover_input(
    store: &DomStore,
    network_magic: u32,
    expected_bridge: BridgeIdentity,
    canonical_tip: dom_core::Hash256,
    burn_id: [u8; 32],
) -> Result<NativeBurnBlockProverInput, DomError> {
    if network_magic != NETWORK_MAGIC_REGTEST {
        return Err(DomError::PolicyRejected(
            "native burn prover Regtest wrapper requires explicit Regtest".into(),
        ));
    }
    export_native_usdom_v4_burn_block_prover_input_for_schedule(
        store,
        network_magic,
        expected_bridge,
        canonical_tip,
        burn_id,
        native_usdom_v4_regtest_activation_schedule(expected_bridge)?,
    )
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_authenticated_usdom_v2_burn_witness(
    store: &DomStore,
    network_magic: u32,
    expected_bridge: BridgeIdentity,
    canonical_checkpoint: dom_core::Hash256,
    burn_id: [u8; 32],
    v1_schedule: NativeUsdomV4ActivationSchedule,
    v2_schedule: NativeUsdomV2ActivationSchedule,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    closure_policy: Option<&StaticIssuanceClosureTrustPolicy>,
    spend_verifier: &SpendVerifier,
) -> Result<BurnStateWitnessV2, DomError> {
    if canonical_checkpoint == v2_schedule.activation_parent()
        || v1_schedule.network_magic() != network_magic
        || v2_schedule.network_magic() != network_magic
        || v1_schedule.chain_id() != v2_schedule.chain_id()
    {
        return Err(DomError::PolicyRejected(
            "finalized-burn exporter schedules do not select one active V2 chain".into(),
        ));
    }
    let current_tip = store
        .get_chain_tip()?
        .map(dom_core::Hash256::from_bytes)
        .ok_or_else(|| DomError::Internal("finalized-burn canonical chain has no tip".into()))?;
    let (activation_state, persisted_v1_schedule) =
        restore_persisted_usdom_v2_activation_state_at_tip(
            store,
            network_magic,
            current_tip,
            expected_bridge,
            v2_schedule,
        )?;
    if persisted_v1_schedule != v1_schedule {
        return Err(DomError::PolicyRejected(
            "finalized-burn exporter V1 schedule is not the persisted activation schedule".into(),
        ));
    }

    let checkpoint_block_bytes = store
        .get_block_body(canonical_checkpoint.as_bytes())?
        .ok_or_else(|| DomError::Internal("finalized-burn checkpoint block is missing".into()))?;
    let checkpoint_block =
        <Block as DomDeserialize>::from_bytes(&checkpoint_block_bytes).map_err(|error| {
            DomError::Internal(format!(
                "finalized-burn checkpoint block is corrupt: {error}"
            ))
        })?;
    let checkpoint_height = checkpoint_block.header.height.0;
    if checkpoint_height < v2_schedule.first_v2_height() {
        return Err(DomError::PolicyRejected(
            "finalized-burn checkpoint predates V2 activation".into(),
        ));
    }
    let checkpoint_record = load_persisted_usdom_v2_block_record(store, canonical_checkpoint)?
        .ok_or_else(|| {
            DomError::Internal("finalized-burn checkpoint V2 block record is missing".into())
        })?;
    let checkpoint_state = checkpoint_record.next_state;
    let activation_v2 = activation_state.state_commitment_v2().map_err(|error| {
        DomError::Internal(format!(
            "finalized-burn activation state is invalid: {error}"
        ))
    })?;
    let activation_parent_height = v2_schedule
        .first_v2_height()
        .checked_sub(1)
        .ok_or_else(|| DomError::Invalid("finalized-burn activation height underflow".into()))?;
    let checkpoint_header_bytes = DomSerialize::to_bytes(&checkpoint_block.header)?;
    let (_, _, raw_rangeproof_root) = compute_block_pmmr_roots(
        checkpoint_block.header.height,
        &checkpoint_block.coinbase,
        &checkpoint_block.transactions,
    )?;
    validate_static_checkpoint_policy_identity(network_magic, expected_bridge, checkpoint_policy)?;
    validate_static_deposit_policy_identity(expected_bridge, deposit_policy)?;
    if let Some(policy) = closure_policy {
        validate_static_issuance_closure_policy_identity(network_magic, expected_bridge, policy)?;
    }
    validate_spend_verifier_identity(expected_bridge, spend_verifier)?;
    if activation_v2.root() != v2_schedule.initial_v2_state_root()
        || crate::canonical_header_identifier(network_magic, &checkpoint_header_bytes)?
            != canonical_checkpoint
        || checkpoint_record.schedule_commitment != v2_schedule.commitment()
        || checkpoint_record.block_identifier != canonical_checkpoint
        || checkpoint_record.parent != checkpoint_block.header.prev_hash
        || checkpoint_record.receipt.block_timestamp != checkpoint_block.header.timestamp.0
        || bind_usdom_batch_commitment(
            raw_rangeproof_root,
            checkpoint_record.receipt.header_commitment,
        )? != checkpoint_block.header.rangeproof_root
        || !v2_state_matches_bridge(checkpoint_record.previous_state, expected_bridge)
        || !v2_state_matches_bridge(checkpoint_state, expected_bridge)
        || store.get_hash_at_height(activation_parent_height)?
            != Some(*v2_schedule.activation_parent().as_bytes())
        || store.get_hash_at_height(checkpoint_height)? != Some(*canonical_checkpoint.as_bytes())
        || store.get_chain_tip()? != Some(*current_tip.as_bytes())
    {
        return Err(DomError::Internal(
            "finalized-burn V2 checkpoint or activation binding disagrees".into(),
        ));
    }
    let records = load_v2_burn_archive_at_height(store, checkpoint_height)?;
    BurnStateWitnessV2::from_burn_records(checkpoint_state, burn_id, &records)
        .map_err(|error| {
            DomError::Internal(format!(
                "authenticated finalized-burn set reconstruction failed: {error}"
            ))
        })?
        .ok_or_else(|| DomError::Invalid("native burn is absent from checkpoint state".into()))
}

/// Export the current `UDFINL04` proof input from an audited canonical V2 state.
///
/// The raw Ethereum witness must authenticate a checkpoint event naming this
/// exact canonical state's root. The supplied checkpoint-outer statement is
/// also part of the canonical private input: the finalized-burn guest accepts
/// it only together with a recursively verified receipt from the pinned
/// checkpoint guest. The Ethereum event, recursive DOM proof and burn witness
/// must therefore agree on the checkpoint height, block and state root.
#[allow(clippy::too_many_arguments)]
pub fn export_finalized_burn_prover_input_for_schedule(
    store: &DomStore,
    network_magic: u32,
    expected_bridge: BridgeIdentity,
    canonical_checkpoint: dom_core::Hash256,
    burn_id: [u8; 32],
    v1_schedule: NativeUsdomV4ActivationSchedule,
    v2_schedule: NativeUsdomV2ActivationSchedule,
    checkpoint_policy: StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    closure_policy: Option<&StaticIssuanceClosureTrustPolicy>,
    spend_verifier: &SpendVerifier,
    checkpoint_statement: dom_usdom_finalized_burn_program::CheckpointStatementV6,
    checkpoint_witness_bytes: Vec<u8>,
) -> Result<dom_usdom_finalized_burn_program::FinalizedBurnProverInput, DomError> {
    let burn_witness_bytes = reconstruct_authenticated_usdom_v2_burn_witness(
        store,
        network_magic,
        expected_bridge,
        canonical_checkpoint,
        burn_id,
        v1_schedule,
        v2_schedule,
        &checkpoint_policy,
        deposit_policy,
        closure_policy,
        spend_verifier,
    )?
    .to_bytes()
    .map_err(|error| DomError::Internal(format!("native burn witness encoding failed: {error}")))?;
    let portable_schedule = dom_usdom_finalized_burn_program::ActivationSchedule::new(
        v1_schedule.network_magic(),
        v1_schedule.chain_id(),
        v1_schedule.first_v4_height(),
        expected_bridge,
    )
    .map_err(|error| DomError::Invalid(format!("portable activation schedule failed: {error}")))?;
    if portable_schedule.empty_state_root() != v1_schedule.empty_state_root()
        || portable_schedule.commitment() != v1_schedule.commitment()
    {
        return Err(DomError::Internal(
            "portable finalized-burn schedule differs from native consensus".into(),
        ));
    }
    let input = dom_usdom_finalized_burn_program::FinalizedBurnProverInput::new(
        portable_schedule,
        checkpoint_policy,
        checkpoint_statement,
        burn_witness_bytes,
        checkpoint_witness_bytes,
    )
    .map_err(|error| DomError::Invalid(format!("finalized burn input failed: {error}")))?;
    if input.statement_hash() == dom_core::Hash256::ZERO {
        return Err(DomError::Internal(
            "finalized burn input produced a zero public statement".into(),
        ));
    }
    Ok(input)
}

/// Persist a Regtest reorganization barrier only after an opaque Ethereum
/// verifier result matches an exact package already present in canonical
/// native storage. The caller must serialize this operation with ChainState;
/// [`crate::ChainState::install_verified_native_burn_checkpoint`] is the normal
/// runtime boundary that also advances its in-memory floor.
pub fn install_verified_native_burn_checkpoint(
    store: &DomStore,
    network_magic: u32,
    tip_height: u64,
    input: &NativeBurnBlockProverInput,
    verified: &usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint,
) -> Result<
    (
        NativeBurnCheckpointBinding,
        crate::ethereum_checkpoint_poc::TestOracleCheckpoint,
    ),
    DomError,
> {
    let block_identifier = input.block_identifier();
    if input.network_magic() != network_magic {
        return Err(DomError::PolicyRejected(
            "native burn checkpoint network does not match its activation schedule".into(),
        ));
    }
    let binding = bind_verified_ethereum_checkpoint_to_native_burn(
        input,
        input.activation_schedule(),
        block_identifier,
        verified,
    )?;
    let persisted = load_persisted_usdom_v4_package(store, network_magic, block_identifier)?
        .ok_or_else(|| DomError::Internal("checkpointed native USDOM package is missing".into()))?;
    if persisted != input.package_bytes() {
        return Err(DomError::Invalid(
            "checkpointed native USDOM package differs from canonical persistence".into(),
        ));
    }
    let checkpoint = crate::ethereum_checkpoint_poc::install_from_verified_handoff(
        store,
        network_magic,
        tip_height,
        verified,
    )?;
    Ok((binding, checkpoint))
}

#[derive(Debug)]
struct PreparedUsdomV4Candidate {
    next_state: NativeUsdomState,
    receipt: TransitionBatchReceipt,
    undo: BatchUndo,
    verified_checkpoint:
        Option<usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint>,
}

#[derive(Debug)]
struct VerifiedEnvelopeTransitions {
    transitions: Vec<VerifiedTransition>,
    checkpoint: Option<usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint>,
}

/// Opaque proof-verified transition batch bound to one exact canonical block
/// package. It has not yet gained state-transition or header authority.
#[derive(Debug)]
pub struct VerifiedUsdomV4TransitionBatch {
    network_magic: u32,
    block_identifier: dom_core::Hash256,
    package_commitment: dom_core::Hash256,
    block: Block,
    transitions: Vec<VerifiedTransition>,
    verified_checkpoint:
        Option<usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint>,
}

/// Opaque candidate produced only after the verified package, candidate-v2
/// state witnesses and the reserved block-v4 commitment all agree.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedUsdomV4CandidateV2 {
    network_magic: u32,
    block_identifier: dom_core::Hash256,
    package_commitment: dom_core::Hash256,
    witness_commitment: dom_core::Hash256,
    next_state: StateCommitmentV2,
    receipt: TransitionBatchReceipt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PersistedUsdomV2BlockRecord {
    schedule_commitment: dom_core::Hash256,
    block_identifier: dom_core::Hash256,
    parent: dom_core::Hash256,
    package_commitment: dom_core::Hash256,
    witness_commitment: dom_core::Hash256,
    previous_state: StateCommitmentV2,
    next_state: StateCommitmentV2,
    receipt: TransitionBatchReceipt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PersistedUsdomV2RuntimeTip {
    schedule_commitment: dom_core::Hash256,
    block_identifier: dom_core::Hash256,
    state_root: dom_core::Hash256,
    package_commitment: dom_core::Hash256,
    witness_commitment: dom_core::Hash256,
    state: StateCommitmentV2,
}

impl PersistedUsdomV2RuntimeTip {
    fn from_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        let mut reader = Reader::new(bytes);
        if reader.read_bytes(8)? != USDOM_V2_RUNTIME_TIP_MAGIC
            || reader.read_u16_be()? != USDOM_V2_PERSISTENCE_VERSION
        {
            return Err(DomError::Malformed(
                "invalid persisted native USDOM v2 runtime tip framing".into(),
            ));
        }
        let schedule_commitment = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let block_identifier = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let state_root = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let package_commitment = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let witness_commitment = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let state_len = usize::from(reader.read_u16_be()?);
        let state =
            StateCommitmentV2::from_bytes(reader.read_bytes(state_len)?).map_err(|error| {
                DomError::Malformed(format!("invalid v2 runtime tip state: {error}"))
            })?;
        reader.finish()?;
        let tip = Self {
            schedule_commitment,
            block_identifier,
            state_root,
            package_commitment,
            witness_commitment,
            state,
        };
        if [
            tip.schedule_commitment,
            tip.block_identifier,
            tip.state_root,
            tip.package_commitment,
            tip.witness_commitment,
        ]
        .contains(&dom_core::Hash256::ZERO)
            || tip.state.root() != tip.state_root
        {
            return Err(DomError::Malformed(
                "invalid persisted native USDOM v2 runtime tip".into(),
            ));
        }
        Ok(tip)
    }
}

impl PersistedUsdomV2BlockRecord {
    const HEADER_BYTES: usize = 380;

    fn validate(&self) -> Result<(), DomError> {
        if [
            self.schedule_commitment,
            self.block_identifier,
            self.parent,
            self.package_commitment,
            self.witness_commitment,
        ]
        .contains(&dom_core::Hash256::ZERO)
            || self.block_identifier == self.parent
            || self.receipt.version != dom_usdom_state::CANDIDATE_V2_TRANSITION_BATCH_VERSION
            || self.receipt.previous_state_root != self.previous_state.root()
            || self.receipt.new_state_root != self.next_state.root()
            || self.receipt.previous_total_issued != self.previous_state.total_issued
            || self.receipt.previous_total_burned != self.previous_state.total_burned
            || self.receipt.new_total_issued != self.next_state.total_issued
            || self.receipt.new_total_burned != self.next_state.total_burned
            || self.previous_state.to_bytes().is_err()
            || self.next_state.to_bytes().is_err()
        {
            return Err(DomError::Invalid(
                "invalid persisted native USDOM v2 block record".into(),
            ));
        }
        Ok(())
    }

    fn to_bytes(self) -> Result<Vec<u8>, DomError> {
        self.validate()?;
        let previous = self.previous_state.to_bytes().map_err(|error| {
            DomError::Invalid(format!("invalid previous native USDOM v2 state: {error}"))
        })?;
        let next = self.next_state.to_bytes().map_err(|error| {
            DomError::Invalid(format!("invalid next native USDOM v2 state: {error}"))
        })?;
        let previous_len: u16 = previous
            .len()
            .try_into()
            .map_err(|_| DomError::Invalid("native USDOM v2 previous state too large".into()))?;
        let next_len: u16 = next
            .len()
            .try_into()
            .map_err(|_| DomError::Invalid("native USDOM v2 next state too large".into()))?;
        let mut bytes = Vec::with_capacity(Self::HEADER_BYTES + previous.len() + next.len());
        bytes.extend_from_slice(USDOM_V2_BLOCK_RECORD_MAGIC);
        bytes.extend_from_slice(&USDOM_V2_PERSISTENCE_VERSION.to_be_bytes());
        bytes.extend_from_slice(self.schedule_commitment.as_bytes());
        bytes.extend_from_slice(self.block_identifier.as_bytes());
        bytes.extend_from_slice(self.parent.as_bytes());
        bytes.extend_from_slice(self.package_commitment.as_bytes());
        bytes.extend_from_slice(self.witness_commitment.as_bytes());
        bytes.extend_from_slice(&previous_len.to_be_bytes());
        bytes.extend_from_slice(&next_len.to_be_bytes());
        bytes.extend_from_slice(&self.receipt.version.to_be_bytes());
        bytes.extend_from_slice(&self.receipt.transition_count.to_be_bytes());
        bytes.extend_from_slice(&self.receipt.block_timestamp.to_be_bytes());
        bytes.extend_from_slice(self.receipt.transitions_root.as_bytes());
        bytes.extend_from_slice(self.receipt.previous_state_root.as_bytes());
        bytes.extend_from_slice(self.receipt.new_state_root.as_bytes());
        bytes.extend_from_slice(&self.receipt.previous_total_issued.to_be_bytes());
        bytes.extend_from_slice(&self.receipt.previous_total_burned.to_be_bytes());
        bytes.extend_from_slice(&self.receipt.new_total_issued.to_be_bytes());
        bytes.extend_from_slice(&self.receipt.new_total_burned.to_be_bytes());
        bytes.extend_from_slice(self.receipt.header_commitment.as_bytes());
        debug_assert_eq!(bytes.len(), Self::HEADER_BYTES);
        bytes.extend_from_slice(&previous);
        bytes.extend_from_slice(&next);
        Ok(bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        let mut reader = Reader::new(bytes);
        if reader.read_bytes(8)? != USDOM_V2_BLOCK_RECORD_MAGIC
            || reader.read_u16_be()? != USDOM_V2_PERSISTENCE_VERSION
        {
            return Err(DomError::Malformed(
                "invalid persisted native USDOM v2 block framing".into(),
            ));
        }
        let schedule_commitment = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let block_identifier = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let parent = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let package_commitment = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let witness_commitment = dom_core::Hash256::from_bytes(reader.read_array::<32>()?);
        let previous_len = usize::from(reader.read_u16_be()?);
        let next_len = usize::from(reader.read_u16_be()?);
        let receipt = TransitionBatchReceipt {
            version: reader.read_u16_be()?,
            transition_count: reader.read_u32_be()?,
            block_timestamp: reader.read_u64_be()?,
            transitions_root: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
            previous_state_root: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
            new_state_root: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
            previous_total_issued: u128::from_be_bytes(reader.read_array::<16>()?),
            previous_total_burned: u128::from_be_bytes(reader.read_array::<16>()?),
            new_total_issued: u128::from_be_bytes(reader.read_array::<16>()?),
            new_total_burned: u128::from_be_bytes(reader.read_array::<16>()?),
            header_commitment: dom_core::Hash256::from_bytes(reader.read_array::<32>()?),
        };
        let previous_state = StateCommitmentV2::from_bytes(reader.read_bytes(previous_len)?)
            .map_err(|error| DomError::Malformed(format!("invalid v2 previous state: {error}")))?;
        let next_state = StateCommitmentV2::from_bytes(reader.read_bytes(next_len)?)
            .map_err(|error| DomError::Malformed(format!("invalid v2 next state: {error}")))?;
        reader.finish()?;
        let record = Self {
            schedule_commitment,
            block_identifier,
            parent,
            package_commitment,
            witness_commitment,
            previous_state,
            next_state,
            receipt,
        };
        record.validate().map_err(|_| {
            DomError::Malformed("invalid persisted native USDOM v2 block record".into())
        })?;
        if record.to_bytes()?.as_slice() != bytes {
            return Err(DomError::Malformed(
                "noncanonical persisted native USDOM v2 block record".into(),
            ));
        }
        Ok(record)
    }
}

impl VerifiedUsdomV4TransitionBatch {
    /// Authenticated checkpoint carried by this exact package, if any. The
    /// chain path must still bind its asserted DOM target before persistence.
    pub fn verified_checkpoint(
        &self,
    ) -> Option<&usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint> {
        self.verified_checkpoint.as_ref()
    }

    /// Execute the private verified transitions through the candidate-v2
    /// stateless relation and validate the exact block body commitment.
    pub fn execute_v2(
        &self,
        validation_context: &ValidationContext,
        expected_previous_root: dom_core::Hash256,
        previous: StateCommitmentV2,
        witnesses: &[NativeTransitionWitness],
    ) -> Result<VerifiedUsdomV4CandidateV2, DomError> {
        let witness_bundle = UsdomV2ExecutionWitnesses::new(witnesses.to_vec())?;
        let (next_state, receipt) = apply_v2_transition_batch_with_receipt(
            expected_previous_root,
            BlockContext {
                timestamp: self.block.header.timestamp.0,
            },
            previous,
            &self.transitions,
            witnesses,
        )
        .map_err(|error| {
            DomError::Invalid(format!("stateless native USDOM v2 batch failed: {error}"))
        })?;
        validate_block_v4_scheduled(
            &self.block,
            validation_context,
            self.network_magic,
            UsdomV4Commitment {
                batch_header_commitment: receipt.header_commitment,
                block_timestamp: Timestamp(receipt.block_timestamp),
            },
        )
        .map_err(|error| DomError::Invalid(format!("USDOM v2 block validation failed: {error}")))?;
        Ok(VerifiedUsdomV4CandidateV2 {
            network_magic: self.network_magic,
            block_identifier: self.block_identifier,
            package_commitment: self.package_commitment,
            witness_commitment: witness_bundle.commitment()?,
            next_state,
            receipt,
        })
    }
}

impl VerifiedUsdomV4CandidateV2 {
    /// Canonical identifier of the validated block.
    pub const fn block_identifier(&self) -> dom_core::Hash256 {
        self.block_identifier
    }

    /// Commitment to every byte of the proof-bearing package.
    pub const fn package_commitment(&self) -> dom_core::Hash256 {
        self.package_commitment
    }

    /// Commitment to the canonical candidate-v2 witness bundle used for this
    /// exact execution. Persistence and replay must reproduce this value.
    pub const fn witness_commitment(&self) -> dom_core::Hash256 {
        self.witness_commitment
    }

    /// Candidate-v2 state after the exact verified batch.
    pub const fn next_state(&self) -> StateCommitmentV2 {
        self.next_state
    }

    /// Versioned batch receipt committed by the validated block.
    pub const fn receipt(&self) -> TransitionBatchReceipt {
        self.receipt
    }

    /// Derive the atomic persistence batch for one proof-verified candidate-v2
    /// direct extension. The exact package, witness bundle, previous state and
    /// ratified migration schedule are required again so a detached capability
    /// cannot install substituted recovery data.
    pub(crate) fn consensus_state_updates(
        &self,
        schedule: NativeUsdomV2ActivationSchedule,
        previous_state: StateCommitmentV2,
        package_bytes: &[u8],
        witness_bundle: &UsdomV2ExecutionWitnesses,
    ) -> Result<Vec<ConsensusStateUpdate>, DomError> {
        schedule.validate()?;
        let package = UsdomV4BlockPackage::from_bytes(package_bytes)?;
        let block = package.block();
        let witness_bytes = witness_bundle.to_bytes()?;
        let witness_count: u32 = witness_bundle
            .witnesses()
            .len()
            .try_into()
            .map_err(|_| DomError::Invalid("native USDOM v2 witness count overflow".into()))?;
        if schedule.network_magic() != self.network_magic
            || block.header.height.0 < schedule.first_v2_height()
            || (block.header.height.0 == schedule.first_v2_height()
                && (block.header.prev_hash != schedule.activation_parent()
                    || previous_state.root() != schedule.initial_v2_state_root()))
            || self.receipt.previous_state_root != previous_state.root()
            || self.receipt.new_state_root != self.next_state.root()
            || self.receipt.block_timestamp != block.header.timestamp.0
            || self.receipt.transition_count != witness_count
            || blake2b_256_tagged(TAG_USDOM_BLOCK_PACKAGE_V4, package_bytes)
                != self.package_commitment
            || witness_bundle.commitment()? != self.witness_commitment
        {
            return Err(DomError::Invalid(
                "native USDOM v2 capability does not match persistence input".into(),
            ));
        }
        let header_bytes = DomSerialize::to_bytes(&block.header)?;
        if crate::canonical_header_identifier(self.network_magic, &header_bytes)?
            != self.block_identifier
        {
            return Err(DomError::Invalid(
                "native USDOM v2 block identifier changed before persistence".into(),
            ));
        }
        let (_, _, raw_rangeproof_root) =
            compute_block_pmmr_roots(block.header.height, &block.coinbase, &block.transactions)?;
        if bind_usdom_batch_commitment(raw_rangeproof_root, self.receipt.header_commitment)?
            != block.header.rangeproof_root
        {
            return Err(DomError::Invalid(
                "native USDOM v2 receipt is not bound into the block header".into(),
            ));
        }
        let record = PersistedUsdomV2BlockRecord {
            schedule_commitment: schedule.commitment(),
            block_identifier: self.block_identifier,
            parent: block.header.prev_hash,
            package_commitment: self.package_commitment,
            witness_commitment: self.witness_commitment,
            previous_state,
            next_state: self.next_state,
            receipt: self.receipt,
        };
        let mut updates = package_persistence_updates(
            self.network_magic,
            self.block_identifier,
            self.package_commitment,
            package_bytes,
        )?;
        updates.extend(v2_witness_persistence_updates(
            self.block_identifier,
            self.witness_commitment,
            &witness_bytes,
        )?);
        updates.push(ConsensusStateUpdate {
            key: persistence_key(USDOM_V2_BLOCK_RECORD_PREFIX, self.block_identifier),
            value: Some(record.to_bytes()?),
        });
        updates.push(ConsensusStateUpdate {
            key: USDOM_V2_TIP_KEY.to_vec(),
            value: Some(v2_runtime_tip_value(schedule, record)?),
        });
        for burn in package.proof_envelope().public_burn_records()? {
            updates.push(v2_burn_archive_update(
                block.header.height.0,
                self.block_identifier,
                burn,
            )?);
        }
        validate_consensus_state_updates(&updates)?;
        Ok(updates)
    }

    /// Move a promoted side block's authenticated V2 package, witnesses,
    /// compact burn index and block record into canonical consensus state. The
    /// reorg transaction deletes the now-redundant immutable sidecar atomically.
    pub(crate) fn sidecar_reorg_persistence_updates(
        &self,
        schedule: NativeUsdomV2ActivationSchedule,
        previous_state: StateCommitmentV2,
        package_bytes: &[u8],
        witness_bundle: &UsdomV2ExecutionWitnesses,
    ) -> Result<Vec<ConsensusStateUpdate>, DomError> {
        let updates =
            self.consensus_state_updates(schedule, previous_state, package_bytes, witness_bundle)?;
        validate_consensus_state_updates(&updates)?;
        Ok(updates)
    }
}

/// Authenticate a bounded v4 proof envelope, apply its ordered opaque
/// transitions to a state clone, and body-validate the exact Regtest candidate.
///
/// Version 1 deliberately supports only the real Ethereum checkpoint witness
/// verifier. Issuance, transfer and burn proof kinds are reserved in the wire
/// format but fail closed until their production verifiers exist.
#[allow(clippy::too_many_arguments)]
fn verify_usdom_v4_envelope_candidate_for_schedule(
    block: &Block,
    validation_context: &ValidationContext,
    network_magic: u32,
    current_state: &NativeUsdomState,
    bridge: BridgeIdentity,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    closure_policy: Option<&StaticIssuanceClosureTrustPolicy>,
    spend_verifier: Option<&SpendVerifier>,
    envelope: &UsdomV4ProofEnvelope,
    schedule: NativeUsdomV4ActivationSchedule,
) -> Result<PreparedUsdomV4Candidate, DomError> {
    validate_scheduled_candidate_context(
        block,
        validation_context,
        network_magic,
        bridge,
        schedule,
    )?;
    if current_state.bridge_identity() != bridge {
        return Err(DomError::Invalid(
            "native USDOM state does not match the selected bridge identity".into(),
        ));
    }
    validate_static_checkpoint_policy_identity(network_magic, bridge, checkpoint_policy)?;
    validate_static_deposit_policy_identity(bridge, deposit_policy)?;
    let verified_envelope = verify_envelope_transitions(
        network_magic,
        block.header.timestamp.0,
        bridge,
        checkpoint_policy,
        deposit_policy,
        closure_policy,
        spend_verifier,
        &envelope.entries,
    )?;
    let mut prepared = verify_usdom_v4_candidate_for_schedule(
        block,
        validation_context,
        network_magic,
        current_state,
        &verified_envelope.transitions,
        schedule,
    )?;
    prepared.verified_checkpoint = verified_envelope.checkpoint;
    Ok(prepared)
}

/// Canonically decode one complete version-4 block package, authenticate its
/// bounded proof envelope, and body-validate the exact Regtest state candidate.
/// Both public serialized-candidate entry points preserve this package boundary,
/// preventing a caller from detaching proof bytes from the block bytes whose
/// header commits the resulting transition batch. This legacy variant grants
/// no transfer or burn proof authority.
pub fn verify_usdom_v4_serialized_candidate_regtest(
    package_bytes: &[u8],
    validation_context: &ValidationContext,
    network_magic: u32,
    current_state: &NativeUsdomState,
    bridge: BridgeIdentity,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    closure_policy: Option<&StaticIssuanceClosureTrustPolicy>,
) -> Result<VerifiedUsdomV4Candidate, DomError> {
    verify_usdom_v4_serialized_candidate_regtest_inner(
        package_bytes,
        validation_context,
        network_magic,
        current_state,
        bridge,
        checkpoint_policy,
        deposit_policy,
        closure_policy,
        // The legacy wrapper intentionally cannot authorize private spends.
        // Proof-bearing callers must supply the bridge-pinned verifier through
        // `verify_usdom_v4_serialized_candidate_with_spend_verifier_regtest`.
        None,
    )
}

/// Verify a serialized Regtest candidate with one exact bridge-committed
/// private-spend verifier. This path adds transfer and burn proof authority;
/// the legacy entry point continues to reject those proof kinds.
#[allow(clippy::too_many_arguments)]
pub fn verify_usdom_v4_serialized_candidate_with_spend_verifier_regtest(
    package_bytes: &[u8],
    validation_context: &ValidationContext,
    network_magic: u32,
    current_state: &NativeUsdomState,
    bridge: BridgeIdentity,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    closure_policy: Option<&StaticIssuanceClosureTrustPolicy>,
    spend_verifier: &SpendVerifier,
) -> Result<VerifiedUsdomV4Candidate, DomError> {
    verify_usdom_v4_serialized_candidate_regtest_inner(
        package_bytes,
        validation_context,
        network_magic,
        current_state,
        bridge,
        checkpoint_policy,
        deposit_policy,
        closure_policy,
        Some(spend_verifier),
    )
}

/// Verify one complete block-v4 package against an exact ratified activation
/// schedule and bridge-committed private-spend verifying key.
///
/// This function does not activate public-network ingress. The caller must
/// obtain `schedule` from local consensus configuration and later commit the
/// verified capability through a chain path enforcing that same schedule.
#[allow(clippy::too_many_arguments)]
pub fn verify_usdom_v4_serialized_candidate_for_schedule(
    package_bytes: &[u8],
    validation_context: &ValidationContext,
    network_magic: u32,
    current_state: &NativeUsdomState,
    bridge: BridgeIdentity,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    closure_policy: Option<&StaticIssuanceClosureTrustPolicy>,
    spend_verifier: &SpendVerifier,
    schedule: NativeUsdomV4ActivationSchedule,
) -> Result<VerifiedUsdomV4Candidate, DomError> {
    verify_usdom_v4_serialized_candidate_for_schedule_inner(
        package_bytes,
        validation_context,
        network_magic,
        current_state,
        bridge,
        checkpoint_policy,
        deposit_policy,
        closure_policy,
        Some(spend_verifier),
        schedule,
    )
}

/// Verify every proof in one canonical block package without opening native
/// state. The returned capability remains bound to the exact block and cannot
/// validate its header until [`VerifiedUsdomV4TransitionBatch::execute_v2`]
/// authenticates the previous state and applies the supplied bounded paths.
#[allow(clippy::too_many_arguments)]
pub fn verify_usdom_v4_serialized_transition_batch_for_schedule(
    package_bytes: &[u8],
    validation_context: &ValidationContext,
    network_magic: u32,
    bridge: BridgeIdentity,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    closure_policy: Option<&StaticIssuanceClosureTrustPolicy>,
    spend_verifier: &SpendVerifier,
    schedule: NativeUsdomV4ActivationSchedule,
) -> Result<VerifiedUsdomV4TransitionBatch, DomError> {
    validate_native_usdom_privacy_policy(bridge)?;
    validate_spend_verifier_identity(bridge, spend_verifier)?;
    let package = UsdomV4BlockPackage::from_bytes(package_bytes)?;
    validate_scheduled_candidate_context(
        package.block(),
        validation_context,
        network_magic,
        bridge,
        schedule,
    )?;
    validate_static_checkpoint_policy_identity(network_magic, bridge, checkpoint_policy)?;
    validate_static_deposit_policy_identity(bridge, deposit_policy)?;
    let verified = verify_envelope_transitions(
        network_magic,
        package.block().header.timestamp.0,
        bridge,
        checkpoint_policy,
        deposit_policy,
        closure_policy,
        Some(spend_verifier),
        &package.proof_envelope().entries,
    )?;
    let header_bytes = DomSerialize::to_bytes(&package.block().header)?;
    let block_identifier = crate::canonical_header_identifier(network_magic, &header_bytes)?;
    Ok(VerifiedUsdomV4TransitionBatch {
        network_magic,
        block_identifier,
        package_commitment: blake2b_256_tagged(TAG_USDOM_BLOCK_PACKAGE_V4, package_bytes),
        block: package.block().clone(),
        transitions: verified.transitions,
        verified_checkpoint: verified.checkpoint,
    })
}

/// Verify a proof-bearing package under the explicit state-v2 migration
/// schedule. The first v2 block must extend the ratified activation parent.
#[allow(clippy::too_many_arguments)]
pub fn verify_usdom_v4_serialized_transition_batch_for_v2_schedule(
    package_bytes: &[u8],
    validation_context: &ValidationContext,
    network_magic: u32,
    bridge: BridgeIdentity,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    closure_policy: Option<&StaticIssuanceClosureTrustPolicy>,
    spend_verifier: &SpendVerifier,
    schedule: NativeUsdomV2ActivationSchedule,
) -> Result<VerifiedUsdomV4TransitionBatch, DomError> {
    validate_native_usdom_privacy_policy(bridge)?;
    validate_spend_verifier_identity(bridge, spend_verifier)?;
    let package = UsdomV4BlockPackage::from_bytes(package_bytes)?;
    let block = package.block();
    if schedule.network_magic() != network_magic
        || schedule.chain_id().as_bytes() != &validation_context.chain_id
        || block.header.version != BLOCK_VERSION_V4
        || block.header.height.0 < schedule.first_v2_height()
        || validation_context.current_height != block.header.height
        || (block.header.height.0 == schedule.first_v2_height()
            && block.header.prev_hash != schedule.activation_parent())
    {
        return Err(DomError::PolicyRejected(
            "native USDOM block does not match the ratified v2 activation schedule".into(),
        ));
    }
    validate_static_checkpoint_policy_identity(network_magic, bridge, checkpoint_policy)?;
    validate_static_deposit_policy_identity(bridge, deposit_policy)?;
    let verified = verify_envelope_transitions(
        network_magic,
        block.header.timestamp.0,
        bridge,
        checkpoint_policy,
        deposit_policy,
        closure_policy,
        Some(spend_verifier),
        &package.proof_envelope().entries,
    )?;
    let header_bytes = DomSerialize::to_bytes(&block.header)?;
    Ok(VerifiedUsdomV4TransitionBatch {
        network_magic,
        block_identifier: crate::canonical_header_identifier(network_magic, &header_bytes)?,
        package_commitment: blake2b_256_tagged(TAG_USDOM_BLOCK_PACKAGE_V4, package_bytes),
        block: block.clone(),
        transitions: verified.transitions,
        verified_checkpoint: verified.checkpoint,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_usdom_v4_serialized_candidate_for_schedule_inner(
    package_bytes: &[u8],
    validation_context: &ValidationContext,
    network_magic: u32,
    current_state: &NativeUsdomState,
    bridge: BridgeIdentity,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    closure_policy: Option<&StaticIssuanceClosureTrustPolicy>,
    spend_verifier: Option<&SpendVerifier>,
    schedule: NativeUsdomV4ActivationSchedule,
) -> Result<VerifiedUsdomV4Candidate, DomError> {
    validate_native_usdom_privacy_policy(bridge)?;
    if let Some(verifier) = spend_verifier {
        validate_spend_verifier_identity(bridge, verifier)?;
    }
    let package = UsdomV4BlockPackage::from_bytes(package_bytes)?;
    let prepared = verify_usdom_v4_envelope_candidate_for_schedule(
        package.block(),
        validation_context,
        network_magic,
        current_state,
        bridge,
        checkpoint_policy,
        deposit_policy,
        closure_policy,
        spend_verifier,
        package.proof_envelope(),
        schedule,
    )?;
    let header_bytes = DomSerialize::to_bytes(&package.block().header)?;
    let block_identifier = crate::canonical_header_identifier(network_magic, &header_bytes)?;
    Ok(VerifiedUsdomV4Candidate {
        network_magic,
        block_identifier,
        package_commitment: blake2b_256_tagged(TAG_USDOM_BLOCK_PACKAGE_V4, package_bytes),
        next_state: prepared.next_state,
        receipt: prepared.receipt,
        undo: prepared.undo,
        verified_checkpoint: prepared.verified_checkpoint,
    })
}

/// Shared serialized-candidate boundary used by direct extension, retained
/// side branches, reorganization replay and runtime ingress. Supplying a spend
/// verifier changes only transfer/burn authority; every other validation rule
/// and byte commitment remains identical.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_usdom_v4_serialized_candidate_regtest_inner(
    package_bytes: &[u8],
    validation_context: &ValidationContext,
    network_magic: u32,
    current_state: &NativeUsdomState,
    bridge: BridgeIdentity,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    closure_policy: Option<&StaticIssuanceClosureTrustPolicy>,
    spend_verifier: Option<&SpendVerifier>,
) -> Result<VerifiedUsdomV4Candidate, DomError> {
    if network_magic != NETWORK_MAGIC_REGTEST {
        return Err(DomError::PolicyRejected(
            "native USDOM serialized candidate is available only on explicit Regtest".into(),
        ));
    }
    let schedule = native_usdom_v4_regtest_activation_schedule(bridge)?;
    verify_usdom_v4_serialized_candidate_for_schedule_inner(
        package_bytes,
        validation_context,
        network_magic,
        current_state,
        bridge,
        checkpoint_policy,
        deposit_policy,
        closure_policy,
        spend_verifier,
        schedule,
    )
}

fn verify_envelope_transitions(
    network_magic: u32,
    block_timestamp: u64,
    bridge: BridgeIdentity,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    deposit_policy: &StaticDepositTrustPolicy,
    closure_policy: Option<&StaticIssuanceClosureTrustPolicy>,
    spend_verifier: Option<&SpendVerifier>,
    entries: &[UsdomV4ProofEntry],
) -> Result<VerifiedEnvelopeTransitions, DomError> {
    validate_envelope_entries(entries)?;
    let private_spends = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.kind,
                UsdomV4ProofKind::Transfer | UsdomV4ProofKind::Burn
            )
        })
        .count();
    let mut private_results = if private_spends > 1 {
        let verifier = spend_verifier.ok_or_else(|| {
            DomError::PolicyRejected(
                "native USDOM production proof verifier is unavailable for this proof kind".into(),
            )
        })?;
        entries
            .par_iter()
            .map(|entry| match entry.kind {
                UsdomV4ProofKind::Transfer => Some(
                    verify_private_transfer_payload(bridge, verifier, &entry.payload).map_err(
                        |error| {
                            DomError::Invalid(format!("native USDOM private proof failed: {error}"))
                        },
                    ),
                ),
                UsdomV4ProofKind::Burn => Some(
                    verify_private_burn_payload(bridge, verifier, &entry.payload).map_err(
                        |error| {
                            DomError::Invalid(format!("native USDOM private proof failed: {error}"))
                        },
                    ),
                ),
                _ => None,
            })
            .collect::<Vec<_>>()
    } else {
        (0..entries.len()).map(|_| None).collect()
    };
    let mut transitions = Vec::with_capacity(entries.len());
    let mut verified_checkpoint = None;
    for (index, entry) in entries.iter().enumerate() {
        match entry.kind {
            UsdomV4ProofKind::Issuance => {
                let dynamic_policy = deposit_policy_for_dom_block(
                    network_magic,
                    block_timestamp,
                    bridge,
                    deposit_policy,
                )?;
                let deposit =
                    verify_deposit_witness(&entry.payload, &dynamic_policy).map_err(|error| {
                        DomError::Invalid(format!(
                            "native USDOM Ethereum deposit verification failed: {error}"
                        ))
                    })?;
                usdom_ethereum_finality_experiment::validate_finalized_time_window(
                    deposit.finalized_execution().timestamp,
                    block_timestamp,
                    bridge.burn_timing.max_ethereum_anchor_age_secs,
                    bridge.burn_timing.max_dom_clock_lead_secs,
                )
                .map_err(|error| {
                    DomError::Invalid(format!(
                        "native USDOM deposit finality freshness failed: {error}"
                    ))
                })?;
                let transition =
                    ethereum_deposit_transition(bridge, &deposit).map_err(|error| {
                        DomError::Invalid(format!(
                            "native USDOM deposit conversion failed: {error}"
                        ))
                    })?;
                transitions.push(transition);
            }
            UsdomV4ProofKind::EthereumCheckpoint => {
                let dynamic_policy = checkpoint_policy_for_dom_block(
                    network_magic,
                    block_timestamp,
                    bridge,
                    checkpoint_policy,
                )?;
                let checkpoint = verify_checkpoint_witness(&entry.payload, &dynamic_policy)
                    .map_err(|error| {
                        DomError::Invalid(format!(
                            "native USDOM Ethereum checkpoint verification failed: {error}"
                        ))
                    })?;
                usdom_ethereum_finality_experiment::validate_finalized_time_window(
                    checkpoint.finalized_execution().timestamp,
                    block_timestamp,
                    bridge.burn_timing.max_ethereum_anchor_age_secs,
                    bridge.burn_timing.max_dom_clock_lead_secs,
                )
                .map_err(|error| {
                    DomError::Invalid(format!(
                        "native USDOM checkpoint finality freshness failed: {error}"
                    ))
                })?;
                let transition =
                    ethereum_checkpoint_transition(bridge, &checkpoint).map_err(|error| {
                        DomError::Invalid(format!(
                            "native USDOM checkpoint conversion failed: {error}"
                        ))
                    })?;
                transitions.push(transition);
                verified_checkpoint = Some(checkpoint);
            }
            UsdomV4ProofKind::IssuanceClosure => {
                let static_policy = closure_policy.ok_or_else(|| {
                    DomError::PolicyRejected(
                        "native USDOM issuance-closure verifier policy is unavailable".into(),
                    )
                })?;
                let dynamic_policy = issuance_closure_policy_for_dom_block(
                    network_magic,
                    block_timestamp,
                    bridge,
                    static_policy,
                )?;
                let closure = verify_issuance_closure_witness(&entry.payload, &dynamic_policy)
                    .map_err(|error| {
                        DomError::Invalid(format!(
                            "native USDOM issuance closure verification failed: {error}"
                        ))
                    })?;
                usdom_ethereum_finality_experiment::validate_finalized_time_window(
                    closure.finalized_execution().timestamp,
                    block_timestamp,
                    bridge.burn_timing.max_ethereum_anchor_age_secs,
                    bridge.burn_timing.max_dom_clock_lead_secs,
                )
                .map_err(|error| {
                    DomError::Invalid(format!(
                        "native USDOM issuance closure freshness failed: {error}"
                    ))
                })?;
                transitions.push(VerifiedTransition::IssuanceClose(
                    ethereum_issuance_closure_transition(bridge, &closure).map_err(|error| {
                        DomError::Invalid(format!(
                            "native USDOM issuance closure conversion failed: {error}"
                        ))
                    })?,
                ));
            }
            UsdomV4ProofKind::GracefulShutdown => {
                let domain: [u8; 32] = entry.payload.as_slice().try_into().map_err(|_| {
                    DomError::Malformed("invalid graceful shutdown domain payload".into())
                })?;
                if domain != bridge.dom_domain {
                    return Err(DomError::Invalid(
                        "graceful shutdown domain does not match bridge".into(),
                    ));
                }
                transitions.push(VerifiedTransition::GracefulShutdown(
                    graceful_shutdown_transition(domain).map_err(|error| {
                        DomError::Invalid(format!(
                            "native USDOM graceful shutdown conversion failed: {error}"
                        ))
                    })?,
                ));
            }
            UsdomV4ProofKind::Transfer | UsdomV4ProofKind::Burn => {
                if private_spends > 1 {
                    let transition = private_results
                        .get_mut(index)
                        .and_then(Option::take)
                        .ok_or_else(|| {
                            DomError::Internal(
                                "parallel private proof result is missing from its canonical slot"
                                    .into(),
                            )
                        })?;
                    transitions.push(transition?);
                    continue;
                }
                let verifier = spend_verifier.ok_or_else(|| {
                    DomError::PolicyRejected(
                        "native USDOM production proof verifier is unavailable for this proof kind"
                            .into(),
                    )
                })?;
                let transition = match entry.kind {
                    UsdomV4ProofKind::Transfer => {
                        verify_private_transfer_payload(bridge, verifier, &entry.payload)
                    }
                    UsdomV4ProofKind::Burn => {
                        verify_private_burn_payload(bridge, verifier, &entry.payload)
                    }
                    _ => {
                        return Err(DomError::Internal(
                            "private proof kind changed after canonical dispatch".into(),
                        ));
                    }
                }
                .map_err(|error| {
                    DomError::Invalid(format!("native USDOM private proof failed: {error}"))
                })?;
                transitions.push(transition);
            }
        }
    }
    Ok(VerifiedEnvelopeTransitions {
        transitions,
        checkpoint: verified_checkpoint,
    })
}

fn issuance_closure_policy_for_dom_block(
    network_magic: u32,
    block_timestamp: u64,
    bridge: BridgeIdentity,
    policy: &StaticIssuanceClosureTrustPolicy,
) -> Result<IssuanceClosureTrustPolicy, DomError> {
    validate_static_issuance_closure_policy_identity(network_magic, bridge, policy)?;
    let max_current_slot = block_timestamp
        .checked_sub(ETHEREUM_MAINNET_GENESIS_TIME)
        .map(|elapsed| elapsed / ETHEREUM_SECONDS_PER_SLOT)
        .ok_or_else(|| {
            DomError::Invalid("DOM timestamp predates Ethereum mainnet genesis".into())
        })?;
    policy
        .at_max_current_slot(max_current_slot)
        .map_err(|error| {
            DomError::PolicyRejected(format!("invalid issuance closure policy: {error}"))
        })
}

fn validate_static_issuance_closure_policy_identity(
    network_magic: u32,
    bridge: BridgeIdentity,
    policy: &StaticIssuanceClosureTrustPolicy,
) -> Result<(), DomError> {
    let canonical_chain_id = bridge.ethereum_chain_id[..24].iter().all(|byte| *byte == 0);
    let bridge_chain_id = u64::from_be_bytes(
        bridge.ethereum_chain_id[24..]
            .try_into()
            .map_err(|_| DomError::Invalid("invalid bridge chain ID word".into()))?,
    );
    if network_magic != dom_core::NETWORK_MAGIC_MAINNET
        || !canonical_chain_id
        || policy.closure().ethereum_chain_id != bridge_chain_id
        || policy.closure().ethereum_genesis_validators_root.as_slice()
            != bridge.ethereum_genesis_validators_root
        || policy.closure().reserve.as_slice() != bridge.reserve
        || policy.closure().bridge_domain.as_slice() != bridge.dom_domain
    {
        return Err(DomError::PolicyRejected(
            "native USDOM issuance closure policy does not match bridge identity".into(),
        ));
    }
    Ok(())
}

fn checkpoint_policy_for_dom_block(
    network_magic: u32,
    block_timestamp: u64,
    bridge: BridgeIdentity,
    policy: &StaticCheckpointTrustPolicy,
) -> Result<CheckpointTrustPolicy, DomError> {
    validate_static_checkpoint_policy_identity(network_magic, bridge, policy)?;
    let max_current_slot = block_timestamp
        .checked_sub(ETHEREUM_MAINNET_GENESIS_TIME)
        .map(|elapsed| elapsed / ETHEREUM_SECONDS_PER_SLOT)
        .ok_or_else(|| {
            DomError::Invalid("DOM timestamp predates Ethereum mainnet genesis".into())
        })?;
    policy
        .at_max_current_slot(max_current_slot)
        .map_err(|error| DomError::Invalid(format!("invalid consensus slot ceiling: {error}")))
}

fn validate_static_checkpoint_policy_identity(
    network_magic: u32,
    bridge: BridgeIdentity,
    policy: &StaticCheckpointTrustPolicy,
) -> Result<(), DomError> {
    let chain_id_word = bridge.ethereum_chain_id;
    let canonical_u64 = chain_id_word[..24].iter().all(|byte| *byte == 0);
    let bridge_chain_id = u64::from_be_bytes(
        chain_id_word[24..]
            .try_into()
            .map_err(|_| DomError::Invalid("invalid bridge chain ID word".into()))?,
    );
    let checkpoint = policy.checkpoint();
    if !canonical_u64
        || bridge_chain_id != checkpoint.ethereum_chain_id
        || checkpoint.dom_network_magic != network_magic
        || policy.policy_hash().as_slice() != bridge.ethereum_checkpoint_policy_hash
        || checkpoint.ethereum_genesis_validators_root.as_slice()
            != bridge.ethereum_genesis_validators_root
        || checkpoint.bridge_domain.as_slice() != bridge.dom_domain
    {
        return Err(DomError::Invalid(
            "native USDOM checkpoint policy does not match immutable bridge identity".into(),
        ));
    }
    Ok(())
}

fn deposit_policy_for_dom_block(
    _network_magic: u32,
    block_timestamp: u64,
    bridge: BridgeIdentity,
    policy: &StaticDepositTrustPolicy,
) -> Result<DepositTrustPolicy, DomError> {
    validate_static_deposit_policy_identity(bridge, policy)?;
    let max_current_slot = block_timestamp
        .checked_sub(ETHEREUM_MAINNET_GENESIS_TIME)
        .map(|elapsed| elapsed / ETHEREUM_SECONDS_PER_SLOT)
        .ok_or_else(|| {
            DomError::Invalid("DOM timestamp predates Ethereum mainnet genesis".into())
        })?;
    policy
        .at_max_current_slot(max_current_slot)
        .map_err(|error| DomError::Invalid(format!("invalid consensus slot ceiling: {error}")))
}

fn validate_static_deposit_policy_identity(
    bridge: BridgeIdentity,
    policy: &StaticDepositTrustPolicy,
) -> Result<(), DomError> {
    let chain_id_word = bridge.ethereum_chain_id;
    let canonical_u64 = chain_id_word[..24].iter().all(|byte| *byte == 0);
    let bridge_chain_id = u64::from_be_bytes(
        chain_id_word[24..]
            .try_into()
            .map_err(|_| DomError::Invalid("invalid bridge chain ID word".into()))?,
    );
    let deposit = policy.deposit();
    if !canonical_u64
        || bridge_chain_id != deposit.ethereum_chain_id
        || policy.policy_hash().as_slice() != bridge.ethereum_deposit_policy_hash
        || deposit.ethereum_genesis_validators_root.as_slice()
            != bridge.ethereum_genesis_validators_root
        || deposit.bridge_domain.as_slice() != bridge.dom_domain
        || deposit.reserve.as_slice() != bridge.reserve
    {
        return Err(DomError::Invalid(
            "native USDOM deposit policy does not match immutable bridge identity".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_regtest_candidate_context(
    block: &Block,
    validation_context: &ValidationContext,
    network_magic: u32,
) -> Result<(), DomError> {
    if network_magic != NETWORK_MAGIC_REGTEST
        || block.header.version != BLOCK_VERSION_V4
        || validation_context.current_height != block.header.height
    {
        return Err(DomError::Invalid(
            "native USDOM block v4 is available only through the explicit Regtest path".into(),
        ));
    }
    Ok(())
}

fn validate_scheduled_candidate_context(
    block: &Block,
    validation_context: &ValidationContext,
    network_magic: u32,
    bridge: BridgeIdentity,
    schedule: NativeUsdomV4ActivationSchedule,
) -> Result<(), DomError> {
    schedule.validate()?;
    let empty_state = NativeUsdomState::new(bridge).map_err(|error| {
        DomError::Invalid(format!("native USDOM scheduled bridge is invalid: {error}"))
    })?;
    if schedule.network_magic() != network_magic
        || schedule.chain_id().as_bytes() != &validation_context.chain_id
        || schedule.empty_state_root() != empty_state.state_root()
        || block.header.version != BLOCK_VERSION_V4
        || block.header.height.0 < schedule.first_v4_height()
        || validation_context.current_height != block.header.height
    {
        return Err(DomError::PolicyRejected(
            "native USDOM block does not match the ratified activation schedule".into(),
        ));
    }
    Ok(())
}

/// Recompute and body-validate one reserved block-v4 candidate on Regtest.
///
/// The caller cannot supply the USDOM commitment independently: it is derived
/// from `current_state`, the block timestamp and the ordered opaque transition
/// capabilities. Any failure leaves `current_state` untouched. Parent, median
/// time, future time, target, accumulated difficulty and PoW remain contextual
/// ChainState checks and are deliberately outside this isolated adapter.
#[cfg(test)]
fn verify_usdom_v4_candidate_regtest(
    block: &Block,
    validation_context: &ValidationContext,
    network_magic: u32,
    current_state: &NativeUsdomState,
    transitions: &[VerifiedTransition],
) -> Result<PreparedUsdomV4Candidate, DomError> {
    validate_regtest_candidate_context(block, validation_context, network_magic)?;
    let schedule = native_usdom_v4_regtest_activation_schedule(current_state.bridge_identity())?;
    verify_usdom_v4_candidate_for_schedule(
        block,
        validation_context,
        network_magic,
        current_state,
        transitions,
        schedule,
    )
}

fn verify_usdom_v4_candidate_for_schedule(
    block: &Block,
    validation_context: &ValidationContext,
    network_magic: u32,
    current_state: &NativeUsdomState,
    transitions: &[VerifiedTransition],
    schedule: NativeUsdomV4ActivationSchedule,
) -> Result<PreparedUsdomV4Candidate, DomError> {
    validate_scheduled_candidate_context(
        block,
        validation_context,
        network_magic,
        current_state.bridge_identity(),
        schedule,
    )?;
    let mut next_state = current_state.clone();
    let (receipt, undo) = next_state
        .apply_batch(
            BlockContext {
                timestamp: block.header.timestamp.0,
            },
            transitions,
        )
        .map_err(|error| {
            DomError::Invalid(format!("native USDOM batch validation failed: {error}"))
        })?;

    validate_block_v4_scheduled(
        block,
        validation_context,
        network_magic,
        UsdomV4Commitment {
            batch_header_commitment: receipt.header_commitment,
            block_timestamp: Timestamp(receipt.block_timestamp),
        },
    )
    .map_err(|error| DomError::Invalid(format!("USDOM v4 block validation failed: {error}")))?;

    Ok(PreparedUsdomV4Candidate {
        next_state,
        receipt,
        undo,
        verified_checkpoint: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_canonical_genesis;
    use ark_bn254::Bn254;
    use ark_groth16::Groth16;
    use ark_serialize::CanonicalSerialize;
    use dom_consensus::{
        bind_usdom_batch_commitment, CoinbaseKernel, CoinbaseTransaction, TransactionOutput,
    };
    use dom_core::{
        BlockHeight, Hash256, KERNEL_FEAT_COINBASE, MAX_FUTURE_BLOCK_TIME, NETWORK_MAGIC_MAINNET,
        TAG_KERNEL_MSG_COINBASE,
    };
    use dom_crypto::pedersen::Commitment;
    use dom_crypto::{schnorr_sign, BlindingFactor, SecretKey};
    use dom_usdom_state::{
        encode_private_burn_payload, encode_private_transfer_payload, unsafe_test_only_burn,
        unsafe_test_only_issuance, verify_private_transfer_payload, BridgeIdentity, BurnRecord,
        BurnTimingPolicy, EthereumAnchor,
    };
    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};
    use tempfile::TempDir;
    use usdom_ethereum_finality_experiment::{
        checkpoints::{
            unsafe_test_only_verified_checkpoint, CheckpointPolicy, CheckpointTrustPolicy,
            StaticCheckpointTrustPolicy,
        },
        deposits::{DepositTrustPolicy, ReserveDepositPolicy, StaticDepositTrustPolicy},
        EthereumFork, EthereumForks,
    };

    const DOMAIN: [u8; 32] = [0x11; 32];

    fn supported_forks() -> EthereumForks {
        let fork = |epoch, version| EthereumFork {
            epoch,
            fork_version: [version, 0, 0, 0].into(),
        };
        EthereumForks {
            genesis: fork(0, 0),
            altair: fork(74_240, 1),
            bellatrix: fork(144_896, 2),
            capella: fork(194_048, 3),
            deneb: fork(269_568, 4),
            electra: fork(364_032, 5),
            fulu: fork(411_392, 6),
            gloas: fork(u64::MAX, 7),
        }
    }

    #[test]
    fn finalized_burn_statement_matches_solidity_abi_known_answer() {
        let mut burn_id = [0; 32];
        burn_id[31] = 1;
        let mut request_id = [0; 32];
        request_id[31] = 2;
        let mut domain = [0; 32];
        domain[31] = 3;
        let mut block_hash = [0; 32];
        block_hash[31] = 5;
        let mut state_root = [0; 32];
        state_root[31] = 6;
        let mut chain_id = [0; 32];
        chain_id[30..].copy_from_slice(&31337u16.to_be_bytes());
        let mut reserve = [0; 20];
        reserve[18..].copy_from_slice(&0x1234u16.to_be_bytes());
        let mut schedule = [0; 32];
        schedule[31] = 11;
        let recipient: [u8; 20] = hex::decode("19e7e376e7c213b7e7e7e46cc70a5dd086daff2a")
            .unwrap()
            .try_into()
            .unwrap();
        let statement = FinalizedBurnStatement {
            burn_id,
            request_id,
            recipient,
            amount: 9_007_199_254_740_993,
            dom_domain: domain,
            height: 4,
            block_hash: Hash256::from_bytes(block_hash),
            state_root: Hash256::from_bytes(state_root),
            finality_beacon_slot: 7,
            valid_until: 1_800_600_000,
            ethereum_chain_id: chain_id,
            reserve,
            activation_schedule_commitment: Hash256::from_bytes(schedule),
        };
        assert_eq!(
            hex::encode(Keccak256::digest(FINALIZED_BURN_STATEMENT_TYPE.as_bytes())),
            "b4a224b119278936bec16ab7cf63f13d2cc130395834d17a30335b9158062ced"
        );
        assert_eq!(
            statement.statement_hash().to_string(),
            "1016275e2148a768d3ff2afca10d14e8b74d7c0d8ac0a3b2d2c3758f81510318"
        );
    }

    #[test]
    fn persisted_auxiliary_decoders_reject_every_prefix_and_trailing_bytes() {
        let block_identifier = Hash256::from_bytes([0x21; 32]);
        let state_root = Hash256::from_bytes([0x22; 32]);
        let package_commitment = Hash256::from_bytes([0x23; 32]);
        let mut tip = Vec::with_capacity(USDOM_V4_TIP_BYTES);
        tip.extend_from_slice(block_identifier.as_bytes());
        tip.extend_from_slice(state_root.as_bytes());
        tip.extend_from_slice(package_commitment.as_bytes());
        assert_eq!(tip.len(), USDOM_V4_TIP_BYTES);
        assert_eq!(
            decode_persisted_usdom_v4_tip(&tip, "test tip").unwrap(),
            PersistedUsdomV4Tip {
                block_identifier,
                state_root,
                package_commitment,
            }
        );
        for end in 0..tip.len() {
            assert!(decode_persisted_usdom_v4_tip(&tip[..end], "test tip").is_err());
        }
        let mut trailing_tip = tip.clone();
        trailing_tip.push(0);
        assert!(decode_persisted_usdom_v4_tip(&trailing_tip, "test tip").is_err());

        let mut burn = BurnRecord {
            burn_id: [0x31; 32],
            request_id: [0x32; 32],
            amount: 1_234_567,
            recipient: [0x33; 20],
            ethereum_chain_id: [0x34; 32],
            reserve: [0x35; 20],
            valid_until: 1_900_000_000,
            obligation_commitment: [0; 32],
        };
        burn.obligation_commitment = burn.expected_obligation_commitment(DOMAIN);
        let archived = v2_burn_archive_update(42, block_identifier, burn)
            .unwrap()
            .value
            .unwrap();
        assert_eq!(
            decode_v2_burn_archive_value(&archived).unwrap(),
            (42, block_identifier, burn)
        );
        for end in 0..archived.len() {
            assert!(decode_v2_burn_archive_value(&archived[..end]).is_err());
        }
        let mut trailing_archive = archived.clone();
        trailing_archive.push(0);
        assert!(decode_v2_burn_archive_value(&trailing_archive).is_err());
        let mut wrong_archive_magic = archived;
        wrong_archive_magic[0] ^= 1;
        assert!(decode_v2_burn_archive_value(&wrong_archive_magic).is_err());

        let cursor = v2_prune_cursor_value(987_654_321);
        assert_eq!(decode_v2_prune_cursor(&cursor).unwrap(), 987_654_321);
        for end in 0..cursor.len() {
            assert!(decode_v2_prune_cursor(&cursor[..end]).is_err());
        }
        let mut trailing_cursor = cursor.clone();
        trailing_cursor.push(0);
        assert!(decode_v2_prune_cursor(&trailing_cursor).is_err());
        let mut wrong_cursor_magic = cursor;
        wrong_cursor_magic[0] ^= 1;
        assert!(decode_v2_prune_cursor(&wrong_cursor_magic).is_err());

        for (version, width, label) in [
            (
                USDOM_V2_PERSISTENCE_VERSION,
                USDOM_V2_WITNESS_META_BYTES,
                "v2 witness test",
            ),
            (
                USDOM_V4_PERSISTENCE_VERSION,
                USDOM_V4_PACKAGE_META_BYTES,
                "v4 package test",
            ),
        ] {
            let mut metadata = Vec::with_capacity(width);
            metadata.extend_from_slice(&version.to_be_bytes());
            metadata.extend_from_slice(package_commitment.as_bytes());
            metadata.extend_from_slice(&123_456u32.to_be_bytes());
            metadata.extend_from_slice(&17u16.to_be_bytes());
            assert_eq!(metadata.len(), width);
            assert_eq!(
                decode_persisted_chunk_metadata(&metadata, width, version, label).unwrap(),
                (package_commitment, 123_456, 17)
            );
            for end in 0..metadata.len() {
                assert!(
                    decode_persisted_chunk_metadata(&metadata[..end], width, version, label)
                        .is_err()
                );
            }
            let mut trailing_metadata = metadata.clone();
            trailing_metadata.push(0);
            assert!(
                decode_persisted_chunk_metadata(&trailing_metadata, width, version, label).is_err()
            );
            let mut wrong_version = metadata;
            wrong_version[..2].copy_from_slice(&version.wrapping_add(1).to_be_bytes());
            assert!(
                decode_persisted_chunk_metadata(&wrong_version, width, version, label).is_err()
            );
        }
    }

    #[test]
    fn v1_undo_retention_prunes_exactly_beyond_rolling_finality() {
        let directory = TempDir::new().unwrap();
        let store = DomStore::open_with_map_size(directory.path(), 64 << 20).unwrap();
        let genesis = Hash256::from_bytes([0x71; 32]);
        let first = Hash256::from_bytes([0x72; 32]);
        store
            .commit_block(
                genesis.as_bytes(),
                0,
                b"retention-genesis-header",
                b"retention-genesis-body",
                &[],
                &[],
                &[],
            )
            .unwrap();
        let undo_key = native_usdom_v4_undo_key(first);
        store
            .commit_block_with_consensus_state(
                first.as_bytes(),
                1,
                b"retention-first-header",
                b"retention-first-body",
                &[],
                &[],
                &[],
                &[ConsensusStateUpdate {
                    key: undo_key.clone(),
                    value: Some(vec![0x73]),
                }],
            )
            .unwrap();

        assert!(
            native_usdom_v4_undo_retention_update(&store, crate::reorg::MAX_REORG_DEPTH - 1,)
                .unwrap()
                .is_none()
        );
        assert!(
            native_usdom_v4_undo_retention_update(&store, crate::reorg::MAX_REORG_DEPTH,)
                .unwrap()
                .is_none()
        );
        let deletion =
            native_usdom_v4_undo_retention_update(&store, crate::reorg::MAX_REORG_DEPTH + 1)
                .unwrap()
                .unwrap();
        assert_eq!(deletion.key, undo_key);
        assert_eq!(deletion.value, None);
    }

    #[test]
    fn v2_compaction_prunes_only_below_checkpoint_and_rolling_floors() {
        let directory = TempDir::new().unwrap();
        let store = DomStore::open_with_map_size(directory.path(), 64 << 20).unwrap();
        let genesis = Hash256::from_bytes([0x81; 32]);
        let first = Hash256::from_bytes([0x82; 32]);
        let state = NativeUsdomState::new(bridge()).unwrap();
        let chain_id = dom_consensus::derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis);
        let schedule = NativeUsdomV2ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            chain_id,
            1,
            genesis,
            &state,
        )
        .unwrap();
        store
            .commit_block(
                genesis.as_bytes(),
                0,
                b"v2-compaction-genesis-header",
                b"v2-compaction-genesis-body",
                &[],
                &[],
                &[],
            )
            .unwrap();
        let mut package_meta = Vec::new();
        package_meta.extend_from_slice(&USDOM_V4_PERSISTENCE_VERSION.to_be_bytes());
        package_meta.extend_from_slice(&[0x83; 32]);
        package_meta.extend_from_slice(&1u32.to_be_bytes());
        package_meta.extend_from_slice(&1u16.to_be_bytes());
        let mut witness_meta = Vec::new();
        witness_meta.extend_from_slice(&USDOM_V2_PERSISTENCE_VERSION.to_be_bytes());
        witness_meta.extend_from_slice(&[0x84; 32]);
        witness_meta.extend_from_slice(&1u32.to_be_bytes());
        witness_meta.extend_from_slice(&1u16.to_be_bytes());
        let package_meta_key = persistence_key(USDOM_V4_PACKAGE_META_PREFIX, first);
        let package_chunk = package_chunk_key(first, 0);
        let witness_meta_key = persistence_key(USDOM_V2_WITNESS_META_PREFIX, first);
        let witness_chunk = v2_witness_chunk_key(first, 0);
        let record_key = persistence_key(USDOM_V2_BLOCK_RECORD_PREFIX, first);
        store
            .commit_block_with_consensus_state(
                first.as_bytes(),
                1,
                b"v2-compaction-first-header",
                b"v2-compaction-first-body",
                &[],
                &[],
                &[],
                &[
                    ConsensusStateUpdate {
                        key: USDOM_V2_PRUNE_CURSOR_KEY.to_vec(),
                        value: Some(v2_prune_cursor_value(1)),
                    },
                    ConsensusStateUpdate {
                        key: package_meta_key.clone(),
                        value: Some(package_meta),
                    },
                    ConsensusStateUpdate {
                        key: package_chunk.clone(),
                        value: Some(vec![1]),
                    },
                    ConsensusStateUpdate {
                        key: witness_meta_key.clone(),
                        value: Some(witness_meta),
                    },
                    ConsensusStateUpdate {
                        key: witness_chunk.clone(),
                        value: Some(vec![2]),
                    },
                    ConsensusStateUpdate {
                        key: record_key.clone(),
                        value: Some(vec![3]),
                    },
                ],
            )
            .unwrap();

        assert!(native_usdom_v2_history_compaction_updates(
            &store,
            schedule,
            crate::reorg::MAX_REORG_DEPTH,
            1,
        )
        .unwrap()
        .is_empty());
        let updates = native_usdom_v2_history_compaction_updates(
            &store,
            schedule,
            crate::reorg::MAX_REORG_DEPTH + 1,
            2,
        )
        .unwrap();
        assert!(updates.iter().any(|update| update.key == package_meta_key));
        assert!(updates.iter().any(|update| update.key == package_chunk));
        assert!(updates.iter().any(|update| update.key == witness_meta_key));
        assert!(updates.iter().any(|update| update.key == witness_chunk));
        assert!(updates.iter().any(|update| update.key == record_key));
        assert_eq!(
            updates.last(),
            Some(&ConsensusStateUpdate {
                key: USDOM_V2_PRUNE_CURSOR_KEY.to_vec(),
                value: Some(v2_prune_cursor_value(2)),
            })
        );
    }

    fn bridge() -> BridgeIdentity {
        let mut chain_id = [0; 32];
        chain_id[31] = 1;
        BridgeIdentity {
            dom_domain: DOMAIN,
            ethereum_genesis_validators_root: [0x22; 32],
            ethereum_chain_id: chain_id,
            ethereum_checkpoint_policy_hash: unused_checkpoint_policy().policy_hash().into(),
            ethereum_deposit_policy_hash: unused_deposit_policy().policy_hash().into(),
            privacy_policy_hash: *privacy_policy_hash().as_bytes(),
            privacy_verifier_config_hash: [0x48; 32],
            reserve: [0x33; 20],
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

    fn ethereum_mainnet_bridge() -> BridgeIdentity {
        let mut value = bridge();
        value.ethereum_chain_id = [0; 32];
        value.ethereum_chain_id[31] = 1;
        value
    }

    fn issuance() -> VerifiedTransition {
        VerifiedTransition::Issue(unsafe_test_only_issuance(
            DOMAIN,
            [0x44; 32],
            [0x15; 32],
            1_000_000,
            EthereumAnchor {
                genesis_validators_root: [0x22; 32],
                execution_block_number: 20_000_000,
                execution_block_hash: [0x66; 32],
                execution_block_timestamp: 1_700_000_000,
                beacon_slot: 16_000_000,
                beacon_root: [0x77; 32],
            },
        ))
    }

    fn issuance_at(block_timestamp: u64) -> VerifiedTransition {
        VerifiedTransition::Issue(unsafe_test_only_issuance(
            DOMAIN,
            [0x64; 32],
            [0x16; 32],
            1_000_000,
            EthereumAnchor {
                genesis_validators_root: [0x22; 32],
                execution_block_number: 20_000_001,
                execution_block_hash: [0x66; 32],
                execution_block_timestamp: block_timestamp,
                beacon_slot: 16_000_001,
                beacon_root: [0x67; 32],
            },
        ))
    }

    fn burn_from_with_bridge(
        state_after_issuance: &NativeUsdomState,
        block_timestamp: u64,
        bridge: BridgeIdentity,
    ) -> VerifiedTransition {
        let nullifiers = vec![[0x14; 32]];
        let recipient = [0x73; 20];
        let valid_until = block_timestamp + 100_000;
        let mut record = BurnRecord {
            burn_id: dom_usdom_state::derive_private_burn_id(
                bridge,
                &nullifiers,
                recipient,
                250_000,
                valid_until,
            )
            .unwrap(),
            request_id: [0x72; 32],
            amount: 250_000,
            recipient,
            ethereum_chain_id: bridge.ethereum_chain_id,
            reserve: bridge.reserve,
            valid_until,
            obligation_commitment: [0; 32],
        };
        record.obligation_commitment = record.expected_obligation_commitment(DOMAIN);
        VerifiedTransition::Burn(unsafe_test_only_burn(
            DOMAIN,
            state_after_issuance.note_anchor(),
            nullifiers,
            vec![[0x17; 32]],
            [0x0e; 32],
            record,
        ))
    }

    fn burn_from(
        state_after_issuance: &NativeUsdomState,
        block_timestamp: u64,
    ) -> VerifiedTransition {
        burn_from_with_bridge(state_after_issuance, block_timestamp, bridge())
    }

    fn checkpoint_policy_for_network(network_magic: u32) -> StaticCheckpointTrustPolicy {
        let dynamic = CheckpointTrustPolicy {
            trusted_checkpoint: [0x41; 32].into(),
            ethereum_genesis_validators_root: [0x22; 32].into(),
            forks: supported_forks(),
            max_current_slot: 1,
            checkpoint: CheckpointPolicy {
                ethereum_chain_id: 1,
                ethereum_genesis_validators_root: [0x22; 32].into(),
                registry: [0x42; 20].into(),
                runtime_code_hash: [0x43; 32].into(),
                config_storage_slot: [0x44; 32].into(),
                checkpoint_config_hash: [0x45; 32].into(),
                bridge_domain: DOMAIN.into(),
                dom_network_magic: network_magic,
            },
        };
        StaticCheckpointTrustPolicy::from_trust_policy(&dynamic).unwrap()
    }

    fn unused_checkpoint_policy() -> StaticCheckpointTrustPolicy {
        checkpoint_policy_for_network(NETWORK_MAGIC_REGTEST)
    }

    fn unused_deposit_policy() -> StaticDepositTrustPolicy {
        let dynamic = DepositTrustPolicy {
            trusted_checkpoint: [0x41; 32].into(),
            ethereum_genesis_validators_root: [0x22; 32].into(),
            forks: supported_forks(),
            max_current_slot: 1,
            deposit: ReserveDepositPolicy {
                ethereum_chain_id: 1,
                ethereum_genesis_validators_root: [0x22; 32].into(),
                reserve: [0x33; 20].into(),
                runtime_code_hash: [0x46; 32].into(),
                bridge_domain: DOMAIN.into(),
                max_amount: 100_000_000_000,
            },
        };
        StaticDepositTrustPolicy::from_trust_policy(&dynamic).unwrap()
    }

    fn checkpoint_policy_for(
        bridge: BridgeIdentity,
        block_timestamp: u64,
    ) -> CheckpointTrustPolicy {
        CheckpointTrustPolicy {
            trusted_checkpoint: [0x41; 32].into(),
            ethereum_genesis_validators_root: bridge.ethereum_genesis_validators_root.into(),
            forks: supported_forks(),
            max_current_slot: (block_timestamp - ETHEREUM_MAINNET_GENESIS_TIME)
                / ETHEREUM_SECONDS_PER_SLOT,
            checkpoint: CheckpointPolicy {
                ethereum_chain_id: 1,
                ethereum_genesis_validators_root: bridge.ethereum_genesis_validators_root.into(),
                registry: [0x42; 20].into(),
                runtime_code_hash: [0x43; 32].into(),
                config_storage_slot: [0x44; 32].into(),
                checkpoint_config_hash: [0x45; 32].into(),
                bridge_domain: bridge.dom_domain.into(),
                dom_network_magic: NETWORK_MAGIC_REGTEST,
            },
        }
    }

    fn envelope_bytes(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(USDOM_V4_ENVELOPE_MAGIC);
        bytes.extend_from_slice(&USDOM_V4_ENVELOPE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(kind);
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn candidate(
        state: &NativeUsdomState,
        transitions: &[VerifiedTransition],
    ) -> (Block, ValidationContext) {
        candidate_after_activation(state, transitions, Hash256::from_bytes([0x90; 32]))
    }

    fn candidate_after_activation(
        state: &NativeUsdomState,
        transitions: &[VerifiedTransition],
        activation_block: Hash256,
    ) -> (Block, ValidationContext) {
        let mut block = build_canonical_genesis(NETWORK_MAGIC_REGTEST, &[0; 32])
            .unwrap()
            .block
            .unwrap();
        block.header.version = BLOCK_VERSION_V4;
        block.header.height = dom_core::BlockHeight(1);
        block.header.prev_hash = activation_block;
        let schedule =
            native_usdom_v4_regtest_activation_schedule(state.bridge_identity()).unwrap();
        block.coinbase = test_coinbase(block.header.height, schedule.chain_id().as_bytes());
        let (output_root, kernel_root, raw_rangeproof_root) =
            compute_block_pmmr_roots(block.header.height, &block.coinbase, &block.transactions)
                .unwrap();
        block.header.output_root = output_root;
        block.header.kernel_root = kernel_root;
        let mut preview = state.clone();
        let (receipt, _) = preview
            .apply_batch(
                BlockContext {
                    timestamp: block.header.timestamp.0,
                },
                transitions,
            )
            .unwrap();
        block.header.rangeproof_root =
            bind_usdom_batch_commitment(raw_rangeproof_root, receipt.header_commitment).unwrap();
        let context = ValidationContext {
            current_height: block.header.height,
            chain_id: *schedule.chain_id().as_bytes(),
            now: Timestamp(u64::MAX),
        };
        (block, context)
    }

    fn test_coinbase(height: BlockHeight, chain_id: &[u8; 32]) -> CoinbaseTransaction {
        let explicit_value = dom_core::block_reward(height).noms();
        let mut scalar = [0u8; 32];
        scalar[31] = 0x51;
        let blinding = BlindingFactor::from_bytes(scalar).unwrap();
        let commitment = Commitment::commit(explicit_value, &blinding);
        let (proof, proof_commitment) =
            dom_crypto::range_proof_prove_bytes_with_nonce(explicit_value, &blinding, &[0x52; 32])
                .unwrap();
        assert_eq!(proof_commitment, *commitment.as_bytes());
        let excess = Commitment::commit(0, &blinding);
        let secret = SecretKey::from_bytes(blinding.as_bytes()).unwrap();
        let mut message = Vec::with_capacity(9);
        message.push(KERNEL_FEAT_COINBASE);
        message.extend_from_slice(&explicit_value.to_le_bytes());
        let digest = blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &message);
        let signature = schnorr_sign(&secret, digest.as_bytes(), chain_id).unwrap();
        CoinbaseTransaction {
            output: TransactionOutput { commitment, proof },
            kernel: CoinbaseKernel {
                features: KERNEL_FEAT_COINBASE,
                explicit_value,
                excess,
                excess_signature: signature.to_bytes(),
            },
            offset: [0; 32],
        }
    }

    fn package_bytes(block: Block, envelope: UsdomV4ProofEnvelope) -> Vec<u8> {
        UsdomV4BlockPackage::new(block, envelope)
            .unwrap()
            .to_bytes()
            .unwrap()
    }

    fn checkpoint_record_for(binding: NativeBurnBlockBinding) -> [u8; 417] {
        let mut record = [0u8; 417];
        record[0] = 2;
        record[1..9].copy_from_slice(&binding.block_height.to_be_bytes());
        record[9..41].copy_from_slice(binding.block_identifier.as_bytes());
        record[41..73].copy_from_slice(binding.state_root.as_bytes());
        record[73..77].copy_from_slice(&binding.network_magic.to_be_bytes());
        record[77..85].copy_from_slice(&binding.ethereum_chain_id[24..]);
        record[85..93].copy_from_slice(&20_000_010u64.to_be_bytes());
        record[93..125].copy_from_slice(&[0xa1; 32]);
        record[125..157].copy_from_slice(&[0xa2; 32]);
        record[157..189].copy_from_slice(&[0xa3; 32]);
        record[189..197].copy_from_slice(&16_000_010u64.to_be_bytes());
        record[197..229].copy_from_slice(&[0xa4; 32]);
        record[229..261].copy_from_slice(&binding.ethereum_genesis_validators_root);
        record[261..265].copy_from_slice(&7u32.to_be_bytes());
        record[265..269].copy_from_slice(&3u32.to_be_bytes());
        record[269..289].copy_from_slice(&[0xa5; 20]);
        record[289..321].copy_from_slice(&[0xa6; 32]);
        record[321..353].copy_from_slice(&[0xa7; 32]);
        record[353..385].copy_from_slice(&binding.dom_domain);
        let mut checkpoint = crate::ethereum_checkpoint_poc::TestOracleCheckpoint {
            height: binding.block_height,
            dom_block: binding.block_identifier,
            dom_state_root: binding.state_root,
            dom_network_magic: binding.network_magic,
            ethereum_chain_id: u64::from_be_bytes(
                binding.ethereum_chain_id[24..].try_into().unwrap(),
            ),
            ethereum_block_number: 20_000_010,
            ethereum_block: Hash256::from_bytes([0xa1; 32]),
            ethereum_receipts_root: Hash256::from_bytes([0xa2; 32]),
            ethereum_state_root: Hash256::from_bytes([0xa3; 32]),
            ethereum_beacon_slot: 16_000_010,
            ethereum_beacon_root: Hash256::from_bytes([0xa4; 32]),
            ethereum_genesis_validators_root: Hash256::from_bytes(
                binding.ethereum_genesis_validators_root,
            ),
            transaction_index: 7,
            receipt_log_index: 3,
            checkpoint_contract: [0xa5; 20],
            checkpoint_code_hash: Hash256::from_bytes([0xa6; 32]),
            checkpoint_config_hash: Hash256::from_bytes([0xa7; 32]),
            bridge_domain: Hash256::from_bytes(binding.dom_domain),
            checkpoint_event_digest: Hash256::ZERO,
        };
        checkpoint.checkpoint_event_digest =
            crate::ethereum_checkpoint_poc::expected_checkpoint_event_digest(checkpoint);
        record[385..417].copy_from_slice(checkpoint.checkpoint_event_digest.as_bytes());
        record
    }

    #[test]
    fn consensus_checkpoint_floor_binds_reconstructed_ancestry_state() {
        let bridge = bridge();
        let target_block = Hash256::from_bytes([0xb1; 32]);
        let target_state_root = Hash256::from_bytes([0xb2; 32]);
        let mut checkpoint = crate::ethereum_checkpoint_poc::TestOracleCheckpoint {
            height: 10,
            dom_block: target_block,
            dom_state_root: target_state_root,
            dom_network_magic: NETWORK_MAGIC_REGTEST,
            ethereum_chain_id: 1,
            ethereum_block_number: 20_000_100,
            ethereum_block: Hash256::from_bytes([0xb3; 32]),
            ethereum_receipts_root: Hash256::from_bytes([0xb4; 32]),
            ethereum_state_root: Hash256::from_bytes([0xb5; 32]),
            ethereum_beacon_slot: 16_000_100,
            ethereum_beacon_root: Hash256::from_bytes([0xb6; 32]),
            ethereum_genesis_validators_root: Hash256::from_bytes(
                bridge.ethereum_genesis_validators_root,
            ),
            transaction_index: 8,
            receipt_log_index: 4,
            checkpoint_contract: [0xb7; 20],
            checkpoint_code_hash: Hash256::from_bytes([0xb8; 32]),
            checkpoint_config_hash: Hash256::from_bytes([0xb9; 32]),
            bridge_domain: Hash256::from_bytes(bridge.dom_domain),
            checkpoint_event_digest: Hash256::ZERO,
        };
        checkpoint.checkpoint_event_digest =
            crate::ethereum_checkpoint_poc::expected_checkpoint_event_digest(checkpoint);
        let record: [u8; 417] = crate::ethereum_checkpoint_poc::encode_test_oracle_v2(checkpoint)
            .unwrap()
            .try_into()
            .unwrap();
        let verified = unsafe_test_only_verified_checkpoint(
            record,
            1_700_000_000,
            bridge.ethereum_checkpoint_policy_hash.into(),
        );

        let (bound, update) = native_checkpoint_floor_update(
            &verified,
            NETWORK_MAGIC_REGTEST,
            bridge,
            NativeCheckpointTarget {
                carrier_height: 11,
                height: 10,
                block: target_block,
                state_root: target_state_root,
            },
            None,
        )
        .unwrap();
        assert_eq!(bound, checkpoint);
        let update = update.unwrap();
        assert_eq!(
            update.key,
            crate::ethereum_checkpoint_poc::CONSENSUS_CHECKPOINT_KEY
        );
        assert_eq!(
            crate::ethereum_checkpoint_poc::decode_test_oracle_v2(update.value.as_deref().unwrap())
                .unwrap(),
            checkpoint
        );
        assert!(native_checkpoint_floor_update(
            &verified,
            NETWORK_MAGIC_REGTEST,
            bridge,
            NativeCheckpointTarget {
                carrier_height: 11,
                height: 10,
                block: target_block,
                state_root: Hash256::from_bytes([0xba; 32]),
            },
            None,
        )
        .is_err());
        assert!(native_checkpoint_floor_update(
            &verified,
            NETWORK_MAGIC_REGTEST,
            bridge,
            NativeCheckpointTarget {
                carrier_height: 10,
                height: 10,
                block: target_block,
                state_root: target_state_root,
            },
            None,
        )
        .is_err());
    }

    #[test]
    fn mainnet_verified_native_burn_checkpoint_becomes_consensus_reorg_floor() {
        let checkpoint_policy = checkpoint_policy_for_network(NETWORK_MAGIC_MAINNET);
        let mut bridge = bridge();
        bridge.ethereum_checkpoint_policy_hash = checkpoint_policy.policy_hash().into();

        let block_timestamp = 1_700_000_000;
        let mut state = NativeUsdomState::new(bridge).unwrap();
        state
            .apply_batch(
                BlockContext {
                    timestamp: block_timestamp,
                },
                &[issuance()],
            )
            .unwrap();
        let burn = burn_from_with_bridge(&state, block_timestamp, bridge);
        state
            .apply_batch(
                BlockContext {
                    timestamp: block_timestamp,
                },
                &[burn],
            )
            .unwrap();
        assert_eq!(state.total_burned(), 250_000);

        let target_block = Hash256::from_bytes([0xc1; 32]);
        let target_state_root = state.state_root();
        let mut checkpoint = crate::ethereum_checkpoint_poc::TestOracleCheckpoint {
            height: 10,
            dom_block: target_block,
            dom_state_root: target_state_root,
            dom_network_magic: NETWORK_MAGIC_MAINNET,
            ethereum_chain_id: 1,
            ethereum_block_number: 20_000_200,
            ethereum_block: Hash256::from_bytes([0xc2; 32]),
            ethereum_receipts_root: Hash256::from_bytes([0xc3; 32]),
            ethereum_state_root: Hash256::from_bytes([0xc4; 32]),
            ethereum_beacon_slot: 16_000_200,
            ethereum_beacon_root: Hash256::from_bytes([0xc5; 32]),
            ethereum_genesis_validators_root: Hash256::from_bytes(
                bridge.ethereum_genesis_validators_root,
            ),
            transaction_index: 9,
            receipt_log_index: 5,
            checkpoint_contract: [0x42; 20],
            checkpoint_code_hash: Hash256::from_bytes([0x43; 32]),
            checkpoint_config_hash: Hash256::from_bytes([0x45; 32]),
            bridge_domain: Hash256::from_bytes(bridge.dom_domain),
            checkpoint_event_digest: Hash256::ZERO,
        };
        checkpoint.checkpoint_event_digest =
            crate::ethereum_checkpoint_poc::expected_checkpoint_event_digest(checkpoint);
        let record: [u8; 417] = crate::ethereum_checkpoint_poc::encode_test_oracle_v2(checkpoint)
            .unwrap()
            .try_into()
            .unwrap();
        let verified = unsafe_test_only_verified_checkpoint(
            record,
            block_timestamp,
            checkpoint_policy.policy_hash(),
        );
        let (bound, update) = native_checkpoint_floor_update(
            &verified,
            NETWORK_MAGIC_MAINNET,
            bridge,
            NativeCheckpointTarget {
                carrier_height: 11,
                height: 10,
                block: target_block,
                state_root: target_state_root,
            },
            None,
        )
        .unwrap();
        assert_eq!(bound, checkpoint);
        let update = update.expect("a newer verified checkpoint must update consensus state");

        assert!(native_checkpoint_floor_update(
            &verified,
            NETWORK_MAGIC_REGTEST,
            bridge,
            NativeCheckpointTarget {
                carrier_height: 11,
                height: 10,
                block: target_block,
                state_root: target_state_root,
            },
            None,
        )
        .is_err());
        let wrong_policy =
            unsafe_test_only_verified_checkpoint(record, block_timestamp, [0xdd; 32].into());
        assert!(native_checkpoint_floor_update(
            &wrong_policy,
            NETWORK_MAGIC_MAINNET,
            bridge,
            NativeCheckpointTarget {
                carrier_height: 11,
                height: 10,
                block: target_block,
                state_root: target_state_root,
            },
            None,
        )
        .is_err());

        let directory = TempDir::new().unwrap();
        let store = DomStore::open_with_map_size(directory.path(), 64 << 20).unwrap();
        store
            .commit_block(
                target_block.as_bytes(),
                10,
                b"mainnet-checkpoint-target-header",
                b"mainnet-checkpoint-target-body",
                &[],
                &[],
                &[],
            )
            .unwrap();
        let carrier = Hash256::from_bytes([0xc6; 32]);
        store
            .commit_block_with_consensus_state(
                carrier.as_bytes(),
                11,
                b"mainnet-checkpoint-carrier-header",
                b"mainnet-checkpoint-carrier-body",
                &[],
                &[],
                &[],
                &[update],
            )
            .unwrap();
        assert_eq!(
            crate::ethereum_checkpoint_poc::load_consensus(&store).unwrap(),
            Some(checkpoint)
        );
        crate::ethereum_checkpoint_poc::check_reorg(&store, 11, 10).unwrap();
        assert!(crate::ethereum_checkpoint_poc::check_reorg(&store, 11, 9)
            .unwrap_err()
            .to_string()
            .contains("reorg would undo checkpoint"));
    }

    #[test]
    fn exact_verified_batch_is_bound_without_mutating_input_state() {
        let state = NativeUsdomState::new(bridge()).unwrap();
        let before = state.state_root();
        let transitions = vec![issuance()];
        let (block, context) = candidate(&state, &transitions);
        let verified = verify_usdom_v4_candidate_regtest(
            &block,
            &context,
            NETWORK_MAGIC_REGTEST,
            &state,
            &transitions,
        )
        .unwrap();

        assert_eq!(state.state_root(), before);
        assert_eq!(verified.receipt.previous_state_root, before);
        assert_eq!(verified.receipt.transition_count, 1);
        assert_eq!(
            verified.receipt.new_state_root,
            verified.next_state.state_root()
        );
        assert_ne!(verified.next_state.state_root(), before);
    }

    #[test]
    fn queued_issuance_metadata_contains_only_verified_public_deposit_ids() {
        let issuance = issuance();
        let expected = match issuance.commitment_projection() {
            TransitionCommitmentProjection::Issue { record, .. } => record.deposit_id,
            _ => unreachable!("issuance helper must create an issuance"),
        };
        let ids = verified_issuance_deposit_ids(&[
            issuance,
            VerifiedTransition::EthereumCheckpoint(
                dom_usdom_state::unsafe_test_only_ethereum_checkpoint(
                    DOMAIN,
                    EthereumAnchor {
                        genesis_validators_root: [0x22; 32],
                        execution_block_number: 20_000_001,
                        execution_block_hash: [0x24; 32],
                        execution_block_timestamp: 1_799_999_901,
                        beacon_slot: 16_000_001,
                        beacon_root: [0x25; 32],
                    },
                ),
            ),
        ]);
        assert_eq!(ids, vec![expected]);
    }

    #[test]
    fn queued_issuance_reserves_each_deposit_for_one_candidate() {
        let queued_deposit = [0x41; 32];
        let candidates = VecDeque::from([NativeUsdomV4MiningCandidate {
            id: Hash256::from_bytes([0x42; 32]),
            encoded_len: 1,
            issuance_deposit_ids: vec![queued_deposit],
            envelope: UsdomV4ProofEnvelope::empty(),
        }]);

        assert!(conflicts_with_queued_issuance(
            &candidates,
            &[queued_deposit]
        ));
        assert!(conflicts_with_queued_issuance(
            &candidates,
            &[[0x43; 32], queued_deposit]
        ));
        assert!(!conflicts_with_queued_issuance(&candidates, &[[0x44; 32]]));
        assert!(!conflicts_with_queued_issuance(&candidates, &[]));
        let v2_queued = [[0x71; 32], [0x72; 32]];
        assert!(has_issuance_deposit_overlap(
            v2_queued.iter(),
            &[[0x73; 32], [0x72; 32]]
        ));
        assert!(!has_issuance_deposit_overlap(
            v2_queued.iter(),
            &[[0x74; 32]]
        ));
    }

    #[test]
    fn canonical_consumption_releases_queued_issuance_reservation() {
        let bridge = bridge();
        let schedule = native_usdom_v4_regtest_activation_schedule(bridge).unwrap();
        let mut runtime = NativeUsdomV4Runtime {
            network_magic: NETWORK_MAGIC_REGTEST,
            schedule,
            bridge,
            checkpoint_policy: unused_checkpoint_policy(),
            deposit_policy: unused_deposit_policy(),
            closure_policy: None,
            spend_verifier: None,
            state: NativeUsdomState::new(bridge).unwrap(),
            startup_audit: NativeUsdomV4HistoryAudit {
                canonical_tip: Hash256::from_bytes([0x31; 32]),
                oldest_audited_parent: Hash256::from_bytes([0x31; 32]),
                audited_blocks: 0,
                boundary_state_root: NativeUsdomState::new(bridge).unwrap().state_root(),
                reached_activation_boundary: false,
            },
            mining_candidates: VecDeque::from([
                NativeUsdomV4MiningCandidate {
                    id: Hash256::from_bytes([0x51; 32]),
                    encoded_len: 1,
                    issuance_deposit_ids: vec![[0x44; 32]],
                    envelope: UsdomV4ProofEnvelope::empty(),
                },
                NativeUsdomV4MiningCandidate {
                    id: Hash256::from_bytes([0x52; 32]),
                    encoded_len: 2,
                    issuance_deposit_ids: Vec::new(),
                    envelope: UsdomV4ProofEnvelope::empty(),
                },
            ]),
            mining_candidate_bytes: 3,
        };

        assert_eq!(runtime.prune_consumed_issuance_candidates().unwrap(), 0);
        assert_eq!(runtime.mining_candidate_stats(), (2, 3));
        runtime
            .state
            .apply_batch(
                BlockContext {
                    timestamp: 1_800_000_000,
                },
                &[issuance()],
            )
            .unwrap();
        assert_eq!(runtime.prune_consumed_issuance_candidates().unwrap(), 1);
        assert_eq!(runtime.mining_candidate_stats(), (1, 2));
        assert!(!conflicts_with_queued_issuance(
            &runtime.mining_candidates,
            &[[0x44; 32]]
        ));
    }

    #[test]
    fn full_candidate_pool_rejects_before_envelope_parsing() {
        let bridge = bridge();
        let state = NativeUsdomState::new(bridge).unwrap();
        let mining_candidates = (0..MAX_USDOM_V4_MINING_CANDIDATES)
            .map(|index| NativeUsdomV4MiningCandidate {
                id: Hash256::from_bytes([index as u8 + 1; 32]),
                encoded_len: 1,
                issuance_deposit_ids: Vec::new(),
                envelope: UsdomV4ProofEnvelope::empty(),
            })
            .collect();
        let mut runtime = NativeUsdomV4Runtime {
            network_magic: NETWORK_MAGIC_REGTEST,
            schedule: native_usdom_v4_regtest_activation_schedule(bridge).unwrap(),
            bridge,
            checkpoint_policy: unused_checkpoint_policy(),
            deposit_policy: unused_deposit_policy(),
            closure_policy: None,
            spend_verifier: None,
            startup_audit: NativeUsdomV4HistoryAudit {
                canonical_tip: Hash256::from_bytes([0x31; 32]),
                oldest_audited_parent: Hash256::from_bytes([0x31; 32]),
                audited_blocks: 0,
                boundary_state_root: state.state_root(),
                reached_activation_boundary: false,
            },
            state,
            mining_candidates,
            mining_candidate_bytes: MAX_USDOM_V4_MINING_CANDIDATES,
        };
        let malformed_but_bounded = vec![0; USDOM_V4_ENVELOPE_HEADER_BYTES];

        assert_eq!(
            runtime
                .admit_mining_envelope(&malformed_but_bounded, Timestamp(1_800_000_000))
                .unwrap_err(),
            DomError::PolicyRejected("native USDOM mining candidate pool is full".into())
        );
        assert_eq!(
            runtime.mining_candidate_stats(),
            (
                MAX_USDOM_V4_MINING_CANDIDATES,
                MAX_USDOM_V4_MINING_CANDIDATES
            )
        );
    }

    #[test]
    fn bridge_committed_spend_verifier_authorizes_exact_serialized_transfer() {
        use dom_usdom_privacy::{
            chain_scalar,
            circuit::{InputWitness, OutputWitness, SpendCircuit, SpendStatement},
            empty_subtree_roots, memo_scalar, owner_commitment, NoteOpening, Scalar,
            NOTE_ORIGIN_ISSUANCE, NOTE_ORIGIN_PRIVATE, NOTE_TREE_DEPTH,
        };

        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_4348);
        let parameters = Groth16::<Bn254>::generate_random_parameters_with_reduction(
            SpendCircuit::default(),
            &mut rng,
        )
        .unwrap();
        let mut key_bytes = Vec::new();
        parameters.vk.serialize_compressed(&mut key_bytes).unwrap();
        let verifier = SpendVerifier::from_bytes(&key_bytes).unwrap();
        let mut bridge = bridge();
        bridge.privacy_verifier_config_hash = *verifier.config_hash().as_bytes();
        let scalar = |value: u8| {
            let mut bytes = [0u8; 32];
            bytes[31] = value;
            Scalar::from_bytes(bytes).unwrap()
        };
        let chain = chain_scalar(DOMAIN, bridge.privacy_policy_hash);
        let secret = scalar(7);
        let input = NoteOpening {
            chain,
            origin: NOTE_ORIGIN_ISSUANCE,
            value: 10,
            owner: owner_commitment(chain, secret).unwrap(),
            rho: scalar(8),
        };
        let input_commitment = input.commitment().unwrap().to_bytes();
        let mut state = NativeUsdomState::new(bridge).unwrap();
        state
            .apply_batch(
                BlockContext {
                    timestamp: 1_800_000_000,
                },
                &[VerifiedTransition::Issue(unsafe_test_only_issuance(
                    DOMAIN,
                    [0x21; 32],
                    input_commitment,
                    10,
                    EthereumAnchor {
                        genesis_validators_root: bridge.ethereum_genesis_validators_root,
                        execution_block_number: 20_000_000,
                        execution_block_hash: [0x22; 32],
                        execution_block_timestamp: 1_799_999_900,
                        beacon_slot: 16_000_000,
                        beacon_root: [0x23; 32],
                    },
                ))],
            )
            .unwrap();
        let anchor = state.note_anchor();
        let output = OutputWitness {
            enabled: true,
            value: 10,
            owner: scalar(9),
            rho: scalar(10),
        };
        let output_commitment = NoteOpening {
            chain,
            origin: NOTE_ORIGIN_PRIVATE,
            value: output.value,
            owner: output.owner,
            rho: output.rho,
        }
        .commitment()
        .unwrap()
        .to_bytes();
        let nullifier = input.nullifier(secret).unwrap().to_bytes();
        let memo = b"encrypted transfer memo";
        let statement = SpendStatement {
            chain,
            anchor: Scalar::from_bytes(*anchor.root.as_bytes()).unwrap(),
            nullifiers: [Scalar::from_bytes(nullifier).unwrap(), Scalar::ZERO],
            output_notes: [Scalar::from_bytes(output_commitment).unwrap(), Scalar::ZERO],
            burn_amount: 0,
            effect: Scalar::ZERO,
            memo: memo_scalar(memo).unwrap(),
        };
        let circuit = SpendCircuit {
            statement,
            inputs: [
                InputWitness {
                    enabled: true,
                    origin: NOTE_ORIGIN_ISSUANCE,
                    value: input.value,
                    owner_secret: secret,
                    rho: input.rho,
                    leaf_index: 0,
                    siblings: empty_subtree_roots()[..NOTE_TREE_DEPTH].try_into().unwrap(),
                },
                InputWitness::default(),
            ],
            outputs: [output, OutputWitness::default()],
        };
        let proof = Groth16::<Bn254>::create_random_proof_with_reduction(
            circuit.clone(),
            &parameters,
            &mut rng,
        )
        .unwrap();
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        let payload = encode_private_transfer_payload(
            anchor,
            &[nullifier],
            &[output_commitment],
            memo,
            &proof_bytes,
        )
        .unwrap();
        let transition = verify_private_transfer_payload(bridge, &verifier, &payload).unwrap();
        state
            .apply_batch(
                BlockContext {
                    timestamp: 1_800_000_000,
                },
                &[issuance_at(1_800_000_000)],
            )
            .unwrap();
        let activation_burn = burn_from_with_bridge(&state, 1_800_000_000, bridge);
        state
            .apply_batch(
                BlockContext {
                    timestamp: 1_800_000_000,
                },
                std::slice::from_ref(&activation_burn),
            )
            .unwrap();
        let activation_burn_id = state.burn_records()[0].burn_id;
        let (block, context) = candidate(&state, std::slice::from_ref(&transition));
        let envelope = UsdomV4ProofEnvelope {
            entries: vec![UsdomV4ProofEntry {
                kind: UsdomV4ProofKind::Transfer,
                payload,
            }],
        };
        let duplicate_entries = vec![envelope.entries[0].clone(), envelope.entries[0].clone()];
        assert!(matches!(
            verify_envelope_transitions(
                NETWORK_MAGIC_REGTEST,
                block.header.timestamp.0,
                bridge,
                &unused_checkpoint_policy(),
                &unused_deposit_policy(),
                None,
                Some(&verifier),
                &duplicate_entries,
            ),
            Err(DomError::Malformed(message))
                if message == "duplicate native USDOM v4 proof entry"
        ));

        // A separately randomized proof for the same valid public statement
        // has distinct canonical bytes and exercises the parallel verifier.
        // State transition validation still rejects the repeated nullifier if
        // both transitions are ever presented to one candidate.
        let second_proof =
            Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &parameters, &mut rng)
                .unwrap();
        let mut second_proof_bytes = Vec::new();
        second_proof
            .serialize_compressed(&mut second_proof_bytes)
            .unwrap();
        let second_payload = encode_private_transfer_payload(
            anchor,
            &[nullifier],
            &[output_commitment],
            memo,
            &second_proof_bytes,
        )
        .unwrap();
        assert_ne!(envelope.entries[0].payload, second_payload);
        let parallel_entries = vec![
            envelope.entries[0].clone(),
            UsdomV4ProofEntry {
                kind: UsdomV4ProofKind::Transfer,
                payload: second_payload,
            },
        ];
        let parallel = verify_envelope_transitions(
            NETWORK_MAGIC_REGTEST,
            block.header.timestamp.0,
            bridge,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
            Some(&verifier),
            &parallel_entries,
        )
        .unwrap();
        assert_eq!(parallel.transitions.len(), 2);
        let mut corrupted_entries = parallel_entries;
        *corrupted_entries[1].payload.last_mut().unwrap() ^= 1;
        assert!(verify_envelope_transitions(
            NETWORK_MAGIC_REGTEST,
            block.header.timestamp.0,
            bridge,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
            Some(&verifier),
            &corrupted_entries,
        )
        .is_err());
        let envelope_bytes = envelope.to_bytes().unwrap();
        let package = package_bytes(block.clone(), envelope.clone());
        assert!(verify_usdom_v4_serialized_candidate_regtest(
            &package,
            &context,
            NETWORK_MAGIC_REGTEST,
            &state,
            bridge,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
        )
        .is_err());
        let verified = verify_usdom_v4_serialized_candidate_with_spend_verifier_regtest(
            &package,
            &context,
            NETWORK_MAGIC_REGTEST,
            &state,
            bridge,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
        )
        .unwrap();
        assert!(verified.next_state().has_nullifier(&nullifier));
        let schedule = native_usdom_v4_regtest_activation_schedule(bridge).unwrap();
        let scheduled = verify_usdom_v4_serialized_candidate_for_schedule(
            &package,
            &context,
            NETWORK_MAGIC_REGTEST,
            &state,
            bridge,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            schedule,
        )
        .unwrap();
        assert_eq!(scheduled.block_identifier(), verified.block_identifier());
        assert_eq!(
            scheduled.next_state().state_root(),
            verified.next_state().state_root()
        );
        let block_context = BlockContext {
            timestamp: block.header.timestamp.0,
        };
        let witnesses = state
            .transition_batch_witnesses(block_context, std::slice::from_ref(&transition))
            .unwrap();
        let previous_v2 = state.state_commitment_v2().unwrap();
        let (_, v2_receipt) = apply_v2_transition_batch_with_receipt(
            previous_v2.root(),
            block_context,
            previous_v2,
            std::slice::from_ref(&transition),
            &witnesses,
        )
        .unwrap();
        let mut v2_block = block.clone();
        let (_, _, raw_rangeproof_root) = compute_block_pmmr_roots(
            v2_block.header.height,
            &v2_block.coinbase,
            &v2_block.transactions,
        )
        .unwrap();
        v2_block.header.rangeproof_root =
            bind_usdom_batch_commitment(raw_rangeproof_root, v2_receipt.header_commitment).unwrap();
        let v2_parent = v2_block.header.prev_hash;
        let v2_package = package_bytes(v2_block.clone(), envelope.clone());
        let v2_schedule = NativeUsdomV2ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            schedule.chain_id(),
            1,
            v2_parent,
            &state,
        )
        .unwrap();
        let verified_batch = verify_usdom_v4_serialized_transition_batch_for_v2_schedule(
            &v2_package,
            &context,
            NETWORK_MAGIC_REGTEST,
            bridge,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            v2_schedule,
        )
        .unwrap();
        let v2_candidate = verified_batch
            .execute_v2(&context, previous_v2.root(), previous_v2, &witnesses)
            .unwrap();
        assert_eq!(v2_candidate.next_state().root(), v2_receipt.new_state_root);
        assert_eq!(v2_candidate.receipt(), v2_receipt);
        let witness_bundle = UsdomV2ExecutionWitnesses::new(witnesses.clone()).unwrap();
        let witness_bytes = witness_bundle.to_bytes().unwrap();
        let decoded_witnesses = UsdomV2ExecutionWitnesses::from_bytes(&witness_bytes).unwrap();
        assert_eq!(decoded_witnesses.to_bytes().unwrap(), witness_bytes);
        let v2_sidecar =
            UsdomV2BlockSidecar::new(envelope.clone(), witness_bundle.clone()).unwrap();
        let v2_sidecar_bytes = v2_sidecar.to_bytes().unwrap();
        let decoded_sidecar = UsdomV2BlockSidecar::from_bytes(&v2_sidecar_bytes).unwrap();
        assert_eq!(decoded_sidecar.to_bytes().unwrap(), v2_sidecar_bytes);
        let mut trailing_sidecar = v2_sidecar_bytes.clone();
        trailing_sidecar.push(0);
        assert!(UsdomV2BlockSidecar::from_bytes(&trailing_sidecar).is_err());
        assert_eq!(
            v2_candidate.witness_commitment(),
            witness_bundle.commitment().unwrap()
        );
        let v2_updates = v2_candidate
            .consensus_state_updates(v2_schedule, previous_v2, &v2_package, &witness_bundle)
            .unwrap();
        let record_key = persistence_key(
            USDOM_V2_BLOCK_RECORD_PREFIX,
            v2_candidate.block_identifier(),
        );
        let record_bytes = v2_updates
            .iter()
            .find(|update| update.key == record_key)
            .and_then(|update| update.value.as_deref())
            .expect("persisted v2 block record");
        let record = PersistedUsdomV2BlockRecord::from_bytes(record_bytes).unwrap();
        assert_eq!(record.previous_state, previous_v2);
        assert_eq!(record.next_state, v2_candidate.next_state());
        assert_eq!(record.receipt, v2_candidate.receipt());
        let runtime_tip = v2_updates
            .iter()
            .find(|update| update.key == USDOM_V2_TIP_KEY)
            .and_then(|update| update.value.as_deref())
            .expect("persisted v2 runtime tip");
        assert_eq!(&runtime_tip[..8], USDOM_V2_RUNTIME_TIP_MAGIC);
        assert_ne!(runtime_tip, v2_activation_tip_value(v2_schedule));
        let directory = TempDir::new().unwrap();
        let store = DomStore::open_with_map_size(directory.path(), 64 << 20).unwrap();
        let parent_block = build_canonical_genesis(NETWORK_MAGIC_REGTEST, &[0; 32])
            .unwrap()
            .block
            .unwrap();
        let mut activation_updates: Vec<_> = state
            .export_entries()
            .into_iter()
            .map(|(key, value)| ConsensusStateUpdate {
                key,
                value: Some(value),
            })
            .collect();
        activation_updates.push(ConsensusStateUpdate {
            key: USDOM_V4_ACTIVATION_KEY.to_vec(),
            value: Some(activation_record(schedule, v2_parent).unwrap()),
        });
        activation_updates.push(ConsensusStateUpdate {
            key: USDOM_V4_TIP_KEY.to_vec(),
            value: Some(tip_value(
                v2_parent,
                state.state_root(),
                dom_core::Hash256::ZERO,
            )),
        });
        activation_updates
            .extend(native_usdom_v2_activation_updates(&state, v2_schedule, v2_parent, 0).unwrap());
        store
            .commit_block_with_consensus_state(
                v2_parent.as_bytes(),
                0,
                &parent_block.header.to_bytes().unwrap(),
                &parent_block.to_bytes().unwrap(),
                &[],
                &[],
                &[],
                &activation_updates,
            )
            .unwrap();
        store
            .commit_block_with_consensus_state(
                v2_candidate.block_identifier().as_bytes(),
                1,
                &v2_block.header.to_bytes().unwrap(),
                &v2_block.to_bytes().unwrap(),
                &[],
                &[],
                &[],
                &v2_updates,
            )
            .unwrap();
        assert_eq!(
            restore_persisted_usdom_v2_state_for_schedule(
                &store,
                NETWORK_MAGIC_REGTEST,
                v2_candidate.block_identifier(),
                bridge,
                &unused_checkpoint_policy(),
                &unused_deposit_policy(),
                None,
                &verifier,
                v2_schedule,
            )
            .unwrap(),
            v2_candidate.next_state()
        );
        drop(store);
        let reopened = DomStore::open_with_map_size(directory.path(), 64 << 20).unwrap();
        assert_eq!(
            restore_persisted_usdom_v2_state_for_schedule(
                &reopened,
                NETWORK_MAGIC_REGTEST,
                v2_candidate.block_identifier(),
                bridge,
                &unused_checkpoint_policy(),
                &unused_deposit_policy(),
                None,
                &verifier,
                v2_schedule,
            )
            .unwrap(),
            v2_candidate.next_state()
        );
        let reconstructed = reconstruct_authenticated_usdom_v2_burn_witness(
            &reopened,
            NETWORK_MAGIC_REGTEST,
            bridge,
            v2_candidate.block_identifier(),
            activation_burn_id,
            schedule,
            v2_schedule,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
        )
        .unwrap();
        assert_eq!(reconstructed.burn.burn_id, activation_burn_id);
        assert_eq!(reconstructed.state, v2_candidate.next_state());
        assert!(reconstructed.verify(v2_candidate.next_state().root()));
        let checkpoint_policy = unused_checkpoint_policy();
        let mut previous_work = [0u8; 32];
        previous_work[31] = 1;
        let mut target_work = [0u8; 32];
        target_work[31] = 2;
        let mut confirmation_work = [0u8; 32];
        confirmation_work[31] = 3;
        let checkpoint_statement = dom_usdom_finalized_burn_program::CheckpointStatementV6 {
            checkpoint: dom_usdom_finalized_burn_program::CheckpointStatement {
                bridge_domain: bridge.dom_domain,
                dom_network_magic: NETWORK_MAGIC_REGTEST,
                previous_height: 0,
                previous_block: [0x41; 32],
                previous_state_root: [0x42; 32],
                previous_context_hash: [0x43; 32],
                previous_total_difficulty: previous_work,
                height: 1,
                block: *v2_candidate.block_identifier().as_bytes(),
                state_root: *v2_candidate.next_state().root().as_bytes(),
                context_hash: [0x44; 32],
                total_difficulty: target_work,
                confirmation_height: 2,
                confirmation_block: [0x45; 32],
                confirmation_total_difficulty: confirmation_work,
                confirmation_timestamp: v2_block.header.timestamp.0 + 120,
                ethereum_chain_id: bridge.ethereum_chain_id,
                registry: checkpoint_policy
                    .checkpoint()
                    .registry
                    .as_slice()
                    .try_into()
                    .unwrap(),
                activation_schedule_commitment: *schedule.commitment().as_bytes(),
                checkpoint_config_hash: checkpoint_policy
                    .checkpoint()
                    .checkpoint_config_hash
                    .as_slice()
                    .try_into()
                    .unwrap(),
            },
            total_issued: v2_candidate.next_state().total_issued,
            total_burned: v2_candidate.next_state().total_burned,
            issuance_closed: v2_candidate.next_state().issuance_closure.is_some(),
        };
        let invalid_checkpoint_error = export_finalized_burn_prover_input_for_schedule(
            &reopened,
            NETWORK_MAGIC_REGTEST,
            bridge,
            v2_candidate.block_identifier(),
            activation_burn_id,
            schedule,
            v2_schedule,
            checkpoint_policy,
            &unused_deposit_policy(),
            None,
            &verifier,
            checkpoint_statement,
            vec![0; 168],
        )
        .unwrap_err()
        .to_string();
        assert!(invalid_checkpoint_error.contains("finalized burn input failed"));

        let record_key = persistence_key(
            USDOM_V2_BLOCK_RECORD_PREFIX,
            v2_candidate.block_identifier(),
        );
        let original_record = reopened.get_consensus_state(&record_key).unwrap().unwrap();
        let mut wrong_parent_record =
            PersistedUsdomV2BlockRecord::from_bytes(&original_record).unwrap();
        wrong_parent_record.parent = Hash256::from_bytes([0xa9; 32]);
        reopened
            .apply_reorg_with_consensus_state(
                v2_candidate.block_identifier().as_bytes(),
                &[],
                &[],
                &[],
                &[ConsensusStateUpdate {
                    key: record_key.clone(),
                    value: Some(wrong_parent_record.to_bytes().unwrap()),
                }],
            )
            .unwrap();
        assert!(reconstruct_authenticated_usdom_v2_burn_witness(
            &reopened,
            NETWORK_MAGIC_REGTEST,
            bridge,
            v2_candidate.block_identifier(),
            activation_burn_id,
            schedule,
            v2_schedule,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
        )
        .is_err());
        reopened
            .apply_reorg_with_consensus_state(
                v2_candidate.block_identifier().as_bytes(),
                &[],
                &[],
                &[],
                &[ConsensusStateUpdate {
                    key: record_key,
                    value: Some(original_record),
                }],
            )
            .unwrap();

        let burn_archive_key = v2_burn_archive_key(activation_burn_id);
        let original_burn_value = reopened
            .get_consensus_state(&burn_archive_key)
            .unwrap()
            .unwrap();
        let mut corrupted_burn_value = original_burn_value.clone();
        corrupted_burn_value[0] ^= 1;
        reopened
            .apply_reorg_with_consensus_state(
                v2_candidate.block_identifier().as_bytes(),
                &[],
                &[],
                &[],
                &[ConsensusStateUpdate {
                    key: burn_archive_key.clone(),
                    value: Some(corrupted_burn_value),
                }],
            )
            .unwrap();
        assert!(reconstruct_authenticated_usdom_v2_burn_witness(
            &reopened,
            NETWORK_MAGIC_REGTEST,
            bridge,
            v2_candidate.block_identifier(),
            activation_burn_id,
            schedule,
            v2_schedule,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
        )
        .is_err());
        reopened
            .apply_reorg_with_consensus_state(
                v2_candidate.block_identifier().as_bytes(),
                &[],
                &[],
                &[],
                &[ConsensusStateUpdate {
                    key: burn_archive_key,
                    value: Some(original_burn_value),
                }],
            )
            .unwrap();
        assert!(reconstruct_authenticated_usdom_v2_burn_witness(
            &reopened,
            NETWORK_MAGIC_REGTEST,
            bridge,
            v2_candidate.block_identifier(),
            activation_burn_id,
            schedule,
            v2_schedule,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
        )
        .is_ok());

        let mut later_block = v2_block.clone();
        later_block.header.height = BlockHeight(2);
        later_block.header.prev_hash = v2_candidate.block_identifier();
        later_block.coinbase =
            test_coinbase(later_block.header.height, schedule.chain_id().as_bytes());
        let (later_output_root, later_kernel_root, later_raw_rangeproof_root) =
            compute_block_pmmr_roots(
                later_block.header.height,
                &later_block.coinbase,
                &later_block.transactions,
            )
            .unwrap();
        later_block.header.output_root = later_output_root;
        later_block.header.kernel_root = later_kernel_root;
        let later_block_context = BlockContext {
            timestamp: later_block.header.timestamp.0,
        };
        let (later_state, later_receipt) = apply_v2_transition_batch_with_receipt(
            v2_candidate.next_state().root(),
            later_block_context,
            v2_candidate.next_state(),
            &[],
            &[],
        )
        .unwrap();
        later_block.header.rangeproof_root =
            bind_usdom_batch_commitment(later_raw_rangeproof_root, later_receipt.header_commitment)
                .unwrap();
        let later_context = ValidationContext {
            current_height: later_block.header.height,
            chain_id: *schedule.chain_id().as_bytes(),
            now: later_block.header.timestamp,
        };
        let later_envelope = UsdomV4ProofEnvelope::empty();
        let later_package = package_bytes(later_block.clone(), later_envelope);
        let later_verified = verify_usdom_v4_serialized_transition_batch_for_v2_schedule(
            &later_package,
            &later_context,
            NETWORK_MAGIC_REGTEST,
            bridge,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            v2_schedule,
        )
        .unwrap();
        let later_candidate = later_verified
            .execute_v2(
                &later_context,
                v2_candidate.next_state().root(),
                v2_candidate.next_state(),
                &[],
            )
            .unwrap();
        assert_eq!(later_candidate.next_state(), later_state);
        let later_witnesses = UsdomV2ExecutionWitnesses::new(Vec::new()).unwrap();
        let later_updates = later_candidate
            .consensus_state_updates(
                v2_schedule,
                v2_candidate.next_state(),
                &later_package,
                &later_witnesses,
            )
            .unwrap();
        reopened
            .commit_block_with_consensus_state(
                later_candidate.block_identifier().as_bytes(),
                later_block.header.height.0,
                &later_block.header.to_bytes().unwrap(),
                &later_block.to_bytes().unwrap(),
                &[],
                &[],
                &[],
                &later_updates,
            )
            .unwrap();
        assert_eq!(
            restore_persisted_usdom_v2_state_for_schedule(
                &reopened,
                NETWORK_MAGIC_REGTEST,
                later_candidate.block_identifier(),
                bridge,
                &unused_checkpoint_policy(),
                &unused_deposit_policy(),
                None,
                &verifier,
                v2_schedule,
            )
            .unwrap(),
            later_candidate.next_state()
        );
        let historical = reconstruct_authenticated_usdom_v2_burn_witness(
            &reopened,
            NETWORK_MAGIC_REGTEST,
            bridge,
            v2_candidate.block_identifier(),
            activation_burn_id,
            schedule,
            v2_schedule,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
        )
        .unwrap();
        assert_eq!(historical.state, v2_candidate.next_state());
        assert!(historical.verify(v2_candidate.next_state().root()));

        let compacted_block = v2_candidate.block_identifier();
        let compaction_updates = native_usdom_v2_history_compaction_updates(
            &reopened,
            v2_schedule,
            crate::reorg::MAX_REORG_DEPTH + 1,
            later_block.header.height.0,
        )
        .unwrap();
        assert!(!compaction_updates.is_empty());
        reopened
            .apply_reorg_with_consensus_state(
                later_candidate.block_identifier().as_bytes(),
                &[],
                &[],
                &[],
                &compaction_updates,
            )
            .unwrap();
        assert!(reopened
            .get_consensus_state(&persistence_key(
                USDOM_V4_PACKAGE_META_PREFIX,
                compacted_block,
            ))
            .unwrap()
            .is_none());
        assert!(reopened
            .get_consensus_state(&persistence_key(
                USDOM_V2_WITNESS_META_PREFIX,
                compacted_block,
            ))
            .unwrap()
            .is_none());
        assert!(reopened
            .get_consensus_state(&persistence_key(
                USDOM_V2_BLOCK_RECORD_PREFIX,
                compacted_block,
            ))
            .unwrap()
            .is_none());
        assert!(reopened
            .get_consensus_state(&v2_burn_archive_key(activation_burn_id))
            .unwrap()
            .is_some());
        let post_compaction = reconstruct_authenticated_usdom_v2_burn_witness(
            &reopened,
            NETWORK_MAGIC_REGTEST,
            bridge,
            later_candidate.block_identifier(),
            activation_burn_id,
            schedule,
            v2_schedule,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
        )
        .unwrap();
        assert_eq!(post_compaction.state, later_candidate.next_state());
        assert!(post_compaction.verify(later_candidate.next_state().root()));
        assert!(reconstruct_authenticated_usdom_v2_burn_witness(
            &reopened,
            NETWORK_MAGIC_REGTEST,
            bridge,
            compacted_block,
            activation_burn_id,
            schedule,
            v2_schedule,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
        )
        .is_err());
        let empty_bundle = UsdomV2ExecutionWitnesses::new(Vec::new()).unwrap();
        assert!(v2_candidate
            .consensus_state_updates(v2_schedule, previous_v2, &v2_package, &empty_bundle)
            .is_err());
        let mut trailing_witness = witness_bytes.clone();
        trailing_witness.push(0);
        assert!(UsdomV2ExecutionWitnesses::from_bytes(&trailing_witness).is_err());
        let mut wrong_witness_version = witness_bytes.clone();
        wrong_witness_version[8..10].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(UsdomV2ExecutionWitnesses::from_bytes(&wrong_witness_version).is_err());
        let mut missing_witness_payload = witness_bytes.clone();
        missing_witness_payload.truncate(USDOM_V2_WITNESS_BUNDLE_HEADER_BYTES + 4);
        assert!(UsdomV2ExecutionWitnesses::from_bytes(&missing_witness_payload).is_err());
        assert_ne!(
            v2_candidate.package_commitment(),
            verified.package_commitment()
        );
        let mut missing_witness = witnesses.clone();
        missing_witness.clear();
        assert!(verified_batch
            .execute_v2(&context, previous_v2.root(), previous_v2, &missing_witness)
            .is_err());
        let wrong_height_schedule = NativeUsdomV4ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            schedule.chain_id(),
            2,
            bridge,
        )
        .unwrap();
        assert!(verify_usdom_v4_serialized_candidate_for_schedule(
            &package,
            &context,
            NETWORK_MAGIC_REGTEST,
            &state,
            bridge,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            wrong_height_schedule,
        )
        .is_err());
        let mut wrong_chain_context = ValidationContext {
            current_height: context.current_height,
            chain_id: context.chain_id,
            now: context.now,
        };
        wrong_chain_context.chain_id[0] ^= 1;
        assert!(verify_usdom_v4_serialized_candidate_for_schedule(
            &package,
            &wrong_chain_context,
            NETWORK_MAGIC_REGTEST,
            &state,
            bridge,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            schedule,
        )
        .is_err());

        let mut v2_runtime = NativeUsdomV2Runtime {
            network_magic: NETWORK_MAGIC_REGTEST,
            schedule: v2_schedule,
            bridge,
            checkpoint_policy: unused_checkpoint_policy(),
            deposit_policy: unused_deposit_policy(),
            closure_policy: None,
            spend_verifier: SpendVerifier::from_bytes(&key_bytes).unwrap(),
            spend_verifying_key: key_bytes.clone(),
            state: previous_v2,
            mining_candidates: VecDeque::new(),
            mining_candidate_bytes: 0,
        };
        let v2_candidate_id = v2_runtime
            .admit_mining_candidate(&envelope_bytes, &witness_bytes, block.header.timestamp)
            .unwrap();
        assert_eq!(
            v2_runtime.mining_candidate_stats(),
            (1, envelope_bytes.len() + witness_bytes.len())
        );
        assert_eq!(
            v2_runtime
                .admit_mining_candidate(&envelope_bytes, &witness_bytes, block.header.timestamp,)
                .unwrap(),
            v2_candidate_id
        );
        let v2_template = v2_runtime
            .mining_batch_template(block.header.timestamp)
            .unwrap();
        assert_eq!(v2_template.candidate_id(), Some(v2_candidate_id));
        assert_eq!(
            v2_template.batch_header_commitment(),
            v2_receipt.header_commitment
        );
        let (template_envelope, template_witnesses) = v2_template.into_parts();
        assert_eq!(template_envelope.to_bytes().unwrap(), envelope_bytes);
        assert_eq!(template_witnesses.to_bytes().unwrap(), witness_bytes);
        assert!(v2_runtime
            .complete_mining_candidate(v2_candidate_id)
            .unwrap());
        assert_eq!(v2_runtime.mining_candidate_stats(), (0, 0));
        assert!(!v2_runtime
            .complete_mining_candidate(v2_candidate_id)
            .unwrap());
        assert!(v2_runtime
            .admit_mining_candidate(
                &envelope_bytes,
                &UsdomV2ExecutionWitnesses::new(Vec::new())
                    .unwrap()
                    .to_bytes()
                    .unwrap(),
                block.header.timestamp,
            )
            .is_err());
        v2_runtime
            .admit_mining_candidate(&envelope_bytes, &witness_bytes, block.header.timestamp)
            .unwrap();
        let post_transfer_state = v2_candidate.next_state();
        v2_runtime.state = post_transfer_state;
        let empty_v2_template = v2_runtime
            .mining_batch_template(block.header.timestamp)
            .unwrap();
        assert_eq!(empty_v2_template.candidate_id(), None);
        assert_eq!(v2_runtime.mining_candidate_stats(), (0, 0));
        assert_eq!(
            empty_v2_template.batch_header_commitment(),
            apply_v2_transition_batch_with_receipt(
                post_transfer_state.root(),
                block_context,
                post_transfer_state,
                &[],
                &[],
            )
            .unwrap()
            .1
            .header_commitment
        );

        let mut runtime = NativeUsdomV4Runtime {
            network_magic: NETWORK_MAGIC_REGTEST,
            schedule,
            bridge,
            checkpoint_policy: unused_checkpoint_policy(),
            deposit_policy: unused_deposit_policy(),
            closure_policy: None,
            spend_verifier: Some(verifier),
            state: state.clone(),
            startup_audit: NativeUsdomV4HistoryAudit {
                canonical_tip: Hash256::from_bytes([0x31; 32]),
                oldest_audited_parent: Hash256::from_bytes([0x31; 32]),
                audited_blocks: 0,
                boundary_state_root: state.state_root(),
                reached_activation_boundary: false,
            },
            mining_candidates: VecDeque::new(),
            mining_candidate_bytes: 0,
        };
        let candidate_id = runtime
            .admit_mining_envelope(&envelope_bytes, block.header.timestamp)
            .unwrap();
        assert_eq!(runtime.mining_candidate_stats(), (1, envelope_bytes.len()));
        assert_eq!(
            runtime
                .admit_mining_envelope(&envelope_bytes, block.header.timestamp)
                .unwrap(),
            candidate_id
        );
        assert_eq!(runtime.mining_candidate_stats(), (1, envelope_bytes.len()));
        let template = runtime
            .mining_batch_template(block.header.timestamp)
            .unwrap();
        assert_eq!(template.candidate_id(), Some(candidate_id));
        assert_eq!(template.envelope(), &envelope);
        assert_eq!(
            template.batch_header_commitment(),
            verified.receipt().header_commitment
        );
        assert!(runtime.complete_mining_candidate(candidate_id).unwrap());
        assert_eq!(runtime.mining_candidate_stats(), (0, 0));
        assert!(!runtime.complete_mining_candidate(candidate_id).unwrap());
        runtime
            .admit_mining_envelope(&envelope_bytes, block.header.timestamp)
            .unwrap();
        runtime.state = verified.next_state().clone();
        let empty_fallback = runtime
            .mining_batch_template(block.header.timestamp)
            .unwrap();
        assert_eq!(empty_fallback.candidate_id(), None);
        assert_eq!(empty_fallback.envelope(), &UsdomV4ProofEnvelope::empty());
        assert_eq!(runtime.mining_candidate_stats(), (0, 0));
        assert!(runtime
            .admit_mining_envelope(
                &UsdomV4ProofEnvelope::empty().to_bytes().unwrap(),
                block.header.timestamp,
            )
            .is_err());
    }

    #[test]
    fn runtime_loads_only_the_exact_bridge_committed_spend_key() {
        use dom_usdom_privacy::circuit::SpendCircuit;

        std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_5254);
        let parameters = Groth16::<Bn254>::generate_random_parameters_with_reduction(
            SpendCircuit::default(),
            &mut rng,
        )
        .unwrap();
        let mut key_bytes = Vec::new();
        parameters.vk.serialize_compressed(&mut key_bytes).unwrap();
        let verifier = SpendVerifier::from_bytes(&key_bytes).unwrap();
        let mut committed_bridge = bridge();
        committed_bridge.privacy_verifier_config_hash = *verifier.config_hash().as_bytes();

        let configured =
            dom_core::configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST).unwrap();
        let chain_id = dom_consensus::derive_chain_id(NETWORK_MAGIC_REGTEST, &configured);
        let canonical =
            build_canonical_genesis(NETWORK_MAGIC_REGTEST, chain_id.as_bytes()).unwrap();
        let state = NativeUsdomState::new(committed_bridge).unwrap();
        let activation = native_usdom_v4_activation_updates(&state, canonical.hash).unwrap();
        let dir = TempDir::new().unwrap();
        let store = DomStore::open_with_map_size(dir.path(), 64 << 20).unwrap();
        store
            .commit_block_with_consensus_state(
                canonical.hash.as_bytes(),
                0,
                &canonical.header_bytes,
                &canonical.block_bytes,
                &[],
                &[],
                &[],
                &activation,
            )
            .unwrap();
        let chain =
            crate::ChainState::open_with_utxo_repair(store, canonical.hash, NETWORK_MAGIC_REGTEST)
                .unwrap();

        let runtime = NativeUsdomV4Runtime::restore_with_spend_verifier(
            &chain,
            committed_bridge,
            unused_checkpoint_policy(),
            unused_deposit_policy(),
            None,
            &key_bytes,
        )
        .unwrap();
        assert_eq!(
            runtime.spend_verifier_config_hash(),
            Some(verifier.config_hash())
        );

        let schedule = native_usdom_v4_regtest_activation_schedule(committed_bridge).unwrap();
        let scheduled = NativeUsdomV4Runtime::restore_for_schedule_with_spend_verifier(
            &chain,
            committed_bridge,
            unused_checkpoint_policy(),
            unused_deposit_policy(),
            None,
            &key_bytes,
            schedule,
        )
        .unwrap();
        assert_eq!(
            scheduled.spend_verifier_config_hash(),
            Some(verifier.config_hash())
        );
        let wrong_schedule = NativeUsdomV4ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            chain_id,
            2,
            committed_bridge,
        )
        .unwrap();
        assert!(
            NativeUsdomV4Runtime::restore_for_schedule_with_spend_verifier(
                &chain,
                committed_bridge,
                unused_checkpoint_policy(),
                unused_deposit_policy(),
                None,
                &key_bytes,
                wrong_schedule,
            )
            .is_err()
        );

        let mut wrong_commitment = committed_bridge;
        wrong_commitment.privacy_verifier_config_hash[0] ^= 1;
        assert!(NativeUsdomV4Runtime::restore_with_spend_verifier(
            &chain,
            wrong_commitment,
            unused_checkpoint_policy(),
            unused_deposit_policy(),
            None,
            &key_bytes,
        )
        .is_err());
        assert!(NativeUsdomV4Runtime::restore_with_spend_verifier(
            &chain,
            committed_bridge,
            unused_checkpoint_policy(),
            unused_deposit_policy(),
            None,
            b"not a verifying key",
        )
        .is_err());
    }

    #[test]
    fn persisted_v2_record_rejects_every_truncation_and_trailing_bytes() {
        let native_state = NativeUsdomState::new(bridge()).unwrap();
        let state = native_state.state_commitment_v2().unwrap();
        let schedule = NativeUsdomV2ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            dom_core::Hash256::from_bytes([0x10; 32]),
            2,
            dom_core::Hash256::from_bytes([0x11; 32]),
            &native_state,
        )
        .unwrap();
        let record = PersistedUsdomV2BlockRecord {
            schedule_commitment: schedule.commitment(),
            block_identifier: dom_core::Hash256::from_bytes([0x12; 32]),
            parent: dom_core::Hash256::from_bytes([0x13; 32]),
            package_commitment: dom_core::Hash256::from_bytes([0x14; 32]),
            witness_commitment: dom_core::Hash256::from_bytes([0x15; 32]),
            previous_state: state,
            next_state: state,
            receipt: TransitionBatchReceipt {
                version: dom_usdom_state::CANDIDATE_V2_TRANSITION_BATCH_VERSION,
                transition_count: 0,
                block_timestamp: 1,
                transitions_root: dom_core::Hash256::from_bytes([0x16; 32]),
                previous_state_root: state.root(),
                new_state_root: state.root(),
                previous_total_issued: state.total_issued,
                previous_total_burned: state.total_burned,
                new_total_issued: state.total_issued,
                new_total_burned: state.total_burned,
                header_commitment: dom_core::Hash256::from_bytes([0x17; 32]),
            },
        };
        let bytes = record.to_bytes().unwrap();
        assert_eq!(
            PersistedUsdomV2BlockRecord::from_bytes(&bytes).unwrap(),
            record
        );
        for end in 0..bytes.len() {
            assert!(PersistedUsdomV2BlockRecord::from_bytes(&bytes[..end]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(PersistedUsdomV2BlockRecord::from_bytes(&trailing).is_err());

        let tip_bytes = v2_runtime_tip_value(schedule, record).unwrap();
        let tip = PersistedUsdomV2RuntimeTip::from_bytes(&tip_bytes).unwrap();
        assert_eq!(tip.block_identifier, record.block_identifier);
        assert_eq!(tip.state, state);
        for end in 0..tip_bytes.len() {
            assert!(PersistedUsdomV2RuntimeTip::from_bytes(&tip_bytes[..end]).is_err());
        }
        let mut trailing_tip = tip_bytes;
        trailing_tip.push(0);
        assert!(PersistedUsdomV2RuntimeTip::from_bytes(&trailing_tip).is_err());
    }

    #[test]
    fn empty_v2_witness_bundle_and_sidecar_reject_all_noncanonical_lengths() {
        let witnesses = UsdomV2ExecutionWitnesses::new(Vec::new()).unwrap();
        let witness_bytes = witnesses.to_bytes().unwrap();
        assert!(UsdomV2ExecutionWitnesses::from_bytes(&witness_bytes).is_ok());
        for end in 0..witness_bytes.len() {
            assert!(UsdomV2ExecutionWitnesses::from_bytes(&witness_bytes[..end]).is_err());
        }
        let mut trailing_witnesses = witness_bytes;
        trailing_witnesses.push(0);
        assert!(UsdomV2ExecutionWitnesses::from_bytes(&trailing_witnesses).is_err());

        let sidecar = UsdomV2BlockSidecar::new(UsdomV4ProofEnvelope::empty(), witnesses).unwrap();
        let sidecar_bytes = sidecar.to_bytes().unwrap();
        assert!(UsdomV2BlockSidecar::from_bytes(&sidecar_bytes).is_ok());
        for end in 0..sidecar_bytes.len() {
            assert!(UsdomV2BlockSidecar::from_bytes(&sidecar_bytes[..end]).is_err());
        }
        let mut trailing_sidecar = sidecar_bytes;
        trailing_sidecar.push(0);
        assert!(UsdomV2BlockSidecar::from_bytes(&trailing_sidecar).is_err());
    }

    #[test]
    fn snapshot_manifest_roundtrips_and_rejects_ambiguous_inventory() {
        let tip = dom_core::Hash256::from_bytes([0x11; 32]);
        let parent = dom_core::Hash256::from_bytes([0x22; 32]);
        let manifest = NativeUsdomV4SnapshotManifest {
            network_magic: NETWORK_MAGIC_REGTEST,
            canonical_tip: tip,
            canonical_height: 1,
            state_root: dom_core::Hash256::from_bytes([0x33; 32]),
            state_entries_commitment: dom_core::Hash256::from_bytes([0x44; 32]),
            oldest_audited_parent: parent,
            boundary_state_root: dom_core::Hash256::from_bytes([0x55; 32]),
            reached_activation_boundary: true,
            activation_schedule_commitment: dom_core::Hash256::from_bytes([0x58; 32]),
            activation_record_commitment: dom_core::Hash256::from_bytes([0x59; 32]),
            checkpoint_floor_commitment: dom_core::Hash256::from_bytes([0x5a; 32]),
            blocks: vec![NativeUsdomV4SnapshotBlock {
                block_identifier: tip,
                height: 1,
                prev_hash: parent,
                package_commitment: dom_core::Hash256::from_bytes([0x66; 32]),
                undo_commitment: dom_core::Hash256::from_bytes([0x77; 32]),
                package_len: 512,
            }],
        };
        let bytes = manifest.to_bytes().unwrap();
        assert_eq!(
            bytes.len(),
            USDOM_V4_SNAPSHOT_HEADER_BYTES + USDOM_V4_SNAPSHOT_BLOCK_BYTES
        );
        assert_eq!(
            NativeUsdomV4SnapshotManifest::from_bytes(&bytes).unwrap(),
            manifest
        );
        assert_ne!(manifest.commitment().unwrap(), dom_core::Hash256::ZERO);

        for end in 0..bytes.len() {
            assert!(NativeUsdomV4SnapshotManifest::from_bytes(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(NativeUsdomV4SnapshotManifest::from_bytes(&trailing).is_err());
        let mut wrong_flag = bytes.clone();
        wrong_flag[190] = 2;
        assert!(NativeUsdomV4SnapshotManifest::from_bytes(&wrong_flag).is_err());
        let mut wrong_count = bytes.clone();
        wrong_count[191..195].copy_from_slice(&2u32.to_be_bytes());
        assert!(NativeUsdomV4SnapshotManifest::from_bytes(&wrong_count).is_err());
        let mut zero_schedule = bytes.clone();
        zero_schedule[195..227].fill(0);
        assert!(NativeUsdomV4SnapshotManifest::from_bytes(&zero_schedule).is_err());
        let mut zero_record = bytes.clone();
        zero_record[227..259].fill(0);
        assert!(NativeUsdomV4SnapshotManifest::from_bytes(&zero_record).is_err());
        let mut substituted_schedule = bytes.clone();
        substituted_schedule[195] ^= 1;
        assert_ne!(
            NativeUsdomV4SnapshotManifest::from_bytes(&substituted_schedule)
                .unwrap()
                .commitment()
                .unwrap(),
            manifest.commitment().unwrap()
        );
        let mut substituted_record = bytes.clone();
        substituted_record[227] ^= 1;
        assert_ne!(
            NativeUsdomV4SnapshotManifest::from_bytes(&substituted_record)
                .unwrap()
                .commitment()
                .unwrap(),
            manifest.commitment().unwrap()
        );
        let mut broken_parent = bytes;
        broken_parent[USDOM_V4_SNAPSHOT_HEADER_BYTES + 40] ^= 1;
        assert!(NativeUsdomV4SnapshotManifest::from_bytes(&broken_parent).is_err());

        // The transport is network-generic; authority comes from the exact
        // independently supplied schedule in the schedule-bound APIs.
        for network_magic in [
            dom_core::NETWORK_MAGIC_MAINNET,
            dom_core::NETWORK_MAGIC_TESTNET,
            dom_core::NETWORK_MAGIC_REGTEST,
        ] {
            let mut network_manifest = manifest.clone();
            network_manifest.network_magic = network_magic;
            let network_bytes = network_manifest.to_bytes().unwrap();
            assert_eq!(
                NativeUsdomV4SnapshotManifest::from_bytes(&network_bytes).unwrap(),
                network_manifest
            );
        }
        let mut unknown_network = manifest;
        unknown_network.network_magic = u32::MAX;
        assert!(unknown_network.to_bytes().is_err());
    }

    #[test]
    fn schedule_bound_snapshot_export_rejects_network_mismatch_before_store_access() {
        let directory = TempDir::new().unwrap();
        let store = DomStore::open_with_map_size(directory.path(), 64 << 20).unwrap();
        let schedule = NativeUsdomV4ActivationSchedule::new(
            dom_core::NETWORK_MAGIC_MAINNET,
            dom_core::Hash256::from_bytes([0x91; 32]),
            1,
            bridge(),
        )
        .unwrap();
        assert!(matches!(
            export_native_usdom_v4_snapshot_manifest_for_schedule(
                &store,
                dom_core::NETWORK_MAGIC_TESTNET,
                bridge(),
                dom_core::Hash256::from_bytes([0x92; 32]),
                schedule,
            ),
            Err(DomError::PolicyRejected(_))
        ));
    }

    #[test]
    fn canonical_envelope_roundtrips_and_rejects_ambiguous_framing() {
        let empty = UsdomV4ProofEnvelope::empty();
        let empty_bytes = empty.to_bytes().unwrap();
        assert_eq!(empty_bytes.len(), USDOM_V4_ENVELOPE_HEADER_BYTES);
        assert_eq!(
            UsdomV4ProofEnvelope::from_bytes(&empty_bytes).unwrap(),
            empty
        );

        let checkpoint = UsdomV4ProofEnvelope::checkpoint_witness(vec![0x5a; 168]).unwrap();
        let checkpoint_bytes = checkpoint.to_bytes().unwrap();
        assert_eq!(
            UsdomV4ProofEnvelope::from_bytes(&checkpoint_bytes).unwrap(),
            checkpoint
        );
        let closure = UsdomV4ProofEnvelope::issuance_closure_witness(vec![0x5b; 168]).unwrap();
        let closure_bytes = closure.to_bytes().unwrap();
        assert_eq!(
            UsdomV4ProofEnvelope::from_bytes(&closure_bytes).unwrap(),
            closure
        );
        assert_eq!(
            closure.entries().next().unwrap().0,
            UsdomV4ProofKind::IssuanceClosure
        );
        assert!(UsdomV4ProofEnvelope::issuance_closure_witness(vec![
            0;
            MAX_ISSUANCE_CLOSURE_WITNESS_BYTES
                + 1
        ])
        .is_err());
        assert!(validate_envelope_entries(&[
            UsdomV4ProofEntry {
                kind: UsdomV4ProofKind::IssuanceClosure,
                payload: vec![1]
            },
            UsdomV4ProofEntry {
                kind: UsdomV4ProofKind::IssuanceClosure,
                payload: vec![2]
            },
        ])
        .is_err());
        let transfer = UsdomV4ProofEnvelope::private_transfer_proof(vec![
            0x6a;
            MAX_PRIVATE_TRANSFER_PAYLOAD_BYTES
        ])
        .unwrap();
        assert_eq!(
            UsdomV4ProofEnvelope::from_bytes(&transfer.to_bytes().unwrap()).unwrap(),
            transfer
        );
        let observed = transfer.entries().collect::<Vec<_>>();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].0, UsdomV4ProofKind::Transfer);
        assert_eq!(observed[0].1.len(), MAX_PRIVATE_TRANSFER_PAYLOAD_BYTES);
        assert!(UsdomV4ProofEnvelope::private_transfer_proof(vec![
            0;
            MAX_PRIVATE_TRANSFER_PAYLOAD_BYTES
                + 1
        ])
        .is_err());
        assert!(UsdomV4ProofEnvelope::private_burn_proof(vec![
            0;
            MAX_PRIVATE_BURN_PAYLOAD_BYTES + 1
        ])
        .is_err());

        let burn_timestamp = 1_700_000_000;
        let mut burn_state = NativeUsdomState::new(bridge()).unwrap();
        burn_state
            .apply(
                BlockContext {
                    timestamp: burn_timestamp,
                },
                &issuance(),
            )
            .unwrap();
        let burn_transition = burn_from(&burn_state, burn_timestamp);
        let mut after_burn = burn_state.clone();
        after_burn
            .apply(
                BlockContext {
                    timestamp: burn_timestamp,
                },
                &burn_transition,
            )
            .unwrap();
        let burn_record = after_burn.burn_records()[0];
        let burn_payload = encode_private_burn_payload(
            burn_state.note_anchor(),
            &[[0x14; 32]],
            &[],
            burn_record,
            &[],
            &[0; 128],
        )
        .unwrap();
        let burn_envelope = UsdomV4ProofEnvelope::private_burn_proof(burn_payload.clone()).unwrap();
        assert_eq!(
            burn_envelope.public_burn_records().unwrap(),
            vec![burn_record]
        );
        assert!(empty.public_burn_records().unwrap().is_empty());
        let mut malformed_burn_payload = burn_payload;
        malformed_burn_payload[0] ^= 1;
        assert!(
            UsdomV4ProofEnvelope::private_burn_proof(malformed_burn_payload)
                .unwrap()
                .public_burn_records()
                .is_err()
        );

        for end in 0..USDOM_V4_ENVELOPE_HEADER_BYTES {
            assert!(UsdomV4ProofEnvelope::from_bytes(&empty_bytes[..end]).is_err());
        }
        let mut trailing = empty_bytes.clone();
        trailing.push(0);
        assert!(UsdomV4ProofEnvelope::from_bytes(&trailing).is_err());
        let mut wrong_magic = empty_bytes.clone();
        wrong_magic[0] ^= 1;
        assert!(UsdomV4ProofEnvelope::from_bytes(&wrong_magic).is_err());
        let mut wrong_version = empty_bytes.clone();
        wrong_version[9] = 2;
        assert!(UsdomV4ProofEnvelope::from_bytes(&wrong_version).is_err());
        assert!(UsdomV4ProofEnvelope::from_bytes(&envelope_bytes(0xff, &[1])).is_err());
        assert!(UsdomV4ProofEnvelope::from_bytes(&envelope_bytes(4, &[])).is_err());

        let mut oversized_count = empty_bytes;
        oversized_count[10..14]
            .copy_from_slice(&((MAX_TRANSITIONS_PER_BATCH as u32) + 1).to_be_bytes());
        assert!(UsdomV4ProofEnvelope::from_bytes(&oversized_count).is_err());

        let one_checkpoint = envelope_bytes(4, &[1]);
        let mut two_checkpoints = one_checkpoint[..10].to_vec();
        two_checkpoints.extend_from_slice(&2u32.to_be_bytes());
        two_checkpoints.extend_from_slice(&one_checkpoint[14..]);
        two_checkpoints.extend_from_slice(&one_checkpoint[14..]);
        assert!(UsdomV4ProofEnvelope::from_bytes(&two_checkpoints).is_err());

        let too_many_issuances = UsdomV4ProofEnvelope {
            entries: (0..=MAX_ISSUANCES_PER_ENVELOPE)
                .map(|_| UsdomV4ProofEntry {
                    kind: UsdomV4ProofKind::Issuance,
                    payload: vec![1],
                })
                .collect(),
        };
        assert!(too_many_issuances.to_bytes().is_err());
        let too_many_spends = UsdomV4ProofEnvelope {
            entries: (0..=MAX_PRIVATE_SPENDS_PER_ENVELOPE)
                .map(|_| UsdomV4ProofEntry {
                    kind: UsdomV4ProofKind::Transfer,
                    payload: vec![1],
                })
                .collect(),
        };
        assert!(too_many_spends.to_bytes().is_err());

        let duplicate_spend = UsdomV4ProofEnvelope {
            entries: vec![
                UsdomV4ProofEntry {
                    kind: UsdomV4ProofKind::Transfer,
                    payload: vec![1],
                },
                UsdomV4ProofEntry {
                    kind: UsdomV4ProofKind::Transfer,
                    payload: vec![1],
                },
            ],
        };
        assert!(duplicate_spend.to_bytes().is_err());
    }

    #[test]
    fn block_package_roundtrips_and_rejects_split_or_ambiguous_framing() {
        let state = NativeUsdomState::new(bridge()).unwrap();
        let (block, _) = candidate(&state, &[]);
        let bytes = package_bytes(block.clone(), UsdomV4ProofEnvelope::empty());
        if let Some(path) = std::env::var_os("DOM_USDOMBL4_CORPUS_OUT") {
            std::fs::write(path, &bytes).unwrap();
        }
        let decoded = UsdomV4BlockPackage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.block(), &block);
        assert_eq!(decoded.proof_envelope(), &UsdomV4ProofEnvelope::empty());
        assert_eq!(decoded.to_bytes().unwrap(), bytes);
        assert!(bytes.len() <= MAX_BLOCK_SERIALIZED_SIZE);

        assert!(UsdomV4BlockPackage::from_bytes(&DomSerialize::to_bytes(&block).unwrap()).is_err());
        // Every proper prefix must fail, including cuts inside the ordinary
        // block and proof envelope rather than only inside the outer header.
        for end in 0..bytes.len() {
            assert!(UsdomV4BlockPackage::from_bytes(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(UsdomV4BlockPackage::from_bytes(&trailing).is_err());
        let mut wrong_magic = bytes.clone();
        wrong_magic[0] ^= 1;
        assert!(UsdomV4BlockPackage::from_bytes(&wrong_magic).is_err());
        let mut wrong_version = bytes.clone();
        wrong_version[9] = 2;
        assert!(UsdomV4BlockPackage::from_bytes(&wrong_version).is_err());
        let mut wrong_block_len = bytes.clone();
        wrong_block_len[10..14].copy_from_slice(&1u32.to_be_bytes());
        assert!(UsdomV4BlockPackage::from_bytes(&wrong_block_len).is_err());
        let mut wrong_proof_len = bytes.clone();
        wrong_proof_len[14..18].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(UsdomV4BlockPackage::from_bytes(&wrong_proof_len).is_err());

        let mut legacy_version = block;
        legacy_version.header.version = 3;
        assert!(UsdomV4BlockPackage::new(legacy_version, UsdomV4ProofEnvelope::empty()).is_err());

        let oversized = vec![0; MAX_BLOCK_SERIALIZED_SIZE + 1];
        assert!(UsdomV4BlockPackage::from_bytes(&oversized).is_err());
    }

    #[test]
    fn history_private_payload_must_match_header_authenticated_effects() {
        let memo = b"encrypted wallet memo";
        let effects = dom_usdom_state::TransitionPublicEffects {
            kind: TransitionKind::Transfer,
            nullifiers: vec![[1; 32]],
            note_commitments: vec![[2; 32]],
            memo_commitment: Some(memo_scalar(memo).unwrap().to_bytes()),
        };
        validate_history_private_effects(&effects, &[[1; 32]], &[[2; 32]], memo).unwrap();
        assert!(validate_history_private_effects(&effects, &[[3; 32]], &[[2; 32]], memo).is_err());
        assert!(validate_history_private_effects(
            &effects,
            &[[1; 32]],
            &[[2; 32]],
            b"substituted memo"
        )
        .is_err());

        let exact_burn = dom_usdom_state::TransitionPublicEffects {
            kind: TransitionKind::Burn,
            nullifiers: vec![[4; 32]],
            note_commitments: Vec::new(),
            memo_commitment: Some([0; 32]),
        };
        validate_history_private_effects(&exact_burn, &[[4; 32]], &[], &[]).unwrap();
        assert!(
            validate_history_private_effects(&exact_burn, &[[4; 32]], &[], b"forbidden").is_err()
        );
    }

    #[test]
    fn public_serialized_path_accepts_empty_batch_and_rejects_invalid_proofs() {
        let state = NativeUsdomState::new(bridge()).unwrap();
        let (block, context) = candidate(&state, &[]);
        let schedule = native_usdom_v4_regtest_activation_schedule(bridge()).unwrap();
        assert_eq!(block.header.height.0, schedule.first_v4_height());
        assert_eq!(context.chain_id, *schedule.chain_id().as_bytes());
        let empty_package = package_bytes(block.clone(), UsdomV4ProofEnvelope::empty());
        let verified = verify_usdom_v4_serialized_candidate_regtest(
            &empty_package,
            &context,
            NETWORK_MAGIC_REGTEST,
            &state,
            bridge(),
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
        )
        .unwrap();
        assert_eq!(verified.receipt().transition_count, 0);
        assert_eq!(verified.next_state().state_root(), state.state_root());
        assert_eq!(
            verified.block_identifier(),
            crate::canonical_header_identifier(
                NETWORK_MAGIC_REGTEST,
                &DomSerialize::to_bytes(&block.header).unwrap(),
            )
            .unwrap()
        );
        assert_eq!(
            verified.package_commitment(),
            blake2b_256_tagged(TAG_USDOM_BLOCK_PACKAGE_V4, &empty_package)
        );
        assert_eq!(
            verified.package_commitment().to_string(),
            "813e84f1611eb1c0a0c22c9b5c15b5341feafc286f912a8e3bc07614e8c54161"
        );

        let mut substituted_package = empty_package.clone();
        let last = substituted_package.len() - 1;
        substituted_package[last] ^= 1;
        assert!(verify_usdom_v4_serialized_candidate_regtest(
            &substituted_package,
            &context,
            NETWORK_MAGIC_REGTEST,
            &state,
            bridge(),
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
        )
        .is_err());

        let unsupported = UsdomV4ProofEnvelope::from_bytes(&envelope_bytes(1, &[1])).unwrap();
        let unsupported_package = package_bytes(block.clone(), unsupported);
        assert!(matches!(
            verify_usdom_v4_serialized_candidate_regtest(
                &unsupported_package,
                &context,
                NETWORK_MAGIC_REGTEST,
                &state,
                bridge(),
                &unused_checkpoint_policy(),
                &unused_deposit_policy(),
                None,
            ),
            Err(DomError::Invalid(_))
        ));

        let mut wrong_bridge = bridge();
        wrong_bridge.dom_domain = [0x99; 32];
        assert!(verify_usdom_v4_serialized_candidate_regtest(
            &empty_package,
            &context,
            NETWORK_MAGIC_REGTEST,
            &state,
            wrong_bridge,
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
        )
        .is_err());
    }

    #[test]
    fn activation_schedule_is_canonical_height_and_bridge_bound() {
        let cross_language_bytes = hex::decode(
            "55444143545630310001444f4d31020202020202020202020202020202020202020202020202020202020202020200000000000186a04444444444444444444444444444444444444444444444444444444444444444",
        )
        .unwrap();
        let cross_language =
            NativeUsdomV4ActivationSchedule::from_bytes(&cross_language_bytes).unwrap();
        assert_eq!(
            cross_language.commitment().to_string(),
            "18e9a8c742efbc9601f49a16405a958a8b2e57da1f8691412ae8e0d7ac1fd4a4"
        );

        let bridge = bridge();
        let state = NativeUsdomState::new(bridge).unwrap();
        let schedule = native_usdom_v4_regtest_activation_schedule(bridge).unwrap();
        let bytes = schedule.to_bytes();
        assert_eq!(bytes.len(), USDOM_V4_ACTIVATION_SCHEDULE_BYTES);
        assert_eq!(
            NativeUsdomV4ActivationSchedule::from_bytes(&bytes).unwrap(),
            schedule
        );
        assert_ne!(schedule.commitment(), dom_core::Hash256::ZERO);
        assert_eq!(schedule.network_magic(), NETWORK_MAGIC_REGTEST);
        assert_eq!(schedule.first_v4_height(), 1);
        assert_eq!(schedule.empty_state_root(), state.state_root());

        let parent = dom_core::Hash256::from_bytes([0x91; 32]);
        assert!(
            native_usdom_v4_activation_updates_for_schedule(&state, schedule, parent, 0).is_ok()
        );
        assert!(
            native_usdom_v4_activation_updates_for_schedule(&state, schedule, parent, 1).is_err()
        );

        let mut changed = bytes.clone();
        changed[54] ^= 1;
        let wrong_root = NativeUsdomV4ActivationSchedule::from_bytes(&changed).unwrap();
        assert!(
            native_usdom_v4_activation_updates_for_schedule(&state, wrong_root, parent, 0).is_err()
        );
        assert!(NativeUsdomV4ActivationSchedule::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(NativeUsdomV4ActivationSchedule::from_bytes(&trailing).is_err());

        let v2 = NativeUsdomV2ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            schedule.chain_id(),
            2,
            parent,
            &state,
        )
        .unwrap();
        let v2_bytes = v2.to_bytes();
        assert_eq!(v2_bytes.len(), USDOM_V2_ACTIVATION_SCHEDULE_BYTES);
        assert_eq!(
            NativeUsdomV2ActivationSchedule::from_bytes(&v2_bytes).unwrap(),
            v2
        );
        assert_eq!(v2.activation_parent(), parent);
        assert_eq!(v2.previous_v1_state_root(), state.state_root());
        assert_eq!(
            v2.initial_v2_state_root(),
            state.state_commitment_v2().unwrap().root()
        );
        assert_ne!(v2.commitment(), schedule.commitment());
        for index in [11usize, 13] {
            let mut wrong = v2_bytes;
            wrong[index] ^= 1;
            assert!(NativeUsdomV2ActivationSchedule::from_bytes(&wrong).is_err());
        }
    }

    #[test]
    fn v2_activation_snapshot_survives_restart_and_partial_markers_fail_closed() {
        let bridge = bridge();
        let mut state = NativeUsdomState::new(bridge).unwrap();
        state
            .apply_batch(
                BlockContext {
                    timestamp: 1_800_000_000,
                },
                &[issuance()],
            )
            .unwrap();
        let genesis =
            dom_core::configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST).unwrap();
        let chain_id = dom_consensus::derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis);
        let parent = dom_core::Hash256::from_bytes([0x91; 32]);
        let v1_schedule =
            NativeUsdomV4ActivationSchedule::new(NETWORK_MAGIC_REGTEST, chain_id, 1, bridge)
                .unwrap();
        let v2_schedule = NativeUsdomV2ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            chain_id,
            11,
            parent,
            &state,
        )
        .unwrap();
        let mut updates: Vec<_> = state
            .export_entries()
            .into_iter()
            .map(|(key, value)| ConsensusStateUpdate {
                key,
                value: Some(value),
            })
            .collect();
        updates.push(ConsensusStateUpdate {
            key: USDOM_V4_ACTIVATION_KEY.to_vec(),
            value: Some(activation_record(v1_schedule, genesis).unwrap()),
        });
        updates.push(ConsensusStateUpdate {
            key: USDOM_V4_TIP_KEY.to_vec(),
            value: Some(tip_value(
                parent,
                state.state_root(),
                dom_core::Hash256::from_bytes([0x92; 32]),
            )),
        });
        updates
            .extend(native_usdom_v2_activation_updates(&state, v2_schedule, parent, 10).unwrap());

        let directory = TempDir::new().unwrap();
        let path = directory.path().to_path_buf();
        let store = DomStore::open_with_map_size(&path, 64 << 20).unwrap();
        store
            .commit_block_with_consensus_state(
                parent.as_bytes(),
                10,
                b"v2-activation-parent-header",
                b"v2-activation-parent-body",
                &[],
                &[],
                &[],
                &updates,
            )
            .unwrap();
        let expected_v2 = state.state_commitment_v2().unwrap();
        assert_eq!(
            restore_persisted_usdom_v2_activation(
                &store,
                NETWORK_MAGIC_REGTEST,
                parent,
                bridge,
                v2_schedule,
            )
            .unwrap(),
            expected_v2
        );
        drop(store);

        let reopened = DomStore::open_with_map_size(&path, 64 << 20).unwrap();
        assert_eq!(
            restore_persisted_usdom_v2_activation(
                &reopened,
                NETWORK_MAGIC_REGTEST,
                parent,
                bridge,
                v2_schedule,
            )
            .unwrap(),
            expected_v2
        );
        let mut substituted = v2_activation_tip_value(v2_schedule);
        substituted[64] ^= 1;
        reopened
            .apply_reorg_with_consensus_state(
                parent.as_bytes(),
                &[],
                &[],
                &[],
                &[ConsensusStateUpdate {
                    key: USDOM_V2_TIP_KEY.to_vec(),
                    value: Some(substituted),
                }],
            )
            .unwrap();
        assert!(restore_persisted_usdom_v2_activation(
            &reopened,
            NETWORK_MAGIC_REGTEST,
            parent,
            bridge,
            v2_schedule,
        )
        .is_err());
        reopened
            .apply_reorg_with_consensus_state(
                parent.as_bytes(),
                &[],
                &[],
                &[],
                &[ConsensusStateUpdate {
                    key: USDOM_V2_ACTIVATION_KEY.to_vec(),
                    value: None,
                }],
            )
            .unwrap();
        assert!(restore_persisted_usdom_v2_activation(
            &reopened,
            NETWORK_MAGIC_REGTEST,
            parent,
            bridge,
            v2_schedule,
        )
        .is_err());
    }

    #[test]
    fn scheduled_mainnet_activation_state_audits_and_rewinds_without_regtest_authority() {
        let bridge = bridge();
        let state = NativeUsdomState::new(bridge).unwrap();
        let genesis =
            dom_core::configured_genesis_hash_for_network_magic(NETWORK_MAGIC_MAINNET).unwrap();
        let chain_id = dom_consensus::derive_chain_id(NETWORK_MAGIC_MAINNET, &genesis);
        let canonical =
            build_canonical_genesis(NETWORK_MAGIC_MAINNET, chain_id.as_bytes()).unwrap();
        assert_eq!(canonical.hash, genesis);
        let schedule =
            NativeUsdomV4ActivationSchedule::new(NETWORK_MAGIC_MAINNET, chain_id, 1, bridge)
                .unwrap();
        let updates =
            native_usdom_v4_activation_updates_for_schedule(&state, schedule, canonical.hash, 0)
                .unwrap();
        let directory = TempDir::new().unwrap();
        let store = DomStore::open_with_map_size(directory.path(), 64 << 20).unwrap();
        store
            .commit_block_with_consensus_state(
                canonical.hash.as_bytes(),
                0,
                &canonical.header_bytes,
                &canonical.block_bytes,
                &[],
                &[],
                &[],
                &updates,
            )
            .unwrap();

        let restored = restore_persisted_usdom_v4_state_for_schedule(
            &store,
            NETWORK_MAGIC_MAINNET,
            bridge,
            canonical.hash,
            schedule,
        )
        .unwrap();
        assert_eq!(restored.state_root(), state.state_root());
        let audit = audit_persisted_usdom_v4_reorg_window_for_schedule(
            &store,
            NETWORK_MAGIC_MAINNET,
            bridge,
            canonical.hash,
            schedule,
        )
        .unwrap();
        assert_eq!(audit.audited_blocks, 0);
        assert!(audit.reached_activation_boundary);
        assert_eq!(audit.oldest_audited_parent, canonical.hash);
        assert_eq!(audit.boundary_state_root, state.state_root());
        assert_eq!(
            rewind_persisted_usdom_v4_state_to_ancestor_for_schedule(
                &store,
                NETWORK_MAGIC_MAINNET,
                bridge,
                canonical.hash,
                canonical.hash,
                schedule,
            )
            .unwrap()
            .state_root(),
            state.state_root()
        );

        let wrong_height =
            NativeUsdomV4ActivationSchedule::new(NETWORK_MAGIC_MAINNET, chain_id, 2, bridge)
                .unwrap();
        assert!(audit_persisted_usdom_v4_reorg_window_for_schedule(
            &store,
            NETWORK_MAGIC_MAINNET,
            bridge,
            canonical.hash,
            wrong_height,
        )
        .is_err());
        assert!(audit_persisted_usdom_v4_reorg_window(
            &store,
            NETWORK_MAGIC_MAINNET,
            bridge,
            canonical.hash,
        )
        .is_err());
    }

    #[test]
    fn activation_marker_and_schedule_record_are_an_atomic_pair() {
        let state = NativeUsdomState::new(bridge()).unwrap();
        let parent = dom_core::Hash256::from_bytes([0x92; 32]);
        let updates = native_usdom_v4_activation_updates(&state, parent).unwrap();

        for omitted_key in [USDOM_V4_TIP_KEY, USDOM_V4_ACTIVATION_KEY] {
            let directory = TempDir::new().unwrap();
            let store = DomStore::open_with_map_size(directory.path(), 64 << 20).unwrap();
            let incomplete = updates
                .iter()
                .filter(|update| update.key.as_slice() != omitted_key)
                .cloned()
                .collect::<Vec<_>>();
            store
                .commit_block_with_consensus_state(
                    parent.as_bytes(),
                    0,
                    b"activation-header",
                    b"activation-body",
                    &[],
                    &[],
                    &[],
                    &incomplete,
                )
                .unwrap();
            assert!(native_usdom_v4_activation_tip(&store).is_err());
        }

        let directory = TempDir::new().unwrap();
        let store = DomStore::open_with_map_size(directory.path(), 64 << 20).unwrap();
        let mut corrupt = updates;
        corrupt
            .iter_mut()
            .find(|update| update.key == USDOM_V4_ACTIVATION_KEY)
            .unwrap()
            .value
            .as_mut()
            .unwrap()[0] ^= 1;
        store
            .commit_block_with_consensus_state(
                parent.as_bytes(),
                0,
                b"activation-header",
                b"activation-body",
                &[],
                &[],
                &[],
                &corrupt,
            )
            .unwrap();
        assert!(native_usdom_v4_activation_tip(&store).is_err());
    }

    #[test]
    fn verified_capability_persists_and_reconstructs_exact_package_atomically() {
        let state = NativeUsdomState::new(bridge()).unwrap();
        assert!(native_usdom_v4_activation_updates(&state, dom_core::Hash256::ZERO).is_err());
        let mut nonempty = state.clone();
        nonempty
            .apply_batch(
                BlockContext {
                    timestamp: 1_800_000_000,
                },
                &[issuance()],
            )
            .unwrap();
        assert!(native_usdom_v4_activation_updates(
            &nonempty,
            dom_core::Hash256::from_bytes([0x9f; 32]),
        )
        .is_err());
        let activation_block = dom_core::Hash256::from_bytes([0xa0; 32]);
        let (block, context) = candidate_after_activation(&state, &[], activation_block);
        let package_bytes = package_bytes(block.clone(), UsdomV4ProofEnvelope::empty());
        let verified = verify_usdom_v4_serialized_candidate_regtest(
            &package_bytes,
            &context,
            NETWORK_MAGIC_REGTEST,
            &state,
            bridge(),
            &unused_checkpoint_policy(),
            &unused_deposit_policy(),
            None,
        )
        .unwrap();
        let updates = verified
            .consensus_state_updates(&state, &package_bytes)
            .unwrap();
        let mut substituted = package_bytes.clone();
        substituted[0] ^= 1;
        assert!(verified
            .consensus_state_updates(&state, &substituted)
            .is_err());

        let dir = TempDir::new().unwrap();
        let store = DomStore::open_with_map_size(dir.path(), 64 << 20).unwrap();
        let activation_updates =
            native_usdom_v4_activation_updates(&state, activation_block).unwrap();
        store
            .commit_block_with_consensus_state(
                activation_block.as_bytes(),
                0,
                b"activation-header",
                b"activation-body",
                &[],
                &[],
                &[],
                &activation_updates,
            )
            .unwrap();
        store
            .commit_block_with_consensus_state(
                verified.block_identifier().as_bytes(),
                block.header.height.0,
                &DomSerialize::to_bytes(&block.header).unwrap(),
                &DomSerialize::to_bytes(&block).unwrap(),
                &[],
                &[],
                &[],
                &updates,
            )
            .unwrap();

        assert_eq!(
            load_persisted_usdom_v4_package(
                &store,
                NETWORK_MAGIC_REGTEST,
                verified.block_identifier(),
            )
            .unwrap(),
            Some(package_bytes)
        );
        let history = load_authenticated_usdom_v4_history_block(
            &store,
            NETWORK_MAGIC_REGTEST,
            bridge().dom_domain,
            verified.block_identifier(),
        )
        .unwrap();
        assert_eq!(history.block_identifier, verified.block_identifier());
        assert_eq!(history.height, block.header.height.0);
        assert_eq!(history.previous_block_identifier, block.header.prev_hash);
        assert_eq!(history.block_timestamp, block.header.timestamp.0);
        assert_eq!(history.previous_state_root, state.state_root());
        assert_eq!(history.new_state_root, verified.next_state().state_root());
        assert_eq!(
            history.transitions_root,
            verified.receipt().transitions_root
        );
        assert_eq!(
            history.batch_header_commitment,
            verified.receipt().header_commitment
        );
        assert!(history.transitions.is_empty());
        let mut wrong_domain = bridge().dom_domain;
        wrong_domain[0] ^= 1;
        assert!(load_authenticated_usdom_v4_history_block(
            &store,
            NETWORK_MAGIC_REGTEST,
            wrong_domain,
            verified.block_identifier(),
        )
        .is_err());
        let persisted_entries = store
            .read_all_consensus_state_raw()
            .unwrap()
            .into_iter()
            .filter(|(key, _)| key.starts_with(b"usdom/v3/"))
            .collect();
        assert_eq!(
            NativeUsdomState::restore_entries(bridge(), &persisted_entries)
                .unwrap()
                .state_root(),
            verified.next_state().state_root()
        );
        assert_eq!(
            restore_persisted_usdom_v4_state(
                &store,
                NETWORK_MAGIC_REGTEST,
                bridge(),
                verified.block_identifier(),
            )
            .unwrap()
            .state_root(),
            verified.next_state().state_root()
        );
        let wrong_schedule = NativeUsdomV4ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            native_usdom_v4_regtest_activation_schedule(bridge())
                .unwrap()
                .chain_id(),
            2,
            bridge(),
        )
        .unwrap();
        assert!(restore_persisted_usdom_v4_state_for_schedule(
            &store,
            NETWORK_MAGIC_REGTEST,
            bridge(),
            verified.block_identifier(),
            wrong_schedule,
        )
        .is_err());
        assert!(restore_persisted_usdom_v4_state(
            &store,
            NETWORK_MAGIC_REGTEST,
            bridge(),
            activation_block,
        )
        .is_err());

        store
            .apply_reorg_with_consensus_state(
                verified.block_identifier().as_bytes(),
                &[],
                &[],
                &[],
                &[ConsensusStateUpdate {
                    key: package_chunk_key(verified.block_identifier(), 0),
                    value: Some(vec![0; USDOM_V4_ENVELOPE_HEADER_BYTES]),
                }],
            )
            .unwrap();
        assert!(load_persisted_usdom_v4_package(
            &store,
            NETWORK_MAGIC_REGTEST,
            verified.block_identifier(),
        )
        .is_err());
        assert!(restore_persisted_usdom_v4_state(
            &store,
            NETWORK_MAGIC_REGTEST,
            bridge(),
            verified.block_identifier(),
        )
        .is_err());
    }

    #[test]
    fn canonical_burn_prover_input_binds_audited_tip_block_batch_and_state() {
        let activation = build_canonical_genesis(NETWORK_MAGIC_REGTEST, &[0; 32])
            .unwrap()
            .block
            .unwrap();
        let activation_header_bytes = DomSerialize::to_bytes(&activation.header).unwrap();
        let activation_block =
            crate::canonical_header_identifier(NETWORK_MAGIC_REGTEST, &activation_header_bytes)
                .unwrap();
        let state = NativeUsdomState::new(bridge()).unwrap();
        let block_timestamp = activation.header.timestamp.0;
        let issue = issuance_at(block_timestamp);
        let mut after_issue = state.clone();
        after_issue
            .apply_batch(
                BlockContext {
                    timestamp: block_timestamp,
                },
                std::slice::from_ref(&issue),
            )
            .unwrap();
        let burn_id = dom_usdom_state::derive_private_burn_id(
            bridge(),
            &[[0x14; 32]],
            [0x73; 20],
            250_000,
            block_timestamp + 100_000,
        )
        .unwrap();
        let burn = burn_from(&after_issue, block_timestamp);
        let transitions = vec![issue, burn];
        let (block, context) = candidate_after_activation(&state, &transitions, activation_block);
        let prepared = verify_usdom_v4_candidate_regtest(
            &block,
            &context,
            NETWORK_MAGIC_REGTEST,
            &state,
            &transitions,
        )
        .unwrap();
        let envelope = UsdomV4ProofEnvelope {
            entries: vec![
                UsdomV4ProofEntry {
                    kind: UsdomV4ProofKind::Issuance,
                    payload: vec![0x81],
                },
                UsdomV4ProofEntry {
                    kind: UsdomV4ProofKind::Burn,
                    payload: vec![0x82],
                },
            ],
        };
        let package_blob = package_bytes(block.clone(), envelope);
        let block_identifier = crate::canonical_header_identifier(
            NETWORK_MAGIC_REGTEST,
            &DomSerialize::to_bytes(&block.header).unwrap(),
        )
        .unwrap();
        let verified = VerifiedUsdomV4Candidate {
            network_magic: NETWORK_MAGIC_REGTEST,
            block_identifier,
            package_commitment: blake2b_256_tagged(TAG_USDOM_BLOCK_PACKAGE_V4, &package_blob),
            next_state: prepared.next_state,
            receipt: prepared.receipt,
            undo: prepared.undo,
            verified_checkpoint: None,
        };
        let updates = verified
            .consensus_state_updates(&state, &package_blob)
            .unwrap();

        let dir = TempDir::new().unwrap();
        let store = DomStore::open_with_map_size(dir.path(), 128 << 20).unwrap();
        store
            .commit_block_with_consensus_state(
                activation_block.as_bytes(),
                activation.header.height.0,
                &activation_header_bytes,
                &DomSerialize::to_bytes(&activation).unwrap(),
                &[],
                &[],
                &[],
                &native_usdom_v4_activation_updates(&state, activation_block).unwrap(),
            )
            .unwrap();
        store
            .commit_block_with_consensus_state(
                block_identifier.as_bytes(),
                block.header.height.0,
                &DomSerialize::to_bytes(&block.header).unwrap(),
                &DomSerialize::to_bytes(&block).unwrap(),
                &[],
                &[],
                &[],
                &updates,
            )
            .unwrap();

        let schedule = native_usdom_v4_regtest_activation_schedule(bridge()).unwrap();
        let input = export_native_usdom_v4_burn_block_prover_input(
            &store,
            NETWORK_MAGIC_REGTEST,
            bridge(),
            block_identifier,
            burn_id,
        )
        .unwrap();
        let scheduled_input = export_native_usdom_v4_burn_block_prover_input_for_schedule(
            &store,
            NETWORK_MAGIC_REGTEST,
            bridge(),
            block_identifier,
            burn_id,
            schedule,
        )
        .unwrap();
        assert_eq!(scheduled_input, input);
        assert!(export_native_usdom_v4_burn_block_prover_input_for_schedule(
            &store,
            NETWORK_MAGIC_MAINNET,
            bridge(),
            block_identifier,
            burn_id,
            schedule,
        )
        .is_err());
        let wrong_chain_schedule = NativeUsdomV4ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            Hash256::from_bytes([0xa7; 32]),
            schedule.first_v4_height(),
            bridge(),
        )
        .unwrap();
        assert!(export_native_usdom_v4_burn_block_prover_input_for_schedule(
            &store,
            NETWORK_MAGIC_REGTEST,
            bridge(),
            block_identifier,
            burn_id,
            wrong_chain_schedule,
        )
        .is_err());
        let wrong_height_schedule = NativeUsdomV4ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            schedule.chain_id(),
            schedule.first_v4_height() + 1,
            bridge(),
        )
        .unwrap();
        assert!(export_native_usdom_v4_burn_block_prover_input_for_schedule(
            &store,
            NETWORK_MAGIC_REGTEST,
            bridge(),
            block_identifier,
            burn_id,
            wrong_height_schedule,
        )
        .is_err());
        let binding = input.verify(schedule, block_identifier).unwrap();
        assert_eq!(binding.chain_id, schedule.chain_id());
        assert_eq!(binding.first_v4_height, schedule.first_v4_height());
        assert_eq!(
            binding.activation_empty_state_root,
            schedule.empty_state_root()
        );
        assert_eq!(
            binding.activation_schedule_commitment,
            schedule.commitment()
        );
        assert_eq!(binding.block_height, 1);
        assert_eq!(binding.block_timestamp, block_timestamp);
        assert_eq!(binding.state_root, verified.next_state().state_root());
        assert_eq!(
            binding.batch_header_commitment,
            verified.receipt().header_commitment
        );
        assert_eq!(binding.package_commitment, verified.package_commitment());
        assert_eq!(binding.burn.burn_id, burn_id);
        assert_eq!(binding.burn.request_id, [0x72; 32]);

        let checkpoint_record = checkpoint_record_for(binding);
        let checkpoint = unsafe_test_only_verified_checkpoint(
            checkpoint_record,
            block_timestamp + 120,
            binding.ethereum_checkpoint_policy_hash.into(),
        );
        let finality_binding = bind_verified_ethereum_checkpoint_to_native_burn(
            &input,
            schedule,
            block_identifier,
            &checkpoint,
        )
        .unwrap();
        assert_eq!(finality_binding.native, binding);
        assert_eq!(
            finality_binding.checkpoint_event_execution_block,
            20_000_010
        );
        assert_eq!(finality_binding.checkpoint_transaction_index, 7);
        assert_eq!(finality_binding.checkpoint_receipt_log_index, 3);
        assert_eq!(finality_binding.ethereum_finality_beacon_slot, 16_000_010);
        assert_eq!(
            finality_binding.checkpoint_event_digest,
            Hash256::from_bytes(checkpoint_record[385..417].try_into().unwrap())
        );
        let statement = FinalizedBurnStatement::from_checkpoint_binding(&finality_binding).unwrap();
        assert_eq!(statement.burn_id, binding.burn.burn_id);
        assert_eq!(statement.request_id, binding.burn.request_id);
        assert_eq!(statement.block_hash, binding.block_identifier);
        assert_eq!(statement.state_root, binding.state_root);
        assert_eq!(
            statement.finality_beacon_slot,
            finality_binding.ethereum_finality_beacon_slot
        );
        assert_eq!(
            statement.activation_schedule_commitment,
            schedule.commitment()
        );
        assert_ne!(statement.statement_hash(), Hash256::ZERO);
        let mut substituted_reserve = finality_binding;
        substituted_reserve.native.reserve[0] ^= 1;
        assert!(FinalizedBurnStatement::from_checkpoint_binding(&substituted_reserve).is_err());
        let mut substituted_obligation = finality_binding;
        substituted_obligation.native.burn.obligation_commitment[0] ^= 1;
        assert!(FinalizedBurnStatement::from_checkpoint_binding(&substituted_obligation).is_err());

        for range in [9..41, 41..73, 73..77, 77..85, 229..261, 353..385] {
            let mut substituted = checkpoint_record;
            substituted[range.start] ^= 1;
            let substituted = unsafe_test_only_verified_checkpoint(
                substituted,
                block_timestamp + 120,
                binding.ethereum_checkpoint_policy_hash.into(),
            );
            assert!(bind_verified_ethereum_checkpoint_to_native_burn(
                &input,
                schedule,
                block_identifier,
                &substituted,
            )
            .is_err());
        }
        let wrong_policy = unsafe_test_only_verified_checkpoint(
            checkpoint_record,
            block_timestamp + 120,
            [0xa9; 32].into(),
        );
        assert!(bind_verified_ethereum_checkpoint_to_native_burn(
            &input,
            schedule,
            block_identifier,
            &wrong_policy,
        )
        .is_err());

        let encoded = input.to_bytes().unwrap();
        assert!(encoded.len() <= MAX_NATIVE_BURN_BLOCK_PROVER_INPUT_BYTES);
        assert_eq!(
            NativeBurnBlockProverInput::from_bytes(&encoded).unwrap(),
            input
        );
        assert!(input
            .verify(wrong_chain_schedule, block_identifier)
            .is_err());
        assert!(input
            .verify(schedule, Hash256::from_bytes([0x91; 32]))
            .is_err());
        assert!(export_native_usdom_v4_burn_block_prover_input(
            &store,
            NETWORK_MAGIC_REGTEST,
            bridge(),
            block_identifier,
            [0x92; 32],
        )
        .is_err());

        for end in 0..USDOM_V4_BURN_PROVER_HEADER_BYTES {
            assert!(NativeBurnBlockProverInput::from_bytes(&encoded[..end]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(NativeBurnBlockProverInput::from_bytes(&trailing).is_err());
        let mut wrong_magic = encoded.clone();
        wrong_magic[0] ^= 1;
        assert!(NativeBurnBlockProverInput::from_bytes(&wrong_magic).is_err());
        let mut wrong_version = encoded.clone();
        wrong_version[9] ^= 1;
        assert!(NativeBurnBlockProverInput::from_bytes(&wrong_version).is_err());
        let mut substituted_chain = encoded.clone();
        substituted_chain[10 + 14] ^= 1;
        assert!(NativeBurnBlockProverInput::from_bytes(&substituted_chain).is_err());
        let mut wrong_activation_root = encoded.clone();
        wrong_activation_root[10 + 54] ^= 1;
        assert!(NativeBurnBlockProverInput::from_bytes(&wrong_activation_root).is_err());
        let mut wrong_package = encoded.clone();
        wrong_package[USDOM_V4_BURN_PROVER_HEADER_BYTES] ^= 1;
        assert!(NativeBurnBlockProverInput::from_bytes(&wrong_package).is_err());
        let undo_offset = USDOM_V4_BURN_PROVER_HEADER_BYTES + input.package_bytes().len();
        let mut wrong_undo = encoded.clone();
        wrong_undo[undo_offset] ^= 1;
        assert!(NativeBurnBlockProverInput::from_bytes(&wrong_undo).is_err());
        let witness_offset = undo_offset + input.undo_bytes().len();
        let mut wrong_witness = encoded.clone();
        wrong_witness[witness_offset] ^= 1;
        assert!(NativeBurnBlockProverInput::from_bytes(&wrong_witness).is_err());

        let mut body_root_mismatch = block.clone();
        body_root_mismatch.header.output_root = Hash256::from_bytes([0x93; 32]);
        let body_root_mismatch_id = crate::canonical_header_identifier(
            NETWORK_MAGIC_REGTEST,
            &DomSerialize::to_bytes(&body_root_mismatch.header).unwrap(),
        )
        .unwrap();
        let body_root_mismatch_package = package_bytes(
            body_root_mismatch,
            UsdomV4ProofEnvelope {
                entries: vec![
                    UsdomV4ProofEntry {
                        kind: UsdomV4ProofKind::Issuance,
                        payload: vec![0x81],
                    },
                    UsdomV4ProofEntry {
                        kind: UsdomV4ProofKind::Burn,
                        payload: vec![0x82],
                    },
                ],
            },
        );
        assert!(NativeBurnBlockProverInput::new(
            schedule,
            body_root_mismatch_id,
            body_root_mismatch_package,
            input.undo_bytes().to_vec(),
            input.burn_witness_bytes().to_vec(),
        )
        .is_err());

        let count_mismatch_package = package_bytes(block, UsdomV4ProofEnvelope::empty());
        assert!(NativeBurnBlockProverInput::new(
            schedule,
            block_identifier,
            count_mismatch_package,
            input.undo_bytes().to_vec(),
            input.burn_witness_bytes().to_vec(),
        )
        .is_err());

        let (installed, installed_checkpoint) = install_verified_native_burn_checkpoint(
            &store,
            NETWORK_MAGIC_REGTEST,
            binding.block_height,
            &input,
            &checkpoint,
        )
        .unwrap();
        assert_eq!(installed, finality_binding);
        assert_eq!(installed_checkpoint.dom_block, block_identifier);
        assert_eq!(
            crate::ethereum_checkpoint_poc::load(&store)
                .unwrap()
                .unwrap()
                .dom_block,
            block_identifier
        );
    }

    #[test]
    fn checkpoint_policy_is_tied_to_dom_time_and_invalid_witness_has_no_authority() {
        let block_timestamp = build_canonical_genesis(NETWORK_MAGIC_REGTEST, &[0; 32])
            .unwrap()
            .block
            .unwrap()
            .header
            .timestamp
            .0;
        let mut bridge = ethereum_mainnet_bridge();
        let policy = checkpoint_policy_for(bridge, block_timestamp);
        let static_policy = StaticCheckpointTrustPolicy::from_trust_policy(&policy).unwrap();
        assert_eq!(
            ethereum_checkpoint_policy_hash(&policy).to_string(),
            "e7b8afd550a914ba7c59cd44211456e56a7f4644903daa110bd9a7f86f2036e3"
        );
        bridge.ethereum_checkpoint_policy_hash =
            *ethereum_checkpoint_policy_hash(&policy).as_bytes();
        let state = NativeUsdomState::new(bridge).unwrap();
        let (block, context) = candidate(&state, &[]);
        assert_eq!(block.header.timestamp.0, block_timestamp);
        let derived = checkpoint_policy_for_dom_block(
            NETWORK_MAGIC_REGTEST,
            block.header.timestamp.0,
            bridge,
            &static_policy,
        )
        .unwrap();
        assert_eq!(derived.max_current_slot, policy.max_current_slot);

        let mut wrong_slot = policy.clone();
        wrong_slot.max_current_slot += 1;
        assert_eq!(
            ethereum_checkpoint_policy_hash(&wrong_slot),
            ethereum_checkpoint_policy_hash(&policy)
        );
        let frozen_wrong_slot =
            StaticCheckpointTrustPolicy::from_trust_policy(&wrong_slot).unwrap();
        assert_eq!(
            checkpoint_policy_for_dom_block(
                NETWORK_MAGIC_REGTEST,
                block.header.timestamp.0,
                bridge,
                &frozen_wrong_slot,
            )
            .unwrap()
            .max_current_slot,
            policy.max_current_slot
        );

        let mut wrong_registry = policy.clone();
        wrong_registry.checkpoint.registry = [0x99; 20].into();
        assert_ne!(
            ethereum_checkpoint_policy_hash(&wrong_registry),
            ethereum_checkpoint_policy_hash(&policy)
        );
        let frozen_wrong_registry =
            StaticCheckpointTrustPolicy::from_trust_policy(&wrong_registry).unwrap();
        assert!(checkpoint_policy_for_dom_block(
            NETWORK_MAGIC_REGTEST,
            block.header.timestamp.0,
            bridge,
            &frozen_wrong_registry,
        )
        .is_err());

        let envelope = UsdomV4ProofEnvelope::checkpoint_witness(vec![0; 168]).unwrap();
        let package = package_bytes(block, envelope);
        let before = state.state_root();
        assert!(verify_usdom_v4_serialized_candidate_regtest(
            &package,
            &context,
            NETWORK_MAGIC_REGTEST,
            &state,
            bridge,
            &static_policy,
            &unused_deposit_policy(),
            None,
        )
        .is_err());
        assert_eq!(state.state_root(), before);
    }

    #[test]
    fn deposit_policy_is_committed_to_bridge_and_dom_time() {
        let bridge = ethereum_mainnet_bridge();
        let policy = unused_deposit_policy();
        validate_static_deposit_policy_identity(bridge, &policy).unwrap();
        let block_timestamp = ETHEREUM_MAINNET_GENESIS_TIME + 12 * 100;
        let derived =
            deposit_policy_for_dom_block(NETWORK_MAGIC_REGTEST, block_timestamp, bridge, &policy)
                .unwrap();
        assert_eq!(derived.max_current_slot, 100);

        let mut wrong_hash = bridge;
        wrong_hash.ethereum_deposit_policy_hash[0] ^= 1;
        assert!(validate_static_deposit_policy_identity(wrong_hash, &policy).is_err());

        let wrong_reserve = StaticDepositTrustPolicy::from_trust_policy(&DepositTrustPolicy {
            trusted_checkpoint: [0x41; 32].into(),
            ethereum_genesis_validators_root: [0x22; 32].into(),
            forks: supported_forks(),
            max_current_slot: 1,
            deposit: ReserveDepositPolicy {
                ethereum_chain_id: 1,
                ethereum_genesis_validators_root: [0x22; 32].into(),
                reserve: [0x99; 20].into(),
                runtime_code_hash: [0x46; 32].into(),
                bridge_domain: DOMAIN.into(),
                max_amount: 100_000_000_000,
            },
        })
        .unwrap();
        assert!(validate_static_deposit_policy_identity(bridge, &wrong_reserve).is_err());
        assert!(deposit_policy_for_dom_block(
            NETWORK_MAGIC_REGTEST,
            ETHEREUM_MAINNET_GENESIS_TIME - 1,
            bridge,
            &policy,
        )
        .is_err());
    }

    proptest! {
        #[test]
        fn arbitrary_envelope_bytes_never_gain_noncanonical_roundtrip_authority(
            bytes in proptest::collection::vec(any::<u8>(), 0..4096)
        ) {
            if let Ok(envelope) = UsdomV4ProofEnvelope::from_bytes(&bytes) {
                prop_assert_eq!(envelope.to_bytes().unwrap(), bytes);
            }
        }

        #[test]
        fn arbitrary_block_package_bytes_never_gain_noncanonical_roundtrip_authority(
            bytes in proptest::collection::vec(any::<u8>(), 0..4096)
        ) {
            if let Ok(package) = UsdomV4BlockPackage::from_bytes(&bytes) {
                prop_assert_eq!(package.to_bytes().unwrap(), bytes);
            }
        }

        #[test]
        fn arbitrary_snapshot_manifest_bytes_never_gain_noncanonical_roundtrip_authority(
            bytes in proptest::collection::vec(any::<u8>(), 0..4096)
        ) {
            if let Ok(manifest) = NativeUsdomV4SnapshotManifest::from_bytes(&bytes) {
                prop_assert_eq!(manifest.to_bytes().unwrap(), bytes);
            }
        }

        #[test]
        fn arbitrary_v2_persistence_bytes_never_gain_noncanonical_roundtrip_authority(
            bytes in proptest::collection::vec(any::<u8>(), 0..4096)
        ) {
            if let Ok(record) = PersistedUsdomV2BlockRecord::from_bytes(&bytes) {
                let canonical = record.to_bytes().unwrap();
                prop_assert_eq!(canonical.as_slice(), bytes.as_slice());
            }
            // The fixed-width runtime-tip decoder is included for panic and
            // bounds coverage; deterministic tests above prove its exact bytes.
            let _ = PersistedUsdomV2RuntimeTip::from_bytes(&bytes);
        }
    }

    #[test]
    fn substituted_state_batch_header_or_network_fails_closed() {
        let state = NativeUsdomState::new(bridge()).unwrap();
        let transitions = vec![issuance()];
        let (block, context) = candidate(&state, &transitions);

        assert!(verify_usdom_v4_candidate_regtest(
            &block,
            &context,
            NETWORK_MAGIC_REGTEST,
            &state,
            &[]
        )
        .is_err());

        let mut wrong_header = block.clone();
        wrong_header.header.rangeproof_root = Hash256::from_bytes([0x88; 32]);
        assert!(verify_usdom_v4_candidate_regtest(
            &wrong_header,
            &context,
            NETWORK_MAGIC_REGTEST,
            &state,
            &transitions
        )
        .is_err());

        assert!(verify_usdom_v4_candidate_regtest(
            &block,
            &context,
            NETWORK_MAGIC_MAINNET,
            &state,
            &transitions
        )
        .is_err());

        let wrong_height_context = ValidationContext {
            current_height: dom_core::BlockHeight(block.header.height.0 + 1),
            chain_id: context.chain_id,
            now: context.now,
        };
        assert!(verify_usdom_v4_candidate_regtest(
            &block,
            &wrong_height_context,
            NETWORK_MAGIC_REGTEST,
            &state,
            &transitions
        )
        .is_err());
        assert_eq!(
            state.state_root(),
            NativeUsdomState::new(bridge()).unwrap().state_root()
        );
    }
}
