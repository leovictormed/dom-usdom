//! Persistent checkpoint record and reorg barrier.
//!
//! The legacy direct installer accepts a TEST ORACLE and is restricted to
//! regtest. Public-network checkpoints enter through the native USDOM carrier
//! path only after the Ethereum verifier has produced an opaque verified
//! capability and DOM consensus has reconstructed the asserted ancestry state.
//! This module owns their shared canonical record and fork-choice enforcement;
//! it is not itself an Ethereum light client.
use dom_core::{DomError, Hash256, NETWORK_MAGIC_REGTEST};
use dom_serialization::Reader;
use dom_store::DomStore;
use sha3::{Digest, Keccak256};

/// Legacy experimental key. Its underspecified value is rejected, not ignored.
pub const LEGACY_CHECKPOINT_KEY: &[u8] = b"experimental/usdom/ethereum-checkpoint/v1";
/// Experimental v2 metadata key, absent from production configuration.
pub const CHECKPOINT_KEY: &[u8] = b"experimental/usdom/ethereum-checkpoint/v2";
/// Consensus-state key installed atomically with a native USDOM carrier block.
/// Unlike the experimental metadata key, this value is deterministic input to
/// every node's reorg barrier and is never rolled back with a carrier reorg.
pub const CONSENSUS_CHECKPOINT_KEY: &[u8] = b"usdom-v4/ethereum-checkpoint/floor/v1";
const CHECKPOINT_V2_LENGTH: usize = 417;
const CHECKPOINT_EVENT_TYPE: &[u8] = b"Checkpoint(bytes32 bridgeDomain,uint32 domNetworkMagic,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 checkpointConfigHash)";

/// Checkpoint supplied by a test oracle. Its Ethereum fields are NOT verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestOracleCheckpoint {
    /// DOM block height selected by the test oracle.
    pub height: u64,
    /// DOM block identifier at that height.
    pub dom_block: Hash256,
    /// Commitment to the native USDOM state asserted at this DOM block.
    pub dom_state_root: Hash256,
    /// DOM network magic asserted for this bridge instance.
    pub dom_network_magic: u32,
    /// Ethereum chain ID asserted by the test oracle (1 for mainnet).
    pub ethereum_chain_id: u64,
    /// Finalized Ethereum execution block number asserted by the test oracle.
    pub ethereum_block_number: u64,
    /// Finalized Ethereum execution block identifier asserted by the test oracle.
    pub ethereum_block: Hash256,
    /// Receipt trie root committed by the asserted execution header.
    pub ethereum_receipts_root: Hash256,
    /// State trie root committed by the asserted execution header.
    pub ethereum_state_root: Hash256,
    /// Finalized beacon slot asserted for the execution payload.
    pub ethereum_beacon_slot: u64,
    /// Beacon root whose finalized execution payload is asserted above.
    pub ethereum_beacon_root: Hash256,
    /// Genesis validators root identifying the Ethereum consensus network.
    pub ethereum_genesis_validators_root: Hash256,
    /// Receipt index of the checkpoint event in the execution block.
    pub transaction_index: u32,
    /// Log index relative to that receipt, never a global RPC log index.
    pub receipt_log_index: u32,
    /// Checkpoint registry that emitted the asserted event.
    pub checkpoint_contract: [u8; 20],
    /// Reviewed runtime code pin asserted for the registry policy.
    pub checkpoint_code_hash: Hash256,
    /// Exact registry/policy generation asserted for this checkpoint.
    pub checkpoint_config_hash: Hash256,
    /// Cross-chain domain separating this bridge instance.
    pub bridge_domain: Hash256,
    /// Digest of the exact authenticated checkpoint event payload.
    pub checkpoint_event_digest: Hash256,
}

fn rejected(message: &str) -> DomError {
    DomError::PolicyRejected(format!("CHECKPOINT_POC: {message}"))
}

fn persisted_checkpoint_error(context: &str, error: DomError) -> DomError {
    DomError::Internal(format!("{context}: {error}"))
}

fn decode_persisted_checkpoint(
    bytes: &[u8],
    context: &str,
) -> Result<TestOracleCheckpoint, DomError> {
    decode_test_oracle_v2(bytes).map_err(|error| persisted_checkpoint_error(context, error))
}

/// Reconstruct the Solidity-compatible EIP-712-style struct digest carried by
/// the authenticated checkpoint log. Receipt verification must separately bind
/// this digest to the expected event signature, emitter and finalized header.
pub fn expected_checkpoint_event_digest(checkpoint: TestOracleCheckpoint) -> Hash256 {
    let type_hash = Keccak256::digest(CHECKPOINT_EVENT_TYPE);
    let mut encoded = [0u8; 224];
    encoded[0..32].copy_from_slice(&type_hash);
    encoded[32..64].copy_from_slice(checkpoint.bridge_domain.as_bytes());
    encoded[92..96].copy_from_slice(&checkpoint.dom_network_magic.to_be_bytes());
    encoded[120..128].copy_from_slice(&checkpoint.height.to_be_bytes());
    encoded[128..160].copy_from_slice(checkpoint.dom_block.as_bytes());
    encoded[160..192].copy_from_slice(checkpoint.dom_state_root.as_bytes());
    encoded[192..224].copy_from_slice(checkpoint.checkpoint_config_hash.as_bytes());
    let digest = Keccak256::digest(encoded);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Hash256::from_bytes(bytes)
}

/// Read bounded, versioned metadata; malformed data fails closed.
pub fn load(store: &DomStore) -> Result<Option<TestOracleCheckpoint>, DomError> {
    let (metadata, consensus) = store.read_atomic_state_entries(
        &[LEGACY_CHECKPOINT_KEY, CHECKPOINT_KEY],
        &[CONSENSUS_CHECKPOINT_KEY],
    )?;
    if metadata[0].is_some() {
        return Err(rejected("legacy v1 checkpoint requires explicit migration"));
    }
    let metadata = metadata[1]
        .as_deref()
        .map(|bytes| decode_persisted_checkpoint(bytes, "persisted checkpoint metadata is corrupt"))
        .transpose()?;
    let consensus = consensus[0]
        .as_deref()
        .map(|bytes| {
            decode_persisted_checkpoint(bytes, "persisted consensus checkpoint is corrupt")
        })
        .transpose()?;
    match (metadata, consensus) {
        (None, None) => Ok(None),
        (Some(checkpoint), None) | (None, Some(checkpoint)) => Ok(Some(checkpoint)),
        (Some(a), Some(b)) if a == b => Ok(Some(a)),
        (Some(a), Some(b)) if a.height < b.height => {
            validate_checkpoint_successor(a, b).map_err(|error| {
                persisted_checkpoint_error("persisted checkpoint generations conflict", error)
            })?;
            Ok(Some(b))
        }
        (Some(a), Some(b)) if b.height < a.height => {
            validate_checkpoint_successor(b, a).map_err(|error| {
                persisted_checkpoint_error("persisted checkpoint generations conflict", error)
            })?;
            Ok(Some(a))
        }
        (Some(_), Some(_)) => Err(rejected(
            "metadata and consensus checkpoints conflict at one DOM height",
        )),
    }
}

/// Read only the checkpoint installed by a consensus-visible carrier block.
/// This lets startup distinguish self-authenticating canonical state from the
/// legacy local metadata path that still requires an external restart floor.
pub fn load_consensus(store: &DomStore) -> Result<Option<TestOracleCheckpoint>, DomError> {
    store
        .get_consensus_state(CONSENSUS_CHECKPOINT_KEY)?
        .map(|bytes| {
            decode_persisted_checkpoint(&bytes, "persisted consensus checkpoint is corrupt")
        })
        .transpose()
}

/// Decode the bounded experimental wire form without granting installation.
/// Successful decoding proves internal canonicality only; Ethereum finality,
/// receipt inclusion and registry state must already have been authenticated.
pub fn decode_test_oracle_v2(bytes: &[u8]) -> Result<TestOracleCheckpoint, DomError> {
    let checkpoint = (|| -> Result<TestOracleCheckpoint, DomError> {
        if bytes.len() != CHECKPOINT_V2_LENGTH {
            return Err(DomError::Malformed(
                "invalid persisted checkpoint length".into(),
            ));
        }
        let mut reader = Reader::new(bytes);
        if reader.read_u8()? != 2 {
            return Err(DomError::Malformed(
                "invalid persisted checkpoint version".into(),
            ));
        }
        let checkpoint = TestOracleCheckpoint {
            height: reader.read_u64_be()?,
            dom_block: Hash256::from_bytes(reader.read_array::<32>()?),
            dom_state_root: Hash256::from_bytes(reader.read_array::<32>()?),
            dom_network_magic: reader.read_u32_be()?,
            ethereum_chain_id: reader.read_u64_be()?,
            ethereum_block_number: reader.read_u64_be()?,
            ethereum_block: Hash256::from_bytes(reader.read_array::<32>()?),
            ethereum_receipts_root: Hash256::from_bytes(reader.read_array::<32>()?),
            ethereum_state_root: Hash256::from_bytes(reader.read_array::<32>()?),
            ethereum_beacon_slot: reader.read_u64_be()?,
            ethereum_beacon_root: Hash256::from_bytes(reader.read_array::<32>()?),
            ethereum_genesis_validators_root: Hash256::from_bytes(reader.read_array::<32>()?),
            transaction_index: reader.read_u32_be()?,
            receipt_log_index: reader.read_u32_be()?,
            checkpoint_contract: reader.read_array::<20>()?,
            checkpoint_code_hash: Hash256::from_bytes(reader.read_array::<32>()?),
            checkpoint_config_hash: Hash256::from_bytes(reader.read_array::<32>()?),
            bridge_domain: Hash256::from_bytes(reader.read_array::<32>()?),
            checkpoint_event_digest: Hash256::from_bytes(reader.read_array::<32>()?),
        };
        reader.finish()?;
        Ok(checkpoint)
    })()
    .map_err(|_| rejected("malformed persisted checkpoint"))?;
    validate_identity(checkpoint)?;
    Ok(checkpoint)
}

fn validate_identity(checkpoint: TestOracleCheckpoint) -> Result<(), DomError> {
    if checkpoint.height == 0
        || checkpoint.dom_block == Hash256::ZERO
        || checkpoint.dom_state_root == Hash256::ZERO
        || checkpoint.dom_network_magic == 0
        || checkpoint.ethereum_chain_id == 0
        || checkpoint.ethereum_block_number == 0
        || checkpoint.ethereum_block == Hash256::ZERO
        || checkpoint.ethereum_receipts_root == Hash256::ZERO
        || checkpoint.ethereum_state_root == Hash256::ZERO
        || checkpoint.ethereum_beacon_slot == 0
        || checkpoint.ethereum_beacon_root == Hash256::ZERO
        || checkpoint.ethereum_genesis_validators_root == Hash256::ZERO
        || checkpoint.checkpoint_contract == [0u8; 20]
        || checkpoint.checkpoint_code_hash == Hash256::ZERO
        || checkpoint.checkpoint_config_hash == Hash256::ZERO
        || checkpoint.bridge_domain == Hash256::ZERO
        || checkpoint.checkpoint_event_digest == Hash256::ZERO
    {
        return Err(rejected("zero checkpoint identity"));
    }
    if checkpoint.checkpoint_event_digest != expected_checkpoint_event_digest(checkpoint) {
        return Err(rejected("checkpoint event digest mismatch"));
    }
    Ok(())
}

fn same_domain(a: TestOracleCheckpoint, b: TestOracleCheckpoint) -> bool {
    a.dom_network_magic == b.dom_network_magic
        && a.ethereum_chain_id == b.ethereum_chain_id
        && a.ethereum_genesis_validators_root == b.ethereum_genesis_validators_root
        && a.checkpoint_contract == b.checkpoint_contract
        && a.checkpoint_code_hash == b.checkpoint_code_hash
        && a.checkpoint_config_hash == b.checkpoint_config_hash
        && a.bridge_domain == b.bridge_domain
}

fn ethereum_locator(checkpoint: TestOracleCheckpoint) -> (u64, u32, u32) {
    (
        checkpoint.ethereum_block_number,
        checkpoint.transaction_index,
        checkpoint.receipt_log_index,
    )
}

fn same_finalized_block_if_same_number(a: TestOracleCheckpoint, b: TestOracleCheckpoint) -> bool {
    a.ethereum_block_number != b.ethereum_block_number
        || (a.ethereum_block == b.ethereum_block
            && a.ethereum_receipts_root == b.ethereum_receipts_root
            && a.ethereum_state_root == b.ethereum_state_root
            && a.ethereum_beacon_slot == b.ethereum_beacon_slot
            && a.ethereum_beacon_root == b.ethereum_beacon_root)
}

fn beacon_slot_advances_with_execution_block(
    newer: TestOracleCheckpoint,
    older: TestOracleCheckpoint,
) -> bool {
    newer.ethereum_block_number == older.ethereum_block_number
        || newer.ethereum_beacon_slot > older.ethereum_beacon_slot
}

/// Validate a strictly newer checkpoint in the same immutable bridge domain.
/// This is shared by the legacy test-oracle installer and the consensus-visible
/// native carrier path so neither persistence route can weaken the floor.
pub fn validate_checkpoint_successor(
    older: TestOracleCheckpoint,
    newer: TestOracleCheckpoint,
) -> Result<(), DomError> {
    validate_identity(older)?;
    validate_identity(newer)?;
    if newer.height <= older.height {
        return Err(rejected("checkpoint rollback or replacement"));
    }
    if !same_domain(older, newer) {
        return Err(rejected("checkpoint domain or configuration changed"));
    }
    if ethereum_locator(newer) <= ethereum_locator(older) {
        return Err(rejected("Ethereum checkpoint locator did not advance"));
    }
    if !same_finalized_block_if_same_number(newer, older) {
        return Err(rejected("conflicting finalized Ethereum block identity"));
    }
    if !beacon_slot_advances_with_execution_block(newer, older) {
        return Err(rejected("finalized beacon slot did not advance"));
    }
    Ok(())
}

/// Canonical bounded wire form used by both metadata and consensus-state
/// persistence. Encoding validates all identity fields first.
pub fn encode_test_oracle_v2(checkpoint: TestOracleCheckpoint) -> Result<Vec<u8>, DomError> {
    validate_identity(checkpoint)?;
    let mut bytes = Vec::with_capacity(CHECKPOINT_V2_LENGTH);
    bytes.push(2);
    bytes.extend_from_slice(&checkpoint.height.to_be_bytes());
    bytes.extend_from_slice(checkpoint.dom_block.as_bytes());
    bytes.extend_from_slice(checkpoint.dom_state_root.as_bytes());
    bytes.extend_from_slice(&checkpoint.dom_network_magic.to_be_bytes());
    bytes.extend_from_slice(&checkpoint.ethereum_chain_id.to_be_bytes());
    bytes.extend_from_slice(&checkpoint.ethereum_block_number.to_be_bytes());
    bytes.extend_from_slice(checkpoint.ethereum_block.as_bytes());
    bytes.extend_from_slice(checkpoint.ethereum_receipts_root.as_bytes());
    bytes.extend_from_slice(checkpoint.ethereum_state_root.as_bytes());
    bytes.extend_from_slice(&checkpoint.ethereum_beacon_slot.to_be_bytes());
    bytes.extend_from_slice(checkpoint.ethereum_beacon_root.as_bytes());
    bytes.extend_from_slice(checkpoint.ethereum_genesis_validators_root.as_bytes());
    bytes.extend_from_slice(&checkpoint.transaction_index.to_be_bytes());
    bytes.extend_from_slice(&checkpoint.receipt_log_index.to_be_bytes());
    bytes.extend_from_slice(&checkpoint.checkpoint_contract);
    bytes.extend_from_slice(checkpoint.checkpoint_code_hash.as_bytes());
    bytes.extend_from_slice(checkpoint.checkpoint_config_hash.as_bytes());
    bytes.extend_from_slice(checkpoint.bridge_domain.as_bytes());
    bytes.extend_from_slice(checkpoint.checkpoint_event_digest.as_bytes());
    debug_assert_eq!(bytes.len(), CHECKPOINT_V2_LENGTH);
    Ok(bytes)
}

/// Require the persisted anchor to exist in the current canonical history.
pub fn ensure_current(store: &DomStore, tip_height: u64) -> Result<(), DomError> {
    ensure_at_least(store, tip_height, None).map(|_| ())
}

/// Check the database against a separately supplied trusted TEST floor.
/// This does not authenticate the floor, Ethereum ancestry, or its freshness.
/// A missing/stale database cannot silently replace an explicit requirement.
pub fn ensure_at_least(
    store: &DomStore,
    tip_height: u64,
    floor: Option<TestOracleCheckpoint>,
) -> Result<Option<TestOracleCheckpoint>, DomError> {
    ensure_at_least_inner(store, tip_height, floor, false)
}

/// Validate checkpoint persistence during startup and require an independently
/// retained floor whenever this database already contains a checkpoint.
///
/// A consensus-state record proves what this database currently says, but it
/// cannot reveal that an operator restored an older, internally consistent
/// snapshot. The external floor is therefore mandatory for every restart after
/// either metadata or consensus checkpoint installation.
pub fn ensure_restart_floor(
    store: &DomStore,
    tip_height: u64,
    floor: Option<TestOracleCheckpoint>,
) -> Result<Option<TestOracleCheckpoint>, DomError> {
    ensure_at_least_inner(store, tip_height, floor, true)
}

fn ensure_at_least_inner(
    store: &DomStore,
    tip_height: u64,
    floor: Option<TestOracleCheckpoint>,
    require_external_floor: bool,
) -> Result<Option<TestOracleCheckpoint>, DomError> {
    let current = load(store)?;
    if require_external_floor && current.is_some() && floor.is_none() {
        return Err(rejected("external restart checkpoint floor is required"));
    }
    if let Some(required) = floor {
        validate_identity(required).map_err(|_| rejected("invalid required checkpoint"))?;
        let checkpoint = current.ok_or_else(|| rejected("required checkpoint is missing"))?;
        if checkpoint.height < required.height {
            return Err(rejected("persisted checkpoint is below required floor"));
        }
        if checkpoint.height == required.height && checkpoint != required {
            return Err(rejected(
                "persisted checkpoint conflicts with required floor",
            ));
        }
        if checkpoint.height > required.height {
            if !same_domain(checkpoint, required) {
                return Err(rejected("persisted checkpoint changed required domain"));
            }
            if ethereum_locator(checkpoint) <= ethereum_locator(required) {
                return Err(rejected(
                    "persisted Ethereum locator did not reach required floor",
                ));
            }
            if !same_finalized_block_if_same_number(checkpoint, required) {
                return Err(rejected("conflicting finalized Ethereum block identity"));
            }
            if !beacon_slot_advances_with_execution_block(checkpoint, required) {
                return Err(rejected("finalized beacon slot did not advance"));
            }
        }
        if required.height > tip_height
            || store.get_hash_at_height(required.height)? != Some(*required.dom_block.as_bytes())
        {
            return Err(rejected("canonical history conflicts with required floor"));
        }
    }
    if let Some(checkpoint) = current {
        if checkpoint.height > tip_height
            || store.get_hash_at_height(checkpoint.height)?
                != Some(*checkpoint.dom_block.as_bytes())
        {
            return Err(rejected("canonical history conflicts with checkpoint"));
        }
    }
    Ok(current)
}

/// Install a TEST ORACLE assertion only in regtest after local canonical alignment.
/// Does not verify any Ethereum signature, finality, receipt or state proof.
pub fn install_from_test_oracle(
    store: &DomStore,
    network_magic: u32,
    tip_height: u64,
    checkpoint: TestOracleCheckpoint,
) -> Result<(), DomError> {
    if network_magic != NETWORK_MAGIC_REGTEST {
        return Err(rejected("test oracle is regtest-only"));
    }
    if checkpoint.dom_network_magic != network_magic {
        return Err(rejected("checkpoint DOM network mismatch"));
    }
    ensure_current(store, tip_height)?;
    if checkpoint.height > tip_height
        || store.get_hash_at_height(checkpoint.height)? != Some(*checkpoint.dom_block.as_bytes())
    {
        return Err(rejected("test oracle checkpoint is not canonical"));
    }
    validate_identity(checkpoint)?;
    if let Some(old) = load(store)? {
        if checkpoint == old {
            return Ok(());
        }
        validate_checkpoint_successor(old, checkpoint)?;
    }
    let bytes = encode_test_oracle_v2(checkpoint)?;
    store.put_metadata(CHECKPOINT_KEY, &bytes)
}

/// Install only a checkpoint whose opaque capability was created by the
/// concrete BLS/SSZ, ancestry, receipt, code, and storage verifier.
///
/// This direct, out-of-band installation route remains regtest-only. Public
/// networks use the native USDOM consensus-carrier path, which binds the
/// verified record to the reconstructed state root before atomic persistence.
#[cfg(feature = "ethereum-checkpoint-verified-poc")]
pub fn install_from_verified_handoff(
    store: &DomStore,
    network_magic: u32,
    tip_height: u64,
    verified: &usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint,
) -> Result<TestOracleCheckpoint, DomError> {
    let checkpoint = decode_test_oracle_v2(verified.record())?;
    install_from_test_oracle(store, network_magic, tip_height, checkpoint)?;
    Ok(checkpoint)
}

/// Replay one bounded witness before using the legacy direct installer. This
/// route remains regtest-only; public networks require a scheduled native
/// carrier block so verification, ancestry binding and persistence are one
/// consensus transition.
#[cfg(feature = "ethereum-checkpoint-verified-poc")]
pub fn verify_and_install_witness(
    store: &DomStore,
    network_magic: u32,
    tip_height: u64,
    witness: &[u8],
    policy: &usdom_ethereum_finality_experiment::checkpoints::CheckpointTrustPolicy,
) -> Result<TestOracleCheckpoint, DomError> {
    if network_magic != NETWORK_MAGIC_REGTEST {
        return Err(rejected("verified witness installation is regtest-only"));
    }
    let verified =
        usdom_ethereum_finality_experiment::checkpoints::verify_checkpoint_witness(witness, policy)
            .map_err(|error| rejected(&format!("invalid Ethereum checkpoint witness: {error}")))?;
    install_from_verified_handoff(store, network_magic, tip_height, &verified)
}

/// Reject a reorg whose shared ancestor precedes the persisted checkpoint.
/// Called before canonical block disconnection in the actual fork-choice path.
pub fn check_reorg(
    store: &DomStore,
    tip_height: u64,
    ancestor_height: u64,
) -> Result<(), DomError> {
    ensure_current(store, tip_height)?;
    if load(store)?.is_some_and(|checkpoint| ancestor_height < checkpoint.height) {
        return Err(rejected("reorg would undo checkpoint"));
    }
    Ok(())
}
