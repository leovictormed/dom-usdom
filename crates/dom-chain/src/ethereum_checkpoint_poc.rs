//! Persistent checkpoint record and reorg barrier.
//!
//! The legacy direct installer accepts a TEST ORACLE and is restricted to
//! regtest. Public-network checkpoints enter through the native USDOM carrier
//! path only after the Ethereum verifier has produced an opaque verified
//! capability and DOM consensus has reconstructed the asserted ancestry state.
//! This module owns their shared canonical record and fork-choice enforcement;
//! it is not itself an Ethereum light client.
use dom_core::{DomError, Hash256, NETWORK_MAGIC_REGTEST};
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
    if store.get_metadata(LEGACY_CHECKPOINT_KEY)?.is_some() {
        return Err(rejected("legacy v1 checkpoint requires explicit migration"));
    }
    let metadata = store
        .get_metadata(CHECKPOINT_KEY)?
        .map(|bytes| decode_test_oracle_v2(&bytes))
        .transpose()?;
    let consensus = store
        .get_consensus_state(CONSENSUS_CHECKPOINT_KEY)?
        .map(|bytes| decode_test_oracle_v2(&bytes))
        .transpose()?;
    match (metadata, consensus) {
        (None, None) => Ok(None),
        (Some(checkpoint), None) | (None, Some(checkpoint)) => Ok(Some(checkpoint)),
        (Some(a), Some(b)) if a == b => Ok(Some(a)),
        (Some(a), Some(b)) if a.height < b.height => {
            validate_checkpoint_successor(a, b)?;
            Ok(Some(b))
        }
        (Some(a), Some(b)) if b.height < a.height => {
            validate_checkpoint_successor(b, a)?;
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
        .map(|bytes| decode_test_oracle_v2(&bytes))
        .transpose()
}

/// Decode the bounded experimental wire form without granting installation.
/// Successful decoding proves internal canonicality only; Ethereum finality,
/// receipt inclusion and registry state must already have been authenticated.
pub fn decode_test_oracle_v2(bytes: &[u8]) -> Result<TestOracleCheckpoint, DomError> {
    if bytes.len() != CHECKPOINT_V2_LENGTH || bytes[0] != 2 {
        return Err(rejected("malformed persisted checkpoint"));
    }
    let hash = |start: usize| {
        let mut value = [0u8; 32];
        value.copy_from_slice(&bytes[start..start + 32]);
        Hash256::from_bytes(value)
    };
    let mut height = [0u8; 8];
    height.copy_from_slice(&bytes[1..9]);
    let mut chain_id = [0u8; 8];
    chain_id.copy_from_slice(&bytes[77..85]);
    let mut ethereum_height = [0u8; 8];
    ethereum_height.copy_from_slice(&bytes[85..93]);
    let mut dom_network_magic = [0u8; 4];
    dom_network_magic.copy_from_slice(&bytes[73..77]);
    let mut transaction_index = [0u8; 4];
    transaction_index.copy_from_slice(&bytes[261..265]);
    let mut receipt_log_index = [0u8; 4];
    receipt_log_index.copy_from_slice(&bytes[265..269]);
    let mut checkpoint_contract = [0u8; 20];
    checkpoint_contract.copy_from_slice(&bytes[269..289]);
    let mut beacon_slot = [0u8; 8];
    beacon_slot.copy_from_slice(&bytes[189..197]);
    let checkpoint = TestOracleCheckpoint {
        height: u64::from_be_bytes(height),
        dom_block: hash(9),
        dom_state_root: hash(41),
        dom_network_magic: u32::from_be_bytes(dom_network_magic),
        ethereum_chain_id: u64::from_be_bytes(chain_id),
        ethereum_block_number: u64::from_be_bytes(ethereum_height),
        ethereum_block: hash(93),
        ethereum_receipts_root: hash(125),
        ethereum_state_root: hash(157),
        ethereum_beacon_slot: u64::from_be_bytes(beacon_slot),
        ethereum_beacon_root: hash(197),
        ethereum_genesis_validators_root: hash(229),
        transaction_index: u32::from_be_bytes(transaction_index),
        receipt_log_index: u32::from_be_bytes(receipt_log_index),
        checkpoint_contract,
        checkpoint_code_hash: hash(289),
        checkpoint_config_hash: hash(321),
        bridge_domain: hash(353),
        checkpoint_event_digest: hash(385),
    };
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
    let current = load(store)?;
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
