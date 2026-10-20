//! Native fork-choice barrier tests with synthetic headers and a trusted test oracle.
//! These are not tests of Ethereum authentication, RandomX or native USDOM burns.
#![cfg(feature = "ethereum-checkpoint-poc")]
mod common;
use dom_chain::{
    ethereum_checkpoint_poc::{self as checkpoint, TestOracleCheckpoint},
    ChainState,
};
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_core::{
    required_block_version_for_network, BlockHeight, Hash256, Timestamp, NETWORK_MAGIC_REGTEST,
};
use dom_pow::CompactTarget;
use dom_serialization::DomSerialize;
use dom_store::ConsensusStateUpdate;
use primitive_types::U256;
use tempfile::TempDir;

fn header(parent: Hash256, height: u64, nonce: u64, work: u64) -> BlockHeader {
    BlockHeader {
        version: required_block_version_for_network(NETWORK_MAGIC_REGTEST, height),
        height: BlockHeight(height),
        prev_hash: parent,
        timestamp: Timestamp(1_700_000_000 + height),
        output_root: Hash256::ZERO,
        kernel_root: Hash256::ZERO,
        rangeproof_root: Hash256::ZERO,
        total_kernel_offset: [0; 32],
        target: CompactTarget(0),
        total_difficulty: U256::from(work),
        pow: ProofOfWork {
            nonce,
            randomx_hash: Hash256::ZERO,
        },
    }
}

// Coinbase fixture construction follows reorg_equivalence.rs::signed_coinbase.
// Real serialized bodies/UTXO changes are needed for startup integrity checks.
fn canonical_blocks() -> &'static Vec<dom_consensus::Block> {
    static BLOCKS: std::sync::OnceLock<Vec<dom_consensus::Block>> = std::sync::OnceLock::new();
    BLOCKS.get_or_init(|| {
        use dom_consensus::{Block, CoinbaseKernel, CoinbaseTransaction, TransactionOutput};
        use dom_crypto::pedersen::{BlindingFactor, Commitment};
        let mut parent = Hash256::ZERO;
        let mut blocks = Vec::new();
        for height in 0..=5 {
            let reward = dom_core::block_reward(BlockHeight(height)).noms();
            let mut secret_bytes = [0u8; 32];
            secret_bytes[31] = height as u8 + 1;
            let blinding = BlindingFactor::from_bytes(secret_bytes).unwrap();
            let commitment = Commitment::commit(reward, &blinding);
            let (proof, _) = dom_crypto::bp2_prove(reward, &blinding).unwrap();
            let excess = Commitment::commit(0, &blinding);
            let secret = dom_crypto::keys::SecretKey::from_bytes(blinding.as_bytes()).unwrap();
            let chain_id = dom_consensus::derive_chain_id(NETWORK_MAGIC_REGTEST, &Hash256::ZERO);
            let mut message = vec![dom_core::KERNEL_FEAT_COINBASE];
            message.extend_from_slice(&reward.to_le_bytes());
            let digest =
                dom_crypto::hash::blake2b_256_tagged(dom_core::TAG_KERNEL_MSG_COINBASE, &message);
            let signature =
                dom_crypto::schnorr_sign(&secret, digest.as_bytes(), chain_id.as_bytes()).unwrap();
            let coinbase = CoinbaseTransaction {
                output: TransactionOutput { commitment, proof },
                kernel: CoinbaseKernel {
                    features: dom_core::KERNEL_FEAT_COINBASE,
                    explicit_value: reward,
                    excess,
                    excess_signature: signature.to_bytes(),
                },
                offset: [0; 32],
            };
            let (output_root, kernel_root, rangeproof_root) =
                dom_consensus::compute_block_pmmr_roots(BlockHeight(height), &coinbase, &[])
                    .unwrap();
            let mut block_header = header(parent, height, height, height);
            block_header.output_root = output_root;
            block_header.kernel_root = kernel_root;
            block_header.rangeproof_root = rangeproof_root;
            parent = dom_crypto::hash::blake2b_256(&block_header.to_bytes().unwrap());
            blocks.push(Block {
                header: block_header,
                coinbase,
                transactions: vec![],
            });
        }
        blocks
    })
}

fn canonical_chain() -> (TempDir, ChainState, Vec<Hash256>) {
    let dir = TempDir::new().unwrap();
    let mut chain = ChainState::open(
        common::open_test_store(dir.path()),
        Hash256::ZERO,
        NETWORK_MAGIC_REGTEST,
    )
    .unwrap();
    let mut hashes = Vec::new();
    for block in canonical_blocks() {
        let height = block.header.height.0;
        let bytes = block.header.to_bytes().unwrap();
        let hash = dom_crypto::hash::blake2b_256(&bytes);
        let utxo = dom_store::utxo::UtxoEntry {
            block_height: height,
            is_coinbase: true,
            proof: block.coinbase.output.proof.clone(),
        };
        chain
            .store
            .commit_block(
                hash.as_bytes(),
                height,
                &bytes,
                &block.to_bytes().unwrap(),
                &[(
                    *block.coinbase.output.commitment.as_bytes(),
                    utxo.to_bytes(),
                )],
                &[],
                &[(*block.coinbase.kernel.excess.as_bytes(), *hash.as_bytes())],
            )
            .unwrap();
        hashes.push(hash);
    }
    chain.tip_hash = *hashes.last().unwrap();
    chain.tip_height = BlockHeight(5);
    chain.tip_difficulty = U256::from(5);
    (dir, chain, hashes)
}

fn oracle(height: u64, dom_block: Hash256) -> TestOracleCheckpoint {
    let mut checkpoint = TestOracleCheckpoint {
        height,
        dom_block,
        dom_state_root: Hash256::from_bytes([0x80 + height as u8; 32]),
        dom_network_magic: NETWORK_MAGIC_REGTEST,
        ethereum_chain_id: 1,
        ethereum_block_number: 17_923_026 + height,
        ethereum_block: Hash256::from_bytes([0x90 + height as u8; 32]),
        ethereum_receipts_root: Hash256::from_bytes([0x50 + height as u8; 32]),
        ethereum_state_root: Hash256::from_bytes([0x60 + height as u8; 32]),
        ethereum_beacon_slot: 7_109_344 + height,
        ethereum_beacon_root: Hash256::from_bytes([0xa0 + height as u8; 32]),
        ethereum_genesis_validators_root: Hash256::from_bytes([0xb0; 32]),
        transaction_index: height as u32,
        receipt_log_index: 0,
        checkpoint_contract: [0xc0; 20],
        checkpoint_code_hash: Hash256::from_bytes([0xd0; 32]),
        checkpoint_config_hash: Hash256::from_bytes([0xe0; 32]),
        bridge_domain: Hash256::from_bytes([0xf0; 32]),
        checkpoint_event_digest: Hash256::ZERO,
    };
    checkpoint.checkpoint_event_digest = checkpoint::expected_checkpoint_event_digest(checkpoint);
    checkpoint
}

fn rebind_event(mut value: TestOracleCheckpoint) -> TestOracleCheckpoint {
    value.checkpoint_event_digest = checkpoint::expected_checkpoint_event_digest(value);
    value
}

#[cfg(feature = "ethereum-checkpoint-verified-poc")]
fn encode_handoff(value: TestOracleCheckpoint) -> [u8; 417] {
    let mut bytes = Vec::with_capacity(417);
    bytes.push(2);
    bytes.extend_from_slice(&value.height.to_be_bytes());
    bytes.extend_from_slice(value.dom_block.as_bytes());
    bytes.extend_from_slice(value.dom_state_root.as_bytes());
    bytes.extend_from_slice(&value.dom_network_magic.to_be_bytes());
    bytes.extend_from_slice(&value.ethereum_chain_id.to_be_bytes());
    bytes.extend_from_slice(&value.ethereum_block_number.to_be_bytes());
    bytes.extend_from_slice(value.ethereum_block.as_bytes());
    bytes.extend_from_slice(value.ethereum_receipts_root.as_bytes());
    bytes.extend_from_slice(value.ethereum_state_root.as_bytes());
    bytes.extend_from_slice(&value.ethereum_beacon_slot.to_be_bytes());
    bytes.extend_from_slice(value.ethereum_beacon_root.as_bytes());
    bytes.extend_from_slice(value.ethereum_genesis_validators_root.as_bytes());
    bytes.extend_from_slice(&value.transaction_index.to_be_bytes());
    bytes.extend_from_slice(&value.receipt_log_index.to_be_bytes());
    bytes.extend_from_slice(&value.checkpoint_contract);
    bytes.extend_from_slice(value.checkpoint_code_hash.as_bytes());
    bytes.extend_from_slice(value.checkpoint_config_hash.as_bytes());
    bytes.extend_from_slice(value.bridge_domain.as_bytes());
    bytes.extend_from_slice(value.checkpoint_event_digest.as_bytes());
    bytes.try_into().unwrap()
}

#[test]
fn checkpoint_event_digest_matches_independent_solidity_abi_vector() {
    let mut value = oracle(42, Hash256::from_bytes([0x11; 32]));
    value.dom_network_magic = 0x4450_4f43;
    value.dom_state_root = Hash256::from_bytes([0x22; 32]);
    value.checkpoint_config_hash = Hash256::from_bytes([0x33; 32]);
    value.bridge_domain = Hash256::from_bytes([0x77; 32]);
    assert_eq!(
        hex::encode(checkpoint::expected_checkpoint_event_digest(value).as_bytes()),
        "f9469e1caff7fa3bd4f9192182fffa95b764e829a0d2a4bf4a9a6a1f4a54ddff"
    );
}

#[test]
fn authenticated_verifier_handoff_vector_decodes_exactly() {
    let raw = hex::decode(
        include_str!("../../../labs/usdom-ethereum-finality/fixtures/checkpoint-handoff-v2.hex")
            .trim(),
    )
    .unwrap();
    let value = checkpoint::decode_test_oracle_v2(&raw).unwrap();
    assert_eq!(value.height, 42);
    assert_eq!(value.dom_block, Hash256::from_bytes([0xaa; 32]));
    assert_eq!(value.dom_state_root, Hash256::from_bytes([0xbb; 32]));
    assert_eq!(value.dom_network_magic, 0x4450_4d52);
    assert_eq!(value.ethereum_chain_id, 1);
    assert_eq!(value.ethereum_block_number, 20_000_000);
    assert_eq!(value.ethereum_block, Hash256::from_bytes([0x33; 32]));
    assert_eq!(
        value.ethereum_receipts_root,
        Hash256::from_bytes([0x44; 32])
    );
    assert_eq!(value.ethereum_state_root, Hash256::from_bytes([0x55; 32]));
    assert_eq!(value.ethereum_beacon_slot, 16_000_000);
    assert_eq!(value.ethereum_beacon_root, Hash256::from_bytes([0x66; 32]));
    assert_eq!(
        value.ethereum_genesis_validators_root,
        Hash256::from_bytes([0x22; 32])
    );
    assert_eq!(value.transaction_index, 7);
    assert_eq!(value.receipt_log_index, 2);
    assert_eq!(value.checkpoint_contract, [0x11; 20]);
    assert_eq!(value.checkpoint_code_hash, Hash256::from_bytes([0x77; 32]));
    assert_eq!(
        value.checkpoint_config_hash,
        Hash256::from_bytes([0x88; 32])
    );
    assert_eq!(value.bridge_domain, Hash256::from_bytes([0x99; 32]));
    assert_eq!(
        hex::encode(value.checkpoint_event_digest.as_bytes()),
        "ca0bfc1b260f22dcd481ebad848648db948baee7ad81caea2860579ff5b001f7"
    );
}

#[cfg(feature = "ethereum-checkpoint-verified-poc")]
#[test]
fn opaque_verified_handoff_reaches_the_real_regtest_barrier() {
    use usdom_ethereum_finality_experiment::checkpoints::unsafe_test_only_verified_checkpoint;

    let (dir, mut chain, hashes) = canonical_chain();
    let expected = oracle(3, hashes[3]);
    let verified = unsafe_test_only_verified_checkpoint(
        encode_handoff(expected),
        1_700_000_000,
        [0x99; 32].into(),
    );
    chain.install_verified_checkpoint(&verified).unwrap();
    assert_eq!(checkpoint::load(&chain.store).unwrap(), Some(expected));

    drop(chain);
    assert!(ChainState::open_with_verified_checkpoint_floor(
        common::open_test_store(dir.path()),
        Hash256::ZERO,
        NETWORK_MAGIC_REGTEST,
        &verified,
        [0x98; 32],
    )
    .is_err());
    let reopened = ChainState::open_with_verified_checkpoint_floor(
        common::open_test_store(dir.path()),
        Hash256::ZERO,
        NETWORK_MAGIC_REGTEST,
        &verified,
        [0x99; 32],
    )
    .unwrap();
    assert_eq!(reopened.tip_hash, hashes[5]);

    let err = checkpoint::install_from_verified_handoff(
        &reopened.store,
        dom_core::NETWORK_MAGIC_MAINNET,
        reopened.tip_height.0,
        &verified,
    )
    .unwrap_err();
    assert!(err.to_string().contains("test oracle is regtest-only"));
}

#[test]
fn consensus_carried_floor_restarts_without_external_handoff() {
    let (dir, chain, hashes) = canonical_chain();
    let floor = oracle(3, hashes[3]);
    let value = checkpoint::encode_test_oracle_v2(floor).unwrap();
    chain
        .store
        .apply_reorg_with_consensus_state(
            chain.tip_hash.as_bytes(),
            &[],
            &[],
            &[],
            &[ConsensusStateUpdate {
                key: checkpoint::CONSENSUS_CHECKPOINT_KEY.to_vec(),
                value: Some(value),
            }],
        )
        .unwrap();
    drop(chain);

    let reopened = ChainState::open(
        common::open_test_store(dir.path()),
        Hash256::ZERO,
        NETWORK_MAGIC_REGTEST,
    )
    .unwrap();
    assert_eq!(reopened.tip_hash, hashes[5]);
    assert_eq!(checkpoint::load(&reopened.store).unwrap(), Some(floor));
}

#[test]
fn arbitrary_checkpoint_event_digest_is_rejected() {
    let (_dir, chain, hashes) = canonical_chain();
    let mut value = oracle(3, hashes[3]);
    value.checkpoint_event_digest = Hash256::from_bytes([0x44; 32]);
    assert!(
        checkpoint::install_from_test_oracle(&chain.store, NETWORK_MAGIC_REGTEST, 5, value,)
            .unwrap_err()
            .to_string()
            .contains("checkpoint event digest mismatch")
    );
}

#[test]
fn nonzero_event_digest_corruption_fails_closed_on_load() {
    let (_dir, chain, hashes) = canonical_chain();
    checkpoint::install_from_test_oracle(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        5,
        oracle(3, hashes[3]),
    )
    .unwrap();
    let mut raw = chain
        .store
        .get_metadata(checkpoint::CHECKPOINT_KEY)
        .unwrap()
        .unwrap();
    raw[416] ^= 1;
    chain
        .store
        .put_metadata(checkpoint::CHECKPOINT_KEY, &raw)
        .unwrap();
    assert!(checkpoint::load(&chain.store)
        .unwrap_err()
        .to_string()
        .contains("checkpoint event digest mismatch"));
}

#[test]
fn actual_fork_choice_rejects_heavier_branch_crossing_checkpoint_before_mutation() {
    let (_dir, mut chain, hashes) = canonical_chain();
    let anchor = oracle(3, hashes[3]);
    checkpoint::install_from_test_oracle(&chain.store, NETWORK_MAGIC_REGTEST, 5, anchor).unwrap();
    let mut parent = hashes[2];
    for height in 3..=6 {
        let block = header(parent, height, 1000 + height, 100 + height);
        let bytes = block.to_bytes().unwrap();
        let hash = dom_crypto::hash::blake2b_256(&bytes);
        chain
            .store
            .store_known_block(hash.as_bytes(), &bytes, &[0; 8])
            .unwrap();
        parent = hash;
    }
    let error = chain
        .promote_heavier_known_tip(parent, Timestamp(2_000_000_000))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("CHECKPOINT_POC: reorg would undo checkpoint"),
        "{error}"
    );
    assert_eq!(chain.tip_hash, hashes[5]);
    assert_eq!(
        chain.store.get_chain_tip().unwrap(),
        Some(*hashes[5].as_bytes())
    );
    assert_eq!(
        chain.store.get_hash_at_height(3).unwrap(),
        Some(*hashes[3].as_bytes())
    );
    assert_eq!(checkpoint::load(&chain.store).unwrap(), Some(anchor));
}

#[test]
fn barrier_allows_shared_ancestor_at_or_after_anchor_but_not_before() {
    let (_dir, chain, hashes) = canonical_chain();
    checkpoint::install_from_test_oracle(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        5,
        oracle(3, hashes[3]),
    )
    .unwrap();
    checkpoint::check_reorg(&chain.store, 5, 3).unwrap();
    checkpoint::check_reorg(&chain.store, 5, 4).unwrap();
    assert!(checkpoint::check_reorg(&chain.store, 5, 2).is_err());
}

#[test]
fn oracle_installation_rejects_mainnet_missing_block_and_rollback() {
    let (_dir, chain, hashes) = canonical_chain();
    assert!(checkpoint::install_from_test_oracle(
        &chain.store,
        dom_core::NETWORK_MAGIC_MAINNET,
        5,
        oracle(3, hashes[3])
    )
    .is_err());
    assert!(checkpoint::install_from_test_oracle(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        5,
        oracle(3, hashes[2])
    )
    .is_err());
    assert!(checkpoint::install_from_test_oracle(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        5,
        oracle(6, hashes[5])
    )
    .is_err());
    checkpoint::install_from_test_oracle(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        5,
        oracle(3, hashes[3]),
    )
    .unwrap();
    checkpoint::install_from_test_oracle(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        5,
        oracle(3, hashes[3]),
    )
    .unwrap();
    assert!(checkpoint::install_from_test_oracle(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        5,
        oracle(2, hashes[2])
    )
    .is_err());
    let mut replacement = oracle(3, hashes[3]);
    replacement.ethereum_block = Hash256::from_bytes([0xdd; 32]);
    assert!(checkpoint::install_from_test_oracle(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        5,
        replacement
    )
    .is_err());
}

#[test]
fn v2_encoding_roundtrips_all_domain_and_locator_fields() {
    let (_dir, chain, hashes) = canonical_chain();
    let expected = oracle(3, hashes[3]);
    checkpoint::install_from_test_oracle(&chain.store, NETWORK_MAGIC_REGTEST, 5, expected).unwrap();
    let raw = chain
        .store
        .get_metadata(checkpoint::CHECKPOINT_KEY)
        .unwrap()
        .unwrap();
    assert_eq!(raw.len(), 417);
    assert_eq!(raw[0], 2);
    assert_eq!(&raw[1..9], &expected.height.to_be_bytes());
    assert_eq!(&raw[9..41], expected.dom_block.as_bytes());
    assert_eq!(&raw[41..73], expected.dom_state_root.as_bytes());
    assert_eq!(&raw[73..77], &expected.dom_network_magic.to_be_bytes());
    assert_eq!(&raw[77..85], &expected.ethereum_chain_id.to_be_bytes());
    assert_eq!(&raw[85..93], &expected.ethereum_block_number.to_be_bytes());
    assert_eq!(&raw[93..125], expected.ethereum_block.as_bytes());
    assert_eq!(&raw[125..157], expected.ethereum_receipts_root.as_bytes());
    assert_eq!(&raw[157..189], expected.ethereum_state_root.as_bytes());
    assert_eq!(&raw[189..197], &expected.ethereum_beacon_slot.to_be_bytes());
    assert_eq!(&raw[197..229], expected.ethereum_beacon_root.as_bytes());
    assert_eq!(
        &raw[229..261],
        expected.ethereum_genesis_validators_root.as_bytes()
    );
    assert_eq!(&raw[261..265], &expected.transaction_index.to_be_bytes());
    assert_eq!(&raw[265..269], &expected.receipt_log_index.to_be_bytes());
    assert_eq!(&raw[269..289], &expected.checkpoint_contract);
    assert_eq!(&raw[289..321], expected.checkpoint_code_hash.as_bytes());
    assert_eq!(&raw[321..353], expected.checkpoint_config_hash.as_bytes());
    assert_eq!(&raw[353..385], expected.bridge_domain.as_bytes());
    assert_eq!(&raw[385..417], expected.checkpoint_event_digest.as_bytes());
    assert_eq!(checkpoint::load(&chain.store).unwrap(), Some(expected));
    assert!(chain
        .store
        .get_metadata(checkpoint::LEGACY_CHECKPOINT_KEY)
        .unwrap()
        .is_none());
}

#[test]
fn domain_configuration_and_ethereum_locator_cannot_silently_change_or_regress() {
    let (_dir, chain, hashes) = canonical_chain();
    let old = oracle(3, hashes[3]);
    checkpoint::install_from_test_oracle(&chain.store, NETWORK_MAGIC_REGTEST, 5, old).unwrap();

    let mut variants = Vec::new();
    let mut changed_network = oracle(4, hashes[4]);
    changed_network.dom_network_magic = dom_core::NETWORK_MAGIC_TESTNET;
    assert!(checkpoint::install_from_test_oracle(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        5,
        changed_network,
    )
    .unwrap_err()
    .to_string()
    .contains("DOM network mismatch"));
    let mut changed = oracle(4, hashes[4]);
    changed.ethereum_chain_id = 2;
    variants.push(changed);
    let mut changed = oracle(4, hashes[4]);
    changed.ethereum_genesis_validators_root = Hash256::from_bytes([1; 32]);
    variants.push(changed);
    let mut changed = oracle(4, hashes[4]);
    changed.checkpoint_contract = [1; 20];
    variants.push(changed);
    let mut changed = oracle(4, hashes[4]);
    changed.checkpoint_code_hash = Hash256::from_bytes([1; 32]);
    variants.push(changed);
    let mut changed = oracle(4, hashes[4]);
    changed.checkpoint_config_hash = Hash256::from_bytes([1; 32]);
    variants.push(rebind_event(changed));
    let mut changed = oracle(4, hashes[4]);
    changed.bridge_domain = Hash256::from_bytes([1; 32]);
    variants.push(rebind_event(changed));
    for changed in variants {
        let error =
            checkpoint::install_from_test_oracle(&chain.store, NETWORK_MAGIC_REGTEST, 5, changed)
                .unwrap_err();
        assert!(error
            .to_string()
            .contains("domain or configuration changed"));
    }

    let mut stale = oracle(4, hashes[4]);
    stale.ethereum_block_number = old.ethereum_block_number;
    stale.ethereum_block = old.ethereum_block;
    stale.ethereum_receipts_root = old.ethereum_receipts_root;
    stale.ethereum_state_root = old.ethereum_state_root;
    stale.ethereum_beacon_slot = old.ethereum_beacon_slot;
    stale.ethereum_beacon_root = old.ethereum_beacon_root;
    stale.transaction_index = old.transaction_index;
    stale.receipt_log_index = old.receipt_log_index;
    assert!(
        checkpoint::install_from_test_oracle(&chain.store, NETWORK_MAGIC_REGTEST, 5, stale,)
            .unwrap_err()
            .to_string()
            .contains("locator did not advance")
    );

    let mut conflicts = Vec::new();
    let mut conflicting = stale;
    conflicting.transaction_index += 1;
    conflicting.ethereum_block = Hash256::from_bytes([2; 32]);
    conflicts.push(conflicting);
    let mut conflicting = stale;
    conflicting.transaction_index += 1;
    conflicting.ethereum_receipts_root = Hash256::from_bytes([2; 32]);
    conflicts.push(conflicting);
    let mut conflicting = stale;
    conflicting.transaction_index += 1;
    conflicting.ethereum_state_root = Hash256::from_bytes([2; 32]);
    conflicts.push(conflicting);
    let mut conflicting = stale;
    conflicting.transaction_index += 1;
    conflicting.ethereum_beacon_slot += 1;
    conflicts.push(conflicting);
    let mut conflicting = stale;
    conflicting.transaction_index += 1;
    conflicting.ethereum_beacon_root = Hash256::from_bytes([2; 32]);
    conflicts.push(conflicting);
    for conflicting in conflicts {
        assert!(checkpoint::install_from_test_oracle(
            &chain.store,
            NETWORK_MAGIC_REGTEST,
            5,
            conflicting,
        )
        .unwrap_err()
        .to_string()
        .contains("conflicting finalized Ethereum block"));
    }

    let mut stale_beacon = oracle(4, hashes[4]);
    stale_beacon.ethereum_beacon_slot = old.ethereum_beacon_slot;
    assert!(checkpoint::install_from_test_oracle(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        5,
        stale_beacon,
    )
    .unwrap_err()
    .to_string()
    .contains("beacon slot did not advance"));

    let mut same_block_next_event = stale;
    same_block_next_event.transaction_index += 1;
    checkpoint::install_from_test_oracle(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        5,
        same_block_next_event,
    )
    .unwrap();
    assert_eq!(
        checkpoint::load(&chain.store).unwrap(),
        Some(same_block_next_event)
    );
}

#[test]
fn anchor_survives_restart_and_can_only_advance() {
    let (dir, chain, hashes) = canonical_chain();
    checkpoint::install_from_test_oracle(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        5,
        oracle(3, hashes[3]),
    )
    .unwrap();
    drop(chain);
    let chain = open_required(dir.path(), oracle(3, hashes[3])).unwrap();
    assert_eq!(
        checkpoint::load(&chain.store).unwrap(),
        Some(oracle(3, hashes[3]))
    );
    checkpoint::install_from_test_oracle(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        5,
        oracle(4, hashes[4]),
    )
    .unwrap();
    assert!(checkpoint::check_reorg(&chain.store, 5, 3).is_err());
}

#[test]
fn malformed_anchor_fails_closed_on_restart() {
    let (dir, chain, _) = canonical_chain();
    chain
        .store
        .put_metadata(checkpoint::CHECKPOINT_KEY, &[1, 2])
        .unwrap();
    drop(chain);
    let result = ChainState::open(
        common::open_test_store(dir.path()),
        Hash256::ZERO,
        NETWORK_MAGIC_REGTEST,
    );
    assert!(
        matches!(result, Err(error) if error.to_string().contains("malformed persisted checkpoint"))
    );
    let store = common::open_test_store(dir.path());
    store
        .put_metadata(checkpoint::CHECKPOINT_KEY, &vec![3; 417])
        .unwrap();
    drop(store);
    let result = ChainState::open(
        common::open_test_store(dir.path()),
        Hash256::ZERO,
        NETWORK_MAGIC_REGTEST,
    );
    require_error(result, "malformed persisted checkpoint");
}

#[test]
fn legacy_v1_anchor_fails_closed_instead_of_becoming_no_checkpoint() {
    let (dir, chain, _) = canonical_chain();
    chain
        .store
        .put_metadata(checkpoint::LEGACY_CHECKPOINT_KEY, &[1; 73])
        .unwrap();
    drop(chain);
    let result = ChainState::open(
        common::open_test_store(dir.path()),
        Hash256::ZERO,
        NETWORK_MAGIC_REGTEST,
    );
    require_error(result, "legacy v1 checkpoint requires explicit migration");
}

#[test]
fn persisted_anchor_conflicting_with_canonical_index_fails_closed() {
    let (_dir, chain, hashes) = canonical_chain();
    checkpoint::install_from_test_oracle(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        5,
        oracle(3, hashes[3]),
    )
    .unwrap();
    let block = header(hashes[2], 3, 999, 999);
    let bytes = block.to_bytes().unwrap();
    let hash = dom_crypto::hash::blake2b_256(&bytes);
    chain
        .store
        .commit_block(hash.as_bytes(), 3, &bytes, &[0; 8], &[], &[], &[])
        .unwrap();
    assert!(checkpoint::ensure_current(&chain.store, 5).is_err());
}

#[test]
fn restart_with_persisted_anchor_requires_external_floor() {
    let (dir, mut chain, hashes) = canonical_chain();
    chain.install_test_checkpoint(oracle(3, hashes[3])).unwrap();
    drop(chain);
    require_error(
        ChainState::open(
            common::open_test_store(dir.path()),
            Hash256::ZERO,
            NETWORK_MAGIC_REGTEST,
        ),
        "persisted checkpoint requires external floor",
    );
    open_required(dir.path(), oracle(3, hashes[3])).unwrap();
}

fn open_required(
    dir: &std::path::Path,
    floor: TestOracleCheckpoint,
) -> Result<ChainState, dom_core::DomError> {
    ChainState::open_with_test_checkpoint_floor(
        common::open_test_store(dir),
        Hash256::ZERO,
        NETWORK_MAGIC_REGTEST,
        floor,
    )
}

fn require_error(result: Result<ChainState, dom_core::DomError>, message: &str) {
    let error = match result {
        Ok(_) => panic!("unexpected successful startup"),
        Err(e) => e,
    };
    assert!(error.to_string().contains(message), "{error}");
}

#[test]
fn explicit_floor_rejects_deleted_anchor_without_recreating_it() {
    let (dir, mut chain, hashes) = canonical_chain();
    let floor = oracle(3, hashes[3]);
    chain.install_test_checkpoint(floor).unwrap();
    chain
        .store
        .delete_metadata(checkpoint::CHECKPOINT_KEY)
        .unwrap();
    drop(chain);
    require_error(
        open_required(dir.path(), floor),
        "required checkpoint is missing",
    );
    let store = common::open_test_store(dir.path());
    assert_eq!(checkpoint::load(&store).unwrap(), None);
    assert_eq!(store.get_chain_tip().unwrap(), Some(*hashes[5].as_bytes()));
}

#[test]
fn floor_rejects_stale_same_height_replacement_and_noncanonical_requirement() {
    let (dir, mut chain, hashes) = canonical_chain();
    chain.install_test_checkpoint(oracle(3, hashes[3])).unwrap();
    drop(chain);
    require_error(
        open_required(dir.path(), oracle(4, hashes[4])),
        "below required floor",
    );
    let mut replacement = oracle(3, hashes[3]);
    replacement.ethereum_block = Hash256::from_bytes([0xdd; 32]);
    require_error(
        open_required(dir.path(), replacement),
        "conflicts with required floor",
    );
    require_error(
        open_required(dir.path(), oracle(2, hashes[1])),
        "canonical history conflicts with required floor",
    );
    let mut zero = oracle(3, hashes[3]);
    zero.ethereum_block = Hash256::ZERO;
    require_error(
        open_required(dir.path(), zero),
        "invalid required checkpoint",
    );
}

#[test]
fn required_floor_checks_full_domain_and_ethereum_order_when_database_is_ahead() {
    let (dir, mut chain, hashes) = canonical_chain();
    chain.install_test_checkpoint(oracle(3, hashes[3])).unwrap();
    chain.install_test_checkpoint(oracle(4, hashes[4])).unwrap();
    drop(chain);

    let mut changed_domain = oracle(3, hashes[3]);
    changed_domain.checkpoint_config_hash = Hash256::from_bytes([7; 32]);
    changed_domain = rebind_event(changed_domain);
    require_error(
        open_required(dir.path(), changed_domain),
        "changed required domain",
    );

    let current = oracle(4, hashes[4]);
    let mut future_locator = oracle(3, hashes[3]);
    future_locator.ethereum_block_number = current.ethereum_block_number;
    future_locator.ethereum_block = current.ethereum_block;
    future_locator.ethereum_receipts_root = current.ethereum_receipts_root;
    future_locator.ethereum_state_root = current.ethereum_state_root;
    future_locator.ethereum_beacon_slot = current.ethereum_beacon_slot;
    future_locator.ethereum_beacon_root = current.ethereum_beacon_root;
    future_locator.transaction_index = current.transaction_index + 1;
    require_error(
        open_required(dir.path(), future_locator),
        "Ethereum locator did not reach required floor",
    );

    let mut conflicting_block = oracle(3, hashes[3]);
    conflicting_block.ethereum_block_number = current.ethereum_block_number;
    conflicting_block.transaction_index = current.transaction_index - 1;
    require_error(
        open_required(dir.path(), conflicting_block),
        "conflicting finalized Ethereum block identity",
    );
}

#[test]
fn every_required_v2_identity_component_is_nonzero() {
    let (_dir, mut chain, hashes) = canonical_chain();
    let valid = oracle(3, hashes[3]);
    chain.install_test_checkpoint(valid).unwrap();
    let mut variants = Vec::new();
    let mut value = valid;
    value.height = 0;
    variants.push(value);
    let mut value = valid;
    value.dom_block = Hash256::ZERO;
    variants.push(value);
    let mut value = valid;
    value.dom_state_root = Hash256::ZERO;
    variants.push(value);
    let mut value = valid;
    value.dom_network_magic = 0;
    variants.push(value);
    let mut value = valid;
    value.ethereum_chain_id = 0;
    variants.push(value);
    let mut value = valid;
    value.ethereum_block_number = 0;
    variants.push(value);
    let mut value = valid;
    value.ethereum_block = Hash256::ZERO;
    variants.push(value);
    let mut value = valid;
    value.ethereum_receipts_root = Hash256::ZERO;
    variants.push(value);
    let mut value = valid;
    value.ethereum_state_root = Hash256::ZERO;
    variants.push(value);
    let mut value = valid;
    value.ethereum_beacon_slot = 0;
    variants.push(value);
    let mut value = valid;
    value.ethereum_beacon_root = Hash256::ZERO;
    variants.push(value);
    let mut value = valid;
    value.ethereum_genesis_validators_root = Hash256::ZERO;
    variants.push(value);
    let mut value = valid;
    value.checkpoint_contract = [0; 20];
    variants.push(value);
    let mut value = valid;
    value.checkpoint_code_hash = Hash256::ZERO;
    variants.push(value);
    let mut value = valid;
    value.checkpoint_config_hash = Hash256::ZERO;
    variants.push(value);
    let mut value = valid;
    value.bridge_domain = Hash256::ZERO;
    variants.push(value);
    let mut value = valid;
    value.checkpoint_event_digest = Hash256::ZERO;
    variants.push(value);
    for invalid in variants {
        assert!(checkpoint::ensure_at_least(&chain.store, 5, Some(invalid))
            .unwrap_err()
            .to_string()
            .contains("invalid required checkpoint"));
    }
}

#[test]
fn deletion_during_runtime_blocks_known_block_ingress_and_reorg_before_mutation() {
    let (_dir, mut chain, hashes) = canonical_chain();
    chain.install_test_checkpoint(oracle(3, hashes[3])).unwrap();
    chain
        .store
        .delete_metadata(checkpoint::CHECKPOINT_KEY)
        .unwrap();
    let error = chain
        .connect_block(&canonical_blocks()[5], Timestamp(2_000_000_000))
        .unwrap_err();
    assert!(error.to_string().contains("required checkpoint is missing"));
    let error = chain
        .promote_heavier_known_tip(Hash256::from_bytes([0xab; 32]), Timestamp(2_000_000_000))
        .unwrap_err();
    assert!(error.to_string().contains("required checkpoint is missing"));
    assert_eq!(chain.tip_hash, hashes[5]);
    assert_eq!(
        chain.store.get_chain_tip().unwrap(),
        Some(*hashes[5].as_bytes())
    );
    let raw = canonical_blocks()[5].header.to_bytes().unwrap();
    assert!(chain
        .validate_ibd_headers_batch(std::slice::from_ref(&raw), Timestamp(2_000_000_000))
        .unwrap_err()
        .to_string()
        .contains("required checkpoint is missing"));
    assert!(chain
        .validate_ibd_header_step(&[raw], 0, &[], Timestamp(2_000_000_000))
        .unwrap_err()
        .to_string()
        .contains("required checkpoint is missing"));
    assert!(chain
        .validate_header_only(&canonical_blocks()[5].header, Timestamp(2_000_000_000))
        .unwrap_err()
        .to_string()
        .contains("required checkpoint is missing"));
    assert!(chain
        .next_block_target()
        .unwrap_err()
        .to_string()
        .contains("required checkpoint is missing"));
    assert!(chain.install_test_checkpoint(oracle(4, hashes[4])).is_err());
}

#[test]
fn newer_observed_anchor_is_remembered_even_with_an_older_startup_floor() {
    let (dir, mut chain, hashes) = canonical_chain();
    chain.install_test_checkpoint(oracle(3, hashes[3])).unwrap();
    let old = chain
        .store
        .get_metadata(checkpoint::CHECKPOINT_KEY)
        .unwrap()
        .unwrap();
    chain.install_test_checkpoint(oracle(4, hashes[4])).unwrap();
    drop(chain);
    let mut chain = open_required(dir.path(), oracle(3, hashes[3])).unwrap();
    chain
        .store
        .put_metadata(checkpoint::CHECKPOINT_KEY, &old)
        .unwrap();
    let error = chain
        .connect_block(&canonical_blocks()[5], Timestamp(2_000_000_000))
        .unwrap_err();
    assert!(error.to_string().contains("below required floor"));
    assert_eq!(chain.tip_hash, hashes[5]);
}

#[test]
fn runtime_installation_advances_floor_and_failed_install_does_not_lower_it() {
    let (_dir, mut chain, hashes) = canonical_chain();
    chain.install_test_checkpoint(oracle(3, hashes[3])).unwrap();
    let old = chain
        .store
        .get_metadata(checkpoint::CHECKPOINT_KEY)
        .unwrap()
        .unwrap();
    chain.install_test_checkpoint(oracle(4, hashes[4])).unwrap();
    assert!(chain.install_test_checkpoint(oracle(2, hashes[2])).is_err());
    assert_eq!(
        checkpoint::load(&chain.store).unwrap(),
        Some(oracle(4, hashes[4]))
    );
    chain
        .store
        .put_metadata(checkpoint::CHECKPOINT_KEY, &old)
        .unwrap();
    assert!(chain
        .connect_block(&canonical_blocks()[5], Timestamp(2_000_000_000))
        .unwrap_err()
        .to_string()
        .contains("below required floor"));
}

#[test]
fn restoring_an_actual_older_database_requires_an_independent_current_floor() {
    let (dir, mut chain, hashes) = canonical_chain();
    chain.install_test_checkpoint(oracle(3, hashes[3])).unwrap();
    drop(chain);
    // Copy a closed, consistent LMDB data file, not a live/mid-write snapshot.
    let snapshot = TempDir::new().unwrap();
    std::fs::copy(
        dir.path().join("data.mdb"),
        snapshot.path().join("data.mdb"),
    )
    .unwrap();
    let mut chain = open_required(dir.path(), oracle(3, hashes[3])).unwrap();
    chain.install_test_checkpoint(oracle(4, hashes[4])).unwrap();
    drop(chain);
    require_error(
        open_required(snapshot.path(), oracle(4, hashes[4])),
        "below required floor",
    );
    // Demonstrates the residual trust boundary, not a production-safe fallback:
    // a caller who also supplies the obsolete floor cannot detect full rollback.
    let old = open_required(snapshot.path(), oracle(3, hashes[3])).unwrap();
    assert_eq!(
        checkpoint::load(&old.store).unwrap(),
        Some(oracle(3, hashes[3]))
    );
}

#[test]
fn exact_oracle_restoration_recovers_without_changing_canonical_state() {
    let (dir, mut chain, hashes) = canonical_chain();
    let floor = oracle(3, hashes[3]);
    chain.install_test_checkpoint(floor).unwrap();
    chain
        .store
        .delete_metadata(checkpoint::CHECKPOINT_KEY)
        .unwrap();
    drop(chain);
    require_error(
        open_required(dir.path(), floor),
        "required checkpoint is missing",
    );
    let store = common::open_test_store(dir.path());
    // Explicit test-oracle repair. No automatic downgrade or operational bypass.
    checkpoint::install_from_test_oracle(&store, NETWORK_MAGIC_REGTEST, 5, floor).unwrap();
    drop(store);
    let chain = open_required(dir.path(), floor).unwrap();
    assert_eq!(chain.tip_hash, hashes[5]);
    assert_eq!(checkpoint::load(&chain.store).unwrap(), Some(floor));
    assert!(checkpoint::check_reorg(&chain.store, 5, 2).is_err());
}

#[test]
fn fresh_store_and_nonregtest_cannot_satisfy_test_floor() {
    let empty = TempDir::new().unwrap();
    let floor = oracle(3, Hash256::from_bytes([0xcc; 32]));
    require_error(
        open_required(empty.path(), floor),
        "required checkpoint is missing",
    );
    let store = common::open_test_store(empty.path());
    assert!(store.get_chain_tip().unwrap().is_none());
    require_error(
        ChainState::open_with_test_checkpoint_floor(
            store,
            Hash256::ZERO,
            dom_core::NETWORK_MAGIC_MAINNET,
            floor,
        ),
        "test floor is regtest-only",
    );
}

#[test]
fn failed_checkpoint_startup_does_not_repair_kernel_index_first() {
    use lmdb::Transaction;
    for mode in 0..3 {
        let (dir, mut chain, hashes) = canonical_chain();
        let floor = oracle(3, hashes[3]);
        chain.install_test_checkpoint(floor).unwrap();
        let excess = *canonical_blocks()[3].coinbase.kernel.excess.as_bytes();
        let mut txn = chain.store.env.begin_rw_txn().unwrap();
        txn.del(chain.store.db_kernels, &excess, None).unwrap();
        txn.commit().unwrap();
        assert!(chain.store.get_kernel_block(&excess).unwrap().is_none());
        if mode == 0 {
            chain
                .store
                .delete_metadata(checkpoint::CHECKPOINT_KEY)
                .unwrap();
        } else {
            chain
                .store
                .put_metadata(checkpoint::CHECKPOINT_KEY, &[1, 2])
                .unwrap();
        }
        drop(chain);
        if mode == 0 {
            require_error(
                open_required(dir.path(), floor),
                "required checkpoint is missing",
            );
        } else {
            let store = common::open_test_store(dir.path());
            let result = if mode == 1 {
                ChainState::open(store, Hash256::ZERO, NETWORK_MAGIC_REGTEST)
            } else {
                ChainState::open_with_utxo_repair(store, Hash256::ZERO, NETWORK_MAGIC_REGTEST)
            };
            require_error(result, "malformed persisted checkpoint");
        }
        let store = common::open_test_store(dir.path());
        assert!(
            store.get_kernel_block(&excess).unwrap().is_none(),
            "rejected startup repaired kernel index in mode {mode}"
        );
        assert_eq!(store.get_chain_tip().unwrap(), Some(*hashes[5].as_bytes()));
    }
}
