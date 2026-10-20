#![cfg(feature = "native-usdom-v4-poc")]

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use dom_chain::{
    build_canonical_genesis, genesis_canonical_changeset, native_usdom_v4_activation_updates,
    native_usdom_v4_activation_updates_for_schedule, native_usdom_v4_regtest_activation_schedule,
    ChainState, ConnectResult, NativeUsdomV4SnapshotManifest, UsdomV2ExecutionWitnesses,
    UsdomV4BlockPackage, UsdomV4ProofEnvelope,
};
use dom_config::{Network, NodeConfig};
use dom_consensus::block::ProofOfWork;
use dom_consensus::{
    bind_usdom_batch_commitment, compute_block_pmmr_roots, derive_chain_id, Block, CoinbaseKernel,
    CoinbaseTransaction, TransactionOutput,
};
use dom_core::{
    BlockHeight, DomError, Hash256, Timestamp, BLOCK_VERSION_V4, KERNEL_FEAT_COINBASE,
    MAX_FUTURE_BLOCK_TIME, NETWORK_MAGIC_REGTEST, TAG_KERNEL_MSG_COINBASE, TARGET_SPACING,
};
use dom_crypto::pedersen::Commitment;
use dom_crypto::{blake2b_256_tagged, schnorr_sign, BlindingFactor, SecretKey};
use dom_node::node::DomNode;
use dom_node::node_handle::NodeHandleImpl;
use dom_pow::{
    fast_pow_hash, hash_meets_target, target_to_compact, target_to_difficulty_for_network_height,
    CompactTarget,
};
use dom_rpc::{NodeHandle, RpcError, UsdomV4HistoryAnchorV1, UsdomV4HistoryRequestV1};
use dom_serialization::DomSerialize;
use dom_store::DomStore;
use dom_usdom_privacy::{circuit::SpendCircuit, verifier::SpendVerifier};
use dom_usdom_state::{
    apply_v2_transition_batch_with_receipt, BlockContext, BridgeIdentity, BurnTimingPolicy,
    NativeUsdomState, StateCommitmentV2,
};
use dom_wire::message::{UsdomV2PackagePayload, UsdomV4PackagePayload};
use rand::{rngs::StdRng, SeedableRng};
use tempfile::TempDir;
use usdom_ethereum_finality_experiment::{
    checkpoints::{CheckpointPolicy, CheckpointTrustPolicy, StaticCheckpointTrustPolicy},
    deposits::{DepositTrustPolicy, ReserveDepositPolicy, StaticDepositTrustPolicy},
    EthereumForks,
};

const TEST_MAP_SIZE: usize = 64 << 20;
const DOMAIN: [u8; 32] = [0x11; 32];

fn policy() -> StaticCheckpointTrustPolicy {
    StaticCheckpointTrustPolicy::from_trust_policy(&CheckpointTrustPolicy {
        trusted_checkpoint: [0x41; 32].into(),
        ethereum_genesis_validators_root: [0x22; 32].into(),
        forks: EthereumForks::default(),
        max_current_slot: 1,
        checkpoint: CheckpointPolicy {
            ethereum_chain_id: 1,
            ethereum_genesis_validators_root: [0x22; 32].into(),
            registry: [0x42; 20].into(),
            runtime_code_hash: [0x43; 32].into(),
            config_storage_slot: [0x44; 32].into(),
            checkpoint_config_hash: [0x45; 32].into(),
            bridge_domain: DOMAIN.into(),
            dom_network_magic: NETWORK_MAGIC_REGTEST,
        },
    })
    .unwrap()
}

fn deposit_policy() -> StaticDepositTrustPolicy {
    StaticDepositTrustPolicy::from_trust_policy(&DepositTrustPolicy {
        trusted_checkpoint: [0x41; 32].into(),
        ethereum_genesis_validators_root: [0x22; 32].into(),
        forks: EthereumForks::default(),
        max_current_slot: 1,
        deposit: ReserveDepositPolicy {
            ethereum_chain_id: 1,
            ethereum_genesis_validators_root: [0x22; 32].into(),
            reserve: [0x33; 20].into(),
            runtime_code_hash: [0x46; 32].into(),
            bridge_domain: DOMAIN.into(),
            max_amount: 100_000_000_000,
        },
    })
    .unwrap()
}

fn bridge() -> BridgeIdentity {
    let mut ethereum_chain_id = [0; 32];
    ethereum_chain_id[31] = 1;
    BridgeIdentity {
        dom_domain: DOMAIN,
        ethereum_genesis_validators_root: [0x22; 32],
        ethereum_chain_id,
        ethereum_checkpoint_policy_hash: policy().policy_hash().into(),
        ethereum_deposit_policy_hash: deposit_policy().policy_hash().into(),
        privacy_policy_hash: *dom_chain::native_usdom_v4::native_usdom_privacy_policy_hash()
            .as_bytes(),
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

fn config(dir: &TempDir, network: Network) -> NodeConfig {
    let mut config = match network {
        Network::Mainnet => NodeConfig::mainnet(),
        Network::Testnet => NodeConfig::testnet(),
        Network::Regtest => NodeConfig::regtest(),
    };
    config.data_dir = dir.path().to_string_lossy().into_owned();
    config.mine = false;
    config.wallet_path = None;
    config.wallet_password = None;
    config
}

fn free_p2p_addr() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

fn activate_native_genesis(dir: &TempDir) -> (dom_chain::CanonicalGenesis, Hash256) {
    let configured =
        dom_core::configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST).unwrap();
    let chain_id = derive_chain_id(NETWORK_MAGIC_REGTEST, &configured);
    let canonical = build_canonical_genesis(NETWORK_MAGIC_REGTEST, chain_id.as_bytes()).unwrap();
    let block = canonical.block.as_ref().unwrap();
    let (new_utxos, spent_utxos, kernel_excesses) =
        genesis_canonical_changeset(block, canonical.hash);
    let activation_state = NativeUsdomState::new(bridge()).unwrap();
    let updates = native_usdom_v4_activation_updates(&activation_state, canonical.hash).unwrap();
    let store = DomStore::open_with_map_size(dir.path(), TEST_MAP_SIZE).unwrap();
    store
        .commit_block_with_consensus_state(
            canonical.hash.as_bytes(),
            0,
            &canonical.header_bytes,
            &canonical.block_bytes,
            &new_utxos,
            &spent_utxos,
            &kernel_excesses,
            &updates,
        )
        .unwrap();
    drop(store);
    (canonical, chain_id)
}

fn test_spend_key_and_bridge() -> (Vec<u8>, BridgeIdentity) {
    static FIXTURE: std::sync::OnceLock<(Vec<u8>, BridgeIdentity)> = std::sync::OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let mut rng = StdRng::seed_from_u64(0x4e4f_4445_5632_5254);
            let parameters = Groth16::<Bn254>::generate_random_parameters_with_reduction(
                SpendCircuit::default(),
                &mut rng,
            )
            .unwrap();
            let mut key_bytes = Vec::new();
            parameters.vk.serialize_compressed(&mut key_bytes).unwrap();
            let verifier = SpendVerifier::from_bytes(&key_bytes).unwrap();
            let mut selected_bridge = bridge();
            selected_bridge.privacy_verifier_config_hash = *verifier.config_hash().as_bytes();
            (key_bytes, selected_bridge)
        })
        .clone()
}

fn activate_scheduled_genesis(
    dir: &TempDir,
    selected_bridge: BridgeIdentity,
) -> (
    dom_chain::CanonicalGenesis,
    Hash256,
    dom_chain::NativeUsdomV4ActivationSchedule,
) {
    let configured =
        dom_core::configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST).unwrap();
    let chain_id = derive_chain_id(NETWORK_MAGIC_REGTEST, &configured);
    let canonical = build_canonical_genesis(NETWORK_MAGIC_REGTEST, chain_id.as_bytes()).unwrap();
    let block = canonical.block.as_ref().unwrap();
    let (new_utxos, spent_utxos, kernel_excesses) =
        genesis_canonical_changeset(block, canonical.hash);
    let state = NativeUsdomState::new(selected_bridge).unwrap();
    let v1_schedule = native_usdom_v4_regtest_activation_schedule(selected_bridge).unwrap();
    let updates =
        native_usdom_v4_activation_updates_for_schedule(&state, v1_schedule, canonical.hash, 0)
            .unwrap();
    let store = DomStore::open_with_map_size(dir.path(), TEST_MAP_SIZE).unwrap();
    store
        .commit_block_with_consensus_state(
            canonical.hash.as_bytes(),
            0,
            &canonical.header_bytes,
            &canonical.block_bytes,
            &new_utxos,
            &spent_utxos,
            &kernel_excesses,
            &updates,
        )
        .unwrap();
    drop(store);
    (canonical, chain_id, v1_schedule)
}

fn connect_final_v1_child(
    dir: &TempDir,
    canonical: &dom_chain::CanonicalGenesis,
    chain_id: Hash256,
    selected_bridge: BridgeIdentity,
    key_bytes: &[u8],
    v1_schedule: dom_chain::NativeUsdomV4ActivationSchedule,
    activate_v2: bool,
) {
    let verifier = SpendVerifier::from_bytes(key_bytes).unwrap();
    let store = DomStore::open_with_map_size(dir.path(), TEST_MAP_SIZE).unwrap();
    let mut chain =
        ChainState::open_with_utxo_repair(store, canonical.hash, NETWORK_MAGIC_REGTEST).unwrap();
    let mut state = NativeUsdomState::new(selected_bridge).unwrap();
    let parent = canonical.block.as_ref().unwrap();
    let child = mine_v4_child(
        parent,
        canonical.hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
    );
    let package = UsdomV4BlockPackage::new(child.clone(), UsdomV4ProofEnvelope::empty())
        .unwrap()
        .to_bytes()
        .unwrap();
    if activate_v2 {
        chain
            .connect_usdom_v4_package_and_activate_v2_for_schedule(
                &package,
                child.header.timestamp,
                &mut state,
                selected_bridge,
                &policy(),
                &deposit_policy(),
                &verifier,
                v1_schedule,
                2,
            )
            .unwrap();
    } else {
        chain
            .connect_usdom_v4_package_for_schedule(
                &package,
                child.header.timestamp,
                &mut state,
                selected_bridge,
                &policy(),
                &deposit_policy(),
                &verifier,
                v1_schedule,
            )
            .unwrap();
    }
}

#[tokio::test]
async fn candidate_startup_selects_one_persisted_phase_and_rejects_missing_boundary_marker() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    std::env::set_var("DOM_PORTMAP", "off");
    let (key_bytes, selected_bridge) = test_spend_key_and_bridge();

    let v1_dir = TempDir::new().unwrap();
    let (v1_canonical, v1_chain_id, v1_schedule) =
        activate_scheduled_genesis(&v1_dir, selected_bridge);
    let v1_node =
        DomNode::init_native_usdom_candidate_for_schedule_with_spend_verifier_and_map_size(
            config(&v1_dir, Network::Regtest),
            TEST_MAP_SIZE,
            selected_bridge,
            policy(),
            deposit_policy(),
            &key_bytes,
            v1_schedule,
            2,
        )
        .unwrap();
    assert!(v1_node.has_native_usdom_v4_runtime());
    assert!(!v1_node.has_native_usdom_v2_runtime());
    let activation_state = NativeUsdomState::new(selected_bridge).unwrap();
    let final_v1 = mine_v4_child(
        v1_canonical.block.as_ref().unwrap(),
        v1_canonical.hash,
        v1_canonical.hash,
        &activation_state,
        v1_chain_id.as_bytes(),
    );
    let final_v1_package =
        UsdomV4BlockPackage::new(final_v1.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
    let final_v1_wire = UsdomV4PackagePayload {
        package_bytes: final_v1_package,
    }
    .to_bytes()
    .unwrap();
    assert_eq!(
        v1_node
            .ingest_native_usdom_v4_wire_payload(&final_v1_wire, final_v1.header.timestamp)
            .await
            .unwrap(),
        ConnectResult::BestChain
    );
    assert!(
        v1_node.shutdown_token().is_shutdown(),
        "committing the V1/V2 boundary must request a coordinated restart"
    );
    drop(v1_node);

    let v2_node =
        DomNode::init_native_usdom_candidate_for_schedule_with_spend_verifier_and_map_size(
            config(&v1_dir, Network::Regtest),
            TEST_MAP_SIZE,
            selected_bridge,
            policy(),
            deposit_policy(),
            &key_bytes,
            v1_schedule,
            2,
        )
        .unwrap();
    assert!(!v2_node.has_native_usdom_v4_runtime());
    assert!(v2_node.has_native_usdom_v2_runtime());
    let final_v1_hash = dom_chain::canonical_header_identifier(
        NETWORK_MAGIC_REGTEST,
        &final_v1.header.to_bytes().unwrap(),
    )
    .unwrap();
    let v2_state = activation_state.state_commitment_v2().unwrap();
    let first_v2 = mine_dom_child_with_empty_usdom_v2_batch(
        &final_v1,
        final_v1_hash,
        v1_canonical.hash,
        v2_state,
        v1_chain_id.as_bytes(),
    );
    let first_v2_package =
        UsdomV4BlockPackage::new(first_v2.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
    let witnesses = UsdomV2ExecutionWitnesses::new(Vec::new())
        .unwrap()
        .to_bytes()
        .unwrap();
    let first_v2_wire = UsdomV2PackagePayload {
        package_bytes: first_v2_package,
        witness_bytes: witnesses,
    }
    .to_bytes()
    .unwrap();
    assert_eq!(
        v2_node
            .ingest_native_usdom_v2_wire_payload(&first_v2_wire, first_v2.header.timestamp)
            .await
            .unwrap(),
        ConnectResult::BestChain
    );
    assert_eq!(v2_node.chain.lock().await.tip_height, BlockHeight(2));
    drop(v2_node);

    let restarted_v2 =
        DomNode::init_native_usdom_candidate_for_schedule_with_spend_verifier_and_map_size(
            config(&v1_dir, Network::Regtest),
            TEST_MAP_SIZE,
            selected_bridge,
            policy(),
            deposit_policy(),
            &key_bytes,
            v1_schedule,
            2,
        )
        .unwrap();
    assert!(!restarted_v2.has_native_usdom_v4_runtime());
    assert!(restarted_v2.has_native_usdom_v2_runtime());
    assert_eq!(restarted_v2.chain.lock().await.tip_height, BlockHeight(2));
    drop(restarted_v2);

    let wrong_height =
        match DomNode::init_native_usdom_candidate_for_schedule_with_spend_verifier_and_map_size(
            config(&v1_dir, Network::Regtest),
            TEST_MAP_SIZE,
            selected_bridge,
            policy(),
            deposit_policy(),
            &key_bytes,
            v1_schedule,
            3,
        ) {
            Ok(_) => panic!("wrong persisted candidate-V2 height must fail closed"),
            Err(error) => error,
        };
    assert!(
        wrong_height
            .to_string()
            .contains("differs from the hash-pinned manifest"),
        "unexpected wrong-height error: {wrong_height}"
    );

    let missing_dir = TempDir::new().unwrap();
    let (missing_canonical, missing_chain_id, missing_v1_schedule) =
        activate_scheduled_genesis(&missing_dir, selected_bridge);
    connect_final_v1_child(
        &missing_dir,
        &missing_canonical,
        missing_chain_id,
        selected_bridge,
        &key_bytes,
        missing_v1_schedule,
        false,
    );
    let missing =
        match DomNode::init_native_usdom_candidate_for_schedule_with_spend_verifier_and_map_size(
            config(&missing_dir, Network::Regtest),
            TEST_MAP_SIZE,
            selected_bridge,
            policy(),
            deposit_policy(),
            &key_bytes,
            missing_v1_schedule,
            2,
        ) {
            Ok(_) => panic!("missing migration marker must fail closed"),
            Err(error) => error,
        };
    assert!(missing
        .to_string()
        .contains("without its atomic migration marker"));
}

fn build_coinbase(
    height: BlockHeight,
    chain_id: &[u8; 32],
    discriminator: u8,
) -> CoinbaseTransaction {
    let explicit_value = dom_core::block_reward(height).noms();
    let mut scalar = [0u8; 32];
    scalar[31] = discriminator;
    let blinding = BlindingFactor::from_bytes(scalar).unwrap();
    let commitment = Commitment::commit(explicit_value, &blinding);
    let (proof, _) = dom_crypto::bp2_prove(explicit_value, &blinding).unwrap();
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

fn mine_v4_child(
    parent: &Block,
    parent_hash: Hash256,
    pow_seed: Hash256,
    state: &NativeUsdomState,
    chain_id: &[u8; 32],
) -> Block {
    let height = parent.header.height.checked_next().unwrap();
    let timestamp = parent
        .header
        .timestamp
        .checked_add_secs(TARGET_SPACING)
        .unwrap();
    let coinbase = build_coinbase(height, chain_id, 0x40u8.wrapping_add(height.0 as u8));
    let (output_root, kernel_root, raw_rangeproof_root) =
        compute_block_pmmr_roots(height, &coinbase, &[]).unwrap();
    let mut preview = state.clone();
    let (receipt, _) = preview
        .apply_batch(
            BlockContext {
                timestamp: timestamp.0,
            },
            &[],
        )
        .unwrap();
    let rangeproof_root =
        bind_usdom_batch_commitment(raw_rangeproof_root, receipt.header_commitment).unwrap();
    let target =
        dom_pow::compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, height).unwrap();
    let total_difficulty = parent.header.total_difficulty
        + target_to_difficulty_for_network_height(NETWORK_MAGIC_REGTEST, height, &target).unwrap();
    let compact = CompactTarget(target_to_compact(&target));
    let canonical_target = compact.to_target().unwrap();
    let mut nonce = 0u64;
    loop {
        let mut header = dom_consensus::BlockHeader {
            version: BLOCK_VERSION_V4,
            height,
            prev_hash: parent_hash,
            timestamp,
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: [0; 32],
            target: compact,
            total_difficulty,
            pow: ProofOfWork {
                nonce,
                randomx_hash: Hash256::ZERO,
            },
        };
        let hash = fast_pow_hash(pow_seed.as_bytes(), &header.pow_preimage());
        if hash_meets_target(&hash, &canonical_target) {
            header.pow.randomx_hash = Hash256::from_bytes(hash);
            return Block {
                header,
                coinbase,
                transactions: vec![],
            };
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// Mine a DOM regtest block whose USDOM V2 transition batch is empty.
/// The coinbase is the ordinary DOM coinbase; an empty USDOM batch issues no USDOM.
fn mine_dom_child_with_empty_usdom_v2_batch(
    parent: &Block,
    parent_hash: Hash256,
    pow_seed: Hash256,
    state: StateCommitmentV2,
    chain_id: &[u8; 32],
) -> Block {
    let height = parent.header.height.checked_next().unwrap();
    let timestamp = parent
        .header
        .timestamp
        .checked_add_secs(TARGET_SPACING)
        .unwrap();
    let coinbase = build_coinbase(height, chain_id, 0x72);
    let (output_root, kernel_root, raw_rangeproof_root) =
        compute_block_pmmr_roots(height, &coinbase, &[]).unwrap();
    let (_, receipt) = apply_v2_transition_batch_with_receipt(
        state.root(),
        BlockContext {
            timestamp: timestamp.0,
        },
        state,
        &[],
        &[],
    )
    .unwrap();
    let rangeproof_root =
        bind_usdom_batch_commitment(raw_rangeproof_root, receipt.header_commitment).unwrap();
    let target =
        dom_pow::compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, height).unwrap();
    let total_difficulty = parent.header.total_difficulty
        + target_to_difficulty_for_network_height(NETWORK_MAGIC_REGTEST, height, &target).unwrap();
    let compact = CompactTarget(target_to_compact(&target));
    let canonical_target = compact.to_target().unwrap();
    let mut nonce = 0u64;
    loop {
        let mut header = dom_consensus::BlockHeader {
            version: BLOCK_VERSION_V4,
            height,
            prev_hash: parent_hash,
            timestamp,
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: [0; 32],
            target: compact,
            total_difficulty,
            pow: ProofOfWork {
                nonce,
                randomx_hash: Hash256::ZERO,
            },
        };
        let hash = fast_pow_hash(pow_seed.as_bytes(), &header.pow_preimage());
        if hash_meets_target(&hash, &canonical_target) {
            header.pow.randomx_hash = Hash256::from_bytes(hash);
            return Block {
                header,
                coinbase,
                transactions: vec![],
            };
        }
        nonce = nonce.wrapping_add(1);
    }
}

#[tokio::test]
async fn native_runtime_requires_explicit_regtest_activation_and_exact_wire_framing() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    std::env::set_var("DOM_PORTMAP", "off");
    let ordinary_dir = TempDir::new().unwrap();
    let ordinary =
        DomNode::init_with_map_size(config(&ordinary_dir, Network::Regtest), TEST_MAP_SIZE)
            .expect("initialize ordinary Regtest node");
    assert!(!ordinary.has_native_usdom_v4_runtime());
    drop(ordinary);
    let unactivated = DomNode::init_native_usdom_v4_regtest_with_map_size(
        config(&ordinary_dir, Network::Regtest),
        TEST_MAP_SIZE,
        bridge(),
        policy(),
        deposit_policy(),
    );
    assert!(unactivated.is_err());

    let dir = TempDir::new().unwrap();
    let configured =
        dom_core::configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST).unwrap();
    let chain_id = derive_chain_id(NETWORK_MAGIC_REGTEST, &configured);
    let canonical = build_canonical_genesis(NETWORK_MAGIC_REGTEST, chain_id.as_bytes()).unwrap();
    assert_eq!(canonical.hash, configured);
    let block = canonical.block.as_ref().unwrap();
    let (new_utxos, spent_utxos, kernel_excesses) =
        genesis_canonical_changeset(block, canonical.hash);
    let activation_state = NativeUsdomState::new(bridge()).unwrap();
    let updates = native_usdom_v4_activation_updates(&activation_state, canonical.hash).unwrap();
    let store = DomStore::open_with_map_size(dir.path(), TEST_MAP_SIZE).unwrap();
    store
        .commit_block_with_consensus_state(
            canonical.hash.as_bytes(),
            0,
            &canonical.header_bytes,
            &canonical.block_bytes,
            &new_utxos,
            &spent_utxos,
            &kernel_excesses,
            &updates,
        )
        .unwrap();
    drop(store);

    let ordinary_after_activation =
        DomNode::init_with_map_size(config(&dir, Network::Regtest), TEST_MAP_SIZE);
    let error = match ordinary_after_activation {
        Ok(_) => panic!("ordinary constructor must reject an activated native data directory"),
        Err(error) => error,
    };
    assert!(matches!(error, dom_core::DomError::PolicyRejected(_)));
    assert!(error
        .to_string()
        .contains("native USDOM v4 is activated in this data directory"));

    assert!(
        DomNode::init_native_usdom_v4_regtest_with_spend_verifier_and_map_size(
            config(&dir, Network::Regtest),
            TEST_MAP_SIZE,
            bridge(),
            policy(),
            deposit_policy(),
            b"malformed verifying key",
        )
        .is_err()
    );

    let native = DomNode::init_native_usdom_v4_regtest_with_map_size(
        config(&dir, Network::Regtest),
        TEST_MAP_SIZE,
        bridge(),
        policy(),
        deposit_policy(),
    )
    .expect("restore activated native runtime");
    assert!(native.has_native_usdom_v4_runtime());
    let mut accepted_relays = native.subscribe_native_usdom_v4_relays();
    let original_tip = native.chain.lock().await.tip_hash;

    assert!(native
        .submit_native_usdom_v4_mining_envelope_regtest(
            &UsdomV4ProofEnvelope::empty().to_bytes().unwrap(),
            block.header.timestamp.checked_add_secs(1).unwrap(),
        )
        .await
        .is_err());
    assert!(native
        .submit_native_usdom_v4_mining_envelope_regtest(
            &UsdomV4ProofEnvelope::private_transfer_proof(vec![1])
                .unwrap()
                .to_bytes()
                .unwrap(),
            block.header.timestamp.checked_add_secs(1).unwrap(),
        )
        .await
        .is_err());
    assert_eq!(
        native
            .metrics
            .native_usdom_v4_mining_admission_rejected
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
    assert_eq!(
        native
            .metrics
            .native_usdom_v4_mining_candidates
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );

    assert!(native
        .ingest_native_usdom_v4_wire_payload_regtest(b"not framed", Timestamp(1))
        .await
        .is_err());
    let framed_but_not_package = UsdomV4PackagePayload {
        package_bytes: vec![0x99],
    }
    .to_bytes()
    .unwrap();
    assert!(native
        .ingest_native_usdom_v4_wire_payload_regtest(&framed_but_not_package, Timestamp(1))
        .await
        .is_err());
    assert_eq!(native.chain.lock().await.tip_hash, original_tip);
    assert!(matches!(
        accepted_relays.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    let state = NativeUsdomState::new(bridge()).unwrap();
    let child = mine_v4_child(
        block,
        canonical.hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
    );
    let package = UsdomV4BlockPackage::new(child.clone(), UsdomV4ProofEnvelope::empty())
        .unwrap()
        .to_bytes()
        .unwrap();
    let wire_payload = UsdomV4PackagePayload {
        package_bytes: package,
    }
    .to_bytes()
    .unwrap();
    let result = native
        .ingest_native_usdom_v4_wire_payload_regtest(
            &wire_payload,
            Timestamp(child.header.timestamp.0 + MAX_FUTURE_BLOCK_TIME),
        )
        .await
        .expect("valid canonical package must commit");
    assert_eq!(result, ConnectResult::BestChain);
    assert_eq!(native.chain.lock().await.tip_height, BlockHeight(1));
    let relay = accepted_relays.recv().await.unwrap();
    assert_eq!(relay.wire_payload, wire_payload);
    assert_eq!(relay.exclude_peer, None);
}

#[tokio::test]
async fn authenticated_history_rpc_pages_are_tip_domain_and_state_anchored() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let dir = TempDir::new().unwrap();
    let (canonical, chain_id) = activate_native_genesis(&dir);
    let node = std::sync::Arc::new(
        DomNode::init_native_usdom_v4_regtest_with_map_size(
            config(&dir, Network::Regtest),
            TEST_MAP_SIZE,
            bridge(),
            policy(),
            deposit_policy(),
        )
        .unwrap(),
    );
    let state = NativeUsdomState::new(bridge()).unwrap();
    let parent = canonical.block.as_ref().unwrap();
    let child = mine_v4_child(
        parent,
        canonical.hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
    );
    let child_hash =
        Hash256::from_bytes(*dom_crypto::blake2b_256(&child.header.to_bytes().unwrap()).as_bytes());
    let grandchild = mine_v4_child(
        &child,
        child_hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
    );
    let grandchild_hash = Hash256::from_bytes(
        *dom_crypto::blake2b_256(&grandchild.header.to_bytes().unwrap()).as_bytes(),
    );
    let wire = |block: Block| {
        UsdomV4PackagePayload {
            package_bytes: UsdomV4BlockPackage::new(block, UsdomV4ProofEnvelope::empty())
                .unwrap()
                .to_bytes()
                .unwrap(),
        }
        .to_bytes()
        .unwrap()
    };
    let now = Timestamp(grandchild.header.timestamp.0 + MAX_FUTURE_BLOCK_TIME);
    node.ingest_native_usdom_v4_wire_payload_regtest(&wire(child), now)
        .await
        .unwrap();
    node.ingest_native_usdom_v4_wire_payload_regtest(&wire(grandchild), now)
        .await
        .unwrap();

    let handle = NodeHandleImpl(std::sync::Arc::clone(&node));
    let initial_anchor = UsdomV4HistoryAnchorV1 {
        height: 0,
        block_hash: *canonical.hash.as_bytes(),
        state_root: *state.state_root().as_bytes(),
    };
    let first = handle
        .scan_usdom_v4_history_v1(UsdomV4HistoryRequestV1 {
            schema_version: 1,
            network_magic: NETWORK_MAGIC_REGTEST,
            chain_id: *chain_id.as_bytes(),
            dom_domain: DOMAIN,
            trusted_tip: dom_rpc::ChainTip {
                height: 2,
                hash: *grandchild_hash.as_bytes(),
            },
            start_height: 1,
            max_blocks: 1,
            anchor: Some(initial_anchor),
            require_checkpoint_finality: false,
        })
        .expect("first authenticated history page");
    assert_eq!(first.blocks.len(), 1);
    assert_eq!(first.blocks[0].height, 1);
    assert_eq!(first.blocks[0].block_hash, *child_hash.as_bytes());
    assert!(first.blocks[0].transitions.is_empty());
    let continuation = first.continuation.expect("second page continuation");
    assert_eq!(continuation.next_height, 2);

    let second = handle
        .scan_usdom_v4_history_v1(UsdomV4HistoryRequestV1 {
            schema_version: 1,
            network_magic: NETWORK_MAGIC_REGTEST,
            chain_id: *chain_id.as_bytes(),
            dom_domain: DOMAIN,
            trusted_tip: first.trusted_tip,
            start_height: continuation.next_height,
            max_blocks: 1,
            anchor: Some(continuation.anchor),
            require_checkpoint_finality: false,
        })
        .expect("second authenticated history page");
    assert_eq!(second.blocks.len(), 1);
    assert_eq!(second.blocks[0].height, 2);
    assert_eq!(second.blocks[0].block_hash, *grandchild_hash.as_bytes());
    assert!(second.continuation.is_none());

    let historical = handle
        .scan_usdom_v4_history_v1(UsdomV4HistoryRequestV1 {
            schema_version: 1,
            network_magic: NETWORK_MAGIC_REGTEST,
            chain_id: *chain_id.as_bytes(),
            dom_domain: DOMAIN,
            trusted_tip: dom_rpc::ChainTip {
                height: 1,
                hash: *child_hash.as_bytes(),
            },
            start_height: 1,
            max_blocks: 1,
            anchor: Some(initial_anchor),
            require_checkpoint_finality: false,
        })
        .expect("historical canonical trusted tip below the current tip");
    assert_eq!(historical.identity.current_tip.height, 2);
    assert_eq!(historical.trusted_tip.height, 1);
    assert_eq!(historical.blocks.len(), 1);
    assert_eq!(historical.blocks[0].block_hash, *child_hash.as_bytes());
    assert!(historical.continuation.is_none());

    assert!(matches!(
        handle.scan_usdom_v4_history_v1(UsdomV4HistoryRequestV1 {
            schema_version: 1,
            network_magic: NETWORK_MAGIC_REGTEST,
            chain_id: *chain_id.as_bytes(),
            dom_domain: DOMAIN,
            trusted_tip: historical.trusted_tip,
            start_height: 1,
            max_blocks: 1,
            anchor: Some(initial_anchor),
            require_checkpoint_finality: true,
        }),
        Err(RpcError::ScanReorg(_))
    ));

    let mut wrong_state_anchor = initial_anchor;
    wrong_state_anchor.state_root[0] ^= 1;
    assert!(matches!(
        handle.scan_usdom_v4_history_v1(UsdomV4HistoryRequestV1 {
            schema_version: 1,
            network_magic: NETWORK_MAGIC_REGTEST,
            chain_id: *chain_id.as_bytes(),
            dom_domain: DOMAIN,
            trusted_tip: first.trusted_tip,
            start_height: 1,
            max_blocks: 1,
            anchor: Some(wrong_state_anchor),
            require_checkpoint_finality: false,
        }),
        Err(RpcError::ScanReorg(_))
    ));
    let mut wrong_tip = first.trusted_tip;
    wrong_tip.hash[0] ^= 1;
    assert!(matches!(
        handle.scan_usdom_v4_history_v1(UsdomV4HistoryRequestV1 {
            schema_version: 1,
            network_magic: NETWORK_MAGIC_REGTEST,
            chain_id: *chain_id.as_bytes(),
            dom_domain: DOMAIN,
            trusted_tip: wrong_tip,
            start_height: 1,
            max_blocks: 1,
            anchor: Some(initial_anchor),
            require_checkpoint_finality: false,
        }),
        Err(RpcError::ScanReorg(_))
    ));
}

#[tokio::test]
async fn native_orphan_replay_preserves_exact_packages_and_converges_child_before_parent() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let dir = TempDir::new().unwrap();
    let (canonical, chain_id) = activate_native_genesis(&dir);
    let node = DomNode::init_native_usdom_v4_regtest_with_map_size(
        config(&dir, Network::Regtest),
        TEST_MAP_SIZE,
        bridge(),
        policy(),
        deposit_policy(),
    )
    .unwrap();
    let state = NativeUsdomState::new(bridge()).unwrap();
    let parent = canonical.block.as_ref().unwrap();
    let child = mine_v4_child(
        parent,
        canonical.hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
    );
    let child_hash =
        Hash256::from_bytes(*dom_crypto::blake2b_256(&child.header.to_bytes().unwrap()).as_bytes());
    let grandchild = mine_v4_child(
        &child,
        child_hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
    );
    let wire = |block: Block| {
        let package = UsdomV4BlockPackage::new(block, UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
        UsdomV4PackagePayload {
            package_bytes: package,
        }
        .to_bytes()
        .unwrap()
    };
    let child_wire = wire(child);
    let grandchild_wire = wire(grandchild.clone());
    let now = Timestamp(grandchild.header.timestamp.0 + MAX_FUTURE_BLOCK_TIME);
    let mut relays = node.subscribe_native_usdom_v4_relays();

    assert!(matches!(
        node.ingest_native_usdom_v4_wire_payload_regtest(&grandchild_wire, now)
            .await,
        Err(DomError::Orphan(_))
    ));
    assert_eq!(node.chain.lock().await.tip_height, BlockHeight::GENESIS);
    assert_eq!(
        node.metrics
            .native_usdom_v4_orphan_packages
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        node.metrics
            .native_usdom_v4_orphan_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        u64::try_from(grandchild_wire.len()).unwrap()
    );
    assert!(matches!(
        relays.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    assert_eq!(
        node.ingest_native_usdom_v4_wire_payload_regtest(&child_wire, now)
            .await
            .unwrap(),
        ConnectResult::BestChain
    );
    assert_eq!(node.chain.lock().await.tip_height, BlockHeight(2));
    assert_eq!(
        node.metrics
            .native_usdom_v4_orphan_packages
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert_eq!(
        node.metrics
            .native_usdom_v4_orphan_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert_eq!(relays.recv().await.unwrap().wire_payload, child_wire);
    assert_eq!(relays.recv().await.unwrap().wire_payload, grandchild_wire);
}

#[tokio::test]
async fn native_future_soft_buffer_preserves_exact_package_until_valid_redelivery() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let dir = TempDir::new().unwrap();
    let (canonical, chain_id) = activate_native_genesis(&dir);
    let node = DomNode::init_native_usdom_v4_regtest_with_map_size(
        config(&dir, Network::Regtest),
        TEST_MAP_SIZE,
        bridge(),
        policy(),
        deposit_policy(),
    )
    .unwrap();
    let state = NativeUsdomState::new(bridge()).unwrap();
    let child = mine_v4_child(
        canonical.block.as_ref().unwrap(),
        canonical.hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
    );
    let wire_payload = UsdomV4PackagePayload {
        package_bytes: UsdomV4BlockPackage::new(child.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap(),
    }
    .to_bytes()
    .unwrap();
    let deferred_now = Timestamp(
        child
            .header
            .timestamp
            .0
            .checked_sub(MAX_FUTURE_BLOCK_TIME + 1)
            .unwrap(),
    );
    let mut relays = node.subscribe_native_usdom_v4_relays();

    assert!(matches!(
        node.ingest_native_usdom_v4_wire_payload_regtest(&wire_payload, deferred_now)
            .await,
        Err(DomError::TemporarilyInvalid(_))
    ));
    assert_eq!(node.chain.lock().await.tip_height, BlockHeight::GENESIS);
    assert_eq!(
        node.metrics
            .native_usdom_v4_future_packages
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        node.metrics
            .native_usdom_v4_future_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        u64::try_from(wire_payload.len()).unwrap()
    );
    assert!(matches!(
        relays.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    assert_eq!(
        node.ingest_native_usdom_v4_wire_payload_regtest(
            &wire_payload,
            Timestamp(child.header.timestamp.0),
        )
        .await
        .unwrap(),
        ConnectResult::BestChain
    );
    assert_eq!(node.chain.lock().await.tip_height, BlockHeight(1));
    assert_eq!(
        node.metrics
            .native_usdom_v4_future_packages
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert_eq!(
        node.metrics
            .native_usdom_v4_future_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert_eq!(relays.recv().await.unwrap().wire_payload, wire_payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_future_queue_runtime_drain_commits_and_relays_exact_package() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .with_test_writer()
        .try_init();
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    std::env::set_var("DOM_PORTMAP", "off");
    let dir = TempDir::new().unwrap();
    let (canonical, chain_id) = activate_native_genesis(&dir);
    let mut node_config = config(&dir, Network::Regtest);
    node_config.p2p_listen_addr = free_p2p_addr();
    node_config.disable_dns_seeds = true;
    node_config.dns_seeds.clear();
    node_config.seed_peers.clear();
    node_config.min_outbound = 0;
    node_config.rpc_listen_addr = None;
    node_config.metrics_listen_addr = None;
    let node = std::sync::Arc::new(
        DomNode::init_native_usdom_v4_regtest_with_map_size(
            node_config,
            TEST_MAP_SIZE,
            bridge(),
            policy(),
            deposit_policy(),
        )
        .unwrap(),
    );
    let state = NativeUsdomState::new(bridge()).unwrap();
    let child = mine_v4_child(
        canonical.block.as_ref().unwrap(),
        canonical.hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
    );
    let wire_payload = UsdomV4PackagePayload {
        package_bytes: UsdomV4BlockPackage::new(child.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap(),
    }
    .to_bytes()
    .unwrap();
    let deferred_now = Timestamp(
        child
            .header
            .timestamp
            .0
            .checked_sub(MAX_FUTURE_BLOCK_TIME + 1)
            .unwrap(),
    );
    assert!(matches!(
        node.ingest_native_usdom_v4_wire_payload_regtest(&wire_payload, deferred_now)
            .await,
        Err(DomError::TemporarilyInvalid(_))
    ));
    assert_eq!(
        node.metrics
            .native_usdom_v4_future_packages
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    let mut relays = node.subscribe_native_usdom_v4_relays();
    let node_task = tokio::spawn(Box::pin(node.clone().run()));

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if node.chain.lock().await.tip_height == BlockHeight(1) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("runtime drain must commit the now-valid native package");
    assert_eq!(
        node.metrics
            .native_usdom_v4_future_packages
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert_eq!(relays.recv().await.unwrap().wire_payload, wire_payload);

    node.request_shutdown().await;
    tokio::time::timeout(std::time::Duration::from_secs(10), node_task)
        .await
        .expect("node runtime must stop")
        .unwrap()
        .unwrap();
}

#[test]
fn native_runtime_rejects_non_regtest_before_creating_a_database() {
    let dir = TempDir::new().unwrap();
    let data_dir = dir.path().join("must-not-exist");
    let mut mainnet = NodeConfig::mainnet();
    mainnet.data_dir = data_dir.to_string_lossy().into_owned();
    let result = DomNode::init_native_usdom_v4_regtest_with_map_size(
        mainnet,
        TEST_MAP_SIZE,
        bridge(),
        policy(),
        deposit_policy(),
    );
    assert!(result.is_err());
    assert!(!data_dir.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_native_nodes_sync_exact_package_over_authenticated_v4_ibd() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    std::env::set_var("DOM_PORTMAP", "off");
    let server_dir = TempDir::new().unwrap();
    let client_dir = TempDir::new().unwrap();
    let (canonical, chain_id) = activate_native_genesis(&server_dir);
    let (client_canonical, client_chain_id) = activate_native_genesis(&client_dir);
    assert_eq!(client_canonical.hash, canonical.hash);
    assert_eq!(client_chain_id, chain_id);

    let server_addr = free_p2p_addr();
    let client_addr = free_p2p_addr();
    assert_ne!(server_addr, client_addr);

    let mut server_config = config(&server_dir, Network::Regtest);
    server_config.p2p_listen_addr = server_addr.clone();
    server_config.disable_dns_seeds = true;
    server_config.dns_seeds.clear();
    server_config.seed_peers.clear();
    server_config.min_outbound = 0;
    server_config.rpc_listen_addr = None;
    server_config.metrics_listen_addr = None;

    let mut client_config = config(&client_dir, Network::Regtest);
    client_config.p2p_listen_addr = client_addr;
    client_config.disable_dns_seeds = true;
    client_config.dns_seeds.clear();
    client_config.seed_peers = vec![server_addr];
    client_config.min_outbound = 1;
    client_config.rpc_listen_addr = None;
    client_config.metrics_listen_addr = None;

    let server = std::sync::Arc::new(
        DomNode::init_native_usdom_v4_regtest_with_map_size(
            server_config,
            TEST_MAP_SIZE,
            bridge(),
            policy(),
            deposit_policy(),
        )
        .unwrap(),
    );
    let client = std::sync::Arc::new(
        DomNode::init_native_usdom_v4_regtest_with_map_size(
            client_config,
            TEST_MAP_SIZE,
            bridge(),
            policy(),
            deposit_policy(),
        )
        .unwrap(),
    );

    let state = NativeUsdomState::new(bridge()).unwrap();
    let child = mine_v4_child(
        canonical.block.as_ref().unwrap(),
        canonical.hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
    );
    let package = UsdomV4BlockPackage::new(child.clone(), UsdomV4ProofEnvelope::empty())
        .unwrap()
        .to_bytes()
        .unwrap();
    let wire_payload = UsdomV4PackagePayload {
        package_bytes: package,
    }
    .to_bytes()
    .unwrap();
    assert_eq!(
        server
            .ingest_native_usdom_v4_wire_payload_regtest(
                &wire_payload,
                Timestamp(child.header.timestamp.0 + MAX_FUTURE_BLOCK_TIME),
            )
            .await
            .unwrap(),
        ConnectResult::BestChain
    );

    let server_task = tokio::spawn(Box::pin(server.clone().run()));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let client_task = tokio::spawn(Box::pin(client.clone().run()));

    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if client.chain.lock().await.tip_height == BlockHeight(1) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("client must converge through native-v4 IBD");
    assert_eq!(
        client.chain.lock().await.tip_hash,
        server.chain.lock().await.tip_hash
    );

    client.request_shutdown().await;
    server.request_shutdown().await;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        client_task.await.unwrap().unwrap();
        server_task.await.unwrap().unwrap();
    })
    .await
    .expect("both node runtimes must shut down cleanly");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_v2_nodes_sync_exact_package_and_witnesses_over_authenticated_v2_ibd() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    std::env::set_var("DOM_PORTMAP", "off");
    let (key_bytes, selected_bridge) = test_spend_key_and_bridge();
    let server_dir = TempDir::new().unwrap();
    let client_dir = TempDir::new().unwrap();
    let (server_genesis, chain_id, schedule) =
        activate_scheduled_genesis(&server_dir, selected_bridge);
    let (client_genesis, client_chain_id, client_schedule) =
        activate_scheduled_genesis(&client_dir, selected_bridge);
    assert_eq!(server_genesis.hash, client_genesis.hash);
    assert_eq!(chain_id, client_chain_id);
    assert_eq!(schedule, client_schedule);
    connect_final_v1_child(
        &server_dir,
        &server_genesis,
        chain_id,
        selected_bridge,
        &key_bytes,
        schedule,
        true,
    );
    let final_v1_package = {
        let store = DomStore::open_with_map_size(server_dir.path(), TEST_MAP_SIZE).unwrap();
        let chain =
            ChainState::open_with_utxo_repair(store, server_genesis.hash, NETWORK_MAGIC_REGTEST)
                .unwrap();
        dom_chain::load_persisted_usdom_v4_package(
            &chain.store,
            NETWORK_MAGIC_REGTEST,
            chain.tip_hash,
        )
        .unwrap()
        .unwrap()
    };
    {
        let verifier = SpendVerifier::from_bytes(&key_bytes).unwrap();
        let store = DomStore::open_with_map_size(client_dir.path(), TEST_MAP_SIZE).unwrap();
        let mut chain =
            ChainState::open_with_utxo_repair(store, client_genesis.hash, NETWORK_MAGIC_REGTEST)
                .unwrap();
        let mut state = NativeUsdomState::new(selected_bridge).unwrap();
        let final_v1_timestamp = UsdomV4BlockPackage::from_bytes(&final_v1_package)
            .unwrap()
            .block()
            .header
            .timestamp;
        chain
            .connect_usdom_v4_package_and_activate_v2_for_schedule(
                &final_v1_package,
                final_v1_timestamp
                    .checked_add_secs(MAX_FUTURE_BLOCK_TIME)
                    .unwrap(),
                &mut state,
                selected_bridge,
                &policy(),
                &deposit_policy(),
                &verifier,
                client_schedule,
                2,
            )
            .unwrap();
    }

    let server_addr = free_p2p_addr();
    let client_addr = free_p2p_addr();
    let mut server_config = config(&server_dir, Network::Regtest);
    server_config.p2p_listen_addr = server_addr.clone();
    server_config.disable_dns_seeds = true;
    server_config.dns_seeds.clear();
    server_config.seed_peers.clear();
    server_config.min_outbound = 0;
    server_config.rpc_listen_addr = None;
    server_config.metrics_listen_addr = None;
    let mut client_config = config(&client_dir, Network::Regtest);
    client_config.p2p_listen_addr = client_addr;
    client_config.disable_dns_seeds = true;
    client_config.dns_seeds.clear();
    client_config.seed_peers = vec![server_addr];
    client_config.min_outbound = 1;
    client_config.rpc_listen_addr = None;
    client_config.metrics_listen_addr = None;

    let server = std::sync::Arc::new(
        DomNode::init_native_usdom_candidate_for_schedule_with_spend_verifier_and_map_size(
            server_config,
            TEST_MAP_SIZE,
            selected_bridge,
            policy(),
            deposit_policy(),
            &key_bytes,
            schedule,
            2,
        )
        .unwrap(),
    );
    let client = std::sync::Arc::new(
        DomNode::init_native_usdom_candidate_for_schedule_with_spend_verifier_and_map_size(
            client_config,
            TEST_MAP_SIZE,
            selected_bridge,
            policy(),
            deposit_policy(),
            &key_bytes,
            schedule,
            2,
        )
        .unwrap(),
    );
    assert!(server.has_native_usdom_v2_runtime());
    assert!(client.has_native_usdom_v2_runtime());

    let activation_state = NativeUsdomState::new(selected_bridge).unwrap();
    let (final_v1_hash, final_v1) = {
        use dom_serialization::DomDeserialize;
        let chain = server.chain.lock().await;
        let hash = chain.tip_hash;
        let bytes = chain
            .store
            .get_block_body(hash.as_bytes())
            .unwrap()
            .unwrap();
        (hash, Block::from_bytes(&bytes).unwrap())
    };
    let first_v2 = mine_dom_child_with_empty_usdom_v2_batch(
        &final_v1,
        final_v1_hash,
        server_genesis.hash,
        activation_state.state_commitment_v2().unwrap(),
        chain_id.as_bytes(),
    );
    let package_bytes = UsdomV4BlockPackage::new(first_v2.clone(), UsdomV4ProofEnvelope::empty())
        .unwrap()
        .to_bytes()
        .unwrap();
    let witness_bytes = UsdomV2ExecutionWitnesses::new(Vec::new())
        .unwrap()
        .to_bytes()
        .unwrap();
    let wire_payload = UsdomV2PackagePayload {
        package_bytes: package_bytes.clone(),
        witness_bytes: witness_bytes.clone(),
    }
    .to_bytes()
    .unwrap();
    let mut relays = server.subscribe_native_usdom_v2_relays();
    assert_eq!(
        server
            .ingest_native_usdom_v2_wire_payload(&wire_payload, first_v2.header.timestamp)
            .await
            .unwrap(),
        ConnectResult::BestChain
    );
    let relay = relays.recv().await.unwrap();
    assert_eq!(relay.wire_payload, wire_payload);

    let server_task = tokio::spawn(Box::pin(server.clone().run()));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let client_task = tokio::spawn(Box::pin(client.clone().run()));
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if client.chain.lock().await.tip_height == BlockHeight(2) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("client must converge through candidate-V2 IBD");
    assert_eq!(
        client.chain.lock().await.tip_hash,
        server.chain.lock().await.tip_hash
    );
    let client_tip = client.chain.lock().await.tip_hash;
    let persisted_witnesses = {
        let chain = client.chain.lock().await;
        dom_chain::load_persisted_usdom_v2_execution_witnesses(&chain.store, client_tip)
            .unwrap()
            .unwrap()
            .to_bytes()
            .unwrap()
    };
    assert_eq!(persisted_witnesses, witness_bytes);

    assert_eq!(
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            dom_node::miner::mine_one_block(server.clone()),
        )
        .await
        .expect("live V2 DOM mining must complete")
        .expect("live V2 DOM mining must succeed"),
        3
    );
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if client.chain.lock().await.tip_height == BlockHeight(3) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("client must accept the live mined V2 relay");
    let live_tip = server.chain.lock().await.tip_hash;
    assert_eq!(client.chain.lock().await.tip_hash, live_tip);
    let (server_live_package, server_live_witnesses, client_live_package, client_live_witnesses) = {
        let server_chain = server.chain.lock().await;
        let client_chain = client.chain.lock().await;
        (
            dom_chain::load_persisted_usdom_v4_package(
                &server_chain.store,
                NETWORK_MAGIC_REGTEST,
                live_tip,
            )
            .unwrap()
            .unwrap(),
            dom_chain::load_persisted_usdom_v2_execution_witnesses(&server_chain.store, live_tip)
                .unwrap()
                .unwrap()
                .to_bytes()
                .unwrap(),
            dom_chain::load_persisted_usdom_v4_package(
                &client_chain.store,
                NETWORK_MAGIC_REGTEST,
                live_tip,
            )
            .unwrap()
            .unwrap(),
            dom_chain::load_persisted_usdom_v2_execution_witnesses(&client_chain.store, live_tip)
                .unwrap()
                .unwrap()
                .to_bytes()
                .unwrap(),
        )
    };
    assert_eq!(client_live_package, server_live_package);
    assert_eq!(client_live_witnesses, server_live_witnesses);

    client.request_shutdown().await;
    server.request_shutdown().await;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        client_task.await.unwrap().unwrap();
        server_task.await.unwrap().unwrap();
    })
    .await
    .expect("both V2 node runtimes must shut down cleanly");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v2_miner_rewards_dom_and_persists_an_exact_empty_usdom_batch_without_issuance() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    std::env::set_var("DOM_PORTMAP", "off");
    let (key_bytes, selected_bridge) = test_spend_key_and_bridge();
    let dir = TempDir::new().unwrap();
    let (genesis, chain_id, v1_schedule) = activate_scheduled_genesis(&dir, selected_bridge);
    connect_final_v1_child(
        &dir,
        &genesis,
        chain_id,
        selected_bridge,
        &key_bytes,
        v1_schedule,
        true,
    );

    let mut node_config = config(&dir, Network::Regtest);
    node_config.miner_threads = 1;
    let node = std::sync::Arc::new(
        DomNode::init_native_usdom_candidate_for_schedule_with_spend_verifier_and_map_size(
            node_config,
            TEST_MAP_SIZE,
            selected_bridge,
            policy(),
            deposit_policy(),
            &key_bytes,
            v1_schedule,
            2,
        )
        .unwrap(),
    );
    assert!(node.has_native_usdom_v2_runtime());
    let verifier = SpendVerifier::from_bytes(&key_bytes).unwrap();
    let (v2_schedule, before) = {
        let chain = node.chain.lock().await;
        let schedule = dom_chain::load_persisted_usdom_v2_activation_schedule(&chain.store)
            .unwrap()
            .unwrap();
        let state = dom_chain::restore_persisted_usdom_v2_state_for_schedule(
            &chain.store,
            NETWORK_MAGIC_REGTEST,
            chain.tip_hash,
            selected_bridge,
            &policy(),
            &deposit_policy(),
            &verifier,
            schedule,
        )
        .unwrap();
        (schedule, state)
    };
    assert_eq!(before.total_issued, 0);
    assert_eq!(before.total_burned, 0);

    let mut native_relays = node.subscribe_native_usdom_v2_relays();
    let mut ordinary_relays = node.block_relay_tx.subscribe();
    assert_eq!(
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            dom_node::miner::mine_one_block(node.clone()),
        )
        .await
        .expect("V2 DOM mining must complete")
        .expect("V2 DOM mining must succeed"),
        2
    );

    let relay = tokio::time::timeout(std::time::Duration::from_secs(1), native_relays.recv())
        .await
        .expect("V2 package must be relayed")
        .unwrap();
    assert_eq!(relay.exclude_peer, None);
    let framed = UsdomV2PackagePayload::from_bytes(&relay.wire_payload).unwrap();
    let package = UsdomV4BlockPackage::from_bytes(&framed.package_bytes).unwrap();
    let witnesses = UsdomV2ExecutionWitnesses::from_bytes(&framed.witness_bytes).unwrap();
    assert_eq!(package.block().header.version, BLOCK_VERSION_V4);
    assert_eq!(package.block().header.height, BlockHeight(2));
    assert_eq!(package.proof_envelope(), &UsdomV4ProofEnvelope::empty());
    assert!(witnesses.witnesses().is_empty());
    assert_eq!(
        package.block().coinbase.kernel.explicit_value,
        dom_core::block_reward(BlockHeight(2)).noms(),
        "the PoW reward is the ordinary DOM coinbase"
    );
    assert!(matches!(
        ordinary_relays.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    let (tip, after, persisted_package, persisted_witnesses) = {
        let chain = node.chain.lock().await;
        let tip = chain.tip_hash;
        let state = dom_chain::restore_persisted_usdom_v2_state_for_schedule(
            &chain.store,
            NETWORK_MAGIC_REGTEST,
            tip,
            selected_bridge,
            &policy(),
            &deposit_policy(),
            &verifier,
            v2_schedule,
        )
        .unwrap();
        let persisted_package =
            dom_chain::load_persisted_usdom_v4_package(&chain.store, NETWORK_MAGIC_REGTEST, tip)
                .unwrap()
                .unwrap();
        let persisted_witnesses =
            dom_chain::load_persisted_usdom_v2_execution_witnesses(&chain.store, tip)
                .unwrap()
                .unwrap()
                .to_bytes()
                .unwrap();
        (tip, state, persisted_package, persisted_witnesses)
    };
    assert_eq!(persisted_package, framed.package_bytes);
    assert_eq!(persisted_witnesses, framed.witness_bytes);
    assert_eq!(after, before, "an empty USDOM V2 batch cannot issue USDOM");
    assert_eq!(after.total_issued, 0);
    assert_eq!(after.total_burned, 0);
    assert_eq!(node.chain.lock().await.tip_hash, tip);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_miner_builds_persists_and_relays_the_exact_empty_v4_package() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    std::env::set_var("DOM_PORTMAP", "off");
    let dir = TempDir::new().unwrap();
    activate_native_genesis(&dir);

    let mut node_config = config(&dir, Network::Regtest);
    node_config.miner_threads = 1;
    let node = std::sync::Arc::new(
        DomNode::init_native_usdom_v4_regtest_with_map_size(
            node_config.clone(),
            TEST_MAP_SIZE,
            bridge(),
            policy(),
            deposit_policy(),
        )
        .unwrap(),
    );
    let mut native_relays = node.subscribe_native_usdom_v4_relays();
    let mut ordinary_relays = node.block_relay_tx.subscribe();

    let activation_manifest = {
        let chain = node.chain.lock().await;
        dom_chain::export_native_usdom_v4_snapshot_manifest(
            &chain.store,
            NETWORK_MAGIC_REGTEST,
            bridge(),
            chain.tip_hash,
        )
        .expect("activation snapshot manifest")
    };
    assert!(activation_manifest.blocks.is_empty());
    assert!(activation_manifest.reached_activation_boundary);
    assert_eq!(
        activation_manifest.oldest_audited_parent,
        activation_manifest.canonical_tip
    );
    assert_eq!(
        activation_manifest.activation_schedule_commitment,
        dom_chain::native_usdom_v4_regtest_activation_schedule(bridge())
            .unwrap()
            .commitment()
    );
    assert_ne!(
        activation_manifest.activation_record_commitment,
        Hash256::ZERO
    );
    assert_eq!(
        NativeUsdomV4SnapshotManifest::from_bytes(&activation_manifest.to_bytes().unwrap())
            .unwrap(),
        activation_manifest
    );

    assert_eq!(
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            dom_node::miner::mine_one_block(node.clone()),
        )
        .await
        .expect("native mining must complete")
        .expect("native mining must succeed"),
        1
    );

    let relay = tokio::time::timeout(std::time::Duration::from_secs(1), native_relays.recv())
        .await
        .expect("native package must be relayed")
        .unwrap();
    assert_eq!(relay.exclude_peer, None);
    let framed = UsdomV4PackagePayload::from_bytes(&relay.wire_payload).unwrap();
    let package = UsdomV4BlockPackage::from_bytes(&framed.package_bytes).unwrap();
    assert_eq!(package.block().header.version, BLOCK_VERSION_V4);
    assert_eq!(package.block().header.height, BlockHeight(1));
    assert_eq!(package.proof_envelope(), &UsdomV4ProofEnvelope::empty());
    assert!(matches!(
        ordinary_relays.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        node.metrics
            .blocks_mined
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    let tip = node.chain.lock().await.tip_hash;
    let persisted = {
        let chain = node.chain.lock().await;
        dom_chain::load_persisted_usdom_v4_package(&chain.store, NETWORK_MAGIC_REGTEST, tip)
            .unwrap()
            .expect("mined native package must be persisted")
    };
    assert_eq!(persisted, framed.package_bytes);

    let manifest_bytes = {
        let chain = node.chain.lock().await;
        let manifest = dom_chain::export_native_usdom_v4_snapshot_manifest(
            &chain.store,
            NETWORK_MAGIC_REGTEST,
            bridge(),
            tip,
        )
        .expect("audited native snapshot manifest export");
        assert_eq!(manifest.blocks.len(), 1);
        assert_eq!(manifest.blocks[0].block_identifier, tip);
        assert_eq!(manifest.blocks[0].height, 1);
        assert_eq!(manifest.blocks[0].package_len as usize, persisted.len());
        assert_eq!(
            manifest.activation_schedule_commitment,
            dom_chain::native_usdom_v4_regtest_activation_schedule(bridge())
                .unwrap()
                .commitment()
        );
        assert_ne!(manifest.activation_record_commitment, Hash256::ZERO);
        assert_ne!(manifest.commitment().unwrap(), Hash256::ZERO);
        let bytes = manifest.to_bytes().unwrap();
        assert_eq!(
            NativeUsdomV4SnapshotManifest::from_bytes(&bytes).unwrap(),
            manifest
        );
        assert_eq!(
            dom_chain::verify_native_usdom_v4_snapshot_manifest(&bytes, &chain.store, bridge())
                .unwrap(),
            manifest
        );
        bytes
    };
    let mut substituted_state_commitment = manifest_bytes.clone();
    substituted_state_commitment[86] ^= 1;
    assert!(NativeUsdomV4SnapshotManifest::from_bytes(&substituted_state_commitment).is_ok());
    assert!(dom_chain::verify_native_usdom_v4_snapshot_manifest(
        &substituted_state_commitment,
        &node.chain.lock().await.store,
        bridge(),
    )
    .is_err());
    let mut substituted_activation_schedule = manifest_bytes.clone();
    substituted_activation_schedule[195] ^= 1;
    assert!(NativeUsdomV4SnapshotManifest::from_bytes(&substituted_activation_schedule).is_ok());
    assert!(dom_chain::verify_native_usdom_v4_snapshot_manifest(
        &substituted_activation_schedule,
        &node.chain.lock().await.store,
        bridge(),
    )
    .is_err());
    let mut substituted_activation_record = manifest_bytes.clone();
    substituted_activation_record[227] ^= 1;
    assert!(NativeUsdomV4SnapshotManifest::from_bytes(&substituted_activation_record).is_ok());
    assert!(dom_chain::verify_native_usdom_v4_snapshot_manifest(
        &substituted_activation_record,
        &node.chain.lock().await.store,
        bridge(),
    )
    .is_err());

    drop(ordinary_relays);
    drop(native_relays);
    drop(node);
    let restored = DomNode::init_native_usdom_v4_regtest_with_map_size(
        node_config,
        TEST_MAP_SIZE,
        bridge(),
        policy(),
        deposit_policy(),
    )
    .expect("mined native package must survive audited restart");
    assert_eq!(restored.chain.lock().await.tip_hash, tip);
}
