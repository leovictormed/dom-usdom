#![cfg(feature = "native-usdom-v4-poc")]

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use dom_chain::{
    build_canonical_genesis, genesis_canonical_changeset, native_usdom_v4_activation_updates,
    native_usdom_v4_activation_updates_for_schedule, native_usdom_v4_regtest_activation_schedule,
    ChainState, ConnectResult, NativeUsdomV2Runtime, NativeUsdomV4SnapshotManifest,
    UsdomV2ExecutionWitnesses, UsdomV4BlockPackage, UsdomV4ProofEnvelope,
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
    hash_meets_target, randomx_pool::MinerVm, target_to_compact,
    target_to_difficulty_for_network_height, CompactTarget,
};
use dom_rpc::{NodeHandle, RpcError, UsdomV4HistoryAnchorV1, UsdomV4HistoryRequestV1};
use dom_serialization::DomSerialize;
use dom_store::DomStore;
use dom_usdom_checkpoint_program::{
    build_first_v2_checkpoint_source, build_latest_v2_checkpoint_sources,
    execute_checkpoint_segment_portable, CheckpointRandomXStatement,
    CheckpointSegmentNativeStateOpening, CheckpointSegmentPolicyInput,
    CheckpointSegmentPrivateInput, CheckpointSegmentTransition,
};
use dom_usdom_privacy::{circuit::SpendCircuit, verifier::SpendVerifier};
use dom_usdom_state::{
    apply_v2_transition_batch_with_receipt, BlockContext, BridgeIdentity, BurnTimingPolicy,
    NativeUsdomState, StateCommitmentV2,
};
use dom_wire::message::{UsdomV2PackagePayload, UsdomV4PackagePayload};
use rand::{rngs::StdRng, SeedableRng};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tempfile::TempDir;
use usdom_ethereum_finality_experiment::{
    checkpoints::{CheckpointPolicy, CheckpointTrustPolicy, StaticCheckpointTrustPolicy},
    closures::{
        IssuanceClosurePolicy, IssuanceClosureTrustPolicy, StaticIssuanceClosureTrustPolicy,
    },
    deposits::{DepositTrustPolicy, ReserveDepositPolicy, StaticDepositTrustPolicy},
    EthereumFork, EthereumForks,
};

const TEST_MAP_SIZE: usize = 64 << 20;
const DOMAIN: [u8; 32] = [0x11; 32];
const RANDOMX_RECEIPT_IMAGE_ID_HEX: &str =
    "8efa49d4fe0f616840013adb1d3029ef71642099cb336c577a2691f7eea1dc24";

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

fn pinned_randomx_receipt_image_id() -> [u8; 32] {
    let artifact =
        include_str!("../../dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.iid").trim();
    assert_eq!(artifact, RANDOMX_RECEIPT_IMAGE_ID_HEX);
    hex::decode(artifact).unwrap().try_into().unwrap()
}

fn policy() -> StaticCheckpointTrustPolicy {
    StaticCheckpointTrustPolicy::from_trust_policy(&CheckpointTrustPolicy {
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
            dom_network_magic: NETWORK_MAGIC_REGTEST,
        },
    })
    .unwrap()
}

fn closure_policy(schedule_commitment: [u8; 32]) -> StaticIssuanceClosureTrustPolicy {
    StaticIssuanceClosureTrustPolicy::from_trust_policy(&IssuanceClosureTrustPolicy {
        trusted_checkpoint: [0x41; 32].into(),
        ethereum_genesis_validators_root: [0x22; 32].into(),
        forks: supported_forks(),
        max_current_slot: 1,
        closure: IssuanceClosurePolicy {
            ethereum_chain_id: 1,
            ethereum_genesis_validators_root: [0x22; 32].into(),
            reserve: [0x33; 20].into(),
            runtime_code_hash: [0x46; 32].into(),
            reserve_config_hash: [0x47; 32].into(),
            activation_schedule_commitment: schedule_commitment.into(),
            bridge_domain: DOMAIN.into(),
            deposits_closed_storage_slot: [0x48; 32].into(),
            total_deposited_storage_slot: [0x49; 32].into(),
        },
    })
    .unwrap()
}

fn deposit_policy() -> StaticDepositTrustPolicy {
    StaticDepositTrustPolicy::from_trust_policy(&DepositTrustPolicy {
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
                None,
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
                None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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

#[test]
fn canonical_first_v2_checkpoint_source_roundtrips_from_persisted_regtest_chain() {
    if let Some(source) = std::env::var_os("USDOM_CHECKPOINT_FIXTURE_MIGRATE_FROM") {
        let source = std::path::PathBuf::from(source);
        let export_root = std::path::PathBuf::from(
            std::env::var_os("USDOM_CHECKPOINT_FIXTURE_OUT")
                .expect("migration requires USDOM_CHECKPOINT_FIXTURE_OUT"),
        );
        migrate_checkpoint_fixture_image_id(&source, &export_root).unwrap();
        return;
    }
    if let Some(candidate) = std::env::var_os("USDOM_CHECKPOINT_FIXTURE_CANDIDATE") {
        let candidate = std::path::PathBuf::from(candidate);
        let export_root = std::path::PathBuf::from(
            std::env::var_os("USDOM_CHECKPOINT_FIXTURE_OUT")
                .expect("resume requires USDOM_CHECKPOINT_FIXTURE_OUT"),
        );
        validate_checkpoint_fixture_candidate(&candidate).unwrap();
        assert!(export_root.is_absolute());
        assert!(!export_root.exists());
        std::fs::rename(candidate, export_root).unwrap();
        return;
    }
    std::env::set_var("DOM_REGTEST_REAL_RANDOMX", "1");
    let directory = TempDir::new().unwrap();
    let (key_bytes, selected_bridge) = test_spend_key_and_bridge();
    let (canonical, chain_id, v1_schedule) =
        activate_scheduled_genesis(&directory, selected_bridge);
    let store = DomStore::open_with_map_size(directory.path(), TEST_MAP_SIZE).unwrap();
    let mut chain =
        ChainState::open_with_utxo_repair(store, canonical.hash, NETWORK_MAGIC_REGTEST).unwrap();
    let verifier = SpendVerifier::from_bytes(&key_bytes).unwrap();
    let checkpoint_policy = policy();
    let reserve_deposit_policy = deposit_policy();
    let mut v1_state = NativeUsdomState::new(selected_bridge).unwrap();
    let mut parent = canonical.block.as_ref().unwrap().clone();
    let mut parent_hash = canonical.hash;
    let first_v2_height = 11;
    let mut v2_schedule = None;

    for height in 1..first_v2_height {
        let child = mine_v4_child(
            &parent,
            parent_hash,
            canonical.hash,
            &v1_state,
            chain_id.as_bytes(),
        );
        eprintln!("native RandomX fixture mined block height={height}");
        assert_eq!(child.header.height.0, height);
        let child_hash = dom_chain::canonical_header_identifier(
            NETWORK_MAGIC_REGTEST,
            &child.header.to_bytes().unwrap(),
        )
        .unwrap();
        let package = UsdomV4BlockPackage::new(child.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
        if height + 1 == first_v2_height {
            let (outcome, schedule) = chain
                .connect_usdom_v4_package_and_activate_v2_for_schedule(
                    &package,
                    child.header.timestamp,
                    &mut v1_state,
                    selected_bridge,
                    &checkpoint_policy,
                    &reserve_deposit_policy,
                    None,
                    &verifier,
                    v1_schedule,
                    first_v2_height,
                )
                .unwrap();
            assert_eq!(outcome, ConnectResult::BestChain);
            v2_schedule = Some(schedule);
        } else {
            assert_eq!(
                chain
                    .connect_usdom_v4_package_for_schedule(
                        &package,
                        child.header.timestamp,
                        &mut v1_state,
                        selected_bridge,
                        &checkpoint_policy,
                        &reserve_deposit_policy,
                        None,
                        &verifier,
                        v1_schedule,
                    )
                    .unwrap(),
                ConnectResult::BestChain
            );
        }
        parent = child;
        parent_hash = child_hash;
    }

    let v2_schedule = v2_schedule.unwrap();
    let issuance_closure_policy = closure_policy(*v2_schedule.commitment().as_bytes());
    let mut runtime = NativeUsdomV2Runtime::restore_for_schedule_with_spend_verifier(
        &chain,
        selected_bridge,
        checkpoint_policy.clone(),
        reserve_deposit_policy.clone(),
        Some(issuance_closure_policy.clone()),
        &key_bytes,
        v2_schedule,
    )
    .unwrap();
    let first_v2 = mine_dom_child_with_empty_usdom_v2_batch(
        &parent,
        parent_hash,
        canonical.hash,
        runtime.state(),
        chain_id.as_bytes(),
    );
    eprintln!("native RandomX fixture mined block height={first_v2_height}");
    let package = UsdomV4BlockPackage::new(first_v2.clone(), UsdomV4ProofEnvelope::empty())
        .unwrap()
        .to_bytes()
        .unwrap();
    let witnesses = UsdomV2ExecutionWitnesses::new(Vec::new()).unwrap();
    assert_eq!(
        runtime
            .ingest(&mut chain, &package, &witnesses, first_v2.header.timestamp)
            .unwrap(),
        ConnectResult::BestChain
    );

    let bundle = build_first_v2_checkpoint_source(
        &chain,
        v2_schedule,
        runtime.checkpoint_policy(),
        runtime.deposit_policy(),
        runtime.issuance_closure_policy().unwrap(),
        runtime.spend_verifying_key(),
        runtime.state(),
        pinned_randomx_receipt_image_id(),
    )
    .unwrap();
    let transition = CheckpointSegmentTransition::from_bytes(bundle.transition_bytes()).unwrap();
    let private_input =
        CheckpointSegmentPrivateInput::from_bytes(bundle.private_input_bytes()).unwrap();
    let policy_input =
        CheckpointSegmentPolicyInput::from_bytes(bundle.policy_input_bytes()).unwrap();
    let native_opening =
        CheckpointSegmentNativeStateOpening::from_bytes(bundle.native_state_opening_bytes())
            .unwrap();
    let execution = execute_checkpoint_segment_portable(
        &transition,
        &private_input,
        &policy_input,
        &native_opening,
    )
    .unwrap();
    assert_eq!(transition.previous.height, first_v2_height - 1);
    assert_eq!(transition.next.height, first_v2_height);
    assert_eq!(transition.next.block_hash, *chain.tip_hash.as_bytes());
    assert_eq!(
        transition.previous.randomx_receipt_image_id,
        pinned_randomx_receipt_image_id()
    );
    assert_eq!(execution.randomx_bindings().len(), 1);
    assert!(build_first_v2_checkpoint_source(
        &chain,
        v2_schedule,
        runtime.checkpoint_policy(),
        runtime.deposit_policy(),
        runtime.issuance_closure_policy().unwrap(),
        runtime.spend_verifying_key(),
        runtime.state(),
        [0; 32],
    )
    .is_err());

    let expected_outputs = [
        bundle.transition_bytes().to_vec(),
        bundle.private_input_bytes().to_vec(),
        bundle.policy_input_bytes().to_vec(),
        bundle.native_state_opening_bytes().to_vec(),
    ];
    drop(runtime);
    drop(chain);

    let export_config = directory.path().join("checkpoint-export-config");
    let output_dir = directory.path().join("checkpoint-export-output");
    std::fs::create_dir(&export_config).unwrap();
    std::fs::create_dir(&output_dir).unwrap();
    std::fs::write(export_config.join("spend.vk"), &key_bytes).unwrap();
    let fork = |epoch: u64, version: &str| serde_json::json!({"epoch": epoch, "version": version});
    let manifest = serde_json::json!({
        "schema_version": 3,
        "network_magic": NETWORK_MAGIC_REGTEST,
        "activation_schedule_hex": hex::encode(v1_schedule.to_bytes()),
        "candidate_v2": {
            "first_height": first_v2_height,
            "checkpoint_interval_blocks": 1,
            "checkpoint_confirmation_depth_blocks": 1
        },
        "spend_verifying_key_file": "spend.vk",
        "spend_verifying_key_sha256":
            dom_node::native_usdom_config::sha256_hex(&key_bytes),
        "ethereum": {
            "trusted_checkpoint": "41".repeat(32),
            "genesis_validators_root": "22".repeat(32),
            "forks": {
                "genesis": fork(0, "00000000"),
                "altair": fork(74_240, "01000000"),
                "bellatrix": fork(144_896, "02000000"),
                "capella": fork(194_048, "03000000"),
                "deneb": fork(269_568, "04000000"),
                "electra": fork(364_032, "05000000"),
                "fulu": fork(411_392, "06000000"),
                "gloas": fork(u64::MAX, "07000000")
            }
        },
        "checkpoint": {
            "ethereum_chain_id": 1,
            "registry": "42".repeat(20),
            "runtime_code_hash": "43".repeat(32),
            "config_storage_slot": "44".repeat(32),
            "checkpoint_config_hash": "45".repeat(32),
            "bridge_domain": "11".repeat(32),
            "randomx_receipt_image_id": RANDOMX_RECEIPT_IMAGE_ID_HEX
        },
        "deposit": {
            "ethereum_chain_id": 1,
            "reserve": "33".repeat(20),
            "runtime_code_hash": "46".repeat(32),
            "bridge_domain": "11".repeat(32),
            "max_amount": 100_000_000_000u64
        },
        "issuance_closure": {
            "ethereum_chain_id": 1,
            "reserve": "33".repeat(20),
            "runtime_code_hash": "46".repeat(32),
            "reserve_config_hash": "47".repeat(32),
            "bridge_domain": "11".repeat(32),
            "deposits_closed_storage_slot": "48".repeat(32),
            "total_deposited_storage_slot": "49".repeat(32)
        },
        "bridge": {
            "dom_domain": hex::encode(selected_bridge.dom_domain),
            "ethereum_chain_id_uint256": hex::encode(selected_bridge.ethereum_chain_id),
            "privacy_policy_hash": hex::encode(selected_bridge.privacy_policy_hash),
            "privacy_verifier_config_hash":
                hex::encode(selected_bridge.privacy_verifier_config_hash),
            "reserve": hex::encode(selected_bridge.reserve),
            "burn_timing": {
                "withdrawal_delay_secs":
                    selected_bridge.burn_timing.withdrawal_delay_secs,
                "min_execution_window_secs":
                    selected_bridge.burn_timing.min_execution_window_secs,
                "max_certificate_lifetime_secs":
                    selected_bridge.burn_timing.max_certificate_lifetime_secs,
                "relay_safety_margin_secs":
                    selected_bridge.burn_timing.relay_safety_margin_secs,
                "max_ethereum_anchor_age_secs":
                    selected_bridge.burn_timing.max_ethereum_anchor_age_secs,
                "max_dom_clock_lead_secs":
                    selected_bridge.burn_timing.max_dom_clock_lead_secs
            }
        }
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let manifest_hash = dom_node::native_usdom_config::sha256_hex(&manifest_bytes);
    let manifest_path = export_config.join("native-usdom-v2.json");
    std::fs::write(&manifest_path, manifest_bytes).unwrap();
    for name in [
        "checkpoint-segment-transition.bin",
        "checkpoint-segment-private-input.bin",
        "checkpoint-segment-policy-input.bin",
        "checkpoint-segment-native-state-opening.bin",
    ] {
        std::fs::write(output_dir.join(name), b"stale").unwrap();
    }
    let output =
        std::process::Command::new(env!("CARGO_BIN_EXE_dom-usdom-export-checkpoint-source"))
            .args([
                "--manifest-file",
                manifest_path.to_str().unwrap(),
                "--manifest-sha256",
                &manifest_hash,
                "--data-dir",
                directory.path().to_str().unwrap(),
                "--output-dir",
                output_dir.to_str().unwrap(),
                "--network",
                "regtest",
            ])
            .output()
            .unwrap();
    assert!(
        output.status.success(),
        "export failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("status: exported"));
    for (name, expected) in [
        ("checkpoint-segment-transition.bin", &expected_outputs[0]),
        ("checkpoint-segment-private-input.bin", &expected_outputs[1]),
        ("checkpoint-segment-policy-input.bin", &expected_outputs[2]),
        (
            "checkpoint-segment-native-state-opening.bin",
            &expected_outputs[3],
        ),
    ] {
        assert_eq!(std::fs::read(output_dir.join(name)).unwrap(), *expected);
    }

    let store = DomStore::open_with_map_size(directory.path(), TEST_MAP_SIZE).unwrap();
    let mut chain =
        ChainState::open_with_utxo_repair(store, canonical.hash, NETWORK_MAGIC_REGTEST).unwrap();
    let mut runtime = NativeUsdomV2Runtime::restore_for_schedule_with_spend_verifier(
        &chain,
        selected_bridge,
        checkpoint_policy.clone(),
        reserve_deposit_policy.clone(),
        Some(issuance_closure_policy.clone()),
        &key_bytes,
        v2_schedule,
    )
    .unwrap();
    let confirmation = mine_dom_child_with_empty_usdom_v2_batch(
        &first_v2,
        chain.tip_hash,
        canonical.hash,
        runtime.state(),
        chain_id.as_bytes(),
    );
    eprintln!(
        "native RandomX fixture mined block height={}",
        confirmation.header.height.0
    );
    let confirmation_package =
        UsdomV4BlockPackage::new(confirmation.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
    assert_eq!(
        runtime
            .ingest(
                &mut chain,
                &confirmation_package,
                &witnesses,
                confirmation.header.timestamp,
            )
            .unwrap(),
        ConnectResult::BestChain
    );
    let source_set = build_latest_v2_checkpoint_sources(
        &chain,
        v2_schedule,
        runtime.checkpoint_policy(),
        runtime.deposit_policy(),
        runtime.issuance_closure_policy().unwrap(),
        runtime.spend_verifying_key(),
        runtime.state(),
        pinned_randomx_receipt_image_id(),
        1,
        1,
    )
    .unwrap();
    assert_eq!(source_set.previous_height(), 10);
    assert_eq!(source_set.target_height(), 11);
    assert_eq!(source_set.confirmation_height(), 12);
    assert_eq!(source_set.segments().len(), 2);
    let mut expected_set_outputs = Vec::new();
    let mut expected_statements = Vec::new();
    for (index, segment) in source_set.segments().iter().enumerate() {
        assert_eq!(segment.economic_blocks().len(), 1);
        assert_eq!(segment.economic_blocks()[0].block_index(), 0);
        assert!(!segment.economic_blocks()[0].source().chunks().is_empty());
        let transition =
            CheckpointSegmentTransition::from_bytes(segment.transition_bytes()).unwrap();
        assert_eq!(transition.block_count, 1);
        assert_eq!(transition.previous.height, 10 + index as u64);
        assert_eq!(transition.next.height, 11 + index as u64);
        let execution = execute_checkpoint_segment_portable(
            &transition,
            &CheckpointSegmentPrivateInput::from_bytes(segment.private_input_bytes()).unwrap(),
            &CheckpointSegmentPolicyInput::from_bytes(segment.policy_input_bytes()).unwrap(),
            &CheckpointSegmentNativeStateOpening::from_bytes(segment.native_state_opening_bytes())
                .unwrap(),
        )
        .unwrap();
        expected_statements.extend(
            execution
                .randomx_bindings()
                .iter()
                .map(|binding| binding.statement().to_bytes().unwrap()),
        );
        expected_set_outputs.push([
            segment.transition_bytes().to_vec(),
            segment.private_input_bytes().to_vec(),
            segment.policy_input_bytes().to_vec(),
            segment.native_state_opening_bytes().to_vec(),
        ]);
    }
    drop(runtime);
    drop(chain);

    let export_root =
        std::env::var_os("USDOM_CHECKPOINT_FIXTURE_OUT").map(std::path::PathBuf::from);
    let evidence_dir = if let Some(export_root) = export_root.as_ref() {
        assert!(export_root.is_absolute());
        let candidate = export_root.parent().unwrap().join(".evidence-candidate");
        assert!(!candidate.exists(), "candidate must be create-once");
        std::fs::create_dir(&candidate).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o700)).unwrap();
        candidate
    } else {
        let evidence = directory.path().join("evidence");
        std::fs::create_dir(&evidence).unwrap();
        evidence
    };
    let set_output_dir = evidence_dir.join("checkpoint-source-set");
    std::fs::create_dir(&set_output_dir).unwrap();
    std::fs::write(
        set_output_dir.join("checkpoint-segment-9999-transition.bin"),
        b"stale",
    )
    .unwrap();
    std::fs::write(
        set_output_dir.join("checkpoint-source-set-index.json"),
        b"stale",
    )
    .unwrap();
    std::fs::write(set_output_dir.join("operator-notes.txt"), b"preserve").unwrap();
    let set_output =
        std::process::Command::new(env!("CARGO_BIN_EXE_dom-usdom-export-checkpoint-source-set"))
            .args([
                "--manifest-file",
                manifest_path.to_str().unwrap(),
                "--manifest-sha256",
                &manifest_hash,
                "--data-dir",
                directory.path().to_str().unwrap(),
                "--output-dir",
                set_output_dir.to_str().unwrap(),
                "--network",
                "regtest",
            ])
            .output()
            .unwrap();
    assert!(
        set_output.status.success(),
        "source-set export failed: stdout={} stderr={}",
        String::from_utf8_lossy(&set_output.stdout),
        String::from_utf8_lossy(&set_output.stderr)
    );
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(set_output_dir.join("checkpoint-source-set-index.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(index["schema"], "usdom-canonical-checkpoint-source-set-v1");
    assert_eq!(index["previous_height"], 10);
    assert_eq!(index["target_height"], 11);
    assert_eq!(index["confirmation_height"], 12);
    assert_eq!(index["segment_count"], 2);
    let economic_index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(set_output_dir.join("checkpoint-economic-source-set-index.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        economic_index["schema"],
        "usdom-economic-proof-source-set-v1"
    );
    assert_eq!(economic_index["block_count"], 2);
    assert_eq!(economic_index["blocks"].as_array().unwrap().len(), 2);
    for (index, expected) in expected_set_outputs.iter().enumerate() {
        for (suffix, value) in [
            ("transition.bin", &expected[0]),
            ("private-input.bin", &expected[1]),
            ("policy-input.bin", &expected[2]),
            ("native-state-opening.bin", &expected[3]),
        ] {
            assert_eq!(
                std::fs::read(
                    set_output_dir.join(format!("checkpoint-segment-{index:04}-{suffix}"))
                )
                .unwrap(),
                *value
            );
        }
    }
    assert!(!set_output_dir
        .join("checkpoint-segment-9999-transition.bin")
        .exists());
    assert_eq!(
        std::fs::read(set_output_dir.join("operator-notes.txt")).unwrap(),
        b"preserve"
    );

    let statement_output_dir = evidence_dir.join("randomx-statement-set");
    std::fs::create_dir(&statement_output_dir).unwrap();
    std::fs::write(
        statement_output_dir.join("randomx-statement-0999.bin"),
        b"stale",
    )
    .unwrap();
    std::fs::write(statement_output_dir.join("operator-notes.txt"), b"preserve").unwrap();
    let statement_output =
        std::process::Command::new(env!("CARGO_BIN_EXE_dom-usdom-export-randomx-statement-set"))
            .args(["--evidence-dir", evidence_dir.to_str().unwrap()])
            .output()
            .unwrap();
    assert!(
        statement_output.status.success(),
        "statement-set export failed: stdout={} stderr={}",
        String::from_utf8_lossy(&statement_output.stdout),
        String::from_utf8_lossy(&statement_output.stderr)
    );
    if export_root.is_some() {
        write_checkpoint_fixture_manifest(&evidence_dir).unwrap();
    }
    let statement_index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(statement_output_dir.join("randomx-statement-set-index.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        statement_index["schema"],
        "usdom-authenticated-randomx-statement-set-v1"
    );
    assert_eq!(statement_index["segment_count"], 2);
    assert_eq!(statement_index["statement_count"], 2);
    assert_eq!(statement_index["portable_segments_executed"], true);
    assert_eq!(statement_index["randomx_relations_executed"], true);
    for (index, expected) in expected_statements.iter().enumerate() {
        assert_eq!(
            std::fs::read(statement_output_dir.join(format!("randomx-statement-{index:04}.bin")))
                .unwrap(),
            *expected
        );
    }
    assert!(!statement_output_dir
        .join("randomx-statement-0999.bin")
        .exists());
    assert_eq!(
        std::fs::read(statement_output_dir.join("operator-notes.txt")).unwrap(),
        b"preserve"
    );
    if let Some(export_root) = export_root {
        validate_checkpoint_fixture_candidate(&evidence_dir).unwrap();
        assert!(!export_root.exists());
        std::fs::rename(&evidence_dir, &export_root).unwrap();
    }
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

const CHECKPOINT_FIXTURE_MANIFEST: &str = "candidate-manifest.json";

fn copy_direct_tree(source: &std::path::Path, destination: &std::path::Path) -> Result<(), String> {
    std::fs::create_dir(destination).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    for entry in std::fs::read_dir(source).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let target = destination.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err(format!("source contains symlink: {}", path.display()));
        }
        if metadata.is_dir() {
            copy_direct_tree(&path, &target)?;
        } else if metadata.is_file() {
            std::fs::copy(&path, &target).map_err(|error| error.to_string())?;
            #[cfg(unix)]
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| error.to_string())?;
        } else {
            return Err(format!(
                "source contains non-regular entry: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn migrate_checkpoint_fixture_image_id(
    source: &std::path::Path,
    export_root: &std::path::Path,
) -> Result<(), String> {
    if !source.is_absolute() || !export_root.is_absolute() || export_root.exists() {
        return Err("migration paths must be absolute and output must be absent".into());
    }
    let candidate = export_root
        .parent()
        .ok_or_else(|| "output parent is absent".to_owned())?
        .join(".evidence-candidate");
    if candidate.exists() {
        return Err("migration candidate must be create-once".into());
    }
    std::fs::create_dir_all(export_root.parent().unwrap()).map_err(|error| error.to_string())?;
    std::fs::create_dir(&candidate).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    let source_set = source.join("checkpoint-source-set");
    let candidate_source = candidate.join("checkpoint-source-set");
    copy_direct_tree(&source_set, &candidate_source)?;

    let source_index_path = candidate_source.join("checkpoint-source-set-index.json");
    let mut source_index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&source_index_path).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if source_index["schema"] != "usdom-canonical-checkpoint-source-set-v1"
        || source_index["randomx_receipt_image_id"] == RANDOMX_RECEIPT_IMAGE_ID_HEX
    {
        return Err("migration source identity is invalid or already migrated".into());
    }
    let segments = source_index["segments"]
        .as_array_mut()
        .ok_or_else(|| "migration source segments absent".to_owned())?;
    let pinned = pinned_randomx_receipt_image_id();
    let mut previous_next: Option<dom_usdom_checkpoint_program::CheckpointSegmentState> = None;
    for segment in segments {
        let transition_name = segment["transition_file"]
            .as_str()
            .ok_or_else(|| "migration transition filename absent".to_owned())?;
        let transition_path = candidate_source.join(transition_name);
        let mut transition = CheckpointSegmentTransition::from_bytes(
            &std::fs::read(&transition_path).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        transition.previous.randomx_receipt_image_id = pinned;
        transition.next.randomx_receipt_image_id = pinned;
        if let Some(expected) = previous_next.as_ref() {
            if &transition.previous != expected {
                return Err("migration source segment continuity mismatch".into());
            }
        }
        let transition_bytes = transition.to_bytes().map_err(|error| error.to_string())?;
        let private_name = segment["private_input_file"]
            .as_str()
            .ok_or_else(|| "migration private input filename absent".to_owned())?;
        let policy_name = segment["policy_input_file"]
            .as_str()
            .ok_or_else(|| "migration policy input filename absent".to_owned())?;
        let opening_name = segment["native_state_opening_file"]
            .as_str()
            .ok_or_else(|| "migration opening filename absent".to_owned())?;
        execute_checkpoint_segment_portable(
            &CheckpointSegmentTransition::from_bytes(&transition_bytes)
                .map_err(|error| error.to_string())?,
            &CheckpointSegmentPrivateInput::from_bytes(
                &std::fs::read(candidate_source.join(private_name))
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?,
            &CheckpointSegmentPolicyInput::from_bytes(
                &std::fs::read(candidate_source.join(policy_name))
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?,
            &CheckpointSegmentNativeStateOpening::from_bytes(
                &std::fs::read(candidate_source.join(opening_name))
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        std::fs::write(&transition_path, &transition_bytes).map_err(|error| error.to_string())?;
        segment["transition_sha256"] =
            serde_json::Value::String(dom_node::native_usdom_config::sha256_hex(&transition_bytes));
        previous_next = Some(transition.next);
    }
    source_index["randomx_receipt_image_id"] =
        serde_json::Value::String(RANDOMX_RECEIPT_IMAGE_ID_HEX.to_owned());
    let mut source_index_bytes =
        serde_json::to_vec_pretty(&source_index).map_err(|error| error.to_string())?;
    source_index_bytes.push(b'\n');
    std::fs::write(&source_index_path, &source_index_bytes).map_err(|error| error.to_string())?;

    let economic_path = candidate_source.join("checkpoint-economic-source-set-index.json");
    let mut economic: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&economic_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    economic["checkpoint_source_index_sha256"] = serde_json::Value::String(
        dom_node::native_usdom_config::sha256_hex(&source_index_bytes),
    );
    let mut economic_bytes =
        serde_json::to_vec_pretty(&economic).map_err(|error| error.to_string())?;
    economic_bytes.push(b'\n');
    std::fs::write(economic_path, economic_bytes).map_err(|error| error.to_string())?;

    let statements = candidate.join("randomx-statement-set");
    std::fs::create_dir(&statements).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    std::fs::set_permissions(&statements, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    let output =
        std::process::Command::new(env!("CARGO_BIN_EXE_dom-usdom-export-randomx-statement-set"))
            .args(["--evidence-dir", candidate.to_str().unwrap()])
            .output()
            .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "migrated statement export failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    write_checkpoint_fixture_manifest(&candidate)?;
    validate_checkpoint_fixture_candidate(&candidate)?;
    std::fs::rename(candidate, export_root).map_err(|error| error.to_string())
}

fn candidate_files(root: &std::path::Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    fn visit(
        root: &std::path::Path,
        directory: &std::path::Path,
        files: &mut Vec<(String, Vec<u8>)>,
    ) -> Result<(), String> {
        for entry in std::fs::read_dir(directory).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            if metadata.file_type().is_symlink() {
                return Err(format!("candidate contains symlink: {}", path.display()));
            }
            if metadata.is_dir() {
                visit(root, &path, files)?;
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|error| error.to_string())?
                    .to_str()
                    .ok_or_else(|| "candidate path is not UTF-8".to_owned())?
                    .replace('\\', "/");
                if relative != CHECKPOINT_FIXTURE_MANIFEST {
                    files.push((
                        relative,
                        std::fs::read(&path).map_err(|error| error.to_string())?,
                    ));
                }
            } else {
                return Err(format!(
                    "candidate has non-regular entry: {}",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    visit(root, root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(files)
}

fn write_checkpoint_fixture_manifest(root: &std::path::Path) -> Result<(), String> {
    let entries = candidate_files(root)?
        .into_iter()
        .map(|(path, bytes)| {
            serde_json::json!({
                "path": path,
                "bytes": bytes.len(),
                "sha256": dom_node::native_usdom_config::sha256_hex(&bytes),
            })
        })
        .collect::<Vec<_>>();
    let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": "usdom-local-checkpoint-fixture-candidate-v1",
        "files": entries,
    }))
    .map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    let path = root.join(CHECKPOINT_FIXTURE_MANIFEST);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options
        .open(path)
        .and_then(|mut file| file.write_all(&bytes).and_then(|()| file.sync_all()))
        .map_err(|error| error.to_string())
}

fn validate_checkpoint_fixture_candidate(root: &std::path::Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err("candidate path must be absolute".into());
    }
    let metadata = std::fs::symlink_metadata(root).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("candidate must be a direct directory".into());
    }
    #[cfg(unix)]
    {
        let home = std::env::var_os("HOME").ok_or_else(|| "HOME is unavailable".to_owned())?;
        let home_owner = std::fs::metadata(home)
            .map_err(|error| error.to_string())?
            .uid();
        if metadata.uid() != home_owner || metadata.permissions().mode() & 0o077 != 0 {
            return Err("candidate must be owned by the operator and mode 0700".into());
        }
    }

    verify_checkpoint_fixture_manifest(root)?;

    let source_dir = root.join("checkpoint-source-set");
    let source_index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(source_dir.join("checkpoint-source-set-index.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if source_index["schema"] != "usdom-canonical-checkpoint-source-set-v1"
        || source_index["randomx_receipt_image_id"] != RANDOMX_RECEIPT_IMAGE_ID_HEX
        || source_index["previous_height"] != 10
        || source_index["target_height"] != 11
        || source_index["confirmation_height"] != 12
        || source_index["segment_count"] != 2
    {
        return Err("candidate source index identity mismatch".into());
    }
    let segments = source_index["segments"]
        .as_array()
        .ok_or_else(|| "candidate segments absent".to_owned())?;
    for segment in segments {
        let read = |field: &str| -> Result<Vec<u8>, String> {
            let name = segment[field]
                .as_str()
                .ok_or_else(|| format!("candidate segment {field} absent"))?;
            std::fs::read(source_dir.join(name)).map_err(|error| error.to_string())
        };
        CheckpointSegmentTransition::from_bytes(&read("transition_file")?)
            .map_err(|error| error.to_string())?;
        CheckpointSegmentPrivateInput::from_bytes(&read("private_input_file")?)
            .map_err(|error| error.to_string())?;
        CheckpointSegmentPolicyInput::from_bytes(&read("policy_input_file")?)
            .map_err(|error| error.to_string())?;
        CheckpointSegmentNativeStateOpening::from_bytes(&read("native_state_opening_file")?)
            .map_err(|error| error.to_string())?;
    }

    let statement_dir = root.join("randomx-statement-set");
    let statement_index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(statement_dir.join("randomx-statement-set-index.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if statement_index["schema"] != "usdom-authenticated-randomx-statement-set-v1"
        || statement_index["randomx_receipt_image_id"] != RANDOMX_RECEIPT_IMAGE_ID_HEX
        || statement_index["segment_count"] != 2
        || statement_index["statement_count"] != 2
        || statement_index["portable_segments_executed"] != true
        || statement_index["randomx_relations_executed"] != true
    {
        return Err("candidate statement index identity mismatch".into());
    }
    for statement in statement_index["statements"]
        .as_array()
        .ok_or_else(|| "candidate statements absent".to_owned())?
    {
        let name = statement["statement_file"]
            .as_str()
            .ok_or_else(|| "candidate statement filename absent".to_owned())?;
        CheckpointRandomXStatement::from_bytes(
            &std::fs::read(statement_dir.join(name)).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn verify_checkpoint_fixture_manifest(root: &std::path::Path) -> Result<(), String> {
    let manifest_bytes =
        std::fs::read(root.join(CHECKPOINT_FIXTURE_MANIFEST)).map_err(|error| error.to_string())?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).map_err(|error| error.to_string())?;
    if manifest["schema"] != "usdom-local-checkpoint-fixture-candidate-v1" {
        return Err("candidate manifest schema mismatch".into());
    }
    let expected = manifest["files"]
        .as_array()
        .ok_or_else(|| "candidate manifest files are absent".to_owned())?;
    let actual = candidate_files(root)?;
    if expected.len() != actual.len() {
        return Err("candidate file inventory mismatch".into());
    }
    for (record, (actual_path, bytes)) in expected.iter().zip(actual.iter()) {
        if record["path"].as_str() != Some(actual_path)
            || record["bytes"].as_u64() != Some(bytes.len() as u64)
            || record["sha256"].as_str()
                != Some(dom_node::native_usdom_config::sha256_hex(bytes).as_str())
        {
            return Err(format!("candidate manifest mismatch: {actual_path}"));
        }
    }

    Ok(())
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
    let header = mine_regtest_header_parallel(
        dom_consensus::BlockHeader {
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
                nonce: 0,
                randomx_hash: Hash256::ZERO,
            },
        },
        pow_seed,
        canonical_target,
    )
    .unwrap();
    Block {
        header,
        coinbase,
        transactions: vec![],
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
    let coinbase = build_coinbase(height, chain_id, 0x72u8.wrapping_add(height.0 as u8));
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
    let header = mine_regtest_header_parallel(
        dom_consensus::BlockHeader {
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
                nonce: 0,
                randomx_hash: Hash256::ZERO,
            },
        },
        pow_seed,
        canonical_target,
    )
    .unwrap();
    Block {
        header,
        coinbase,
        transactions: vec![],
    }
}

fn mine_regtest_header_parallel(
    template: dom_consensus::BlockHeader,
    pow_seed: Hash256,
    target: [u8; 32],
) -> Result<dom_consensus::BlockHeader, String> {
    let worker_count = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .min(4);
    let found = Arc::new(AtomicBool::new(false));
    let winner = Arc::new(Mutex::new(None));
    let first_error = Arc::new(Mutex::new(None));

    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for worker in 0..worker_count {
            let found = Arc::clone(&found);
            let winner = Arc::clone(&winner);
            let first_error = Arc::clone(&first_error);
            let template = template.clone();
            let target = target.clone();
            handles.push(scope.spawn(move || {
                let mining_vm = match MinerVm::new_light(pow_seed.as_bytes()) {
                    Ok(vm) => vm,
                    Err(error) => {
                        found.store(true, Ordering::Release);
                        if let Ok(mut slot) = first_error.lock() {
                            slot.get_or_insert_with(|| {
                                format!("initialize RandomX worker: {error}")
                            });
                        }
                        return;
                    }
                };
                let stride = worker_count as u64;
                let mut nonce = worker as u64;
                while !found.load(Ordering::Acquire) {
                    let mut header = template.clone();
                    header.pow.nonce = nonce;
                    let hash = match mining_vm.hash(&header.pow_preimage()) {
                        Ok(hash) => hash,
                        Err(error) => {
                            found.store(true, Ordering::Release);
                            if let Ok(mut slot) = first_error.lock() {
                                slot.get_or_insert_with(|| {
                                    format!("execute RandomX worker: {error}")
                                });
                            }
                            return;
                        }
                    };
                    if hash_meets_target(&hash, &target)
                        && found
                            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                    {
                        header.pow.randomx_hash = Hash256::from_bytes(hash);
                        if let Ok(mut slot) = winner.lock() {
                            *slot = Some(header);
                        }
                        return;
                    }
                    nonce = match nonce.checked_add(stride) {
                        Some(next) => next,
                        None => return,
                    };
                }
            }));
        }
        for handle in handles {
            if handle.join().is_err() {
                found.store(true, Ordering::Release);
                if let Ok(mut slot) = first_error.lock() {
                    slot.get_or_insert_with(|| "RandomX mining worker panicked".to_owned());
                }
            }
        }
    });

    if let Some(header) = winner.lock().map_err(|_| "winner lock poisoned")?.take() {
        return Ok(header);
    }
    if let Some(error) = first_error
        .lock()
        .map_err(|_| "error lock poisoned")?
        .take()
    {
        return Err(error);
    }
    Err("RandomX nonce space exhausted without a valid regtest header".to_owned())
}

#[test]
fn bounded_parallel_regtest_miner_returns_a_native_randomx_header() {
    let seed = Hash256::from_bytes([0x42; 32]);
    let template = dom_consensus::BlockHeader {
        version: BLOCK_VERSION_V4,
        height: BlockHeight(1),
        prev_hash: Hash256::from_bytes([0x11; 32]),
        timestamp: Timestamp(1),
        output_root: Hash256::from_bytes([0x22; 32]),
        kernel_root: Hash256::from_bytes([0x33; 32]),
        rangeproof_root: Hash256::from_bytes([0x44; 32]),
        total_kernel_offset: [0; 32],
        target: CompactTarget(target_to_compact(&[0xff; 32])),
        total_difficulty: Default::default(),
        pow: ProofOfWork {
            nonce: 0,
            randomx_hash: Hash256::ZERO,
        },
    };
    let mined = mine_regtest_header_parallel(template, seed, [0xff; 32]).unwrap();
    let verifier = MinerVm::new_light(seed.as_bytes()).unwrap();
    assert_eq!(
        mined.pow.randomx_hash,
        Hash256::from_bytes(verifier.hash(&mined.pow_preimage()).unwrap())
    );
    assert!(mined.pow.nonce < 4);
}

#[test]
fn checkpoint_fixture_candidate_manifest_rejects_mutation() {
    let directory = TempDir::new().unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = directory.path().join("fixture.bin");
    std::fs::write(&fixture, b"canonical").unwrap();
    write_checkpoint_fixture_manifest(directory.path()).unwrap();
    verify_checkpoint_fixture_manifest(directory.path()).unwrap();
    std::fs::write(fixture, b"mutated").unwrap();
    assert!(verify_checkpoint_fixture_manifest(directory.path()).is_err());
}

#[test]
fn checkpoint_fixture_uses_the_pinned_randomx_guest_image_id() {
    let image_id = pinned_randomx_receipt_image_id();
    assert_ne!(image_id, [0; 32]);
    assert_ne!(image_id, [0x17; 32]);
    assert_eq!(hex::encode(image_id), RANDOMX_RECEIPT_IMAGE_ID_HEX);
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
        None,
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
            None,
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
        None,
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
            None,
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
        None,
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
        None,
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
            None,
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
        None,
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
            None,
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
            None,
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
                None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
        None,
    )
    .expect("mined native package must survive audited restart");
    assert_eq!(restored.chain.lock().await.tip_hash, tip);
}
