#![cfg(feature = "native-usdom-v4-poc")]

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use dom_chain::{
    audit_persisted_usdom_v4_reorg_window, build_canonical_genesis, canonical_header_identifier,
    ethereum_checkpoint_poc, load_persisted_usdom_v2_activation_schedule,
    load_persisted_usdom_v2_execution_witnesses, load_persisted_usdom_v4_package,
    native_usdom_v2_activation_updates, native_usdom_v4_activation_updates,
    native_usdom_v4_activation_updates_for_schedule, native_usdom_v4_regtest_activation_schedule,
    restore_persisted_usdom_v2_state_for_schedule, restore_persisted_usdom_v4_state,
    rewind_persisted_usdom_v4_state_to_ancestor, ChainState, ConnectResult,
    NativeUsdomV2ActivationSchedule, NativeUsdomV2Runtime, NativeUsdomV4ActivationSchedule,
    NativeUsdomV4Runtime, UsdomV2ExecutionWitnesses, UsdomV4BlockPackage, UsdomV4ProofEnvelope,
};
use dom_consensus::block::ProofOfWork;
use dom_consensus::{
    bind_usdom_batch_commitment, compute_block_pmmr_roots, Block, CoinbaseKernel,
    CoinbaseTransaction, TransactionOutput,
};
use dom_core::{
    BlockHeight, Hash256, Timestamp, BLOCK_VERSION_V3, BLOCK_VERSION_V4, KERNEL_FEAT_COINBASE,
    MAX_FUTURE_BLOCK_TIME, NETWORK_MAGIC_REGTEST, TAG_KERNEL_MSG_COINBASE, TARGET_SPACING,
};
use dom_crypto::pedersen::Commitment;
use dom_crypto::{blake2b_256_tagged, schnorr_sign, BlindingFactor, SecretKey};
use dom_pow::{
    fast_pow_hash, hash_meets_target, target_to_compact, target_to_difficulty_for_network_height,
    CompactTarget,
};
use dom_serialization::DomSerialize;
use dom_store::{ConsensusStateUpdate, DomStore};
use dom_usdom_privacy::{circuit::SpendCircuit, verifier::SpendVerifier};
use dom_usdom_state::{
    apply_v2_transition_batch_with_receipt, BlockContext, BridgeIdentity, BurnTimingPolicy,
    NativeUsdomState, StateCommitmentV2,
};
use lmdb::{Transaction as LmdbTransaction, WriteFlags};
use rand::{rngs::StdRng, SeedableRng};
use tempfile::TempDir;
use usdom_ethereum_finality_experiment::{
    checkpoints::{CheckpointPolicy, CheckpointTrustPolicy, StaticCheckpointTrustPolicy},
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

fn bridge() -> BridgeIdentity {
    let mut chain_id = [0; 32];
    chain_id[31] = 1;
    BridgeIdentity {
        dom_domain: DOMAIN,
        ethereum_genesis_validators_root: [0x22; 32],
        ethereum_chain_id: chain_id,
        ethereum_checkpoint_policy_hash: unused_policy().policy_hash().into(),
        ethereum_deposit_policy_hash: unused_deposit_policy().policy_hash().into(),
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

fn unused_policy() -> StaticCheckpointTrustPolicy {
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
            dom_network_magic: NETWORK_MAGIC_REGTEST,
        },
    };
    StaticCheckpointTrustPolicy::from_trust_policy(&dynamic).unwrap()
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
    coinbase_discriminator: u8,
) -> Block {
    let height = parent.header.height.checked_next().unwrap();
    let timestamp = parent
        .header
        .timestamp
        .checked_add_secs(TARGET_SPACING)
        .unwrap();
    let coinbase = build_coinbase(height, chain_id, coinbase_discriminator);
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

fn mine_v2_empty_child(
    parent: &Block,
    parent_hash: Hash256,
    pow_seed: Hash256,
    state: StateCommitmentV2,
    chain_id: &[u8; 32],
    coinbase_discriminator: u8,
) -> Block {
    let height = parent.header.height.checked_next().unwrap();
    let timestamp = parent
        .header
        .timestamp
        .checked_add_secs(TARGET_SPACING)
        .unwrap();
    let coinbase = build_coinbase(height, chain_id, coinbase_discriminator);
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

fn remine_as_legacy_v3(mut block: Block, pow_seed: Hash256) -> Block {
    let (_, _, raw_rangeproof_root) =
        compute_block_pmmr_roots(block.header.height, &block.coinbase, &block.transactions)
            .unwrap();
    block.header.version = BLOCK_VERSION_V3;
    block.header.rangeproof_root = raw_rangeproof_root;
    block.header.pow.nonce = 0;
    block.header.pow.randomx_hash = Hash256::ZERO;
    let canonical_target = block.header.target.to_target().unwrap();
    loop {
        let hash = fast_pow_hash(pow_seed.as_bytes(), &block.header.pow_preimage());
        if hash_meets_target(&hash, &canonical_target) {
            block.header.pow.randomx_hash = Hash256::from_bytes(hash);
            return block;
        }
        block.header.pow.nonce = block.header.pow.nonce.wrapping_add(1);
    }
}

#[test]
fn activated_native_state_rejects_every_unknown_legacy_block_path() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let configured =
        dom_core::configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST).unwrap();
    let chain_id = dom_consensus::derive_chain_id(NETWORK_MAGIC_REGTEST, &configured);
    let canonical = build_canonical_genesis(NETWORK_MAGIC_REGTEST, chain_id.as_bytes()).unwrap();
    let parent = canonical.block.clone().unwrap();
    let state = NativeUsdomState::new(bridge()).unwrap();
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
    let mut chain =
        ChainState::open_with_utxo_repair(store, canonical.hash, NETWORK_MAGIC_REGTEST).unwrap();
    let v4 = mine_v4_child(
        &parent,
        canonical.hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
        0x3f,
    );
    let legacy = remine_as_legacy_v3(v4.clone(), canonical.hash);
    let raw_legacy = vec![legacy.header.to_bytes().unwrap()];
    let now = legacy.timestamp_after_margin();

    for result in [
        chain.validate_header_only(&legacy.header, now),
        chain
            .validate_ibd_headers_batch(&raw_legacy, now)
            .map(|_| ()),
        chain
            .validate_ibd_header_step(&raw_legacy, 0, &[], now)
            .map(|_| ()),
        chain.connect_block(&legacy, now).map(|_| ()),
    ] {
        let error = result.expect_err("legacy ingress must fail after native activation");
        assert!(matches!(error, dom_core::DomError::PolicyRejected(_)));
        assert!(error
            .to_string()
            .contains("ordinary block ingress is disabled"));
    }
    assert_eq!(chain.tip_hash, canonical.hash);
    assert_eq!(chain.tip_height, BlockHeight::GENESIS);

    let raw_v4 = vec![v4.header.to_bytes().unwrap()];
    assert_eq!(
        chain
            .validate_native_usdom_v4_ibd_headers_batch_regtest(&raw_v4, now)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn native_header_mode_requires_activation_and_legacy_remains_available_before_it() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let configured =
        dom_core::configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST).unwrap();
    let chain_id = dom_consensus::derive_chain_id(NETWORK_MAGIC_REGTEST, &configured);
    let canonical = build_canonical_genesis(NETWORK_MAGIC_REGTEST, chain_id.as_bytes()).unwrap();
    let parent = canonical.block.clone().unwrap();
    let state = NativeUsdomState::new(bridge()).unwrap();
    let dir = TempDir::new().unwrap();
    let store = DomStore::open_with_map_size(dir.path(), 64 << 20).unwrap();
    store
        .commit_block(
            canonical.hash.as_bytes(),
            0,
            &canonical.header_bytes,
            &canonical.block_bytes,
            &[],
            &[],
            &[],
        )
        .unwrap();
    let chain =
        ChainState::open_with_utxo_repair(store, canonical.hash, NETWORK_MAGIC_REGTEST).unwrap();
    let schedule = native_usdom_v4_regtest_activation_schedule(bridge()).unwrap();
    assert!(chain
        .prepare_native_usdom_v4_activation(&state, schedule)
        .is_ok());
    let wrong_height =
        NativeUsdomV4ActivationSchedule::new(NETWORK_MAGIC_REGTEST, chain_id, 2, bridge()).unwrap();
    assert!(chain
        .prepare_native_usdom_v4_activation(&state, wrong_height)
        .is_err());
    let wrong_chain = NativeUsdomV4ActivationSchedule::new(
        NETWORK_MAGIC_REGTEST,
        Hash256::from_bytes([0xfe; 32]),
        1,
        bridge(),
    )
    .unwrap();
    assert!(chain
        .prepare_native_usdom_v4_activation(&state, wrong_chain)
        .is_err());
    let v4 = mine_v4_child(
        &parent,
        canonical.hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
        0x3e,
    );
    let legacy = remine_as_legacy_v3(v4.clone(), canonical.hash);
    let now = legacy.timestamp_after_margin();

    let error = chain
        .validate_native_usdom_v4_ibd_headers_batch_regtest(&[v4.header.to_bytes().unwrap()], now)
        .expect_err("native header mode must require atomic activation");
    assert!(matches!(error, dom_core::DomError::PolicyRejected(_)));
    assert!(error.to_string().contains("activation marker"));

    assert_eq!(
        chain
            .validate_ibd_headers_batch(&[legacy.header.to_bytes().unwrap()], now)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn native_ibd_header_mode_is_explicit_and_matches_batch_and_resume_paths() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let configured =
        dom_core::configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST).unwrap();
    let chain_id = dom_consensus::derive_chain_id(NETWORK_MAGIC_REGTEST, &configured);
    let canonical = build_canonical_genesis(NETWORK_MAGIC_REGTEST, chain_id.as_bytes()).unwrap();
    let parent = canonical.block.clone().unwrap();
    let state = NativeUsdomState::new(bridge()).unwrap();
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
        ChainState::open_with_utxo_repair(store, canonical.hash, NETWORK_MAGIC_REGTEST).unwrap();
    let child = mine_v4_child(
        &parent,
        canonical.hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
        0x40,
    );
    let raw = vec![child.header.to_bytes().unwrap()];
    let now = child.timestamp_after_margin();

    assert!(chain.validate_ibd_headers_batch(&raw, now).is_err());
    let batch = chain
        .validate_native_usdom_v4_ibd_headers_batch_regtest(&raw, now)
        .unwrap();
    assert_eq!(batch.len(), 1);
    let (height, resumed) = chain
        .validate_native_usdom_v4_ibd_header_step_regtest(&raw, 0, &[], now)
        .unwrap();
    assert_eq!(height, 1);
    assert_eq!(resumed, batch);

    let schedule = native_usdom_v4_regtest_activation_schedule(bridge()).unwrap();
    let scheduled_batch = chain
        .validate_native_usdom_v4_ibd_headers_batch_for_schedule(&raw, now, schedule)
        .unwrap();
    let (scheduled_height, scheduled_resumed) = chain
        .validate_native_usdom_v4_ibd_header_step_for_schedule(&raw, 0, &[], now, schedule)
        .unwrap();
    assert_eq!(scheduled_batch, batch);
    assert_eq!(scheduled_height, height);
    assert_eq!(scheduled_resumed, batch);

    let wrong_schedule =
        NativeUsdomV4ActivationSchedule::new(NETWORK_MAGIC_REGTEST, chain_id, 2, bridge()).unwrap();
    assert!(chain
        .validate_native_usdom_v4_ibd_headers_batch_for_schedule(&raw, now, wrong_schedule)
        .is_err());
    assert!(chain
        .validate_native_usdom_v4_ibd_header_step_for_schedule(&raw, 0, &[], now, wrong_schedule,)
        .is_err());
}

#[test]
fn chainstate_direct_extension_validates_and_commits_native_state_with_block() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let configured =
        dom_core::configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST).unwrap();
    let chain_id = dom_consensus::derive_chain_id(NETWORK_MAGIC_REGTEST, &configured);
    let canonical = build_canonical_genesis(NETWORK_MAGIC_REGTEST, chain_id.as_bytes()).unwrap();
    let parent = canonical.block.clone().unwrap();
    assert_eq!(canonical.hash, configured);

    let state = NativeUsdomState::new(bridge()).unwrap();
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

    let mut chain =
        ChainState::open_with_utxo_repair(store, canonical.hash, NETWORK_MAGIC_REGTEST).unwrap();
    let activation_runtime = NativeUsdomV4Runtime::restore(
        &chain,
        bridge(),
        unused_policy(),
        unused_deposit_policy(),
        None,
    )
    .unwrap();
    assert_eq!(activation_runtime.startup_audit().audited_blocks, 0);
    assert!(
        activation_runtime
            .startup_audit()
            .reached_activation_boundary
    );
    assert_eq!(activation_runtime.state().state_root(), state.state_root());
    let block = mine_v4_child(
        &parent,
        canonical.hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
        0x41,
    );
    let package = UsdomV4BlockPackage::new(block.clone(), UsdomV4ProofEnvelope::empty())
        .unwrap()
        .to_bytes()
        .unwrap();
    let now = block.timestamp_after_margin();
    let mut caller_state = state.clone();

    assert!(chain.connect_block(&block, now).is_err());
    assert_eq!(chain.tip_hash, canonical.hash);

    let mut wrong_bridge = bridge();
    wrong_bridge.reserve = [0x99; 20];
    let mut wrong_state = NativeUsdomState::new(wrong_bridge).unwrap();
    assert!(chain
        .connect_usdom_v4_package_regtest(
            &package,
            now,
            &mut wrong_state,
            bridge(),
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            None,
        )
        .is_err());
    assert_eq!(chain.tip_hash, canonical.hash);

    let mut bad_pow_block = block.clone();
    bad_pow_block.header.pow.randomx_hash = Hash256::ZERO;
    let bad_pow_package = UsdomV4BlockPackage::new(bad_pow_block, UsdomV4ProofEnvelope::empty())
        .unwrap()
        .to_bytes()
        .unwrap();
    assert!(chain
        .connect_usdom_v4_package_regtest(
            &bad_pow_package,
            now,
            &mut caller_state,
            bridge(),
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            None,
        )
        .is_err());
    assert_eq!(chain.tip_hash, canonical.hash);
    assert_eq!(caller_state.state_root(), state.state_root());

    assert_eq!(
        chain
            .ingest_usdom_v4_package_regtest(
                &package,
                now,
                &mut caller_state,
                bridge(),
                &unused_policy(),
                &unused_deposit_policy(),
                None,
                None,
            )
            .unwrap(),
        ConnectResult::BestChain
    );
    assert_eq!(chain.tip_height, BlockHeight(1));
    assert_eq!(caller_state.state_root(), state.state_root());
    assert_eq!(
        chain
            .ingest_usdom_v4_package_regtest(
                &package,
                now,
                &mut caller_state,
                bridge(),
                &unused_policy(),
                &unused_deposit_policy(),
                None,
                None,
            )
            .unwrap(),
        ConnectResult::AlreadyHave
    );

    let first_v4_hash = chain.tip_hash;
    let second = mine_v4_child(
        &block,
        first_v4_hash,
        canonical.hash,
        &caller_state,
        chain_id.as_bytes(),
        0x42,
    );
    let second_package = UsdomV4BlockPackage::new(second.clone(), UsdomV4ProofEnvelope::empty())
        .unwrap()
        .to_bytes()
        .unwrap();
    assert_eq!(
        chain
            .ingest_usdom_v4_package_regtest(
                &second_package,
                second.timestamp_after_margin(),
                &mut caller_state,
                bridge(),
                &unused_policy(),
                &unused_deposit_policy(),
                None,
                None,
            )
            .unwrap(),
        ConnectResult::BestChain
    );
    let second_v4_hash = chain.tip_hash;
    assert_eq!(chain.tip_height, BlockHeight(2));
    assert_eq!(
        rewind_persisted_usdom_v4_state_to_ancestor(
            &chain.store,
            NETWORK_MAGIC_REGTEST,
            bridge(),
            second_v4_hash,
            first_v4_hash,
        )
        .unwrap()
        .state_root(),
        state.state_root()
    );
    assert_eq!(
        rewind_persisted_usdom_v4_state_to_ancestor(
            &chain.store,
            NETWORK_MAGIC_REGTEST,
            bridge(),
            second_v4_hash,
            canonical.hash,
        )
        .unwrap()
        .state_root(),
        state.state_root()
    );

    let side_two = mine_v4_child(
        &block,
        first_v4_hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
        0x52,
    );
    let side_two_package =
        UsdomV4BlockPackage::new(side_two.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
    let retained_side_two = chain
        .store_usdom_v4_side_package_regtest(
            &side_two_package,
            side_two.timestamp_after_margin(),
            &caller_state,
            bridge(),
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            None,
        )
        .unwrap();
    assert_eq!(chain.tip_hash, second_v4_hash);
    assert_eq!(
        chain
            .store
            .get_block_sidecar(retained_side_two.as_bytes())
            .unwrap()
            .unwrap(),
        UsdomV4ProofEnvelope::empty().to_bytes().unwrap()
    );

    let side_three = mine_v4_child(
        &side_two,
        retained_side_two,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
        0x53,
    );
    let side_three_package =
        UsdomV4BlockPackage::new(side_three.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
    let retained_side_three = chain
        .store_usdom_v4_side_package_regtest(
            &side_three_package,
            side_three.timestamp_after_margin(),
            &caller_state,
            bridge(),
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            None,
        )
        .unwrap();
    assert_ne!(retained_side_three, retained_side_two);
    assert_eq!(chain.tip_hash, second_v4_hash);

    let entries = chain.store.read_all_consensus_state_raw().unwrap();
    let (undo_key, mut undo_bytes) = entries
        .into_iter()
        .find(|(key, _)| {
            key.starts_with(b"usdom-v4/undo/") && key.ends_with(second_v4_hash.as_bytes())
        })
        .unwrap();
    let original_undo_bytes = undo_bytes.clone();
    let last = undo_bytes.len().checked_sub(1).unwrap();
    undo_bytes[last] ^= 1;
    chain
        .store
        .apply_reorg_with_consensus_state(
            second_v4_hash.as_bytes(),
            &[],
            &[],
            &[],
            &[ConsensusStateUpdate {
                key: undo_key.clone(),
                value: Some(undo_bytes),
            }],
        )
        .unwrap();
    assert!(rewind_persisted_usdom_v4_state_to_ancestor(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        bridge(),
        second_v4_hash,
        first_v4_hash,
    )
    .is_err());

    chain
        .store
        .apply_reorg_with_consensus_state(
            second_v4_hash.as_bytes(),
            &[],
            &[],
            &[],
            &[ConsensusStateUpdate {
                key: undo_key,
                value: Some(original_undo_bytes),
            }],
        )
        .unwrap();
    let original_sidecar = chain
        .store
        .get_block_sidecar(retained_side_three.as_bytes())
        .unwrap()
        .unwrap();
    let mut corrupt_sidecar = original_sidecar.clone();
    let last = corrupt_sidecar.len().checked_sub(1).unwrap();
    corrupt_sidecar[last] ^= 1;
    {
        let mut txn = chain.store.env.begin_rw_txn().unwrap();
        txn.put(
            chain.store.db_block_sidecars,
            retained_side_three.as_bytes(),
            &corrupt_sidecar,
            WriteFlags::empty(),
        )
        .unwrap();
        txn.commit().unwrap();
    }
    let state_before_rejected_promotion = caller_state.clone();
    assert!(chain
        .promote_usdom_v4_known_tip_regtest(
            retained_side_three,
            side_three.timestamp_after_margin(),
            &mut caller_state,
            bridge(),
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            None,
        )
        .is_err());
    assert_eq!(chain.tip_hash, second_v4_hash);
    assert_eq!(
        caller_state.state_root(),
        state_before_rejected_promotion.state_root()
    );
    assert_eq!(
        caller_state.export_entries(),
        state_before_rejected_promotion.export_entries()
    );
    {
        let mut txn = chain.store.env.begin_rw_txn().unwrap();
        txn.put(
            chain.store.db_block_sidecars,
            retained_side_three.as_bytes(),
            &original_sidecar,
            WriteFlags::empty(),
        )
        .unwrap();
        txn.commit().unwrap();
    }
    let reorg = match chain
        .ingest_usdom_v4_package_regtest(
            &side_three_package,
            side_three.timestamp_after_margin(),
            &mut caller_state,
            bridge(),
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            None,
        )
        .unwrap()
    {
        ConnectResult::Reorg(reorg) => reorg,
        other => panic!("expected automatic native-v4 reorg, got {other:?}"),
    };
    assert_eq!(reorg.common_ancestor_height, 1);
    assert_eq!(reorg.disconnected_blocks.len(), 1);
    assert_eq!(reorg.connected_blocks.len(), 2);
    assert_eq!(chain.tip_hash, retained_side_three);
    assert_eq!(chain.tip_height, BlockHeight(3));
    assert_eq!(
        chain.store.get_hash_at_height(2).unwrap(),
        Some(*retained_side_two.as_bytes())
    );
    assert_eq!(
        chain.store.get_hash_at_height(3).unwrap(),
        Some(*retained_side_three.as_bytes())
    );
    assert_eq!(
        chain
            .store
            .get_block_sidecar(second_v4_hash.as_bytes())
            .unwrap()
            .unwrap(),
        UsdomV4ProofEnvelope::empty().to_bytes().unwrap()
    );
    assert_eq!(
        restore_persisted_usdom_v4_state(
            &chain.store,
            NETWORK_MAGIC_REGTEST,
            bridge(),
            retained_side_three,
        )
        .unwrap()
        .state_root(),
        caller_state.state_root()
    );
    assert!(load_persisted_usdom_v4_package(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        retained_side_two,
    )
    .unwrap()
    .is_some());
    assert!(load_persisted_usdom_v4_package(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        retained_side_three,
    )
    .unwrap()
    .is_some());
    assert_eq!(
        chain
            .ingest_usdom_v4_package_regtest(
                &side_three_package,
                side_three.timestamp_after_margin(),
                &mut caller_state,
                bridge(),
                &unused_policy(),
                &unused_deposit_policy(),
                None,
                None,
            )
            .unwrap(),
        ConnectResult::AlreadyHave
    );

    let audit = audit_persisted_usdom_v4_reorg_window(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        bridge(),
        chain.tip_hash,
    )
    .unwrap();
    assert_eq!(audit.audited_blocks, 3);
    assert_eq!(audit.oldest_audited_parent, canonical.hash);
    assert!(audit.reached_activation_boundary);
    assert_eq!(audit.boundary_state_root, state.state_root());

    let entries = chain.store.read_all_consensus_state_raw().unwrap();
    let (promoted_undo_key, promoted_undo) = entries
        .into_iter()
        .find(|(key, _)| {
            key.starts_with(b"usdom-v4/undo/") && key.ends_with(retained_side_two.as_bytes())
        })
        .unwrap();
    let mut corrupt_promoted_undo = promoted_undo.clone();
    let last = corrupt_promoted_undo.len().checked_sub(1).unwrap();
    corrupt_promoted_undo[last] ^= 1;
    chain
        .store
        .apply_reorg_with_consensus_state(
            chain.tip_hash.as_bytes(),
            &[],
            &[],
            &[],
            &[ConsensusStateUpdate {
                key: promoted_undo_key.clone(),
                value: Some(corrupt_promoted_undo),
            }],
        )
        .unwrap();
    assert!(audit_persisted_usdom_v4_reorg_window(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        bridge(),
        chain.tip_hash,
    )
    .is_err());
    chain
        .store
        .apply_reorg_with_consensus_state(
            chain.tip_hash.as_bytes(),
            &[],
            &[],
            &[],
            &[ConsensusStateUpdate {
                key: promoted_undo_key,
                value: Some(promoted_undo),
            }],
        )
        .unwrap();
    assert!(audit_persisted_usdom_v4_reorg_window(
        &chain.store,
        NETWORK_MAGIC_REGTEST,
        bridge(),
        chain.tip_hash,
    )
    .is_ok());

    let mut restarted_runtime = NativeUsdomV4Runtime::restore(
        &chain,
        bridge(),
        unused_policy(),
        unused_deposit_policy(),
        None,
    )
    .unwrap();
    assert_eq!(restarted_runtime.startup_audit().audited_blocks, 3);
    assert_eq!(
        restarted_runtime.state().state_root(),
        caller_state.state_root()
    );
    assert_eq!(
        restarted_runtime
            .ingest(
                &mut chain,
                &side_three_package,
                side_three.timestamp_after_margin(),
            )
            .unwrap(),
        ConnectResult::AlreadyHave
    );

    let mut checkpoint = ethereum_checkpoint_poc::TestOracleCheckpoint {
        height: 2,
        dom_block: retained_side_two,
        dom_state_root: caller_state.state_root(),
        dom_network_magic: NETWORK_MAGIC_REGTEST,
        ethereum_chain_id: 1,
        ethereum_block_number: 20_000_020,
        ethereum_block: Hash256::from_bytes([0xb1; 32]),
        ethereum_receipts_root: Hash256::from_bytes([0xb2; 32]),
        ethereum_state_root: Hash256::from_bytes([0xb3; 32]),
        ethereum_beacon_slot: 16_000_020,
        ethereum_beacon_root: Hash256::from_bytes([0xb4; 32]),
        ethereum_genesis_validators_root: Hash256::from_bytes([0x22; 32]),
        transaction_index: 7,
        receipt_log_index: 3,
        checkpoint_contract: [0xb5; 20],
        checkpoint_code_hash: Hash256::from_bytes([0xb6; 32]),
        checkpoint_config_hash: Hash256::from_bytes([0xb7; 32]),
        bridge_domain: Hash256::from_bytes(DOMAIN),
        checkpoint_event_digest: Hash256::ZERO,
    };
    checkpoint.checkpoint_event_digest =
        ethereum_checkpoint_poc::expected_checkpoint_event_digest(checkpoint);
    chain.install_test_checkpoint(checkpoint).unwrap();

    let competing_three = mine_v4_child(
        &second,
        second_v4_hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
        0x63,
    );
    let competing_three_package =
        UsdomV4BlockPackage::new(competing_three.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
    let competing_three_hash = chain
        .store_usdom_v4_side_package_regtest(
            &competing_three_package,
            competing_three.timestamp_after_margin(),
            &caller_state,
            bridge(),
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            None,
        )
        .unwrap();
    let competing_four = mine_v4_child(
        &competing_three,
        competing_three_hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
        0x64,
    );
    let competing_four_package =
        UsdomV4BlockPackage::new(competing_four.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
    let competing_four_hash = chain
        .store_usdom_v4_side_package_regtest(
            &competing_four_package,
            competing_four.timestamp_after_margin(),
            &caller_state,
            bridge(),
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            None,
        )
        .unwrap();
    let tip_before_rejected_reorg = chain.tip_hash;
    let error = chain
        .promote_usdom_v4_known_tip_regtest(
            competing_four_hash,
            competing_four.timestamp_after_margin(),
            &mut caller_state,
            bridge(),
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            None,
        )
        .unwrap_err();
    assert!(error.to_string().contains("reorg would undo checkpoint"));
    assert_eq!(chain.tip_hash, tip_before_rejected_reorg);
}

#[test]
fn scheduled_ingress_requires_exact_schedule_and_atomically_promotes_heavier_branch() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_5343);
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

    let configured =
        dom_core::configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST).unwrap();
    let chain_id = dom_consensus::derive_chain_id(NETWORK_MAGIC_REGTEST, &configured);
    let canonical = build_canonical_genesis(NETWORK_MAGIC_REGTEST, chain_id.as_bytes()).unwrap();
    let parent = canonical.block.clone().unwrap();
    let state = NativeUsdomState::new(selected_bridge).unwrap();
    let schedule = native_usdom_v4_regtest_activation_schedule(selected_bridge).unwrap();
    let activation =
        native_usdom_v4_activation_updates_for_schedule(&state, schedule, canonical.hash, 0)
            .unwrap();
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
    let mut chain =
        ChainState::open_with_utxo_repair(store, canonical.hash, NETWORK_MAGIC_REGTEST).unwrap();
    let block = mine_v4_child(
        &parent,
        canonical.hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
        0x6a,
    );
    let package = UsdomV4BlockPackage::new(block.clone(), UsdomV4ProofEnvelope::empty())
        .unwrap()
        .to_bytes()
        .unwrap();
    let now = block.timestamp_after_margin();
    let mut caller_state = state.clone();
    let wrong_height =
        NativeUsdomV4ActivationSchedule::new(NETWORK_MAGIC_REGTEST, chain_id, 2, selected_bridge)
            .unwrap();
    assert!(chain
        .connect_usdom_v4_package_for_schedule(
            &package,
            now,
            &mut caller_state,
            selected_bridge,
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            wrong_height,
        )
        .is_err());
    assert_eq!(chain.tip_hash, canonical.hash);
    assert_eq!(caller_state.state_root(), state.state_root());

    assert_eq!(
        chain
            .connect_usdom_v4_package_for_schedule(
                &package,
                now,
                &mut caller_state,
                selected_bridge,
                &unused_policy(),
                &unused_deposit_policy(),
                None,
                &verifier,
                schedule,
            )
            .unwrap(),
        ConnectResult::BestChain
    );
    assert_eq!(chain.tip_height, BlockHeight(1));
    assert_eq!(caller_state.state_root(), state.state_root());

    let first_hash = chain.tip_hash;
    let canonical_two = mine_v4_child(
        &block,
        first_hash,
        canonical.hash,
        &caller_state,
        chain_id.as_bytes(),
        0x6b,
    );
    let canonical_two_package =
        UsdomV4BlockPackage::new(canonical_two.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
    assert_eq!(
        chain
            .ingest_usdom_v4_package_for_schedule(
                &canonical_two_package,
                canonical_two.timestamp_after_margin(),
                &mut caller_state,
                selected_bridge,
                &unused_policy(),
                &unused_deposit_policy(),
                None,
                &verifier,
                schedule,
            )
            .unwrap(),
        ConnectResult::BestChain
    );
    let canonical_two_hash = chain.tip_hash;

    let side_two = mine_v4_child(
        &block,
        first_hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
        0x7b,
    );
    let side_two_package =
        UsdomV4BlockPackage::new(side_two.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
    let side_two_hash = chain
        .store_usdom_v4_side_package_for_schedule(
            &side_two_package,
            side_two.timestamp_after_margin(),
            &caller_state,
            selected_bridge,
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            schedule,
        )
        .unwrap();
    assert_ne!(side_two_hash, canonical_two_hash);
    assert_eq!(chain.tip_hash, canonical_two_hash);

    let side_three = mine_v4_child(
        &side_two,
        side_two_hash,
        canonical.hash,
        &state,
        chain_id.as_bytes(),
        0x7c,
    );
    let side_three_package =
        UsdomV4BlockPackage::new(side_three.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
    assert!(matches!(
        chain
            .ingest_usdom_v4_package_for_schedule(
                &side_three_package,
                side_three.timestamp_after_margin(),
                &mut caller_state,
                selected_bridge,
                &unused_policy(),
                &unused_deposit_policy(),
                None,
                &verifier,
                schedule,
            )
            .unwrap(),
        ConnectResult::Reorg(_)
    ));
    assert_eq!(chain.tip_height, BlockHeight(3));
    assert_eq!(caller_state.state_root(), state.state_root());
}

#[test]
fn v1_parent_and_v2_activation_commit_atomically_then_accept_v2_child() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_4132);
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

    let configured =
        dom_core::configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST).unwrap();
    let chain_id = dom_consensus::derive_chain_id(NETWORK_MAGIC_REGTEST, &configured);
    let canonical = build_canonical_genesis(NETWORK_MAGIC_REGTEST, chain_id.as_bytes()).unwrap();
    let genesis = canonical.block.clone().unwrap();
    let v1_schedule = native_usdom_v4_regtest_activation_schedule(selected_bridge).unwrap();
    let mut v1_state = NativeUsdomState::new(selected_bridge).unwrap();
    let activation =
        native_usdom_v4_activation_updates_for_schedule(&v1_state, v1_schedule, canonical.hash, 0)
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
            &activation,
        )
        .unwrap();
    let mut chain =
        ChainState::open_with_utxo_repair(store, canonical.hash, NETWORK_MAGIC_REGTEST).unwrap();

    let final_v1 = mine_v4_child(
        &genesis,
        canonical.hash,
        canonical.hash,
        &v1_state,
        chain_id.as_bytes(),
        0x71,
    );
    let final_v1_hash =
        canonical_header_identifier(NETWORK_MAGIC_REGTEST, &final_v1.header.to_bytes().unwrap())
            .unwrap();
    let final_v1_package =
        UsdomV4BlockPackage::new(final_v1.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();

    let rejected = chain.connect_usdom_v4_package_and_activate_v2_for_schedule(
        &final_v1_package,
        final_v1.timestamp_after_margin(),
        &mut v1_state,
        selected_bridge,
        &unused_policy(),
        &unused_deposit_policy(),
        None,
        &verifier,
        v1_schedule,
        3,
    );
    assert!(rejected.is_err());
    assert_eq!(chain.tip_hash, canonical.hash);
    assert!(chain
        .store
        .get_consensus_state(b"usdom-v2/activation")
        .unwrap()
        .is_none());
    assert!(chain
        .store
        .get_consensus_state(b"usdom-v2/tip")
        .unwrap()
        .is_none());

    let (outcome, v2_schedule) = chain
        .connect_usdom_v4_package_and_activate_v2_for_schedule(
            &final_v1_package,
            final_v1.timestamp_after_margin(),
            &mut v1_state,
            selected_bridge,
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            v1_schedule,
            2,
        )
        .unwrap();
    assert_eq!(outcome, ConnectResult::BestChain);
    assert_eq!(chain.tip_hash, final_v1_hash);
    assert_eq!(v2_schedule.activation_parent(), final_v1_hash);
    assert_eq!(v2_schedule.first_v2_height(), 2);
    assert_eq!(v2_schedule.previous_v1_state_root(), v1_state.state_root());
    let mut v2_state = v1_state.state_commitment_v2().unwrap();
    assert_eq!(v2_schedule.initial_v2_state_root(), v2_state.root());
    assert_eq!(
        restore_persisted_usdom_v2_state_for_schedule(
            &chain.store,
            NETWORK_MAGIC_REGTEST,
            final_v1_hash,
            selected_bridge,
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            v2_schedule,
        )
        .unwrap(),
        v2_state
    );

    let (duplicate, duplicate_schedule) = chain
        .connect_usdom_v4_package_and_activate_v2_for_schedule(
            &final_v1_package,
            final_v1.timestamp_after_margin(),
            &mut v1_state,
            selected_bridge,
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            v1_schedule,
            2,
        )
        .unwrap();
    assert_eq!(duplicate, ConnectResult::AlreadyHave);
    assert_eq!(duplicate_schedule, v2_schedule);
    assert_eq!(
        load_persisted_usdom_v2_activation_schedule(&chain.store).unwrap(),
        Some(v2_schedule)
    );

    let forbidden_v1 = mine_v4_child(
        &final_v1,
        final_v1_hash,
        canonical.hash,
        &v1_state,
        chain_id.as_bytes(),
        0x73,
    );
    let forbidden_v1_package =
        UsdomV4BlockPackage::new(forbidden_v1.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
    assert!(chain
        .connect_usdom_v4_package_for_schedule(
            &forbidden_v1_package,
            forbidden_v1.timestamp_after_margin(),
            &mut v1_state,
            selected_bridge,
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            v1_schedule,
        )
        .is_err());
    assert!(chain
        .ingest_usdom_v4_package_for_schedule(
            &forbidden_v1_package,
            forbidden_v1.timestamp_after_margin(),
            &mut v1_state,
            selected_bridge,
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            v1_schedule,
        )
        .is_err());
    assert_eq!(chain.tip_hash, final_v1_hash);

    let mut v2_runtime = NativeUsdomV2Runtime::restore_for_schedule_with_spend_verifier(
        &chain,
        selected_bridge,
        unused_policy(),
        unused_deposit_policy(),
        None,
        &key_bytes,
        v2_schedule,
    )
    .unwrap();
    assert_eq!(v2_runtime.state(), v2_state);
    assert_eq!(v2_runtime.activation_schedule(), v2_schedule);
    assert_eq!(v2_runtime.bridge_identity(), selected_bridge);
    assert_eq!(
        v2_runtime.spend_verifier_config_hash(),
        verifier.config_hash()
    );

    let witnesses = UsdomV2ExecutionWitnesses::new(Vec::new()).unwrap();
    let first_v2 = mine_v2_empty_child(
        &final_v1,
        final_v1_hash,
        canonical.hash,
        v2_state,
        chain_id.as_bytes(),
        0x72,
    );
    let first_v2_package =
        UsdomV4BlockPackage::new(first_v2.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
    assert_eq!(
        v2_runtime
            .ingest(
                &mut chain,
                &first_v2_package,
                &witnesses,
                first_v2.timestamp_after_margin(),
            )
            .unwrap(),
        ConnectResult::BestChain
    );
    v2_state = v2_runtime.state();
    assert_eq!(chain.tip_height, BlockHeight(2));
    assert_eq!(v2_state.root(), v2_schedule.initial_v2_state_root());
    assert_eq!(
        load_persisted_usdom_v2_activation_schedule(&chain.store).unwrap(),
        Some(v2_schedule)
    );
}

#[test]
fn candidate_v2_direct_ingress_persists_replays_and_continues_after_restart() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_5632);
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

    let configured =
        dom_core::configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST).unwrap();
    let chain_id = dom_consensus::derive_chain_id(NETWORK_MAGIC_REGTEST, &configured);
    let canonical = build_canonical_genesis(NETWORK_MAGIC_REGTEST, chain_id.as_bytes()).unwrap();
    let parent = canonical.block.clone().unwrap();
    let state = NativeUsdomState::new(selected_bridge).unwrap();
    let v1_schedule = native_usdom_v4_regtest_activation_schedule(selected_bridge).unwrap();
    let v2_schedule = NativeUsdomV2ActivationSchedule::new(
        NETWORK_MAGIC_REGTEST,
        chain_id,
        1,
        canonical.hash,
        &state,
    )
    .unwrap();
    let mut activation =
        native_usdom_v4_activation_updates_for_schedule(&state, v1_schedule, canonical.hash, 0)
            .unwrap();
    activation.extend(
        native_usdom_v2_activation_updates(&state, v2_schedule, canonical.hash, 0).unwrap(),
    );
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
            &activation,
        )
        .unwrap();
    let mut chain =
        ChainState::open_with_utxo_repair(store, canonical.hash, NETWORK_MAGIC_REGTEST).unwrap();
    let mut caller_state = state.state_commitment_v2().unwrap();
    let witnesses = UsdomV2ExecutionWitnesses::new(Vec::new()).unwrap();
    let first = mine_v2_empty_child(
        &parent,
        canonical.hash,
        canonical.hash,
        caller_state,
        chain_id.as_bytes(),
        0x81,
    );
    let first_package = UsdomV4BlockPackage::new(first.clone(), UsdomV4ProofEnvelope::empty())
        .unwrap()
        .to_bytes()
        .unwrap();
    let wrong_schedule = NativeUsdomV2ActivationSchedule::new(
        NETWORK_MAGIC_REGTEST,
        chain_id,
        2,
        canonical.hash,
        &state,
    )
    .unwrap();
    assert!(chain
        .connect_usdom_v2_package_for_schedule(
            &first_package,
            &witnesses,
            first.timestamp_after_margin(),
            &mut caller_state,
            selected_bridge,
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            wrong_schedule,
        )
        .is_err());
    assert_eq!(chain.tip_hash, canonical.hash);

    assert_eq!(
        chain
            .connect_usdom_v2_package_for_schedule(
                &first_package,
                &witnesses,
                first.timestamp_after_margin(),
                &mut caller_state,
                selected_bridge,
                &unused_policy(),
                &unused_deposit_policy(),
                None,
                &verifier,
                v2_schedule,
            )
            .unwrap(),
        ConnectResult::BestChain
    );
    let first_hash = chain.tip_hash;
    assert_eq!(chain.tip_height, BlockHeight(1));
    assert_eq!(
        caller_state.root(),
        state.state_commitment_v2().unwrap().root()
    );
    assert_eq!(
        chain
            .connect_usdom_v2_package_for_schedule(
                &first_package,
                &witnesses,
                first.timestamp_after_margin(),
                &mut caller_state,
                selected_bridge,
                &unused_policy(),
                &unused_deposit_policy(),
                None,
                &verifier,
                v2_schedule,
            )
            .unwrap(),
        ConnectResult::AlreadyHave
    );
    drop(chain);

    let reopened_store = DomStore::open_with_map_size(directory.path(), 64 << 20).unwrap();
    let restored = restore_persisted_usdom_v2_state_for_schedule(
        &reopened_store,
        NETWORK_MAGIC_REGTEST,
        first_hash,
        selected_bridge,
        &unused_policy(),
        &unused_deposit_policy(),
        None,
        &verifier,
        v2_schedule,
    )
    .unwrap();
    assert_eq!(restored, caller_state);
    let mut reopened =
        ChainState::open_with_utxo_repair(reopened_store, canonical.hash, NETWORK_MAGIC_REGTEST)
            .unwrap();
    assert_eq!(reopened.tip_hash, first_hash);
    let second = mine_v2_empty_child(
        &first,
        first_hash,
        canonical.hash,
        caller_state,
        chain_id.as_bytes(),
        0x82,
    );
    let second_package = UsdomV4BlockPackage::new(second.clone(), UsdomV4ProofEnvelope::empty())
        .unwrap()
        .to_bytes()
        .unwrap();
    assert_eq!(
        reopened
            .connect_usdom_v2_package_for_schedule(
                &second_package,
                &witnesses,
                second.timestamp_after_margin(),
                &mut caller_state,
                selected_bridge,
                &unused_policy(),
                &unused_deposit_policy(),
                None,
                &verifier,
                v2_schedule,
            )
            .unwrap(),
        ConnectResult::BestChain
    );
    assert_eq!(reopened.tip_height, BlockHeight(2));

    let canonical_second_hash = reopened.tip_hash;
    let (side_two, side_two_hash) = (0x90..=0xff)
        .find_map(|discriminator| {
            let candidate = mine_v2_empty_child(
                &first,
                first_hash,
                canonical.hash,
                caller_state,
                chain_id.as_bytes(),
                discriminator,
            );
            let header_bytes = candidate.header.to_bytes().unwrap();
            let hash = canonical_header_identifier(NETWORK_MAGIC_REGTEST, &header_bytes).unwrap();
            (hash.as_bytes() > canonical_second_hash.as_bytes()).then_some((candidate, hash))
        })
        .expect("a losing equal-work v2 side block must be found");
    let side_two_package =
        UsdomV4BlockPackage::new(side_two.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
    assert_eq!(
        reopened
            .ingest_usdom_v2_package_for_schedule(
                &side_two_package,
                &witnesses,
                side_two.timestamp_after_margin(),
                &mut caller_state,
                selected_bridge,
                &unused_policy(),
                &unused_deposit_policy(),
                None,
                &verifier,
                v2_schedule,
            )
            .unwrap(),
        ConnectResult::SideChain
    );
    assert_eq!(reopened.tip_hash, canonical_second_hash);
    assert_eq!(
        load_persisted_usdom_v4_package(&reopened.store, NETWORK_MAGIC_REGTEST, side_two_hash,)
            .unwrap()
            .unwrap(),
        side_two_package
    );
    assert_eq!(
        load_persisted_usdom_v2_execution_witnesses(&reopened.store, side_two_hash)
            .unwrap()
            .unwrap()
            .to_bytes()
            .unwrap(),
        witnesses.to_bytes().unwrap()
    );

    let side_three = mine_v2_empty_child(
        &side_two,
        side_two_hash,
        canonical.hash,
        caller_state,
        chain_id.as_bytes(),
        0x73,
    );
    let side_three_package =
        UsdomV4BlockPackage::new(side_three.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
    let side_three_hash = reopened
        .store_usdom_v2_side_package_for_schedule(
            &side_three_package,
            &witnesses,
            side_three.timestamp_after_margin(),
            &caller_state,
            selected_bridge,
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            v2_schedule,
        )
        .unwrap();
    assert_eq!(reopened.tip_hash, canonical_second_hash);

    let original_sidecar = reopened
        .store
        .get_block_sidecar(side_three_hash.as_bytes())
        .unwrap()
        .unwrap();
    let mut corrupt_sidecar = original_sidecar.clone();
    let last = corrupt_sidecar.len().checked_sub(1).unwrap();
    corrupt_sidecar[last] ^= 1;
    {
        let mut txn = reopened.store.env.begin_rw_txn().unwrap();
        txn.put(
            reopened.store.db_block_sidecars,
            side_three_hash.as_bytes(),
            &corrupt_sidecar,
            WriteFlags::empty(),
        )
        .unwrap();
        txn.commit().unwrap();
    }
    let state_before_rejected_promotion = caller_state;
    assert!(reopened
        .ingest_usdom_v2_package_for_schedule(
            &side_three_package,
            &witnesses,
            side_three.timestamp_after_margin(),
            &mut caller_state,
            selected_bridge,
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            v2_schedule,
        )
        .is_err());
    assert_eq!(reopened.tip_hash, canonical_second_hash);
    assert_eq!(reopened.tip_height, BlockHeight(2));
    assert_eq!(caller_state, state_before_rejected_promotion);
    assert_eq!(
        reopened.store.get_hash_at_height(2).unwrap(),
        Some(*canonical_second_hash.as_bytes())
    );
    {
        let mut txn = reopened.store.env.begin_rw_txn().unwrap();
        txn.put(
            reopened.store.db_block_sidecars,
            side_three_hash.as_bytes(),
            &original_sidecar,
            WriteFlags::empty(),
        )
        .unwrap();
        txn.commit().unwrap();
    }

    let reorg = match reopened
        .ingest_usdom_v2_package_for_schedule(
            &side_three_package,
            &witnesses,
            side_three.timestamp_after_margin(),
            &mut caller_state,
            selected_bridge,
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            v2_schedule,
        )
        .unwrap()
    {
        ConnectResult::Reorg(reorg) => reorg,
        other => panic!("expected automatic native-v2 reorg, got {other:?}"),
    };
    assert_eq!(reorg.common_ancestor_height, 1);
    assert_eq!(reorg.disconnected_blocks.len(), 1);
    assert_eq!(reorg.connected_blocks.len(), 2);
    assert_eq!(reopened.tip_hash, side_three_hash);
    assert_eq!(reopened.tip_height, BlockHeight(3));
    assert_eq!(
        reopened.store.get_hash_at_height(2).unwrap(),
        Some(*side_two_hash.as_bytes())
    );
    assert_eq!(
        reopened.store.get_hash_at_height(3).unwrap(),
        Some(*side_three_hash.as_bytes())
    );
    assert!(reopened
        .store
        .get_utxo(second.coinbase.output.commitment.as_bytes())
        .unwrap()
        .is_none());
    assert!(reopened
        .store
        .get_utxo(side_two.coinbase.output.commitment.as_bytes())
        .unwrap()
        .is_some());
    assert!(reopened
        .store
        .get_utxo(side_three.coinbase.output.commitment.as_bytes())
        .unwrap()
        .is_some());
    assert_eq!(
        load_persisted_usdom_v4_package(
            &reopened.store,
            NETWORK_MAGIC_REGTEST,
            canonical_second_hash,
        )
        .unwrap()
        .unwrap(),
        second_package
    );
    assert_eq!(
        restore_persisted_usdom_v2_state_for_schedule(
            &reopened.store,
            NETWORK_MAGIC_REGTEST,
            side_three_hash,
            selected_bridge,
            &unused_policy(),
            &unused_deposit_policy(),
            None,
            &verifier,
            v2_schedule,
        )
        .unwrap(),
        caller_state
    );
    assert_eq!(
        reopened
            .ingest_usdom_v2_package_for_schedule(
                &side_three_package,
                &witnesses,
                side_three.timestamp_after_margin(),
                &mut caller_state,
                selected_bridge,
                &unused_policy(),
                &unused_deposit_policy(),
                None,
                &verifier,
                v2_schedule,
            )
            .unwrap(),
        ConnectResult::AlreadyHave
    );

    drop(reopened);
    let reopened_store = DomStore::open_with_map_size(directory.path(), 64 << 20).unwrap();
    let restored_after_reorg = restore_persisted_usdom_v2_state_for_schedule(
        &reopened_store,
        NETWORK_MAGIC_REGTEST,
        side_three_hash,
        selected_bridge,
        &unused_policy(),
        &unused_deposit_policy(),
        None,
        &verifier,
        v2_schedule,
    )
    .unwrap();
    assert_eq!(restored_after_reorg, caller_state);
    let reopened_after_reorg =
        ChainState::open_with_utxo_repair(reopened_store, canonical.hash, NETWORK_MAGIC_REGTEST)
            .unwrap();
    assert_eq!(reopened_after_reorg.tip_hash, side_three_hash);
    assert_eq!(reopened_after_reorg.tip_height, BlockHeight(3));
}

trait TimestampMargin {
    fn timestamp_after_margin(&self) -> Timestamp;
}

impl TimestampMargin for Block {
    fn timestamp_after_margin(&self) -> Timestamp {
        Timestamp(self.header.timestamp.0 + MAX_FUTURE_BLOCK_TIME)
    }
}
