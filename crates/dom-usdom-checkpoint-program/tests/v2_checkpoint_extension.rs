#![cfg(feature = "host-reference")]

use std::collections::BTreeMap;

use ark_bn254::Bn254;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::CanonicalSerialize;
use dom_chain::{
    canonical_header_identifier, NativeUsdomV2ActivationSchedule, UsdomV2ExecutionWitnesses,
    UsdomV4BlockPackage, UsdomV4ProofEnvelope,
};
use dom_consensus::block::ProofOfWork;
use dom_consensus::{
    bind_usdom_batch_commitment, compute_block_pmmr_roots, derive_chain_id, Block, BlockHeader,
    CoinbaseKernel, CoinbaseTransaction, TransactionOutput,
};
use dom_core::{
    BlockHeight, Hash256, Timestamp, BLOCK_VERSION_V4, KERNEL_FEAT_COINBASE, MAX_FUTURE_BLOCK_TIME,
    NETWORK_MAGIC_REGTEST, TAG_KERNEL_MSG_COINBASE, TARGET_SPACING,
};
use dom_crypto::pedersen::Commitment;
use dom_crypto::{blake2b_256_tagged, schnorr_sign, BlindingFactor, SecretKey};
use dom_pow::{
    fast_pow_hash, hash_meets_target, target_to_compact, target_to_difficulty_for_network_height,
    CompactTarget,
};
use dom_serialization::DomSerialize;
use dom_usdom_checkpoint_program::{
    economic_chunk_package_commitment, execute_checkpoint_extension_v2_with_witnesses,
    execute_checkpoint_segment_portable, validate_checkpoint_outer_chain, CheckpointOuterChain,
    CheckpointProgramError, CheckpointProgramPolicyV2, CheckpointSegmentBlockInput,
    CheckpointSegmentNativeStateOpening, CheckpointSegmentPolicyInput,
    CheckpointSegmentPrivateInput, CheckpointSegmentState, CheckpointSegmentTransition,
    EconomicBlockTransition, EconomicBlockWitness, EconomicRoots, EconomicState,
    MAX_CHECKPOINT_OUTER_CHAIN_BYTES, MAX_CHECKPOINT_OUTER_SEGMENTS,
};
use dom_usdom_checkpoint_statement::{
    checkpoint_economic_state_root, CheckpointContext, CheckpointStatement, CheckpointStatementV4,
    ContextHeader, SeedAnchor, CHECKPOINT_CONTEXT_HEADER_COUNT,
    CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS,
};
use dom_usdom_privacy::{
    chain_scalar,
    circuit::{InputWitness, OutputWitness, SpendCircuit, SpendStatement},
    empty_subtree_roots, memo_scalar, owner_commitment,
    verifier::SpendVerifier,
    IncrementalNoteTree, NoteOpening, Scalar, NOTE_ORIGIN_ISSUANCE, NOTE_ORIGIN_PRIVATE,
    NOTE_TREE_DEPTH,
};
use dom_usdom_state::{
    apply_v2_transition_batch_with_receipt, derive_private_burn_id, encode_private_burn_payload,
    encode_private_transfer_payload, private_burn_effect_scalar, verify_private_burn_payload,
    verify_private_transfer_payload, BatchUndo, BlockContext, BridgeIdentity, BurnRecord,
    BurnTimingPolicy, NativeTransitionWitness, NativeUsdomState, StateCommitmentV2,
    VerifiedTransition, RESERVE_MAX_CERTIFICATE_LIFETIME_SECS, RESERVE_MIN_EXECUTION_WINDOW_SECS,
};
use primitive_types::U256;
use rand::{rngs::StdRng, SeedableRng};
use usdom_ethereum_finality_experiment::{
    checkpoints::{CheckpointPolicy, CheckpointTrustPolicy, StaticCheckpointTrustPolicy},
    deposits::{DepositTrustPolicy, ReserveDepositPolicy, StaticDepositTrustPolicy},
    EthereumForks,
};

const DOMAIN: [u8; 32] = [0x11; 32];
const CHECKPOINT_INTERVAL: u32 = 360;
const CONFIRMATION_DEPTH: u32 = 30;
const PREVIOUS_HEIGHT: u64 = 10;

fn checkpoint_policy() -> StaticCheckpointTrustPolicy {
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

fn spend_setup() -> (ProvingKey<Bn254>, Vec<u8>, SpendVerifier) {
    let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_5632);
    let parameters = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        SpendCircuit::default(),
        &mut rng,
    )
    .unwrap();
    let mut bytes = Vec::new();
    parameters.vk.serialize_compressed(&mut bytes).unwrap();
    let verifier = SpendVerifier::from_bytes(&bytes).unwrap();
    (parameters, bytes, verifier)
}

fn seeded_activation_state(bridge: BridgeIdentity) -> NativeUsdomState {
    let mut entries = BTreeMap::new();
    for line in include_str!("fixtures/seeded_activation_state_v3.hex").lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').unwrap();
        assert!(entries
            .insert(hex::decode(key).unwrap(), hex::decode(value).unwrap())
            .is_none());
    }
    NativeUsdomState::restore_entries(bridge, &entries).unwrap()
}

fn scalar(value: u8) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    Scalar::from_bytes(bytes).unwrap()
}

fn bridge(
    checkpoint: &StaticCheckpointTrustPolicy,
    deposit: &StaticDepositTrustPolicy,
    verifier: &SpendVerifier,
) -> BridgeIdentity {
    let mut ethereum_chain_id = [0; 32];
    ethereum_chain_id[31] = 1;
    BridgeIdentity {
        dom_domain: DOMAIN,
        ethereum_genesis_validators_root: [0x22; 32],
        ethereum_chain_id,
        ethereum_checkpoint_policy_hash: checkpoint.policy_hash().into(),
        ethereum_deposit_policy_hash: deposit.policy_hash().into(),
        privacy_policy_hash: *dom_chain::native_usdom_v4::native_usdom_privacy_policy_hash()
            .as_bytes(),
        privacy_verifier_config_hash: *verifier.config_hash().as_bytes(),
        reserve: [0x33; 20],
        burn_timing: BurnTimingPolicy {
            withdrawal_delay_secs: 86_400,
            min_execution_window_secs: RESERVE_MIN_EXECUTION_WINDOW_SECS,
            max_certificate_lifetime_secs: RESERVE_MAX_CERTIFICATE_LIFETIME_SECS,
            relay_safety_margin_secs: 3_600,
            max_ethereum_anchor_age_secs: 1_800,
            max_dom_clock_lead_secs: MAX_FUTURE_BLOCK_TIME,
        },
    }
}

fn coinbase(height: BlockHeight, chain_id: &[u8; 32], discriminator: u64) -> CoinbaseTransaction {
    let value = dom_core::block_reward(height).noms();
    let mut scalar = [0u8; 32];
    scalar[24..].copy_from_slice(&(discriminator + 1).to_be_bytes());
    let blinding = BlindingFactor::from_bytes(scalar).unwrap();
    let commitment = Commitment::commit(value, &blinding);
    let (proof, proof_commitment) =
        dom_crypto::range_proof_prove_bytes_with_nonce(value, &blinding, &[0x52; 32]).unwrap();
    assert_eq!(proof_commitment, *commitment.as_bytes());
    let excess = Commitment::commit(0, &blinding);
    let secret = SecretKey::from_bytes(blinding.as_bytes()).unwrap();
    let mut message = vec![KERNEL_FEAT_COINBASE];
    message.extend_from_slice(&value.to_le_bytes());
    let digest = blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &message);
    let signature = schnorr_sign(&secret, digest.as_bytes(), chain_id).unwrap();
    CoinbaseTransaction {
        output: TransactionOutput { commitment, proof },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value: value,
            excess,
            excess_signature: signature.to_bytes(),
        },
        offset: [0; 32],
    }
}

#[allow(clippy::too_many_arguments)]
fn block(
    height: u64,
    previous: Hash256,
    timestamp: u64,
    previous_difficulty: U256,
    genesis: Hash256,
    chain_id: &[u8; 32],
    state: StateCommitmentV2,
    transitions: &[VerifiedTransition],
    witnesses: &[NativeTransitionWitness],
) -> (Block, U256, StateCommitmentV2) {
    let height = BlockHeight(height);
    let timestamp = Timestamp(timestamp);
    let coinbase = coinbase(height, chain_id, height.0);
    let (output_root, kernel_root, raw_rangeproof_root) =
        compute_block_pmmr_roots(height, &coinbase, &[]).unwrap();
    let (next_state, receipt) = apply_v2_transition_batch_with_receipt(
        state.root(),
        BlockContext {
            timestamp: timestamp.0,
        },
        state,
        transitions,
        witnesses,
    )
    .unwrap();
    let rangeproof_root =
        bind_usdom_batch_commitment(raw_rangeproof_root, receipt.header_commitment).unwrap();
    let target =
        dom_pow::compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, height).unwrap();
    let compact = CompactTarget(target_to_compact(&target));
    let canonical_target = compact.to_target().unwrap();
    let difficulty = previous_difficulty
        + target_to_difficulty_for_network_height(NETWORK_MAGIC_REGTEST, height, &canonical_target)
            .unwrap();
    let mut nonce = 0;
    loop {
        let mut header = BlockHeader {
            version: BLOCK_VERSION_V4,
            height,
            prev_hash: previous,
            timestamp,
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: [0; 32],
            target: compact,
            total_difficulty: difficulty,
            pow: ProofOfWork {
                nonce,
                randomx_hash: Hash256::ZERO,
            },
        };
        let hash = fast_pow_hash(genesis.as_bytes(), &header.pow_preimage());
        if hash_meets_target(&hash, &canonical_target) {
            header.pow.randomx_hash = Hash256::from_bytes(hash);
            return (
                Block {
                    header,
                    coinbase,
                    transactions: Vec::new(),
                },
                difficulty,
                next_state,
            );
        }
        nonce = nonce.wrapping_add(1);
    }
}

fn difficulty_bytes(value: U256) -> [u8; 32] {
    let mut bytes = [0; 32];
    value.to_big_endian(&mut bytes);
    bytes
}

#[test]
fn segment_policy_preimages_are_authenticated_against_recursive_state() {
    let checkpoint = checkpoint_policy();
    let deposit = deposit_policy();
    let (_, verifying_key, verifier) = spend_setup();
    let bridge = bridge(&checkpoint, &deposit, &verifier);
    let native_state = NativeUsdomState::new(bridge).unwrap();
    let genesis = Hash256::from_bytes([0x71; 32]);
    let chain_id = derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis);
    let height = 100u64;
    let activation_parent = Hash256::from_bytes([0x72; 32]);
    let schedule = NativeUsdomV2ActivationSchedule::new(
        NETWORK_MAGIC_REGTEST,
        chain_id,
        height + 1,
        activation_parent,
        &native_state,
    )
    .unwrap();
    let economic_utxo_root = [0x31; 32];
    let economic_kernel_root = [0x32; 32];
    let mut recent_headers = [ContextHeader {
        height: 0,
        block: [0; 32],
        timestamp: 0,
    }; CHECKPOINT_CONTEXT_HEADER_COUNT];
    for (index, header) in recent_headers.iter_mut().enumerate() {
        header.height = height - (CHECKPOINT_CONTEXT_HEADER_COUNT - 1 - index) as u64;
        header.block = [0x40 + index as u8; 32];
        header.timestamp = 1_700_000_000 + index as u64;
    }
    recent_headers[CHECKPOINT_CONTEXT_HEADER_COUNT - 1].block = *activation_parent.as_bytes();
    let context = CheckpointContext {
        checkpoint_height: height,
        checkpoint_block: *activation_parent.as_bytes(),
        max_span: 390,
        economic_state_root: checkpoint_economic_state_root(
            economic_utxo_root,
            economic_kernel_root,
        )
        .unwrap(),
        recent_headers,
        seed_anchor_count: 0,
        seed_anchors: [SeedAnchor::default(); CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS],
    };
    let state = CheckpointSegmentState {
        network_magic: NETWORK_MAGIC_REGTEST,
        chain_id: *chain_id.as_bytes(),
        activation_schedule_commitment: *schedule.commitment().as_bytes(),
        checkpoint_config_hash: [0x45; 32],
        checkpoint_policy_hash: checkpoint.policy_hash().into(),
        deposit_policy_hash: deposit.policy_hash().into(),
        privacy_verifier_config_hash: *verifier.config_hash().as_bytes(),
        randomx_receipt_image_id: [0x17; 32],
        height,
        block_hash: *activation_parent.as_bytes(),
        native_state_root: *schedule.initial_v2_state_root().as_bytes(),
        economic_utxo_root,
        economic_kernel_root,
        total_difficulty: [0x23; 32],
        context,
    };
    let input = CheckpointSegmentPolicyInput::new(
        *genesis.as_bytes(),
        schedule.to_bytes(),
        checkpoint.to_bytes().try_into().unwrap(),
        deposit.to_bytes().try_into().unwrap(),
        verifying_key.clone(),
    )
    .unwrap();
    let bytes = input.to_bytes().unwrap();
    let decoded = CheckpointSegmentPolicyInput::from_bytes(&bytes).unwrap();
    let validated = decoded.validate_for_state(&state).unwrap();
    assert_eq!(validated.dom_genesis_hash(), genesis);
    assert_eq!(validated.schedule(), schedule);
    assert_eq!(
        validated.checkpoint_policy().policy_hash(),
        checkpoint.policy_hash()
    );
    assert_eq!(
        validated.deposit_policy().policy_hash(),
        deposit.policy_hash()
    );
    assert_eq!(
        validated.spend_verifier().config_hash(),
        verifier.config_hash()
    );
    let initial_v2 = native_state.state_commitment_v2().unwrap();
    let opening = CheckpointSegmentNativeStateOpening::new(initial_v2.to_bytes().unwrap()).unwrap();
    let portable = decoded
        .validate_portable_for_state(&state, &opening)
        .unwrap();
    assert_eq!(portable.dom_genesis_hash(), *genesis.as_bytes());
    assert_eq!(portable.schedule().to_bytes(), schedule.to_bytes());
    assert_eq!(
        portable.schedule().commitment(),
        *schedule.commitment().as_bytes()
    );
    assert_eq!(portable.bridge(), bridge);
    assert_eq!(portable.previous_native_state(), initial_v2);
    assert_eq!(
        portable.checkpoint_policy().policy_hash(),
        checkpoint.policy_hash()
    );
    assert_eq!(
        portable.deposit_policy().policy_hash(),
        deposit.policy_hash()
    );
    assert_eq!(
        portable.spend_verifier().config_hash(),
        verifier.config_hash()
    );

    let mut wrong_genesis = *genesis.as_bytes();
    wrong_genesis[0] ^= 1;
    assert!(CheckpointSegmentPolicyInput::new(
        wrong_genesis,
        schedule.to_bytes(),
        checkpoint.to_bytes().try_into().unwrap(),
        deposit.to_bytes().try_into().unwrap(),
        verifying_key,
    )
    .unwrap()
    .validate_for_state(&state)
    .is_err());
    let mut wrong_state = state;
    wrong_state.checkpoint_policy_hash[0] ^= 1;
    assert!(input.validate_for_state(&wrong_state).is_err());
}

#[test]
fn portable_segment_executes_exact_empty_native_batch_and_economic_witness() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let checkpoint = checkpoint_policy();
    let deposit = deposit_policy();
    let (_, verifying_key, verifier) = spend_setup();
    let bridge = bridge(&checkpoint, &deposit, &verifier);
    let native_state = NativeUsdomState::new(bridge).unwrap();
    let previous_native = native_state.state_commitment_v2().unwrap();
    let genesis = Hash256::from_bytes([0x71; 32]);
    let chain_id = derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis);
    let previous_height = 100u64;
    let previous_block = Hash256::from_bytes([0x72; 32]);
    let schedule = NativeUsdomV2ActivationSchedule::new(
        NETWORK_MAGIC_REGTEST,
        chain_id,
        previous_height + 1,
        previous_block,
        &native_state,
    )
    .unwrap();
    let previous_difficulty = U256::from(1u64);
    let block_timestamp = 1_700_000_011u64;
    let (candidate, next_difficulty, next_native) = block(
        previous_height + 1,
        previous_block,
        block_timestamp,
        previous_difficulty,
        genesis,
        chain_id.as_bytes(),
        previous_native,
        &[],
        &[],
    );
    let header_bytes = DomSerialize::to_bytes(&candidate.header).unwrap();
    let next_block = canonical_header_identifier(NETWORK_MAGIC_REGTEST, &header_bytes).unwrap();
    let package = UsdomV4BlockPackage::new(candidate.clone(), UsdomV4ProofEnvelope::empty())
        .unwrap()
        .to_bytes()
        .unwrap();
    let native_witnesses = UsdomV2ExecutionWitnesses::new(vec![])
        .unwrap()
        .to_bytes()
        .unwrap();
    let mut economic_state = EconomicState::default();
    let previous_economic = EconomicRoots {
        utxo_root: economic_state.utxo_set_root().unwrap(),
        kernel_root: economic_state.kernel_set_root().unwrap(),
    };
    let economic_witness = EconomicBlockWitness::from_state(&economic_state, &candidate).unwrap();
    economic_state
        .apply_block(&candidate, dom_core::REGTEST_COINBASE_MATURITY)
        .unwrap();
    let next_economic = EconomicRoots {
        utxo_root: economic_state.utxo_set_root().unwrap(),
        kernel_root: economic_state.kernel_set_root().unwrap(),
    };

    let mut recent_headers = [ContextHeader {
        height: 0,
        block: [0; 32],
        timestamp: 0,
    }; CHECKPOINT_CONTEXT_HEADER_COUNT];
    for (index, header) in recent_headers.iter_mut().enumerate() {
        header.height = previous_height - (CHECKPOINT_CONTEXT_HEADER_COUNT - 1 - index) as u64;
        header.block = [0x40 + index as u8; 32];
        header.timestamp = block_timestamp - (CHECKPOINT_CONTEXT_HEADER_COUNT - index) as u64;
    }
    recent_headers[CHECKPOINT_CONTEXT_HEADER_COUNT - 1].block = *previous_block.as_bytes();
    let previous_context = CheckpointContext {
        checkpoint_height: previous_height,
        checkpoint_block: *previous_block.as_bytes(),
        max_span: 2,
        economic_state_root: checkpoint_economic_state_root(
            previous_economic.utxo_root,
            previous_economic.kernel_root,
        )
        .unwrap(),
        recent_headers,
        seed_anchor_count: 0,
        seed_anchors: [SeedAnchor::default(); CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS],
    };
    let previous = CheckpointSegmentState {
        network_magic: NETWORK_MAGIC_REGTEST,
        chain_id: *chain_id.as_bytes(),
        activation_schedule_commitment: *schedule.commitment().as_bytes(),
        checkpoint_config_hash: [0x45; 32],
        checkpoint_policy_hash: checkpoint.policy_hash().into(),
        deposit_policy_hash: deposit.policy_hash().into(),
        privacy_verifier_config_hash: *verifier.config_hash().as_bytes(),
        randomx_receipt_image_id: [0x17; 32],
        height: previous_height,
        block_hash: *previous_block.as_bytes(),
        native_state_root: *previous_native.root().as_bytes(),
        economic_utxo_root: previous_economic.utxo_root,
        economic_kernel_root: previous_economic.kernel_root,
        total_difficulty: difficulty_bytes(previous_difficulty),
        context: previous_context,
    };
    let mut next_recent = previous_context.recent_headers;
    next_recent.rotate_left(1);
    next_recent[CHECKPOINT_CONTEXT_HEADER_COUNT - 1] = ContextHeader {
        height: previous_height + 1,
        block: *next_block.as_bytes(),
        timestamp: block_timestamp,
    };
    let next = CheckpointSegmentState {
        height: previous_height + 1,
        block_hash: *next_block.as_bytes(),
        native_state_root: *next_native.root().as_bytes(),
        economic_utxo_root: next_economic.utxo_root,
        economic_kernel_root: next_economic.kernel_root,
        total_difficulty: difficulty_bytes(next_difficulty),
        context: CheckpointContext {
            checkpoint_height: previous_height + 1,
            checkpoint_block: *next_block.as_bytes(),
            max_span: 2,
            economic_state_root: checkpoint_economic_state_root(
                next_economic.utxo_root,
                next_economic.kernel_root,
            )
            .unwrap(),
            recent_headers: next_recent,
            seed_anchor_count: 0,
            seed_anchors: [SeedAnchor::default(); CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS],
        },
        ..previous
    };
    let economic_witness_bytes = economic_witness.to_bytes().unwrap();
    let private_input = CheckpointSegmentPrivateInput::new(vec![CheckpointSegmentBlockInput::new(
        package.clone(),
        native_witnesses.clone(),
        economic_witness_bytes.clone(),
    )
    .unwrap()])
    .unwrap();
    let transition = private_input.transition_statement(previous, next).unwrap();
    let policy_input = CheckpointSegmentPolicyInput::new(
        *genesis.as_bytes(),
        schedule.to_bytes(),
        checkpoint.to_bytes().try_into().unwrap(),
        deposit.to_bytes().try_into().unwrap(),
        verifying_key,
    )
    .unwrap();
    let opening =
        CheckpointSegmentNativeStateOpening::new(previous_native.to_bytes().unwrap()).unwrap();

    let executed =
        execute_checkpoint_segment_portable(&transition, &private_input, &policy_input, &opening)
            .unwrap();
    assert_eq!(
        executed.transition_commitment(),
        transition.commitment().unwrap()
    );
    assert_eq!(executed.randomx_bindings().len(), 1);
    assert_eq!(
        executed.randomx_bindings()[0].block_hash(),
        next_block.as_bytes()
    );
    assert!(executed.economic_block_bindings().is_empty());

    let economic_claim = EconomicBlockTransition {
        network_magic: NETWORK_MAGIC_REGTEST,
        package_commitment: economic_chunk_package_commitment(
            private_input.blocks()[0].package_bytes(),
        ),
        block_hash: *next_block.as_bytes(),
        block_height: previous_height + 1,
        utxo_effects: 1,
        kernel_effects: 1,
        previous_roots: previous_economic,
        next_roots: next_economic,
    };
    let recursive_input =
        CheckpointSegmentPrivateInput::new(vec![CheckpointSegmentBlockInput::new(
            private_input.blocks()[0].package_bytes().to_vec(),
            native_witnesses.clone(),
            economic_claim.to_bytes().unwrap().to_vec(),
        )
        .unwrap()])
        .unwrap();
    let recursive_transition = recursive_input
        .transition_statement(previous, next)
        .unwrap();
    let recursive_execution = execute_checkpoint_segment_portable(
        &recursive_transition,
        &recursive_input,
        &policy_input,
        &opening,
    )
    .unwrap();
    assert_eq!(recursive_execution.economic_block_bindings().len(), 1);
    assert_eq!(
        recursive_execution.economic_block_bindings()[0].journal(),
        &economic_claim.commitment().unwrap()
    );

    let mut wrong_economic_claim = economic_claim;
    wrong_economic_claim.package_commitment[0] ^= 1;
    let wrong_recursive_input =
        CheckpointSegmentPrivateInput::new(vec![CheckpointSegmentBlockInput::new(
            private_input.blocks()[0].package_bytes().to_vec(),
            native_witnesses.clone(),
            wrong_economic_claim.to_bytes().unwrap().to_vec(),
        )
        .unwrap()])
        .unwrap();
    let wrong_recursive_transition = wrong_recursive_input
        .transition_statement(previous, next)
        .unwrap();
    assert!(execute_checkpoint_segment_portable(
        &wrong_recursive_transition,
        &wrong_recursive_input,
        &policy_input,
        &opening,
    )
    .is_err());

    let mut wrong_next = transition;
    wrong_next.next.native_state_root[0] ^= 1;
    assert!(execute_checkpoint_segment_portable(
        &wrong_next,
        &private_input,
        &policy_input,
        &opening,
    )
    .is_err());

    let mut malformed_package = package;
    malformed_package[0] ^= 1;
    let malformed_package_input =
        CheckpointSegmentPrivateInput::new(vec![CheckpointSegmentBlockInput::new(
            malformed_package,
            native_witnesses.clone(),
            economic_witness_bytes.clone(),
        )
        .unwrap()])
        .unwrap();
    let malformed_package_transition = malformed_package_input
        .transition_statement(previous, next)
        .unwrap();
    assert!(execute_checkpoint_segment_portable(
        &malformed_package_transition,
        &malformed_package_input,
        &policy_input,
        &opening,
    )
    .is_err());

    let mut malformed_native_witness = native_witnesses;
    malformed_native_witness[0] ^= 1;
    let malformed_native_input =
        CheckpointSegmentPrivateInput::new(vec![CheckpointSegmentBlockInput::new(
            private_input.blocks()[0].package_bytes().to_vec(),
            malformed_native_witness,
            economic_witness_bytes.clone(),
        )
        .unwrap()])
        .unwrap();
    let malformed_native_transition = malformed_native_input
        .transition_statement(previous, next)
        .unwrap();
    assert!(execute_checkpoint_segment_portable(
        &malformed_native_transition,
        &malformed_native_input,
        &policy_input,
        &opening,
    )
    .is_err());

    let mut malformed_economic_witness = economic_witness_bytes;
    malformed_economic_witness[0] ^= 1;
    let malformed_economic_input =
        CheckpointSegmentPrivateInput::new(vec![CheckpointSegmentBlockInput::new(
            private_input.blocks()[0].package_bytes().to_vec(),
            private_input.blocks()[0].native_witness_bytes().to_vec(),
            malformed_economic_witness,
        )
        .unwrap()])
        .unwrap();
    let malformed_economic_transition = malformed_economic_input
        .transition_statement(previous, next)
        .unwrap();
    assert!(execute_checkpoint_segment_portable(
        &malformed_economic_transition,
        &malformed_economic_input,
        &policy_input,
        &opening,
    )
    .is_err());

    let mut committed_input_bytes = private_input.to_bytes().unwrap();
    *committed_input_bytes.last_mut().unwrap() ^= 1;
    let different_private_input =
        CheckpointSegmentPrivateInput::from_bytes(&committed_input_bytes).unwrap();
    assert!(execute_checkpoint_segment_portable(
        &transition,
        &different_private_input,
        &policy_input,
        &opening,
    )
    .is_err());

    let confirmation_block = [0x88; 32];
    let confirmation_difficulty = next_difficulty + U256::one();
    let mut confirmation_recent = next.context.recent_headers;
    confirmation_recent.rotate_left(1);
    confirmation_recent[CHECKPOINT_CONTEXT_HEADER_COUNT - 1] = ContextHeader {
        height: previous_height + 2,
        block: confirmation_block,
        timestamp: block_timestamp + 1,
    };
    let confirmation = CheckpointSegmentState {
        height: previous_height + 2,
        block_hash: confirmation_block,
        total_difficulty: difficulty_bytes(confirmation_difficulty),
        context: CheckpointContext {
            checkpoint_height: previous_height + 2,
            checkpoint_block: confirmation_block,
            max_span: 2,
            economic_state_root: next.context.economic_state_root,
            recent_headers: confirmation_recent,
            seed_anchor_count: 0,
            seed_anchors: [SeedAnchor::default(); CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS],
        },
        ..next
    };
    let confirmation_transition = CheckpointSegmentTransition {
        block_count: 1,
        private_input_commitment: [0x55; 32],
        previous: next,
        next: confirmation,
    };
    let outer_chain = CheckpointOuterChain::new(vec![transition, confirmation_transition]).unwrap();
    assert_eq!(MAX_CHECKPOINT_OUTER_SEGMENTS, 720);
    assert_eq!(MAX_CHECKPOINT_OUTER_CHAIN_BYTES, 1_622_892);
    let statement = CheckpointStatementV4 {
        checkpoint: CheckpointStatement {
            bridge_domain: DOMAIN,
            dom_network_magic: NETWORK_MAGIC_REGTEST,
            previous_height,
            previous_block: *previous_block.as_bytes(),
            previous_state_root: previous.native_state_root,
            previous_context_hash: previous.context.commitment().unwrap(),
            previous_total_difficulty: previous.total_difficulty,
            height: previous_height + 1,
            block: next.block_hash,
            state_root: next.native_state_root,
            context_hash: next.context.commitment().unwrap(),
            total_difficulty: next.total_difficulty,
            confirmation_height: previous_height + 2,
            confirmation_block,
            confirmation_total_difficulty: confirmation.total_difficulty,
            confirmation_timestamp: block_timestamp + 1,
            ethereum_chain_id: bridge.ethereum_chain_id,
            registry: [0x42; 20],
            activation_schedule_commitment: previous.activation_schedule_commitment,
            checkpoint_config_hash: previous.checkpoint_config_hash,
        },
    };
    let outer = validate_checkpoint_outer_chain(
        &statement,
        &outer_chain,
        &policy_input,
        &opening,
        [0x99; 32],
    )
    .unwrap();
    assert_eq!(outer.statement_hash(), statement.statement_hash().unwrap());
    assert_eq!(outer.segment_receipts().len(), 2);
    assert_eq!(outer.segment_receipts()[0].image_id(), &[0x99; 32]);
    assert_eq!(
        outer.segment_receipts()[0].journal(),
        &transition.commitment().unwrap()
    );
    assert_eq!(
        CheckpointOuterChain::from_bytes(&outer_chain.to_bytes().unwrap()).unwrap(),
        outer_chain
    );
    let outer_bytes = outer_chain.to_bytes().unwrap();
    for end in 0..outer_bytes.len() {
        assert!(CheckpointOuterChain::from_bytes(&outer_bytes[..end]).is_err());
    }
    let mut trailing_outer = outer_bytes.clone();
    trailing_outer.push(0);
    assert!(CheckpointOuterChain::from_bytes(&trailing_outer).is_err());
    let mut wrong_outer_magic = outer_bytes;
    wrong_outer_magic[0] ^= 1;
    assert!(CheckpointOuterChain::from_bytes(&wrong_outer_magic).is_err());

    let mut wrong_target = statement;
    wrong_target.checkpoint.state_root[0] ^= 1;
    assert!(validate_checkpoint_outer_chain(
        &wrong_target,
        &outer_chain,
        &policy_input,
        &opening,
        [0x99; 32],
    )
    .is_err());
    let mut wrong_previous = statement;
    wrong_previous.checkpoint.previous_context_hash[0] ^= 1;
    assert!(validate_checkpoint_outer_chain(
        &wrong_previous,
        &outer_chain,
        &policy_input,
        &opening,
        [0x99; 32],
    )
    .is_err());
    let mut wrong_confirmation = statement;
    wrong_confirmation.checkpoint.confirmation_timestamp += 1;
    assert!(validate_checkpoint_outer_chain(
        &wrong_confirmation,
        &outer_chain,
        &policy_input,
        &opening,
        [0x99; 32],
    )
    .is_err());
    let mut wrong_registry = statement;
    wrong_registry.checkpoint.registry[0] ^= 1;
    assert!(validate_checkpoint_outer_chain(
        &wrong_registry,
        &outer_chain,
        &policy_input,
        &opening,
        [0x99; 32],
    )
    .is_err());
    let mut wrong_schedule = statement;
    wrong_schedule.checkpoint.activation_schedule_commitment[0] ^= 1;
    assert!(validate_checkpoint_outer_chain(
        &wrong_schedule,
        &outer_chain,
        &policy_input,
        &opening,
        [0x99; 32],
    )
    .is_err());
    let reordered = CheckpointOuterChain::new(vec![confirmation_transition, transition]).unwrap();
    assert!(validate_checkpoint_outer_chain(
        &statement,
        &reordered,
        &policy_input,
        &opening,
        [0x99; 32],
    )
    .is_err());
    assert!(validate_checkpoint_outer_chain(
        &statement,
        &outer_chain,
        &policy_input,
        &opening,
        [0; 32],
    )
    .is_err());
    let crossing_target = CheckpointOuterChain::new(vec![CheckpointSegmentTransition {
        block_count: 2,
        private_input_commitment: [0x66; 32],
        previous,
        next: confirmation,
    }])
    .unwrap();
    assert!(validate_checkpoint_outer_chain(
        &statement,
        &crossing_target,
        &policy_input,
        &opening,
        [0x99; 32],
    )
    .is_err());
}

#[test]
#[ignore = "full 390-block release-vector exercise"]
fn full_360_plus_30_v2_checkpoint_extension_is_recomputed() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let checkpoint = checkpoint_policy();
    let deposit = deposit_policy();
    let (parameters, _, verifier) = spend_setup();
    let bridge = bridge(&checkpoint, &deposit, &verifier);
    let native_state = seeded_activation_state(bridge);
    assert_eq!(native_state.total_issued(), 10);
    assert_eq!(native_state.total_burned(), 0);
    let initial_v2 = native_state.state_commitment_v2().unwrap();

    // The activation snapshot contains one previously ratified issuance. From
    // this point onward every private state change is proven and independently
    // reverified by the checkpoint relation; no unsafe oracle is compiled into
    // this release-profile test.
    let chain = chain_scalar(DOMAIN, bridge.privacy_policy_hash);
    let issuance_secret = scalar(7);
    let issuance_note = NoteOpening {
        chain,
        origin: NOTE_ORIGIN_ISSUANCE,
        value: 10,
        owner: owner_commitment(chain, issuance_secret).unwrap(),
        rho: scalar(8),
    };
    assert_eq!(
        native_state.issuance(&[0x21; 32]).unwrap().note_commitment,
        issuance_note.commitment().unwrap().to_bytes()
    );
    let transfer_owner_secret = scalar(9);
    let transfer_output = OutputWitness {
        enabled: true,
        value: 10,
        owner: owner_commitment(chain, transfer_owner_secret).unwrap(),
        rho: scalar(10),
    };
    let transfer_note = NoteOpening {
        chain,
        origin: NOTE_ORIGIN_PRIVATE,
        value: transfer_output.value,
        owner: transfer_output.owner,
        rho: transfer_output.rho,
    };
    let transfer_commitment = transfer_note.commitment().unwrap().to_bytes();
    let issuance_nullifier = issuance_note.nullifier(issuance_secret).unwrap().to_bytes();
    let transfer_memo = b"checkpoint lifecycle transfer";
    let transfer_anchor = native_state.note_anchor();
    let transfer_statement = SpendStatement {
        chain,
        anchor: Scalar::from_bytes(*transfer_anchor.root.as_bytes()).unwrap(),
        nullifiers: [
            Scalar::from_bytes(issuance_nullifier).unwrap(),
            Scalar::ZERO,
        ],
        output_notes: [
            Scalar::from_bytes(transfer_commitment).unwrap(),
            Scalar::ZERO,
        ],
        burn_amount: 0,
        effect: Scalar::ZERO,
        memo: memo_scalar(transfer_memo).unwrap(),
    };
    let transfer_circuit = SpendCircuit {
        statement: transfer_statement,
        inputs: [
            InputWitness {
                enabled: true,
                origin: NOTE_ORIGIN_ISSUANCE,
                value: issuance_note.value,
                owner_secret: issuance_secret,
                rho: issuance_note.rho,
                leaf_index: 0,
                siblings: empty_subtree_roots()[..NOTE_TREE_DEPTH].try_into().unwrap(),
            },
            InputWitness::default(),
        ],
        outputs: [transfer_output, OutputWitness::default()],
    };
    let mut proof_rng = StdRng::seed_from_u64(0x5553_444f_4d5f_4c43);
    let transfer_proof = Groth16::<Bn254>::create_random_proof_with_reduction(
        transfer_circuit,
        &parameters,
        &mut proof_rng,
    )
    .unwrap();
    let mut transfer_proof_bytes = Vec::new();
    transfer_proof
        .serialize_compressed(&mut transfer_proof_bytes)
        .unwrap();
    let transfer_payload = encode_private_transfer_payload(
        transfer_anchor,
        &[issuance_nullifier],
        &[transfer_commitment],
        transfer_memo,
        &transfer_proof_bytes,
    )
    .unwrap();
    let transfer_transition =
        verify_private_transfer_payload(bridge, &verifier, &transfer_payload).unwrap();

    let mut note_tree = IncrementalNoteTree::new();
    note_tree
        .append(Scalar::from_bytes(issuance_note.commitment().unwrap().to_bytes()).unwrap())
        .unwrap();
    let transfer_path = note_tree.next_leaf_path().unwrap();
    note_tree
        .append(Scalar::from_bytes(transfer_commitment).unwrap())
        .unwrap();
    let burn_anchor = dom_usdom_state::NoteAnchor {
        root: Hash256::from_bytes(note_tree.root().to_bytes()),
        leaf_count: note_tree.leaf_count(),
    };
    let transfer_nullifier = transfer_note
        .nullifier(transfer_owner_secret)
        .unwrap()
        .to_bytes();
    let valid_until = 1_700_095_100;
    let recipient = [0x24; 20];
    let mut burn_record = BurnRecord {
        burn_id: derive_private_burn_id(bridge, &[transfer_nullifier], recipient, 10, valid_until)
            .unwrap(),
        request_id: [0x25; 32],
        amount: 10,
        recipient,
        ethereum_chain_id: bridge.ethereum_chain_id,
        reserve: bridge.reserve,
        valid_until,
        obligation_commitment: [0; 32],
    };
    burn_record.obligation_commitment = burn_record.expected_obligation_commitment(DOMAIN);
    let burn_statement = SpendStatement {
        chain,
        anchor: Scalar::from_bytes(*burn_anchor.root.as_bytes()).unwrap(),
        nullifiers: [
            Scalar::from_bytes(transfer_nullifier).unwrap(),
            Scalar::ZERO,
        ],
        output_notes: [Scalar::ZERO, Scalar::ZERO],
        burn_amount: 10,
        effect: private_burn_effect_scalar(bridge, burn_record).unwrap(),
        memo: Scalar::ZERO,
    };
    let burn_circuit = SpendCircuit {
        statement: burn_statement,
        inputs: [
            InputWitness {
                enabled: true,
                origin: NOTE_ORIGIN_PRIVATE,
                value: transfer_note.value,
                owner_secret: transfer_owner_secret,
                rho: transfer_note.rho,
                leaf_index: 1,
                siblings: transfer_path,
            },
            InputWitness::default(),
        ],
        outputs: [OutputWitness::default(), OutputWitness::default()],
    };
    let burn_proof = Groth16::<Bn254>::create_random_proof_with_reduction(
        burn_circuit,
        &parameters,
        &mut proof_rng,
    )
    .unwrap();
    let mut burn_proof_bytes = Vec::new();
    burn_proof
        .serialize_compressed(&mut burn_proof_bytes)
        .unwrap();
    let burn_payload = encode_private_burn_payload(
        burn_anchor,
        &[transfer_nullifier],
        &[],
        burn_record,
        &[],
        &burn_proof_bytes,
    )
    .unwrap();
    let burn_transition = verify_private_burn_payload(bridge, &verifier, &burn_payload).unwrap();
    let genesis = Hash256::from_bytes([0x77; 32]);
    let chain_id = derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis);
    let initial_economic = EconomicState::default();
    let mut economic = initial_economic.clone();
    let initial_roots = EconomicRoots {
        utxo_root: economic.utxo_set_root().unwrap(),
        kernel_root: economic.kernel_set_root().unwrap(),
    };
    let initial_headers: [ContextHeader; CHECKPOINT_CONTEXT_HEADER_COUNT] =
        std::array::from_fn(|index| ContextHeader {
            height: index as u64,
            block: [index as u8 + 1; 32],
            timestamp: 1_700_000_000 + index as u64 * TARGET_SPACING,
        });
    let previous_block = Hash256::from_bytes(initial_headers[10].block);
    let previous_context = CheckpointContext {
        checkpoint_height: PREVIOUS_HEIGHT,
        checkpoint_block: initial_headers[10].block,
        max_span: CHECKPOINT_INTERVAL + CONFIRMATION_DEPTH,
        economic_state_root: economic.context_root().unwrap(),
        recent_headers: initial_headers,
        seed_anchor_count: 0,
        seed_anchors: [SeedAnchor::default(); CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS],
    };
    let schedule = NativeUsdomV2ActivationSchedule::new(
        NETWORK_MAGIC_REGTEST,
        chain_id,
        PREVIOUS_HEIGHT + 1,
        previous_block,
        &native_state,
    )
    .unwrap();
    let policy = CheckpointProgramPolicyV2::new(
        schedule,
        bridge,
        &native_state,
        genesis,
        CHECKPOINT_INTERVAL,
        CONFIRMATION_DEPTH,
    )
    .unwrap();

    let mut packages = Vec::with_capacity(390);
    let mut native_witnesses: Vec<Vec<NativeTransitionWitness>> = Vec::with_capacity(390);
    let mut economic_witnesses = Vec::with_capacity(390);
    let mut native = native_state.clone();
    let mut current_v2 = initial_v2;
    let mut projections = initial_headers.to_vec();
    let mut parent = previous_block;
    let mut total_difficulty = U256::from(1_000_000u64);
    let previous_total_difficulty = total_difficulty;
    let mut target = None;
    let mut confirmation = None;
    for index in 0..390u64 {
        let height = PREVIOUS_HEIGHT + index + 1;
        let timestamp = initial_headers[10].timestamp + (index + 1) * TARGET_SPACING;
        let (envelope, transitions) = match index {
            0 => (
                UsdomV4ProofEnvelope::private_transfer_proof(transfer_payload.clone()).unwrap(),
                vec![transfer_transition.clone()],
            ),
            1 => (
                UsdomV4ProofEnvelope::private_burn_proof(burn_payload.clone()).unwrap(),
                vec![burn_transition.clone()],
            ),
            _ => (UsdomV4ProofEnvelope::empty(), Vec::new()),
        };
        let block_context = BlockContext { timestamp };
        let witnesses = native
            .transition_batch_witnesses(block_context, &transitions)
            .unwrap();
        let (candidate, difficulty, next_v2) = block(
            height,
            parent,
            timestamp,
            total_difficulty,
            genesis,
            chain_id.as_bytes(),
            current_v2,
            &transitions,
            &witnesses,
        );
        let before_native = native.clone();
        let (full_receipt, full_undo) = native.apply_batch(block_context, &transitions).unwrap();
        assert_eq!(full_receipt.new_state_root, native.state_root());
        assert_eq!(native.state_commitment_v2().unwrap(), next_v2);
        if index <= 1 {
            // Exercise the same durable boundary used by a node restart. The
            // restored full state must reproduce both roots, and the canonical
            // undo must be independently decoded before it can roll the exact
            // authenticated block batch back.
            let post_entries = native.export_entries();
            let mut restarted = NativeUsdomState::restore_entries(bridge, &post_entries).unwrap();
            assert_eq!(restarted.state_root(), native.state_root());
            assert_eq!(restarted.state_commitment_v2().unwrap(), next_v2);
            let encoded_undo = full_undo.to_bytes().unwrap();
            let decoded_undo = BatchUndo::from_bytes(&encoded_undo).unwrap();
            assert_eq!(decoded_undo.to_bytes().unwrap(), encoded_undo);
            restarted
                .revert_batch(&decoded_undo, full_receipt.header_commitment)
                .unwrap();
            assert_eq!(restarted.export_entries(), before_native.export_entries());
            assert_eq!(
                restarted.state_commitment_v2().unwrap(),
                before_native.state_commitment_v2().unwrap()
            );

            if index == 1 {
                // A competing same-height block with an empty native batch must
                // retain the pre-burn root and commit a different batch header.
                let mut alternative = restarted.clone();
                let (alternative_receipt, _) = alternative.apply_batch(block_context, &[]).unwrap();
                assert_eq!(alternative.state_root(), before_native.state_root());
                assert_ne!(
                    alternative_receipt.header_commitment,
                    full_receipt.header_commitment
                );
            }

            let (replayed_receipt, replayed_undo) =
                restarted.apply_batch(block_context, &transitions).unwrap();
            assert_eq!(replayed_receipt, full_receipt);
            assert_eq!(replayed_undo.to_bytes().unwrap(), encoded_undo);
            assert_eq!(restarted.export_entries(), post_entries);
            native = restarted;
        }
        current_v2 = next_v2;
        native_witnesses.push(witnesses);
        let witness = EconomicBlockWitness::from_state(&economic, &candidate).unwrap();
        economic
            .apply_block(&candidate, dom_core::REGTEST_COINBASE_MATURITY)
            .unwrap();
        economic_witnesses.push(witness);
        let identifier = canonical_header_identifier(
            NETWORK_MAGIC_REGTEST,
            &DomSerialize::to_bytes(&candidate.header).unwrap(),
        )
        .unwrap();
        packages.push(
            UsdomV4BlockPackage::new(candidate, envelope)
                .unwrap()
                .to_bytes()
                .unwrap(),
        );
        parent = identifier;
        total_difficulty = difficulty;
        projections.push(ContextHeader {
            height,
            block: *identifier.as_bytes(),
            timestamp,
        });
        if projections.len() > CHECKPOINT_CONTEXT_HEADER_COUNT {
            projections.remove(0);
        }
        if index + 1 == u64::from(CHECKPOINT_INTERVAL) {
            let recent_headers = projections.clone().try_into().unwrap();
            let context = CheckpointContext {
                checkpoint_height: height,
                checkpoint_block: *identifier.as_bytes(),
                max_span: CHECKPOINT_INTERVAL + CONFIRMATION_DEPTH,
                economic_state_root: economic.context_root().unwrap(),
                recent_headers,
                seed_anchor_count: 0,
                seed_anchors: [SeedAnchor::default(); CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS],
            };
            target = Some((
                identifier,
                difficulty,
                context.commitment().unwrap(),
                current_v2.root(),
            ));
        }
        if index == 389 {
            confirmation = Some((identifier, difficulty, timestamp));
        }
    }
    assert_eq!(native.total_issued(), 10);
    assert_eq!(native.total_burned(), 10);
    assert_eq!(native.outstanding(), 0);
    assert_eq!(native_witnesses[0].len(), 1);
    assert_eq!(native_witnesses[1].len(), 1);
    let (target_block, target_difficulty, target_context_hash, target_state_root) = target.unwrap();
    let (confirmation_block, confirmation_difficulty, confirmation_timestamp) =
        confirmation.unwrap();
    let statement = CheckpointStatementV4 {
        checkpoint: CheckpointStatement {
            bridge_domain: DOMAIN,
            dom_network_magic: NETWORK_MAGIC_REGTEST,
            previous_height: PREVIOUS_HEIGHT,
            previous_block: *previous_block.as_bytes(),
            previous_state_root: *initial_v2.root().as_bytes(),
            previous_context_hash: previous_context.commitment().unwrap(),
            previous_total_difficulty: difficulty_bytes(previous_total_difficulty),
            height: PREVIOUS_HEIGHT + u64::from(CHECKPOINT_INTERVAL),
            block: *target_block.as_bytes(),
            state_root: *target_state_root.as_bytes(),
            context_hash: target_context_hash,
            total_difficulty: difficulty_bytes(target_difficulty),
            confirmation_height: PREVIOUS_HEIGHT
                + u64::from(CHECKPOINT_INTERVAL + CONFIRMATION_DEPTH),
            confirmation_block: *confirmation_block.as_bytes(),
            confirmation_total_difficulty: difficulty_bytes(confirmation_difficulty),
            confirmation_timestamp,
            ethereum_chain_id: bridge.ethereum_chain_id,
            registry: [0x42; 20],
            activation_schedule_commitment: *schedule.commitment().as_bytes(),
            checkpoint_config_hash: [0x45; 32],
        },
    };
    let statement_bytes = statement.to_bytes().unwrap();
    let context_bytes = previous_context.to_bytes().unwrap();
    let output = execute_checkpoint_extension_v2_with_witnesses(
        policy,
        &statement_bytes,
        &context_bytes,
        initial_v2,
        initial_roots,
        &packages,
        &native_witnesses,
        &economic_witnesses,
        &checkpoint,
        &deposit,
        &verifier,
    )
    .unwrap();
    assert_eq!(output.as_bytes(), &statement.statement_hash().unwrap());
    assert_eq!(
        execute_checkpoint_extension_v2_with_witnesses(
            policy,
            &statement_bytes,
            &context_bytes,
            initial_v2,
            initial_roots,
            &packages,
            &native_witnesses[..389],
            &economic_witnesses,
            &checkpoint,
            &deposit,
            &verifier,
        ),
        Err(CheckpointProgramError::InvalidExtension)
    );
}
