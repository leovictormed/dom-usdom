use alloy::{
    consensus::{Receipt, ReceiptEnvelope, ReceiptWithBloom},
    eips::eip2718::Encodable2718,
    primitives::{keccak256, Address, Bytes, Log, LogData, B256, U256},
};
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles, TrieAccount};
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};
use dom_core::{Hash256, NETWORK_MAGIC_REGTEST};
use dom_usdom_finalized_burn_program::{execute, ActivationSchedule, FinalizedBurnProverInput};
use dom_usdom_privacy::privacy_policy_hash;
use dom_usdom_state::{
    derive_private_burn_id, unsafe_test_only_burn, unsafe_test_only_issuance, BlockContext,
    BridgeIdentity, BurnRecord, BurnStateWitness, BurnTimingPolicy, EthereumAnchor,
    NativeUsdomState, VerifiedTransition,
};
use helios_consensus_core::{
    consensus_spec::{ConsensusSpec, MainnetConsensusSpec as Spec},
    types::{Bootstrap, FinalityUpdate, Fork, Forks, GenericUpdate, LightClientHeader},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tree_hash::TreeHash;
use usdom_ethereum_finality_experiment::{
    checkpoints::{
        checkpoint_witness_replay_slot, encode_checkpoint_witness, verify_checkpoint_witness,
        CheckpointEvidence, CheckpointPolicy, CheckpointTrustPolicy, StaticCheckpointTrustPolicy,
    },
    receipts::ReceiptEvidence,
    state::{AccountEvidence, StorageEvidence},
    EthereumFinalityClient,
};

const DOMAIN: [u8; 32] = [0x11; 32];
const GENESIS: [u8; 32] = [0x22; 32];
const REGISTRY: [u8; 20] = [0x42; 20];
const CONFIG: [u8; 32] = [0x45; 32];
const RESERVE: [u8; 20] = [0x33; 20];
const BOOTSTRAP_SLOT: u64 = 7_109_300;
const FINALIZED_SLOT: u64 = 7_109_344;
const ATTESTED_SLOT: u64 = FINALIZED_SLOT + 1;
const SIGNATURE_SLOT: u64 = ATTESTED_SLOT + 1;
const EXECUTION_BLOCK: u64 = 20_000_010;
const EXECUTION_TIMESTAMP: u64 = 1_700_000_240;

fn forks() -> Forks {
    fn fork(epoch: u64, version: u8) -> Fork {
        Fork {
            epoch,
            fork_version: [version, 0, 0, 0].into(),
        }
    }
    Forks {
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

fn merkle_root(mut leaf: B256, branch: &[B256], index: usize) -> B256 {
    for (depth, sibling) in branch.iter().enumerate() {
        let mut hasher = Sha256::new();
        if (index >> depth) & 1 == 0 {
            hasher.update(leaf);
            hasher.update(sibling);
        } else {
            hasher.update(sibling);
            hasher.update(leaf);
        }
        leaf = B256::from_slice(&hasher.finalize());
    }
    leaf
}

fn hash_pair(left: B256, right: B256) -> B256 {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    B256::from_slice(&hasher.finalize())
}

fn committee_signing_root(header_root: B256) -> B256 {
    // These synthetic slots are in Capella under `forks()`, whose version is
    // 0x03000000. SSZ ForkData is two 32-byte leaves; SigningData is likewise.
    let mut version = [0u8; 32];
    version[..4].copy_from_slice(&[3, 0, 0, 0]);
    let fork_data_root = hash_pair(B256::from(version), B256::from(GENESIS));
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&[7, 0, 0, 0]);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    hash_pair(header_root, B256::from(domain))
}

fn hex32(value: B256) -> Value {
    json!(format!("{value:#x}"))
}

fn set_execution_header(header: &mut Value, state_root: B256, receipts_root: B256) {
    let execution = &mut header["execution"];
    execution["state_root"] = hex32(state_root);
    execution["receipts_root"] = hex32(receipts_root);
    execution["block_number"] = json!(EXECUTION_BLOCK.to_string());
    execution["timestamp"] = json!(EXECUTION_TIMESTAMP.to_string());
    execution["block_hash"] = hex32(B256::repeat_byte(0xa1));
}

fn bind_execution_branch(header: &mut Value) -> LightClientHeader {
    let branch = vec![B256::repeat_byte(0x31); 4];
    header["execution_branch"] =
        json!(branch.iter().map(|v| format!("{v:#x}")).collect::<Vec<_>>());
    header["beacon"]["body_root"] = hex32(B256::ZERO);
    let parsed: LightClientHeader = serde_json::from_value(header.clone()).unwrap();
    header["beacon"]["body_root"] = hex32(merkle_root(parsed.execution_root(), &branch, 9));
    serde_json::from_value(header.clone()).unwrap()
}

fn make_bootstrap() -> (Bootstrap<Spec>, B256, Scalar) {
    let secret = Scalar::from(7u64);
    let public = G1Affine::from(G1Projective::generator() * secret);
    let aggregate =
        G1Affine::from(G1Projective::from(public) * Scalar::from(Spec::sync_committee_size()));
    let public_hex = format!("0x{}", hex::encode(public.to_compressed()));
    let aggregate_hex = format!("0x{}", hex::encode(aggregate.to_compressed()));
    let mut wire: Value = serde_json::from_str(include_str!(
        "../../../labs/usdom-ethereum-finality/fixtures/bootstrap.json"
    ))
    .unwrap();
    let data = &mut wire["data"];
    data["current_sync_committee"]["pubkeys"] =
        json!(vec![public_hex; Spec::sync_committee_size() as usize]);
    data["current_sync_committee"]["aggregate_pubkey"] = json!(aggregate_hex);
    let committee_branch = vec![B256::repeat_byte(0x21); 5];
    data["current_sync_committee_branch"] = json!(committee_branch
        .iter()
        .map(|v| format!("{v:#x}"))
        .collect::<Vec<_>>());
    data["header"]["beacon"]["slot"] = json!(BOOTSTRAP_SLOT.to_string());
    bind_execution_branch(&mut data["header"]);
    let partial: Bootstrap<Spec> = serde_json::from_value(data.clone()).unwrap();
    data["header"]["beacon"]["state_root"] = hex32(merkle_root(
        partial.current_sync_committee().tree_hash_root(),
        &committee_branch,
        22,
    ));
    let bootstrap: Bootstrap<Spec> = serde_json::from_value(data.clone()).unwrap();
    let trusted = bootstrap.header().beacon().tree_hash_root();
    (bootstrap, trusted, secret)
}

fn bridge(policy: &StaticCheckpointTrustPolicy) -> BridgeIdentity {
    let mut chain_id = [0; 32];
    chain_id[31] = 1;
    BridgeIdentity {
        dom_domain: DOMAIN,
        ethereum_genesis_validators_root: GENESIS,
        ethereum_chain_id: chain_id,
        ethereum_checkpoint_policy_hash: policy.policy_hash().into(),
        ethereum_deposit_policy_hash: [0x46; 32],
        privacy_policy_hash: *privacy_policy_hash().as_bytes(),
        privacy_verifier_config_hash: [0x48; 32],
        reserve: RESERVE,
        burn_timing: BurnTimingPolicy {
            withdrawal_delay_secs: 86_400,
            min_execution_window_secs: 3_600,
            max_certificate_lifetime_secs: 604_800,
            relay_safety_margin_secs: 3_600,
            max_ethereum_anchor_age_secs: 1_800,
            max_dom_clock_lead_secs: dom_core::MAX_FUTURE_BLOCK_TIME,
        },
    }
}

fn burn_witness(policy: &StaticCheckpointTrustPolicy) -> BurnStateWitness {
    let bridge = bridge(policy);
    let timestamp = 1_700_000_120;
    let mut state = NativeUsdomState::new(bridge).unwrap();
    state
        .apply_batch(
            BlockContext { timestamp },
            &[VerifiedTransition::Issue(unsafe_test_only_issuance(
                DOMAIN,
                [0x44; 32],
                [0x15; 32],
                1_000_000,
                EthereumAnchor {
                    genesis_validators_root: GENESIS,
                    execution_block_number: 20_000_000,
                    execution_block_hash: [0x66; 32],
                    execution_block_timestamp: 1_700_000_000,
                    beacon_slot: 16_000_000,
                    beacon_root: [0x77; 32],
                },
            ))],
        )
        .unwrap();
    let nullifiers = vec![[0x14; 32]];
    let burn_id = derive_private_burn_id(
        bridge,
        &nullifiers,
        [0x73; 20],
        250_000,
        timestamp + 100_000,
    )
    .unwrap();
    let mut record = BurnRecord {
        burn_id,
        request_id: [0x72; 32],
        amount: 250_000,
        recipient: [0x73; 20],
        ethereum_chain_id: bridge.ethereum_chain_id,
        reserve: bridge.reserve,
        valid_until: timestamp + 100_000,
        obligation_commitment: [0; 32],
    };
    record.obligation_commitment = record.expected_obligation_commitment(DOMAIN);
    state
        .apply_batch(
            BlockContext { timestamp },
            &[VerifiedTransition::Burn(unsafe_test_only_burn(
                DOMAIN,
                state.note_anchor(),
                nullifiers,
                vec![[0x17; 32]],
                [0x0e; 32],
                record,
            ))],
        )
        .unwrap();
    state.burn_state_witness(&burn_id).unwrap().unwrap()
}

struct ExecutionEvidence {
    evidence: CheckpointEvidence,
    state_root: B256,
    receipts_root: B256,
}

fn execution_evidence(state_root: Hash256, runtime: &[u8]) -> ExecutionEvidence {
    let registry = Address::from(REGISTRY);
    let config = U256::from_be_bytes(CONFIG);
    let slot = B256::ZERO;
    let storage_key = Nibbles::unpack(keccak256(slot));
    let mut storage =
        HashBuilder::default().with_proof_retainer(ProofRetainer::new(vec![storage_key]));
    storage.add_leaf(storage_key, &alloy_rlp::encode(config));
    let storage_root = storage.root();
    let storage_proof = storage
        .take_proof_nodes()
        .matching_nodes_sorted(&storage_key)
        .into_iter()
        .map(|(_, node)| node)
        .collect();

    let account = TrieAccount {
        nonce: 1,
        balance: U256::ZERO,
        storage_root,
        code_hash: keccak256(runtime),
    };
    let account_key = Nibbles::unpack(keccak256(registry));
    let account_rlp = alloy_rlp::encode(account);
    let mut state =
        HashBuilder::default().with_proof_retainer(ProofRetainer::new(vec![account_key]));
    state.add_leaf(account_key, &account_rlp);
    let ethereum_state_root = state.root();
    let account_proof = state
        .take_proof_nodes()
        .matching_nodes_sorted(&account_key)
        .into_iter()
        .map(|(_, node)| node)
        .collect();

    let mut network = [0u8; 32];
    network[28..].copy_from_slice(&NETWORK_MAGIC_REGTEST.to_be_bytes());
    let mut data = [0u8; 128];
    data[24..32].copy_from_slice(&2u64.to_be_bytes());
    data[32..64].copy_from_slice(&[0x61; 32]);
    data[64..96].copy_from_slice(state_root.as_bytes());
    data[96..128].copy_from_slice(&CONFIG);
    let log = Log {
        address: registry,
        data: LogData::new_unchecked(
            vec![
                keccak256(b"Checkpoint(bytes32,uint32,uint64,bytes32,bytes32,bytes32)"),
                B256::from(DOMAIN),
                B256::from(network),
            ],
            Bytes::copy_from_slice(&data),
        ),
    };
    let receipt = ReceiptEnvelope::Legacy(ReceiptWithBloom::from(Receipt {
        status: true.into(),
        cumulative_gas_used: 21_000,
        logs: vec![log],
    }));
    let receipt_bytes = receipt.encoded_2718();
    let receipt_key = Nibbles::unpack(alloy_rlp::encode(0u64));
    let mut receipts =
        HashBuilder::default().with_proof_retainer(ProofRetainer::new(vec![receipt_key]));
    receipts.add_leaf(receipt_key, &receipt_bytes);
    let receipts_root = receipts.root();
    let receipt_proof = receipts
        .take_proof_nodes()
        .matching_nodes_sorted(&receipt_key)
        .into_iter()
        .map(|(_, node)| node)
        .collect();

    let block_hash = B256::repeat_byte(0xa1);
    ExecutionEvidence {
        state_root: ethereum_state_root,
        receipts_root,
        evidence: CheckpointEvidence {
            execution_ancestry: None,
            receipt: ReceiptEvidence {
                block_hash,
                block_number: EXECUTION_BLOCK,
                transaction_index: 0,
                receipt_bytes: receipt_bytes.into(),
                proof: receipt_proof,
            },
            receipt_log_index: 0,
            registry_account: AccountEvidence {
                block_hash,
                block_number: EXECUTION_BLOCK,
                address: registry,
                account_rlp: Some(account_rlp.into()),
                proof: account_proof,
            },
            config_storage: StorageEvidence {
                slot,
                value: config,
                proof: storage_proof,
            },
            runtime_bytecode: Bytes::copy_from_slice(runtime),
        },
    }
}

fn make_finality_update(
    state_root: B256,
    receipts_root: B256,
    secret: Scalar,
    forks: &Forks,
) -> FinalityUpdate<Spec> {
    let mut wire: Value = serde_json::from_str(include_str!(
        "../../../labs/usdom-ethereum-finality/fixtures/finality.json"
    ))
    .unwrap();
    let data = &mut wire["data"];
    let finalized = &mut data["finalized_header"];
    finalized["beacon"]["slot"] = json!(FINALIZED_SLOT.to_string());
    set_execution_header(finalized, state_root, receipts_root);
    let finalized = bind_execution_branch(finalized);

    let branch = vec![B256::repeat_byte(0x41); 6];
    data["finality_branch"] = json!(branch.iter().map(|v| format!("{v:#x}")).collect::<Vec<_>>());
    let attested = &mut data["attested_header"];
    attested["beacon"]["slot"] = json!(ATTESTED_SLOT.to_string());
    set_execution_header(attested, state_root, receipts_root);
    bind_execution_branch(attested);
    attested["beacon"]["state_root"] = hex32(merkle_root(
        finalized.beacon().tree_hash_root(),
        &branch,
        41,
    ));
    let attested: LightClientHeader = serde_json::from_value(attested.clone()).unwrap();
    data["signature_slot"] = json!(SIGNATURE_SLOT.to_string());
    data["sync_aggregate"]["sync_committee_bits"] = json!(format!(
        "0x{}",
        "ff".repeat((Spec::sync_committee_size() / 8) as usize)
    ));
    let _ = forks;
    let signing_root = committee_signing_root(attested.beacon().tree_hash_root());
    let message = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
        signing_root.as_slice(),
        b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
    );
    let aggregate_secret = secret * Scalar::from(Spec::sync_committee_size());
    let signature = G2Affine::from(message * aggregate_secret).to_compressed();
    data["sync_aggregate"]["sync_committee_signature"] =
        json!(format!("0x{}", hex::encode(signature)));
    serde_json::from_value(data.clone()).unwrap()
}

#[test]
fn raw_ethereum_checkpoint_executes_udfinl02_end_to_end() {
    let (bootstrap, trusted_checkpoint, secret) = make_bootstrap();
    let forks = forks();
    let runtime = [0x60, 0x00];
    let trust = CheckpointTrustPolicy {
        trusted_checkpoint,
        ethereum_genesis_validators_root: B256::from(GENESIS),
        forks: forks.clone(),
        max_current_slot: SIGNATURE_SLOT,
        checkpoint: CheckpointPolicy {
            ethereum_chain_id: 1,
            ethereum_genesis_validators_root: B256::from(GENESIS),
            registry: Address::from(REGISTRY),
            runtime_code_hash: keccak256(runtime),
            config_storage_slot: B256::ZERO,
            checkpoint_config_hash: B256::from(CONFIG),
            bridge_domain: B256::from(DOMAIN),
            dom_network_magic: NETWORK_MAGIC_REGTEST,
        },
    };
    let static_policy = StaticCheckpointTrustPolicy::from_trust_policy(&trust).unwrap();
    let burn = burn_witness(&static_policy);
    let execution = execution_evidence(burn.state.root(), &runtime);
    let update = make_finality_update(
        execution.state_root,
        execution.receipts_root,
        secret,
        &forks,
    );
    let mut client = EthereumFinalityClient::bootstrap(
        &bootstrap,
        trusted_checkpoint,
        B256::from(GENESIS),
        forks,
    )
    .unwrap();
    client
        .accept(&GenericUpdate::from(&update), SIGNATURE_SLOT)
        .unwrap();
    let finalized = client.finalized();
    assert_eq!(finalized.beacon_slot, FINALIZED_SLOT);
    assert_eq!(finalized.state_root, execution.state_root);
    assert_eq!(finalized.receipts_root, execution.receipts_root);
    let checkpoint_witness = encode_checkpoint_witness(
        &client.export_transcript().unwrap(),
        &finalized,
        &execution.evidence,
    )
    .unwrap();
    assert_eq!(
        checkpoint_witness_replay_slot(&checkpoint_witness).unwrap(),
        SIGNATURE_SLOT
    );
    let transcript_len = u32::from_be_bytes(checkpoint_witness[8..12].try_into().unwrap()) as usize;
    let mut noncanonical_clock = checkpoint_witness.clone();
    let mut transcript: Value =
        serde_json::from_slice(&noncanonical_clock[168..168 + transcript_len]).unwrap();
    transcript["updates"][0]["current_slot"] = json!(SIGNATURE_SLOT + 1);
    let changed_transcript = serde_json::to_vec(&transcript).unwrap();
    assert_eq!(changed_transcript.len(), transcript_len);
    noncanonical_clock[168..168 + transcript_len].copy_from_slice(&changed_transcript);
    assert!(checkpoint_witness_replay_slot(&noncanonical_clock).is_err());
    let checkpoint_witness_len = checkpoint_witness.len();
    let schedule = ActivationSchedule::new(
        NETWORK_MAGIC_REGTEST,
        Hash256::from_bytes([0x55; 32]),
        1,
        bridge(&static_policy),
    )
    .unwrap();
    let verified = verify_checkpoint_witness(
        &checkpoint_witness,
        &static_policy.at_max_current_slot(SIGNATURE_SLOT).unwrap(),
    )
    .unwrap();
    assert_eq!(&verified.record()[41..73], burn.state.root().as_bytes());
    let input = FinalizedBurnProverInput::new(
        schedule,
        static_policy,
        burn.to_bytes().unwrap(),
        checkpoint_witness,
    )
    .unwrap();
    let bytes = input.to_bytes().unwrap();
    assert_eq!(
        execute(&bytes).unwrap().as_bytes(),
        input.statement_hash().as_bytes()
    );
    assert_eq!(checkpoint_witness_len, 62_638);
    assert_eq!(bytes.len(), 64_070);
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        "975383b1ad8dbf8e7ec471673314e6b26250ca6e325456f8380cbaef3529ff4e"
    );
    assert_eq!(
        hex::encode(input.statement_hash().as_bytes()),
        "881ebff15b6a4ee9939138160651119b4107713397d362b550355aae22fafaf8"
    );
    let mut wrong_replay_ceiling = bytes.clone();
    wrong_replay_ceiling[49] ^= 1;
    assert!(FinalizedBurnProverInput::from_bytes(&wrong_replay_ceiling).is_err());
    if let Some(path) = std::env::var_os("USDOM_RAW_CHECKPOINT_VECTOR_OUT") {
        std::fs::write(path, &bytes).unwrap();
    }
}
