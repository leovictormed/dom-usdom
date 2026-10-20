use alloy::primitives::{address, b256, keccak256, Address, Bytes, B256};
use helios_consensus_core::{
    consensus_spec::MainnetConsensusSpec as Spec,
    types::{Bootstrap, FinalityUpdate, Fork, Forks, GenericUpdate, Update},
};
use serde_json::Value;
use std::sync::OnceLock;
use usdom_ethereum_finality_experiment::{
    receipts::{LogPolicy, ReceiptEvidence},
    HistoricalCapellaClient,
};

const USDT: Address = address!("dac17f958d2ee523a2206206994597c13d831ec7");
const GENESIS: B256 = b256!("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95");

fn client() -> &'static HistoricalCapellaClient {
    static CLIENT: OnceLock<HistoricalCapellaClient> = OnceLock::new();
    CLIENT.get_or_init(|| {
        fn f(epoch: u64, version: u8) -> Fork {
            Fork {
                epoch,
                fork_version: [version, 0, 0, 0].into(),
            }
        }
        let forks = Forks {
            genesis: f(0, 0),
            altair: f(74240, 1),
            bellatrix: f(144896, 2),
            capella: f(194048, 3),
            deneb: f(269568, 4),
            electra: f(364032, 5),
            fulu: f(411392, 6),
            gloas: f(u64::MAX, 7),
        };
        let b: Value = serde_json::from_str(include_str!("../fixtures/bootstrap.json")).unwrap();
        let b: Bootstrap<Spec> = serde_json::from_value(b["data"].clone()).unwrap();
        let mut c = HistoricalCapellaClient::bootstrap(
            &b,
            b256!("5afc212a7924789b2bc86acad3ab3a6ffb1f6e97253ea50bee7f4f51422c9275"),
            GENESIS,
            forks,
        )
        .unwrap();
        let updates: Vec<Value> =
            serde_json::from_str(include_str!("../fixtures/updates.json")).unwrap();
        for value in updates {
            let update: Update<Spec> = serde_json::from_value(value["data"].clone()).unwrap();
            c.accept(&GenericUpdate::from(&update), 7109432).unwrap();
        }
        let f: Value = serde_json::from_str(include_str!("../fixtures/finality.json")).unwrap();
        let f: FinalityUpdate<Spec> = serde_json::from_value(f["data"].clone()).unwrap();
        c.accept(&GenericUpdate::from(&f), 7109432).unwrap();
        c
    })
}

fn vectors() -> &'static Value {
    static VECTORS: OnceLock<Value> = OnceLock::new();
    VECTORS.get_or_init(|| {
        serde_json::from_str(include_str!("../fixtures/receipt-vectors.json")).unwrap()
    })
}

fn evidence(index: usize) -> ReceiptEvidence {
    let fixture = vectors();
    let value = &fixture["vectors"][index];
    ReceiptEvidence {
        block_hash: fixture["blockHash"].as_str().unwrap().parse().unwrap(),
        block_number: fixture["blockNumber"].as_str().unwrap().parse().unwrap(),
        transaction_index: value["transactionIndex"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        receipt_bytes: value["receipt"].as_str().unwrap().parse().unwrap(),
        proof: value["proof"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap().parse().unwrap())
            .collect(),
    }
}

fn transfer_policy() -> LogPolicy {
    LogPolicy {
        emitter: USDT,
        topic0: keccak256(b"Transfer(address,address,uint256)"),
        topic_count: 3,
    }
}

#[test]
fn all_167_receipts_and_32_transfers_verify_in_one_rust_process() {
    let c = client();
    let values = vectors()["vectors"].as_array().unwrap();
    assert_eq!(values.len(), 167);
    let mut transfers = 0;
    let mut failures = 0;
    for (index, value) in values.iter().enumerate() {
        let receipt = c.verify_receipt(&evidence(index)).unwrap();
        let successful = value["status"] == 1;
        assert_eq!(receipt.is_success(), successful);
        assert_eq!(receipt.log_count(), value["logs"].as_array().unwrap().len());
        if !successful {
            failures += 1;
            assert!(receipt.log(0, &transfer_policy()).is_err());
        }
        for (log_index, value) in value["logs"].as_array().unwrap().iter().enumerate() {
            if value["emitter"]
                .as_str()
                .unwrap()
                .parse::<Address>()
                .unwrap()
                == USDT
                && value["topics"][0]
                    .as_str()
                    .unwrap()
                    .parse::<B256>()
                    .unwrap()
                    == transfer_policy().topic0
            {
                let event = receipt.log(log_index as u32, &transfer_policy()).unwrap();
                assert_eq!(event.emitter(), USDT);
                assert_eq!(event.locator().genesis_validators_root, GENESIS);
                assert_eq!(event.locator().block_hash, c.finalized().block_hash);
                assert_eq!(event.locator().transaction_index, index as u32);
                assert_eq!(event.locator().receipt_log_index, log_index as u32);
                assert_eq!(
                    event.data(),
                    value["data"]
                        .as_str()
                        .unwrap()
                        .parse::<Bytes>()
                        .unwrap()
                        .as_ref()
                );
                let expected: Vec<B256> = value["topics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|topic| topic.as_str().unwrap().parse().unwrap())
                    .collect();
                assert_eq!(event.topics(), expected);
                transfers += 1;
            }
        }
    }
    assert_eq!(transfers, 32);
    println!("Rust verified 167 receipt proofs, {transfers} USDT transfers, {failures} failed transaction receipts; no monetary authorization");
}

#[test]
fn differing_block_identity_and_attested_header_are_rejected() {
    let mut e = evidence(50);
    e.block_hash = B256::repeat_byte(9);
    assert!(client().verify_receipt(&e).is_err());
    let mut e = evidence(50);
    e.block_number -= 1;
    assert!(client().verify_receipt(&e).is_err());
    e.block_number = 17923112;
    e.block_hash = b256!("71305d343b77fa1444cf825353974dacfd7ba0813e085ea87a02ec261d66262a");
    assert!(client().verify_receipt(&e).is_err());
}

#[test]
fn changed_receipt_or_proof_cannot_pass_under_finalized_root() {
    let mut e = evidence(50);
    let mut raw = e.receipt_bytes.to_vec();
    let last = raw.len() - 1;
    raw[last] ^= 1;
    e.receipt_bytes = raw.into();
    assert!(client().verify_receipt(&e).is_err());
    let mut e = evidence(50);
    let mut node = e.proof[0].to_vec();
    let last = node.len() - 1;
    node[last] ^= 1;
    e.proof[0] = node.into();
    assert!(client().verify_receipt(&e).is_err());
}

#[test]
fn truncated_extra_reordered_and_wrong_index_proofs_are_rejected() {
    let base = evidence(50);
    let mut e = base.clone();
    e.proof.pop();
    assert!(client().verify_receipt(&e).is_err());
    let mut e = base.clone();
    e.proof.push(e.proof[0].clone());
    assert!(client().verify_receipt(&e).is_err());
    let mut e = base.clone();
    e.proof.reverse();
    assert!(client().verify_receipt(&e).is_err());
    let mut e = base.clone();
    e.transaction_index = 51;
    assert!(client().verify_receipt(&e).is_err());
    let mut e = base;
    e.transaction_index = 167;
    assert!(client().verify_receipt(&e).is_err());
}

#[test]
fn event_policy_and_relative_index_are_enforced() {
    let receipt = client().verify_receipt(&evidence(50)).unwrap();
    let event = receipt.log(0, &transfer_policy()).unwrap();
    assert_eq!(event.emitter(), USDT);
    let mut wrong = transfer_policy();
    wrong.emitter = Address::ZERO;
    assert!(receipt.log(0, &wrong).is_err());
    let mut wrong = transfer_policy();
    wrong.topic_count = 4;
    assert!(receipt.log(0, &wrong).is_err());
    let mut wrong = transfer_policy();
    wrong.topic0 = keccak256(b"Deposited(bytes32,address,uint64,bytes32)");
    assert!(receipt.log(0, &wrong).is_err());
    assert!(receipt.log(u32::MAX, &transfer_policy()).is_err());
}

#[test]
fn mutation_after_validation_cannot_relabel_opaque_results() {
    let mut e = evidence(50);
    let receipt = client().verify_receipt(&e).unwrap();
    e.transaction_index = 999;
    e.block_hash = B256::ZERO;
    e.receipt_bytes = Bytes::new();
    let mut displayed = client().finalized();
    displayed.receipts_root = B256::ZERO;
    let event = receipt.log(0, &transfer_policy()).unwrap();
    assert_eq!(event.locator().transaction_index, 50);
    assert_ne!(event.locator().block_hash, B256::ZERO);
    assert_ne!(client().finalized().receipts_root, displayed.receipts_root);
    client().verify_receipt(&evidence(50)).unwrap();
}

#[test]
fn excessive_resources_are_rejected_before_decoding_or_trie_verification() {
    let mut e = evidence(50);
    e.receipt_bytes = Bytes::from(vec![0; 262145]);
    assert!(client()
        .verify_receipt(&e)
        .unwrap_err()
        .to_string()
        .contains("receipt byte limit"));
    let mut e = evidence(50);
    e.proof = vec![Bytes::from_static(&[0xc0]); 33];
    assert!(client()
        .verify_receipt(&e)
        .unwrap_err()
        .to_string()
        .contains("proof node count"));
    let mut e = evidence(50);
    e.proof = vec![Bytes::from(vec![0; 262145])];
    assert!(client()
        .verify_receipt(&e)
        .unwrap_err()
        .to_string()
        .contains("proof node size"));
    let mut e = evidence(50);
    e.proof = vec![Bytes::from(vec![0; 180000]); 3];
    assert!(client()
        .verify_receipt(&e)
        .unwrap_err()
        .to_string()
        .contains("proof byte limit"));
}
