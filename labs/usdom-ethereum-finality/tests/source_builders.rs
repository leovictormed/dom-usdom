use alloy::{
    consensus::Header,
    primitives::{Address, Bytes, B256, U256},
};
use serde_json::Value;
use usdom_ethereum_finality_experiment::{
    ancestry::build_execution_ancestry,
    receipts::build_receipt_evidence,
    state::{account_evidence_from_rpc_claim, RpcAccountClaim},
    verified_transcript_from_rest, EthereumFork, EthereumForks,
};

const CHECKPOINT: &str = "a8f19965d0082e1f0c6099cc2a73aa6315d3a7eae012731480140defae43e30f";
const GENESIS: &str = "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";

fn forks() -> EthereumForks {
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
fn rest_transcript_and_execution_ancestry_builders_replay_real_fulu_data() {
    let bootstrap: Value =
        serde_json::from_str(include_str!("../fixtures/mainnet-fulu-bootstrap.json")).unwrap();
    let finality: Value =
        serde_json::from_str(include_str!("../fixtures/mainnet-fulu-finality.json")).unwrap();
    let (transcript, finalized, replay_slot) = verified_transcript_from_rest(
        bootstrap["data"].clone(),
        vec![],
        finality["data"].clone(),
        format!("0x{CHECKPOINT}").parse().unwrap(),
        format!("0x{GENESIS}").parse().unwrap(),
        forks(),
    )
    .unwrap();
    assert!(!transcript.is_empty());
    assert!(replay_slot >= finalized.beacon_slot);

    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/mainnet-fulu-execution-headers.json"
    ))
    .unwrap();
    let headers: Vec<Header> = fixture["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| serde_json::from_value(value.clone()).unwrap())
        .collect();
    let ancestry = build_execution_ancestry(&headers).unwrap();
    assert_eq!(ancestry.anchor_block_hash, finalized.block_hash);
    assert_eq!(ancestry.anchor_block_number, finalized.block_number);
    assert_eq!(ancestry.headers_rlp.len(), headers.len());
}

#[test]
fn receipt_and_account_source_builders_reproduce_local_authenticated_roots() {
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/local-reserve-receipts.json")).unwrap();
    let block = &fixture["block"];
    let block_hash: B256 = block["hash"].as_str().unwrap().parse().unwrap();
    let block_number = u64::from_str_radix(
        block["number"].as_str().unwrap().trim_start_matches("0x"),
        16,
    )
    .unwrap();
    let receipts: Vec<Bytes> = fixture["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value["receipt"].as_str().unwrap().parse().unwrap())
        .collect();
    let (root, receipt) = build_receipt_evidence(block_hash, block_number, 0, &receipts).unwrap();
    assert_eq!(
        root,
        block["receiptsRoot"]
            .as_str()
            .unwrap()
            .parse::<B256>()
            .unwrap()
    );
    assert_eq!(receipt.receipt_bytes, receipts[0]);

    let raw = &fixture["reserveAccount"];
    let evidence = account_evidence_from_rpc_claim(RpcAccountClaim {
        block_hash,
        block_number,
        address: fixture["reserve"]
            .as_str()
            .unwrap()
            .parse::<Address>()
            .unwrap(),
        nonce: raw["nonce"]
            .as_str()
            .unwrap()
            .parse::<U256>()
            .unwrap()
            .try_into()
            .unwrap(),
        balance: raw["balance"].as_str().unwrap().parse().unwrap(),
        storage_root: raw["storageHash"].as_str().unwrap().parse().unwrap(),
        code_hash: raw["codeHash"].as_str().unwrap().parse().unwrap(),
        proof: raw["accountProof"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().parse().unwrap())
            .collect(),
    })
    .unwrap();
    assert_eq!(evidence.block_hash, block_hash);
    assert!(evidence
        .account_rlp
        .as_ref()
        .is_some_and(|value| !value.is_empty()));
}
