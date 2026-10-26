use alloy::{
    consensus::Header,
    primitives::{b256, B256},
};
use helios_consensus_core::{
    consensus_spec::MainnetConsensusSpec as Spec,
    types::{Bootstrap, FinalityUpdate, Fork, Forks, GenericUpdate},
};
use serde_json::Value;
use usdom_ethereum_finality_experiment::{
    ancestry::ExecutionAncestryEvidence, EthereumFinalityClient,
};

const CHECKPOINT: B256 = b256!("a8f19965d0082e1f0c6099cc2a73aa6315d3a7eae012731480140defae43e30f");
const GENESIS: B256 = b256!("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95");

fn forks() -> Forks {
    fn f(epoch: u64, version: u8) -> Fork {
        Fork {
            epoch,
            fork_version: [version, 0, 0, 0].into(),
        }
    }
    Forks {
        genesis: f(0, 0),
        altair: f(74240, 1),
        bellatrix: f(144896, 2),
        capella: f(194048, 3),
        deneb: f(269568, 4),
        electra: f(364032, 5),
        fulu: f(411392, 6),
        gloas: f(u64::MAX, 7),
    }
}

fn synced() -> EthereumFinalityClient {
    let bootstrap_json: Value =
        serde_json::from_str(include_str!("../fixtures/mainnet-fulu-bootstrap.json")).unwrap();
    let finality_json: Value =
        serde_json::from_str(include_str!("../fixtures/mainnet-fulu-finality.json")).unwrap();
    let bootstrap: Bootstrap<Spec> =
        serde_json::from_value(bootstrap_json["data"].clone()).unwrap();
    let finality: FinalityUpdate<Spec> =
        serde_json::from_value(finality_json["data"].clone()).unwrap();
    let update = GenericUpdate::from(&finality);
    let mut client =
        EthereumFinalityClient::bootstrap(&bootstrap, CHECKPOINT, GENESIS, forks()).unwrap();
    client.accept(&update).unwrap();
    client
}

fn evidence() -> (ExecutionAncestryEvidence, Vec<Header>) {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/mainnet-fulu-execution-headers.json"
    ))
    .unwrap();
    let rows = fixture["headers"].as_array().unwrap();
    let headers: Vec<Header> = rows
        .iter()
        .map(|row| serde_json::from_value(row.clone()).unwrap())
        .collect();
    for (row, header) in rows.iter().zip(&headers) {
        let reported: B256 = row["hash"].as_str().unwrap().parse().unwrap();
        assert_eq!(header.hash_slow(), reported);
    }
    let anchor = headers.last().unwrap();
    (
        ExecutionAncestryEvidence {
            anchor_block_hash: anchor.hash_slow(),
            anchor_block_number: anchor.number,
            headers_rlp: headers
                .iter()
                .map(|header| alloy_rlp::encode(header).into())
                .collect(),
        },
        headers,
    )
}

#[test]
fn real_fulu_execution_headers_authenticate_an_earlier_mainnet_block() {
    let client = synced();
    let (evidence, headers) = evidence();
    let serialized = serde_json::to_vec(&evidence).unwrap();
    let evidence: ExecutionAncestryEvidence = serde_json::from_slice(&serialized).unwrap();
    let authenticated = client.verify_execution_ancestry(&evidence).unwrap();
    assert_eq!(authenticated.block_number(), 26_208_720);
    assert_eq!(authenticated.block_hash(), headers[0].hash_slow());
    assert_eq!(authenticated.receipts_root(), headers[0].receipts_root);
    assert_eq!(authenticated.state_root(), headers[0].state_root);
    assert_eq!(authenticated.anchor_block_number(), 26_208_724);
    assert_eq!(authenticated.anchor_block_hash(), headers[4].hash_slow());
}

#[test]
fn ancestry_rejects_truncation_reordering_corruption_and_resource_exhaustion() {
    let client = synced();
    let (evidence, _) = evidence();

    let mut bad = evidence.clone();
    bad.headers_rlp.clear();
    let error = client
        .verify_execution_ancestry(&bad)
        .expect_err("empty ancestry must fail without panicking");
    assert!(error
        .to_string()
        .contains("execution ancestry header count"));

    let mut bad = evidence.clone();
    bad.headers_rlp.pop();
    assert!(client.verify_execution_ancestry(&bad).is_err());

    let mut bad = evidence.clone();
    bad.headers_rlp.swap(1, 2);
    assert!(client.verify_execution_ancestry(&bad).is_err());

    let mut bad = evidence.clone();
    let mut corrupted = bad.headers_rlp[1].to_vec();
    corrupted.push(0);
    bad.headers_rlp[1] = corrupted.into();
    assert!(client.verify_execution_ancestry(&bad).is_err());

    let mut bad = evidence.clone();
    bad.anchor_block_hash = B256::repeat_byte(7);
    assert!(client.verify_execution_ancestry(&bad).is_err());

    let mut bad = evidence;
    bad.headers_rlp = vec![bad.headers_rlp[0].clone(); 257];
    assert!(client.verify_execution_ancestry(&bad).is_err());
}
