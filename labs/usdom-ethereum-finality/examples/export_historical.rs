//! Fixed historical fixture runner for the receipt-composition experiment.
//! Not an RPC client, production bootstrap, or general JSON trust-store importer.
use alloy::primitives::b256;
use helios_consensus_core::{
    consensus_spec::MainnetConsensusSpec as Spec,
    types::{Bootstrap, FinalityUpdate, Fork, Forks, GenericUpdate, Update},
};
use serde_json::{json, Value};
use usdom_ethereum_finality_experiment::HistoricalCapellaClient;

fn main() -> eyre::Result<()> {
    fn fork(epoch: u64, version: u8) -> Fork {
        Fork {
            epoch,
            fork_version: [version, 0, 0, 0].into(),
        }
    }
    let forks = Forks {
        genesis: fork(0, 0),
        altair: fork(74240, 1),
        bellatrix: fork(144896, 2),
        capella: fork(194048, 3),
        deneb: fork(269568, 4),
        electra: fork(364032, 5),
        fulu: fork(411392, 6),
        gloas: fork(u64::MAX, 7),
    };
    let bootstrap: Value = serde_json::from_str(include_str!("../fixtures/bootstrap.json"))?;
    let bootstrap: Bootstrap<Spec> = serde_json::from_value(bootstrap["data"].clone())?;
    let mut client = HistoricalCapellaClient::bootstrap(
        &bootstrap,
        b256!("5afc212a7924789b2bc86acad3ab3a6ffb1f6e97253ea50bee7f4f51422c9275"),
        b256!("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"),
        forks,
    )?;
    let updates: Vec<Value> = serde_json::from_str(include_str!("../fixtures/updates.json"))?;
    for value in updates {
        let update: Update<Spec> = serde_json::from_value(value["data"].clone())?;
        client.accept(&GenericUpdate::from(&update), 7109432)?;
    }
    let finality: Value = serde_json::from_str(include_str!("../fixtures/finality.json"))?;
    let update: FinalityUpdate<Spec> = serde_json::from_value(finality["data"].clone())?;
    client.accept(&GenericUpdate::from(&update), 7109432)?;
    let view = client.finalized();
    println!(
        "{}",
        json!({
            "scope": "historical-mainnet-capella-experiment-only",
            "chainId": "1",
            "beaconSlot": view.beacon_slot.to_string(),
            "beaconRoot": view.beacon_root,
            "blockNumber": view.block_number.to_string(),
            "blockHash": view.block_hash,
            "receiptsRoot": view.receipts_root,
            "stateRoot": view.state_root,
        })
    );
    Ok(())
}
