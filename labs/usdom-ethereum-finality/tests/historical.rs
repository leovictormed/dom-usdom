use alloy::primitives::{b256, B256};
use helios_consensus_core::{
    apply_bootstrap, apply_generic_update,
    consensus_spec::MainnetConsensusSpec as Spec,
    force_update,
    types::{
        Bootstrap, FinalityUpdate, Fork, Forks, GenericUpdate, LightClientStore, OptimisticUpdate,
        Update,
    },
    verify_bootstrap, verify_generic_update,
};
use serde_json::{json, Value};
use usdom_ethereum_finality_experiment::{
    EthereumFinalityClient, FinalizedExecution, HistoricalCapellaClient,
};

const TRUSTED: B256 = b256!("5afc212a7924789b2bc86acad3ab3a6ffb1f6e97253ea50bee7f4f51422c9275");
const GENESIS: B256 = b256!("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95");
const NOW: u64 = 7109432;

// Mainnet fork versions and epochs through Fulu. Gloas remains deliberately
// inactive because its header no longer carries the execution state/receipt roots.
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

#[test]
fn current_mainnet_fulu_bootstrap_and_finality_signature_verify() {
    const CHECKPOINT: B256 =
        b256!("a8f19965d0082e1f0c6099cc2a73aa6315d3a7eae012731480140defae43e30f");
    let bootstrap_json: Value =
        serde_json::from_str(include_str!("../fixtures/mainnet-fulu-bootstrap.json")).unwrap();
    let finality_json: Value =
        serde_json::from_str(include_str!("../fixtures/mainnet-fulu-finality.json")).unwrap();
    assert_eq!(bootstrap_json["version"], "fulu");
    assert_eq!(finality_json["version"], "fulu");

    let bootstrap: Bootstrap<Spec> =
        serde_json::from_value(bootstrap_json["data"].clone()).unwrap();
    let finality: FinalityUpdate<Spec> =
        serde_json::from_value(finality_json["data"].clone()).unwrap();
    let update = GenericUpdate::from(&finality);
    assert!(
        EthereumFinalityClient::bootstrap(&bootstrap, B256::repeat_byte(9), GENESIS, forks(),)
            .is_err()
    );
    let mut client =
        EthereumFinalityClient::bootstrap(&bootstrap, CHECKPOINT, GENESIS, forks()).unwrap();
    let initial = client.finalized();
    assert_eq!(initial.beacon_slot, 15_446_016);

    let mut bad_signature = update.clone();
    bad_signature.sync_aggregate.sync_committee_signature =
        optimistic().sync_aggregate.sync_committee_signature;
    rejected_unchanged(&mut client, &bad_signature, update.signature_slot);
    client.accept(&update, update.signature_slot).unwrap();
    let finalized = client.finalized();
    assert_eq!(finalized.beacon_slot, 15_447_776);
    assert!(finalized.beacon_slot > initial.beacon_slot);
    assert!(!finalized.block_hash.is_zero());
    assert!(!finalized.receipts_root.is_zero());
    assert!(!finalized.state_root.is_zero());

    let transcript = client.export_transcript().unwrap();
    let restored = EthereumFinalityClient::restore_transcript(
        &transcript,
        CHECKPOINT,
        GENESIS,
        forks(),
        &finalized,
    )
    .unwrap();
    assert_eq!(restored.finalized(), finalized);
}

fn fixture(name: &str) -> Value {
    let data = match name {
        "bootstrap" => include_str!("../fixtures/bootstrap.json"),
        "updates" => include_str!("../fixtures/updates.json"),
        "finality" => include_str!("../fixtures/finality.json"),
        "optimistic" => include_str!("../fixtures/optimistic.json"),
        _ => panic!("unknown fixture"),
    };
    serde_json::from_str(data).unwrap()
}

fn bootstrap() -> Bootstrap<Spec> {
    serde_json::from_value(fixture("bootstrap")["data"].clone()).unwrap()
}

fn updates() -> Vec<GenericUpdate<Spec>> {
    fixture("updates")
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            let update: Update<Spec> = serde_json::from_value(v["data"].clone()).unwrap();
            GenericUpdate::from(&update)
        })
        .collect()
}

fn finality() -> GenericUpdate<Spec> {
    let u: FinalityUpdate<Spec> =
        serde_json::from_value(fixture("finality")["data"].clone()).unwrap();
    GenericUpdate::from(&u)
}

fn optimistic() -> GenericUpdate<Spec> {
    let u: OptimisticUpdate<Spec> =
        serde_json::from_value(fixture("optimistic")["data"].clone()).unwrap();
    GenericUpdate::from(&u)
}

fn fresh() -> HistoricalCapellaClient {
    HistoricalCapellaClient::bootstrap(&bootstrap(), TRUSTED, GENESIS, forks()).unwrap()
}

fn synced() -> HistoricalCapellaClient {
    let mut client = fresh();
    for update in updates() {
        client.accept(&update, NOW).unwrap();
    }
    client
}

fn mutate(update: &GenericUpdate<Spec>, f: impl FnOnce(&mut Value)) -> GenericUpdate<Spec> {
    let mut v = serde_json::to_value(update).unwrap();
    f(&mut v);
    serde_json::from_value(v).unwrap()
}

fn rejected_unchanged(client: &mut HistoricalCapellaClient, u: &GenericUpdate<Spec>, now: u64) {
    let before = client.finalized();
    let retained = client.retained_finalized_headers();
    assert!(client.accept(u, now).is_err());
    assert_eq!(client.finalized(), before);
    assert_eq!(client.retained_finalized_headers(), retained);
}

#[test]
fn real_mainnet_signatures_and_committee_rotations_authenticate_execution_roots() {
    let mut client = fresh();
    let initial = client.finalized();
    assert_eq!(client.retained_finalized_headers(), 1);
    assert_eq!(initial.beacon_slot, 7069376);
    let list = updates();
    // The first valid update teaches the next committee but has an older finalized
    // header. Rejecting all such updates would prevent synchronization here.
    client.accept(&list[0], NOW).unwrap();
    assert_eq!(client.finalized(), initial);
    assert_eq!(client.retained_finalized_headers(), 1);
    for update in &list[1..] {
        let before = client.finalized();
        let retained = client.retained_finalized_headers();
        client.accept(update, NOW).unwrap();
        assert!(client.finalized().beacon_slot >= before.beacon_slot);
        assert_eq!(client.retained_finalized_headers(), retained + 1);
    }
    client.accept(&finality(), NOW).unwrap();
    assert_eq!(client.retained_finalized_headers(), 7);
    let actual = client.finalized();
    assert_eq!(actual.beacon_slot, 7109344);
    assert_eq!(
        actual.block_hash,
        b256!("bc8499537876e5406c7a65e25f99063f1cd85a17014a3aa5ade38271b1fbf64f")
    );
    assert_eq!(actual.block_number, 17923026);
    assert_ne!(
        actual.block_hash,
        b256!("71305d343b77fa1444cf825353974dacfd7ba0813e085ea87a02ec261d66262a")
    );
    assert_eq!(
        actual.receipts_root,
        b256!("a71c4101ece61ca0fc624efdb54dc382be561a8c047a19cf5f10e530378e0b9c")
    );
    let v = fixture("finality");
    let e = &v["data"]["finalized_header"]["execution"];
    assert_eq!(
        actual.receipts_root,
        e["receipts_root"]
            .as_str()
            .unwrap()
            .parse::<B256>()
            .unwrap()
    );
    assert_eq!(
        actual.state_root,
        e["state_root"].as_str().unwrap().parse::<B256>().unwrap()
    );
    println!("authenticated_finalized_execution={actual:?}");
}

#[test]
fn transcript_revalidates_every_update_and_requires_the_external_finalized_tip() {
    let mut client = synced();
    client.accept(&finality(), NOW).unwrap();
    let expected = client.finalized();
    let bytes = client.export_transcript().unwrap();
    let restored =
        HistoricalCapellaClient::restore_transcript(&bytes, TRUSTED, GENESIS, forks(), &expected)
            .unwrap();
    assert_eq!(restored.finalized(), expected);
    assert_eq!(
        restored.retained_finalized_headers(),
        client.retained_finalized_headers()
    );
    assert_eq!(restored.export_transcript().unwrap(), bytes);

    let mut noncanonical = vec![b'\n'];
    noncanonical.extend_from_slice(&bytes);
    assert!(HistoricalCapellaClient::restore_transcript(
        &noncanonical,
        TRUSTED,
        GENESIS,
        forks(),
        &expected,
    )
    .err()
    .expect("noncanonical transcript must fail")
    .to_string()
    .contains("noncanonical transcript"));
    assert!(HistoricalCapellaClient::restore_transcript_bounded(
        &bytes,
        TRUSTED,
        GENESIS,
        forks(),
        &expected,
        NOW - 1,
    )
    .err()
    .expect("slot above consensus limit must fail")
    .to_string()
    .contains("current slot exceeds consensus limit"));

    let before = client.export_transcript().unwrap();
    client.accept(&updates()[1], NOW).unwrap();
    assert_eq!(client.export_transcript().unwrap(), before);

    let mut truncated: Value = serde_json::from_slice(&bytes).unwrap();
    truncated["updates"].as_array_mut().unwrap().pop();
    assert!(HistoricalCapellaClient::restore_transcript(
        &serde_json::to_vec(&truncated).unwrap(),
        TRUSTED,
        GENESIS,
        forks(),
        &expected,
    )
    .is_err());

    let mut bad_signature: Value = serde_json::from_slice(&bytes).unwrap();
    let replacement = serde_json::to_value(optimistic()).unwrap();
    let last = bad_signature["updates"].as_array().unwrap().len() - 1;
    bad_signature["updates"][last]["update"]["sync_aggregate"]["sync_committee_signature"] =
        replacement["sync_aggregate"]["sync_committee_signature"].clone();
    assert!(HistoricalCapellaClient::restore_transcript(
        &serde_json::to_vec(&bad_signature).unwrap(),
        TRUSTED,
        GENESIS,
        forks(),
        &expected,
    )
    .is_err());

    let mut duplicate: Value = serde_json::from_slice(&bytes).unwrap();
    let repeated = duplicate["updates"][1].clone();
    duplicate["updates"].as_array_mut().unwrap().push(repeated);
    assert!(HistoricalCapellaClient::restore_transcript(
        &serde_json::to_vec(&duplicate).unwrap(),
        TRUSTED,
        GENESIS,
        forks(),
        &expected,
    )
    .is_err());

    let mut unknown: Value = serde_json::from_slice(&bytes).unwrap();
    unknown["uncommitted"] = json!(true);
    assert!(HistoricalCapellaClient::restore_transcript(
        &serde_json::to_vec(&unknown).unwrap(),
        TRUSTED,
        GENESIS,
        forks(),
        &expected,
    )
    .is_err());

    let mut wrong_expected = expected.clone();
    wrong_expected.block_number -= 1;
    assert!(HistoricalCapellaClient::restore_transcript(
        &bytes,
        TRUSTED,
        GENESIS,
        forks(),
        &wrong_expected,
    )
    .is_err());
    assert!(HistoricalCapellaClient::restore_transcript(
        &bytes,
        B256::repeat_byte(7),
        GENESIS,
        forks(),
        &expected,
    )
    .is_err());
}

#[test]
fn wrong_trusted_root_and_corrupt_bootstrap_committee_are_rejected() {
    assert!(
        HistoricalCapellaClient::bootstrap(&bootstrap(), B256::ZERO, GENESIS, forks()).is_err()
    );
    assert!(HistoricalCapellaClient::bootstrap(
        &bootstrap(),
        B256::repeat_byte(7),
        GENESIS,
        forks()
    )
    .is_err());
    let mut v = fixture("bootstrap")["data"].clone();
    v["current_sync_committee_branch"][0] = json!(B256::ZERO);
    let b = serde_json::from_value(v).unwrap();
    assert!(HistoricalCapellaClient::bootstrap(&b, TRUSTED, GENESIS, forks()).is_err());
}

#[test]
fn wrong_genesis_and_signature_domain_are_rejected() {
    let mut client =
        HistoricalCapellaClient::bootstrap(&bootstrap(), TRUSTED, B256::repeat_byte(8), forks())
            .unwrap();
    rejected_unchanged(&mut client, &updates()[0], NOW);
    let mut config = forks();
    config.capella.fork_version = [3, 1, 0, 0].into();
    let mut client =
        HistoricalCapellaClient::bootstrap(&bootstrap(), TRUSTED, GENESIS, config).unwrap();
    rejected_unchanged(&mut client, &updates()[0], NOW);
}

#[test]
fn invalid_bls_signature_is_rejected_without_poisoning_next_update() {
    let mut client = synced();
    let mut bad = finality();
    // Another well-formed real signature is still invalid for this signed message.
    bad.sync_aggregate.sync_committee_signature =
        optimistic().sync_aggregate.sync_committee_signature;
    rejected_unchanged(&mut client, &bad, NOW);
    client.accept(&finality(), NOW).unwrap();
    assert_eq!(client.finalized().beacon_slot, 7109344);
}

#[test]
fn corrupted_finality_branch_is_rejected() {
    let mut client = synced();
    let mut bad = finality();
    bad.finality_branch.as_mut().unwrap()[0] = B256::ZERO;
    rejected_unchanged(&mut client, &bad, NOW);
}

#[test]
fn corrupted_execution_receipts_root_is_rejected() {
    let mut client = synced();
    let bad = mutate(&finality(), |v| {
        v["finalized_header"]["execution"]["receipts_root"] = json!(B256::ZERO);
    });
    rejected_unchanged(&mut client, &bad, NOW);
}

#[test]
fn corrupted_next_committee_proof_is_rejected_and_recovery_replays_valid_update() {
    let mut client = fresh();
    let mut bad = updates().remove(0);
    bad.next_sync_committee_branch.as_mut().unwrap()[0] = B256::ZERO;
    rejected_unchanged(&mut client, &bad, NOW);
    for update in updates() {
        client.accept(&update, NOW).unwrap();
    }
    client.accept(&finality(), NOW).unwrap();
}

#[test]
fn future_signature_and_missing_committee_period_are_rejected() {
    let mut client = synced();
    rejected_unchanged(&mut client, &finality(), finality().signature_slot - 1);
    let mut client = fresh();
    rejected_unchanged(&mut client, &finality(), NOW);
}

#[test]
fn insufficient_participation_and_missing_finality_are_rejected() {
    let mut client = synced();
    let bad = mutate(&finality(), |v| {
        // 341 of 512 participants: below the required 342. This intentionally
        // invalidates the signature too; this test isolates the pre-BLS policy gate.
        let bits = format!("0x{}1f{}", "ff".repeat(42), "00".repeat(21));
        v["sync_aggregate"]["sync_committee_bits"] = json!(bits);
    });
    assert!(client
        .accept(&bad, NOW)
        .unwrap_err()
        .to_string()
        .contains("supermajority"));
    let mut bad = finality();
    bad.finality_branch = None;
    rejected_unchanged(&mut client, &bad, NOW);
    rejected_unchanged(&mut client, &optimistic(), NOW);
}

#[test]
fn upstream_timeout_can_promote_optimistic_header_but_strict_path_cannot() {
    let b = bootstrap();
    let config = forks();
    let mut upstream: LightClientStore<Spec> = LightClientStore::default();
    verify_bootstrap(&b, TRUSTED, &config).unwrap();
    apply_bootstrap(&mut upstream, &b);
    let mut strict = fresh();
    for u in updates().into_iter().chain([finality()]) {
        verify_generic_update(&u, NOW, &upstream, GENESIS, &config).unwrap();
        apply_generic_update(&mut upstream, &u);
        strict.accept(&u, NOW).unwrap();
    }
    let before = strict.finalized();
    let u = optimistic();
    verify_generic_update(&u, NOW, &upstream, GENESIS, &config).unwrap();
    apply_generic_update(&mut upstream, &u);
    assert_eq!(upstream.finalized_header.beacon().slot, before.beacon_slot);
    let after_timeout = NOW + 8192 + 1;
    force_update(&mut upstream, after_timeout);
    assert_eq!(upstream.finalized_header.beacon().slot, 7109431);
    rejected_unchanged(&mut strict, &u, after_timeout);
    assert_eq!(strict.finalized(), before);
}

#[test]
fn replay_from_trusted_bootstrap_reconstructs_same_state_and_old_updates_do_not_rewind() {
    fn replay() -> (HistoricalCapellaClient, FinalizedExecution) {
        let mut c = synced();
        c.accept(&finality(), NOW).unwrap();
        let view = c.finalized();
        (c, view)
    }
    let (mut first, expected) = replay();
    let (_, recovered) = replay();
    assert_eq!(expected, recovered);
    first.accept(&finality(), NOW).unwrap();
    assert_eq!(first.finalized(), expected);
    let retained = first.retained_finalized_headers();
    first.accept(&updates()[0], NOW).unwrap();
    assert_eq!(first.finalized(), expected);
    assert_eq!(first.retained_finalized_headers(), retained);
}

#[test]
fn unsupported_header_variant_is_rejected_without_advancing() {
    let mut client = synced();
    let mut bad = finality();
    bad.finalized_header = Some(Default::default());
    rejected_unchanged(&mut client, &bad, NOW);
}
