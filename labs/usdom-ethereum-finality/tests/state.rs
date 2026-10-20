use alloy::primitives::{address, b256, keccak256, Address, Bytes, B256, U256};
use alloy_trie::{TrieAccount, EMPTY_ROOT_HASH, KECCAK_EMPTY};
use helios_consensus_core::{
    consensus_spec::MainnetConsensusSpec as Spec,
    types::{Bootstrap, FinalityUpdate, Fork, Forks, GenericUpdate, Update},
};
use serde_json::Value;
use std::sync::OnceLock;
use usdom_ethereum_finality_experiment::{
    receipts::{LogPolicy, ReceiptEvidence},
    state::{AccountEvidence, StorageEvidence},
    HistoricalCapellaClient,
};
const USDT: Address = address!("dac17f958d2ee523a2206206994597c13d831ec7");
const GENESIS: B256 = b256!("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95");
const CODE_HASH: B256 = b256!("b44fb4e949d0f78f87f79ee46428f23a2a5713ce6fc6e0beb3dda78c2ac1ea55");

fn fixtures() -> &'static Value {
    static FIXTURE: OnceLock<Value> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        serde_json::from_str(include_str!("../fixtures/account-state.json")).unwrap()
    })
}

fn quantity(v: &Value) -> U256 {
    v.as_str().unwrap().parse().unwrap()
}
fn nodes(v: &Value) -> Vec<Bytes> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().parse().unwrap())
        .collect()
}
fn claimed_account(index: usize) -> TrieAccount {
    let p = &fixtures()["accounts"][index]["proof"];
    TrieAccount::new(
        quantity(&p["nonce"]).try_into().unwrap(),
        quantity(&p["balance"]),
        p["storageHash"].as_str().unwrap().parse().unwrap(),
        p["codeHash"].as_str().unwrap().parse().unwrap(),
    )
}
fn evidence(index: usize) -> AccountEvidence {
    let f = fixtures();
    let p = &f["accounts"][index]["proof"];
    AccountEvidence {
        block_hash: f["blockHash"].as_str().unwrap().parse().unwrap(),
        block_number: f["blockNumber"].as_u64().unwrap(),
        address: p["address"].as_str().unwrap().parse().unwrap(),
        // This is the claim to test, not an inference from RPC zero values.
        account_rlp: if index == 2 {
            None
        } else {
            Some(alloy_rlp::encode(claimed_account(index)).into())
        },
        proof: nodes(&p["accountProof"]),
    }
}
fn storage(account: usize, slot: usize) -> StorageEvidence {
    let s = &fixtures()["accounts"][account]["proof"]["storageProof"][slot];
    StorageEvidence {
        slot: s["key"].as_str().unwrap().parse().unwrap(),
        value: quantity(&s["value"]),
        proof: nodes(&s["proof"]),
    }
}
fn code() -> Bytes {
    fixtures()["accounts"][0]["code"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn real_post_state_authenticates_account_code_nonzero_and_absent_storage() {
    let a = client().verify_account(&evidence(0)).unwrap().unwrap();
    assert_eq!(a.location().address, USDT);
    assert_eq!(a.location().genesis_validators_root, GENESIS);
    assert_eq!(a.nonce(), 1);
    assert_eq!(a.balance(), U256::from(1));
    let c = a.check_contract_code(CODE_HASH, &code()).unwrap();
    assert_eq!(c.code_hash(), CODE_HASH);
    assert_eq!(c.code_length(), 11075);
    assert_eq!(c.location(), a.location());
    let nonzero = a.verify_storage(&storage(0, 0)).unwrap();
    assert!(!nonzero.value().is_zero());
    assert_eq!(nonzero.slot(), B256::ZERO);
    assert_eq!(nonzero.location(), a.location());
    let zero = a.verify_storage(&storage(0, 1)).unwrap();
    assert!(zero.value().is_zero());
    assert_eq!(zero.slot(), B256::repeat_byte(255));
    // These are raw words. No owner/implementation/pause layout is assumed.
}

#[test]
fn authenticated_empty_storage_and_absent_account_are_distinct() {
    let a = client().verify_account(&evidence(1)).unwrap().unwrap();
    assert_eq!(a.code_hash(), KECCAK_EMPTY);
    assert_eq!(a.storage_root(), EMPTY_ROOT_HASH);
    assert!(a.balance() > U256::ZERO);
    assert!(storage(1, 0).proof.is_empty());
    assert!(a.verify_storage(&storage(1, 0)).unwrap().value().is_zero());
    assert!(a.check_contract_code(KECCAK_EMPTY, &[]).is_err());
    assert!(client().verify_account(&evidence(2)).unwrap().is_none());
    let mut forged = evidence(2);
    forged.account_rlp = Some(alloy_rlp::encode(TrieAccount::default()).into());
    assert!(client().verify_account(&forged).is_err());
    let mut false_absence = evidence(0);
    false_absence.account_rlp = None;
    assert!(client().verify_account(&false_absence).is_err());
}

#[test]
fn block_address_and_each_account_field_are_bound_to_finalized_state() {
    let mut e = evidence(0);
    e.block_hash = B256::ZERO;
    assert!(client().verify_account(&e).is_err());
    let mut e = evidence(0);
    e.block_number += 1;
    assert!(client().verify_account(&e).is_err());
    let mut e = evidence(0);
    e.address = Address::ZERO;
    assert!(client().verify_account(&e).is_err());
    for field in 0..4 {
        let mut a = claimed_account(0);
        match field {
            0 => a.nonce += 1,
            1 => a.balance += U256::from(1),
            2 => a.storage_root = EMPTY_ROOT_HASH,
            _ => a.code_hash = KECCAK_EMPTY,
        }
        let mut e = evidence(0);
        e.account_rlp = Some(alloy_rlp::encode(a).into());
        assert!(client().verify_account(&e).is_err());
    }
    let mut e = evidence(0);
    let mut raw = e.account_rlp.unwrap().to_vec();
    raw.push(0);
    e.account_rlp = Some(raw.into());
    assert!(client().verify_account(&e).is_err());
}

#[test]
fn malformed_missing_truncated_reordered_and_extra_account_nodes_fail() {
    for index in 0..3 {
        let base = evidence(index);
        for mode in 0..6 {
            let mut e = base.clone();
            match mode {
                0 => e.proof.clear(),
                1 => {
                    e.proof.pop();
                }
                2 => e.proof.reverse(),
                3 => e.proof.push(e.proof[0].clone()),
                4 => e.proof[0] = Bytes::from_static(&[0xff]),
                _ => {
                    let mut n = e.proof[0].to_vec();
                    n[10] ^= 1;
                    e.proof[0] = n.into();
                }
            }
            assert!(
                client().verify_account(&e).is_err(),
                "account {index}, mode {mode}"
            );
        }
    }
}

#[test]
fn storage_cannot_default_to_zero_or_borrow_other_account_proofs() {
    let a = client().verify_account(&evidence(0)).unwrap().unwrap();
    for slot in 0..2 {
        let base = storage(0, slot);
        let mut s = base.clone();
        s.value += U256::from(1);
        assert!(a.verify_storage(&s).is_err());
        let mut s = base.clone();
        s.slot = storage(0, 1 - slot).slot;
        assert!(a.verify_storage(&s).is_err());
        for mode in 0..5 {
            let mut s = base.clone();
            match mode {
                0 => s.proof.clear(),
                1 => {
                    s.proof.pop();
                }
                2 => s.proof.reverse(),
                3 => s.proof.push(s.proof[0].clone()),
                _ => s.proof[0] = Bytes::from_static(&[0xff]),
            }
            assert!(a.verify_storage(&s).is_err());
        }
    }
    let mut s = storage(0, 0);
    s.value = U256::ZERO;
    assert!(a.verify_storage(&s).is_err());
    assert!(a.verify_storage(&storage(1, 0)).is_err());
    let empty = client().verify_account(&evidence(1)).unwrap().unwrap();
    assert!(empty.verify_storage(&storage(0, 0)).is_err());
    let mut s = storage(1, 0);
    s.value = U256::from(1);
    assert!(empty.verify_storage(&s).is_err());
}

#[test]
fn code_requires_both_authenticated_hash_and_separately_configured_pin() {
    let a = client().verify_account(&evidence(0)).unwrap().unwrap();
    assert!(a.check_contract_code(B256::ZERO, &code()).is_err());
    let mut changed = code().to_vec();
    changed[0] ^= 1;
    assert!(a.check_contract_code(CODE_HASH, &changed).is_err());
    assert!(a
        .check_contract_code(keccak256(&changed), &changed)
        .is_err());
    assert!(a.check_contract_code(CODE_HASH, &[]).is_err());
    assert!(a.check_contract_code(CODE_HASH, &vec![0; 24577]).is_err());
    let mut e = evidence(0);
    let verified = client().verify_account(&e).unwrap().unwrap();
    e.address = Address::ZERO;
    e.account_rlp = None;
    assert_eq!(verified.location().address, USDT);
    verified.check_contract_code(CODE_HASH, &code()).unwrap();
}

#[test]
fn receipt_and_account_share_emitter_post_state_but_do_not_authorize_mint() {
    let f: Value = serde_json::from_str(include_str!("../fixtures/receipt-vectors.json")).unwrap();
    let r = &f["vectors"][50];
    let receipt = client()
        .verify_receipt(&ReceiptEvidence {
            block_hash: f["blockHash"].as_str().unwrap().parse().unwrap(),
            block_number: f["blockNumber"].as_str().unwrap().parse().unwrap(),
            transaction_index: 50,
            receipt_bytes: r["receipt"].as_str().unwrap().parse().unwrap(),
            proof: nodes(&r["proof"]),
        })
        .unwrap();
    let event = receipt
        .log(
            0,
            &LogPolicy {
                emitter: USDT,
                topic0: keccak256(b"Transfer(address,address,uint256)"),
                topic_count: 3,
            },
        )
        .unwrap();
    let a = client().verify_account(&evidence(0)).unwrap().unwrap();
    assert!(a.is_emitter_post_state_for(&event));
    assert!(!client()
        .verify_account(&evidence(1))
        .unwrap()
        .unwrap()
        .is_emitter_post_state_for(&event));
    // No API yields an EligibleDeposit or checkpoint authorization from this relation.
}

#[test]
fn resource_limits_reject_before_trie_decode() {
    let cases = [
        (vec![Bytes::from_static(&[0xc0]); 33], "node count"),
        (vec![Bytes::from(vec![0; 262145])], "node size"),
        (vec![Bytes::from(vec![0; 180000]); 3], "byte limit"),
        (vec![Bytes::new()], "node size"),
    ];
    let a = client().verify_account(&evidence(0)).unwrap().unwrap();
    for (nodes, error) in cases {
        let mut e = evidence(0);
        e.proof = nodes.clone();
        assert!(client()
            .verify_account(&e)
            .unwrap_err()
            .to_string()
            .contains(error));
        let mut s = storage(0, 0);
        s.proof = nodes;
        assert!(a
            .verify_storage(&s)
            .unwrap_err()
            .to_string()
            .contains(error));
    }
    let mut e = evidence(0);
    e.account_rlp = Some(vec![0; 129].into());
    assert!(client()
        .verify_account(&e)
        .unwrap_err()
        .to_string()
        .contains("account byte limit"));
}
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
