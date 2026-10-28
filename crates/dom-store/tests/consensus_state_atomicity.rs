//! Atomic storage boundary for future native consensus extensions.
//!
//! These tests exercise persistence only. They do not claim that USDOM note,
//! nullifier, issuance, burn, or proof semantics already exist.

mod common;

use common::open_test_store;
use dom_store::{
    ConsensusStateUpdate, MAX_CONSENSUS_STATE_KEY_BYTES, MAX_CONSENSUS_STATE_UPDATES,
    MAX_CONSENSUS_STATE_VALUE_BYTES,
};
use tempfile::TempDir;

fn hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn put(key: &[u8], value: &[u8]) -> ConsensusStateUpdate {
    ConsensusStateUpdate {
        key: key.to_vec(),
        value: Some(value.to_vec()),
    }
}

fn delete(key: &[u8]) -> ConsensusStateUpdate {
    ConsensusStateUpdate {
        key: key.to_vec(),
        value: None,
    }
}

#[test]
fn block_and_extension_state_commit_together_and_survive_reopen() {
    let dir = TempDir::new().unwrap();
    let block = hash(1);
    {
        let store = open_test_store(dir.path());
        store
            .commit_block_with_consensus_state(
                &block,
                1,
                b"header-1",
                b"body-1",
                &[],
                &[],
                &[],
                &[
                    put(b"usdom/v1/state-root", &[0x11; 32]),
                    put(b"usdom/v1/note/0001", &[0x22; 32]),
                    put(b"usdom/v1/undo/0001", b"canonical-undo"),
                ],
            )
            .unwrap();
        assert_eq!(store.get_chain_tip().unwrap(), Some(block));
        assert_eq!(
            store.get_consensus_state(b"usdom/v1/state-root").unwrap(),
            Some(vec![0x11; 32])
        );
    }

    let reopened = open_test_store(dir.path());
    assert_eq!(reopened.get_chain_tip().unwrap(), Some(block));
    let all = reopened.read_all_consensus_state_raw().unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[b"usdom/v1/note/0001".as_slice()], vec![0x22; 32]);
}

#[test]
fn canonical_consensus_snapshot_cannot_mix_atomic_commits() {
    let dir = TempDir::new().unwrap();
    let store = open_test_store(dir.path());
    let first = hash(0x71);
    let second = hash(0x72);
    store
        .commit_block_with_consensus_state(
            &first,
            7,
            b"header-first",
            b"body-first",
            &[],
            &[],
            &[],
            &[put(b"usdom/v1/state-root", &[0x17; 32])],
        )
        .unwrap();

    let before = store.read_canonical_consensus_snapshot(7).unwrap();
    assert_eq!(before.chain_tip, Some(first));
    assert_eq!(before.requested_height_hash, Some(first));
    assert_eq!(
        before.consensus_state[b"usdom/v1/state-root".as_slice()],
        vec![0x17; 32]
    );

    store
        .commit_block_with_consensus_state(
            &second,
            8,
            b"header-second",
            b"body-second",
            &[],
            &[],
            &[],
            &[put(b"usdom/v1/state-root", &[0x28; 32])],
        )
        .unwrap();

    assert_eq!(before.chain_tip, Some(first));
    assert_eq!(before.requested_height_hash, Some(first));
    assert_eq!(
        before.consensus_state[b"usdom/v1/state-root".as_slice()],
        vec![0x17; 32]
    );
    let after = store.read_canonical_consensus_snapshot(8).unwrap();
    assert_eq!(after.chain_tip, Some(second));
    assert_eq!(after.requested_height_hash, Some(second));
    assert_eq!(
        after.consensus_state[b"usdom/v1/state-root".as_slice()],
        vec![0x28; 32]
    );
}

#[test]
fn selected_metadata_and_consensus_entries_share_one_bounded_snapshot() {
    let dir = TempDir::new().unwrap();
    let store = open_test_store(dir.path());
    store.put_metadata(b"restart/floor", b"external").unwrap();
    store
        .commit_block_with_consensus_state(
            &hash(9),
            1,
            b"header-1",
            b"body-1",
            &[],
            &[],
            &[],
            &[put(b"consensus/floor", b"canonical")],
        )
        .unwrap();

    let (metadata, consensus) = store
        .read_atomic_state_entries(&[b"restart/floor", b"missing"], &[b"consensus/floor"])
        .unwrap();
    assert_eq!(metadata, vec![Some(b"external".to_vec()), None]);
    assert_eq!(consensus, vec![Some(b"canonical".to_vec())]);

    let too_many = vec![b"key".as_slice(); 17];
    assert!(store
        .read_atomic_state_entries(&too_many, &[])
        .unwrap_err()
        .to_string()
        .contains("exceeds key bounds"));
    assert!(store
        .read_atomic_state_entries(&[b""], &[])
        .unwrap_err()
        .to_string()
        .contains("exceeds key bounds"));
}

#[test]
fn invalid_or_ambiguous_batch_is_rejected_before_block_mutation() {
    let dir = TempDir::new().unwrap();
    let store = open_test_store(dir.path());
    let block = hash(2);
    let duplicate = [put(b"usdom/v1/root", b"old"), put(b"usdom/v1/root", b"new")];
    let error = store
        .commit_block_with_consensus_state(
            &block,
            2,
            b"header-2",
            b"body-2",
            &[],
            &[],
            &[],
            &duplicate,
        )
        .unwrap_err();
    assert!(error.to_string().contains("duplicate consensus-state key"));
    assert_eq!(store.get_chain_tip().unwrap(), None);
    assert_eq!(store.get_block_header(&block).unwrap(), None);
    assert!(store.read_all_consensus_state_raw().unwrap().is_empty());

    for update in [
        ConsensusStateUpdate {
            key: vec![],
            value: Some(vec![1]),
        },
        ConsensusStateUpdate {
            key: vec![1; MAX_CONSENSUS_STATE_KEY_BYTES + 1],
            value: Some(vec![1]),
        },
        ConsensusStateUpdate {
            key: b"usdom/v1/empty".to_vec(),
            value: Some(vec![]),
        },
        ConsensusStateUpdate {
            key: b"usdom/v1/oversize".to_vec(),
            value: Some(vec![1; MAX_CONSENSUS_STATE_VALUE_BYTES + 1]),
        },
    ] {
        assert!(store
            .commit_block_with_consensus_state(
                &block,
                2,
                b"header-2",
                b"body-2",
                &[],
                &[],
                &[],
                &[update],
            )
            .is_err());
        assert_eq!(store.get_chain_tip().unwrap(), None);
    }

    let too_many = vec![delete(b"usdom/v1/delete"); MAX_CONSENSUS_STATE_UPDATES + 1];
    assert!(store
        .commit_block_with_consensus_state(
            &block,
            2,
            b"header-2",
            b"body-2",
            &[],
            &[],
            &[],
            &too_many,
        )
        .is_err());
    assert_eq!(store.get_chain_tip().unwrap(), None);
}

#[test]
fn reorg_pointer_and_final_extension_state_change_in_one_call() {
    let dir = TempDir::new().unwrap();
    let store = open_test_store(dir.path());
    let old_tip = hash(3);
    let new_tip = hash(4);
    store
        .commit_block_with_consensus_state(
            &old_tip,
            3,
            b"header-old",
            b"body-old",
            &[],
            &[],
            &[],
            &[
                put(b"usdom/v1/state-root", &[0x33; 32]),
                put(b"usdom/v1/nullifier/old", &[1]),
                put(b"usdom/v1/undo/old", b"old-undo"),
            ],
        )
        .unwrap();
    store
        .store_known_block(&new_tip, b"header-new", b"body-new")
        .unwrap();

    store
        .apply_reorg_with_consensus_state(
            &new_tip,
            &[(3, Some(new_tip))],
            &[],
            &[],
            &[
                put(b"usdom/v1/state-root", &[0x44; 32]),
                delete(b"usdom/v1/nullifier/old"),
                delete(b"usdom/v1/undo/old"),
                put(b"usdom/v1/nullifier/new", &[1]),
                put(b"usdom/v1/undo/new", b"new-undo"),
            ],
        )
        .unwrap();

    assert_eq!(store.get_chain_tip().unwrap(), Some(new_tip));
    assert_eq!(store.get_hash_at_height(3).unwrap(), Some(new_tip));
    assert_eq!(
        store.get_consensus_state(b"usdom/v1/state-root").unwrap(),
        Some(vec![0x44; 32])
    );
    assert_eq!(
        store
            .get_consensus_state(b"usdom/v1/nullifier/old")
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .get_consensus_state(b"usdom/v1/nullifier/new")
            .unwrap(),
        Some(vec![1])
    );
}

#[test]
fn rejected_reorg_batch_leaves_tip_and_extension_state_unchanged() {
    let dir = TempDir::new().unwrap();
    let store = open_test_store(dir.path());
    let old_tip = hash(5);
    let rejected_tip = hash(6);
    store
        .commit_block_with_consensus_state(
            &old_tip,
            5,
            b"header-old",
            b"body-old",
            &[],
            &[],
            &[],
            &[put(b"usdom/v1/state-root", &[0x55; 32])],
        )
        .unwrap();

    let error = store
        .apply_reorg_with_consensus_state(
            &rejected_tip,
            &[(5, Some(rejected_tip))],
            &[],
            &[],
            &[
                put(b"usdom/v1/state-root", &[0x66; 32]),
                put(b"usdom/v1/state-root", &[0x77; 32]),
            ],
        )
        .unwrap_err();
    assert!(error.to_string().contains("duplicate consensus-state key"));
    assert_eq!(store.get_chain_tip().unwrap(), Some(old_tip));
    assert_eq!(store.get_hash_at_height(5).unwrap(), Some(old_tip));
    assert_eq!(
        store.get_consensus_state(b"usdom/v1/state-root").unwrap(),
        Some(vec![0x55; 32])
    );
}

#[test]
fn stale_same_height_commit_aborts_without_partial_extension_state() {
    let dir = TempDir::new().unwrap();
    let store = open_test_store(dir.path());
    let first = hash(0x81);
    let stale = hash(0x82);
    store
        .commit_block_with_consensus_state(
            &first,
            9,
            b"header-first",
            b"body-first",
            &[],
            &[],
            &[],
            &[put(b"usdom/v2/root", &[0x11; 32])],
        )
        .unwrap();

    let error = store
        .commit_block_with_consensus_state(
            &stale,
            9,
            b"header-stale",
            b"body-stale",
            &[],
            &[],
            &[],
            &[
                put(b"usdom/v2/root", &[0x22; 32]),
                put(b"usdom/v2/undo/stale", b"undo"),
            ],
        )
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("canonical height already exists"));
    assert_eq!(store.get_chain_tip().unwrap(), Some(first));
    assert_eq!(store.get_hash_at_height(9).unwrap(), Some(first));
    assert_eq!(store.get_block_header(&stale).unwrap(), None);
    assert_eq!(
        store.get_consensus_state(b"usdom/v2/root").unwrap(),
        Some(vec![0x11; 32])
    );
    assert_eq!(
        store.get_consensus_state(b"usdom/v2/undo/stale").unwrap(),
        None
    );
}

#[test]
fn duplicate_reorg_coordinates_fail_before_any_atomic_write() {
    let dir = TempDir::new().unwrap();
    let store = open_test_store(dir.path());
    let old = hash(0x91);
    let new = hash(0x92);
    store
        .commit_block_with_consensus_state(
            &old,
            10,
            b"old",
            b"old-body",
            &[],
            &[],
            &[],
            &[put(b"usdom/v2/root", &[0x31; 32])],
        )
        .unwrap();

    let duplicate_height = store
        .apply_reorg_with_consensus_state(
            &new,
            &[(10, Some(new)), (10, None)],
            &[],
            &[],
            &[put(b"usdom/v2/root", &[0x32; 32])],
        )
        .unwrap_err();
    assert!(duplicate_height.to_string().contains("duplicate height"));
    let commitment = [0x41; 33];
    let duplicate_utxo = store
        .apply_reorg_with_consensus_state(
            &new,
            &[],
            &[(commitment, Some(vec![1])), (commitment, None)],
            &[],
            &[],
        )
        .unwrap_err();
    assert!(duplicate_utxo.to_string().contains("duplicate UTXO"));
    let excess = [0x51; 33];
    let duplicate_kernel = store
        .apply_reorg_with_consensus_state(
            &new,
            &[],
            &[],
            &[(excess, Some(new)), (excess, None)],
            &[],
        )
        .unwrap_err();
    assert!(duplicate_kernel.to_string().contains("duplicate kernel"));
    assert_eq!(store.get_chain_tip().unwrap(), Some(old));
    assert_eq!(store.get_hash_at_height(10).unwrap(), Some(old));
    assert_eq!(
        store.get_consensus_state(b"usdom/v2/root").unwrap(),
        Some(vec![0x31; 32])
    );
}

#[test]
fn reorg_sidecar_insert_and_canonical_state_are_one_atomic_transaction() {
    let dir = TempDir::new().unwrap();
    let store = open_test_store(dir.path());
    let old_tip = hash(7);
    let new_tip = hash(8);
    let rejected_tip = hash(9);
    store
        .commit_block_with_consensus_state(
            &old_tip,
            7,
            b"header-old",
            b"body-old",
            &[],
            &[],
            &[],
            &[put(b"usdom/v1/state-root", &[0x77; 32])],
        )
        .unwrap();
    store
        .store_known_block(&new_tip, b"header-new", b"body-new")
        .unwrap();
    store
        .store_known_block(&rejected_tip, b"header-rejected", b"body-rejected")
        .unwrap();

    store
        .apply_reorg_with_consensus_state_and_sidecars(
            &new_tip,
            &[(7, Some(new_tip))],
            &[],
            &[],
            &[put(b"usdom/v1/state-root", &[0x88; 32])],
            &[(old_tip, b"old-canonical-proof".to_vec())],
        )
        .unwrap();
    assert_eq!(store.get_chain_tip().unwrap(), Some(new_tip));
    assert_eq!(
        store.get_block_sidecar(&old_tip).unwrap(),
        Some(b"old-canonical-proof".to_vec())
    );

    assert!(store
        .apply_reorg_with_consensus_state_and_sidecars(
            &rejected_tip,
            &[(7, Some(rejected_tip))],
            &[],
            &[],
            &[put(b"usdom/v1/state-root", &[0x99; 32])],
            &[(old_tip, b"substituted-proof".to_vec())],
        )
        .is_err());
    assert_eq!(store.get_chain_tip().unwrap(), Some(new_tip));
    assert_eq!(store.get_hash_at_height(7).unwrap(), Some(new_tip));
    assert_eq!(
        store.get_consensus_state(b"usdom/v1/state-root").unwrap(),
        Some(vec![0x88; 32])
    );
    assert_eq!(
        store.get_block_sidecar(&old_tip).unwrap(),
        Some(b"old-canonical-proof".to_vec())
    );
}
