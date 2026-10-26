//! Immutable side-branch extension sidecars share one LMDB transaction with
//! their header/body and never mutate canonical pointers or state.

mod common;

use common::open_test_store;
use dom_core::MAX_BLOCK_SERIALIZED_SIZE;
use dom_store::{ConsensusStateUpdate, ReorgSidecarChanges};
use std::collections::BTreeSet;
use tempfile::TempDir;

#[test]
fn sidecar_header_and_body_commit_together_survive_reopen_and_prune_together() {
    let dir = TempDir::new().unwrap();
    let hash = [0x61; 32];
    let header = b"side-header";
    let body = b"side-body";
    let sidecar = b"canonical-extension-envelope";
    {
        let store = open_test_store(dir.path());
        store
            .store_known_block_with_sidecar(&hash, header, body, sidecar)
            .unwrap();
        assert_eq!(store.get_block_header(&hash).unwrap().unwrap(), header);
        assert_eq!(store.get_block_body(&hash).unwrap().unwrap(), body);
        assert_eq!(store.get_block_sidecar(&hash).unwrap().unwrap(), sidecar);
        assert_eq!(store.get_chain_tip().unwrap(), None);
    }
    let store = open_test_store(dir.path());
    assert_eq!(store.get_block_sidecar(&hash).unwrap().unwrap(), sidecar);
    let mut prune = BTreeSet::new();
    prune.insert(hash);
    store.prune_known_blocks(&prune).unwrap();
    assert!(store.get_block_header(&hash).unwrap().is_none());
    assert!(store.get_block_body(&hash).unwrap().is_none());
    assert!(store.get_block_sidecar(&hash).unwrap().is_none());
}

#[test]
fn invalid_or_duplicate_sidecar_batch_has_no_partial_effect() {
    let dir = TempDir::new().unwrap();
    let store = open_test_store(dir.path());
    let empty_hash = [0x62; 32];
    assert!(store
        .store_known_block_with_sidecar(&empty_hash, b"header", b"body", &[])
        .is_err());
    assert!(store.get_block_header(&empty_hash).unwrap().is_none());
    assert!(store.get_block_body(&empty_hash).unwrap().is_none());

    let oversized_hash = [0x63; 32];
    let oversized = vec![0; MAX_BLOCK_SERIALIZED_SIZE + 1];
    assert!(store
        .store_known_block_with_sidecar(&oversized_hash, b"header", b"body", &oversized)
        .is_err());
    assert!(store.get_block_header(&oversized_hash).unwrap().is_none());

    let hash = [0x64; 32];
    store
        .store_known_block_with_sidecar(&hash, b"header-a", b"body-a", b"sidecar-a")
        .unwrap();
    assert!(store
        .store_known_block_with_sidecar(&hash, b"header-b", b"body-b", b"sidecar-b")
        .is_err());
    assert_eq!(
        store.get_block_sidecar(&hash).unwrap().unwrap(),
        b"sidecar-a"
    );
    assert_eq!(store.get_block_body(&hash).unwrap().unwrap(), b"body-a");
}

#[test]
fn promoted_sidecar_moves_to_consensus_state_atomically() {
    let dir = TempDir::new().unwrap();
    let store = open_test_store(dir.path());
    let hash = [0x65; 32];
    store
        .store_known_block_with_sidecar(
            &hash,
            b"promoted-header",
            b"promoted-body",
            b"authenticated-sidecar",
        )
        .unwrap();

    let updates = [ConsensusStateUpdate {
        key: b"usdom-v2/package/promoted".to_vec(),
        value: Some(b"authenticated-sidecar".to_vec()),
    }];
    store
        .apply_reorg_with_consensus_state_and_sidecar_changes(
            &hash,
            &[(9, Some(hash))],
            &[],
            &[],
            &updates,
            ReorgSidecarChanges {
                inserts: &[],
                deletes: &[hash],
            },
        )
        .unwrap();

    assert_eq!(store.get_chain_tip().unwrap(), Some(hash));
    assert_eq!(store.get_hash_at_height(9).unwrap(), Some(hash));
    assert!(store.get_block_sidecar(&hash).unwrap().is_none());
    assert_eq!(
        store
            .get_consensus_state(b"usdom-v2/package/promoted")
            .unwrap(),
        Some(b"authenticated-sidecar".to_vec())
    );
}

#[test]
fn conflicting_sidecar_change_rejects_entire_reorg() {
    let dir = TempDir::new().unwrap();
    let store = open_test_store(dir.path());
    let old_tip = [0x66; 32];
    let candidate = [0x67; 32];
    store
        .commit_block(&old_tip, 4, b"old-header", b"old-body", &[], &[], &[])
        .unwrap();
    store
        .store_known_block_with_sidecar(
            &candidate,
            b"candidate-header",
            b"candidate-body",
            b"candidate-sidecar",
        )
        .unwrap();

    let inserts = [(candidate, b"candidate-sidecar".to_vec())];
    let error = store
        .apply_reorg_with_consensus_state_and_sidecar_changes(
            &candidate,
            &[(4, Some(candidate))],
            &[],
            &[],
            &[ConsensusStateUpdate {
                key: b"usdom-v2/package/candidate".to_vec(),
                value: Some(b"candidate-sidecar".to_vec()),
            }],
            ReorgSidecarChanges {
                inserts: &inserts,
                deletes: &[candidate],
            },
        )
        .unwrap_err();

    assert!(error.to_string().contains("duplicate or conflicting"));
    assert_eq!(store.get_chain_tip().unwrap(), Some(old_tip));
    assert_eq!(store.get_hash_at_height(4).unwrap(), Some(old_tip));
    assert_eq!(
        store.get_block_sidecar(&candidate).unwrap(),
        Some(b"candidate-sidecar".to_vec())
    );
    assert!(store
        .get_consensus_state(b"usdom-v2/package/candidate")
        .unwrap()
        .is_none());
}
