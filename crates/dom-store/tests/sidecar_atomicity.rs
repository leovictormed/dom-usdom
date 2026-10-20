//! Immutable side-branch extension sidecars share one LMDB transaction with
//! their header/body and never mutate canonical pointers or state.

mod common;

use common::open_test_store;
use dom_core::MAX_BLOCK_SERIALIZED_SIZE;
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
