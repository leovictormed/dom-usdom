//! # dom-store
//!
//! Persistent storage for the DOM node using LMDB.
//!
//! ## Database Layout
//!
//! All data lives in a single LMDB environment with multiple named databases:
//!
//! | DB name         | Key                    | Value                    |
//! |-----------------|------------------------|--------------------------|
//! | `blocks`        | block_hash [32 bytes]  | serialized BlockHeader   |
//! | `block_sidecars` | block_hash [32 bytes] | immutable extension bytes |
//! | `block_height`  | height [8 bytes LE]    | block_hash [32 bytes]    |
//! | `chain_tip`     | b"tip"                 | block_hash [32 bytes]    |
//! | `utxos`         | commitment [33 bytes]  | UtxoEntry (serialized)   |
//! | `kernel_index`  | kernel_excess [33 bytes] | block_hash [32 bytes]  |
//! | `consensus_state` | domain-separated bytes | canonical extension state |
//! | `peer_addrs`    | ip:port string         | last_seen u64 LE         |
//!
//! ## Atomicity
//!
//! RFC-0007 step 14: atomic state commit.
//! All writes during block processing go into ONE LMDB transaction.
//! If anything fails, the whole transaction is aborted — no partial state.
//!
//! ## LMDB dependency status
//!
//! The LMDB backend is provided by the maintained `lmdb-rkv` package through the
//! workspace `lmdb` crate rename and is isolated behind `DomStore`; callers do
//! not use LMDB handles directly except corruption/durability tests. A
//! storage-engine migration is intentionally not performed as an incidental
//! dependency cleanup because it would alter persistence semantics. The current
//! mitigation is to keep LMDB usage narrow, retain default sync durability,
//! perform block commits in a single write transaction, surface `MDB_MAP_FULL`
//! via `LMDB_MAP_FULL_SENTINEL`, and pin crash/corruption behavior with the
//! store tests.

// unsafe allowed for lmdb API
#![deny(missing_docs)]

#[cfg(kani)]
mod kani_invariants;

pub mod block_store;
pub mod db;
pub mod peer_store;
pub mod utxo;

pub use block_store::BlockStore;
pub use db::{
    validate_consensus_state_updates, CanonicalConsensusSnapshot, ConsensusStateUpdate, DomStore,
    ReorgSidecarChanges, DB_BLOCKS, DB_BLOCK_BODIES, DB_BLOCK_HEIGHT, DB_BLOCK_SIDECARS,
    DB_CHAIN_TIP, DB_CONSENSUS_STATE, DB_KERNEL_INDEX, DB_METADATA, DB_PEER_ADDRS, DB_UTXOS,
    LMDB_MAP_FULL_SENTINEL, MAX_CONSENSUS_STATE_BATCH_BYTES, MAX_CONSENSUS_STATE_KEY_BYTES,
    MAX_CONSENSUS_STATE_UPDATES, MAX_CONSENSUS_STATE_VALUE_BYTES, METADATA_UTXO_SET_DIGEST_KEY,
};
pub use peer_store::PeerAddr;
pub use utxo::{UtxoEntry, UtxoSet};
