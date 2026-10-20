#![allow(missing_docs)]
//! LMDB environment and database handles.
//!
//! ## Durability stance (Roadmap v2 Phase 3.3)
//!
//! The environment is opened with the *default* sync mode. Concretely:
//!
//! - `MDB_NOSYNC` is NOT set. `mdb_txn_commit` therefore fsyncs the
//!   data file before returning. A successful `commit_block` MUST mean
//!   the block is durable across a power loss or kernel panic — that
//!   is the consensus-grade contract a blockchain store has to honour.
//! - `MDB_NOMETASYNC` is NOT set. The meta page (the LMDB superblock)
//!   is fsynced too; without it a power loss can leave the file
//!   structurally inconsistent.
//!
//! The pre-Phase-3.3 flag set (`NO_TLS | NO_SYNC`) traded durability
//! for a throughput win that does not exist at our commit cadence
//! (~one fsync per ≥120-second block) and that the LMDB docs
//! explicitly warn "can corrupt the database or lose the last
//! transactions". A blockchain cannot accept either outcome.
//!
//! `NO_TLS` is retained: it disables the per-thread reader-slot
//! reservation that prevents a single thread from opening multiple
//! read transactions concurrently. The DomStore caller pool is async
//! / multi-thread and the slot model would otherwise serialise reads.
//!
//! ## Map size (Roadmap v2 Phase 3.3)
//!
//! `MAP_SIZE` is the maximum mapped region size — LMDB will refuse
//! commits with `MDB_MAP_FULL` once the file grows past it. We
//! pre-allocate 16 GiB on every host; that buys >5 years at the
//! current 33-DOM block reward + typical 1 MB block budget before any
//! manual extension is needed. When a commit fails with `MapFull`,
//! `commit_block` returns a tagged `DomError::Internal` containing
//! `"LMDB_MAP_FULL"` so the chain-init layer can surface the
//! condition distinctly from a generic LMDB error.
//!
//! Dynamic map_size growth is intentionally deferred: it requires a
//! safe quiescent point with no in-flight read transactions, and the
//! current async multi-reader model can't guarantee that cheaply.
//! Once Phase 6 lands rebuild-from-genesis, the operator path
//! "raise the limit and restart" becomes equivalent to "wait,
//! redeliver" and the deferral is no longer a release blocker.
//! Tracked under RB-LMDB-MAPSIZE in RELEASE_BLOCKERS.
//!
//! ## Partial-persistence contract (Roadmap v2 Phase 3.2)
//!
//! Under normal use, every `commit_block` is one LMDB transaction, and
//! LMDB's per-txn atomicity guarantees that an interrupted process
//! either persists the whole transaction or nothing. The SIGKILL
//! harness in `tests/crash_consistency_sigkill.rs` exercises this.
//!
//! If something *outside* `commit_block` does manage to leave the
//! store in a partial state — a future refactor that splits a write
//! across txns, an external corruption tool, a manual recovery — the
//! contract is:
//!
//! 1. `DomStore::open` MUST succeed on the partial state. It must not
//!    panic, abort, or refuse to open. Callers need to be able to
//!    inspect the store in order to repair it; bailing out here would
//!    deny them that.
//! 2. Every read method (`get_block_header`, `get_block_body`,
//!    `get_hash_at_height`, `get_chain_tip`, `get_utxo`) MUST report
//!    the on-disk state honestly:
//!      - `Some(v)` if the value is present in its database;
//!      - `None` if it is not.
//!
//!    No silent reconstruction, no fabricated bytes.
//! 3. Pointer relations (`chain_tip → block`, `height → hash`,
//!    `kernel_index → block_hash`) MUST be returned verbatim. If the
//!    pointer survives but its target is missing, the caller observes
//!    `Some(ptr)` from the pointer read and then `None` from the
//!    dereference. Detecting that mismatch and reacting (log, abort,
//!    rebuild) is the chain-init layer's responsibility, not this
//!    crate's.
//!
//! These guarantees are pinned by `tests/partial_persistence.rs`.

use dom_core::{DomError, MAX_BLOCK_SERIALIZED_SIZE};
use lmdb::{
    Cursor, Database, DatabaseFlags, Environment, EnvironmentFlags, RwTransaction, Transaction,
    WriteFlags,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const DEFAULT_MAP_SIZE: usize = 1 << 34; // 16 GiB — see module doc § "Map size"
const MAX_DBS: u32 = 16;

/// Sentinel substring callers can grep for in `DomError::Internal`
/// messages to detect LMDB map-full conditions distinctly from other
/// internal errors. Exposed as a constant so the chain-init layer can
/// match exactly without typo risk.
pub const LMDB_MAP_FULL_SENTINEL: &str = "LMDB_MAP_FULL";

/// Named LMDB databases.
pub const DB_BLOCKS: &str = "blocks";
pub const DB_BLOCK_BODIES: &str = "block_bodies";
/// Immutable consensus-extension sidecar bytes keyed by block hash.
pub const DB_BLOCK_SIDECARS: &str = "block_sidecars";
pub const DB_BLOCK_HEIGHT: &str = "block_height";
pub const DB_CHAIN_TIP: &str = "chain_tip";
pub const DB_UTXOS: &str = "utxos";
pub const DB_KERNEL_INDEX: &str = "kernel_index";
pub const DB_PEER_ADDRS: &str = "peer_addrs";
pub const DB_METADATA: &str = "metadata";
/// Canonical protocol-extension state updated atomically with blocks/reorgs.
pub const DB_CONSENSUS_STATE: &str = "consensus_state";
/// tx_identity: canonical transaction hash → primary kernel excess plus the
/// height at which this node admitted the transaction to its own mempool
/// (33 + 8 bytes LE). Ratified 2026-08-21 (F8_PLAN_AND_DECISIONS_RATIFICATION.md Q-3, signed) — Option A of
/// `F7_NODE_TX_IDENTITY_DEFECTS_FOR_RATIFICATION.md` §3. The mapping is a property of the transaction
/// and never changes, so this database needs no reorg maintenance of its
/// own: every reorg-dependent answer is served by `kernel_index`, which
/// `apply_reorg` maintains. Confirmation is therefore never asserted from
/// this entry alone.
pub const DB_TX_IDENTITY: &str = "tx_identity";

/// How long a tx-identity entry is retained, in blocks after admission.
/// At the 6-second block target this is roughly one week. This constant
/// REMAINS INTERIM by the ratification's own text (Q-3): changing it is a
/// policy decision requiring a new ratification, not a tuning knob.
pub const TX_IDENTITY_RETENTION_BLOCKS: u64 = 100_000;
/// Stable metadata key holding the canonical UTXO-set digest when the
/// persisted UTXO database has been verified or rebuilt against canonical
/// history on reopen.
pub const METADATA_UTXO_SET_DIGEST_KEY: &[u8] = b"canonical_utxo_digest_v1";

/// Maximum number of canonical extension-state mutations in one atomic batch.
pub const MAX_CONSENSUS_STATE_UPDATES: usize = 20_000;
/// Maximum encoded key length for canonical extension state.
pub const MAX_CONSENSUS_STATE_KEY_BYTES: usize = 128;
/// Maximum encoded value length for one canonical extension-state entry.
pub const MAX_CONSENSUS_STATE_VALUE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum aggregate key/value bytes for one canonical extension-state batch.
pub const MAX_CONSENSUS_STATE_BATCH_BYTES: usize = 16 * 1024 * 1024;

/// One deterministic canonical-state mutation. `None` deletes the key.
///
/// Callers must derive these bytes entirely from validated consensus inputs.
/// The store enforces resource/canonicality bounds but does not interpret keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusStateUpdate {
    /// Non-empty, domain-separated state key.
    pub key: Vec<u8>,
    /// Canonical value bytes, or `None` to delete an existing entry.
    pub value: Option<Vec<u8>>,
}

/// One LMDB-consistent view of the canonical tip, one requested height index,
/// and every protocol-extension state entry.
///
/// All fields are copied from the same read transaction, so a concurrent block
/// commit or reorganization cannot mix an old tip with new extension state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalConsensusSnapshot {
    /// Chain tip visible to the read transaction, or `None` for an empty store.
    pub chain_tip: Option<[u8; 32]>,
    /// Height whose canonical occupant was requested.
    pub requested_height: u64,
    /// Canonical hash at `requested_height`, if present in the same snapshot.
    pub requested_height_hash: Option<[u8; 32]>,
    /// Complete canonical protocol-extension state in bytewise key order.
    pub consensus_state: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// The DOM storage engine.
pub struct DomStore {
    /// LMDB environment.
    pub env: Environment,
    /// Configured LMDB map size for this environment.
    pub map_size: usize,
    /// blocks: hash → header bytes
    pub db_blocks: Database,
    /// block_bodies: hash → serialized Block body (full block bytes minus header)
    pub db_block_bodies: Database,
    /// block_sidecars: hash → immutable bounded extension bytes
    pub db_block_sidecars: Database,
    /// block_height: height_le8 → hash
    pub db_height: Database,
    /// chain_tip: "tip" → hash
    pub db_tip: Database,
    /// utxos: commitment_33 → UtxoEntry
    pub db_utxos: Database,
    /// kernel_index: excess_33 → block_hash
    pub db_kernels: Database,
    /// peer_addrs: addr_str → last_seen_u64
    pub db_peers: Database,
    /// metadata: arbitrary bounded node/runtime metadata keyed by stable bytes
    pub db_metadata: Database,
    /// consensus_state: canonical protocol-extension key/value state
    pub db_consensus_state: Database,
    /// tx_identity: tx_hash_32 → excess_33 ‖ admitted_height_le8 (see [`DB_TX_IDENTITY`])
    pub db_tx_identity: Database,
}

/// Validate extension-state update resource limits and key uniqueness without
/// opening a write transaction. Consensus adapters should call this after
/// deriving a batch so oversized proof/state combinations fail before commit.
pub fn validate_consensus_state_updates(updates: &[ConsensusStateUpdate]) -> Result<(), DomError> {
    if updates.len() > MAX_CONSENSUS_STATE_UPDATES {
        return Err(DomError::Invalid(format!(
            "too many consensus-state updates: {} > {MAX_CONSENSUS_STATE_UPDATES}",
            updates.len()
        )));
    }
    let mut seen = BTreeSet::new();
    let mut total = 0usize;
    for update in updates {
        if update.key.is_empty() || update.key.len() > MAX_CONSENSUS_STATE_KEY_BYTES {
            return Err(DomError::Invalid(format!(
                "invalid consensus-state key length {}",
                update.key.len()
            )));
        }
        if !seen.insert(update.key.as_slice()) {
            return Err(DomError::Invalid(
                "duplicate consensus-state key in atomic batch".into(),
            ));
        }
        total = total
            .checked_add(update.key.len())
            .ok_or_else(|| DomError::Invalid("consensus-state batch size overflow".into()))?;
        if let Some(value) = &update.value {
            if value.is_empty() || value.len() > MAX_CONSENSUS_STATE_VALUE_BYTES {
                return Err(DomError::Invalid(format!(
                    "invalid consensus-state value length {}",
                    value.len()
                )));
            }
            total = total
                .checked_add(value.len())
                .ok_or_else(|| DomError::Invalid("consensus-state batch size overflow".into()))?;
        }
        if total > MAX_CONSENSUS_STATE_BATCH_BYTES {
            return Err(DomError::Invalid(format!(
                "consensus-state batch bytes {total} > {MAX_CONSENSUS_STATE_BATCH_BYTES}"
            )));
        }
    }
    Ok(())
}

fn apply_consensus_state_updates(
    txn: &mut RwTransaction<'_>,
    database: Database,
    updates: &[ConsensusStateUpdate],
) -> Result<(), DomError> {
    for update in updates {
        match &update.value {
            Some(value) => txn
                .put(database, &update.key, value, WriteFlags::empty())
                .map_err(|e| DomError::Internal(format!("put consensus state: {e}")))?,
            None => match txn.del(database, &update.key, None) {
                Ok(()) | Err(lmdb::Error::NotFound) => {}
                Err(e) => {
                    return Err(DomError::Internal(format!("delete consensus state: {e}")));
                }
            },
        }
    }
    Ok(())
}

impl DomStore {
    /// Open (or create) the store at the given directory.
    pub fn open(data_dir: &Path) -> Result<Self, DomError> {
        Self::open_with_map_size(data_dir, DEFAULT_MAP_SIZE)
    }

    /// Open (or create) the store at the given directory with an explicit
    /// LMDB map size. Production callers should use [`Self::open`]; this is
    /// primarily for tiny test fixtures where reserving the full production
    /// map would be wasteful on constrained CI hosts.
    pub fn open_with_map_size(data_dir: &Path, map_size: usize) -> Result<Self, DomError> {
        std::fs::create_dir_all(data_dir)
            .map_err(|e| DomError::Internal(format!("create data dir: {e}")))?;

        // NO_TLS only — see module doc § "Durability stance". NO_SYNC and
        // NO_META_SYNC are intentionally absent: every commit_block must
        // fsync the data file + meta page before returning.
        let env = Environment::new()
            .set_flags(EnvironmentFlags::NO_TLS)
            .set_max_dbs(MAX_DBS)
            .set_map_size(map_size)
            .open(data_dir)
            .map_err(|e| DomError::Internal(format!("lmdb open: {e}")))?;

        let open_db = |name: &str| -> Result<Database, DomError> {
            let txn = env
                .begin_rw_txn()
                .map_err(|e| DomError::Internal(format!("begin txn: {e}")))?;
            let db = unsafe {
                txn.open_db(Some(name))
                    .or_else(|_| txn.create_db(Some(name), DatabaseFlags::empty()))
            }
            .map_err(|e| DomError::Internal(format!("open db {name}: {e}")))?;
            txn.commit()
                .map_err(|e| DomError::Internal(format!("commit db open: {e}")))?;
            Ok(db)
        };

        Ok(Self {
            map_size,
            db_blocks: open_db(DB_BLOCKS)?,
            db_block_bodies: open_db(DB_BLOCK_BODIES)?,
            db_block_sidecars: open_db(DB_BLOCK_SIDECARS)?,
            db_height: open_db(DB_BLOCK_HEIGHT)?,
            db_tip: open_db(DB_CHAIN_TIP)?,
            db_utxos: open_db(DB_UTXOS)?,
            db_kernels: open_db(DB_KERNEL_INDEX)?,
            db_peers: open_db(DB_PEER_ADDRS)?,
            db_metadata: open_db(DB_METADATA)?,
            db_consensus_state: open_db(DB_CONSENSUS_STATE)?,
            db_tx_identity: open_db(DB_TX_IDENTITY)?,
            env,
        })
    }

    /// Read a metadata value by stable key.
    pub fn get_metadata(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        match txn.get(self.db_metadata, &key) {
            Ok(bytes) => Ok(Some(bytes.to_vec())),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(DomError::Internal(format!("get metadata: {e}"))),
        }
    }

    /// Upsert a metadata value by stable key.
    pub fn put_metadata(&self, key: &[u8], value: &[u8]) -> Result<(), DomError> {
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| DomError::Internal(format!("rw txn: {e}")))?;
        txn.put(self.db_metadata, &key, &value, WriteFlags::empty())
            .map_err(|e| DomError::Internal(format!("put metadata: {e}")))?;
        txn.commit()
            .map_err(|e| DomError::Internal(format!("commit metadata: {e}")))?;
        Ok(())
    }

    /// Delete a metadata key if present.
    pub fn delete_metadata(&self, key: &[u8]) -> Result<(), DomError> {
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| DomError::Internal(format!("rw txn: {e}")))?;
        match txn.del(self.db_metadata, &key, None) {
            Ok(()) | Err(lmdb::Error::NotFound) => {}
            Err(e) => return Err(DomError::Internal(format!("delete metadata: {e}"))),
        }
        txn.commit()
            .map_err(|e| DomError::Internal(format!("commit metadata delete: {e}")))?;
        Ok(())
    }

    /// Read one canonical protocol-extension state entry.
    pub fn get_consensus_state(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        match txn.get(self.db_consensus_state, &key) {
            Ok(bytes) => Ok(Some(bytes.to_vec())),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(DomError::Internal(format!("get consensus state: {e}"))),
        }
    }

    /// Read all canonical protocol-extension state in bytewise key order.
    ///
    /// Intended for deterministic state-root computation, startup verification,
    /// snapshots, and tests. Consensus code must still bound the state model;
    /// this method does not make an unbounded full scan cheap.
    pub fn read_all_consensus_state_raw(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        let mut cursor = txn
            .open_ro_cursor(self.db_consensus_state)
            .map_err(|e| DomError::Internal(format!("open consensus-state cursor: {e}")))?;
        let mut out = BTreeMap::new();
        for item in cursor.iter() {
            let (key, value) =
                item.map_err(|e| DomError::Internal(format!("read consensus-state cursor: {e}")))?;
            out.insert(key.to_vec(), value.to_vec());
        }
        Ok(out)
    }

    /// Read the canonical tip, one height index and all extension state from a
    /// single LMDB transaction.
    ///
    /// This is intended for startup restoration and portable snapshots that
    /// must never combine fields observed before and after a concurrent atomic
    /// chain commit. The returned bytes are owned and remain a stable snapshot
    /// after the read transaction closes.
    pub fn read_canonical_consensus_snapshot(
        &self,
        requested_height: u64,
    ) -> Result<CanonicalConsensusSnapshot, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        let chain_tip = match txn.get(self.db_tip, b"tip") {
            Ok(bytes) if bytes.len() == 32 => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(bytes);
                Some(hash)
            }
            Ok(_) => return Err(DomError::Internal("corrupt chain tip".into())),
            Err(lmdb::Error::NotFound) => None,
            Err(e) => return Err(DomError::Internal(format!("get tip: {e}"))),
        };
        let height_key = requested_height.to_le_bytes();
        let requested_height_hash = match txn.get(self.db_height, &height_key) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(bytes);
                Some(hash)
            }
            Ok(_) => return Err(DomError::Internal("corrupt height index".into())),
            Err(lmdb::Error::NotFound) => None,
            Err(e) => return Err(DomError::Internal(format!("get height: {e}"))),
        };
        let mut cursor = txn
            .open_ro_cursor(self.db_consensus_state)
            .map_err(|e| DomError::Internal(format!("open consensus-state cursor: {e}")))?;
        let mut consensus_state = BTreeMap::new();
        for item in cursor.iter() {
            let (key, value) =
                item.map_err(|e| DomError::Internal(format!("read consensus-state cursor: {e}")))?;
            consensus_state.insert(key.to_vec(), value.to_vec());
        }
        Ok(CanonicalConsensusSnapshot {
            chain_tip,
            requested_height,
            requested_height_hash,
            consensus_state,
        })
    }

    /// Get the current chain tip hash. Returns None if chain is empty.
    pub fn get_chain_tip(&self) -> Result<Option<[u8; 32]>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        match txn.get(self.db_tip, b"tip") {
            Ok(bytes) if bytes.len() == 32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(bytes);
                Ok(Some(h))
            }
            Ok(_) => Err(DomError::Internal("corrupt chain tip".into())),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(DomError::Internal(format!("get tip: {e}"))),
        }
    }

    /// Get a block header by hash. Returns None if not found.
    pub fn get_block_header(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        match txn.get(self.db_blocks, hash) {
            Ok(bytes) => Ok(Some(bytes.to_vec())),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(DomError::Internal(format!("get block: {e}"))),
        }
    }

    /// Get block hash at a given height.
    pub fn get_hash_at_height(&self, height: u64) -> Result<Option<[u8; 32]>, DomError> {
        let key = height.to_le_bytes();
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        match txn.get(self.db_height, &key) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(bytes);
                Ok(Some(h))
            }
            Ok(_) => Err(DomError::Internal("corrupt height index".into())),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(DomError::Internal(format!("get height: {e}"))),
        }
    }

    /// Get a UTXO entry by commitment (33-byte compressed point).
    /// Returns None if the UTXO does not exist (spent or never created).
    pub fn get_utxo(
        &self,
        commitment: &[u8; 33],
    ) -> Result<Option<crate::utxo::UtxoEntry>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        match txn.get(self.db_utxos, commitment) {
            Ok(bytes) => Ok(Some(crate::utxo::UtxoEntry::from_bytes(bytes)?)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(DomError::Internal(format!("get utxo: {e}"))),
        }
    }

    /// Get the full serialized block body by hash.
    ///
    /// Returns None if the block is unknown (not yet committed or pruned).
    pub fn get_block_body(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        match txn.get(self.db_block_bodies, hash) {
            Ok(bytes) => Ok(Some(bytes.to_vec())),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(DomError::Internal(format!("get block body: {e}"))),
        }
    }

    /// Get immutable consensus-extension sidecar bytes by block hash.
    pub fn get_block_sidecar(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        match txn.get(self.db_block_sidecars, hash) {
            Ok(bytes) => Ok(Some(bytes.to_vec())),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(DomError::Internal(format!("get block sidecar: {e}"))),
        }
    }

    /// Read the full persisted UTXO database as raw key/value bytes.
    ///
    /// This is used by chain reopen verification to compare the on-disk UTXO
    /// database against a canonical reconstruction without trusting the stored
    /// entry encoding first.
    pub fn read_all_utxos_raw(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        let mut cursor = txn
            .open_ro_cursor(self.db_utxos)
            .map_err(|e| DomError::Internal(format!("open utxo cursor: {e}")))?;
        let mut out = BTreeMap::new();
        for item in cursor.iter() {
            let (key, value) =
                item.map_err(|e| DomError::Internal(format!("read utxo cursor: {e}")))?;
            out.insert(key.to_vec(), value.to_vec());
        }
        Ok(out)
    }

    /// Read the full persisted kernel index as raw key/value bytes.
    ///
    /// Tests and recovery checks use this to compare canonical kernel-index
    /// convergence without trusting any higher-level reconstruction first.
    pub fn read_all_kernel_index_raw(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        let mut cursor = txn
            .open_ro_cursor(self.db_kernels)
            .map_err(|e| DomError::Internal(format!("open kernel cursor: {e}")))?;
        let mut out = BTreeMap::new();
        for item in cursor.iter() {
            let (key, value) =
                item.map_err(|e| DomError::Internal(format!("read kernel cursor: {e}")))?;
            out.insert(key.to_vec(), value.to_vec());
        }
        Ok(out)
    }

    /// Read every persisted block header by hash.
    ///
    /// Includes canonical and retained non-canonical blocks. Used by
    /// deterministic side-chain retention on reopen / block ingest.
    pub fn read_all_block_headers_raw(&self) -> Result<BTreeMap<[u8; 32], Vec<u8>>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        let mut cursor = txn
            .open_ro_cursor(self.db_blocks)
            .map_err(|e| DomError::Internal(format!("open block cursor: {e}")))?;
        let mut out = BTreeMap::new();
        for item in cursor.iter() {
            let (key, value) =
                item.map_err(|e| DomError::Internal(format!("read block cursor: {e}")))?;
            if key.len() != 32 {
                return Err(DomError::Internal("corrupt block hash key".into()));
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(key);
            out.insert(hash, value.to_vec());
        }
        Ok(out)
    }

    /// Get the canonical block hash that first indexed a kernel excess.
    pub fn get_kernel_block(&self, excess: &[u8; 33]) -> Result<Option<[u8; 32]>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        match txn.get(self.db_kernels, excess) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(bytes);
                Ok(Some(h))
            }
            Ok(_) => Err(DomError::Internal("corrupt kernel index".into())),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(DomError::Internal(format!("get kernel: {e}"))),
        }
    }

    /// Record which kernel excess a transaction hash resolves through, at the
    /// moment this node admits the transaction to its own mempool.
    ///
    /// Ratified 2026-08-21 (F8_PLAN_AND_DECISIONS_RATIFICATION.md Q-3, signed) — Option A; see [`DB_TX_IDENTITY`].
    ///
    /// The same write transaction also sweeps expired entries — those admitted
    /// more than [`TX_IDENTITY_RETENTION_BLOCKS`] before `current_height`.
    /// Admissions are wallet-scale, the whole database is bounded by the
    /// retention rule to roughly one week of submissions, and a full cursor
    /// pass over it costs milliseconds, so the sweep runs on every put rather
    /// than on a schedule that could silently never fire.
    pub fn put_tx_identity(
        &self,
        tx_hash: &[u8; 32],
        excess: &[u8; 33],
        current_height: u64,
    ) -> Result<(), DomError> {
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| DomError::Internal(format!("rw txn: {e}")))?;
        let expired: Vec<[u8; 32]> = {
            let mut cursor = txn
                .open_ro_cursor(self.db_tx_identity)
                .map_err(|e| DomError::Internal(format!("tx_identity cursor: {e}")))?;
            cursor
                .iter_start()
                .filter_map(|entry| entry.ok())
                .filter_map(|(key, value)| {
                    if key.len() != 32 || value.len() != 41 {
                        return None; // tolerated: skipped here, surfaced on read
                    }
                    let mut admitted = [0u8; 8];
                    admitted.copy_from_slice(&value[33..41]);
                    let admitted = u64::from_le_bytes(admitted);
                    if admitted.saturating_add(TX_IDENTITY_RETENTION_BLOCKS) < current_height {
                        let mut k = [0u8; 32];
                        k.copy_from_slice(key);
                        Some(k)
                    } else {
                        None
                    }
                })
                .collect()
        };
        for key in &expired {
            match txn.del(self.db_tx_identity, key, None) {
                Ok(()) | Err(lmdb::Error::NotFound) => {}
                Err(e) => return Err(DomError::Internal(format!("tx_identity prune: {e}"))),
            }
        }
        let mut value = [0u8; 41];
        value[..33].copy_from_slice(excess);
        value[33..].copy_from_slice(&current_height.to_le_bytes());
        txn.put(self.db_tx_identity, tx_hash, &value, WriteFlags::empty())
            .map_err(|e| DomError::Internal(format!("put tx_identity: {e}")))?;
        txn.commit()
            .map_err(|e| DomError::Internal(format!("commit tx_identity: {e}")))?;
        Ok(())
    }

    /// Resolve a transaction hash this node admitted to its primary kernel
    /// excess and the admission height. `None` means this node never saw the
    /// transaction, or the entry aged out of the retention window — callers
    /// must not read `None` as "not on chain".
    pub fn get_tx_identity(&self, tx_hash: &[u8; 32]) -> Result<Option<([u8; 33], u64)>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        match txn.get(self.db_tx_identity, tx_hash) {
            Ok(bytes) if bytes.len() == 41 => {
                let mut excess = [0u8; 33];
                excess.copy_from_slice(&bytes[..33]);
                let mut admitted = [0u8; 8];
                admitted.copy_from_slice(&bytes[33..41]);
                Ok(Some((excess, u64::from_le_bytes(admitted))))
            }
            Ok(_) => Err(DomError::Internal("corrupt tx_identity entry".into())),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(DomError::Internal(format!("get tx_identity: {e}"))),
        }
    }

    /// Ensure kernel excess index entries exist and agree with `block_hash`.
    ///
    /// Used by recovery/reindex paths over already-committed canonical blocks.
    /// Missing entries are inserted; matching entries are left untouched; entries
    /// pointing at another block are treated as corruption or kernel replay.
    pub fn ensure_kernel_indices(
        &self,
        kernel_excesses: &[([u8; 33], [u8; 32])],
    ) -> Result<(), DomError> {
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| DomError::Internal(format!("rw txn: {e}")))?;

        for (excess, hash) in kernel_excesses {
            match txn.get(self.db_kernels, excess) {
                Ok(existing) if existing == hash => {}
                Ok(existing) if existing.len() == 32 => {
                    return Err(DomError::Internal(format!(
                        "KERNEL REPLAY DETECTED — excess already indexed to different block: excess={}, existing={}, new={}",
                        hex::encode(excess),
                        hex::encode(existing),
                        hex::encode(hash)
                    )));
                }
                Ok(_) => return Err(DomError::Internal("corrupt kernel index".into())),
                Err(lmdb::Error::NotFound) => {
                    txn.put(self.db_kernels, excess, hash, WriteFlags::NO_OVERWRITE)
                        .map_err(|e| DomError::Internal(format!("put kernel: {e}")))?;
                }
                Err(e) => return Err(DomError::Internal(format!("get kernel: {e}"))),
            }
        }

        txn.commit()
            .map_err(|e| DomError::Internal(format!("commit kernel index rebuild: {e}")))?;
        Ok(())
    }

    /// Atomically commit a validated block to storage.
    ///
    /// RFC-0007 step 14: ALL writes in ONE transaction.
    /// On any error the transaction is aborted — no partial state.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_block(
        &self,
        block_hash: &[u8; 32],
        block_height: u64,
        header_bytes: &[u8],
        block_body_bytes: &[u8],
        new_utxos: &[([u8; 33], Vec<u8>)], // (commitment, utxo_entry)
        spent_utxos: &[[u8; 33]],          // commitments to remove
        kernel_excesses: &[([u8; 33], [u8; 32])], // (excess, block_hash)
    ) -> Result<(), DomError> {
        self.commit_block_with_consensus_state(
            block_hash,
            block_height,
            header_bytes,
            block_body_bytes,
            new_utxos,
            spent_utxos,
            kernel_excesses,
            &[],
        )
    }

    /// Atomically commit a validated block and canonical extension-state batch.
    ///
    /// This is the only supported persistence boundary for future native USDOM
    /// transitions: block pointers, ordinary UTXOs/kernels, extension state,
    /// and any undo entries supplied in `consensus_updates` commit together or
    /// all abort. The storage layer checks resource bounds and duplicate keys;
    /// consensus code must validate the semantic transition before this call.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_block_with_consensus_state(
        &self,
        block_hash: &[u8; 32],
        block_height: u64,
        header_bytes: &[u8],
        block_body_bytes: &[u8],
        new_utxos: &[([u8; 33], Vec<u8>)],
        spent_utxos: &[[u8; 33]],
        kernel_excesses: &[([u8; 33], [u8; 32])],
        consensus_updates: &[ConsensusStateUpdate],
    ) -> Result<(), DomError> {
        validate_consensus_state_updates(consensus_updates)?;
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| DomError::Internal(format!("rw txn: {e}")))?;

        // Store block header.
        // DOM-LMDB-001: NO_OVERWRITE detects duplicates. connect_block's
        // ab82f89 early-return should prevent this from ever firing; if it
        // does, upstream dedup was bypassed (security-relevant).
        txn.put(
            self.db_blocks,
            block_hash,
            &header_bytes.to_vec(),
            WriteFlags::NO_OVERWRITE,
        )
        .map_err(|e| match e {
            lmdb::Error::KeyExist => DomError::Internal(format!(
                "block header already exists — connect_block dedup bypassed? hash={}",
                hex::encode(block_hash)
            )),
            other => DomError::Internal(format!("put block: {other}")),
        })?;

        // Store block body (full serialized block) for IBD responses.
        // DOM-LMDB-001: NO_OVERWRITE — block body is immutable by hash.
        txn.put(
            self.db_block_bodies,
            block_hash,
            &block_body_bytes.to_vec(),
            WriteFlags::NO_OVERWRITE,
        )
        .map_err(|e| match e {
            lmdb::Error::KeyExist => DomError::Internal(format!(
                "block body already exists — connect_block dedup bypassed? hash={}",
                hex::encode(block_hash)
            )),
            other => DomError::Internal(format!("put block body: {other}")),
        })?;

        // Store height → hash index
        let height_key = block_height.to_le_bytes();
        txn.put(self.db_height, &height_key, block_hash, WriteFlags::empty())
            .map_err(|e| DomError::Internal(format!("put height: {e}")))?;

        // Update chain tip
        txn.put(self.db_tip, b"tip", block_hash, WriteFlags::empty())
            .map_err(|e| DomError::Internal(format!("put tip: {e}")))?;

        // Add new UTXOs.
        // DOM-LMDB-001: NO_OVERWRITE — commitments must be unique. Duplicate
        // commitment means the same (value, blinding) pair was produced twice,
        // which would be a critical consensus bug (double output).
        for (commitment, entry) in new_utxos {
            txn.put(self.db_utxos, commitment, entry, WriteFlags::NO_OVERWRITE)
                .map_err(|e| match e {
                    lmdb::Error::KeyExist => DomError::Internal(format!(
                        "UTXO commitment already exists — consensus bug? commitment={}",
                        hex::encode(commitment)
                    )),
                    other => DomError::Internal(format!("put utxo: {other}")),
                })?;
        }

        // Remove spent UTXOs
        for commitment in spent_utxos {
            match txn.del(self.db_utxos, commitment, None) {
                Ok(()) => {}
                Err(lmdb::Error::NotFound) => {
                    return Err(DomError::Internal(format!(
                        "spent UTXO not found in canonical store — double-spend or missing input: commitment={}",
                        hex::encode(commitment)
                    )));
                }
                Err(e) => return Err(DomError::Internal(format!("del utxo: {e}"))),
            }
        }

        // Index kernels.
        // DOM-LMDB-001 — MOST CRITICAL of the NO_OVERWRITE conversions.
        // A duplicate kernel excess is the signature of a kernel-replay attack.
        // R-06: the consensus layer NOW rejects blocks containing previously-seen
        // kernels on BOTH connect paths — the reorg path in apply_connect and the
        // direct connect path in ChainState::connect_block both return
        // DomError::Invalid (ban-scored) before reaching commit_block. So for a
        // replay this NO_OVERWRITE branch should be unreachable; it stays as a
        // last-resort defense-in-depth guard. If we still get here with KeyExist,
        // either:
        //   - a consensus check has a bypass (security-critical bug)
        //   - the same block is being committed twice (caught by db_blocks
        //     check above first, so this is defense-in-depth)
        // Either way, loud-fail with explicit error.
        for (excess, hash) in kernel_excesses {
            txn.put(self.db_kernels, excess, hash, WriteFlags::NO_OVERWRITE)
                .map_err(|e| match e {
                    lmdb::Error::KeyExist => DomError::Internal(format!(
                        "KERNEL REPLAY DETECTED — excess already indexed (DOM-SEC critical): excess={}, block={}",
                        hex::encode(excess),
                        hex::encode(hash)
                    )),
                    other => DomError::Internal(format!("put kernel: {other}")),
                })?;
        }

        match txn.del(self.db_metadata, &METADATA_UTXO_SET_DIGEST_KEY, None) {
            Ok(()) | Err(lmdb::Error::NotFound) => {}
            Err(e) => return Err(DomError::Internal(format!("delete stale utxo digest: {e}"))),
        }

        apply_consensus_state_updates(&mut txn, self.db_consensus_state, consensus_updates)?;

        // Single atomic commit — if this fails nothing was written.
        // MDB_MAP_FULL is tagged with LMDB_MAP_FULL_SENTINEL so the
        // chain-init layer can recognise it without parsing free-form
        // error text.
        txn.commit().map_err(|e| match e {
            lmdb::Error::MapFull => DomError::Internal(format!(
                "{LMDB_MAP_FULL_SENTINEL}: map_size={} exhausted while committing block {} at height {block_height}",
                self.map_size,
                hex::encode(block_hash)
            )),
            other => DomError::Internal(format!("commit block: {other}")),
        })?;

        Ok(())
    }

    /// Persist an immutable, non-canonical block body by hash.
    ///
    /// This is for valid side-chain blocks that the node should remember for
    /// duplicate suppression and future reorg work, but that MUST NOT mutate
    /// canonical pointers (`chain_tip`, `block_height`) or canonical state
    /// (`utxos`, `kernel_index`). Those mutations are reserved for
    /// `commit_block` after the chain-selection path has determined the block
    /// is a canonical direct extension.
    pub fn store_known_block(
        &self,
        block_hash: &[u8; 32],
        header_bytes: &[u8],
        block_body_bytes: &[u8],
    ) -> Result<(), DomError> {
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| DomError::Internal(format!("rw txn: {e}")))?;

        txn.put(
            self.db_blocks,
            block_hash,
            &header_bytes.to_vec(),
            WriteFlags::NO_OVERWRITE,
        )
        .map_err(|e| match e {
            lmdb::Error::KeyExist => DomError::Internal(format!(
                "block header already exists — connect_block dedup bypassed? hash={}",
                hex::encode(block_hash)
            )),
            other => DomError::Internal(format!("put known block: {other}")),
        })?;

        txn.put(
            self.db_block_bodies,
            block_hash,
            &block_body_bytes.to_vec(),
            WriteFlags::NO_OVERWRITE,
        )
        .map_err(|e| match e {
            lmdb::Error::KeyExist => DomError::Internal(format!(
                "block body already exists — connect_block dedup bypassed? hash={}",
                hex::encode(block_hash)
            )),
            other => DomError::Internal(format!("put known block body: {other}")),
        })?;

        txn.commit()
            .map_err(|e| DomError::Internal(format!("commit known block: {e}")))?;

        Ok(())
    }

    /// Atomically retain a non-canonical block and its immutable extension
    /// sidecar without changing canonical pointers, UTXOs, kernels or extension
    /// state. A failure to write any one relation aborts all three writes.
    pub fn store_known_block_with_sidecar(
        &self,
        block_hash: &[u8; 32],
        header_bytes: &[u8],
        block_body_bytes: &[u8],
        sidecar_bytes: &[u8],
    ) -> Result<(), DomError> {
        if sidecar_bytes.is_empty() || sidecar_bytes.len() > MAX_BLOCK_SERIALIZED_SIZE {
            return Err(DomError::Invalid(format!(
                "invalid block sidecar length {}",
                sidecar_bytes.len()
            )));
        }
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| DomError::Internal(format!("rw txn: {e}")))?;
        txn.put(
            self.db_blocks,
            block_hash,
            &header_bytes.to_vec(),
            WriteFlags::NO_OVERWRITE,
        )
        .map_err(|e| match e {
            lmdb::Error::KeyExist => DomError::Internal(format!(
                "sidecar block header already exists: {}",
                hex::encode(block_hash)
            )),
            other => DomError::Internal(format!("put sidecar block: {other}")),
        })?;
        txn.put(
            self.db_block_bodies,
            block_hash,
            &block_body_bytes.to_vec(),
            WriteFlags::NO_OVERWRITE,
        )
        .map_err(|e| match e {
            lmdb::Error::KeyExist => DomError::Internal(format!(
                "sidecar block body already exists: {}",
                hex::encode(block_hash)
            )),
            other => DomError::Internal(format!("put sidecar block body: {other}")),
        })?;
        txn.put(
            self.db_block_sidecars,
            block_hash,
            &sidecar_bytes.to_vec(),
            WriteFlags::NO_OVERWRITE,
        )
        .map_err(|e| match e {
            lmdb::Error::KeyExist => DomError::Internal(format!(
                "block sidecar already exists: {}",
                hex::encode(block_hash)
            )),
            other => DomError::Internal(format!("put block sidecar: {other}")),
        })?;
        txn.commit()
            .map_err(|e| DomError::Internal(format!("commit sidecar block: {e}")))?;
        Ok(())
    }

    /// Atomically rewrite canonical chain pointers and touched state for a reorg.
    ///
    /// `height_updates` lists the final canonical occupant (or absence) for every
    /// touched height. `utxo_updates` and `kernel_updates` likewise describe the
    /// final desired state for each touched key after the reorg completes.
    ///
    /// Block headers / bodies are assumed to have been persisted already via
    /// `commit_block` (canonical) or `store_known_block` (side-chain retention).
    #[allow(clippy::type_complexity)]
    pub fn apply_reorg(
        &self,
        new_tip_hash: &[u8; 32],
        height_updates: &[(u64, Option<[u8; 32]>)],
        utxo_updates: &[([u8; 33], Option<Vec<u8>>)],
        kernel_updates: &[([u8; 33], Option<[u8; 32]>)],
    ) -> Result<(), DomError> {
        self.apply_reorg_with_consensus_state(
            new_tip_hash,
            height_updates,
            utxo_updates,
            kernel_updates,
            &[],
        )
    }

    /// Atomically apply a canonical reorganization and extension-state batch.
    ///
    /// Native protocol extensions must compute the final desired key/value
    /// state for the whole disconnect/connect sequence before calling this API.
    /// The chain tip, height index, UTXOs, kernels, extension state, and undo
    /// entries then change in one LMDB transaction.
    #[allow(clippy::type_complexity)]
    pub fn apply_reorg_with_consensus_state(
        &self,
        new_tip_hash: &[u8; 32],
        height_updates: &[(u64, Option<[u8; 32]>)],
        utxo_updates: &[([u8; 33], Option<Vec<u8>>)],
        kernel_updates: &[([u8; 33], Option<[u8; 32]>)],
        consensus_updates: &[ConsensusStateUpdate],
    ) -> Result<(), DomError> {
        self.apply_reorg_with_consensus_state_and_sidecars(
            new_tip_hash,
            height_updates,
            utxo_updates,
            kernel_updates,
            consensus_updates,
            &[],
        )
    }

    /// Atomically apply a canonical reorganization, extension-state batch and
    /// immutable sidecars for blocks leaving the canonical branch.
    ///
    /// Sidecars are accepted only for already-known header/body pairs. An
    /// existing byte-identical sidecar is idempotent; substitution aborts the
    /// entire transaction before any canonical pointer or state can change.
    #[allow(clippy::type_complexity)]
    pub fn apply_reorg_with_consensus_state_and_sidecars(
        &self,
        new_tip_hash: &[u8; 32],
        height_updates: &[(u64, Option<[u8; 32]>)],
        utxo_updates: &[([u8; 33], Option<Vec<u8>>)],
        kernel_updates: &[([u8; 33], Option<[u8; 32]>)],
        consensus_updates: &[ConsensusStateUpdate],
        sidecar_inserts: &[([u8; 32], Vec<u8>)],
    ) -> Result<(), DomError> {
        validate_consensus_state_updates(consensus_updates)?;
        let mut sidecar_hashes = BTreeSet::new();
        let mut sidecar_bytes_total = 0usize;
        for (block_hash, sidecar) in sidecar_inserts {
            if sidecar.is_empty() || sidecar.len() > MAX_BLOCK_SERIALIZED_SIZE {
                return Err(DomError::Invalid(format!(
                    "invalid reorg sidecar length {} for {}",
                    sidecar.len(),
                    hex::encode(block_hash)
                )));
            }
            if !sidecar_hashes.insert(*block_hash) {
                return Err(DomError::Invalid(
                    "duplicate block hash in reorg sidecar batch".into(),
                ));
            }
            sidecar_bytes_total = sidecar_bytes_total
                .checked_add(sidecar.len())
                .ok_or_else(|| DomError::Invalid("reorg sidecar byte total overflow".into()))?;
            if sidecar_bytes_total > MAX_CONSENSUS_STATE_BATCH_BYTES {
                return Err(DomError::Invalid(format!(
                    "reorg sidecar bytes {sidecar_bytes_total} > {MAX_CONSENSUS_STATE_BATCH_BYTES}"
                )));
            }
        }
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| DomError::Internal(format!("rw txn: {e}")))?;

        for (block_hash, sidecar) in sidecar_inserts {
            txn.get(self.db_blocks, block_hash)
                .map_err(|error| match error {
                    lmdb::Error::NotFound => DomError::Internal(format!(
                        "reorg sidecar header is missing: {}",
                        hex::encode(block_hash)
                    )),
                    other => DomError::Internal(format!("get reorg sidecar header: {other}")),
                })?;
            txn.get(self.db_block_bodies, block_hash)
                .map_err(|error| match error {
                    lmdb::Error::NotFound => DomError::Internal(format!(
                        "reorg sidecar body is missing: {}",
                        hex::encode(block_hash)
                    )),
                    other => DomError::Internal(format!("get reorg sidecar body: {other}")),
                })?;
            match txn.get(self.db_block_sidecars, block_hash) {
                Ok(existing) if existing == sidecar.as_slice() => {}
                Ok(_) => {
                    return Err(DomError::Internal(format!(
                        "reorg sidecar substitution for {}",
                        hex::encode(block_hash)
                    )));
                }
                Err(lmdb::Error::NotFound) => txn
                    .put(
                        self.db_block_sidecars,
                        block_hash,
                        sidecar,
                        WriteFlags::NO_OVERWRITE,
                    )
                    .map_err(|error| DomError::Internal(format!("put reorg sidecar: {error}")))?,
                Err(error) => {
                    return Err(DomError::Internal(format!("get reorg sidecar: {error}")));
                }
            }
        }

        for (height, maybe_hash) in height_updates {
            let key = height.to_le_bytes();
            match maybe_hash {
                Some(hash) => txn
                    .put(self.db_height, &key, hash, WriteFlags::empty())
                    .map_err(|e| DomError::Internal(format!("put reorg height: {e}")))?,
                None => match txn.del(self.db_height, &key, None) {
                    Ok(()) | Err(lmdb::Error::NotFound) => {}
                    Err(e) => {
                        return Err(DomError::Internal(format!("del reorg height: {e}")));
                    }
                },
            }
        }

        for (commitment, maybe_entry) in utxo_updates {
            match maybe_entry {
                Some(entry) => match txn.get(self.db_utxos, commitment) {
                    Ok(existing) if existing == entry.as_slice() => {}
                    Ok(_) => {
                        // A2-001: build_utxo_updates only emits a Some-update
                        // for an existing commitment after confirming it is an
                        // approved re-homing (same proof and is_coinbase,
                        // differing only in block_height). Execute the overwrite;
                        // the identity check that matters happened upstream. This
                        // path is reorg-only — commit_block keeps NO_OVERWRITE.
                        txn.put(self.db_utxos, commitment, entry, WriteFlags::empty())
                            .map_err(|e| {
                                DomError::Internal(format!("put reorg utxo (rehome): {e}"))
                            })?;
                    }
                    Err(lmdb::Error::NotFound) => txn
                        .put(self.db_utxos, commitment, entry, WriteFlags::NO_OVERWRITE)
                        .map_err(|e| DomError::Internal(format!("put reorg utxo: {e}")))?,
                    Err(e) => return Err(DomError::Internal(format!("get reorg utxo: {e}"))),
                },
                None => match txn.del(self.db_utxos, commitment, None) {
                    Ok(()) | Err(lmdb::Error::NotFound) => {}
                    Err(e) => {
                        return Err(DomError::Internal(format!("del reorg utxo: {e}")));
                    }
                },
            }
        }

        for (excess, maybe_hash) in kernel_updates {
            match maybe_hash {
                Some(hash) => match txn.get(self.db_kernels, excess) {
                    Ok(existing) if existing == hash => {}
                    Ok(_) => {
                        // A2-001: apply_connect's anti-replay guard already
                        // validated this kernel migration — apply_disconnect
                        // released the excess and apply_connect re-admitted it
                        // past the replay check. Execute the re-homing to the new
                        // block hash. Reorg-only; commit_block keeps NO_OVERWRITE.
                        txn.put(self.db_kernels, excess, hash, WriteFlags::empty())
                            .map_err(|e| {
                                DomError::Internal(format!("put reorg kernel (rehome): {e}"))
                            })?;
                    }
                    Err(lmdb::Error::NotFound) => txn
                        .put(self.db_kernels, excess, hash, WriteFlags::NO_OVERWRITE)
                        .map_err(|e| DomError::Internal(format!("put reorg kernel: {e}")))?,
                    Err(e) => return Err(DomError::Internal(format!("get reorg kernel: {e}"))),
                },
                None => match txn.del(self.db_kernels, excess, None) {
                    Ok(()) | Err(lmdb::Error::NotFound) => {}
                    Err(e) => {
                        return Err(DomError::Internal(format!("del reorg kernel: {e}")));
                    }
                },
            }
        }

        txn.put(self.db_tip, b"tip", new_tip_hash, WriteFlags::empty())
            .map_err(|e| DomError::Internal(format!("put reorg tip: {e}")))?;

        match txn.del(self.db_metadata, &METADATA_UTXO_SET_DIGEST_KEY, None) {
            Ok(()) | Err(lmdb::Error::NotFound) => {}
            Err(e) => return Err(DomError::Internal(format!("delete stale utxo digest: {e}"))),
        }

        apply_consensus_state_updates(&mut txn, self.db_consensus_state, consensus_updates)?;

        txn.commit()
            .map_err(|e| DomError::Internal(format!("commit reorg: {e}")))?;
        Ok(())
    }

    /// Atomically replace the entire canonical UTXO database and persist the
    /// digest that corresponds to the replacement contents.
    pub fn replace_utxo_set(
        &self,
        utxos: &BTreeMap<[u8; 33], Vec<u8>>,
        digest: &[u8; 32],
    ) -> Result<(), DomError> {
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| DomError::Internal(format!("rw txn: {e}")))?;
        txn.clear_db(self.db_utxos)
            .map_err(|e| DomError::Internal(format!("clear utxos: {e}")))?;
        for (commitment, entry) in utxos {
            txn.put(self.db_utxos, commitment, entry, WriteFlags::NO_OVERWRITE)
                .map_err(|e| DomError::Internal(format!("rewrite utxo: {e}")))?;
        }
        txn.put(
            self.db_metadata,
            &METADATA_UTXO_SET_DIGEST_KEY,
            digest,
            WriteFlags::empty(),
        )
        .map_err(|e| DomError::Internal(format!("put utxo digest: {e}")))?;
        txn.commit()
            .map_err(|e| DomError::Internal(format!("commit utxo rewrite: {e}")))?;
        Ok(())
    }

    /// Persist the digest for the currently-verified canonical UTXO set.
    pub fn persist_utxo_set_digest(&self, digest: &[u8; 32]) -> Result<(), DomError> {
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| DomError::Internal(format!("rw txn: {e}")))?;
        txn.put(
            self.db_metadata,
            &METADATA_UTXO_SET_DIGEST_KEY,
            digest,
            WriteFlags::empty(),
        )
        .map_err(|e| DomError::Internal(format!("put utxo digest: {e}")))?;
        txn.commit()
            .map_err(|e| DomError::Internal(format!("commit utxo digest: {e}")))?;
        Ok(())
    }

    /// Delete retained non-canonical blocks by hash.
    ///
    /// Canonical callers must never pass hashes that remain referenced by
    /// `chain_tip` / `block_height`. This deletes both the header and body so
    /// retained side-chain storage stays bounded.
    pub fn prune_known_blocks(&self, prune_hashes: &BTreeSet<[u8; 32]>) -> Result<(), DomError> {
        if prune_hashes.is_empty() {
            return Ok(());
        }

        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| DomError::Internal(format!("rw txn: {e}")))?;

        for hash in prune_hashes {
            match txn.del(self.db_blocks, hash, None) {
                Ok(()) | Err(lmdb::Error::NotFound) => {}
                Err(e) => return Err(DomError::Internal(format!("delete pruned block: {e}"))),
            }
            match txn.del(self.db_block_bodies, hash, None) {
                Ok(()) | Err(lmdb::Error::NotFound) => {}
                Err(e) => {
                    return Err(DomError::Internal(format!("delete pruned block body: {e}")));
                }
            }
            match txn.del(self.db_block_sidecars, hash, None) {
                Ok(()) | Err(lmdb::Error::NotFound) => {}
                Err(e) => {
                    return Err(DomError::Internal(format!(
                        "delete pruned block sidecar: {e}"
                    )));
                }
            }
        }

        txn.commit()
            .map_err(|e| DomError::Internal(format!("commit pruned blocks: {e}")))?;
        Ok(())
    }
}
