//! Isolated Ethereum finality experiment through the Fulu mainnet fork.
//! NOT a production Ethereum light client.
//! The caller must independently trust the bootstrap checkpoint and network parameters.
//! There is no timeout promotion, arbitrary store import, RPC, mint, or DOM integration.

#[cfg(all(feature = "unsafe-test-oracle", not(debug_assertions)))]
compile_error!("unsafe-test-oracle is forbidden in release builds");

use alloy::primitives::{keccak256, B256};
use eyre::{ensure, Result};
use helios_consensus_core::{
    apply_bootstrap, apply_generic_update,
    consensus_spec::{ConsensusSpec, MainnetConsensusSpec},
    get_bits,
    types::{Bootstrap, Forks, GenericUpdate, LightClientHeader, LightClientStore},
    verify_bootstrap, verify_generic_update,
};
use serde::{Deserialize, Serialize};
use tree_hash::TreeHash;

pub use helios_consensus_core::types::{Fork as EthereumFork, Forks as EthereumForks};

pub mod ancestry;
pub mod checkpoints;
pub mod deposits;
pub mod receipts;
pub mod state;

type Spec = MainnetConsensusSpec;
const MAX_RETAINED_FINALIZED_HEADERS: usize = 4096;
const MAX_TRANSCRIPT_BYTES: usize = 64 * 1024 * 1024;
const MAX_UPDATE_BYTES: usize = 2 * 1024 * 1024;
const MAX_TRANSCRIPT_UPDATES: usize = 4096;
const TRANSCRIPT_VERSION: u8 = 1;
const TRANSCRIPT_ENVELOPE_BYTES: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedUpdate {
    current_slot: u64,
    update: GenericUpdate<Spec>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientTranscript {
    version: u8,
    bootstrap: serde_json::Value,
    updates: Vec<AcceptedUpdate>,
}

/// Only the finalized execution header's own roots are exposed. An earlier Ethereum
/// receipt needs a separate authenticated ancestry proof; block numbers are insufficient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedExecution {
    pub beacon_slot: u64,
    pub beacon_root: B256,
    pub block_number: u64,
    pub block_hash: B256,
    /// Timestamp authenticated inside the execution payload/header.
    pub timestamp: u64,
    pub receipts_root: B256,
    pub state_root: B256,
}

/// Private state prevents importing a store that previously used force_update.
/// This is not a weak-subjectivity, freshness, persistence, or full-consensus solution.
pub struct EthereumFinalityClient {
    store: LightClientStore<Spec>,
    /// Last execution view extracted through the fallible supported-fork
    /// boundary. Keeping it explicitly avoids re-entering that boundary from
    /// the infallible public accessor.
    current_finalized: FinalizedExecution,
    genesis_root: B256,
    forks: Forks,
    /// Authenticated views only. Capacity exhaustion stops advancement rather
    /// than silently deleting evidence needed for deterministic history replay.
    finalized_history: Vec<FinalizedExecution>,
    bootstrap_json: serde_json::Value,
    accepted_updates: Vec<AcceptedUpdate>,
    accepted_update_ids: Vec<B256>,
    transcript_bytes: usize,
}

impl EthereumFinalityClient {
    pub fn bootstrap(
        bootstrap: &Bootstrap<Spec>,
        trusted_checkpoint: B256,
        genesis_root: B256,
        forks: Forks,
    ) -> Result<Self> {
        ensure!(
            !trusted_checkpoint.is_zero() && !genesis_root.is_zero(),
            "zero trust anchor"
        );
        check_header(&bootstrap.header(), &forks)?;
        verify_bootstrap(bootstrap, trusted_checkpoint, &forks)?;
        let bootstrap_json = serde_json::to_value(bootstrap)?;
        let bootstrap_bytes = serde_json::to_vec(&bootstrap_json)?.len();
        let transcript_bytes = bootstrap_bytes
            .checked_add(TRANSCRIPT_ENVELOPE_BYTES)
            .ok_or_else(|| eyre::eyre!("bootstrap transcript size overflow"))?;
        ensure!(
            transcript_bytes <= MAX_TRANSCRIPT_BYTES,
            "bootstrap transcript size"
        );
        let mut store = LightClientStore::default();
        apply_bootstrap(&mut store, bootstrap);
        let initial = execution_view(&store.finalized_header)?;
        Ok(Self {
            store,
            current_finalized: initial.clone(),
            genesis_root,
            forks,
            finalized_history: vec![initial],
            bootstrap_json,
            accepted_updates: vec![],
            accepted_update_ids: vec![],
            transcript_bytes,
        })
    }

    /// `current_slot` is a deterministic test input, not authenticated wall-clock time.
    /// Production needs a consensus rule for time, update age, and bootstrap freshness.
    /// A historical finality update may teach a missing next committee without rewinding
    /// the finalized view. All validation precedes an atomic in-memory state replacement.
    pub fn accept(&mut self, update: &GenericUpdate<Spec>, current_slot: u64) -> Result<()> {
        let update_bytes = serde_json::to_vec(update)?;
        ensure!(
            update_bytes.len() <= MAX_UPDATE_BYTES,
            "update transcript size"
        );
        let update_id = keccak256(&update_bytes);
        if self.accepted_update_ids.contains(&update_id) {
            return Ok(());
        }
        ensure!(
            self.accepted_updates.len() < MAX_TRANSCRIPT_UPDATES,
            "transcript update count"
        );
        let record = AcceptedUpdate {
            current_slot,
            update: update.clone(),
        };
        let record_bytes = serde_json::to_vec(&record)?.len();
        let next_transcript_bytes = self
            .transcript_bytes
            .checked_add(record_bytes + 1)
            .ok_or_else(|| eyre::eyre!("transcript size overflow"))?;
        ensure!(
            next_transcript_bytes <= MAX_TRANSCRIPT_BYTES,
            "transcript byte limit"
        );
        let finalized = update
            .finalized_header
            .as_ref()
            .ok_or_else(|| eyre::eyre!("finality header required"))?;
        ensure!(update.finality_branch.is_some(), "finality branch required");
        ensure!(
            get_bits::<Spec>(&update.sync_aggregate.sync_committee_bits) * 3
                >= Spec::sync_committee_size() * 2,
            "supermajority required"
        );
        check_header(&update.attested_header, &self.forks)?;
        check_header(finalized, &self.forks)?;
        ensure!(
            update.signature_slot / Spec::slots_per_epoch() < self.forks.gloas.epoch,
            "Gloas signatures are not supported"
        );
        verify_generic_update(
            update,
            current_slot,
            &self.store,
            self.genesis_root,
            &self.forks,
        )?;
        let before = self.finalized();
        ensure!(
            finalized.beacon().slot != before.beacon_slot
                || finalized.beacon().tree_hash_root() == before.beacon_root,
            "conflicting finalized header at current slot"
        );
        let mut candidate = self.store.clone();
        apply_generic_update(&mut candidate, update);
        let after = execution_view(&candidate.finalized_header)?;
        ensure!(after.beacon_slot >= before.beacon_slot, "finality rollback");
        ensure!(
            after.beacon_slot != before.beacon_slot || after == before,
            "finality conflict"
        );
        let retain = self.finalized_history.last() != Some(&after);
        if retain {
            ensure!(
                self.finalized_history.len() < MAX_RETAINED_FINALIZED_HEADERS,
                "finalized header retention capacity"
            );
        }
        self.store = candidate;
        self.current_finalized = after.clone();
        if retain {
            self.finalized_history.push(after);
        }
        self.accepted_updates.push(record);
        self.accepted_update_ids.push(update_id);
        self.transcript_bytes = next_transcript_bytes;
        Ok(())
    }

    pub fn finalized(&self) -> FinalizedExecution {
        self.current_finalized.clone()
    }

    pub fn retained_finalized_headers(&self) -> usize {
        self.finalized_history.len()
    }

    /// Export only data that will be fully revalidated during restoration.
    pub fn export_transcript(&self) -> Result<Vec<u8>> {
        let transcript = ClientTranscript {
            version: TRANSCRIPT_VERSION,
            bootstrap: self.bootstrap_json.clone(),
            updates: self.accepted_updates.clone(),
        };
        let bytes = serde_json::to_vec(&transcript)?;
        ensure!(bytes.len() <= MAX_TRANSCRIPT_BYTES, "transcript byte limit");
        Ok(bytes)
    }

    /// Rebuild from an externally trusted checkpoint/configuration and require
    /// the exact externally committed final view. Truncation cannot roll back the
    /// caller's minimum because every bootstrap/update is verified again first.
    pub fn restore_transcript(
        bytes: &[u8],
        trusted_checkpoint: B256,
        genesis_root: B256,
        forks: Forks,
        expected_finalized: &FinalizedExecution,
    ) -> Result<Self> {
        Self::restore_transcript_bounded(
            bytes,
            trusted_checkpoint,
            genesis_root,
            forks,
            expected_finalized,
            u64::MAX,
        )
    }

    /// Rebuild a canonical transcript while bounding every caller-recorded
    /// `current_slot` by a slot derived outside the witness. Consensus callers
    /// must use this path so a relayer cannot authorize future-dated updates by
    /// selecting its own notion of Ethereum time.
    pub fn restore_transcript_bounded(
        bytes: &[u8],
        trusted_checkpoint: B256,
        genesis_root: B256,
        forks: Forks,
        expected_finalized: &FinalizedExecution,
        max_current_slot: u64,
    ) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_TRANSCRIPT_BYTES,
            "transcript byte limit"
        );
        let transcript: ClientTranscript = serde_json::from_slice(bytes)?;
        ensure!(
            transcript.version == TRANSCRIPT_VERSION
                && transcript.updates.len() <= MAX_TRANSCRIPT_UPDATES,
            "transcript format"
        );
        let bootstrap: Bootstrap<Spec> = serde_json::from_value(transcript.bootstrap)?;
        let mut client = Self::bootstrap(&bootstrap, trusted_checkpoint, genesis_root, forks)?;
        for accepted in transcript.updates {
            ensure!(
                accepted.current_slot <= max_current_slot,
                "transcript current slot exceeds consensus limit"
            );
            let before = client.accepted_updates.len();
            client.accept(&accepted.update, accepted.current_slot)?;
            ensure!(
                client.accepted_updates.len() == before + 1,
                "duplicate transcript update"
            );
        }
        ensure!(
            &client.finalized() == expected_finalized,
            "transcript finalized view mismatch"
        );
        ensure!(
            client.export_transcript()?.as_slice() == bytes,
            "noncanonical transcript encoding"
        );
        Ok(client)
    }

    pub(crate) fn finalized_execution(
        &self,
        block_hash: B256,
        block_number: u64,
    ) -> Result<&FinalizedExecution> {
        self.finalized_history
            .iter()
            .find(|header| header.block_hash == block_hash && header.block_number == block_number)
            .ok_or_else(|| eyre::eyre!("execution block is not a retained finalized header"))
    }
}

/// Return the minimal deterministic clock ceiling required to replay a
/// canonical proof transcript. Proof witnesses do not receive authority to
/// choose a later wall-clock slot: every accepted update must record its own
/// authenticated signature slot exactly.
pub(crate) fn canonical_transcript_replay_slot(bytes: &[u8]) -> Result<u64> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_TRANSCRIPT_BYTES,
        "transcript byte limit"
    );
    let transcript: ClientTranscript = serde_json::from_slice(bytes)?;
    ensure!(
        transcript.version == TRANSCRIPT_VERSION
            && transcript.updates.len() <= MAX_TRANSCRIPT_UPDATES,
        "transcript format"
    );
    let bootstrap: Bootstrap<Spec> = serde_json::from_value(transcript.bootstrap)?;
    let mut replay_slot = bootstrap.header().beacon().slot;
    ensure!(replay_slot != 0, "zero bootstrap slot");
    for accepted in transcript.updates {
        ensure!(
            accepted.current_slot == accepted.update.signature_slot,
            "noncanonical transcript replay slot"
        );
        replay_slot = replay_slot.max(accepted.current_slot);
    }
    Ok(replay_slot)
}

/// Compatibility alias for earlier experiment consumers.
pub type HistoricalCapellaClient = EthereumFinalityClient;

fn check_header(header: &LightClientHeader, forks: &Forks) -> Result<()> {
    let epoch = header.beacon().slot / Spec::slots_per_epoch();
    // Capella through Fulu share the same outer light-client header fields.
    // The upstream enum is deliberately untagged and may deserialize any of
    // those wire-equivalent shapes as Capella. The authenticated epoch selects
    // the signature domain, while the execution enum and Merkle proof bind the
    // fork-specific execution payload fields.
    let supported = epoch >= forks.capella.epoch
        && epoch < forks.gloas.epoch
        && matches!(
            header,
            LightClientHeader::Capella(_)
                | LightClientHeader::Deneb(_)
                | LightClientHeader::Electra(_)
        );
    ensure!(supported, "unsupported light-client header fork");
    Ok(())
}

fn execution_view(header: &LightClientHeader) -> Result<FinalizedExecution> {
    let (beacon, execution) = match header {
        LightClientHeader::Capella(h) => (&h.beacon, &h.execution),
        LightClientHeader::Deneb(h) => (&h.beacon, &h.execution),
        LightClientHeader::Electra(h) => (&h.beacon, &h.execution),
        LightClientHeader::Bellatrix(_) | LightClientHeader::Gloas(_) => {
            return Err(eyre::eyre!(
                "unsupported finalized header without an execution-root view"
            ));
        }
    };
    Ok(FinalizedExecution {
        beacon_slot: beacon.slot,
        beacon_root: beacon.tree_hash_root(),
        block_number: *execution.block_number(),
        block_hash: *execution.block_hash(),
        timestamp: *execution.timestamp(),
        receipts_root: *execution.receipts_root(),
        state_root: *execution.state_root(),
    })
}

pub(crate) fn read_u32_be(bytes: &[u8], offset: usize, label: &'static str) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| eyre::eyre!("{label} offset overflow"))?;
    let word: [u8; 4] = bytes
        .get(offset..end)
        .ok_or_else(|| eyre::eyre!("truncated {label}"))?
        .try_into()
        .map_err(|_| eyre::eyre!("invalid {label} width"))?;
    Ok(u32::from_be_bytes(word))
}

pub(crate) fn read_u64_be(bytes: &[u8], offset: usize, label: &'static str) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| eyre::eyre!("{label} offset overflow"))?;
    let word: [u8; 8] = bytes
        .get(offset..end)
        .ok_or_else(|| eyre::eyre!("truncated {label}"))?
        .try_into()
        .map_err(|_| eyre::eyre!("invalid {label} width"))?;
    Ok(u64::from_be_bytes(word))
}
