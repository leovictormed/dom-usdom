//! Ethereum light-client verification through the Fulu mainnet fork.
//! The bootstrap checkpoint and network parameters remain immutable protocol
//! trust inputs. Canonical transcripts bind their replay clock to authenticated
//! signature slots, reject clock rollback/future ceilings, and require a recent
//! bootstrap before they can become native USDOM evidence.

#[cfg(all(feature = "unsafe-test-oracle", not(debug_assertions)))]
compile_error!("unsafe-test-oracle is forbidden in release builds");

use alloy::primitives::{keccak256, B256};
use eyre::{ensure, Result};
use helios_consensus_core::{
    apply_bootstrap, apply_generic_update,
    consensus_spec::{ConsensusSpec, MainnetConsensusSpec},
    get_bits,
    types::{
        Bootstrap, FinalityUpdate, Forks, GenericUpdate, LightClientHeader, LightClientStore,
        Update,
    },
    verify_bootstrap, verify_generic_update,
};
use serde::{Deserialize, Serialize};
use tree_hash::TreeHash;

pub use helios_consensus_core::types::{Fork as EthereumFork, Forks as EthereumForks};

pub mod ancestry;
pub mod checkpoints;
pub mod closures;
pub mod deposits;
pub mod receipts;
pub mod state;

type Spec = MainnetConsensusSpec;
const MAX_RETAINED_FINALIZED_HEADERS: usize = 4096;
const MAX_EVIDENCE_JSON_DEPTH: usize = 32;
const MAX_EVIDENCE_JSON_TOKENS: usize = 16_384;
// Opening/closing quotes plus the `0x` prefix around a maximum-size byte node.
const MAX_EVIDENCE_JSON_STRING_BYTES: usize = 2 * 256 * 1024 + 4;

/// Zero-allocation preflight for hostile evidence JSON. Semantic proof limits
/// are checked after decoding, but this gate runs first so serde cannot amplify
/// a bounded wire payload into unbounded vectors/strings or excessive nesting.
pub(crate) fn preflight_evidence_json(bytes: &[u8]) -> eyre::Result<()> {
    preflight_json(
        bytes,
        MAX_EVIDENCE_JSON_DEPTH,
        MAX_EVIDENCE_JSON_TOKENS,
        MAX_EVIDENCE_JSON_STRING_BYTES,
    )
}

pub(crate) fn preflight_transcript_json(bytes: &[u8]) -> eyre::Result<()> {
    preflight_json(bytes, 64, 512 * 1024, MAX_UPDATE_BYTES + 2)?;
    eyre::ensure!(
        bytes
            .windows(b"\"current_slot\":".len())
            .filter(|window| *window == b"\"current_slot\":")
            .count()
            <= MAX_TRANSCRIPT_UPDATES,
        "transcript update count"
    );
    Ok(())
}

fn preflight_json(
    bytes: &[u8],
    max_depth: usize,
    max_tokens: usize,
    max_string_bytes: usize,
) -> eyre::Result<()> {
    let mut depth = 0usize;
    let mut tokens = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'{' | b'[' => {
                depth = depth
                    .checked_add(1)
                    .ok_or_else(|| eyre::eyre!("evidence JSON depth overflow"))?;
                eyre::ensure!(depth <= max_depth, "JSON depth limit");
                tokens += 1;
                index += 1;
            }
            b'}' | b']' => {
                eyre::ensure!(depth != 0, "unbalanced evidence JSON");
                depth -= 1;
                index += 1;
            }
            b'"' => {
                let start = index;
                index += 1;
                let mut escaped = false;
                let mut terminated = false;
                while index < bytes.len() {
                    let byte = bytes[index];
                    index += 1;
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == b'"' {
                        terminated = true;
                        break;
                    }
                    eyre::ensure!(index - start <= max_string_bytes, "JSON string byte limit");
                }
                eyre::ensure!(terminated, "unterminated JSON string");
                tokens += 1;
            }
            b',' | b':' | b' ' | b'\n' | b'\r' | b'\t' => index += 1,
            _ => {
                tokens += 1;
                while index < bytes.len()
                    && !matches!(
                        bytes[index],
                        b',' | b':' | b']' | b'}' | b' ' | b'\n' | b'\r' | b'\t'
                    )
                {
                    index += 1;
                }
            }
        }
        eyre::ensure!(tokens <= max_tokens, "JSON token limit");
    }
    eyre::ensure!(depth == 0, "unbalanced evidence JSON");
    Ok(())
}
const MAX_TRANSCRIPT_BYTES: usize = 64 * 1024 * 1024;
const MAX_UPDATE_BYTES: usize = 2 * 1024 * 1024;
const MAX_TRANSCRIPT_UPDATES: usize = 4096;
const TRANSCRIPT_VERSION: u8 = 1;
const TRANSCRIPT_ENVELOPE_BYTES: usize = 128;
/// Fourteen days at Ethereum's twelve-second slot cadence. This is a
/// deliberately conservative weak-subjectivity operating horizon: production
/// release configuration must rotate the trusted checkpoint before it expires.
pub const MAX_TRUSTED_BOOTSTRAP_AGE_SLOTS: u64 = 14 * 24 * 60 * 60 / 12;

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
/// Native consensus supplies the upper slot/time boundary; this client enforces
/// canonical authenticated replay and a bounded weak-subjectivity bootstrap age.
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
    latest_replay_slot: u64,
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
        validate_fork_schedule(&forks)?;
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
        let bootstrap_slot = bootstrap.header().beacon().slot;
        ensure!(bootstrap_slot != 0, "zero bootstrap slot");
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
            // A trusted bootstrap can be newer than the first update needed to
            // learn the committee that bridges into its period. Permit only
            // that bounded historical prefix; once one update is accepted the
            // replay cursor remains strictly monotonic across the transcript.
            latest_replay_slot: bootstrap_slot.saturating_sub(MAX_TRUSTED_BOOTSTRAP_AGE_SLOTS),
        })
    }

    /// The recorded replay slot is derived from the update's authenticated
    /// signature slot and cannot move backwards. A containing consensus object
    /// supplies the final future-slot ceiling when restoring the transcript.
    /// A historical finality update may teach a missing next committee without rewinding
    /// the finalized view. All validation precedes an atomic in-memory state replacement.
    pub fn accept(&mut self, update: &GenericUpdate<Spec>) -> Result<()> {
        let current_slot = update.signature_slot;
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
            current_slot >= self.latest_replay_slot,
            "transcript replay slot rollback"
        );
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
        self.latest_replay_slot = current_slot;
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

    /// Rebuild a canonical transcript while bounding every authenticated
    /// signature slot by a ceiling derived outside the witness. Consensus
    /// callers use this path so a relayer cannot authorize future-dated updates.
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
        // Reject alternate JSON spellings before any BLS/Merkle verification.
        // Besides making the witness commitment unambiguous, this prevents a
        // relayer from spending consensus verification work on whitespace,
        // reordered members, or duplicate-member encodings that are certain to
        // fail the canonical re-export check at the end of this function.
        let transcript = decode_canonical_transcript(bytes)?;
        ensure!(
            transcript.version == TRANSCRIPT_VERSION
                && transcript.updates.len() <= MAX_TRANSCRIPT_UPDATES,
            "transcript format"
        );
        let bootstrap: Bootstrap<Spec> = serde_json::from_value(transcript.bootstrap)?;
        let bootstrap_slot = bootstrap.header().beacon().slot;
        ensure!(max_current_slot != 0, "zero consensus slot ceiling");
        ensure!(
            bootstrap_slot != 0 && bootstrap_slot <= max_current_slot,
            "bootstrap slot exceeds consensus limit"
        );
        ensure!(
            max_current_slot - bootstrap_slot <= MAX_TRUSTED_BOOTSTRAP_AGE_SLOTS,
            "trusted bootstrap is outside the freshness horizon"
        );
        ensure!(
            expected_finalized.beacon_slot <= max_current_slot,
            "expected finalized slot exceeds consensus limit"
        );
        let mut client = Self::bootstrap(&bootstrap, trusted_checkpoint, genesis_root, forks)?;
        // The first committee-bridging update may legitimately predate the
        // trusted bootstrap, but never by more than the same freshness horizon
        // used for bootstrap trust. Every following record is monotonic.
        let mut previous_slot = bootstrap_slot.saturating_sub(MAX_TRUSTED_BOOTSTRAP_AGE_SLOTS);
        for accepted in transcript.updates {
            ensure!(
                accepted.current_slot == accepted.update.signature_slot,
                "noncanonical transcript replay slot"
            );
            ensure!(
                accepted.current_slot >= previous_slot,
                "transcript replay slot rollback"
            );
            ensure!(
                accepted.current_slot <= max_current_slot,
                "transcript current slot exceeds consensus limit"
            );
            let before = client.accepted_updates.len();
            client.accept(&accepted.update)?;
            ensure!(
                client.accepted_updates.len() == before + 1,
                "duplicate transcript update"
            );
            previous_slot = accepted.current_slot;
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
    let transcript = decode_canonical_transcript(bytes)?;
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
        ensure!(
            accepted.current_slot >= replay_slot,
            "transcript replay slot rollback"
        );
        replay_slot = accepted.current_slot;
    }
    Ok(replay_slot)
}

fn decode_canonical_transcript(bytes: &[u8]) -> Result<ClientTranscript> {
    preflight_transcript_json(bytes)?;
    let transcript: ClientTranscript = serde_json::from_slice(bytes)?;
    let canonical = serde_json::to_vec(&transcript)?;
    ensure!(
        canonical.as_slice() == bytes,
        "noncanonical transcript encoding"
    );
    Ok(transcript)
}

/// Compatibility alias for earlier experiment consumers.
pub type HistoricalCapellaClient = EthereumFinalityClient;

/// Verify untrusted Beacon REST payloads and export the canonical replay
/// transcript used by consensus witnesses. Every accepted update uses its own
/// authenticated signature slot as the minimal deterministic clock ceiling.
pub fn verified_transcript_from_rest(
    bootstrap: serde_json::Value,
    updates: Vec<serde_json::Value>,
    finality: serde_json::Value,
    trusted_checkpoint: B256,
    genesis_root: B256,
    forks: Forks,
) -> Result<(Vec<u8>, FinalizedExecution, u64)> {
    ensure!(updates.len() <= 128, "REST light-client update count");
    let bootstrap: Bootstrap<Spec> = serde_json::from_value(bootstrap)?;
    let mut client =
        EthereumFinalityClient::bootstrap(&bootstrap, trusted_checkpoint, genesis_root, forks)?;
    let mut replay_slot = bootstrap.header().beacon().slot;
    for value in updates {
        let update: Update<Spec> = serde_json::from_value(value)?;
        let update = GenericUpdate::from(&update);
        replay_slot = replay_slot.max(update.signature_slot);
        client.accept(&update)?;
    }
    let finality: FinalityUpdate<Spec> = serde_json::from_value(finality)?;
    let finality = GenericUpdate::from(&finality);
    replay_slot = replay_slot.max(finality.signature_slot);
    client.accept(&finality)?;
    let finalized = client.finalized();
    ensure!(
        replay_slot >= finalized.beacon_slot,
        "transcript replay slot precedes finalized slot"
    );
    let transcript = client.export_transcript()?;
    let restored = EthereumFinalityClient::restore_transcript_bounded(
        &transcript,
        trusted_checkpoint,
        genesis_root,
        client.forks.clone(),
        &finalized,
        replay_slot,
    )?;
    ensure!(
        restored.finalized() == finalized,
        "transcript round trip changed finality"
    );
    Ok((transcript, finalized, replay_slot))
}

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

/// Validate the structural fork horizon used to select signature domains.
/// Exact mainnet epochs/versions are pinned by the node manifest; this shared
/// boundary additionally protects proof hosts and serialized policy consumers.
pub(crate) fn validate_fork_schedule(forks: &Forks) -> Result<()> {
    let ordered = [
        &forks.genesis,
        &forks.altair,
        &forks.bellatrix,
        &forks.capella,
        &forks.deneb,
        &forks.electra,
        &forks.fulu,
        &forks.gloas,
    ];
    ensure!(
        forks.genesis.epoch == 0,
        "genesis fork must start at epoch zero"
    );
    ensure!(
        ordered.windows(2).all(|pair| pair[0].epoch < pair[1].epoch),
        "fork epochs are not strictly increasing"
    );
    ensure!(
        forks.capella.epoch != 0 && forks.gloas.epoch > forks.fulu.epoch,
        "unsupported fork horizon"
    );
    for (index, fork) in ordered.iter().enumerate() {
        ensure!(
            ordered[..index]
                .iter()
                .all(|prior| prior.fork_version != fork.fork_version),
            "duplicate fork version"
        );
    }
    Ok(())
}

/// Bind an authenticated finalized execution timestamp to the containing
/// consensus timestamp. The permitted lead absorbs bounded cross-chain clock
/// skew; it cannot be supplied by the witness.
pub fn validate_finalized_time_window(
    finalized_timestamp: u64,
    consensus_timestamp: u64,
    maximum_age_seconds: u64,
    maximum_future_lead_seconds: u64,
) -> Result<()> {
    ensure!(
        finalized_timestamp != 0 && consensus_timestamp != 0 && maximum_age_seconds != 0,
        "invalid finality freshness policy"
    );
    let latest_acceptable = finalized_timestamp
        .checked_add(maximum_age_seconds)
        .ok_or_else(|| eyre::eyre!("finalized timestamp age overflow"))?;
    let freshness_reference = consensus_timestamp.saturating_sub(maximum_future_lead_seconds);
    ensure!(
        freshness_reference <= latest_acceptable,
        "finalized execution anchor is stale"
    );
    let latest_future = consensus_timestamp
        .checked_add(maximum_future_lead_seconds)
        .ok_or_else(|| eyre::eyre!("consensus timestamp lead overflow"))?;
    ensure!(
        finalized_timestamp <= latest_future,
        "finalized execution anchor is from the future"
    );
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

#[cfg(test)]
mod allocation_bound_tests {
    use super::*;

    #[test]
    fn evidence_json_preflight_rejects_allocation_amplifiers() {
        let deeply_nested = format!("{}0{}", "[".repeat(33), "]".repeat(33));
        assert!(preflight_evidence_json(deeply_nested.as_bytes()).is_err());

        let oversized_string = format!("\"{}\"", "a".repeat(MAX_EVIDENCE_JSON_STRING_BYTES));
        assert!(preflight_evidence_json(oversized_string.as_bytes()).is_err());

        let excessive_tokens = format!(
            "[{}]",
            std::iter::repeat("0")
                .take(MAX_EVIDENCE_JSON_TOKENS + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(preflight_evidence_json(excessive_tokens.as_bytes()).is_err());
        assert!(preflight_evidence_json(b"\"").is_err());
    }

    #[test]
    fn evidence_json_preflight_accepts_bounded_canonical_shape() {
        assert!(preflight_evidence_json(br#"{"proof":["0x01"],"count":1}"#).is_ok());
    }

    #[test]
    fn finalized_time_window_has_exact_inclusive_bounds_and_checked_overflow() {
        let finalized = 1_800_000_000;
        let age = 1_800;
        let lead = 120;

        assert!(
            validate_finalized_time_window(finalized, finalized + age + lead, age, lead).is_ok()
        );
        assert!(
            validate_finalized_time_window(finalized, finalized + age + lead + 1, age, lead)
                .is_err()
        );
        assert!(validate_finalized_time_window(finalized + lead, finalized, age, lead).is_ok());
        assert!(
            validate_finalized_time_window(finalized + lead + 1, finalized, age, lead).is_err()
        );
        assert!(validate_finalized_time_window(u64::MAX, 1, 1, lead).is_err());
        assert!(validate_finalized_time_window(1, u64::MAX, age, 1).is_err());
    }
}
