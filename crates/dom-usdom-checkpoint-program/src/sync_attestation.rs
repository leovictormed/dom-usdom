//! Canonical multi-peer evidence that an offline activation anchor was synced.

use dom_core::DomError;
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;

#[cfg(feature = "host-reference")]
const SYNC_ATTESTATION_METADATA_KEY: &[u8] = b"usdom/checkpoint/sync-attestation/v1";
const ATTESTATION_MAGIC: &[u8; 8] = b"UDSYNC01";
const POLICY_MAGIC: &[u8; 8] = b"UDSYNP01";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 167;
const OBSERVATION_BYTES: usize = 48;
/// Minimum number of independently configured Noise identities.
pub const MIN_SYNC_ATTESTATION_PEERS: usize = 3;
/// Absolute framing and verification bound.
pub const MAX_SYNC_ATTESTATION_PEERS: usize = 16;
/// Maximum gap between authenticated samples that still counts as continuous.
pub const MAX_SYNC_OBSERVATION_GAP_SECONDS: u64 = 120;
/// Maximum tolerated difference between sender and receiver wall clocks.
pub const MAX_SYNC_TIP_CLOCK_SKEW_SECONDS: u64 = 300;

/// Exact local canonical-chain tuple affirmed by the peer quorum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncTip {
    /// DOM network discriminator.
    pub network_magic: u32,
    /// Chain identity derived from network and genesis.
    pub chain_id: [u8; 32],
    /// Canonical height.
    pub height: u64,
    /// Canonical block identifier.
    pub block: [u8; 32],
    /// Cumulative work, unsigned big-endian.
    pub total_difficulty: [u8; 32],
}

/// Stable observation from one authenticated Noise peer identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncPeerObservation {
    /// Remote static Noise identity, never an address or DNS name.
    pub peer_id: [u8; 32],
    /// First Unix second at which this peer affirmed the exact tuple.
    pub first_observed_at: u64,
    /// Last Unix second at which this peer still affirmed the exact tuple.
    pub last_observed_at: u64,
}

/// Operator-ratified peer set and time bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAttestationPolicy {
    /// Strictly sorted, unique, nonzero Noise peer identities.
    pub trusted_peer_ids: Vec<[u8; 32]>,
    /// Required observations; must be strictly greater than two thirds.
    pub threshold: u8,
    /// Minimum seconds for which every quorum member must remain stable.
    pub minimum_stability_seconds: u64,
    /// Maximum age of the final observation at offline verification.
    pub maximum_age_seconds: u64,
}

/// Canonical durable receipt produced only after a stable peer quorum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAttestation {
    /// Exact locally stored tip affirmed by peers.
    pub tip: SyncTip,
    /// Inclusive beginning of the common stable observation window.
    pub observed_from: u64,
    /// Inclusive end of the common stable observation window.
    pub observed_until: u64,
    /// Commitment to the ratified peer policy.
    pub policy_hash: [u8; 32],
    /// Strictly peer-id-sorted quorum observations.
    pub observations: Vec<SyncPeerObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LiveObservation {
    first_received_at: u64,
    last_received_at: u64,
    last_generated_at: u64,
}

/// Bounded in-memory quorum collector for authenticated peer sessions.
///
/// Callers must pass the Noise static identity attached to the connection.
/// Address strings and unauthenticated Hello aliases are never accepted.
#[derive(Debug, Clone)]
pub struct SyncAttestationCollector {
    policy: SyncAttestationPolicy,
    tip: Option<SyncTip>,
    observations: BTreeMap<[u8; 32], LiveObservation>,
}

impl SyncAttestationCollector {
    /// Create an empty collector after validating the ratified policy.
    pub fn new(policy: SyncAttestationPolicy) -> Result<Self, DomError> {
        policy.commitment()?;
        Ok(Self {
            policy,
            tip: None,
            observations: BTreeMap::new(),
        })
    }

    /// Return the exact ratified policy used by this collector.
    pub fn policy(&self) -> &SyncAttestationPolicy {
        &self.policy
    }

    /// Record one authenticated advertisement and return a receipt only after
    /// a stable trusted quorum covers the exact current local tuple.
    pub fn observe(
        &mut self,
        peer_id: [u8; 32],
        advertised_tip: SyncTip,
        generated_at: u64,
        received_at: u64,
        local_tip: SyncTip,
    ) -> Result<Option<SyncAttestation>, DomError> {
        if self.tip != Some(local_tip) {
            self.tip = Some(local_tip);
            self.observations.clear();
        }
        if self
            .policy
            .trusted_peer_ids
            .binary_search(&peer_id)
            .is_err()
        {
            // Capability support is network-wide while trust is local policy.
            // Unknown identities remain ordinary compatible peers but can
            // never consume collector capacity or advance quorum.
            return Ok(None);
        }
        let clock_delta = generated_at.abs_diff(received_at);
        if advertised_tip != local_tip
            || generated_at == 0
            || received_at == 0
            || clock_delta > MAX_SYNC_TIP_CLOCK_SKEW_SECONDS
        {
            self.observations.remove(&peer_id);
            return Err(rejected(
                "sync-tip tuple or clock does not match local state",
            ));
        }
        match self.observations.get_mut(&peer_id) {
            Some(live)
                if generated_at > live.last_generated_at
                    && received_at > live.last_received_at
                    && received_at - live.last_received_at <= MAX_SYNC_OBSERVATION_GAP_SECONDS =>
            {
                live.last_generated_at = generated_at;
                live.last_received_at = received_at;
            }
            Some(live) => {
                *live = LiveObservation {
                    first_received_at: received_at,
                    last_received_at: received_at,
                    last_generated_at: generated_at,
                };
            }
            None => {
                self.observations.insert(
                    peer_id,
                    LiveObservation {
                        first_received_at: received_at,
                        last_received_at: received_at,
                        last_generated_at: generated_at,
                    },
                );
            }
        }
        self.ready(received_at)
    }

    /// Persist only a fully verified quorum receipt; partial observations stay
    /// in memory and cannot be mistaken for durable synchronization evidence.
    #[cfg(feature = "host-reference")]
    pub fn observe_and_persist(
        &mut self,
        store: &dom_store::DomStore,
        peer_id: [u8; 32],
        advertised_tip: SyncTip,
        generated_at: u64,
        received_at: u64,
        local_tip: SyncTip,
    ) -> Result<Option<SyncAttestation>, DomError> {
        let receipt = self.observe(
            peer_id,
            advertised_tip,
            generated_at,
            received_at,
            local_tip,
        )?;
        if let Some(receipt) = &receipt {
            receipt.save(store, &self.policy, received_at)?;
        }
        Ok(receipt)
    }

    fn ready(&self, now: u64) -> Result<Option<SyncAttestation>, DomError> {
        let eligible: Vec<_> = self
            .observations
            .iter()
            .filter(|(_, live)| {
                live.last_received_at
                    .checked_sub(live.first_received_at)
                    .is_some_and(|span| span >= self.policy.minimum_stability_seconds)
                    && now.saturating_sub(live.last_received_at) <= MAX_SYNC_OBSERVATION_GAP_SECONDS
            })
            .collect();
        if eligible.len() < usize::from(self.policy.threshold) {
            return Ok(None);
        }
        let observed_from = eligible
            .iter()
            .map(|(_, live)| live.first_received_at)
            .max()
            .ok_or_else(|| rejected("sync quorum unexpectedly empty"))?;
        let observed_until = eligible
            .iter()
            .map(|(_, live)| live.last_received_at)
            .min()
            .ok_or_else(|| rejected("sync quorum unexpectedly empty"))?;
        if observed_until.saturating_sub(observed_from) < self.policy.minimum_stability_seconds {
            return Ok(None);
        }
        let observations = eligible
            .into_iter()
            .map(|(peer, live)| SyncPeerObservation {
                peer_id: *peer,
                first_observed_at: live.first_received_at,
                last_observed_at: live.last_received_at,
            })
            .collect();
        SyncAttestation::new(
            self.tip
                .ok_or_else(|| rejected("sync collector has no tip"))?,
            observed_from,
            observed_until,
            &self.policy,
            observations,
            now,
        )
        .map(Some)
    }
}

impl SyncAttestationPolicy {
    /// Validate the anti-Sybil policy and return its domain-separated hash.
    pub fn commitment(&self) -> Result<[u8; 32], DomError> {
        validate_policy(self)?;
        let mut bytes = Vec::with_capacity(26 + self.trusted_peer_ids.len() * 32);
        bytes.extend_from_slice(POLICY_MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.push(self.threshold);
        bytes.extend_from_slice(&self.minimum_stability_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.maximum_age_seconds.to_be_bytes());
        bytes.push(self.trusted_peer_ids.len() as u8);
        for peer in &self.trusted_peer_ids {
            bytes.extend_from_slice(peer);
        }
        Ok(Keccak256::digest(bytes).into())
    }
}

impl SyncAttestation {
    /// Construct and validate one canonical receipt.
    pub fn new(
        tip: SyncTip,
        observed_from: u64,
        observed_until: u64,
        policy: &SyncAttestationPolicy,
        observations: Vec<SyncPeerObservation>,
        verification_time: u64,
    ) -> Result<Self, DomError> {
        let receipt = Self {
            tip,
            observed_from,
            observed_until,
            policy_hash: policy.commitment()?,
            observations,
        };
        receipt.verify(policy, verification_time)?;
        Ok(receipt)
    }

    /// Verify identity, tuple, quorum, stable window, freshness and ordering.
    pub fn verify(
        &self,
        policy: &SyncAttestationPolicy,
        verification_time: u64,
    ) -> Result<(), DomError> {
        let expected_policy = policy.commitment()?;
        let stability = self
            .observed_until
            .checked_sub(self.observed_from)
            .ok_or_else(|| rejected("sync-attestation window runs backwards"))?;
        let age = verification_time
            .checked_sub(self.observed_until)
            .ok_or_else(|| rejected("sync-attestation is from the future"))?;
        if self.tip.chain_id == [0; 32]
            || self.tip.block == [0; 32]
            || self.tip.total_difficulty == [0; 32]
            || self.policy_hash != expected_policy
            || stability < policy.minimum_stability_seconds
            || age > policy.maximum_age_seconds
            || self.observations.len() < usize::from(policy.threshold)
            || self.observations.len() > policy.trusted_peer_ids.len()
        {
            return Err(rejected(
                "sync-attestation identity, window, age, or quorum mismatch",
            ));
        }
        let mut previous = None;
        for observation in &self.observations {
            if observation.peer_id == [0; 32]
                || previous.is_some_and(|peer| peer >= observation.peer_id)
                || policy
                    .trusted_peer_ids
                    .binary_search(&observation.peer_id)
                    .is_err()
                || observation.first_observed_at > self.observed_from
                || observation.last_observed_at < self.observed_until
                || observation.first_observed_at > observation.last_observed_at
                || observation.last_observed_at > verification_time
            {
                return Err(rejected(
                    "sync-attestation contains an untrusted, duplicate, unordered, or unstable peer",
                ));
            }
            previous = Some(observation.peer_id);
        }
        Ok(())
    }

    /// Encode with fixed-width, bounded, canonical big-endian framing.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DomError> {
        if self.observations.len() > MAX_SYNC_ATTESTATION_PEERS {
            return Err(rejected("sync-attestation exceeds peer bound"));
        }
        let mut out =
            Vec::with_capacity(HEADER_BYTES + self.observations.len() * OBSERVATION_BYTES);
        out.extend_from_slice(ATTESTATION_MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&self.tip.network_magic.to_be_bytes());
        out.extend_from_slice(&self.tip.chain_id);
        out.extend_from_slice(&self.tip.height.to_be_bytes());
        out.extend_from_slice(&self.tip.block);
        out.extend_from_slice(&self.tip.total_difficulty);
        out.extend_from_slice(&self.observed_from.to_be_bytes());
        out.extend_from_slice(&self.observed_until.to_be_bytes());
        out.extend_from_slice(&self.policy_hash);
        out.push(self.observations.len() as u8);
        for observation in &self.observations {
            out.extend_from_slice(&observation.peer_id);
            out.extend_from_slice(&observation.first_observed_at.to_be_bytes());
            out.extend_from_slice(&observation.last_observed_at.to_be_bytes());
        }
        Ok(out)
    }

    /// Decode strict framing; semantic authorization is performed by [`Self::verify`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        if bytes.len() < HEADER_BYTES
            || bytes.get(..8) != Some(ATTESTATION_MAGIC.as_slice())
            || read_u16(bytes, 8)? != VERSION
        {
            return Err(malformed("invalid sync-attestation framing"));
        }
        let count = usize::from(bytes[166]);
        if !(MIN_SYNC_ATTESTATION_PEERS..=MAX_SYNC_ATTESTATION_PEERS).contains(&count)
            || bytes.len() != HEADER_BYTES + count * OBSERVATION_BYTES
        {
            return Err(malformed("invalid sync-attestation peer count or length"));
        }
        let mut observations = Vec::with_capacity(count);
        let mut cursor = HEADER_BYTES;
        for _ in 0..count {
            observations.push(SyncPeerObservation {
                peer_id: array(bytes, cursor)?,
                first_observed_at: read_u64(bytes, cursor + 32)?,
                last_observed_at: read_u64(bytes, cursor + 40)?,
            });
            cursor += OBSERVATION_BYTES;
        }
        let decoded = Self {
            tip: SyncTip {
                network_magic: read_u32(bytes, 10)?,
                chain_id: array(bytes, 14)?,
                height: read_u64(bytes, 46)?,
                block: array(bytes, 54)?,
                total_difficulty: array(bytes, 86)?,
            },
            observed_from: read_u64(bytes, 118)?,
            observed_until: read_u64(bytes, 126)?,
            policy_hash: array(bytes, 134)?,
            observations,
        };
        if decoded.to_bytes()?.as_slice() != bytes {
            return Err(malformed("noncanonical sync-attestation"));
        }
        Ok(decoded)
    }

    /// Verify and atomically replace the single durable receipt in node metadata.
    #[cfg(feature = "host-reference")]
    pub fn save(
        &self,
        store: &dom_store::DomStore,
        policy: &SyncAttestationPolicy,
        verification_time: u64,
    ) -> Result<(), DomError> {
        self.verify(policy, verification_time)?;
        store.put_metadata(SYNC_ATTESTATION_METADATA_KEY, &self.to_bytes()?)
    }

    /// Load and strictly decode the durable receipt, if present.
    #[cfg(feature = "host-reference")]
    pub fn load(store: &dom_store::DomStore) -> Result<Option<Self>, DomError> {
        store
            .get_metadata(SYNC_ATTESTATION_METADATA_KEY)?
            .map(|bytes| Self::from_bytes(&bytes))
            .transpose()
    }
}

fn validate_policy(policy: &SyncAttestationPolicy) -> Result<(), DomError> {
    let count = policy.trusted_peer_ids.len();
    if !(MIN_SYNC_ATTESTATION_PEERS..=MAX_SYNC_ATTESTATION_PEERS).contains(&count)
        || usize::from(policy.threshold) <= count * 2 / 3
        || usize::from(policy.threshold) > count
        || policy.minimum_stability_seconds == 0
        || policy.maximum_age_seconds == 0
    {
        return Err(rejected("invalid sync-attestation policy bounds or quorum"));
    }
    let mut previous = None;
    for peer in &policy.trusted_peer_ids {
        if *peer == [0; 32] || previous.is_some_and(|prior| prior >= *peer) {
            return Err(rejected(
                "sync-attestation trusted peers must be nonzero, unique, and sorted",
            ));
        }
        previous = Some(*peer);
    }
    Ok(())
}

fn array(bytes: &[u8], offset: usize) -> Result<[u8; 32], DomError> {
    bytes
        .get(offset..offset + 32)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| malformed("truncated sync-attestation"))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DomError> {
    Ok(u16::from_be_bytes(
        bytes
            .get(offset..offset + 2)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| malformed("truncated sync-attestation"))?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DomError> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| malformed("truncated sync-attestation"))?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, DomError> {
    Ok(u64::from_be_bytes(
        bytes
            .get(offset..offset + 8)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| malformed("truncated sync-attestation"))?,
    ))
}

fn rejected(message: impl Into<String>) -> DomError {
    DomError::PolicyRejected(message.into())
}

fn malformed(message: impl Into<String>) -> DomError {
    DomError::Malformed(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SyncAttestationPolicy {
        SyncAttestationPolicy {
            trusted_peer_ids: vec![[1; 32], [2; 32], [3; 32], [4; 32]],
            threshold: 3,
            minimum_stability_seconds: 600,
            maximum_age_seconds: 300,
        }
    }

    fn receipt() -> SyncAttestation {
        let policy = policy();
        SyncAttestation::new(
            SyncTip {
                network_magic: 1,
                chain_id: [5; 32],
                height: 42,
                block: [6; 32],
                total_difficulty: [7; 32],
            },
            1_000,
            1_600,
            &policy,
            vec![
                SyncPeerObservation {
                    peer_id: [1; 32],
                    first_observed_at: 900,
                    last_observed_at: 1_600,
                },
                SyncPeerObservation {
                    peer_id: [2; 32],
                    first_observed_at: 1_000,
                    last_observed_at: 1_700,
                },
                SyncPeerObservation {
                    peer_id: [3; 32],
                    first_observed_at: 950,
                    last_observed_at: 1_650,
                },
            ],
            1_700,
        )
        .expect("valid receipt")
    }

    #[test]
    fn canonical_receipt_roundtrips_and_rejects_trailing_or_truncated_bytes() {
        let receipt = receipt();
        let bytes = receipt.to_bytes().unwrap();
        assert_eq!(SyncAttestation::from_bytes(&bytes).unwrap(), receipt);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(SyncAttestation::from_bytes(&trailing).is_err());
        assert!(SyncAttestation::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn verifier_rejects_stale_short_untrusted_duplicate_and_policy_substitution() {
        let receipt = receipt();
        assert!(receipt.verify(&policy(), 1_901).is_err());

        let mut short = receipt.clone();
        short.observed_from += 1;
        assert!(short.verify(&policy(), 1_700).is_err());

        let mut untrusted = receipt.clone();
        untrusted.observations[2].peer_id = [9; 32];
        assert!(untrusted.verify(&policy(), 1_700).is_err());

        let mut duplicate = receipt.clone();
        duplicate.observations[2].peer_id = [2; 32];
        assert!(duplicate.verify(&policy(), 1_700).is_err());

        let mut substituted = policy();
        substituted.trusted_peer_ids[3] = [8; 32];
        assert!(receipt.verify(&substituted, 1_700).is_err());
    }

    #[test]
    fn policy_requires_strict_supermajority_and_canonical_peer_set() {
        let mut invalid = policy();
        invalid.threshold = 2;
        assert!(invalid.commitment().is_err());
        invalid = policy();
        invalid.trusted_peer_ids[2] = [2; 32];
        assert!(invalid.commitment().is_err());
        invalid = policy();
        invalid.trusted_peer_ids.truncate(2);
        assert!(invalid.commitment().is_err());
    }

    #[cfg(feature = "host-reference")]
    #[test]
    fn durable_receipt_replaces_atomically_and_loads_with_strict_framing() {
        let directory = tempfile::tempdir().unwrap();
        let store = dom_store::DomStore::open(directory.path()).unwrap();
        assert_eq!(SyncAttestation::load(&store).unwrap(), None);
        let first = receipt();
        first.save(&store, &policy(), 1_700).unwrap();
        assert_eq!(SyncAttestation::load(&store).unwrap(), Some(first.clone()));

        let mut replacement = first;
        replacement.tip.height += 1;
        replacement.tip.block = [8; 32];
        replacement.save(&store, &policy(), 1_700).unwrap();
        assert_eq!(SyncAttestation::load(&store).unwrap(), Some(replacement));
    }

    #[test]
    fn collector_requires_repeated_honest_supermajority_before_receipt() {
        let policy = policy();
        let mut collector = SyncAttestationCollector::new(policy.clone()).unwrap();
        let tip = receipt().tip;
        for peer in [[1; 32], [2; 32], [3; 32]] {
            assert!(collector
                .observe(peer, tip, 1_000, 1_000, tip)
                .unwrap()
                .is_none());
        }
        for sampled_at in [1_100, 1_200, 1_300, 1_400, 1_500] {
            for peer in [[1; 32], [2; 32], [3; 32]] {
                assert!(collector
                    .observe(peer, tip, sampled_at, sampled_at, tip)
                    .unwrap()
                    .is_none());
            }
        }
        let mut completed = None;
        for peer in [[1; 32], [2; 32], [3; 32]] {
            completed = collector
                .observe(peer, tip, 1_600, 1_600, tip)
                .unwrap()
                .or(completed);
        }
        let completed = completed.expect("stable quorum receipt");
        assert_eq!(completed.observations.len(), 3);
        completed.verify(&policy, 1_600).unwrap();
    }

    #[test]
    fn collector_rejects_malicious_replay_tuple_change_and_sampling_gap() {
        let mut collector = SyncAttestationCollector::new(policy()).unwrap();
        let tip = receipt().tip;
        assert!(collector
            .observe([1; 32], tip, 1_000, 1_000, tip)
            .unwrap()
            .is_none());
        // Replaying the same sender timestamp resets rather than extending stability.
        assert!(collector
            .observe([1; 32], tip, 1_000, 1_100, tip)
            .unwrap()
            .is_none());
        let mut forged = tip;
        forged.block = [9; 32];
        assert!(collector
            .observe([1; 32], forged, 1_200, 1_200, tip)
            .is_err());
        // A gap beyond the liveness bound also restarts the peer's window.
        assert!(collector
            .observe([1; 32], tip, 2_000, 2_000, tip)
            .unwrap()
            .is_none());
        assert!(collector
            .observe([1; 32], tip, 2_600, 2_600, tip)
            .unwrap()
            .is_none());
    }

    #[test]
    fn untrusted_eclipse_identities_never_advance_quorum_or_persist() {
        let directory = tempfile::tempdir().unwrap();
        let store = dom_store::DomStore::open(directory.path()).unwrap();
        let mut collector = SyncAttestationCollector::new(policy()).unwrap();
        let tip = receipt().tip;
        for peer in 10u8..=100 {
            assert!(collector
                .observe_and_persist(&store, [peer; 32], tip, 1_000, 1_000, tip)
                .unwrap()
                .is_none());
        }
        assert_eq!(SyncAttestation::load(&store).unwrap(), None);
    }
}
