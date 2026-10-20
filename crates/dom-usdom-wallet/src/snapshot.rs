//! Canonical encrypted wallet snapshots with caller-anchored rollback detection.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    path::Path,
};

use dom_core::Hash256;
use dom_crypto::hash::blake2b_256_tagged;
use dom_usdom_privacy::{NoteOpening, Scalar, NOTE_ORIGIN_ISSUANCE};
use dom_usdom_state::{
    inspect_private_burn_outputs, inspect_private_burn_record, inspect_private_transfer_outputs,
    private_burn_payload_id, private_transfer_payload_id, EthereumDepositOccurrence,
};
use dom_wallet_crypto::{load_envelope_bytes, save_envelope_bytes, EnvelopeError};
use fs2::FileExt;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use super::{
    builder::PendingPrivateTransfer, burn_builder::PendingPrivateBurn, ExpectedIssuance,
    ReceivedNote, TrackedNote, WalletBlockUndo, WalletError, WalletSecrets, WalletState,
};

const ENVELOPE_MAGIC: &[u8; 14] = b"USD-WALLET-S7\0";
const ENVELOPE_VERSION: u16 = 7;
const SNAPSHOT_MAGIC: &[u8; 8] = b"USWSTA07";
const SEAL_MAGIC: &[u8; 8] = b"USWSL001";
const SNAPSHOT_DIGEST_TAG: &str = "DOM:usdom-wallet-snapshot:v1";
const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const MAX_SNAPSHOT_ITEMS: usize = 1_000_000;
/// Minimum encoded byte length accepted by [`WalletPassphrase`].
pub const MIN_WALLET_PASSPHRASE_BYTES: usize = 16;
/// Maximum encoded byte length accepted by [`WalletPassphrase`].
pub const MAX_WALLET_PASSPHRASE_BYTES: usize = 1024;

/// Owned wallet passphrase with bounded construction and memory erasure.
///
/// The value cannot be cloned, formatted, serialized, or recovered through a
/// public accessor. Callers should move freshly read secret input directly
/// into this type and keep it alive only while the wallet is unlocked.
pub struct WalletPassphrase(Zeroizing<String>);

impl WalletPassphrase {
    /// Accept a nonblank passphrase within the fixed resource bounds.
    pub fn new(mut value: String) -> Result<Self, WalletSnapshotError> {
        if value.len() < MIN_WALLET_PASSPHRASE_BYTES
            || value.len() > MAX_WALLET_PASSPHRASE_BYTES
            || value.trim().is_empty()
        {
            value.zeroize();
            return Err(WalletSnapshotError::InvalidPassphrase);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

/// Exact canonical width of an external wallet snapshot seal.
pub const WALLET_SNAPSHOT_SEAL_BYTES: usize = 48;

/// Authenticated logical identity that must be retained outside the snapshot
/// file in a rollback-resistant store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletSnapshotSeal {
    /// Strictly increasing save generation.
    pub generation: u64,
    /// Domain-separated digest of the exact decrypted canonical snapshot.
    pub digest: Hash256,
}

impl WalletSnapshotSeal {
    /// Encode the generation and logical snapshot digest for an external
    /// monotonic or hardware-backed authority.
    pub fn to_bytes(self) -> [u8; WALLET_SNAPSHOT_SEAL_BYTES] {
        let mut bytes = [0u8; WALLET_SNAPSHOT_SEAL_BYTES];
        bytes[..8].copy_from_slice(SEAL_MAGIC);
        bytes[8..16].copy_from_slice(&self.generation.to_be_bytes());
        bytes[16..].copy_from_slice(self.digest.as_bytes());
        bytes
    }

    /// Decode the unique fixed-width external seal representation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WalletSnapshotError> {
        if bytes.len() != WALLET_SNAPSHOT_SEAL_BYTES || &bytes[..8] != SEAL_MAGIC {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
        let generation = u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| WalletSnapshotError::InvalidSnapshot)?,
        );
        let digest = Hash256::from_bytes(
            bytes[16..]
                .try_into()
                .map_err(|_| WalletSnapshotError::InvalidSnapshot)?,
        );
        if generation == 0 || digest == Hash256::ZERO {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
        let seal = Self { generation, digest };
        if seal.to_bytes().as_slice() != bytes {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
        Ok(seal)
    }
}

/// Atomic state exposed by a rollback-resistant snapshot seal authority.
///
/// `prepared` is the next seal in a two-phase transition. An implementation
/// must retain both fields outside the encrypted snapshot storage and update
/// them with compare-and-swap semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletSealAuthorityState {
    /// Last fully committed wallet snapshot seal.
    pub committed: Option<WalletSnapshotSeal>,
    /// Next prepared seal, if a save was interrupted before commit or abort.
    pub prepared: Option<WalletSnapshotSeal>,
}

/// Bounded failures returned by an external monotonic seal authority.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WalletSealAuthorityError {
    /// The external authority could not be reached or durably updated.
    #[error("wallet seal authority unavailable")]
    Unavailable,
    /// Its compare-and-swap predecessor or prepared seal did not match.
    #[error("wallet seal authority compare-and-swap conflict")]
    Conflict,
    /// The authority reported a structurally impossible generation state.
    #[error("wallet seal authority contains invalid state")]
    InvalidState,
}

/// Rollback-resistant two-phase authority used to order wallet persistence
/// before any private-transfer submission.
///
/// Every mutating method must be durable before returning success. `prepare`
/// may succeed only when `committed == expected` and no transition is already
/// prepared. `commit` moves the exact prepared seal to `committed`; `abort`
/// removes that exact prepared seal without changing `committed`.
pub trait WalletSnapshotSealAuthority {
    /// Read one atomic view of committed and prepared seals.
    fn state(&mut self) -> Result<WalletSealAuthorityState, WalletSealAuthorityError>;

    /// Atomically prepare `proposed` from the exact committed predecessor.
    fn prepare(
        &mut self,
        expected: Option<WalletSnapshotSeal>,
        proposed: WalletSnapshotSeal,
    ) -> Result<(), WalletSealAuthorityError>;

    /// Atomically commit the exact prepared seal.
    fn commit(&mut self, proposed: WalletSnapshotSeal) -> Result<(), WalletSealAuthorityError>;

    /// Atomically abandon the exact prepared seal while retaining committed.
    fn abort(&mut self, proposed: WalletSnapshotSeal) -> Result<(), WalletSealAuthorityError>;
}

/// Capability proving that one exact pending payload was present in a
/// snapshot committed by the external seal authority before submission.
///
/// It has no public constructor. The wallet persistence protocol is the only
/// code path that can issue it.
#[derive(Debug, PartialEq, Eq)]
pub struct DurablePendingTransferPermit {
    transition_id: Hash256,
    snapshot_seal: WalletSnapshotSeal,
}

/// Capability proving that one exact pending private burn was committed to
/// rollback-resistant wallet storage before network submission.
#[derive(Debug, PartialEq, Eq)]
pub struct DurablePendingBurnPermit {
    transition_id: Hash256,
    snapshot_seal: WalletSnapshotSeal,
}

impl DurablePendingBurnPermit {
    /// Exact randomized private-burn payload identifier.
    pub fn transition_id(&self) -> Hash256 {
        self.transition_id
    }

    /// Rollback-resistant snapshot seal that authorized submission.
    pub fn snapshot_seal(&self) -> WalletSnapshotSeal {
        self.snapshot_seal
    }
}

#[derive(Clone, Copy)]
enum PendingSubmissionKind {
    Transfer,
    Burn,
}

struct PendingSubmissionRequest<'a> {
    transition_id: Hash256,
    kind: PendingSubmissionKind,
    path: &'a Path,
    password: &'a WalletPassphrase,
    previous_seal: Option<WalletSnapshotSeal>,
}

struct DurablePendingPermitCore {
    transition_id: Hash256,
    snapshot_seal: WalletSnapshotSeal,
}

impl DurablePendingTransferPermit {
    /// Exact randomized private-transfer payload identifier.
    pub fn transition_id(&self) -> Hash256 {
        self.transition_id
    }

    /// Rollback-resistant snapshot seal that authorized submission.
    pub fn snapshot_seal(&self) -> WalletSnapshotSeal {
        self.snapshot_seal
    }
}

/// Failure while coordinating snapshot storage with its monotonic authority.
#[derive(Debug, Error)]
pub enum DurableWalletPersistenceError {
    /// Canonical snapshot validation, encryption, or storage failed.
    #[error(transparent)]
    Snapshot(#[from] WalletSnapshotError),
    /// External authority operation failed before its final state was proven.
    #[error(transparent)]
    Authority(#[from] WalletSealAuthorityError),
    /// File predecessor and authority committed predecessor did not agree.
    #[error("wallet snapshot and seal authority state do not match")]
    StateMismatch,
    /// A prepared two-phase transition must be reconciled before continuing.
    #[error("wallet snapshot seal transition requires crash recovery")]
    RecoveryRequired,
    /// The requested transfer is not pending in this exact wallet state.
    #[error("unknown pending native USDOM transfer")]
    UnknownPendingTransfer,
    /// The requested burn is not pending in this exact wallet state.
    #[error("unknown pending native USDOM burn")]
    UnknownPendingBurn,
    /// A fresh permit was requested for an already-authorized in-memory state.
    #[error("pending native USDOM transfer already has submission authority")]
    AlreadyAuthorized,
}

/// Fully restored secret wallet and canonical state.
pub struct LoadedWalletSnapshot {
    /// Long-lived owner and scanning secrets recovered from the envelope.
    pub wallet: WalletSecrets,
    /// Canonical state, undo history, notes, and reconstructed witnesses.
    pub state: WalletState,
    /// Seal of the loaded snapshot, equal to the required external seal.
    pub seal: WalletSnapshotSeal,
    /// Predecessor seal embedded in the authenticated snapshot, if any.
    pub previous_seal: Option<WalletSnapshotSeal>,
}

/// Failure while saving or restoring an encrypted USDOM wallet snapshot.
#[derive(Debug, Error)]
pub enum WalletSnapshotError {
    /// Password KDF, authenticated encryption, or durable file I/O failed.
    #[error("USDOM encrypted snapshot envelope failed: {0}")]
    Envelope(#[from] EnvelopeError),
    /// Snapshot framing, counts, scalars, history, or wallet invariants failed.
    #[error("invalid canonical USDOM wallet snapshot")]
    InvalidSnapshot,
    /// Generation did not advance exactly once from the supplied predecessor.
    #[error("invalid USDOM wallet snapshot generation")]
    InvalidGeneration,
    /// Existing or loaded data does not match the externally retained seal.
    #[error("USDOM wallet snapshot rollback or substitution detected")]
    RollbackDetected,
    /// Snapshot exceeds the fixed resource bound.
    #[error("USDOM wallet snapshot exceeds configured limit")]
    SnapshotTooLarge,
    /// Passphrases must be nonblank and remain within fixed resource bounds.
    #[error("invalid USDOM wallet passphrase")]
    InvalidPassphrase,
}

impl From<WalletError> for WalletSnapshotError {
    fn from(_: WalletError) -> Self {
        Self::InvalidSnapshot
    }
}

impl WalletState {
    /// Mark one pending intent as irrevocably submission-authorized, save that
    /// exact state, and commit its seal through the external two-phase
    /// authority before issuing a network capability.
    pub fn persist_pending_transfer_for_submission<A: WalletSnapshotSealAuthority>(
        &mut self,
        wallet: &WalletSecrets,
        transition_id: Hash256,
        path: &Path,
        password: &WalletPassphrase,
        previous_seal: Option<WalletSnapshotSeal>,
        authority: &mut A,
    ) -> Result<(WalletSnapshotSeal, DurablePendingTransferPermit), DurableWalletPersistenceError>
    {
        let (seal, permit) = self.persist_pending_payload_for_submission(
            wallet,
            PendingSubmissionRequest {
                transition_id,
                kind: PendingSubmissionKind::Transfer,
                path,
                password,
                previous_seal,
            },
            authority,
        )?;
        Ok((
            seal,
            DurablePendingTransferPermit {
                transition_id: permit.transition_id,
                snapshot_seal: permit.snapshot_seal,
            },
        ))
    }

    /// Durably authorize one exact private burn before any network submission.
    pub fn persist_pending_burn_for_submission<A: WalletSnapshotSealAuthority>(
        &mut self,
        wallet: &WalletSecrets,
        transition_id: Hash256,
        path: &Path,
        password: &WalletPassphrase,
        previous_seal: Option<WalletSnapshotSeal>,
        authority: &mut A,
    ) -> Result<(WalletSnapshotSeal, DurablePendingBurnPermit), DurableWalletPersistenceError> {
        let (seal, permit) = self.persist_pending_payload_for_submission(
            wallet,
            PendingSubmissionRequest {
                transition_id,
                kind: PendingSubmissionKind::Burn,
                path,
                password,
                previous_seal,
            },
            authority,
        )?;
        Ok((
            seal,
            DurablePendingBurnPermit {
                transition_id: permit.transition_id,
                snapshot_seal: permit.snapshot_seal,
            },
        ))
    }

    fn persist_pending_payload_for_submission<A: WalletSnapshotSealAuthority>(
        &mut self,
        wallet: &WalletSecrets,
        request: PendingSubmissionRequest<'_>,
        authority: &mut A,
    ) -> Result<(WalletSnapshotSeal, DurablePendingPermitCore), DurableWalletPersistenceError> {
        let PendingSubmissionRequest {
            transition_id,
            kind,
            path,
            password,
            previous_seal,
        } = request;
        let _lock = SnapshotLock::acquire(path)?;
        let initial_authority = checked_authority_state(authority)?;
        if initial_authority.prepared.is_some() {
            return Err(DurableWalletPersistenceError::RecoveryRequired);
        }
        if initial_authority.committed != previous_seal {
            return Err(DurableWalletPersistenceError::StateMismatch);
        }
        validate_snapshot_predecessor(path, password, previous_seal)?;

        let submission_authorized = self.pending_submission_flag_mut(kind, transition_id)?;
        if *submission_authorized {
            return Err(DurableWalletPersistenceError::AlreadyAuthorized);
        }
        *submission_authorized = true;

        let generation = previous_seal.map_or(Some(1), |seal| seal.generation.checked_add(1));
        let Some(generation) = generation else {
            *self
                .pending_submission_flag_mut(kind, transition_id)
                .map_err(|_| DurableWalletPersistenceError::RecoveryRequired)? = false;
            return Err(WalletSnapshotError::InvalidGeneration.into());
        };
        let prepared = match self
            .validate_for_snapshot(wallet)
            .and_then(|()| self.encode_snapshot(wallet, generation, previous_seal))
            .and_then(|plaintext| {
                let seal = seal_for(&plaintext)?;
                Ok((plaintext, seal))
            }) {
            Ok(prepared) => prepared,
            Err(error) => {
                *self
                    .pending_submission_flag_mut(kind, transition_id)
                    .map_err(|_| DurableWalletPersistenceError::RecoveryRequired)? = false;
                return Err(error.into());
            }
        };
        let (plaintext, proposed_seal) = prepared;

        if let Err(error) = authority.prepare(previous_seal, proposed_seal) {
            let state = checked_authority_state(authority);
            if state.ok() == Some(initial_authority) {
                *self
                    .pending_submission_flag_mut(kind, transition_id)
                    .map_err(|_| DurableWalletPersistenceError::RecoveryRequired)? = false;
                return Err(error.into());
            }
            return Err(DurableWalletPersistenceError::RecoveryRequired);
        }
        if checked_authority_state(authority).ok()
            != Some(WalletSealAuthorityState {
                committed: previous_seal,
                prepared: Some(proposed_seal),
            })
        {
            return Err(DurableWalletPersistenceError::RecoveryRequired);
        }

        if save_envelope_bytes(
            path,
            ENVELOPE_MAGIC,
            ENVELOPE_VERSION,
            &plaintext,
            password.expose(),
        )
        .is_err()
        {
            // A storage error can occur after an atomic rename but before its
            // durability acknowledgement. Keep the prepared authority state;
            // recovery must inspect the actual file before commit or abort.
            return Err(DurableWalletPersistenceError::RecoveryRequired);
        }
        if authority.commit(proposed_seal).is_err()
            || checked_authority_state(authority).ok()
                != Some(WalletSealAuthorityState {
                    committed: Some(proposed_seal),
                    prepared: None,
                })
        {
            return Err(DurableWalletPersistenceError::RecoveryRequired);
        }
        Ok((
            proposed_seal,
            DurablePendingPermitCore {
                transition_id,
                snapshot_seal: proposed_seal,
            },
        ))
    }

    fn pending_submission_flag_mut(
        &mut self,
        kind: PendingSubmissionKind,
        transition_id: Hash256,
    ) -> Result<&mut bool, DurableWalletPersistenceError> {
        match kind {
            PendingSubmissionKind::Transfer => self
                .pending_transfers
                .get_mut(transition_id.as_bytes())
                .map(|pending| &mut pending.submission_authorized)
                .ok_or(DurableWalletPersistenceError::UnknownPendingTransfer),
            PendingSubmissionKind::Burn => self
                .pending_burns
                .get_mut(transition_id.as_bytes())
                .map(|pending| &mut pending.submission_authorized)
                .ok_or(DurableWalletPersistenceError::UnknownPendingBurn),
        }
    }

    /// Reconcile a crash at either side of the two-phase seal transition.
    /// The prepared seal commits when it matches the stored snapshot and
    /// aborts when the file still matches the prior committed seal.
    pub fn reconcile_encrypted_snapshot_authority<A: WalletSnapshotSealAuthority>(
        path: &Path,
        password: &WalletPassphrase,
        authority: &mut A,
    ) -> Result<Option<LoadedWalletSnapshot>, DurableWalletPersistenceError> {
        let _lock = SnapshotLock::acquire(path)?;
        let mut authority_state = checked_authority_state(authority)?;
        if let Some(prepared) = authority_state.prepared {
            if !path.exists() {
                if authority_state.committed.is_some() {
                    return Err(DurableWalletPersistenceError::StateMismatch);
                }
                authority.abort(prepared)?;
            } else {
                let plaintext = decrypt_snapshot(path, password)?;
                let stored = seal_for(&plaintext)?;
                if stored == prepared {
                    authority.commit(prepared)?;
                } else if Some(stored) == authority_state.committed {
                    authority.abort(prepared)?;
                } else {
                    return Err(DurableWalletPersistenceError::StateMismatch);
                }
            }
            authority_state = checked_authority_state(authority)?;
            if authority_state.prepared.is_some() {
                return Err(DurableWalletPersistenceError::RecoveryRequired);
            }
        }

        match (authority_state.committed, path.exists()) {
            (None, false) => Ok(None),
            (Some(expected), true) => {
                let plaintext = decrypt_snapshot(path, password)?;
                if seal_for(&plaintext)? != expected {
                    return Err(DurableWalletPersistenceError::StateMismatch);
                }
                Ok(Some(decode_snapshot(&plaintext, expected)?))
            }
            _ => Err(DurableWalletPersistenceError::StateMismatch),
        }
    }

    /// Atomically encrypt and save this wallet after comparing the existing
    /// file with `previous_seal`. The returned seal must be committed to a
    /// separate rollback-resistant authority before the next save or load.
    pub fn save_encrypted_snapshot(
        &self,
        wallet: &WalletSecrets,
        path: &Path,
        password: &WalletPassphrase,
        generation: u64,
        previous_seal: Option<WalletSnapshotSeal>,
    ) -> Result<WalletSnapshotSeal, WalletSnapshotError> {
        let _lock = SnapshotLock::acquire(path)?;
        let expected_generation = match previous_seal {
            Some(previous) => previous
                .generation
                .checked_add(1)
                .ok_or(WalletSnapshotError::InvalidGeneration)?,
            None => 1,
        };
        if generation != expected_generation {
            return Err(WalletSnapshotError::InvalidGeneration);
        }
        validate_snapshot_predecessor(path, password, previous_seal)?;
        self.validate_for_snapshot(wallet)?;
        let plaintext = self.encode_snapshot(wallet, generation, previous_seal)?;
        let seal = seal_for(&plaintext)?;
        save_envelope_bytes(
            path,
            ENVELOPE_MAGIC,
            ENVELOPE_VERSION,
            &plaintext,
            password.expose(),
        )?;
        Ok(seal)
    }

    /// Decrypt and restore only when the exact externally retained seal
    /// matches. A valid older encrypted file is therefore rejected.
    pub fn load_encrypted_snapshot(
        path: &Path,
        password: &WalletPassphrase,
        expected_seal: WalletSnapshotSeal,
    ) -> Result<LoadedWalletSnapshot, WalletSnapshotError> {
        let _lock = SnapshotLock::acquire(path)?;
        let plaintext = decrypt_snapshot(path, password)?;
        if seal_for(&plaintext)? != expected_seal {
            return Err(WalletSnapshotError::RollbackDetected);
        }
        decode_snapshot(&plaintext, expected_seal)
    }

    fn validate_for_snapshot(&self, wallet: &WalletSecrets) -> Result<(), WalletSnapshotError> {
        if wallet.chain != self.chain
            || self.commitment_log.len() != self.seen_commitments.len()
            || self.commitment_log.iter().copied().collect::<BTreeSet<_>>() != self.seen_commitments
        {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
        let indices = self
            .notes
            .iter()
            .map(|(commitment, note)| (*commitment, note.leaf_index))
            .collect::<BTreeMap<_, _>>();
        let (tree, paths) = Self::reconstruct_tree_and_paths(&self.commitment_log, &indices)?;
        if tree.root() != self.note_tree.root()
            || self.notes.iter().any(|(commitment, note)| {
                paths.get(commitment) != Some(&note.siblings)
                    || note.received.opening.chain != self.chain
                    || note
                        .received
                        .opening
                        .commitment()
                        .ok()
                        .map(|v| v.to_bytes())
                        != Some(*commitment)
                    || wallet
                        .nullifier_for(&note.received.opening)
                        .ok()
                        .map(|nullifier| self.seen_nullifiers.contains(&nullifier.to_bytes()))
                        != Some(note.spent)
            })
        {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
        validate_expected_issuances(self, wallet)?;
        validate_pending(self, wallet)?;
        validate_history(self, wallet)?;
        Ok(())
    }

    fn encode_snapshot(
        &self,
        wallet: &WalletSecrets,
        generation: u64,
        previous: Option<WalletSnapshotSeal>,
    ) -> Result<Zeroizing<Vec<u8>>, WalletSnapshotError> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(SNAPSHOT_MAGIC);
        put_u64(&mut bytes, generation);
        put_u64(&mut bytes, previous.map_or(0, |seal| seal.generation));
        bytes.extend_from_slice(
            previous
                .map(|seal| *seal.digest.as_bytes())
                .unwrap_or([0; 32])
                .as_slice(),
        );
        bytes.extend_from_slice(&self.chain.to_bytes());
        bytes.extend_from_slice(&wallet.owner_secret.to_bytes());
        bytes.extend_from_slice(&wallet.scan_secret.to_bytes());
        put_u64(&mut bytes, self.tip_height);
        bytes.extend_from_slice(self.tip_identifier.as_bytes());
        put_count(&mut bytes, self.commitment_log.len())?;
        for value in &self.commitment_log {
            bytes.extend_from_slice(value);
        }
        put_count(&mut bytes, self.notes.len())?;
        for (commitment, note) in &self.notes {
            bytes.extend_from_slice(commitment);
            put_u64(&mut bytes, note.leaf_index);
            bytes.push(note.received.output_index);
            bytes.push(note.received.opening.origin);
            put_u64(&mut bytes, note.received.opening.value);
            bytes.extend_from_slice(&note.received.opening.owner.to_bytes());
            bytes.extend_from_slice(&note.received.opening.rho.to_bytes());
            bytes.push(u8::from(note.spent));
            match note.reservation_id {
                Some(identifier) => {
                    bytes.push(1);
                    bytes.extend_from_slice(identifier.as_bytes());
                }
                None => bytes.push(0),
            }
        }
        put_count(&mut bytes, self.expected_issuances.len())?;
        for (commitment, expected) in &self.expected_issuances {
            let occurrence = expected.occurrence;
            bytes.extend_from_slice(commitment);
            bytes.extend_from_slice(&occurrence.genesis_validators_root);
            bytes.extend_from_slice(&occurrence.block_hash);
            put_u64(&mut bytes, occurrence.block_number);
            put_u64(&mut bytes, occurrence.transaction_index);
            put_u64(&mut bytes, occurrence.receipt_log_index);
            bytes.extend_from_slice(&occurrence.deposit_id);
            bytes.extend_from_slice(&occurrence.funder);
            put_u64(&mut bytes, occurrence.amount);
            bytes.extend_from_slice(&occurrence.receiving_commitment);
        }
        put_count(&mut bytes, self.pending_transfers.len())?;
        for (identifier, pending) in &self.pending_transfers {
            bytes.extend_from_slice(identifier);
            bytes.extend_from_slice(pending.anchor.root.as_bytes());
            put_u64(&mut bytes, pending.anchor.leaf_count);
            bytes.extend_from_slice(pending.created_at_tip.as_bytes());
            put_u64(&mut bytes, pending.created_at_height);
            put_list(&mut bytes, &pending.selected_commitments)?;
            put_list(&mut bytes, &pending.nullifiers)?;
            put_count(&mut bytes, pending.payload.len())?;
            bytes.extend_from_slice(&pending.payload);
            bytes.push(u8::from(pending.submission_authorized));
        }
        put_count(&mut bytes, self.pending_burns.len())?;
        for (identifier, pending) in &self.pending_burns {
            bytes.extend_from_slice(identifier);
            bytes.extend_from_slice(pending.anchor.root.as_bytes());
            put_u64(&mut bytes, pending.anchor.leaf_count);
            bytes.extend_from_slice(pending.created_at_tip.as_bytes());
            put_u64(&mut bytes, pending.created_at_height);
            put_list(&mut bytes, &pending.selected_commitments)?;
            put_list(&mut bytes, &pending.nullifiers)?;
            put_count(&mut bytes, pending.payload.len())?;
            bytes.extend_from_slice(&pending.payload);
            bytes.push(u8::from(pending.submission_authorized));
        }
        put_count(&mut bytes, self.history.len())?;
        for undo in &self.history {
            bytes.extend_from_slice(undo.identifier.as_bytes());
            bytes.extend_from_slice(undo.parent_identifier.as_bytes());
            put_u64(&mut bytes, undo.height);
            put_u64(
                &mut bytes,
                u64::try_from(undo.commitment_count_before)
                    .map_err(|_| WalletSnapshotError::SnapshotTooLarge)?,
            );
            put_list(&mut bytes, &undo.inserted_commitments)?;
            put_list(&mut bytes, &undo.inserted_nullifiers)?;
            put_list(&mut bytes, &undo.inserted_private_payloads)?;
            put_list(&mut bytes, &undo.inserted_owned_notes)?;
            put_list(&mut bytes, &undo.spent_existing_notes)?;
        }
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(WalletSnapshotError::SnapshotTooLarge);
        }
        Ok(bytes)
    }
}

impl LoadedWalletSnapshot {
    /// Reissue the capability for an already-authorized pending intent after
    /// loading the exact snapshot committed by the external authority.
    pub fn pending_transfer_submission_permit<A: WalletSnapshotSealAuthority>(
        &self,
        transition_id: Hash256,
        authority: &mut A,
    ) -> Result<DurablePendingTransferPermit, DurableWalletPersistenceError> {
        let authority_state = checked_authority_state(authority)?;
        if authority_state
            != (WalletSealAuthorityState {
                committed: Some(self.seal),
                prepared: None,
            })
        {
            return Err(DurableWalletPersistenceError::StateMismatch);
        }
        let pending = self
            .state
            .pending_transfers
            .get(transition_id.as_bytes())
            .ok_or(DurableWalletPersistenceError::UnknownPendingTransfer)?;
        if !pending.submission_authorized {
            return Err(DurableWalletPersistenceError::StateMismatch);
        }
        Ok(DurablePendingTransferPermit {
            transition_id,
            snapshot_seal: self.seal,
        })
    }

    /// Reissue a burn submission capability only from the exact committed
    /// snapshot and matching external monotonic authority state.
    pub fn pending_burn_submission_permit<A: WalletSnapshotSealAuthority>(
        &self,
        transition_id: Hash256,
        authority: &mut A,
    ) -> Result<DurablePendingBurnPermit, DurableWalletPersistenceError> {
        let authority_state = checked_authority_state(authority)?;
        if authority_state
            != (WalletSealAuthorityState {
                committed: Some(self.seal),
                prepared: None,
            })
        {
            return Err(DurableWalletPersistenceError::StateMismatch);
        }
        let pending = self
            .state
            .pending_burns
            .get(transition_id.as_bytes())
            .ok_or(DurableWalletPersistenceError::UnknownPendingBurn)?;
        if !pending.submission_authorized {
            return Err(DurableWalletPersistenceError::StateMismatch);
        }
        Ok(DurablePendingBurnPermit {
            transition_id,
            snapshot_seal: self.seal,
        })
    }
}

fn checked_authority_state<A: WalletSnapshotSealAuthority>(
    authority: &mut A,
) -> Result<WalletSealAuthorityState, WalletSealAuthorityError> {
    let state = authority.state()?;
    for seal in [state.committed, state.prepared].into_iter().flatten() {
        WalletSnapshotSeal::from_bytes(&seal.to_bytes())
            .map_err(|_| WalletSealAuthorityError::InvalidState)?;
    }
    if let Some(prepared) = state.prepared {
        let expected_generation = state
            .committed
            .map_or(Some(1), |committed| committed.generation.checked_add(1));
        if expected_generation != Some(prepared.generation) {
            return Err(WalletSealAuthorityError::InvalidState);
        }
    }
    Ok(state)
}

fn validate_snapshot_predecessor(
    path: &Path,
    password: &WalletPassphrase,
    previous_seal: Option<WalletSnapshotSeal>,
) -> Result<(), WalletSnapshotError> {
    match (path.exists(), previous_seal) {
        (false, None) => Ok(()),
        (true, Some(previous)) => {
            let current = decrypt_snapshot(path, password)?;
            if seal_for(&current)? != previous {
                return Err(WalletSnapshotError::RollbackDetected);
            }
            Ok(())
        }
        _ => Err(WalletSnapshotError::RollbackDetected),
    }
}

fn decrypt_snapshot(
    path: &Path,
    password: &WalletPassphrase,
) -> Result<Zeroizing<Vec<u8>>, WalletSnapshotError> {
    load_envelope_bytes(
        path,
        ENVELOPE_MAGIC,
        ENVELOPE_VERSION,
        MAX_SNAPSHOT_BYTES,
        password.expose(),
    )
    .map_err(WalletSnapshotError::from)
}

fn seal_for(bytes: &[u8]) -> Result<WalletSnapshotSeal, WalletSnapshotError> {
    if bytes.len() < 16 || &bytes[..8] != SNAPSHOT_MAGIC {
        return Err(WalletSnapshotError::InvalidSnapshot);
    }
    let generation = u64::from_be_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| WalletSnapshotError::InvalidSnapshot)?,
    );
    if generation == 0 {
        return Err(WalletSnapshotError::InvalidGeneration);
    }
    let digest = blake2b_256_tagged(SNAPSHOT_DIGEST_TAG, bytes);
    if digest == Hash256::ZERO {
        return Err(WalletSnapshotError::InvalidSnapshot);
    }
    Ok(WalletSnapshotSeal { generation, digest })
}

fn decode_snapshot(
    bytes: &[u8],
    seal: WalletSnapshotSeal,
) -> Result<LoadedWalletSnapshot, WalletSnapshotError> {
    let mut reader = Reader::new(bytes);
    if reader.take(8)? != SNAPSHOT_MAGIC {
        return Err(WalletSnapshotError::InvalidSnapshot);
    }
    let generation = reader.u64()?;
    if generation != seal.generation {
        return Err(WalletSnapshotError::RollbackDetected);
    }
    let previous_generation = reader.u64()?;
    let previous_digest = Hash256::from_bytes(reader.array()?);
    let previous_seal = match (previous_generation, previous_digest == Hash256::ZERO) {
        (0, true) => None,
        (0, false) | (_, true) => return Err(WalletSnapshotError::InvalidSnapshot),
        (value, false) if value.checked_add(1) == Some(generation) => Some(WalletSnapshotSeal {
            generation: value,
            digest: previous_digest,
        }),
        _ => return Err(WalletSnapshotError::InvalidGeneration),
    };
    if generation == 1 && previous_seal.is_some() || generation > 1 && previous_seal.is_none() {
        return Err(WalletSnapshotError::InvalidGeneration);
    }
    let chain =
        Scalar::from_bytes(reader.array()?).map_err(|_| WalletSnapshotError::InvalidSnapshot)?;
    let mut owner_secret: [u8; 32] = reader.array()?;
    let mut scan_secret: [u8; 32] = reader.array()?;
    let wallet = WalletSecrets::from_bytes(chain, owner_secret, scan_secret)
        .map_err(|_| WalletSnapshotError::InvalidSnapshot);
    owner_secret.zeroize();
    scan_secret.zeroize();
    let wallet = wallet?;
    let tip_height = reader.u64()?;
    let tip_identifier = Hash256::from_bytes(reader.array()?);
    if tip_identifier == Hash256::ZERO {
        return Err(WalletSnapshotError::InvalidSnapshot);
    }
    let commitment_count = reader.count()?;
    let mut commitment_log = Vec::with_capacity(commitment_count);
    let mut seen_commitments = BTreeSet::new();
    for _ in 0..commitment_count {
        let value: [u8; 32] = reader.array()?;
        let scalar = Scalar::from_bytes(value).map_err(|_| WalletSnapshotError::InvalidSnapshot)?;
        if scalar.is_zero() || !seen_commitments.insert(value) {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
        commitment_log.push(value);
    }
    let note_count = reader.count()?;
    let mut notes = BTreeMap::new();
    for _ in 0..note_count {
        let commitment: [u8; 32] = reader.array()?;
        let leaf_index = reader.u64()?;
        let output_index = reader.u8()?;
        let origin = reader.u8()?;
        let value = reader.u64()?;
        let owner = Scalar::from_bytes(reader.array()?)
            .map_err(|_| WalletSnapshotError::InvalidSnapshot)?;
        let rho = Scalar::from_bytes(reader.array()?)
            .map_err(|_| WalletSnapshotError::InvalidSnapshot)?;
        let spent = match reader.u8()? {
            0 => false,
            1 => true,
            _ => return Err(WalletSnapshotError::InvalidSnapshot),
        };
        let reservation_id = match reader.u8()? {
            0 => None,
            1 => Some(Hash256::from_bytes(reader.array()?)),
            _ => return Err(WalletSnapshotError::InvalidSnapshot),
        };
        let opening = NoteOpening {
            chain,
            origin,
            value,
            owner,
            rho,
        };
        let parsed_commitment = opening
            .commitment()
            .map_err(|_| WalletSnapshotError::InvalidSnapshot)?;
        if output_index >= super::MAX_MEMO_OUTPUTS as u8
            || parsed_commitment.to_bytes() != commitment
            || wallet.nullifier_for(&opening).is_err()
            || notes
                .insert(
                    commitment,
                    TrackedNote {
                        received: ReceivedNote {
                            output_index,
                            commitment: parsed_commitment,
                            opening,
                        },
                        leaf_index,
                        siblings: [Scalar::ZERO; dom_usdom_privacy::NOTE_TREE_DEPTH],
                        spent,
                        reservation_id,
                    },
                )
                .is_some()
        {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
    }
    let expected_issuance_count = reader.count()?;
    let mut expected_issuances = BTreeMap::new();
    for _ in 0..expected_issuance_count {
        let commitment: [u8; 32] = reader.array()?;
        let occurrence = EthereumDepositOccurrence {
            genesis_validators_root: reader.array()?,
            block_hash: reader.array()?,
            block_number: reader.u64()?,
            transaction_index: reader.u64()?,
            receipt_log_index: reader.u64()?,
            deposit_id: reader.array()?,
            funder: reader.array()?,
            amount: reader.u64()?,
            receiving_commitment: reader.array()?,
        };
        let owner = Scalar::from_bytes(occurrence.receiving_commitment)
            .map_err(|_| WalletSnapshotError::InvalidSnapshot)?;
        let opening = NoteOpening {
            chain,
            origin: NOTE_ORIGIN_ISSUANCE,
            value: occurrence.amount,
            owner,
            rho: occurrence
                .issuance_rho()
                .map_err(|_| WalletSnapshotError::InvalidSnapshot)?,
        };
        if opening
            .commitment()
            .map_err(|_| WalletSnapshotError::InvalidSnapshot)?
            .to_bytes()
            != commitment
            || expected_issuances
                .insert(
                    commitment,
                    ExpectedIssuance {
                        occurrence,
                        opening,
                    },
                )
                .is_some()
        {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
    }
    let pending_count = reader.count()?;
    let mut pending_transfers = BTreeMap::new();
    for _ in 0..pending_count {
        let identifier: [u8; 32] = reader.array()?;
        let pending = PendingPrivateTransfer {
            anchor: dom_usdom_state::NoteAnchor {
                root: Hash256::from_bytes(reader.array()?),
                leaf_count: reader.u64()?,
            },
            created_at_tip: Hash256::from_bytes(reader.array()?),
            created_at_height: reader.u64()?,
            selected_commitments: reader.list()?,
            nullifiers: reader.list()?,
            payload: {
                let length = reader.count()?;
                reader.take(length)?.to_vec()
            },
            submission_authorized: match reader.u8()? {
                0 => false,
                1 => true,
                _ => return Err(WalletSnapshotError::InvalidSnapshot),
            },
        };
        if pending_transfers.insert(identifier, pending).is_some() {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
    }
    let pending_burn_count = reader.count()?;
    let mut pending_burns = BTreeMap::new();
    for _ in 0..pending_burn_count {
        let identifier: [u8; 32] = reader.array()?;
        let anchor = dom_usdom_state::NoteAnchor {
            root: Hash256::from_bytes(reader.array()?),
            leaf_count: reader.u64()?,
        };
        let created_at_tip = Hash256::from_bytes(reader.array()?);
        let created_at_height = reader.u64()?;
        let selected_commitments = reader.list()?;
        let nullifiers = reader.list()?;
        let payload = {
            let length = reader.count()?;
            reader.take(length)?.to_vec()
        };
        let submission_authorized = match reader.u8()? {
            0 => false,
            1 => true,
            _ => return Err(WalletSnapshotError::InvalidSnapshot),
        };
        let record = inspect_private_burn_record(&payload)
            .map_err(|_| WalletSnapshotError::InvalidSnapshot)?;
        let pending = PendingPrivateBurn {
            anchor,
            created_at_tip,
            created_at_height,
            selected_commitments,
            nullifiers,
            payload,
            record,
            submission_authorized,
        };
        if pending_burns.insert(identifier, pending).is_some() {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
    }
    let history_count = reader.count()?;
    let mut history = Vec::with_capacity(history_count);
    for _ in 0..history_count {
        history.push(WalletBlockUndo {
            identifier: Hash256::from_bytes(reader.array()?),
            parent_identifier: Hash256::from_bytes(reader.array()?),
            height: reader.u64()?,
            commitment_count_before: usize::try_from(reader.u64()?)
                .map_err(|_| WalletSnapshotError::InvalidSnapshot)?,
            inserted_commitments: reader.list()?,
            inserted_nullifiers: reader.list()?,
            inserted_private_payloads: reader.list()?,
            inserted_owned_notes: reader.list()?,
            spent_existing_notes: reader.list()?,
        });
    }
    if !reader.is_empty() {
        return Err(WalletSnapshotError::InvalidSnapshot);
    }
    let indices = notes
        .iter()
        .map(|(commitment, note)| (*commitment, note.leaf_index))
        .collect::<BTreeMap<_, _>>();
    let (note_tree, paths) = WalletState::reconstruct_tree_and_paths(&commitment_log, &indices)?;
    for (commitment, siblings) in paths {
        notes
            .get_mut(&commitment)
            .ok_or(WalletSnapshotError::InvalidSnapshot)?
            .siblings = siblings;
    }
    let seen_nullifiers = history
        .iter()
        .flat_map(|undo| undo.inserted_nullifiers.iter().copied())
        .collect::<BTreeSet<_>>();
    let seen_private_payloads = history
        .iter()
        .flat_map(|undo| undo.inserted_private_payloads.iter().copied())
        .collect::<BTreeSet<_>>();
    let state = WalletState {
        chain,
        tip_height,
        tip_identifier,
        note_tree,
        commitment_log,
        seen_commitments,
        seen_nullifiers,
        seen_private_payloads,
        notes,
        expected_issuances,
        pending_transfers,
        pending_burns,
        history,
    };
    state.validate_for_snapshot(&wallet)?;
    Ok(LoadedWalletSnapshot {
        wallet,
        state,
        seal,
        previous_seal,
    })
}

fn validate_history(
    state: &WalletState,
    wallet: &WalletSecrets,
) -> Result<(), WalletSnapshotError> {
    if state.history.is_empty() {
        return if state.commitment_log.is_empty()
            && state.seen_nullifiers.is_empty()
            && state.seen_private_payloads.is_empty()
            && state.notes.is_empty()
        {
            Ok(())
        } else {
            Err(WalletSnapshotError::InvalidSnapshot)
        };
    }
    let mut commitment_count = 0usize;
    let mut prior_identifier = state.history[0].parent_identifier;
    let mut prior_height = state.history[0]
        .height
        .checked_sub(1)
        .ok_or(WalletSnapshotError::InvalidSnapshot)?;
    let mut nullifiers = BTreeSet::new();
    let mut private_payloads = BTreeSet::new();
    let mut owned_notes = BTreeSet::new();
    for undo in &state.history {
        let commitment_count_after = undo
            .commitment_count_before
            .checked_add(undo.inserted_commitments.len())
            .ok_or(WalletSnapshotError::InvalidSnapshot)?;
        if undo.identifier == Hash256::ZERO
            || undo.parent_identifier != prior_identifier
            || undo.height
                != prior_height
                    .checked_add(1)
                    .ok_or(WalletSnapshotError::InvalidSnapshot)?
            || undo.commitment_count_before != commitment_count
            || undo.inserted_commitments.len()
                > super::MAX_TRANSITIONS_PER_BATCH * super::MAX_OUTPUT_NOTES
            || undo.inserted_nullifiers.len()
                > super::MAX_TRANSITIONS_PER_BATCH * super::MAX_INPUT_NULLIFIERS
            || undo.inserted_private_payloads.len() > super::MAX_TRANSITIONS_PER_BATCH
            || undo.inserted_owned_notes.len() > undo.inserted_commitments.len()
            || undo.spent_existing_notes.len() > undo.inserted_nullifiers.len()
            || undo
                .inserted_owned_notes
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || undo
                .spent_existing_notes
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || undo
                .inserted_owned_notes
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != undo.inserted_owned_notes.len()
            || undo
                .spent_existing_notes
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != undo.spent_existing_notes.len()
            || commitment_count
                .checked_add(undo.inserted_commitments.len())
                .ok_or(WalletSnapshotError::InvalidSnapshot)?
                > state.commitment_log.len()
            || state.commitment_log
                [commitment_count..commitment_count + undo.inserted_commitments.len()]
                != undo.inserted_commitments
            || undo.inserted_owned_notes.iter().any(|value| {
                !state.notes.contains_key(value)
                    || !undo.inserted_commitments.contains(value)
                    || !owned_notes.insert(*value)
            })
            || undo.spent_existing_notes.iter().any(|value| {
                state
                    .notes
                    .get(value)
                    .map(|note| note.leaf_index as usize)
                    .is_none_or(|index| index >= undo.commitment_count_before)
            })
            || undo.spent_existing_notes.iter().any(|commitment| {
                state.notes.get(commitment).is_none_or(|note| {
                    wallet
                        .nullifier_for(&note.received.opening)
                        .map(|value| !undo.inserted_nullifiers.contains(&value.to_bytes()))
                        .unwrap_or(true)
                })
            })
            || state.notes.iter().any(|(commitment, note)| {
                let Ok(nullifier) = wallet.nullifier_for(&note.received.opening) else {
                    return true;
                };
                if !undo.inserted_nullifiers.contains(&nullifier.to_bytes()) {
                    return false;
                }
                let leaf_index = note.leaf_index as usize;
                if leaf_index < undo.commitment_count_before {
                    !undo.spent_existing_notes.contains(commitment)
                } else if leaf_index < commitment_count_after {
                    !undo.inserted_owned_notes.contains(commitment)
                        || undo.spent_existing_notes.contains(commitment)
                } else {
                    true
                }
            })
            || undo
                .inserted_nullifiers
                .iter()
                .any(|value| *value == [0; 32] || !nullifiers.insert(*value))
            || undo
                .inserted_private_payloads
                .iter()
                .any(|value| *value == [0; 32] || !private_payloads.insert(*value))
        {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
        commitment_count += undo.inserted_commitments.len();
        prior_identifier = undo.identifier;
        prior_height = undo.height;
    }
    if commitment_count != state.commitment_log.len()
        || nullifiers != state.seen_nullifiers
        || private_payloads != state.seen_private_payloads
        || owned_notes != state.notes.keys().copied().collect()
        || prior_identifier != state.tip_identifier
        || prior_height != state.tip_height
    {
        return Err(WalletSnapshotError::InvalidSnapshot);
    }
    Ok(())
}

fn validate_expected_issuances(
    state: &WalletState,
    wallet: &WalletSecrets,
) -> Result<(), WalletSnapshotError> {
    let owner = wallet
        .address()
        .map_err(|_| WalletSnapshotError::InvalidSnapshot)?
        .owner();
    let mut deposit_ids = BTreeSet::new();
    for (commitment, expected) in &state.expected_issuances {
        let occurrence = expected.occurrence;
        if !deposit_ids.insert(occurrence.deposit_id)
            || expected.opening.chain != state.chain
            || expected.opening.origin != NOTE_ORIGIN_ISSUANCE
            || expected.opening.value != occurrence.amount
            || expected.opening.owner != owner
            || occurrence.receiving_commitment != owner.to_bytes()
            || expected.opening.rho
                != occurrence
                    .issuance_rho()
                    .map_err(|_| WalletSnapshotError::InvalidSnapshot)?
            || expected
                .opening
                .commitment()
                .map_err(|_| WalletSnapshotError::InvalidSnapshot)?
                .to_bytes()
                != *commitment
            || state.seen_commitments.contains(commitment) != state.notes.contains_key(commitment)
        {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
        if let Some(note) = state.notes.get(commitment) {
            if note
                .received
                .opening
                .commitment()
                .ok()
                .map(|value| value.to_bytes())
                != Some(*commitment)
                || note.received.opening.origin != NOTE_ORIGIN_ISSUANCE
            {
                return Err(WalletSnapshotError::InvalidSnapshot);
            }
        }
    }
    Ok(())
}

fn validate_pending(
    state: &WalletState,
    wallet: &WalletSecrets,
) -> Result<(), WalletSnapshotError> {
    let mut reserved = BTreeMap::<[u8; 32], [u8; 32]>::new();
    for (commitment, note) in &state.notes {
        if let Some(identifier) = note.reservation_id {
            if identifier == Hash256::ZERO
                || reserved
                    .insert(*commitment, *identifier.as_bytes())
                    .is_some()
            {
                return Err(WalletSnapshotError::InvalidSnapshot);
            }
        }
    }
    let mut expected_reserved = BTreeMap::new();
    for (identifier, pending) in &state.pending_transfers {
        if *identifier == [0; 32]
            || private_transfer_payload_id(&pending.payload).as_bytes() != identifier
            || pending.anchor.root == Hash256::ZERO
            || pending.anchor.leaf_count == 0
            || pending.created_at_tip == Hash256::ZERO
            || pending.selected_commitments.is_empty()
            || pending.selected_commitments.len() > 2
            || pending.nullifiers.len() != pending.selected_commitments.len()
            || !pending.nullifiers.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
        let observed = inspect_private_transfer_outputs(&pending.payload)
            .map_err(|_| WalletSnapshotError::InvalidSnapshot)?;
        if observed.nullifiers != pending.nullifiers {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
        let mut derived = Vec::with_capacity(pending.selected_commitments.len());
        for commitment in &pending.selected_commitments {
            if expected_reserved.insert(*commitment, *identifier).is_some() {
                return Err(WalletSnapshotError::InvalidSnapshot);
            }
            if let Some(note) = state.notes.get(commitment) {
                if note.reservation_id.as_ref().map(Hash256::as_bytes) != Some(identifier) {
                    return Err(WalletSnapshotError::InvalidSnapshot);
                }
                derived.push(
                    wallet
                        .nullifier_for(&note.received.opening)
                        .map_err(|_| WalletSnapshotError::InvalidSnapshot)?
                        .to_bytes(),
                );
            }
        }
        derived.sort_unstable();
        if !derived
            .iter()
            .all(|nullifier| pending.nullifiers.binary_search(nullifier).is_ok())
        {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
    }
    for (identifier, pending) in &state.pending_burns {
        if *identifier == [0; 32]
            || private_burn_payload_id(&pending.payload).as_bytes() != identifier
            || pending.anchor.root == Hash256::ZERO
            || pending.anchor.leaf_count == 0
            || pending.created_at_tip == Hash256::ZERO
            || pending.selected_commitments.is_empty()
            || pending.selected_commitments.len() > 2
            || pending.nullifiers.len() != pending.selected_commitments.len()
            || !pending.nullifiers.windows(2).all(|pair| pair[0] < pair[1])
            || inspect_private_burn_record(&pending.payload).ok() != Some(pending.record)
        {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
        let observed = inspect_private_burn_outputs(&pending.payload)
            .map_err(|_| WalletSnapshotError::InvalidSnapshot)?;
        if observed.nullifiers != pending.nullifiers {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
        let mut derived = Vec::with_capacity(pending.selected_commitments.len());
        for commitment in &pending.selected_commitments {
            if expected_reserved.insert(*commitment, *identifier).is_some() {
                return Err(WalletSnapshotError::InvalidSnapshot);
            }
            if let Some(note) = state.notes.get(commitment) {
                if note.reservation_id.as_ref().map(Hash256::as_bytes) != Some(identifier) {
                    return Err(WalletSnapshotError::InvalidSnapshot);
                }
                derived.push(
                    wallet
                        .nullifier_for(&note.received.opening)
                        .map_err(|_| WalletSnapshotError::InvalidSnapshot)?
                        .to_bytes(),
                );
            }
        }
        derived.sort_unstable();
        if !derived
            .iter()
            .all(|nullifier| pending.nullifiers.binary_search(nullifier).is_ok())
        {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
    }
    if reserved
        .iter()
        .any(|(commitment, identifier)| expected_reserved.get(commitment) != Some(identifier))
        || expected_reserved.iter().any(|(commitment, identifier)| {
            state.notes.contains_key(commitment) && reserved.get(commitment) != Some(identifier)
        })
    {
        return Err(WalletSnapshotError::InvalidSnapshot);
    }
    Ok(())
}

struct SnapshotLock {
    file: File,
}

impl SnapshotLock {
    fn acquire(snapshot: &Path) -> Result<Self, WalletSnapshotError> {
        let file_name = snapshot
            .file_name()
            .ok_or(WalletSnapshotError::InvalidSnapshot)?;
        let mut lock_name = file_name.to_os_string();
        lock_name.push(".lock");
        let lock_path = snapshot.with_file_name(lock_name);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&lock_path)
            .map_err(|error| EnvelopeError::Io(format!("failed to open snapshot lock: {error}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let retained = file.metadata().map_err(|error| {
                EnvelopeError::Io(format!("failed to inspect snapshot lock: {error}"))
            })?;
            let named = std::fs::symlink_metadata(&lock_path).map_err(|error| {
                EnvelopeError::Io(format!("failed to inspect named snapshot lock: {error}"))
            })?;
            if !retained.file_type().is_file()
                || !named.file_type().is_file()
                || named.file_type().is_symlink()
                || retained.mode() & 0o7777 != 0o600
                || retained.nlink() != 1
                || retained.dev() != named.dev()
                || retained.ino() != named.ino()
            {
                return Err(EnvelopeError::Io("invalid snapshot lock authority".to_owned()).into());
            }
        }
        file.lock_exclusive().map_err(|error| {
            EnvelopeError::Io(format!("failed to acquire snapshot lock: {error}"))
        })?;
        Ok(Self { file })
    }
}

impl Drop for SnapshotLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_count(bytes: &mut Vec<u8>, count: usize) -> Result<(), WalletSnapshotError> {
    if count > MAX_SNAPSHOT_ITEMS {
        return Err(WalletSnapshotError::SnapshotTooLarge);
    }
    put_u64(
        bytes,
        u64::try_from(count).map_err(|_| WalletSnapshotError::SnapshotTooLarge)?,
    );
    Ok(())
}

fn put_list(bytes: &mut Vec<u8>, values: &[[u8; 32]]) -> Result<(), WalletSnapshotError> {
    put_count(bytes, values.len())?;
    for value in values {
        bytes.extend_from_slice(value);
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], WalletSnapshotError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(WalletSnapshotError::InvalidSnapshot)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(WalletSnapshotError::InvalidSnapshot)?;
        self.offset = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], WalletSnapshotError> {
        self.take(N)?
            .try_into()
            .map_err(|_| WalletSnapshotError::InvalidSnapshot)
    }
    fn u8(&mut self) -> Result<u8, WalletSnapshotError> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64, WalletSnapshotError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn count(&mut self) -> Result<usize, WalletSnapshotError> {
        let value =
            usize::try_from(self.u64()?).map_err(|_| WalletSnapshotError::InvalidSnapshot)?;
        if value > MAX_SNAPSHOT_ITEMS {
            return Err(WalletSnapshotError::SnapshotTooLarge);
        }
        Ok(value)
    }
    fn list(&mut self) -> Result<Vec<[u8; 32]>, WalletSnapshotError> {
        let count = self.count()?;
        if count > self.bytes.len().saturating_sub(self.offset) / 32 {
            return Err(WalletSnapshotError::InvalidSnapshot);
        }
        (0..count).map(|_| self.array()).collect()
    }
    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use dom_usdom_privacy::{chain_scalar, privacy_policy_hash};
    use dom_usdom_state::{
        encode_private_transfer_payload, unsafe_test_only_transfer, NoteAnchor, VerifiedTransition,
    };
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    use crate::{encrypt_outputs, CanonicalWalletBlock, MemoOutput, WalletTransitionObservation};

    fn passphrase(value: &str) -> WalletPassphrase {
        WalletPassphrase::new(value.to_owned()).unwrap()
    }

    struct TestAuthority {
        state: WalletSealAuthorityState,
    }

    impl WalletSnapshotSealAuthority for TestAuthority {
        fn state(&mut self) -> Result<WalletSealAuthorityState, WalletSealAuthorityError> {
            Ok(self.state)
        }

        fn prepare(
            &mut self,
            expected: Option<WalletSnapshotSeal>,
            proposed: WalletSnapshotSeal,
        ) -> Result<(), WalletSealAuthorityError> {
            if self.state.committed != expected || self.state.prepared.is_some() {
                return Err(WalletSealAuthorityError::Conflict);
            }
            self.state.prepared = Some(proposed);
            Ok(())
        }

        fn commit(&mut self, proposed: WalletSnapshotSeal) -> Result<(), WalletSealAuthorityError> {
            if self.state.prepared != Some(proposed) {
                return Err(WalletSealAuthorityError::Conflict);
            }
            self.state.committed = Some(proposed);
            self.state.prepared = None;
            Ok(())
        }

        fn abort(&mut self, proposed: WalletSnapshotSeal) -> Result<(), WalletSealAuthorityError> {
            if self.state.prepared != Some(proposed) {
                return Err(WalletSealAuthorityError::Conflict);
            }
            self.state.prepared = None;
            Ok(())
        }
    }

    fn scalar(value: u64) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Scalar::from_bytes(bytes).unwrap()
    }

    fn state_with_owned_note() -> (WalletSecrets, WalletState, Hash256, Scalar) {
        let domain = [0xbb; 32];
        let chain = chain_scalar(domain, *privacy_policy_hash().as_bytes());
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_5350);
        let wallet = WalletSecrets::generate(chain, &mut rng).unwrap();
        let encrypted = encrypt_outputs(
            chain,
            vec![MemoOutput {
                recipient: wallet.address().unwrap(),
                value: 29,
                rho: scalar(61),
            }],
            &mut rng,
        )
        .unwrap();
        let anchor = NoteAnchor {
            root: Hash256::from_bytes(scalar(62).to_bytes()),
            leaf_count: 1,
        };
        let nullifier = scalar(63).to_bytes();
        let commitment = encrypted.commitments()[0];
        let payload = encode_private_transfer_payload(
            anchor,
            &[nullifier],
            &[commitment.to_bytes()],
            encrypted.memo(),
            &[0; 128],
        )
        .unwrap();
        let verified = VerifiedTransition::Transfer(unsafe_test_only_transfer(
            domain,
            anchor,
            vec![nullifier],
            vec![commitment.to_bytes()],
            dom_usdom_privacy::memo_scalar(encrypted.memo())
                .unwrap()
                .to_bytes(),
        ));
        let observation =
            WalletTransitionObservation::from_verified(&verified, Some(&payload)).unwrap();
        let initial = Hash256::from_bytes([0x31; 32]);
        let tip = Hash256::from_bytes([0x32; 32]);
        let mut state = WalletState::new_empty(chain, 40, initial).unwrap();
        state
            .apply_block(
                &wallet,
                CanonicalWalletBlock {
                    height: 41,
                    identifier: tip,
                    parent_identifier: initial,
                    transitions: vec![observation],
                },
            )
            .unwrap();
        (wallet, state, initial, commitment)
    }

    #[test]
    fn wallet_passphrase_is_owned_bounded_and_rejects_blank_input() {
        assert!(matches!(
            WalletPassphrase::new("x".repeat(MIN_WALLET_PASSPHRASE_BYTES - 1)),
            Err(WalletSnapshotError::InvalidPassphrase)
        ));
        assert!(WalletPassphrase::new("x".repeat(MIN_WALLET_PASSPHRASE_BYTES)).is_ok());
        assert!(WalletPassphrase::new("x".repeat(MAX_WALLET_PASSPHRASE_BYTES)).is_ok());
        assert!(matches!(
            WalletPassphrase::new("x".repeat(MAX_WALLET_PASSPHRASE_BYTES + 1)),
            Err(WalletSnapshotError::InvalidPassphrase)
        ));
        assert!(matches!(
            WalletPassphrase::new(" ".repeat(MIN_WALLET_PASSPHRASE_BYTES)),
            Err(WalletSnapshotError::InvalidPassphrase)
        ));
    }

    #[test]
    fn encrypted_snapshot_roundtrips_reorg_state_and_rejects_old_file() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = directory.path().join("wallet.usdom");
        let password = passphrase("test-only high entropy wallet password");
        let (wallet, state, initial, commitment) = state_with_owned_note();
        let root = state.note_root();
        let address = wallet.address().unwrap();

        let seal1 = state
            .save_encrypted_snapshot(&wallet, &path, &password, 1, None)
            .unwrap();
        assert_eq!(
            WalletSnapshotSeal::from_bytes(&seal1.to_bytes()).unwrap(),
            seal1
        );
        let generation1_file = fs::read(&path).unwrap();
        let loaded1 = WalletState::load_encrypted_snapshot(&path, &password, seal1).unwrap();
        assert_eq!(loaded1.wallet.address().unwrap(), address);
        assert_eq!(loaded1.state.tip_height(), 41);
        assert_eq!(loaded1.state.note_root(), root);
        assert_eq!(loaded1.state.available_balance(), 29);
        assert_eq!(
            loaded1
                .state
                .spend_witness(&loaded1.wallet, commitment)
                .unwrap()
                .value,
            29
        );

        let seal2 = loaded1
            .state
            .save_encrypted_snapshot(&loaded1.wallet, &path, &password, 2, Some(seal1))
            .unwrap();
        assert_ne!(seal1.digest, seal2.digest);
        let generation2_file = fs::read(&path).unwrap();
        let mut loaded2 = WalletState::load_encrypted_snapshot(&path, &password, seal2).unwrap();
        assert_eq!(loaded2.previous_seal, Some(seal1));
        loaded2
            .state
            .rollback_tip(Hash256::from_bytes([0x32; 32]))
            .unwrap();
        assert_eq!(loaded2.state.tip_identifier(), initial);
        assert_eq!(loaded2.state.available_balance(), 0);

        fs::write(&path, &generation1_file).unwrap();
        assert!(matches!(
            WalletState::load_encrypted_snapshot(&path, &password, seal2),
            Err(WalletSnapshotError::RollbackDetected)
        ));
        fs::write(&path, &generation2_file).unwrap();
        assert!(matches!(
            state.save_encrypted_snapshot(&wallet, &path, &password, 2, Some(seal1)),
            Err(WalletSnapshotError::RollbackDetected)
        ));
        assert!(matches!(
            WalletState::load_encrypted_snapshot(
                &path,
                &passphrase("wrong password but long enough"),
                seal2
            ),
            Err(WalletSnapshotError::Envelope(EnvelopeError::Decryption))
        ));

        let mut tampered = generation2_file;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        fs::write(&path, tampered).unwrap();
        assert!(matches!(
            WalletState::load_encrypted_snapshot(&path, &password, seal2),
            Err(WalletSnapshotError::Envelope(EnvelopeError::Decryption))
        ));
    }

    #[test]
    fn canonical_snapshot_decoder_rejects_every_truncation_and_trailing_byte() {
        let (wallet, state, _, _) = state_with_owned_note();
        let plaintext = state.encode_snapshot(&wallet, 1, None).unwrap();
        for end in 0..plaintext.len() {
            let truncated = &plaintext[..end];
            if let Ok(seal) = seal_for(truncated) {
                assert!(
                    decode_snapshot(truncated, seal).is_err(),
                    "accepted truncation at {end}"
                );
            }
        }
        let mut trailing = Zeroizing::new(plaintext.to_vec());
        trailing.push(0);
        let trailing_seal = seal_for(&trailing).unwrap();
        assert!(decode_snapshot(&trailing, trailing_seal).is_err());
    }

    #[test]
    fn two_phase_authority_recovery_commits_new_file_or_aborts_old_file() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = directory.path().join("wallet.usdom");
        let password = passphrase("test-only two-phase recovery password");
        let (wallet, state, _, _) = state_with_owned_note();
        let seal1 = state
            .save_encrypted_snapshot(&wallet, &path, &password, 1, None)
            .unwrap();
        let plaintext2 = state.encode_snapshot(&wallet, 2, Some(seal1)).unwrap();
        let seal2 = seal_for(&plaintext2).unwrap();

        let mut authority = TestAuthority {
            state: WalletSealAuthorityState {
                committed: Some(seal1),
                prepared: Some(seal2),
            },
        };
        let old =
            WalletState::reconcile_encrypted_snapshot_authority(&path, &password, &mut authority)
                .unwrap()
                .unwrap();
        assert_eq!(old.seal, seal1);
        assert_eq!(authority.state.committed, Some(seal1));
        assert_eq!(authority.state.prepared, None);

        authority.prepare(Some(seal1), seal2).unwrap();
        save_envelope_bytes(
            &path,
            ENVELOPE_MAGIC,
            ENVELOPE_VERSION,
            &plaintext2,
            password.expose(),
        )
        .unwrap();
        let new =
            WalletState::reconcile_encrypted_snapshot_authority(&path, &password, &mut authority)
                .unwrap()
                .unwrap();
        assert_eq!(new.seal, seal2);
        assert_eq!(authority.state.committed, Some(seal2));
        assert_eq!(authority.state.prepared, None);

        authority.state.prepared = Some(WalletSnapshotSeal {
            generation: 4,
            digest: Hash256::from_bytes([0x77; 32]),
        });
        assert_eq!(
            checked_authority_state(&mut authority),
            Err(WalletSealAuthorityError::InvalidState)
        );
    }
}
