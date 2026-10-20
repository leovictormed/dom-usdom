//! Offline recipient addressing, authenticated memo encryption, and note scanning
//! for native USDOM.
//!
//! This crate is deliberately absent from the node dependency graph. Consensus
//! commits the returned memo bytes through the spend proof; wallets encrypt note
//! openings to recipient scan keys and independently recompute each public note
//! commitment after decryption.
//!
//! Long-lived owner and scanning keys may be derived from one opaque recovery
//! seed. Recovery expansion is chain- and purpose-separated with HKDF-SHA256;
//! the seed's only persistence API uses the shared Argon2id+AEAD wallet envelope.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use dom_core::Hash256;
use dom_usdom_privacy::{
    circuit::InputWitness, memo_scalar, owner_commitment, privacy_policy_hash, verify_membership,
    IncrementalNoteTree, NoteOpening, PrivacyError, Scalar, NOTE_ORIGIN_PRIVATE, NOTE_TREE_DEPTH,
};
use dom_usdom_state::{
    ethereum_deposit_note_opening, inspect_private_burn_outputs, inspect_private_transfer_outputs,
    private_burn_payload_id, private_transfer_payload_id, BridgeIdentity,
    EthereumDepositOccurrence, TransitionCommitmentProjection, TransitionKind,
    TransitionPublicEffects, VerifiedTransition, MAX_INPUT_NULLIFIERS, MAX_OUTPUT_NOTES,
    MAX_TRANSITIONS_PER_BATCH,
};
use dom_wallet_crypto::{load_envelope_bytes, save_envelope_bytes_noclobber, EnvelopeError};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod builder;
mod burn_builder;
#[cfg(feature = "rpc-client")]
mod rpc_client;
mod snapshot;

pub use builder::{BuiltPrivateTransfer, PendingPrivateTransferSummary, PrivateTransferBuildError};
pub use burn_builder::{
    BuiltPrivateBurn, PendingPrivateBurnSummary, PrivateBurnBuildError, PrivateBurnRequest,
};
#[cfg(feature = "rpc-client")]
pub use rpc_client::{
    AuthenticatedHistoryAnchor, AuthenticatedHistoryRequest, AuthenticatedHistoryScan,
    CanonicalPrivateBurnInclusion, CanonicalPrivateTransferInclusion, PrivateBurnScanPage,
    PrivateBurnScanRequest, PrivateBurnSubmission, PrivateTransferScanPage,
    PrivateTransferScanRequest, PrivateTransferSubmission, RemoteHistoricalDepositRecoveryError,
    UsdomRpcClient, UsdomRpcClientError, V2CandidateSubmission, VerifiedCheckpointHistoryAnchor,
    VerifiedCheckpointHistoryScan,
};
pub use snapshot::{
    DurablePendingBurnPermit, DurablePendingTransferPermit, DurableWalletPersistenceError,
    LoadedWalletSnapshot, WalletPassphrase, WalletSealAuthorityError, WalletSealAuthorityState,
    WalletSnapshotError, WalletSnapshotSeal, WalletSnapshotSealAuthority,
    MAX_WALLET_PASSPHRASE_BYTES, MIN_WALLET_PASSPHRASE_BYTES, WALLET_SNAPSHOT_SEAL_BYTES,
};

const ADDRESS_MAGIC: &[u8; 8] = b"USDADR01";
const RECOVERY_ENVELOPE_MAGIC: &[u8; 14] = b"USD-RECOVERY1\0";
const RECOVERY_ENVELOPE_VERSION: u16 = 1;
const RECOVERY_PLAINTEXT_BYTES: usize = 64;
const RECOVERY_KDF_SALT: &[u8] = b"DOM:usdom-wallet-recovery:v1";
const RECOVERY_OWNER_INFO: &[u8] = b"DOM:usdom-wallet-recovery:owner:v1";
const RECOVERY_SCAN_INFO: &[u8] = b"DOM:usdom-wallet-recovery:scan:v1";
const MEMO_MAGIC: &[u8; 8] = b"USDMEM01";
const NOTE_PLAINTEXT_MAGIC: &[u8; 8] = b"USDNOTE1";
const MEMO_KEY_SALT: &[u8] = b"DOM:usdom-wallet-memo-key:v1";
const MEMO_AAD_TAG: &[u8] = b"DOM:usdom-wallet-memo-aad:v1";
const ADDRESS_BYTES: usize = 8 + 32 + 32 + 32;
const NONCE_BYTES: usize = 24;
const PLAINTEXT_BYTES: usize = 8 + 8 + 32;
const TAG_BYTES: usize = 16;
const CIPHERTEXT_BYTES: usize = PLAINTEXT_BYTES + TAG_BYTES;
const ENTRY_BYTES: usize = 32 + NONCE_BYTES + CIPHERTEXT_BYTES;
const MEMO_HEADER_BYTES: usize = 8 + 1;
type OwnedNotePaths = BTreeMap<[u8; 32], [Scalar; NOTE_TREE_DEPTH]>;
type ReconstructedWalletTree = (IncrementalNoteTree, OwnedNotePaths);

/// Maximum private outputs represented by one frozen spend circuit.
pub const MAX_MEMO_OUTPUTS: usize = 2;
/// Exact encoded length of one recipient address.
pub const RECIPIENT_ADDRESS_BYTES: usize = ADDRESS_BYTES;
/// Largest canonical memo emitted by this version.
pub const MAX_CANONICAL_MEMO_BYTES: usize = MEMO_HEADER_BYTES + MAX_MEMO_OUTPUTS * ENTRY_BYTES;

/// Failure while handling wallet secrets, addresses, or authenticated memos.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WalletError {
    /// A chain, secret, owner, randomness, amount, or commitment was zero or invalid.
    #[error("invalid USDOM wallet identity or note field")]
    InvalidIdentity,
    /// Recipient address bytes are malformed, noncanonical, or belong to another chain.
    #[error("invalid USDOM recipient address")]
    InvalidAddress,
    /// Output count or memo framing is outside the frozen two-output format.
    #[error("invalid canonical USDOM encrypted memo")]
    InvalidMemo,
    /// X25519 rejected a noncontributory peer public key.
    #[error("invalid USDOM memo scan public key")]
    InvalidScanKey,
    /// HKDF or authenticated encryption failed closed.
    #[error("USDOM memo cryptographic operation failed")]
    CryptographicFailure,
    /// A memo authenticated for this wallet did not reproduce its public note commitment.
    #[error("authenticated USDOM memo does not match its output commitment")]
    AuthenticatedMemoMismatch,
    /// The enclosing private transfer or burn payload is malformed.
    #[error("invalid USDOM private transition payload for wallet scanning")]
    InvalidTransitionPayload,
    /// A purported canonical block does not extend the exact wallet tip.
    #[error("USDOM wallet block continuity mismatch")]
    BlockContinuity,
    /// Verified effects and their transported private payload do not match.
    #[error("USDOM wallet observation does not match verified transition effects")]
    ObservationMismatch,
    /// A canonical public note or nullifier was repeated.
    #[error("duplicate USDOM wallet chain effect")]
    DuplicateChainEffect,
    /// The requested rollback does not target the exact applied wallet tip.
    #[error("USDOM wallet rollback does not match the current tip")]
    RollbackMismatch,
    /// Wallet balance or height arithmetic overflowed.
    #[error("USDOM wallet arithmetic overflow")]
    ArithmeticOverflow,
    /// The requested note is unknown, already spent, or not controlled by this wallet.
    #[error("USDOM wallet note is unavailable for spending")]
    NoteUnavailable,
    /// A locally maintained membership witness does not reproduce the current root.
    #[error("USDOM wallet membership witness invariant failed")]
    InvalidWitnessState,
    /// A deposit identifier or issuance commitment was registered twice.
    #[error("duplicate expected USDOM deposit issuance")]
    DuplicateExpectedIssuance,
    /// Registration occurred after the commitment was already canonical.
    #[error("expected USDOM deposit must be registered before canonical issuance")]
    ExpectedIssuanceTooLate,
    /// Recovery was requested before the exact issuance commitment appeared
    /// in the wallet's authenticated canonical history.
    #[error("expected USDOM deposit issuance is not canonical in wallet history")]
    ExpectedIssuanceNotCanonical,
}

/// Failures while creating or restoring an encrypted deterministic recovery seed.
#[derive(Debug, Error)]
pub enum WalletRecoveryError {
    /// Password KDF, authenticated encryption, or durable storage failed.
    #[error(transparent)]
    Envelope(#[from] EnvelopeError),
    /// The authenticated plaintext did not contain one exact canonical backup.
    #[error("invalid USDOM wallet recovery backup")]
    InvalidBackup,
    /// The backup was opened under a different native USDOM chain identity.
    #[error("USDOM wallet recovery backup belongs to another chain")]
    WrongChain,
    /// Deterministic key expansion did not produce a valid wallet identity.
    #[error("USDOM wallet recovery derivation failed")]
    DerivationFailed,
}

/// Opaque 256-bit root for deterministic USDOM owner and scanning keys.
///
/// This type is neither cloneable, printable nor serializable. The only public
/// persistence path encrypts it with the wallet envelope's Argon2id and AEAD
/// construction. Dropping the value erases its memory.
pub struct WalletRecoverySeed(Zeroizing<[u8; 32]>);

impl WalletRecoverySeed {
    /// Generate a nonzero recovery seed from an operating-system-grade caller RNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        loop {
            let mut bytes = Zeroizing::new([0u8; 32]);
            rng.fill_bytes(&mut *bytes);
            if bytes.iter().any(|byte| *byte != 0) {
                return Self(bytes);
            }
        }
    }

    /// Encrypt and atomically persist this seed, bound to one chain identity.
    /// An existing path is never replaced, including under a concurrent save.
    pub fn save_encrypted_backup(
        &self,
        chain: Scalar,
        path: &Path,
        passphrase: &WalletPassphrase,
    ) -> Result<(), WalletRecoveryError> {
        if chain.is_zero() {
            return Err(WalletRecoveryError::InvalidBackup);
        }
        let mut plaintext = Zeroizing::new(Vec::with_capacity(RECOVERY_PLAINTEXT_BYTES));
        plaintext.extend_from_slice(&chain.to_bytes());
        plaintext.extend_from_slice(&self.0[..]);
        save_envelope_bytes_noclobber(
            path,
            RECOVERY_ENVELOPE_MAGIC,
            RECOVERY_ENVELOPE_VERSION,
            &plaintext,
            passphrase.expose(),
        )?;
        Ok(())
    }

    /// Authenticate, decrypt and restore one chain-bound recovery seed.
    pub fn load_encrypted_backup(
        path: &Path,
        expected_chain: Scalar,
        passphrase: &WalletPassphrase,
    ) -> Result<Self, WalletRecoveryError> {
        if expected_chain.is_zero() {
            return Err(WalletRecoveryError::InvalidBackup);
        }
        let plaintext = load_envelope_bytes(
            path,
            RECOVERY_ENVELOPE_MAGIC,
            RECOVERY_ENVELOPE_VERSION,
            RECOVERY_PLAINTEXT_BYTES,
            passphrase.expose(),
        )?;
        if plaintext.len() != RECOVERY_PLAINTEXT_BYTES {
            return Err(WalletRecoveryError::InvalidBackup);
        }
        let stored_chain = Scalar::from_bytes(
            plaintext[..32]
                .try_into()
                .map_err(|_| WalletRecoveryError::InvalidBackup)?,
        )
        .map_err(|_| WalletRecoveryError::InvalidBackup)?;
        if stored_chain != expected_chain {
            return Err(WalletRecoveryError::WrongChain);
        }
        let seed: [u8; 32] = plaintext[32..]
            .try_into()
            .map_err(|_| WalletRecoveryError::InvalidBackup)?;
        if seed.iter().all(|byte| *byte == 0) {
            return Err(WalletRecoveryError::InvalidBackup);
        }
        Ok(Self(Zeroizing::new(seed)))
    }
}

impl From<PrivacyError> for WalletError {
    fn from(_: PrivacyError) -> Self {
        Self::InvalidIdentity
    }
}

/// Public recipient data: protocol chain, hidden-note owner commitment, and scan key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecipientAddress {
    chain: Scalar,
    owner: Scalar,
    scan_public: [u8; 32],
}

impl RecipientAddress {
    /// Decode the unique fixed-width address representation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WalletError> {
        if bytes.len() != ADDRESS_BYTES || &bytes[..8] != ADDRESS_MAGIC {
            return Err(WalletError::InvalidAddress);
        }
        let chain = Scalar::from_bytes(
            bytes[8..40]
                .try_into()
                .map_err(|_| WalletError::InvalidAddress)?,
        )
        .map_err(|_| WalletError::InvalidAddress)?;
        let owner = Scalar::from_bytes(
            bytes[40..72]
                .try_into()
                .map_err(|_| WalletError::InvalidAddress)?,
        )
        .map_err(|_| WalletError::InvalidAddress)?;
        let scan_public = bytes[72..104]
            .try_into()
            .map_err(|_| WalletError::InvalidAddress)?;
        let address = Self {
            chain,
            owner,
            scan_public,
        };
        address.validate()?;
        if address.to_bytes().as_slice() != bytes {
            return Err(WalletError::InvalidAddress);
        }
        Ok(address)
    }

    /// Encode the unique fixed-width address representation.
    pub fn to_bytes(self) -> [u8; ADDRESS_BYTES] {
        let mut bytes = [0u8; ADDRESS_BYTES];
        bytes[..8].copy_from_slice(ADDRESS_MAGIC);
        bytes[8..40].copy_from_slice(&self.chain.to_bytes());
        bytes[40..72].copy_from_slice(&self.owner.to_bytes());
        bytes[72..104].copy_from_slice(&self.scan_public);
        bytes
    }

    /// Protocol chain scalar to which this address is bound.
    pub fn chain(self) -> Scalar {
        self.chain
    }

    /// Poseidon commitment to the recipient's private owner secret.
    pub fn owner(self) -> Scalar {
        self.owner
    }

    /// X25519 public key used only to discover and decrypt note memos.
    pub fn scan_public(self) -> [u8; 32] {
        self.scan_public
    }

    fn validate(self) -> Result<(), WalletError> {
        if self.chain.is_zero() || self.owner.is_zero() || self.scan_public == [0; 32] {
            return Err(WalletError::InvalidAddress);
        }
        Ok(())
    }
}

/// Long-lived wallet secrets kept outside the node process.
///
/// This type intentionally implements neither `Clone`, `Copy`, `Debug`, nor
/// serialization. Dropping it zeroizes both the BN254 owner secret and X25519
/// scan secret.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WalletSecrets {
    chain: Scalar,
    owner_secret: Scalar,
    scan_secret: StaticSecret,
}

impl WalletSecrets {
    /// Generate independent owner and scan secrets from a cryptographic RNG.
    pub fn generate<R: RngCore + CryptoRng>(
        chain: Scalar,
        rng: &mut R,
    ) -> Result<Self, WalletError> {
        if chain.is_zero() {
            return Err(WalletError::InvalidIdentity);
        }
        let owner_secret = loop {
            let mut candidate = Zeroizing::new([0u8; 32]);
            rng.fill_bytes(&mut *candidate);
            if let Ok(value) = Scalar::from_bytes(*candidate) {
                if !value.is_zero() {
                    break value;
                }
            }
        };
        let scan_secret = StaticSecret::random_from_rng(&mut *rng);
        Ok(Self {
            chain,
            owner_secret,
            scan_secret,
        })
    }

    /// Deterministically derive independent owner and scanning secrets from one
    /// encrypted-backup recovery root. The chain identity and purpose tags are
    /// included in every HKDF expansion, preventing reuse across networks or
    /// cryptographic roles.
    pub fn from_recovery_seed(
        chain: Scalar,
        seed: &WalletRecoverySeed,
    ) -> Result<Self, WalletRecoveryError> {
        if chain.is_zero() {
            return Err(WalletRecoveryError::DerivationFailed);
        }
        let hkdf = Hkdf::<Sha256>::new(Some(RECOVERY_KDF_SALT), &seed.0[..]);
        let chain_bytes = chain.to_bytes();
        let mut owner_secret = None;
        for counter in 0u8..=u8::MAX {
            let mut info = Vec::with_capacity(RECOVERY_OWNER_INFO.len() + 33);
            info.extend_from_slice(RECOVERY_OWNER_INFO);
            info.extend_from_slice(&chain_bytes);
            info.push(counter);
            let mut candidate = Zeroizing::new([0u8; 32]);
            hkdf.expand(&info, &mut candidate[..])
                .map_err(|_| WalletRecoveryError::DerivationFailed)?;
            if let Ok(scalar) = Scalar::from_bytes(*candidate) {
                if !scalar.is_zero() {
                    owner_secret = Some(scalar);
                    break;
                }
            }
        }
        let owner_secret = owner_secret.ok_or(WalletRecoveryError::DerivationFailed)?;

        let mut scan_secret = None;
        for counter in 0u8..=u8::MAX {
            let mut info = Vec::with_capacity(RECOVERY_SCAN_INFO.len() + 33);
            info.extend_from_slice(RECOVERY_SCAN_INFO);
            info.extend_from_slice(&chain_bytes);
            info.push(counter);
            let mut candidate = Zeroizing::new([0u8; 32]);
            hkdf.expand(&info, &mut candidate[..])
                .map_err(|_| WalletRecoveryError::DerivationFailed)?;
            let secret = StaticSecret::from(*candidate);
            if PublicKey::from(&secret).to_bytes() != [0; 32] {
                scan_secret = Some(secret);
                break;
            }
        }
        let wallet = Self {
            chain,
            owner_secret,
            scan_secret: scan_secret.ok_or(WalletRecoveryError::DerivationFailed)?,
        };
        wallet
            .address()
            .map_err(|_| WalletRecoveryError::DerivationFailed)?;
        Ok(wallet)
    }

    /// Restore exact wallet secrets from a protected storage boundary.
    pub fn from_bytes(
        chain: Scalar,
        owner_secret: [u8; 32],
        scan_secret: [u8; 32],
    ) -> Result<Self, WalletError> {
        let owner_secret = Zeroizing::new(owner_secret);
        let scan_secret = Zeroizing::new(scan_secret);
        let parsed_owner = Scalar::from_bytes(*owner_secret)?;
        if chain.is_zero() || parsed_owner.is_zero() || *scan_secret == [0; 32] {
            return Err(WalletError::InvalidIdentity);
        }
        Ok(Self {
            chain,
            owner_secret: parsed_owner,
            scan_secret: StaticSecret::from(*scan_secret),
        })
    }

    /// Derive the public recipient address without exposing either secret.
    pub fn address(&self) -> Result<RecipientAddress, WalletError> {
        let address = RecipientAddress {
            chain: self.chain,
            owner: owner_commitment(self.chain, self.owner_secret)?,
            scan_public: PublicKey::from(&self.scan_secret).to_bytes(),
        };
        address.validate()?;
        Ok(address)
    }

    /// Derive the canonical public nullifier for one note owned by this wallet.
    pub fn nullifier_for(&self, opening: &NoteOpening) -> Result<Scalar, WalletError> {
        if opening.chain != self.chain {
            return Err(WalletError::InvalidIdentity);
        }
        opening
            .nullifier(self.owner_secret)
            .map_err(WalletError::from)
    }
}

/// One private output opening to encrypt for a recipient.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MemoOutput {
    /// Public recipient address.
    #[zeroize(skip)]
    pub recipient: RecipientAddress,
    /// Six-decimal note value.
    pub value: u64,
    /// Unique nonzero note randomness.
    pub rho: Scalar,
}

/// Public commitments and exact encrypted memo produced for a spend circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedOutputs {
    commitments: Vec<Scalar>,
    memo: Vec<u8>,
}

impl EncryptedOutputs {
    /// Output note commitments in the same order as the encrypted entries.
    pub fn commitments(&self) -> &[Scalar] {
        &self.commitments
    }

    /// Canonical memo bytes to commit in the proof statement and payload.
    pub fn memo(&self) -> &[u8] {
        &self.memo
    }
}

/// One note opening recovered and independently matched to a public output.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ReceivedNote {
    /// Zero-based output slot in the enclosing private transition.
    pub output_index: u8,
    /// Public note commitment matched after authenticated decryption.
    pub commitment: Scalar,
    /// Secret note opening needed to construct a future spend witness.
    pub opening: NoteOpening,
}

fn memo_context(
    chain: Scalar,
    owner: Scalar,
    scan_public: [u8; 32],
    ephemeral_public: [u8; 32],
    commitment: Scalar,
    output_index: u8,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(MEMO_AAD_TAG.len() + 32 * 5 + 1);
    context.extend_from_slice(MEMO_AAD_TAG);
    context.extend_from_slice(&chain.to_bytes());
    context.extend_from_slice(&owner.to_bytes());
    context.extend_from_slice(&scan_public);
    context.extend_from_slice(&ephemeral_public);
    context.extend_from_slice(&commitment.to_bytes());
    context.push(output_index);
    context
}

fn derive_memo_key(shared: &[u8; 32], context: &[u8]) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(MEMO_KEY_SALT), shared)
        .expand(context, &mut *key)
        .map_err(|_| WalletError::CryptographicFailure)?;
    Ok(key)
}

/// Encrypt one or two exact note openings and return their public commitments.
pub fn encrypt_outputs<R: RngCore + CryptoRng>(
    chain: Scalar,
    outputs: Vec<MemoOutput>,
    rng: &mut R,
) -> Result<EncryptedOutputs, WalletError> {
    if chain.is_zero() || outputs.is_empty() || outputs.len() > MAX_MEMO_OUTPUTS {
        return Err(WalletError::InvalidMemo);
    }
    let mut commitments = Vec::with_capacity(outputs.len());
    let mut memo = Vec::with_capacity(MEMO_HEADER_BYTES + outputs.len() * ENTRY_BYTES);
    memo.extend_from_slice(MEMO_MAGIC);
    memo.push(outputs.len() as u8);
    let mut uniqueness = BTreeSet::new();

    for (index, output) in outputs.iter().enumerate() {
        output.recipient.validate()?;
        if output.recipient.chain != chain || output.value == 0 || output.rho.is_zero() {
            return Err(WalletError::InvalidIdentity);
        }
        let commitment = NoteOpening {
            chain,
            origin: NOTE_ORIGIN_PRIVATE,
            value: output.value,
            owner: output.recipient.owner,
            rho: output.rho,
        }
        .commitment()?;
        let ephemeral_secret = EphemeralSecret::random_from_rng(&mut *rng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret).to_bytes();
        let recipient_public = PublicKey::from(output.recipient.scan_public);
        let shared = ephemeral_secret.diffie_hellman(&recipient_public);
        if !shared.was_contributory() {
            return Err(WalletError::InvalidScanKey);
        }
        let mut nonce = [0u8; NONCE_BYTES];
        rng.fill_bytes(&mut nonce);
        if !uniqueness.insert((ephemeral_public, nonce)) {
            return Err(WalletError::CryptographicFailure);
        }
        let context = memo_context(
            chain,
            output.recipient.owner,
            output.recipient.scan_public,
            ephemeral_public,
            commitment,
            index as u8,
        );
        let key = derive_memo_key(shared.as_bytes(), &context)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*key)
            .map_err(|_| WalletError::CryptographicFailure)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(PLAINTEXT_BYTES));
        plaintext.extend_from_slice(NOTE_PLAINTEXT_MAGIC);
        plaintext.extend_from_slice(&output.value.to_be_bytes());
        plaintext.extend_from_slice(&output.rho.to_bytes());
        let nonce_value = XNonce::from(nonce);
        let ciphertext = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: &plaintext,
                    aad: &context,
                },
            )
            .map_err(|_| WalletError::CryptographicFailure)?;
        if ciphertext.len() != CIPHERTEXT_BYTES {
            return Err(WalletError::CryptographicFailure);
        }
        memo.extend_from_slice(&ephemeral_public);
        memo.extend_from_slice(&nonce);
        memo.extend_from_slice(&ciphertext);
        commitments.push(commitment);
    }
    if memo.len() != MEMO_HEADER_BYTES + outputs.len() * ENTRY_BYTES {
        return Err(WalletError::CryptographicFailure);
    }
    Ok(EncryptedOutputs { commitments, memo })
}

/// Scan one canonical memo against public commitments and recover owned notes.
///
/// Authentication failures remain indistinguishable from entries for another
/// recipient. If authentication succeeds, every private field is recomputed
/// against the enclosing output commitment before a note is returned.
pub fn scan_memo(
    wallet: &WalletSecrets,
    commitments: &[Scalar],
    memo: &[u8],
) -> Result<Vec<ReceivedNote>, WalletError> {
    if commitments.is_empty()
        || commitments.len() > MAX_MEMO_OUTPUTS
        || memo.len() != MEMO_HEADER_BYTES + commitments.len() * ENTRY_BYTES
        || &memo[..8] != MEMO_MAGIC
        || usize::from(memo[8]) != commitments.len()
        || commitments.iter().any(|value| value.is_zero())
    {
        return Err(WalletError::InvalidMemo);
    }
    let address = wallet.address()?;
    let mut received = Vec::new();
    let mut uniqueness = BTreeSet::new();
    for (index, commitment) in commitments.iter().copied().enumerate() {
        let start = MEMO_HEADER_BYTES + index * ENTRY_BYTES;
        let ephemeral_public: [u8; 32] = memo[start..start + 32]
            .try_into()
            .map_err(|_| WalletError::InvalidMemo)?;
        let nonce: [u8; NONCE_BYTES] = memo[start + 32..start + 32 + NONCE_BYTES]
            .try_into()
            .map_err(|_| WalletError::InvalidMemo)?;
        if !uniqueness.insert((ephemeral_public, nonce)) {
            return Err(WalletError::InvalidMemo);
        }
        let ciphertext = &memo[start + 32 + NONCE_BYTES..start + ENTRY_BYTES];
        let peer = PublicKey::from(ephemeral_public);
        let shared = wallet.scan_secret.diffie_hellman(&peer);
        if !shared.was_contributory() {
            continue;
        }
        let context = memo_context(
            wallet.chain,
            address.owner,
            address.scan_public,
            ephemeral_public,
            commitment,
            index as u8,
        );
        let key = derive_memo_key(shared.as_bytes(), &context)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*key)
            .map_err(|_| WalletError::CryptographicFailure)?;
        let nonce_value = XNonce::from(nonce);
        let Ok(decrypted) = cipher.decrypt(
            &nonce_value,
            Payload {
                msg: ciphertext,
                aad: &context,
            },
        ) else {
            continue;
        };
        let plaintext = Zeroizing::new(decrypted);
        if plaintext.len() != PLAINTEXT_BYTES || &plaintext[..8] != NOTE_PLAINTEXT_MAGIC {
            return Err(WalletError::AuthenticatedMemoMismatch);
        }
        let value = u64::from_be_bytes(
            plaintext[8..16]
                .try_into()
                .map_err(|_| WalletError::AuthenticatedMemoMismatch)?,
        );
        let rho = Scalar::from_bytes(
            plaintext[16..48]
                .try_into()
                .map_err(|_| WalletError::AuthenticatedMemoMismatch)?,
        )
        .map_err(|_| WalletError::AuthenticatedMemoMismatch)?;
        let opening = NoteOpening {
            chain: wallet.chain,
            origin: NOTE_ORIGIN_PRIVATE,
            value,
            owner: address.owner,
            rho,
        };
        if value == 0 || rho.is_zero() || opening.commitment()? != commitment {
            return Err(WalletError::AuthenticatedMemoMismatch);
        }
        received.push(ReceivedNote {
            output_index: index as u8,
            commitment,
            opening,
        });
    }
    Ok(received)
}

/// Parse an untrusted private-transfer payload and scan its exact committed
/// output memo. Callers must independently require that the enclosing block is
/// validated and canonical before persisting any returned note.
pub fn scan_private_transfer_payload(
    wallet: &WalletSecrets,
    payload: &[u8],
) -> Result<Vec<ReceivedNote>, WalletError> {
    let observation = inspect_private_transfer_outputs(payload)
        .map_err(|_| WalletError::InvalidTransitionPayload)?;
    let commitments = observation
        .output_notes
        .iter()
        .map(|bytes| Scalar::from_bytes(*bytes).map_err(|_| WalletError::InvalidTransitionPayload))
        .collect::<Result<Vec<_>, _>>()?;
    scan_memo(wallet, &commitments, observation.encrypted_memo)
}

/// Parse an untrusted private-burn payload and scan any exact committed change
/// notes. A full burn with no change correctly yields an empty result.
pub fn scan_private_burn_payload(
    wallet: &WalletSecrets,
    payload: &[u8],
) -> Result<Vec<ReceivedNote>, WalletError> {
    let observation =
        inspect_private_burn_outputs(payload).map_err(|_| WalletError::InvalidTransitionPayload)?;
    if observation.output_notes.is_empty() {
        return Ok(Vec::new());
    }
    let commitments = observation
        .output_notes
        .iter()
        .map(|bytes| Scalar::from_bytes(*bytes).map_err(|_| WalletError::InvalidTransitionPayload))
        .collect::<Result<Vec<_>, _>>()?;
    scan_memo(wallet, &commitments, observation.encrypted_memo)
}

/// Wallet observation tied to public effects extracted from one verified
/// native transition. Private spends require the exact transported payload;
/// issuance and checkpoint transitions carry no recipient memo here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletTransitionObservation {
    effects: TransitionPublicEffects,
    encrypted_memo: Vec<u8>,
    private_payload_id: Option<Hash256>,
}

impl WalletTransitionObservation {
    /// Match one proof-verified transition to its exact private payload shape.
    pub fn from_verified(
        transition: &VerifiedTransition,
        private_payload: Option<&[u8]>,
    ) -> Result<Self, WalletError> {
        Self::from_effects(transition.public_effects(), private_payload)
    }

    /// Match a header-authenticated public projection to its exact transported
    /// private payload. The caller must first authenticate the projection's
    /// commitment under the corresponding trusted DOM header.
    pub fn from_authenticated_projection(
        projection: &TransitionCommitmentProjection,
        private_payload: Option<&[u8]>,
    ) -> Result<Self, WalletError> {
        projection
            .consensus_commitment()
            .map_err(|_| WalletError::ObservationMismatch)?;
        Self::from_effects(projection.public_effects(), private_payload)
    }

    fn from_effects(
        effects: TransitionPublicEffects,
        private_payload: Option<&[u8]>,
    ) -> Result<Self, WalletError> {
        let (encrypted_memo, private_payload_id) = match effects.kind {
            TransitionKind::Transfer => {
                let payload = private_payload.ok_or(WalletError::ObservationMismatch)?;
                let observed = inspect_private_transfer_outputs(payload)
                    .map_err(|_| WalletError::InvalidTransitionPayload)?;
                if observed.nullifiers != effects.nullifiers
                    || observed.output_notes != effects.note_commitments
                    || effects.memo_commitment
                        != Some(observed_memo_commitment(
                            &observed.output_notes,
                            observed.encrypted_memo,
                        )?)
                {
                    return Err(WalletError::ObservationMismatch);
                }
                (
                    observed.encrypted_memo.to_vec(),
                    Some(private_transfer_payload_id(payload)),
                )
            }
            TransitionKind::Burn => {
                let observed = inspect_private_burn_outputs(
                    private_payload.ok_or(WalletError::ObservationMismatch)?,
                )
                .map_err(|_| WalletError::InvalidTransitionPayload)?;
                if observed.nullifiers != effects.nullifiers
                    || observed.output_notes != effects.note_commitments
                    || effects.memo_commitment
                        != Some(observed_memo_commitment(
                            &observed.output_notes,
                            observed.encrypted_memo,
                        )?)
                {
                    return Err(WalletError::ObservationMismatch);
                }
                (
                    observed.encrypted_memo.to_vec(),
                    Some(private_burn_payload_id(
                        private_payload.ok_or(WalletError::ObservationMismatch)?,
                    )),
                )
            }
            TransitionKind::Issue | TransitionKind::EthereumCheckpoint => {
                if private_payload.is_some() {
                    return Err(WalletError::ObservationMismatch);
                }
                (Vec::new(), None)
            }
        };
        Ok(Self {
            effects,
            encrypted_memo,
            private_payload_id,
        })
    }
}

fn observed_memo_commitment(
    output_notes: &[[u8; 32]],
    encrypted_memo: &[u8],
) -> Result<[u8; 32], WalletError> {
    if output_notes.is_empty() {
        if encrypted_memo.is_empty() {
            return Ok([0; 32]);
        }
        return Err(WalletError::ObservationMismatch);
    }
    memo_scalar(encrypted_memo)
        .map(Scalar::to_bytes)
        .map_err(|_| WalletError::ObservationMismatch)
}

/// One authenticated canonical block projection consumed by the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalWalletBlock {
    /// Canonical DOM height.
    pub height: u64,
    /// Canonical network-domain block identifier.
    pub identifier: Hash256,
    /// Exact parent identifier.
    pub parent_identifier: Hash256,
    /// Ordered proof-verified USDOM transition observations.
    pub transitions: Vec<WalletTransitionObservation>,
}

/// Public inventory record for one note controlled by this wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletNoteSummary {
    /// Canonical note commitment.
    pub commitment: Scalar,
    /// Origin namespace: ordinary private output or finalized issuance.
    pub origin: u8,
    /// Global note-tree leaf index.
    pub leaf_index: u64,
    /// Six-decimal note value.
    pub value: u64,
    /// Whether a canonical applied nullifier has spent this note.
    pub spent: bool,
    /// Pending private transfer or burn that currently reserves this note.
    pub reservation_id: Option<Hash256>,
}

/// Encrypted-wallet record for one deposit expected to become a native note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedIssuanceSummary {
    /// Public reserve deposit identifier.
    pub deposit_id: [u8; 32],
    /// Consensus-derived origin-separated note commitment.
    pub note_commitment: Scalar,
    /// Six-decimal deposit amount.
    pub amount: u64,
    /// Whether the commitment is present in the canonical wallet projection.
    pub canonical: bool,
}

struct ExpectedIssuance {
    occurrence: EthereumDepositOccurrence,
    opening: NoteOpening,
}

impl Zeroize for ExpectedIssuance {
    fn zeroize(&mut self) {
        self.occurrence = EthereumDepositOccurrence {
            genesis_validators_root: [0; 32],
            block_hash: [0; 32],
            block_number: 0,
            transaction_index: 0,
            receipt_log_index: 0,
            deposit_id: [0; 32],
            funder: [0; 20],
            amount: 0,
            receiving_commitment: [0; 32],
        };
        self.opening.zeroize();
    }
}

impl Drop for ExpectedIssuance {
    fn drop(&mut self) {
        self.zeroize();
    }
}

struct TrackedNote {
    received: ReceivedNote,
    leaf_index: u64,
    siblings: [Scalar; NOTE_TREE_DEPTH],
    spent: bool,
    reservation_id: Option<Hash256>,
}

impl Zeroize for TrackedNote {
    fn zeroize(&mut self) {
        self.received.zeroize();
        self.leaf_index.zeroize();
        self.siblings.zeroize();
        self.spent.zeroize();
        self.reservation_id = None;
    }
}

impl Drop for TrackedNote {
    fn drop(&mut self) {
        self.zeroize();
    }
}

struct WalletBlockUndo {
    identifier: Hash256,
    parent_identifier: Hash256,
    height: u64,
    commitment_count_before: usize,
    inserted_commitments: Vec<[u8; 32]>,
    inserted_nullifiers: Vec<[u8; 32]>,
    inserted_private_payloads: Vec<[u8; 32]>,
    inserted_owned_notes: Vec<[u8; 32]>,
    spent_existing_notes: Vec<[u8; 32]>,
}

/// In-memory canonical wallet projection with exact tip rollback.
///
/// Block identifiers and verified observations must come from the validated
/// canonical node path. This state independently enforces continuity, global
/// note/nullifier uniqueness, memo authentication, and atomic apply/rollback.
pub struct WalletState {
    chain: Scalar,
    tip_height: u64,
    tip_identifier: Hash256,
    note_tree: IncrementalNoteTree,
    commitment_log: Vec<[u8; 32]>,
    seen_commitments: BTreeSet<[u8; 32]>,
    seen_nullifiers: BTreeSet<[u8; 32]>,
    seen_private_payloads: BTreeSet<[u8; 32]>,
    notes: BTreeMap<[u8; 32], TrackedNote>,
    expected_issuances: BTreeMap<[u8; 32], ExpectedIssuance>,
    pending_transfers: BTreeMap<[u8; 32], builder::PendingPrivateTransfer>,
    pending_burns: BTreeMap<[u8; 32], burn_builder::PendingPrivateBurn>,
    history: Vec<WalletBlockUndo>,
}

impl WalletState {
    /// Start at an authenticated tip whose native note tree is empty.
    pub fn new_empty(
        chain: Scalar,
        tip_height: u64,
        tip_identifier: Hash256,
    ) -> Result<Self, WalletError> {
        if chain.is_zero() || tip_identifier == Hash256::ZERO {
            return Err(WalletError::InvalidIdentity);
        }
        Ok(Self {
            chain,
            tip_height,
            tip_identifier,
            note_tree: IncrementalNoteTree::new(),
            commitment_log: Vec::new(),
            seen_commitments: BTreeSet::new(),
            seen_nullifiers: BTreeSet::new(),
            seen_private_payloads: BTreeSet::new(),
            notes: BTreeMap::new(),
            expected_issuances: BTreeMap::new(),
            pending_transfers: BTreeMap::new(),
            pending_burns: BTreeMap::new(),
            history: Vec::new(),
        })
    }

    /// Current authenticated DOM height represented by the wallet.
    pub fn tip_height(&self) -> u64 {
        self.tip_height
    }

    /// Current authenticated canonical block identifier.
    pub fn tip_identifier(&self) -> Hash256 {
        self.tip_identifier
    }

    /// Current reconstructed native note-tree root.
    pub fn note_root(&self) -> Scalar {
        self.note_tree.root()
    }

    /// Sum of currently unspent owned notes using overflow-safe `u128`.
    pub fn available_balance(&self) -> u128 {
        self.notes
            .values()
            .filter(|note| !note.spent && note.reservation_id.is_none())
            .map(|note| u128::from(note.received.opening.value))
            .sum()
    }

    /// Public inventory without owner secrets or note randomness.
    pub fn note_summaries(&self) -> Vec<WalletNoteSummary> {
        self.notes
            .values()
            .map(|note| WalletNoteSummary {
                commitment: note.received.commitment,
                origin: note.received.opening.origin,
                leaf_index: note.leaf_index,
                value: note.received.opening.value,
                spent: note.spent,
                reservation_id: note.reservation_id,
            })
            .collect()
    }

    /// Register an authenticated Ethereum deposit occurrence before its
    /// issuance commitment is scanned from the canonical DOM chain.
    pub fn register_expected_deposit(
        &mut self,
        wallet: &WalletSecrets,
        bridge: BridgeIdentity,
        occurrence: EthereumDepositOccurrence,
    ) -> Result<Scalar, WalletError> {
        let (commitment, opening) = self.expected_deposit_opening(wallet, bridge, occurrence)?;
        let commitment_bytes = commitment.to_bytes();
        if self.seen_commitments.contains(&commitment_bytes) {
            return Err(WalletError::ExpectedIssuanceTooLate);
        }
        if self.expected_issuances.contains_key(&commitment_bytes)
            || self
                .expected_issuances
                .values()
                .any(|expected| expected.occurrence.deposit_id == occurrence.deposit_id)
        {
            return Err(WalletError::DuplicateExpectedIssuance);
        }
        self.expected_issuances.insert(
            commitment_bytes,
            ExpectedIssuance {
                occurrence,
                opening,
            },
        );
        Ok(commitment)
    }

    /// Recover a deposit that was registered too late, but whose exact
    /// issuance-origin commitment is already present in this wallet's
    /// proof-verified canonical history.
    ///
    /// This does not trust an RPC inclusion claim or an arbitrary leaf index.
    /// The method derives the commitment from the authenticated Ethereum
    /// occurrence, locates it in the locally reconstructed global note tree,
    /// rebuilds every owned witness, and amends the original insertion/spend
    /// undo records so later reorgs remain exact.
    pub fn recover_canonical_deposit(
        &mut self,
        wallet: &WalletSecrets,
        bridge: BridgeIdentity,
        occurrence: EthereumDepositOccurrence,
    ) -> Result<Scalar, WalletError> {
        let (commitment, opening) = self.expected_deposit_opening(wallet, bridge, occurrence)?;
        let commitment_bytes = commitment.to_bytes();
        if self.expected_issuances.contains_key(&commitment_bytes)
            || self
                .expected_issuances
                .values()
                .any(|expected| expected.occurrence.deposit_id == occurrence.deposit_id)
            || self.notes.contains_key(&commitment_bytes)
        {
            return Err(WalletError::DuplicateExpectedIssuance);
        }
        if !self.seen_commitments.contains(&commitment_bytes) {
            return Err(WalletError::ExpectedIssuanceNotCanonical);
        }
        let mut matching_indices = self
            .commitment_log
            .iter()
            .enumerate()
            .filter_map(|(index, value)| (*value == commitment_bytes).then_some(index));
        let leaf_index = matching_indices
            .next()
            .ok_or(WalletError::InvalidWitnessState)?;
        if matching_indices.next().is_some() {
            return Err(WalletError::InvalidWitnessState);
        }
        let leaf_index = u64::try_from(leaf_index).map_err(|_| WalletError::ArithmeticOverflow)?;

        let mut insertion_undo = None;
        for (index, undo) in self.history.iter().enumerate() {
            if undo.inserted_commitments.contains(&commitment_bytes)
                && (insertion_undo.replace(index).is_some()
                    || undo.inserted_owned_notes.contains(&commitment_bytes))
            {
                return Err(WalletError::InvalidWitnessState);
            }
        }
        let insertion_undo = insertion_undo.ok_or(WalletError::InvalidWitnessState)?;
        let nullifier = wallet.nullifier_for(&opening)?.to_bytes();
        let spent = self.seen_nullifiers.contains(&nullifier);
        let mut spend_undo = None;
        if spent {
            for (index, undo) in self.history.iter().enumerate() {
                if undo.inserted_nullifiers.contains(&nullifier)
                    && spend_undo.replace(index).is_some()
                {
                    return Err(WalletError::InvalidWitnessState);
                }
            }
            let index = spend_undo.ok_or(WalletError::InvalidWitnessState)?;
            if index < insertion_undo
                || (index != insertion_undo
                    && leaf_index as usize >= self.history[index].commitment_count_before)
                || (index != insertion_undo
                    && self.history[index]
                        .spent_existing_notes
                        .contains(&commitment_bytes))
            {
                return Err(WalletError::InvalidWitnessState);
            }
        }

        let mut indices = self
            .notes
            .iter()
            .map(|(owned, note)| (*owned, note.leaf_index))
            .collect::<BTreeMap<_, _>>();
        if indices.insert(commitment_bytes, leaf_index).is_some() {
            return Err(WalletError::InvalidWitnessState);
        }
        let (rebuilt_tree, paths) =
            Self::reconstruct_tree_and_paths(&self.commitment_log, &indices)?;
        if rebuilt_tree.root() != self.note_tree.root()
            || rebuilt_tree.leaf_count() != self.note_tree.leaf_count()
        {
            return Err(WalletError::InvalidWitnessState);
        }
        let recovered_path = *paths
            .get(&commitment_bytes)
            .ok_or(WalletError::InvalidWitnessState)?;
        for (owned, note) in &self.notes {
            if paths.get(owned) != Some(&note.siblings) {
                return Err(WalletError::InvalidWitnessState);
            }
        }

        let insertion_position = self.history[insertion_undo]
            .inserted_owned_notes
            .binary_search(&commitment_bytes)
            .map_or_else(Ok, |_| Err(WalletError::InvalidWitnessState))?;
        let spend_position = spend_undo
            .filter(|index| *index != insertion_undo)
            .map(|index| {
                self.history[index]
                    .spent_existing_notes
                    .binary_search(&commitment_bytes)
                    .map_or_else(
                        |position| Ok((index, position)),
                        |_| Err(WalletError::InvalidWitnessState),
                    )
            })
            .transpose()?;

        self.history[insertion_undo]
            .inserted_owned_notes
            .insert(insertion_position, commitment_bytes);
        if let Some((index, position)) = spend_position {
            self.history[index]
                .spent_existing_notes
                .insert(position, commitment_bytes);
        }
        self.expected_issuances.insert(
            commitment_bytes,
            ExpectedIssuance {
                occurrence,
                opening: opening.clone(),
            },
        );
        self.notes.insert(
            commitment_bytes,
            TrackedNote {
                received: ReceivedNote {
                    output_index: 0,
                    commitment,
                    opening,
                },
                leaf_index,
                siblings: recovered_path,
                spent,
                reservation_id: None,
            },
        );
        Ok(commitment)
    }

    fn expected_deposit_opening(
        &self,
        wallet: &WalletSecrets,
        bridge: BridgeIdentity,
        occurrence: EthereumDepositOccurrence,
    ) -> Result<(Scalar, NoteOpening), WalletError> {
        let address = wallet.address()?;
        if wallet.chain != self.chain
            || bridge.privacy_policy_hash != *privacy_policy_hash().as_bytes()
            || occurrence.receiving_commitment != address.owner().to_bytes()
        {
            return Err(WalletError::InvalidIdentity);
        }
        let opening = ethereum_deposit_note_opening(bridge, occurrence)
            .map_err(|_| WalletError::InvalidIdentity)?;
        if opening.chain != self.chain || opening.owner != address.owner() {
            return Err(WalletError::InvalidIdentity);
        }
        let commitment = opening.commitment()?;
        Ok((commitment, opening))
    }

    /// Registered deposits and whether their exact issuance note is canonical.
    pub fn expected_issuances(&self) -> Vec<ExpectedIssuanceSummary> {
        self.expected_issuances
            .iter()
            .map(|(commitment, expected)| {
                let note_commitment = match Scalar::from_bytes(*commitment) {
                    Ok(value) => value,
                    Err(_) => Scalar::ZERO,
                };
                ExpectedIssuanceSummary {
                    deposit_id: expected.occurrence.deposit_id,
                    note_commitment,
                    amount: expected.occurrence.amount,
                    canonical: !note_commitment.is_zero()
                        && self.seen_commitments.contains(commitment),
                }
            })
            .collect()
    }

    /// Build the exact secret input witness for one currently unspent owned
    /// note under the wallet's present canonical note root.
    pub fn spend_witness(
        &self,
        wallet: &WalletSecrets,
        commitment: Scalar,
    ) -> Result<InputWitness, WalletError> {
        if wallet.chain != self.chain || commitment.is_zero() {
            return Err(WalletError::NoteUnavailable);
        }
        let note = self
            .notes
            .get(&commitment.to_bytes())
            .filter(|note| !note.spent && note.reservation_id.is_none())
            .ok_or(WalletError::NoteUnavailable)?;
        if wallet.nullifier_for(&note.received.opening).is_err() {
            return Err(WalletError::NoteUnavailable);
        }
        if !verify_membership(
            commitment,
            note.leaf_index,
            &note.siblings,
            self.note_tree.root(),
        )
        .map_err(|_| WalletError::InvalidWitnessState)?
        {
            return Err(WalletError::InvalidWitnessState);
        }
        Ok(InputWitness {
            enabled: true,
            origin: note.received.opening.origin,
            value: note.received.opening.value,
            owner_secret: wallet.owner_secret,
            rho: note.received.opening.rho,
            leaf_index: note.leaf_index,
            siblings: note.siblings,
        })
    }

    /// Atomically apply one exact canonical successor block.
    pub fn apply_block(
        &mut self,
        wallet: &WalletSecrets,
        block: CanonicalWalletBlock,
    ) -> Result<(), WalletError> {
        if wallet.chain != self.chain
            || block.identifier == Hash256::ZERO
            || block.parent_identifier != self.tip_identifier
            || block.height
                != self
                    .tip_height
                    .checked_add(1)
                    .ok_or(WalletError::ArithmeticOverflow)?
            || block.transitions.len() > MAX_TRANSITIONS_PER_BATCH
        {
            return Err(WalletError::BlockContinuity);
        }

        let mut candidate_tree = self.note_tree.clone();
        let mut block_commitments = BTreeSet::new();
        let mut block_nullifiers = BTreeSet::new();
        let mut block_private_payloads = BTreeSet::new();
        let mut inserted_commitments = Vec::new();
        let mut inserted_nullifiers = Vec::new();
        let mut spent_existing = BTreeSet::new();
        let mut staged_notes = BTreeMap::<[u8; 32], TrackedNote>::new();
        let mut updated_existing_paths = BTreeMap::<[u8; 32], [Scalar; NOTE_TREE_DEPTH]>::new();

        for observation in &block.transitions {
            if observation.effects.nullifiers.len() > MAX_INPUT_NULLIFIERS
                || observation.effects.note_commitments.len() > MAX_OUTPUT_NOTES
            {
                return Err(WalletError::ObservationMismatch);
            }
            if let Some(identifier) = observation.private_payload_id {
                if identifier == Hash256::ZERO
                    || self.seen_private_payloads.contains(identifier.as_bytes())
                    || !block_private_payloads.insert(*identifier.as_bytes())
                {
                    return Err(WalletError::DuplicateChainEffect);
                }
            }
            for nullifier in &observation.effects.nullifiers {
                let scalar =
                    Scalar::from_bytes(*nullifier).map_err(|_| WalletError::ObservationMismatch)?;
                if scalar.is_zero()
                    || self.seen_nullifiers.contains(nullifier)
                    || !block_nullifiers.insert(*nullifier)
                {
                    return Err(WalletError::DuplicateChainEffect);
                }
                let mut matched = 0usize;
                for (commitment, note) in &self.notes {
                    if !note.spent
                        && !spent_existing.contains(commitment)
                        && wallet.nullifier_for(&note.received.opening)? == scalar
                    {
                        spent_existing.insert(*commitment);
                        matched += 1;
                    }
                }
                for note in staged_notes.values_mut() {
                    if !note.spent && wallet.nullifier_for(&note.received.opening)? == scalar {
                        note.spent = true;
                        matched += 1;
                    }
                }
                if matched > 1 {
                    return Err(WalletError::DuplicateChainEffect);
                }
                inserted_nullifiers.push(*nullifier);
            }

            let commitments = observation
                .effects
                .note_commitments
                .iter()
                .map(|bytes| {
                    Scalar::from_bytes(*bytes).map_err(|_| WalletError::ObservationMismatch)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let received = if observation.encrypted_memo.is_empty() {
                Vec::new()
            } else {
                scan_memo(wallet, &commitments, &observation.encrypted_memo)?
            };
            let mut received_by_slot = received
                .into_iter()
                .map(|note| (usize::from(note.output_index), note))
                .collect::<BTreeMap<_, _>>();
            for (index, commitment) in commitments.into_iter().enumerate() {
                let bytes = commitment.to_bytes();
                if self.seen_commitments.contains(&bytes) || !block_commitments.insert(bytes) {
                    return Err(WalletError::DuplicateChainEffect);
                }
                let leaf_index = candidate_tree.leaf_count();
                let next_leaf_path = candidate_tree.next_leaf_path()?;
                for (tracked_commitment, note) in &self.notes {
                    if note.leaf_index >= leaf_index {
                        return Err(WalletError::InvalidWitnessState);
                    }
                    let differing_level =
                        (u64::BITS - 1 - (note.leaf_index ^ leaf_index).leading_zeros()) as usize;
                    let siblings = updated_existing_paths
                        .entry(*tracked_commitment)
                        .or_insert(note.siblings);
                    siblings[differing_level] =
                        candidate_tree.prospective_subtree_root(commitment, differing_level)?;
                }
                for note in staged_notes.values_mut() {
                    if note.leaf_index >= leaf_index {
                        return Err(WalletError::InvalidWitnessState);
                    }
                    let differing_level =
                        (u64::BITS - 1 - (note.leaf_index ^ leaf_index).leading_zeros()) as usize;
                    note.siblings[differing_level] =
                        candidate_tree.prospective_subtree_root(commitment, differing_level)?;
                }
                let leaf_index = candidate_tree.append(commitment)?;
                inserted_commitments.push(bytes);
                let expected_issuance = self.expected_issuances.get(&bytes);
                if expected_issuance.is_some() && observation.effects.kind != TransitionKind::Issue
                {
                    return Err(WalletError::ObservationMismatch);
                }
                let issuance_note = expected_issuance
                    .filter(|_| observation.effects.kind == TransitionKind::Issue)
                    .map(|expected| ReceivedNote {
                        output_index: index as u8,
                        commitment,
                        opening: expected.opening.clone(),
                    });
                let memo_note = received_by_slot.remove(&index);
                if memo_note.is_some() && issuance_note.is_some() {
                    return Err(WalletError::ObservationMismatch);
                }
                if let Some(note) = memo_note.or(issuance_note) {
                    if note.commitment != commitment || staged_notes.contains_key(&bytes) {
                        return Err(WalletError::ObservationMismatch);
                    }
                    let mut reservation_id = None;
                    for (identifier, pending) in &self.pending_transfers {
                        if pending.selected_commitments.contains(&bytes) {
                            if reservation_id.is_some() {
                                return Err(WalletError::InvalidWitnessState);
                            }
                            reservation_id = Some(Hash256::from_bytes(*identifier));
                        }
                    }
                    for (identifier, pending) in &self.pending_burns {
                        if pending.selected_commitments.contains(&bytes) {
                            if reservation_id.is_some() {
                                return Err(WalletError::InvalidWitnessState);
                            }
                            reservation_id = Some(Hash256::from_bytes(*identifier));
                        }
                    }
                    staged_notes.insert(
                        bytes,
                        TrackedNote {
                            received: note,
                            leaf_index,
                            siblings: next_leaf_path,
                            spent: false,
                            reservation_id,
                        },
                    );
                }
            }
            if !received_by_slot.is_empty() {
                return Err(WalletError::ObservationMismatch);
            }
        }

        let candidate_root = candidate_tree.root();
        for (commitment, note) in &self.notes {
            let siblings = updated_existing_paths
                .get(commitment)
                .unwrap_or(&note.siblings);
            if !verify_membership(
                note.received.commitment,
                note.leaf_index,
                siblings,
                candidate_root,
            )
            .map_err(|_| WalletError::InvalidWitnessState)?
            {
                return Err(WalletError::InvalidWitnessState);
            }
        }
        for note in staged_notes.values() {
            if !verify_membership(
                note.received.commitment,
                note.leaf_index,
                &note.siblings,
                candidate_root,
            )
            .map_err(|_| WalletError::InvalidWitnessState)?
            {
                return Err(WalletError::InvalidWitnessState);
            }
        }

        let commitment_count_before = self.commitment_log.len();
        let inserted_owned_notes = staged_notes.keys().copied().collect::<Vec<_>>();
        if spent_existing
            .iter()
            .any(|commitment| !self.notes.contains_key(commitment))
            || updated_existing_paths
                .keys()
                .any(|commitment| !self.notes.contains_key(commitment))
        {
            return Err(WalletError::ObservationMismatch);
        }
        for (commitment, siblings) in updated_existing_paths {
            if let Some(note) = self.notes.get_mut(&commitment) {
                note.siblings = siblings;
            }
        }
        for commitment in &spent_existing {
            if let Some(note) = self.notes.get_mut(commitment) {
                note.spent = true;
            }
        }
        self.note_tree = candidate_tree;
        self.commitment_log
            .extend(inserted_commitments.iter().copied());
        self.seen_commitments.extend(block_commitments);
        self.seen_nullifiers.extend(block_nullifiers);
        self.seen_private_payloads
            .extend(block_private_payloads.iter().copied());
        self.notes.extend(staged_notes);
        self.history.push(WalletBlockUndo {
            identifier: block.identifier,
            parent_identifier: block.parent_identifier,
            height: block.height,
            commitment_count_before,
            inserted_commitments,
            inserted_nullifiers,
            inserted_private_payloads: block_private_payloads.into_iter().collect(),
            inserted_owned_notes,
            spent_existing_notes: spent_existing.into_iter().collect(),
        });
        self.tip_height = block.height;
        self.tip_identifier = block.identifier;
        Ok(())
    }

    /// Apply a complete trusted-tip history segment atomically.
    ///
    /// If any block fails continuity, memo, uniqueness, witness, or arithmetic
    /// validation, every earlier block from this call is rolled back before the
    /// error is returned. Callers should supply only the complete output of
    /// `UsdomRpcClient::scan_authenticated_history_to_trusted_tip`.
    pub fn apply_authenticated_history(
        &mut self,
        wallet: &WalletSecrets,
        blocks: Vec<CanonicalWalletBlock>,
    ) -> Result<(), WalletError> {
        if blocks.is_empty() {
            return Err(WalletError::BlockContinuity);
        }
        let original_height = self.tip_height;
        let original_identifier = self.tip_identifier;
        for block in blocks {
            if let Err(error) = self.apply_block(wallet, block) {
                while self.tip_height > original_height {
                    let identifier = self.tip_identifier;
                    if self.rollback_tip(identifier).is_err() {
                        return Err(WalletError::InvalidWitnessState);
                    }
                }
                if self.tip_height != original_height || self.tip_identifier != original_identifier
                {
                    return Err(WalletError::InvalidWitnessState);
                }
                return Err(error);
            }
        }
        Ok(())
    }

    /// Apply one complete authenticated history segment and recover an exact
    /// historical Ethereum deposit as one atomic wallet operation.
    ///
    /// The deposit commitment is independently derived from `occurrence`; no
    /// RPC-provided leaf index, wallet balance, or ownership claim is trusted.
    /// If recovery fails after valid blocks were applied, the complete segment
    /// is rolled back to the original wallet tip.
    pub fn apply_authenticated_history_and_recover_deposit(
        &mut self,
        wallet: &WalletSecrets,
        blocks: Vec<CanonicalWalletBlock>,
        bridge: BridgeIdentity,
        occurrence: EthereumDepositOccurrence,
    ) -> Result<Scalar, WalletError> {
        let original_height = self.tip_height;
        let original_identifier = self.tip_identifier;
        self.apply_authenticated_history(wallet, blocks)?;
        match self.recover_canonical_deposit(wallet, bridge, occurrence) {
            Ok(commitment) => Ok(commitment),
            Err(error) => {
                while self.tip_height > original_height {
                    let identifier = self.tip_identifier;
                    if self.rollback_tip(identifier).is_err() {
                        return Err(WalletError::InvalidWitnessState);
                    }
                }
                if self.tip_height != original_height || self.tip_identifier != original_identifier
                {
                    return Err(WalletError::InvalidWitnessState);
                }
                Err(error)
            }
        }
    }

    /// Roll back exactly the current tip and no other block.
    pub fn rollback_tip(&mut self, expected_identifier: Hash256) -> Result<(), WalletError> {
        let undo = self.history.last().ok_or(WalletError::RollbackMismatch)?;
        if expected_identifier != self.tip_identifier
            || undo.identifier != expected_identifier
            || undo.height != self.tip_height
            || undo
                .inserted_owned_notes
                .iter()
                .any(|commitment| !self.notes.contains_key(commitment))
            || undo
                .spent_existing_notes
                .iter()
                .any(|commitment| !self.notes.contains_key(commitment))
            || undo
                .inserted_commitments
                .iter()
                .any(|commitment| !self.seen_commitments.contains(commitment))
            || undo
                .inserted_nullifiers
                .iter()
                .any(|nullifier| !self.seen_nullifiers.contains(nullifier))
            || undo
                .inserted_private_payloads
                .iter()
                .any(|identifier| !self.seen_private_payloads.contains(identifier))
            || undo
                .commitment_count_before
                .checked_add(undo.inserted_commitments.len())
                != Some(self.commitment_log.len())
            || self.commitment_log[undo.commitment_count_before..] != undo.inserted_commitments
        {
            return Err(WalletError::RollbackMismatch);
        }
        let prior_height = self
            .tip_height
            .checked_sub(1)
            .ok_or(WalletError::ArithmeticOverflow)?;
        let inserted_owned = undo
            .inserted_owned_notes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let retained_notes = self
            .notes
            .iter()
            .filter(|(commitment, _)| !inserted_owned.contains(*commitment))
            .map(|(commitment, note)| (*commitment, note.leaf_index))
            .collect::<BTreeMap<_, _>>();
        let (restored_tree, restored_paths) = Self::reconstruct_tree_and_paths(
            &self.commitment_log[..undo.commitment_count_before],
            &retained_notes,
        )?;
        let undo = self.history.pop().ok_or(WalletError::RollbackMismatch)?;
        for commitment in undo.inserted_owned_notes {
            self.notes.remove(&commitment);
        }
        for commitment in undo.spent_existing_notes {
            if let Some(note) = self.notes.get_mut(&commitment) {
                note.spent = false;
            }
        }
        for commitment in undo.inserted_commitments {
            self.seen_commitments.remove(&commitment);
        }
        for nullifier in undo.inserted_nullifiers {
            self.seen_nullifiers.remove(&nullifier);
        }
        for identifier in undo.inserted_private_payloads {
            self.seen_private_payloads.remove(&identifier);
        }
        self.commitment_log.truncate(undo.commitment_count_before);
        self.note_tree = restored_tree;
        for (commitment, siblings) in restored_paths {
            if let Some(note) = self.notes.get_mut(&commitment) {
                note.siblings = siblings;
            }
        }
        self.tip_identifier = undo.parent_identifier;
        self.tip_height = prior_height;
        Ok(())
    }

    fn reconstruct_tree_and_paths(
        commitments: &[[u8; 32]],
        owned_indices: &BTreeMap<[u8; 32], u64>,
    ) -> Result<ReconstructedWalletTree, WalletError> {
        let mut tree = IncrementalNoteTree::new();
        let mut paths = BTreeMap::<[u8; 32], [Scalar; NOTE_TREE_DEPTH]>::new();
        for (index, encoded) in commitments.iter().copied().enumerate() {
            let index = u64::try_from(index).map_err(|_| WalletError::ArithmeticOverflow)?;
            let commitment =
                Scalar::from_bytes(encoded).map_err(|_| WalletError::InvalidWitnessState)?;
            if commitment.is_zero() {
                return Err(WalletError::InvalidWitnessState);
            }
            for (owned_commitment, owned_index) in owned_indices {
                if *owned_index >= index {
                    continue;
                }
                let siblings = paths
                    .get_mut(owned_commitment)
                    .ok_or(WalletError::InvalidWitnessState)?;
                let differing_level =
                    (u64::BITS - 1 - (*owned_index ^ index).leading_zeros()) as usize;
                siblings[differing_level] =
                    tree.prospective_subtree_root(commitment, differing_level)?;
            }
            let next_path = tree.next_leaf_path()?;
            if let Some(owned_index) = owned_indices.get(&encoded) {
                if *owned_index != index || paths.insert(encoded, next_path).is_some() {
                    return Err(WalletError::InvalidWitnessState);
                }
            }
            if tree.append(commitment)? != index {
                return Err(WalletError::InvalidWitnessState);
            }
        }
        if paths.len() != owned_indices.len() {
            return Err(WalletError::InvalidWitnessState);
        }
        let root = tree.root();
        for (commitment, index) in owned_indices {
            let leaf =
                Scalar::from_bytes(*commitment).map_err(|_| WalletError::InvalidWitnessState)?;
            if !verify_membership(
                leaf,
                *index,
                paths
                    .get(commitment)
                    .ok_or(WalletError::InvalidWitnessState)?,
                root,
            )
            .map_err(|_| WalletError::InvalidWitnessState)?
            {
                return Err(WalletError::InvalidWitnessState);
            }
        }
        Ok((tree, paths))
    }
}

#[cfg(test)]
mod tests {
    use dom_core::Hash256;
    use dom_usdom_privacy::{chain_scalar, memo_scalar, privacy_policy_hash, NOTE_ORIGIN_ISSUANCE};
    use dom_usdom_state::{
        encode_private_burn_payload, encode_private_transfer_payload, unsafe_test_only_burn,
        unsafe_test_only_issuance, unsafe_test_only_transfer, BurnRecord, BurnTimingPolicy,
        EthereumAnchor, NoteAnchor, VerifiedTransition,
    };
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    fn scalar(value: u64) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Scalar::from_bytes(bytes).unwrap()
    }

    fn passphrase(value: &str) -> WalletPassphrase {
        WalletPassphrase::new(value.to_owned()).unwrap()
    }

    fn test_bridge(domain: [u8; 32]) -> BridgeIdentity {
        let mut ethereum_chain_id = [0u8; 32];
        ethereum_chain_id[31] = 1;
        BridgeIdentity {
            dom_domain: domain,
            ethereum_genesis_validators_root: [0xa1; 32],
            ethereum_chain_id,
            ethereum_checkpoint_policy_hash: [0xa2; 32],
            ethereum_deposit_policy_hash: [0xa3; 32],
            privacy_policy_hash: *privacy_policy_hash().as_bytes(),
            privacy_verifier_config_hash: [0xa4; 32],
            reserve: [0xa5; 20],
            burn_timing: BurnTimingPolicy {
                withdrawal_delay_secs: 24 * 60 * 60,
                min_execution_window_secs: 60 * 60,
                max_certificate_lifetime_secs: 7 * 24 * 60 * 60,
                relay_safety_margin_secs: 2 * 24 * 60 * 60,
                max_ethereum_anchor_age_secs: 24 * 60 * 60,
                max_dom_clock_lead_secs: 2 * 60 * 60,
            },
        }
    }

    #[test]
    fn deterministic_recovery_seed_is_chain_separated_and_encrypted_at_rest() {
        let chain = chain_scalar([0x91; 32], *privacy_policy_hash().as_bytes());
        let other_chain = chain_scalar([0x92; 32], *privacy_policy_hash().as_bytes());
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_5243);
        let seed = WalletRecoverySeed::generate(&mut rng);
        let address = WalletSecrets::from_recovery_seed(chain, &seed)
            .unwrap()
            .address()
            .unwrap();
        let same_address = WalletSecrets::from_recovery_seed(chain, &seed)
            .unwrap()
            .address()
            .unwrap();
        let other_address = WalletSecrets::from_recovery_seed(other_chain, &seed)
            .unwrap()
            .address()
            .unwrap();
        assert_eq!(address, same_address);
        assert_ne!(address, other_address);

        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let path = directory.path().join("recovery.usdom");
        let password = passphrase("correct recovery backup password");
        seed.save_encrypted_backup(chain, &path, &password).unwrap();
        let encrypted = std::fs::read(&path).unwrap();
        assert!(encrypted.len() > RECOVERY_PLAINTEXT_BYTES);
        assert!(!encrypted
            .windows(address.to_bytes().len())
            .any(|window| { window == address.to_bytes().as_slice() }));

        let restored = WalletRecoverySeed::load_encrypted_backup(&path, chain, &password).unwrap();
        assert_eq!(
            WalletSecrets::from_recovery_seed(chain, &restored)
                .unwrap()
                .address()
                .unwrap(),
            address
        );
        assert!(matches!(
            seed.save_encrypted_backup(chain, &path, &password),
            Err(WalletRecoveryError::Envelope(
                EnvelopeError::DestinationExists
            ))
        ));
        assert!(matches!(
            WalletRecoverySeed::load_encrypted_backup(&path, other_chain, &password),
            Err(WalletRecoveryError::WrongChain)
        ));
        assert!(matches!(
            WalletRecoverySeed::load_encrypted_backup(
                &path,
                chain,
                &passphrase("incorrect recovery backup password")
            ),
            Err(WalletRecoveryError::Envelope(_))
        ));

        let mut corrupted = encrypted;
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        std::fs::write(&path, corrupted).unwrap();
        assert!(matches!(
            WalletRecoverySeed::load_encrypted_backup(&path, chain, &password),
            Err(WalletRecoveryError::Envelope(_))
        ));
    }

    #[test]
    fn two_recipient_memo_roundtrips_and_is_bound_to_slots_and_commitments() {
        let chain = chain_scalar([0x44; 32], *privacy_policy_hash().as_bytes());
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_4d45);
        let alice = WalletSecrets::generate(chain, &mut rng).unwrap();
        let bob = WalletSecrets::generate(chain, &mut rng).unwrap();
        let outsider = WalletSecrets::generate(chain, &mut rng).unwrap();
        let encrypted = encrypt_outputs(
            chain,
            vec![
                MemoOutput {
                    recipient: bob.address().unwrap(),
                    value: 7,
                    rho: scalar(17),
                },
                MemoOutput {
                    recipient: alice.address().unwrap(),
                    value: 3,
                    rho: scalar(18),
                },
            ],
            &mut rng,
        )
        .unwrap();
        assert_eq!(encrypted.memo().len(), MAX_CANONICAL_MEMO_BYTES);
        assert!(!memo_scalar(encrypted.memo()).unwrap().is_zero());

        let bob_notes = scan_memo(&bob, encrypted.commitments(), encrypted.memo()).unwrap();
        assert_eq!(bob_notes.len(), 1);
        assert_eq!(bob_notes[0].output_index, 0);
        assert_eq!(bob_notes[0].opening.value, 7);
        let alice_notes = scan_memo(&alice, encrypted.commitments(), encrypted.memo()).unwrap();
        assert_eq!(alice_notes.len(), 1);
        assert_eq!(alice_notes[0].output_index, 1);
        assert_eq!(alice_notes[0].opening.value, 3);
        assert!(
            scan_memo(&outsider, encrypted.commitments(), encrypted.memo())
                .unwrap()
                .is_empty()
        );

        let mut swapped = encrypted.commitments().to_vec();
        swapped.swap(0, 1);
        assert!(scan_memo(&bob, &swapped, encrypted.memo())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn address_and_memo_framing_are_canonical_and_fail_closed() {
        let chain = chain_scalar([0x55; 32], *privacy_policy_hash().as_bytes());
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_4144);
        let wallet = WalletSecrets::generate(chain, &mut rng).unwrap();
        let address = wallet.address().unwrap();
        assert_eq!(
            RecipientAddress::from_bytes(&address.to_bytes()).unwrap(),
            address
        );
        let mut trailing = address.to_bytes().to_vec();
        trailing.push(0);
        assert_eq!(
            RecipientAddress::from_bytes(&trailing),
            Err(WalletError::InvalidAddress)
        );

        let encrypted = encrypt_outputs(
            chain,
            vec![MemoOutput {
                recipient: address,
                value: 1,
                rho: scalar(19),
            }],
            &mut rng,
        )
        .unwrap();
        let mut malformed = encrypted.memo().to_vec();
        malformed.push(0);
        assert!(matches!(
            scan_memo(&wallet, encrypted.commitments(), &malformed),
            Err(WalletError::InvalidMemo)
        ));
        let mut duplicate = encrypted.memo().to_vec();
        duplicate[8] = 2;
        assert!(matches!(
            scan_memo(&wallet, encrypted.commitments(), &duplicate),
            Err(WalletError::InvalidMemo)
        ));
    }

    #[test]
    fn wrong_chain_and_low_order_scan_key_are_rejected() {
        let chain = chain_scalar([0x66; 32], *privacy_policy_hash().as_bytes());
        let other_chain = chain_scalar([0x67; 32], *privacy_policy_hash().as_bytes());
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_4c4f);
        let wallet = WalletSecrets::generate(chain, &mut rng).unwrap();
        assert_eq!(
            encrypt_outputs(
                other_chain,
                vec![MemoOutput {
                    recipient: wallet.address().unwrap(),
                    value: 1,
                    rho: scalar(20),
                }],
                &mut rng,
            )
            .unwrap_err(),
            WalletError::InvalidIdentity
        );
        let mut zero_key = wallet.address().unwrap();
        zero_key.scan_public = [0; 32];
        assert_eq!(
            encrypt_outputs(
                chain,
                vec![MemoOutput {
                    recipient: zero_key,
                    value: 1,
                    rho: scalar(21),
                }],
                &mut rng,
            )
            .unwrap_err(),
            WalletError::InvalidAddress
        );
        let mut low_order = wallet.address().unwrap();
        low_order.scan_public = {
            let mut point = [0; 32];
            point[0] = 1;
            point
        };
        assert_eq!(
            encrypt_outputs(
                chain,
                vec![MemoOutput {
                    recipient: low_order,
                    value: 1,
                    rho: scalar(21),
                }],
                &mut rng,
            )
            .unwrap_err(),
            WalletError::InvalidScanKey
        );
    }

    #[test]
    fn canonical_transfer_payload_scans_without_granting_proof_authority() {
        let chain = chain_scalar([0x77; 32], *privacy_policy_hash().as_bytes());
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_504c);
        let wallet = WalletSecrets::generate(chain, &mut rng).unwrap();
        let encrypted = encrypt_outputs(
            chain,
            vec![MemoOutput {
                recipient: wallet.address().unwrap(),
                value: 42,
                rho: scalar(22),
            }],
            &mut rng,
        )
        .unwrap();
        let payload = encode_private_transfer_payload(
            NoteAnchor {
                root: Hash256::from_bytes(scalar(23).to_bytes()),
                leaf_count: 1,
            },
            &[scalar(24).to_bytes()],
            &[encrypted.commitments()[0].to_bytes()],
            encrypted.memo(),
            &[0u8; 128],
        )
        .unwrap();
        let notes = scan_private_transfer_payload(&wallet, &payload).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].opening.value, 42);

        let mut malformed = payload;
        malformed.push(0);
        assert!(matches!(
            scan_private_transfer_payload(&wallet, &malformed),
            Err(WalletError::InvalidTransitionPayload)
        ));
    }

    #[test]
    fn authenticated_history_application_is_all_or_nothing() {
        let domain = [0x86; 32];
        let chain = chain_scalar(domain, *privacy_policy_hash().as_bytes());
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_4849);
        let wallet = WalletSecrets::generate(chain, &mut rng).unwrap();
        let original = Hash256::from_bytes([0x11; 32]);
        let first = Hash256::from_bytes([0x12; 32]);
        let second = Hash256::from_bytes([0x13; 32]);
        let mut state = WalletState::new_empty(chain, 10, original).unwrap();
        let block = |height, identifier, parent_identifier| CanonicalWalletBlock {
            height,
            identifier,
            parent_identifier,
            transitions: Vec::new(),
        };

        assert_eq!(
            state.apply_authenticated_history(
                &wallet,
                vec![
                    block(11, first, original),
                    block(12, second, first),
                    block(
                        13,
                        Hash256::from_bytes([0x14; 32]),
                        Hash256::from_bytes([0xff; 32])
                    ),
                ],
            ),
            Err(WalletError::BlockContinuity)
        );
        assert_eq!(state.tip_height(), 10);
        assert_eq!(state.tip_identifier(), original);

        state
            .apply_authenticated_history(
                &wallet,
                vec![block(11, first, original), block(12, second, first)],
            )
            .unwrap();
        assert_eq!(state.tip_height(), 12);
        assert_eq!(state.tip_identifier(), second);
        assert_eq!(
            state.apply_authenticated_history(&wallet, Vec::new()),
            Err(WalletError::BlockContinuity)
        );
    }

    #[test]
    fn authenticated_history_deposit_recovery_commits_or_rolls_back_together() {
        let domain = [0x87; 32];
        let bridge = test_bridge(domain);
        let chain = chain_scalar(domain, bridge.privacy_policy_hash);
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_4852);
        let wallet = WalletSecrets::generate(chain, &mut rng).unwrap();
        let occurrence = EthereumDepositOccurrence {
            genesis_validators_root: bridge.ethereum_genesis_validators_root,
            block_hash: [0x31; 32],
            block_number: 22_200_000,
            transaction_index: 4,
            receipt_log_index: 2,
            deposit_id: [0x32; 32],
            funder: [0x33; 20],
            amount: 43_000_000,
            receiving_commitment: wallet.address().unwrap().owner().to_bytes(),
        };
        let commitment = ethereum_deposit_note_opening(bridge, occurrence)
            .unwrap()
            .commitment()
            .unwrap();
        let initial = Hash256::from_bytes([0x34; 32]);
        let issued_tip = Hash256::from_bytes([0x35; 32]);
        let issuance = VerifiedTransition::Issue(unsafe_test_only_issuance(
            domain,
            occurrence.deposit_id,
            commitment.to_bytes(),
            occurrence.amount,
            EthereumAnchor {
                genesis_validators_root: bridge.ethereum_genesis_validators_root,
                execution_block_number: occurrence.block_number,
                execution_block_hash: occurrence.block_hash,
                execution_block_timestamp: 1_800_000_200,
                beacon_slot: 12_345_800,
                beacon_root: [0x36; 32],
            },
        ));
        let block = CanonicalWalletBlock {
            height: 301,
            identifier: issued_tip,
            parent_identifier: initial,
            transitions: vec![WalletTransitionObservation::from_verified(&issuance, None).unwrap()],
        };

        let mut successful = WalletState::new_empty(chain, 300, initial).unwrap();
        assert_eq!(
            successful
                .apply_authenticated_history_and_recover_deposit(
                    &wallet,
                    vec![block.clone()],
                    bridge,
                    occurrence,
                )
                .unwrap(),
            commitment
        );
        assert_eq!(successful.tip_identifier(), issued_tip);
        assert_eq!(
            successful.available_balance(),
            u128::from(occurrence.amount)
        );

        let mut absent = occurrence;
        absent.deposit_id = [0x37; 32];
        let mut rejected = WalletState::new_empty(chain, 300, initial).unwrap();
        assert_eq!(
            rejected.apply_authenticated_history_and_recover_deposit(
                &wallet,
                vec![block],
                bridge,
                absent,
            ),
            Err(WalletError::ExpectedIssuanceNotCanonical)
        );
        assert_eq!(rejected.tip_height(), 300);
        assert_eq!(rejected.tip_identifier(), initial);
        assert!(rejected.note_summaries().is_empty());
        assert!(rejected.expected_issuances().is_empty());
    }

    #[test]
    fn wallet_state_applies_spends_and_rolls_back_exact_tip_atomically() {
        let domain = [0x88; 32];
        let chain = chain_scalar(domain, *privacy_policy_hash().as_bytes());
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_5354);
        let wallet = WalletSecrets::generate(chain, &mut rng).unwrap();
        let rho = scalar(31);
        let encrypted = encrypt_outputs(
            chain,
            vec![MemoOutput {
                recipient: wallet.address().unwrap(),
                value: 11,
                rho,
            }],
            &mut rng,
        )
        .unwrap();
        let anchor = NoteAnchor {
            root: Hash256::from_bytes(scalar(32).to_bytes()),
            leaf_count: 1,
        };
        let unrelated_nullifier = scalar(33).to_bytes();
        let output = encrypted.commitments()[0].to_bytes();
        let payload = encode_private_transfer_payload(
            anchor,
            &[unrelated_nullifier],
            &[output],
            encrypted.memo(),
            &[0u8; 128],
        )
        .unwrap();
        let verified = VerifiedTransition::Transfer(unsafe_test_only_transfer(
            domain,
            anchor,
            vec![unrelated_nullifier],
            vec![output],
            memo_scalar(encrypted.memo()).unwrap().to_bytes(),
        ));
        let mismatched_verified = VerifiedTransition::Transfer(unsafe_test_only_transfer(
            domain,
            anchor,
            vec![unrelated_nullifier],
            vec![scalar(34).to_bytes()],
            memo_scalar(encrypted.memo()).unwrap().to_bytes(),
        ));
        assert_eq!(
            WalletTransitionObservation::from_verified(&mismatched_verified, Some(&payload)),
            Err(WalletError::ObservationMismatch)
        );
        let mut substituted_memo = encrypted.memo().to_vec();
        *substituted_memo.last_mut().unwrap() ^= 1;
        let substituted_payload = encode_private_transfer_payload(
            anchor,
            &[unrelated_nullifier],
            &[output],
            &substituted_memo,
            &[0u8; 128],
        )
        .unwrap();
        assert_eq!(
            WalletTransitionObservation::from_verified(&verified, Some(&substituted_payload)),
            Err(WalletError::ObservationMismatch)
        );
        let mut ethereum_chain_id = [0; 32];
        ethereum_chain_id[31] = 1;
        let mut record = BurnRecord {
            burn_id: [0x41; 32],
            request_id: [0x42; 32],
            amount: 1,
            recipient: [0x43; 20],
            ethereum_chain_id,
            reserve: [0x44; 20],
            valid_until: 1_900_000_000,
            obligation_commitment: [0; 32],
        };
        record.obligation_commitment = record.expected_obligation_commitment(domain);
        let burn_payload = encode_private_burn_payload(
            anchor,
            &[unrelated_nullifier],
            &[output],
            record,
            encrypted.memo(),
            &[0u8; 128],
        )
        .unwrap();
        let verified_burn = VerifiedTransition::Burn(unsafe_test_only_burn(
            domain,
            anchor,
            vec![unrelated_nullifier],
            vec![output],
            memo_scalar(encrypted.memo()).unwrap().to_bytes(),
            record,
        ));
        WalletTransitionObservation::from_verified(&verified_burn, Some(&burn_payload)).unwrap();
        let substituted_burn_payload = encode_private_burn_payload(
            anchor,
            &[unrelated_nullifier],
            &[output],
            record,
            &substituted_memo,
            &[0u8; 128],
        )
        .unwrap();
        assert_eq!(
            WalletTransitionObservation::from_verified(
                &verified_burn,
                Some(&substituted_burn_payload)
            ),
            Err(WalletError::ObservationMismatch)
        );
        let receive =
            WalletTransitionObservation::from_verified(&verified, Some(&payload)).unwrap();

        let initial_id = Hash256::from_bytes([1; 32]);
        let receive_id = Hash256::from_bytes([2; 32]);
        let spend_id = Hash256::from_bytes([3; 32]);
        let mut state = WalletState::new_empty(chain, 10, initial_id).unwrap();
        let empty_root = state.note_root();
        state
            .apply_block(
                &wallet,
                CanonicalWalletBlock {
                    height: 11,
                    identifier: receive_id,
                    parent_identifier: initial_id,
                    transitions: vec![receive],
                },
            )
            .unwrap();
        assert_eq!(state.available_balance(), 11);
        assert_eq!(state.note_summaries()[0].leaf_index, 0);
        assert_ne!(state.note_root(), empty_root);

        let before_bad = (
            state.tip_height(),
            state.tip_identifier(),
            state.available_balance(),
        );
        assert!(matches!(
            state.apply_block(
                &wallet,
                CanonicalWalletBlock {
                    height: 12,
                    identifier: Hash256::from_bytes([9; 32]),
                    parent_identifier: initial_id,
                    transitions: Vec::new(),
                }
            ),
            Err(WalletError::BlockContinuity)
        ));
        assert_eq!(
            (
                state.tip_height(),
                state.tip_identifier(),
                state.available_balance()
            ),
            before_bad
        );

        let opening = NoteOpening {
            chain,
            origin: NOTE_ORIGIN_PRIVATE,
            value: 11,
            owner: wallet.address().unwrap().owner(),
            rho,
        };
        let spend_nullifier = wallet.nullifier_for(&opening).unwrap().to_bytes();
        let spend = WalletTransitionObservation {
            effects: TransitionPublicEffects {
                kind: TransitionKind::Burn,
                nullifiers: vec![spend_nullifier],
                note_commitments: Vec::new(),
                memo_commitment: Some([0; 32]),
            },
            encrypted_memo: Vec::new(),
            private_payload_id: None,
        };
        state
            .apply_block(
                &wallet,
                CanonicalWalletBlock {
                    height: 12,
                    identifier: spend_id,
                    parent_identifier: receive_id,
                    transitions: vec![spend],
                },
            )
            .unwrap();
        assert_eq!(state.available_balance(), 0);
        assert!(state.note_summaries()[0].spent);
        assert!(matches!(
            state.rollback_tip(receive_id),
            Err(WalletError::RollbackMismatch)
        ));
        assert_eq!(state.available_balance(), 0);

        state.rollback_tip(spend_id).unwrap();
        assert_eq!(state.available_balance(), 11);
        assert!(!state.note_summaries()[0].spent);

        let duplicate = WalletTransitionObservation {
            effects: TransitionPublicEffects {
                kind: TransitionKind::Issue,
                nullifiers: Vec::new(),
                note_commitments: vec![output],
                memo_commitment: None,
            },
            encrypted_memo: Vec::new(),
            private_payload_id: None,
        };
        assert!(matches!(
            state.apply_block(
                &wallet,
                CanonicalWalletBlock {
                    height: 12,
                    identifier: Hash256::from_bytes([4; 32]),
                    parent_identifier: receive_id,
                    transitions: vec![duplicate],
                }
            ),
            Err(WalletError::DuplicateChainEffect)
        ));
        assert_eq!(state.tip_identifier(), receive_id);
        assert_eq!(state.available_balance(), 11);

        state.rollback_tip(receive_id).unwrap();
        assert_eq!(state.tip_identifier(), initial_id);
        assert_eq!(state.tip_height(), 10);
        assert_eq!(state.available_balance(), 0);
        assert_eq!(state.note_root(), empty_root);
        assert!(state.note_summaries().is_empty());
    }

    #[test]
    fn wallet_state_tracks_a_note_received_and_spent_in_the_same_block() {
        let domain = [0x99; 32];
        let chain = chain_scalar(domain, *privacy_policy_hash().as_bytes());
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_5342);
        let wallet = WalletSecrets::generate(chain, &mut rng).unwrap();
        let rho = scalar(41);
        let encrypted = encrypt_outputs(
            chain,
            vec![MemoOutput {
                recipient: wallet.address().unwrap(),
                value: 17,
                rho,
            }],
            &mut rng,
        )
        .unwrap();
        let anchor = NoteAnchor {
            root: Hash256::from_bytes(scalar(42).to_bytes()),
            leaf_count: 1,
        };
        let unrelated_nullifier = scalar(43).to_bytes();
        let output = encrypted.commitments()[0].to_bytes();
        let payload = encode_private_transfer_payload(
            anchor,
            &[unrelated_nullifier],
            &[output],
            encrypted.memo(),
            &[0u8; 128],
        )
        .unwrap();
        let verified = VerifiedTransition::Transfer(unsafe_test_only_transfer(
            domain,
            anchor,
            vec![unrelated_nullifier],
            vec![output],
            memo_scalar(encrypted.memo()).unwrap().to_bytes(),
        ));
        let receive =
            WalletTransitionObservation::from_verified(&verified, Some(&payload)).unwrap();
        let opening = NoteOpening {
            chain,
            origin: NOTE_ORIGIN_PRIVATE,
            value: 17,
            owner: wallet.address().unwrap().owner(),
            rho,
        };
        let spend = WalletTransitionObservation {
            effects: TransitionPublicEffects {
                kind: TransitionKind::Burn,
                nullifiers: vec![wallet.nullifier_for(&opening).unwrap().to_bytes()],
                note_commitments: Vec::new(),
                memo_commitment: Some([0; 32]),
            },
            encrypted_memo: Vec::new(),
            private_payload_id: None,
        };

        let initial_id = Hash256::from_bytes([5; 32]);
        let block_id = Hash256::from_bytes([6; 32]);
        let mut state = WalletState::new_empty(chain, 20, initial_id).unwrap();
        state
            .apply_block(
                &wallet,
                CanonicalWalletBlock {
                    height: 21,
                    identifier: block_id,
                    parent_identifier: initial_id,
                    transitions: vec![receive, spend],
                },
            )
            .unwrap();
        assert_eq!(state.available_balance(), 0);
        assert_eq!(state.note_summaries().len(), 1);
        assert!(state.note_summaries()[0].spent);

        state.rollback_tip(block_id).unwrap();
        assert_eq!(state.tip_identifier(), initial_id);
        assert_eq!(state.available_balance(), 0);
        assert!(state.note_summaries().is_empty());
    }

    #[test]
    fn wallet_state_exports_current_witness_and_rolls_path_updates_back() {
        let domain = [0xaa; 32];
        let chain = chain_scalar(domain, *privacy_policy_hash().as_bytes());
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_5754);
        let wallet = WalletSecrets::generate(chain, &mut rng).unwrap();
        let encrypted = encrypt_outputs(
            chain,
            vec![
                MemoOutput {
                    recipient: wallet.address().unwrap(),
                    value: 19,
                    rho: scalar(51),
                },
                MemoOutput {
                    recipient: wallet.address().unwrap(),
                    value: 23,
                    rho: scalar(52),
                },
            ],
            &mut rng,
        )
        .unwrap();
        let anchor = NoteAnchor {
            root: Hash256::from_bytes(scalar(53).to_bytes()),
            leaf_count: 1,
        };
        let unrelated_nullifier = scalar(54).to_bytes();
        let outputs = encrypted
            .commitments()
            .iter()
            .map(|commitment| commitment.to_bytes())
            .collect::<Vec<_>>();
        let payload = encode_private_transfer_payload(
            anchor,
            &[unrelated_nullifier],
            &outputs,
            encrypted.memo(),
            &[0u8; 128],
        )
        .unwrap();
        let verified = VerifiedTransition::Transfer(unsafe_test_only_transfer(
            domain,
            anchor,
            vec![unrelated_nullifier],
            outputs,
            memo_scalar(encrypted.memo()).unwrap().to_bytes(),
        ));
        let receive =
            WalletTransitionObservation::from_verified(&verified, Some(&payload)).unwrap();

        let initial_id = Hash256::from_bytes([7; 32]);
        let receive_id = Hash256::from_bytes([8; 32]);
        let append_id = Hash256::from_bytes([9; 32]);
        let mut state = WalletState::new_empty(chain, 30, initial_id).unwrap();
        state
            .apply_block(
                &wallet,
                CanonicalWalletBlock {
                    height: 31,
                    identifier: receive_id,
                    parent_identifier: initial_id,
                    transitions: vec![receive],
                },
            )
            .unwrap();
        assert_eq!(state.available_balance(), 42);
        let first_commitment = encrypted.commitments()[0];
        let witness_before = state.spend_witness(&wallet, first_commitment).unwrap();
        assert_eq!(witness_before.value, 19);
        assert!(verify_membership(
            first_commitment,
            witness_before.leaf_index,
            &witness_before.siblings,
            state.note_root(),
        )
        .unwrap());
        let path_before = witness_before.siblings;
        let root_before = state.note_root();

        let unrelated_commitment = scalar(55);
        state
            .apply_block(
                &wallet,
                CanonicalWalletBlock {
                    height: 32,
                    identifier: append_id,
                    parent_identifier: receive_id,
                    transitions: vec![WalletTransitionObservation {
                        effects: TransitionPublicEffects {
                            kind: TransitionKind::Issue,
                            nullifiers: Vec::new(),
                            note_commitments: vec![unrelated_commitment.to_bytes()],
                            memo_commitment: None,
                        },
                        encrypted_memo: Vec::new(),
                        private_payload_id: None,
                    }],
                },
            )
            .unwrap();
        let witness_after = state.spend_witness(&wallet, first_commitment).unwrap();
        assert_ne!(witness_after.siblings, path_before);
        assert_ne!(state.note_root(), root_before);
        assert!(verify_membership(
            first_commitment,
            witness_after.leaf_index,
            &witness_after.siblings,
            state.note_root(),
        )
        .unwrap());

        state.rollback_tip(append_id).unwrap();
        let restored = state.spend_witness(&wallet, first_commitment).unwrap();
        assert_eq!(restored.siblings, path_before);
        assert_eq!(state.note_root(), root_before);
    }

    #[test]
    fn preregistered_finalized_deposit_becomes_an_origin_separated_owned_note() {
        let domain = [0xd1; 32];
        let bridge = test_bridge(domain);
        let chain = chain_scalar(domain, bridge.privacy_policy_hash);
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_4953);
        let wallet = WalletSecrets::generate(chain, &mut rng).unwrap();
        let occurrence = EthereumDepositOccurrence {
            genesis_validators_root: bridge.ethereum_genesis_validators_root,
            block_hash: [0xd2; 32],
            block_number: 22_000_000,
            transaction_index: 7,
            receipt_log_index: 3,
            deposit_id: [0xd3; 32],
            funder: [0xd4; 20],
            amount: 25_000_000,
            receiving_commitment: wallet.address().unwrap().owner().to_bytes(),
        };
        let initial = Hash256::from_bytes([0xd5; 32]);
        let mut state = WalletState::new_empty(chain, 100, initial).unwrap();
        let commitment = state
            .register_expected_deposit(&wallet, bridge, occurrence)
            .unwrap();
        assert_eq!(state.expected_issuances().len(), 1);
        assert!(!state.expected_issuances()[0].canonical);
        assert_eq!(
            state.register_expected_deposit(&wallet, bridge, occurrence),
            Err(WalletError::DuplicateExpectedIssuance)
        );
        let opening = ethereum_deposit_note_opening(bridge, occurrence).unwrap();
        assert_eq!(opening.origin, NOTE_ORIGIN_ISSUANCE);
        assert_ne!(
            opening.commitment().unwrap(),
            NoteOpening {
                origin: NOTE_ORIGIN_PRIVATE,
                ..opening.clone()
            }
            .commitment()
            .unwrap()
        );

        let ethereum_anchor = EthereumAnchor {
            genesis_validators_root: bridge.ethereum_genesis_validators_root,
            execution_block_number: occurrence.block_number,
            execution_block_hash: occurrence.block_hash,
            execution_block_timestamp: 1_800_000_000,
            beacon_slot: 12_345_678,
            beacon_root: [0xd6; 32],
        };
        let issuance = VerifiedTransition::Issue(unsafe_test_only_issuance(
            domain,
            occurrence.deposit_id,
            commitment.to_bytes(),
            occurrence.amount,
            ethereum_anchor,
        ));
        let observation = WalletTransitionObservation::from_verified(&issuance, None).unwrap();
        let issued_tip = Hash256::from_bytes([0xd7; 32]);
        state
            .apply_block(
                &wallet,
                CanonicalWalletBlock {
                    height: 101,
                    identifier: issued_tip,
                    parent_identifier: initial,
                    transitions: vec![observation],
                },
            )
            .unwrap();
        assert_eq!(state.available_balance(), u128::from(occurrence.amount));
        assert_eq!(state.note_summaries()[0].origin, NOTE_ORIGIN_ISSUANCE);
        assert!(state.expected_issuances()[0].canonical);
        assert_eq!(
            state.spend_witness(&wallet, commitment).unwrap().origin,
            NOTE_ORIGIN_ISSUANCE
        );

        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let snapshot = directory.path().join("issuance.usdom");
        let seal = state
            .save_encrypted_snapshot(
                &wallet,
                &snapshot,
                &passphrase("issuance snapshot password"),
                1,
                None,
            )
            .unwrap();
        let mut restored = WalletState::load_encrypted_snapshot(
            &snapshot,
            &passphrase("issuance snapshot password"),
            seal,
        )
        .unwrap();
        assert!(restored.state.expected_issuances()[0].canonical);
        restored.state.rollback_tip(issued_tip).unwrap();
        assert_eq!(restored.state.available_balance(), 0);
        assert!(!restored.state.expected_issuances()[0].canonical);
    }

    #[test]
    fn late_deposit_recovery_rebuilds_witness_snapshot_and_exact_reorg_undo() {
        let domain = [0xe1; 32];
        let bridge = test_bridge(domain);
        let chain = chain_scalar(domain, bridge.privacy_policy_hash);
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_5245);
        let wallet = WalletSecrets::generate(chain, &mut rng).unwrap();
        let occurrence = EthereumDepositOccurrence {
            genesis_validators_root: bridge.ethereum_genesis_validators_root,
            block_hash: [0xe2; 32],
            block_number: 22_100_000,
            transaction_index: 9,
            receipt_log_index: 4,
            deposit_id: [0xe3; 32],
            funder: [0xe4; 20],
            amount: 31_000_000,
            receiving_commitment: wallet.address().unwrap().owner().to_bytes(),
        };
        let opening = ethereum_deposit_note_opening(bridge, occurrence).unwrap();
        let commitment = opening.commitment().unwrap();
        let initial = Hash256::from_bytes([0xe5; 32]);
        let issued_tip = Hash256::from_bytes([0xe6; 32]);
        let mut state = WalletState::new_empty(chain, 200, initial).unwrap();
        assert_eq!(
            state.recover_canonical_deposit(&wallet, bridge, occurrence),
            Err(WalletError::ExpectedIssuanceNotCanonical)
        );
        let issuance = VerifiedTransition::Issue(unsafe_test_only_issuance(
            domain,
            occurrence.deposit_id,
            commitment.to_bytes(),
            occurrence.amount,
            EthereumAnchor {
                genesis_validators_root: bridge.ethereum_genesis_validators_root,
                execution_block_number: occurrence.block_number,
                execution_block_hash: occurrence.block_hash,
                execution_block_timestamp: 1_800_000_100,
                beacon_slot: 12_345_700,
                beacon_root: [0xe7; 32],
            },
        ));
        state
            .apply_block(
                &wallet,
                CanonicalWalletBlock {
                    height: 201,
                    identifier: issued_tip,
                    parent_identifier: initial,
                    transitions: vec![
                        WalletTransitionObservation::from_verified(&issuance, None).unwrap()
                    ],
                },
            )
            .unwrap();
        assert_eq!(state.available_balance(), 0);
        assert!(state.note_summaries().is_empty());
        assert_eq!(
            state.register_expected_deposit(&wallet, bridge, occurrence),
            Err(WalletError::ExpectedIssuanceTooLate)
        );

        assert_eq!(
            state
                .recover_canonical_deposit(&wallet, bridge, occurrence)
                .unwrap(),
            commitment
        );
        assert_eq!(state.available_balance(), u128::from(occurrence.amount));
        assert_eq!(
            state.spend_witness(&wallet, commitment).unwrap().origin,
            NOTE_ORIGIN_ISSUANCE
        );
        assert_eq!(
            state.recover_canonical_deposit(&wallet, bridge, occurrence),
            Err(WalletError::DuplicateExpectedIssuance)
        );

        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let snapshot = directory.path().join("recovered-issuance.usdom");
        let seal = state
            .save_encrypted_snapshot(
                &wallet,
                &snapshot,
                &passphrase("recovered issuance snapshot password"),
                1,
                None,
            )
            .unwrap();
        let mut restored = WalletState::load_encrypted_snapshot(
            &snapshot,
            &passphrase("recovered issuance snapshot password"),
            seal,
        )
        .unwrap();
        assert_eq!(
            restored.state.available_balance(),
            u128::from(occurrence.amount)
        );
        restored.state.rollback_tip(issued_tip).unwrap();
        assert_eq!(restored.state.available_balance(), 0);
        assert!(restored.state.note_summaries().is_empty());
        assert!(!restored.state.expected_issuances()[0].canonical);
    }

    #[test]
    fn late_deposit_recovery_preserves_prior_spend_and_rolls_it_back_exactly() {
        let domain = [0xf1; 32];
        let bridge = test_bridge(domain);
        let chain = chain_scalar(domain, bridge.privacy_policy_hash);
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_5350);
        let wallet = WalletSecrets::generate(chain, &mut rng).unwrap();
        let occurrence = EthereumDepositOccurrence {
            genesis_validators_root: bridge.ethereum_genesis_validators_root,
            block_hash: [0xf2; 32],
            block_number: 22_200_000,
            transaction_index: 11,
            receipt_log_index: 5,
            deposit_id: [0xf3; 32],
            funder: [0xf4; 20],
            amount: 19_000_000,
            receiving_commitment: wallet.address().unwrap().owner().to_bytes(),
        };
        let opening = ethereum_deposit_note_opening(bridge, occurrence).unwrap();
        let commitment = opening.commitment().unwrap();
        let nullifier = wallet.nullifier_for(&opening).unwrap().to_bytes();
        let initial = Hash256::from_bytes([0xf5; 32]);
        let issued_tip = Hash256::from_bytes([0xf6; 32]);
        let spent_tip = Hash256::from_bytes([0xf7; 32]);
        let mut state = WalletState::new_empty(chain, 300, initial).unwrap();
        let issuance = VerifiedTransition::Issue(unsafe_test_only_issuance(
            domain,
            occurrence.deposit_id,
            commitment.to_bytes(),
            occurrence.amount,
            EthereumAnchor {
                genesis_validators_root: bridge.ethereum_genesis_validators_root,
                execution_block_number: occurrence.block_number,
                execution_block_hash: occurrence.block_hash,
                execution_block_timestamp: 1_800_000_200,
                beacon_slot: 12_345_800,
                beacon_root: [0xf8; 32],
            },
        ));
        state
            .apply_block(
                &wallet,
                CanonicalWalletBlock {
                    height: 301,
                    identifier: issued_tip,
                    parent_identifier: initial,
                    transitions: vec![
                        WalletTransitionObservation::from_verified(&issuance, None).unwrap()
                    ],
                },
            )
            .unwrap();
        state
            .apply_block(
                &wallet,
                CanonicalWalletBlock {
                    height: 302,
                    identifier: spent_tip,
                    parent_identifier: issued_tip,
                    transitions: vec![WalletTransitionObservation {
                        effects: TransitionPublicEffects {
                            kind: TransitionKind::Burn,
                            nullifiers: vec![nullifier],
                            note_commitments: Vec::new(),
                            memo_commitment: Some([0; 32]),
                        },
                        encrypted_memo: Vec::new(),
                        private_payload_id: None,
                    }],
                },
            )
            .unwrap();

        state
            .recover_canonical_deposit(&wallet, bridge, occurrence)
            .unwrap();
        assert_eq!(state.available_balance(), 0);
        assert!(state.note_summaries()[0].spent);
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let snapshot = directory.path().join("recovered-spent-issuance.usdom");
        let seal = state
            .save_encrypted_snapshot(
                &wallet,
                &snapshot,
                &passphrase("recovered spent issuance password"),
                1,
                None,
            )
            .unwrap();
        let mut restored = WalletState::load_encrypted_snapshot(
            &snapshot,
            &passphrase("recovered spent issuance password"),
            seal,
        )
        .unwrap();
        assert!(restored.state.note_summaries()[0].spent);
        let mut misplaced_spend = WalletState::load_encrypted_snapshot(
            &snapshot,
            &passphrase("recovered spent issuance password"),
            seal,
        )
        .unwrap();
        misplaced_spend.state.history[1]
            .spent_existing_notes
            .clear();
        assert!(misplaced_spend
            .state
            .save_encrypted_snapshot(
                &misplaced_spend.wallet,
                &directory.path().join("invalid-spend-history.usdom"),
                &passphrase("invalid spend history password"),
                2,
                Some(seal),
            )
            .is_err());
        restored.state.rollback_tip(spent_tip).unwrap();
        assert!(!restored.state.note_summaries()[0].spent);
        assert_eq!(
            restored.state.available_balance(),
            u128::from(occurrence.amount)
        );
        restored.state.rollback_tip(issued_tip).unwrap();
        assert!(restored.state.note_summaries().is_empty());
        assert!(!restored.state.expected_issuances()[0].canonical);
    }
}
