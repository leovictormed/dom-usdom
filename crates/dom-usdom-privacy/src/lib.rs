//! Canonical, ZK-friendly primitives for native USDOM private notes.
//!
//! This crate freezes only the public cryptographic relation shared by native
//! consensus and a future proof circuit. It deliberately contains no trusted
//! setup, proving key, test authority, or proof-verification bypass.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge},
    CryptographicSponge, FieldBasedCryptographicSponge,
};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, Zero};
use dom_core::{blake2b_256_tagged, Hash256};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod circuit;
pub mod verifier;

const POLICY_TAG: &str = "DOM:usdom-privacy-policy:v3";
const HASH_TO_FIELD_TAG: &[u8] = b"DOM:usdom-hash-to-field:v1";
const OWNER_DOMAIN: u64 = 0x0055_444f_4d01;
const NOTE_DOMAIN: u64 = 0x0055_444f_4d02;
const NULLIFIER_DOMAIN: u64 = 0x0055_444f_4d03;
const NODE_DOMAIN: u64 = 0x0055_444f_4d04;
const CHAIN_DOMAIN: u64 = 0x0055_444f_4d05;
const RHO_DOMAIN: u64 = 0x0055_444f_4d06;
const EFFECT_DOMAIN: u64 = 0x0055_444f_4d07;
const MEMO_DOMAIN: u64 = 0x0055_444f_4d08;
const POLICY_VERSION: u16 = 3;
const ASSET_USDOM: u64 = 1;

/// Origin tag for notes created by an ordinary private transfer or change.
pub const NOTE_ORIGIN_PRIVATE: u8 = 1;
/// Origin tag reserved for notes created directly by finalized deposits.
pub const NOTE_ORIGIN_ISSUANCE: u8 = 2;

/// Depth of the consensus note tree, supporting at most 2^32 notes.
pub const NOTE_TREE_DEPTH: usize = 32;
/// Maximum number of leaves in the fixed-depth note tree.
pub const NOTE_TREE_CAPACITY: u64 = 1u64 << NOTE_TREE_DEPTH;
const NOTE_FRONTIER_MAGIC: &[u8; 8] = b"UDNTFR01";
const NOTE_FRONTIER_BITMAP_BYTES: usize = (NOTE_TREE_DEPTH + 1).div_ceil(8);
const NOTE_FRONTIER_HEADER_BYTES: usize = 8 + 8 + NOTE_FRONTIER_BITMAP_BYTES + 1;
/// Maximum canonical byte length of the Poseidon note-tree frontier.
pub const MAX_NOTE_TREE_FRONTIER_BYTES: usize =
    NOTE_FRONTIER_HEADER_BYTES + (NOTE_TREE_DEPTH + 1) * 32;

/// Error returned by canonical USDOM privacy primitives.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PrivacyError {
    /// A scalar byte string was not the unique big-endian BN254 representation.
    #[error("noncanonical BN254 scalar")]
    NonCanonicalScalar,
    /// A zero scalar was supplied where the protocol requires an identity.
    #[error("zero scalar identity")]
    ZeroScalar,
    /// The fixed-depth note accumulator is full.
    #[error("USDOM note tree is full")]
    TreeFull,
    /// A Merkle path does not have the exact consensus depth.
    #[error("invalid USDOM note path length")]
    InvalidPathLength,
    /// A leaf index lies outside the fixed-depth note tree.
    #[error("invalid USDOM note leaf index")]
    InvalidLeafIndex,
    /// A transported incremental note-tree frontier was malformed.
    #[error("invalid USDOM note-tree frontier")]
    InvalidFrontier,
    /// The supplied secret does not open the note's owner commitment.
    #[error("USDOM note owner secret mismatch")]
    OwnerMismatch,
    /// Note origin is outside the frozen private/issuance namespace.
    #[error("invalid USDOM note origin")]
    InvalidNoteOrigin,
}

/// A BN254 scalar with one canonical 32-byte big-endian wire representation.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Scalar(Fr);

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for Scalar {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("Scalar")
            .field(&hex_string(&self.to_bytes()))
            .finish()
    }
}

impl Scalar {
    /// Canonical zero scalar, used only for empty tree leaves and disabled slots.
    pub const ZERO: Self = Self(Fr::ZERO);

    /// Decode exactly one canonical, unreduced big-endian field element.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PrivacyError> {
        let value = Self(Fr::from_be_bytes_mod_order(&bytes));
        if value.to_bytes() != bytes {
            return Err(PrivacyError::NonCanonicalScalar);
        }
        Ok(value)
    }

    /// Return the unique 32-byte big-endian representation.
    pub fn to_bytes(self) -> [u8; 32] {
        let encoded = self.0.into_bigint().to_bytes_be();
        let mut bytes = [0u8; 32];
        bytes[32 - encoded.len()..].copy_from_slice(&encoded);
        bytes
    }

    /// Whether this is the additive identity.
    pub fn is_zero(self) -> bool {
        self.0.is_zero()
    }

    fn from_u64(value: u64) -> Self {
        Self(Fr::from(value))
    }

    fn from_hash(domain: u64, bytes: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(HASH_TO_FIELD_TAG);
        digest.update(domain.to_be_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
        Self(Fr::from_be_bytes_mod_order(&digest.finalize()))
    }
}

/// Private opening of one USDOM note. Callers must never serialize or log it.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NoteOpening {
    /// Protocol chain scalar derived from the immutable bridge identity.
    pub chain: Scalar,
    /// Consensus origin namespace separating issuance from private outputs.
    pub origin: u8,
    /// Six-decimal USDOM amount, range constrained as `u64` by the proof circuit.
    pub value: u64,
    /// Poseidon owner commitment derived from the recipient's secret.
    pub owner: Scalar,
    /// Unique note randomness.
    pub rho: Scalar,
}

impl NoteOpening {
    /// Compute the canonical Poseidon note commitment.
    pub fn commitment(&self) -> Result<Scalar, PrivacyError> {
        if self.chain.is_zero()
            || !matches!(self.origin, NOTE_ORIGIN_PRIVATE | NOTE_ORIGIN_ISSUANCE)
            || self.value == 0
            || self.owner.is_zero()
            || self.rho.is_zero()
        {
            if !matches!(self.origin, NOTE_ORIGIN_PRIVATE | NOTE_ORIGIN_ISSUANCE) {
                return Err(PrivacyError::InvalidNoteOrigin);
            }
            return Err(PrivacyError::ZeroScalar);
        }
        let commitment = poseidon_hash(
            NOTE_DOMAIN,
            &[
                self.chain,
                Scalar::from_u64(ASSET_USDOM),
                Scalar::from_u64(u64::from(self.origin)),
                Scalar::from_u64(self.value),
                self.owner,
                self.rho,
            ],
        );
        if commitment.is_zero() {
            return Err(PrivacyError::ZeroScalar);
        }
        Ok(commitment)
    }

    /// Derive the spend nullifier from the owner secret and this exact note.
    pub fn nullifier(&self, owner_secret: Scalar) -> Result<Scalar, PrivacyError> {
        if owner_secret.is_zero() {
            return Err(PrivacyError::ZeroScalar);
        }
        let expected_owner = owner_commitment(self.chain, owner_secret)?;
        if expected_owner != self.owner {
            return Err(PrivacyError::OwnerMismatch);
        }
        let nullifier = poseidon_hash(
            NULLIFIER_DOMAIN,
            &[self.chain, owner_secret, self.commitment()?],
        );
        if nullifier.is_zero() {
            return Err(PrivacyError::ZeroScalar);
        }
        Ok(nullifier)
    }
}

/// Derive the chain scalar committed by every note and proof statement.
pub fn chain_scalar(dom_domain: [u8; 32], privacy_policy_hash: [u8; 32]) -> Scalar {
    let limbs = bytes_to_limbs(&[dom_domain.as_slice(), privacy_policy_hash.as_slice()].concat());
    poseidon_hash(CHAIN_DOMAIN, &limbs)
}

/// Derive a receiver commitment from a nonzero wallet secret.
pub fn owner_commitment(chain: Scalar, secret: Scalar) -> Result<Scalar, PrivacyError> {
    if chain.is_zero() || secret.is_zero() {
        return Err(PrivacyError::ZeroScalar);
    }
    let owner = poseidon_hash(OWNER_DOMAIN, &[chain, secret]);
    if owner.is_zero() {
        return Err(PrivacyError::ZeroScalar);
    }
    Ok(owner)
}

/// Derive deterministic note randomness from one authenticated deposit occurrence.
pub fn issuance_rho(occurrence: &[u8]) -> Result<Scalar, PrivacyError> {
    if occurrence.is_empty() {
        return Err(PrivacyError::ZeroScalar);
    }
    let seed = Scalar::from_hash(RHO_DOMAIN, occurrence);
    let rho = poseidon_hash(RHO_DOMAIN, &[seed]);
    if rho.is_zero() {
        return Err(PrivacyError::ZeroScalar);
    }
    Ok(rho)
}

/// Bind a spend proof to one exact public transfer or burn effect encoding.
pub fn effect_scalar(effect: &[u8]) -> Result<Scalar, PrivacyError> {
    if effect.is_empty() {
        return Err(PrivacyError::ZeroScalar);
    }
    let value = Scalar::from_hash(EFFECT_DOMAIN, effect);
    if value.is_zero() {
        return Err(PrivacyError::ZeroScalar);
    }
    Ok(value)
}

/// Bind output notes to the exact encrypted wallet memo transported with them.
pub fn memo_scalar(ciphertext: &[u8]) -> Result<Scalar, PrivacyError> {
    if ciphertext.is_empty() {
        return Err(PrivacyError::ZeroScalar);
    }
    let value = Scalar::from_hash(MEMO_DOMAIN, ciphertext);
    if value.is_zero() {
        return Err(PrivacyError::ZeroScalar);
    }
    Ok(value)
}

/// Incremental fixed-depth Poseidon accumulator used by native consensus.
#[derive(Debug, Clone)]
pub struct IncrementalNoteTree {
    frontier: [Option<Scalar>; NOTE_TREE_DEPTH + 1],
    leaf_count: u64,
}

impl Default for IncrementalNoteTree {
    fn default() -> Self {
        Self::new()
    }
}

impl IncrementalNoteTree {
    /// Construct the canonical empty tree.
    pub fn new() -> Self {
        Self {
            frontier: [None; NOTE_TREE_DEPTH + 1],
            leaf_count: 0,
        }
    }

    /// Number of appended note commitments.
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Membership path that the next appended leaf will have before later
    /// leaves update its right-hand siblings.
    pub fn next_leaf_path(&self) -> Result<[Scalar; NOTE_TREE_DEPTH], PrivacyError> {
        if self.leaf_count == NOTE_TREE_CAPACITY {
            return Err(PrivacyError::TreeFull);
        }
        let empty = empty_roots();
        let mut index = self.leaf_count;
        let mut siblings = [Scalar::ZERO; NOTE_TREE_DEPTH];
        for level in 0..NOTE_TREE_DEPTH {
            siblings[level] = if index & 1 == 1 {
                self.frontier[level].ok_or(PrivacyError::InvalidFrontier)?
            } else {
                empty[level]
            };
            index >>= 1;
        }
        Ok(siblings)
    }

    /// Root, padded with canonical empty nodes, of the rightmost subtree at
    /// `depth` after hypothetically appending `leaf`.
    ///
    /// Wallets use this before the real append to update the one sibling in an
    /// older note path whose subtree receives the new leaf.
    pub fn prospective_subtree_root(
        &self,
        leaf: Scalar,
        depth: usize,
    ) -> Result<Scalar, PrivacyError> {
        if depth > NOTE_TREE_DEPTH {
            return Err(PrivacyError::InvalidPathLength);
        }
        if leaf.is_zero() {
            return Err(PrivacyError::ZeroScalar);
        }
        if self.leaf_count == NOTE_TREE_CAPACITY {
            return Err(PrivacyError::TreeFull);
        }
        let empty = empty_roots();
        let mut current = leaf;
        let mut index = self.leaf_count;
        for (level, empty_at_level) in empty.iter().copied().enumerate().take(depth) {
            current = if index & 1 == 1 {
                node_hash(
                    level,
                    self.frontier[level].ok_or(PrivacyError::InvalidFrontier)?,
                    current,
                )
            } else {
                node_hash(level, current, empty_at_level)
            };
            index >>= 1;
        }
        Ok(current)
    }

    /// Append one nonzero canonical note commitment and return its index.
    pub fn append(&mut self, leaf: Scalar) -> Result<u64, PrivacyError> {
        if leaf.is_zero() {
            return Err(PrivacyError::ZeroScalar);
        }
        if self.leaf_count == NOTE_TREE_CAPACITY {
            return Err(PrivacyError::TreeFull);
        }
        self.validate_frontier()?;
        let inserted = self.leaf_count;
        let mut index = inserted;
        let mut current = leaf;
        let mut level = 0usize;
        while index & 1 == 1 {
            let left = self.frontier[level].ok_or(PrivacyError::InvalidFrontier)?;
            current = node_hash(level, left, current);
            index >>= 1;
            level += 1;
        }
        for consumed in &mut self.frontier[..level] {
            *consumed = None;
        }
        self.frontier[level] = Some(current);
        self.leaf_count += 1;
        Ok(inserted)
    }

    /// Current canonical root including every fixed empty subtree.
    pub fn root(&self) -> Scalar {
        // Constructors and decoders preserve the frontier invariant. Returning
        // the reserved zero scalar on corrupted in-memory state keeps this
        // widely used accessor total and forces downstream state checks to
        // fail closed instead of aborting the process.
        match self.checked_root() {
            Ok(root) => root,
            Err(_) => Scalar::ZERO,
        }
    }

    fn checked_root(&self) -> Result<Scalar, PrivacyError> {
        self.validate_frontier()?;
        if self.leaf_count == NOTE_TREE_CAPACITY {
            return self.frontier[NOTE_TREE_DEPTH].ok_or(PrivacyError::InvalidFrontier);
        }
        let empty = empty_roots();
        let mut current = Scalar::ZERO;
        let mut occupied = self.leaf_count;
        for (level, empty_at_level) in empty.iter().copied().enumerate().take(NOTE_TREE_DEPTH) {
            current = if occupied & 1 == 1 {
                node_hash(
                    level,
                    self.frontier[level].ok_or(PrivacyError::InvalidFrontier)?,
                    current,
                )
            } else {
                node_hash(level, current, empty_at_level)
            };
            occupied >>= 1;
        }
        Ok(current)
    }

    /// Encode the unique bounded `UDNTFR01` append frontier.
    pub fn to_frontier_bytes(&self) -> Result<Vec<u8>, PrivacyError> {
        self.validate_frontier()?;
        let mut bitmap = [0u8; NOTE_FRONTIER_BITMAP_BYTES];
        let mut values = Vec::new();
        for (level, value) in self.frontier.iter().copied().enumerate() {
            if let Some(value) = value {
                bitmap[level / 8] |= 1 << (level % 8);
                values.push(value);
            }
        }
        let value_count: u8 = values
            .len()
            .try_into()
            .map_err(|_| PrivacyError::InvalidFrontier)?;
        let mut bytes = Vec::with_capacity(NOTE_FRONTIER_HEADER_BYTES + values.len() * 32);
        bytes.extend_from_slice(NOTE_FRONTIER_MAGIC);
        bytes.extend_from_slice(&self.leaf_count.to_be_bytes());
        bytes.extend_from_slice(&bitmap);
        bytes.push(value_count);
        for value in values {
            bytes.extend_from_slice(&value.to_bytes());
        }
        Ok(bytes)
    }

    /// Decode and canonically re-encode one `UDNTFR01` append frontier.
    pub fn from_frontier_bytes(bytes: &[u8]) -> Result<Self, PrivacyError> {
        if bytes.len() < NOTE_FRONTIER_HEADER_BYTES
            || bytes.len() > MAX_NOTE_TREE_FRONTIER_BYTES
            || &bytes[..8] != NOTE_FRONTIER_MAGIC
        {
            return Err(PrivacyError::InvalidFrontier);
        }
        let leaf_count = u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| PrivacyError::InvalidFrontier)?,
        );
        let bitmap: [u8; NOTE_FRONTIER_BITMAP_BYTES] = bytes[16..16 + NOTE_FRONTIER_BITMAP_BYTES]
            .try_into()
            .map_err(|_| PrivacyError::InvalidFrontier)?;
        if bitmap[NOTE_FRONTIER_BITMAP_BYTES - 1] & !((1u8 << ((NOTE_TREE_DEPTH + 1) % 8)) - 1) != 0
        {
            return Err(PrivacyError::InvalidFrontier);
        }
        let value_count = usize::from(bytes[16 + NOTE_FRONTIER_BITMAP_BYTES]);
        let expected = NOTE_FRONTIER_HEADER_BYTES
            .checked_add(
                value_count
                    .checked_mul(32)
                    .ok_or(PrivacyError::InvalidFrontier)?,
            )
            .ok_or(PrivacyError::InvalidFrontier)?;
        if expected != bytes.len()
            || value_count
                != bitmap
                    .iter()
                    .map(|byte| byte.count_ones() as usize)
                    .sum::<usize>()
        {
            return Err(PrivacyError::InvalidFrontier);
        }
        let mut frontier = [None; NOTE_TREE_DEPTH + 1];
        let mut cursor = NOTE_FRONTIER_HEADER_BYTES;
        for level in 0..=NOTE_TREE_DEPTH {
            if bitmap[level / 8] & (1 << (level % 8)) != 0 {
                let encoded = bytes
                    .get(cursor..cursor + 32)
                    .ok_or(PrivacyError::InvalidFrontier)?
                    .try_into()
                    .map_err(|_| PrivacyError::InvalidFrontier)?;
                frontier[level] =
                    Some(Scalar::from_bytes(encoded).map_err(|_| PrivacyError::InvalidFrontier)?);
                cursor += 32;
            }
        }
        let tree = Self {
            frontier,
            leaf_count,
        };
        tree.validate_frontier()?;
        if tree.to_frontier_bytes()?.as_slice() != bytes {
            return Err(PrivacyError::InvalidFrontier);
        }
        Ok(tree)
    }

    fn validate_frontier(&self) -> Result<(), PrivacyError> {
        if self.leaf_count > NOTE_TREE_CAPACITY {
            return Err(PrivacyError::InvalidFrontier);
        }
        for level in 0..=NOTE_TREE_DEPTH {
            let expected = if self.leaf_count == NOTE_TREE_CAPACITY {
                level == NOTE_TREE_DEPTH
            } else if level < NOTE_TREE_DEPTH {
                self.leaf_count & (1u64 << level) != 0
            } else {
                false
            };
            if self.frontier[level].is_some() != expected {
                return Err(PrivacyError::InvalidFrontier);
            }
        }
        Ok(())
    }
}

/// Verify one exact-depth private membership path against a public anchor.
pub fn verify_membership(
    leaf: Scalar,
    leaf_index: u64,
    siblings: &[Scalar],
    expected_root: Scalar,
) -> Result<bool, PrivacyError> {
    if siblings.len() != NOTE_TREE_DEPTH {
        return Err(PrivacyError::InvalidPathLength);
    }
    if leaf_index >= NOTE_TREE_CAPACITY {
        return Err(PrivacyError::InvalidLeafIndex);
    }
    let mut current = leaf;
    let mut index = leaf_index;
    for (level, sibling) in siblings.iter().copied().enumerate() {
        current = if index & 1 == 0 {
            node_hash(level, current, sibling)
        } else {
            node_hash(level, sibling, current)
        };
        index >>= 1;
    }
    Ok(current == expected_root)
}

/// Return the frozen empty-subtree roots used to build wallet membership paths.
pub fn empty_subtree_roots() -> [Scalar; NOTE_TREE_DEPTH + 1] {
    *empty_roots()
}

/// Hash every frozen primitive and Poseidon parameter into one policy identity.
pub fn privacy_policy_hash() -> Hash256 {
    static HASH: OnceLock<Hash256> = OnceLock::new();
    *HASH.get_or_init(|| {
        let config = poseidon_config();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&POLICY_VERSION.to_be_bytes());
        bytes.extend_from_slice(b"BN254-Fr");
        bytes.extend_from_slice(&(NOTE_TREE_DEPTH as u16).to_be_bytes());
        bytes.push(NOTE_ORIGIN_PRIVATE);
        bytes.push(NOTE_ORIGIN_ISSUANCE);
        for domain in [
            OWNER_DOMAIN,
            NOTE_DOMAIN,
            NULLIFIER_DOMAIN,
            NODE_DOMAIN,
            CHAIN_DOMAIN,
            RHO_DOMAIN,
            EFFECT_DOMAIN,
            MEMO_DOMAIN,
        ] {
            bytes.extend_from_slice(&domain.to_be_bytes());
        }
        bytes.extend_from_slice(&(config.full_rounds as u32).to_be_bytes());
        bytes.extend_from_slice(&(config.partial_rounds as u32).to_be_bytes());
        bytes.extend_from_slice(&config.alpha.to_be_bytes());
        bytes.extend_from_slice(&(config.rate as u16).to_be_bytes());
        bytes.extend_from_slice(&(config.capacity as u16).to_be_bytes());
        bytes.extend_from_slice(
            b"spend-v2:origin-separated:2-input:2-output:depth32:u64:direct-public:chain,anchor,nf0,nf1,out0,out1,burn,effect,memo",
        );
        for value in config
            .ark
            .iter()
            .flatten()
            .chain(config.mds.iter().flatten())
        {
            bytes.extend_from_slice(&Scalar(*value).to_bytes());
        }
        blake2b_256_tagged(POLICY_TAG, &bytes)
    })
}

fn poseidon_config() -> &'static PoseidonConfig<Fr> {
    static CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(Fr::MODULUS_BIT_SIZE as u64, 2, 8, 57, 0);
        PoseidonConfig::new(8, 57, 5, mds, ark, 2, 1)
    })
}

fn poseidon_hash(domain: u64, values: &[Scalar]) -> Scalar {
    let mut sponge = PoseidonSponge::new(poseidon_config());
    sponge.absorb(&Fr::from(domain));
    sponge.absorb(&values.iter().map(|value| value.0).collect::<Vec<_>>());
    match sponge.squeeze_native_field_elements(1).into_iter().next() {
        Some(value) => Scalar(value),
        None => Scalar::ZERO,
    }
}

fn node_hash(level: usize, left: Scalar, right: Scalar) -> Scalar {
    poseidon_hash(NODE_DOMAIN, &[Scalar::from_u64(level as u64), left, right])
}

fn empty_roots() -> &'static [Scalar; NOTE_TREE_DEPTH + 1] {
    static ROOTS: OnceLock<[Scalar; NOTE_TREE_DEPTH + 1]> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let mut roots = [Scalar::ZERO; NOTE_TREE_DEPTH + 1];
        for level in 0..NOTE_TREE_DEPTH {
            roots[level + 1] = node_hash(level, roots[level], roots[level]);
        }
        roots
    })
}

fn bytes_to_limbs(bytes: &[u8]) -> Vec<Scalar> {
    bytes
        .chunks(8)
        .map(|chunk| {
            let mut word = [0u8; 8];
            word[8 - chunk.len()..].copy_from_slice(chunk);
            Scalar::from_u64(u64::from_be_bytes(word))
        })
        .collect()
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(value: u64) -> Scalar {
        Scalar::from_u64(value)
    }

    fn naive_root(leaves: &[Scalar]) -> Scalar {
        let empty = empty_roots();
        let mut level = leaves.to_vec();
        level.resize(leaves.len().next_power_of_two().max(1), Scalar::ZERO);
        let mut height = 0usize;
        while level.len() > 1 {
            level = level
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| node_hash(height, pair[0], pair[1]))
                .collect();
            height += 1;
        }
        let mut root = level[0];
        while height < NOTE_TREE_DEPTH {
            root = node_hash(height, root, empty[height]);
            height += 1;
        }
        root
    }

    #[test]
    fn scalar_encoding_is_big_endian_unique_and_never_reduces() {
        for value in [0, 1, u64::MAX] {
            let scalar = Scalar::from_u64(value);
            assert_eq!(Scalar::from_bytes(scalar.to_bytes()).unwrap(), scalar);
        }
        assert_eq!(
            Scalar::from_bytes([0xff; 32]),
            Err(PrivacyError::NonCanonicalScalar)
        );
        let one = scalar(1).to_bytes();
        assert_eq!(one[31], 1);
        assert!(one[..31].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn note_owner_nullifier_and_policy_are_domain_bound() {
        let policy = *privacy_policy_hash().as_bytes();
        let chain = chain_scalar([0x11; 32], policy);
        let secret = scalar(7);
        let owner = owner_commitment(chain, secret).unwrap();
        let note = NoteOpening {
            chain,
            origin: NOTE_ORIGIN_ISSUANCE,
            value: 1_000_000,
            owner,
            rho: issuance_rho(b"deposit occurrence").unwrap(),
        };
        let commitment = note.commitment().unwrap();
        let private_commitment = NoteOpening {
            origin: NOTE_ORIGIN_PRIVATE,
            ..note.clone()
        }
        .commitment()
        .unwrap();
        assert_ne!(commitment, private_commitment);
        assert!(!commitment.is_zero());
        assert!(!note.nullifier(secret).unwrap().is_zero());
        assert!(note.nullifier(scalar(8)).is_err());
        assert_ne!(chain, chain_scalar([0x12; 32], policy));
        assert_ne!(
            commitment,
            NoteOpening {
                value: 999_999,
                ..note.clone()
            }
            .commitment()
            .unwrap()
        );
        assert_eq!(
            hex_string(privacy_policy_hash().as_bytes()),
            "d66687e30a3540932de46fc6a6c9d151d1a46d5f2e0e0fcd2bca568b05bad90c"
        );
        assert_eq!(
            hex_string(&commitment.to_bytes()),
            "016ce629ea89473c4cd119e795de4824874e74a2b3bacf5d95c52acd87fe5b9e"
        );
    }

    #[test]
    fn incremental_root_matches_independent_tree_for_prefixes() {
        let mut tree = IncrementalNoteTree::new();
        let mut leaves = Vec::new();
        assert_eq!(tree.root(), empty_roots()[NOTE_TREE_DEPTH]);
        for value in 1..=257u64 {
            let leaf = poseidon_hash(NOTE_DOMAIN, &[scalar(value)]);
            assert_eq!(tree.append(leaf).unwrap(), value - 1);
            leaves.push(leaf);
            assert_eq!(tree.root(), naive_root(&leaves), "prefix {value}");
        }
    }

    #[test]
    fn note_frontier_roundtrip_preserves_every_append_and_rejects_malleability() {
        let mut original = IncrementalNoteTree::new();
        for value in 1u64..=256 {
            let encoded = original.to_frontier_bytes().expect("encode");
            assert!(encoded.len() <= MAX_NOTE_TREE_FRONTIER_BYTES);
            let mut restored =
                IncrementalNoteTree::from_frontier_bytes(&encoded).expect("decode frontier");
            assert_eq!(restored.leaf_count(), original.leaf_count());
            assert_eq!(restored.root(), original.root());
            let leaf = scalar(value);
            assert_eq!(restored.append(leaf).expect("restored append"), value - 1);
            assert_eq!(original.append(leaf).expect("original append"), value - 1);
            assert_eq!(restored.root(), original.root());
        }
        let encoded = original.to_frontier_bytes().expect("final frontier");
        assert_eq!(hex::encode(&encoded), "55444e5446523031000000000000010000010000000104a87f725258a83233d7413a80256d336ecdb3ff6b3505fe8bc0d76c010963aa");
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            IncrementalNoteTree::from_frontier_bytes(&trailing),
            Err(PrivacyError::InvalidFrontier)
        ));
        let mut bad_padding = encoded;
        bad_padding[16 + NOTE_FRONTIER_BITMAP_BYTES - 1] |= 0x80;
        assert!(matches!(
            IncrementalNoteTree::from_frontier_bytes(&bad_padding),
            Err(PrivacyError::InvalidFrontier)
        ));
    }

    #[test]
    fn note_frontier_decoder_rejects_hostile_bounded_bytes_without_panicking() {
        for length in 0..=MAX_NOTE_TREE_FRONTIER_BYTES + 1 {
            for seed in [0u8, 0x5a, 0xff] {
                let mut bytes = (0..length)
                    .map(|index| seed.wrapping_add((index as u8).wrapping_mul(73)))
                    .collect::<Vec<_>>();
                let prefix = NOTE_FRONTIER_MAGIC.len().min(bytes.len());
                bytes[..prefix].copy_from_slice(&NOTE_FRONTIER_MAGIC[..prefix]);
                let _ = IncrementalNoteTree::from_frontier_bytes(&bytes);
            }
        }
    }

    #[test]
    fn membership_requires_exact_depth_index_and_order() {
        let leaf = scalar(9);
        let siblings = empty_roots()[..NOTE_TREE_DEPTH].to_vec();
        let mut root = leaf;
        for (level, sibling) in siblings.iter().copied().enumerate() {
            root = node_hash(level, root, sibling);
        }
        assert!(verify_membership(leaf, 0, &siblings, root).unwrap());
        assert!(!verify_membership(leaf, 1, &siblings, root).unwrap());
        assert_eq!(
            verify_membership(leaf, 0, &siblings[..31], root),
            Err(PrivacyError::InvalidPathLength)
        );
        assert_eq!(
            verify_membership(leaf, NOTE_TREE_CAPACITY, &siblings, root),
            Err(PrivacyError::InvalidLeafIndex)
        );
    }

    #[test]
    fn next_leaf_paths_remain_valid_when_updated_by_later_appends() {
        let mut tree = IncrementalNoteTree::new();
        let mut tracked = Vec::<(Scalar, u64, [Scalar; NOTE_TREE_DEPTH])>::new();
        for value in 1..=17u64 {
            let leaf = poseidon_hash(NOTE_DOMAIN, &[scalar(value)]);
            let index = tree.leaf_count();
            for (_, tracked_index, siblings) in &mut tracked {
                let differing_level =
                    (u64::BITS - 1 - (*tracked_index ^ index).leading_zeros()) as usize;
                siblings[differing_level] = tree
                    .prospective_subtree_root(leaf, differing_level)
                    .unwrap();
            }
            let siblings = tree.next_leaf_path().unwrap();
            assert_eq!(tree.append(leaf).unwrap(), index);
            tracked.push((leaf, index, siblings));
            for (tracked_leaf, tracked_index, tracked_siblings) in &tracked {
                assert!(verify_membership(
                    *tracked_leaf,
                    *tracked_index,
                    tracked_siblings,
                    tree.root()
                )
                .unwrap());
            }
        }
        assert_eq!(
            tree.prospective_subtree_root(scalar(1), NOTE_TREE_DEPTH + 1),
            Err(PrivacyError::InvalidPathLength)
        );
    }
}
