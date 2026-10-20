//! Pure-Rust SHA-256 primitives for Ethereum consensus tree hashing.
//!
//! This is the deliberately small API consumed by `tree_hash` 0.10.0. It
//! replaces architecture-dependent runtime dispatch with one deterministic
//! RustCrypto implementation suitable for a proving guest.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256 as RustSha256};

#[cfg(feature = "zero_hash_cache")]
mod zero_hashes;

#[cfg(feature = "zero_hash_cache")]
pub use zero_hashes::{ZERO_HASHES, ZERO_HASHES_MAX_INDEX};

/// Length of one SHA-256 digest in bytes.
pub const HASH_LEN: usize = 32;

/// Incremental SHA-256 context used by `tree_hash::MerkleHasher`.
#[derive(Clone)]
pub struct Context(RustSha256);

/// Context operations retained for source compatibility with
/// `ethereum_hashing` 0.7.0.
pub trait Sha256Context {
    /// Construct an empty SHA-256 transcript.
    fn new() -> Self;

    /// Append bytes to the transcript.
    fn update(&mut self, bytes: &[u8]);

    /// Finalize the transcript as exactly 32 bytes.
    fn finalize(self) -> [u8; HASH_LEN];
}

impl Sha256Context for Context {
    fn new() -> Self {
        Self(RustSha256::new())
    }

    fn update(&mut self, bytes: &[u8]) {
        Digest::update(&mut self.0, bytes);
    }

    fn finalize(self) -> [u8; HASH_LEN] {
        self.0.finalize().into()
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot SHA-256 backend operations retained for API compatibility.
pub trait Sha256 {
    /// Incremental context produced by this backend.
    type Context: Sha256Context;

    /// Hash bytes into an allocated 32-byte vector.
    fn hash(&self, input: &[u8]) -> Vec<u8>;

    /// Hash bytes into a fixed 32-byte array.
    fn hash_fixed(&self, input: &[u8]) -> [u8; HASH_LEN];
}

/// The only backend: RustCrypto SHA-256 with no architecture dispatch.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha2CrateImpl;

impl Sha256 for Sha2CrateImpl {
    type Context = Context;

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        self.hash_fixed(input).to_vec()
    }

    fn hash_fixed(&self, input: &[u8]) -> [u8; HASH_LEN] {
        RustSha256::digest(input).into()
    }
}

/// Compatibility selector with a single deterministic variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicImpl {
    /// RustCrypto SHA-256.
    Sha2,
}

impl DynamicImpl {
    /// Return the only permitted implementation.
    pub const fn best() -> Self {
        Self::Sha2
    }
}

impl Sha256 for DynamicImpl {
    type Context = Context;

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        Sha2CrateImpl.hash(input)
    }

    fn hash_fixed(&self, input: &[u8]) -> [u8; HASH_LEN] {
        Sha2CrateImpl.hash_fixed(input)
    }
}

/// Runtime CPU dispatch is intentionally disabled for reproducible guests.
pub const fn have_sha_extensions() -> bool {
    false
}

/// Compute SHA-256 and return an allocated 32-byte vector.
pub fn hash(input: &[u8]) -> Vec<u8> {
    DynamicImpl::best().hash(input)
}

/// Compute SHA-256 and return a fixed 32-byte array.
pub fn hash_fixed(input: &[u8]) -> [u8; HASH_LEN] {
    DynamicImpl::best().hash_fixed(input)
}

/// Compute SHA-256 over the exact concatenation of two slices.
pub fn hash32_concat(left: &[u8], right: &[u8]) -> [u8; HASH_LEN] {
    let mut context = Context::new();
    context.update(left);
    context.update(right);
    context.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn nist_and_upstream_vectors_are_frozen() {
        assert_eq!(
            hex::encode(hash_fixed(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex::encode(hash_fixed(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(hash(b"hello world")),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn incremental_and_concatenated_hashes_match_one_shot() {
        let mut context = Context::new();
        context.update(b"hello ");
        context.update(b"world");
        assert_eq!(context.finalize(), hash_fixed(b"hello world"));
        assert_eq!(
            hash32_concat(&[0x11; 32], &[0x22; 32]),
            hash_fixed(&[[0x11; 32], [0x22; 32]].concat())
        );
    }

    #[test]
    fn million_a_nist_vector() {
        assert_eq!(
            hex::encode(hash_fixed(&vec![b'a'; 1_000_000])),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[cfg(feature = "zero_hash_cache")]
    #[test]
    fn ethereum_zero_hash_chain_is_complete_and_self_consistent() {
        assert_eq!(ZERO_HASHES_MAX_INDEX, 48);
        assert_eq!(ZERO_HASHES.len(), ZERO_HASHES_MAX_INDEX + 1);
        assert_eq!(ZERO_HASHES[0], [0; HASH_LEN]);
        for index in 0..ZERO_HASHES_MAX_INDEX {
            assert_eq!(
                ZERO_HASHES[index + 1],
                hash32_concat(&ZERO_HASHES[index], &ZERO_HASHES[index])
            );
        }
        assert_eq!(
            hex::encode(ZERO_HASHES[48]),
            "7ba3ae4a417fe8545b142bc89f4adcd7ae13941cbab7750b83e9f0a66d16be64"
        );
    }
}
