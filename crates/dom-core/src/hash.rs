//! Tagged Blake2b-256 hashing used by DOM consensus.
//!
//! This module is deliberately part of `dom-core`: deterministic consensus
//! and proving code must not have to link signing, Bulletproof, random-number,
//! or native secp256k1 backends merely to recompute a state commitment.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

use crate::Hash256;

type Blake2b256 = Blake2b<U32>;

/// Compute Blake2b-256 of `data`.
pub fn blake2b_256(data: &[u8]) -> Hash256 {
    let mut hasher = Blake2b256::new();
    hasher.update(data);
    Hash256::from_bytes(hasher.finalize().into())
}

/// Compute `Blake2b-256(u16_le(len(tag)) || tag || data)`.
///
/// The length prefix makes the domain separation unambiguous. Consensus tags
/// are required to fit in `u16`; a larger static or dynamic tag is a protocol
/// programming error and therefore fails closed.
pub fn blake2b_256_tagged(tag: &str, data: &[u8]) -> Hash256 {
    let tag_bytes = tag.as_bytes();
    let tag_len: u16 = tag_bytes
        .len()
        .try_into()
        .expect("DOM tag must be <= 65535 bytes");

    let mut hasher = Blake2b256::new();
    hasher.update(tag_len.to_le_bytes());
    hasher.update(tag_bytes);
    hasher.update(data);
    Hash256::from_bytes(hasher.finalize().into())
}

/// Incremental DOM hasher initialized with the canonical tag framing.
pub struct DomHasher {
    inner: Blake2b256,
}

impl DomHasher {
    /// Create a hasher for one domain-separated stream.
    pub fn new(tag: &str) -> Self {
        let tag_bytes = tag.as_bytes();
        let tag_len: u16 = tag_bytes
            .len()
            .try_into()
            .expect("DOM tag must be <= 65535 bytes");

        let mut inner = Blake2b256::new();
        inner.update(tag_len.to_le_bytes());
        inner.update(tag_bytes);
        Self { inner }
    }

    /// Append bytes to the tagged stream.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize the stream as exactly 32 bytes.
    pub fn finalize(self) -> Hash256 {
        Hash256::from_bytes(self.inner.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_hash_vectors() {
        assert_eq!(
            hex::encode(blake2b_256(b"DOM test vector").as_bytes()),
            "adc9da746270bcde5e37291ec3f228b845d29985fbf14d3e29e4e915a5ae56a9"
        );
        assert_eq!(
            hex::encode(blake2b_256_tagged("DOM:test:v1", b"hello world").as_bytes()),
            "528814152b04831e28fee797e809cf44f2d4ec18e23a0140bede9d84bfd17102"
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let mut incremental = DomHasher::new("DOM:test:v1");
        incremental.update(b"hello ");
        incremental.update(b"world");
        assert_eq!(
            incremental.finalize(),
            blake2b_256_tagged("DOM:test:v1", b"hello world")
        );
    }
}
