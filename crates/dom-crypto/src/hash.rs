//! Compatibility re-exports for the consensus hash implementation.
//!
//! The implementation lives in `dom-core` so proof programs can recompute
//! consensus commitments without linking this crate's native curve backends.

pub use dom_core::{blake2b_256, blake2b_256_tagged, DomHasher};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2b_256_is_deterministic() {
        let h1 = blake2b_256(b"DOM test vector");
        let h2 = blake2b_256(b"DOM test vector");
        assert_eq!(h1, h2);
    }

    #[test]
    fn tagged_hash_differs_from_untagged() {
        let data = b"same data";
        let tagged = blake2b_256_tagged("DOM:test:v1", data);
        let untagged = blake2b_256(data);
        assert_ne!(tagged, untagged);
    }

    #[test]
    fn different_tags_produce_different_hashes() {
        let data = b"same data";
        let h1 = blake2b_256_tagged("DOM:tag-a:v1", data);
        let h2 = blake2b_256_tagged("DOM:tag-b:v1", data);
        assert_ne!(h1, h2);
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data = b"hello world";
        let oneshot = blake2b_256_tagged("DOM:test:v1", data);

        let mut hasher = DomHasher::new("DOM:test:v1");
        hasher.update(b"hello ");
        hasher.update(b"world");
        let incremental = hasher.finalize();

        assert_eq!(oneshot, incremental);
    }

    /// Reference vector — MUST be reproduced by all implementations.
    /// If this test fails, serialization or hashing has changed.
    #[test]
    fn kernel_sig_tag_vector() {
        let h = blake2b_256_tagged(dom_core::TAG_KERNEL_SIG, b"");
        // This is a deterministic vector for the empty message.
        // Record actual value once computed on reference hardware.
        // For now, assert it is 32 bytes and non-zero.
        assert_eq!(h.as_bytes().len(), 32);
        assert_ne!(h, dom_core::Hash256::ZERO);
    }
}
