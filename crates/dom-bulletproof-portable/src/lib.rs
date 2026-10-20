//! Portable primitives for DOM's frozen classic Bulletproof verifier.
//!
//! The live DOM format uses the generator set created by grin's pinned
//! `libsecp256k1-zkp` backend. Re-deriving those generators inside every zkVM
//! execution is expensive, so this crate freezes their canonical zkp encodings
//! and verifies the entire table against the original deterministic derivation
//! in tests. Production code remains pure Rust and has no C, operating-system
//! randomness, filesystem, or network dependency.

#![no_std]
#![deny(unsafe_code)]
#![deny(missing_docs)]

mod generators;
mod verifier;

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, FieldElement, ProjectivePoint};
use sha2::{Digest, Sha256};

pub use verifier::{verify_bounded_range_proof, BOUNDED_RANGE_PROOF_BYTES, MAX_PROVABLE_VALUE};

/// Number of points in the generator set created by the live native backend.
pub const BULLETPROOF_GENERATOR_COUNT: usize = 256;

/// SHA-256 of all 256 canonical 33-byte zkp encodings in index order.
pub const BULLETPROOF_GENERATORS_SHA256: [u8; 32] = [
    0x7e, 0x43, 0x32, 0x30, 0x7e, 0x2b, 0x6b, 0xd8, 0x78, 0x8d, 0xdf, 0xa7, 0x66, 0x41, 0xe9, 0x26,
    0x45, 0xed, 0xae, 0x37, 0xc6, 0xa3, 0x3e, 0xc2, 0xde, 0xa1, 0x2a, 0x84, 0x3d, 0x36, 0x25, 0x5d,
];

/// Failure while decoding the frozen native generator table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortableBulletproofError {
    /// The caller requested an index outside the 256-point table.
    GeneratorIndex,
    /// A frozen zkp encoding does not describe a valid secp256k1 point.
    InvalidGenerator,
    /// The supplied SEC1 commitment is malformed or degenerates at the bound.
    InvalidCommitment,
    /// The proof does not have the one canonical serialized length.
    InvalidProofLength,
}

/// Return one canonical zkp generator encoding (`0x0a/0x0b || X`).
pub fn bulletproof_generator_zkp(index: usize) -> Option<&'static [u8; 33]> {
    generators::BULLETPROOF_GENERATORS_ZKP.get(index)
}

/// Decode one frozen generator into a pure-Rust secp256k1 point.
///
/// The zkp prefix records whether `Y` is a quadratic residue, rather than the
/// SEC1 parity bit. Exactly one of the two possible SEC1 points for `X`
/// matches that predicate because the secp256k1 field is `3 mod 4`.
pub fn bulletproof_generator_point(
    index: usize,
) -> Result<ProjectivePoint, PortableBulletproofError> {
    let zkp = bulletproof_generator_zkp(index).ok_or(PortableBulletproofError::GeneratorIndex)?;
    point_from_zkp(zkp)
}

/// Recompute the table commitment used by provenance and release checks.
pub fn bulletproof_generators_sha256() -> [u8; 32] {
    let mut hasher = Sha256::new();
    for generator in generators::BULLETPROOF_GENERATORS_ZKP {
        hasher.update(generator);
    }
    hasher.finalize().into()
}

pub(crate) fn point_from_zkp(zkp: &[u8; 33]) -> Result<ProjectivePoint, PortableBulletproofError> {
    let expected_square = match zkp[0] {
        0x0a => true,
        0x0b => false,
        _ => return Err(PortableBulletproofError::InvalidGenerator),
    };
    for prefix in [0x02_u8, 0x03_u8] {
        let mut sec1 = [0u8; 33];
        sec1[0] = prefix;
        sec1[1..].copy_from_slice(&zkp[1..]);
        let Ok(encoded) = EncodedPoint::from_bytes(sec1) else {
            continue;
        };
        let candidate = AffinePoint::from_encoded_point(&encoded);
        if bool::from(candidate.is_none()) {
            continue;
        }
        let affine = candidate.unwrap();
        let uncompressed = affine.to_encoded_point(false);
        let Some(y_bytes) = uncompressed.y() else {
            continue;
        };
        let y = FieldElement::from_bytes(y_bytes);
        if bool::from(y.is_none()) {
            continue;
        }
        let is_square = bool::from(y.unwrap().sqrt().is_some());
        if is_square == expected_square {
            return Ok(ProjectivePoint::from(affine));
        }
    }
    Err(PortableBulletproofError::InvalidGenerator)
}

pub(crate) fn point_from_sec1(
    sec1: &[u8; 33],
) -> Result<ProjectivePoint, PortableBulletproofError> {
    let encoded =
        EncodedPoint::from_bytes(sec1).map_err(|_| PortableBulletproofError::InvalidCommitment)?;
    let affine = AffinePoint::from_encoded_point(&encoded);
    if bool::from(affine.is_none()) {
        return Err(PortableBulletproofError::InvalidCommitment);
    }
    Ok(ProjectivePoint::from(affine.unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use secp256k1_zkp::{Generator, Secp256k1, Tag};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    struct Rfc6979 {
        k: [u8; 32],
        v: [u8; 32],
        retry: bool,
    }

    impl Rfc6979 {
        fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
            let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
            for part in parts {
                mac.update(part);
            }
            mac.finalize().into_bytes().into()
        }

        fn new(seed: &[u8]) -> Self {
            let mut this = Self {
                k: [0; 32],
                v: [1; 32],
                retry: false,
            };
            this.k = Self::hmac(&this.k, &[&this.v, &[0], seed]);
            this.v = Self::hmac(&this.k, &[&this.v]);
            this.k = Self::hmac(&this.k, &[&this.v, &[1], seed]);
            this.v = Self::hmac(&this.k, &[&this.v]);
            this
        }

        fn generate(&mut self) -> [u8; 32] {
            if self.retry {
                self.k = Self::hmac(&self.k, &[&self.v, &[0]]);
                self.v = Self::hmac(&self.k, &[&self.v]);
            }
            self.v = Self::hmac(&self.k, &[&self.v]);
            self.retry = true;
            self.v
        }
    }

    fn generator_seed() -> [u8; 64] {
        let affine = k256::AffinePoint::GENERATOR;
        let encoded = affine.to_encoded_point(false);
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(encoded.x().expect("uncompressed generator has X"));
        seed[32..].copy_from_slice(encoded.y().expect("uncompressed generator has Y"));
        seed
    }

    #[test]
    fn frozen_table_matches_pinned_native_derivation() {
        let mut rng = Rfc6979::new(&generator_seed());
        let secp = Secp256k1::new();
        for (index, frozen) in generators::BULLETPROOF_GENERATORS_ZKP.iter().enumerate() {
            let derived = Generator::new_unblinded(&secp, Tag::from(rng.generate())).serialize();
            assert_eq!(*frozen, derived, "generator {index} drifted");
        }
    }

    #[test]
    fn table_commitment_and_points_are_canonical() {
        assert_eq!(
            bulletproof_generators_sha256(),
            BULLETPROOF_GENERATORS_SHA256
        );
        for index in 0..BULLETPROOF_GENERATOR_COUNT {
            assert!(
                bulletproof_generator_point(index).is_ok(),
                "generator {index}"
            );
        }
        assert_eq!(
            bulletproof_generator_point(BULLETPROOF_GENERATOR_COUNT),
            Err(PortableBulletproofError::GeneratorIndex)
        );
    }

    #[test]
    fn frozen_generators_are_distinct() {
        for left in 0..BULLETPROOF_GENERATOR_COUNT {
            for right in left + 1..BULLETPROOF_GENERATOR_COUNT {
                assert_ne!(
                    generators::BULLETPROOF_GENERATORS_ZKP[left],
                    generators::BULLETPROOF_GENERATORS_ZKP[right]
                );
            }
        }
    }
}
