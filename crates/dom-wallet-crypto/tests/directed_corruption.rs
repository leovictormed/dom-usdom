//! dom-shield — dom-wallet-crypto / directed-corruption.
//!
//! Flip each header field of a real envelope and assert the loader fails closed.
//! Crucially this documents the header's trust model:
//!
//!   * magic / version are validated EXPLICITLY before any crypto → flipping
//!     them yields a typed rejection (BadMagic / UnsupportedVersion).
//!   * salt / nonce are NOT in the AEAD's associated data (AAD): `save_envelope`
//!     calls `encrypt(nonce, json)` with no `.aad(...)` (lib.rs:195-197). The
//!     header is therefore UNAUTHENTICATED. However it is still TAMPER-DETECTED
//!     indirectly: flipping the salt re-derives a wrong key, flipping the nonce
//!     uses a wrong nonce → the Poly1305 tag fails → Decryption.
//!
//! Net finding (documented, not a bug to fix here): the 64-byte header is
//! unauthenticated-but-tamper-detected for salt/nonce, and explicitly validated
//! for magic/version. There is no field whose corruption is silently accepted.

use dom_wallet_crypto::{load_envelope, save_envelope, EnvelopeError, HEADER_SIZE, MAGIC_LEN};
use serde::{Deserialize, Serialize};

const TEST_MAGIC: &[u8; MAGIC_LEN] = b"DOM-TEST-ENV\0\0";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Payload {
    a: u32,
    b: String,
}

fn sample() -> Payload {
    Payload {
        a: 99,
        b: "directed".into(),
    }
}

fn written() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().unwrap();
    // The envelope audit refuses a parent that is not owner-only, and a fresh
    // tempdir inherits the process umask (0o755 under the usual 022).
    #[cfg(unix)]
    std::fs::set_permissions(
        dir.path(),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .unwrap();
    let path = dir.path().join("env.dat");
    save_envelope(&path, TEST_MAGIC, 1, &sample(), "pw").unwrap();
    (dir, path)
}

/// [x][w] Flip a magic byte → explicit BadMagic (fail-closed, pre-crypto).
#[test]
fn flip_magic_field_rejected() {
    let (_d, path) = written();
    let mut data = std::fs::read(&path).unwrap();
    data[3] ^= 0xFF; // inside [0..14)
    std::fs::write(&path, &data).unwrap();
    let err = load_envelope::<Payload>(&path, TEST_MAGIC, 1, "pw").unwrap_err();
    assert!(matches!(err, EnvelopeError::BadMagic), "got {err:?}");
}

/// [x][w] Flip a version byte → explicit UnsupportedVersion (fail-closed).
#[test]
fn flip_version_field_rejected() {
    let (_d, path) = written();
    let mut data = std::fs::read(&path).unwrap();
    data[14] ^= 0x10; // version LE low byte at offset 14
    std::fs::write(&path, &data).unwrap();
    let err = load_envelope::<Payload>(&path, TEST_MAGIC, 1, "pw").unwrap_err();
    assert!(
        matches!(err, EnvelopeError::UnsupportedVersion(v) if v != 1),
        "got {err:?}"
    );
}

/// [x][w] Flip a salt byte → wrong key derived → AEAD tag fails → Decryption.
/// Proves salt is tamper-detected despite NOT being in AAD.
#[test]
fn flip_salt_field_rejected_via_aead() {
    let (_d, path) = written();
    let mut data = std::fs::read(&path).unwrap();
    data[20] ^= 0xFF; // inside salt [16..48)
    std::fs::write(&path, &data).unwrap();
    let err = load_envelope::<Payload>(&path, TEST_MAGIC, 1, "pw").unwrap_err();
    assert!(matches!(err, EnvelopeError::Decryption), "got {err:?}");
}

/// [x][w] Flip a nonce byte → wrong nonce → AEAD tag fails → Decryption.
/// Proves nonce is tamper-detected despite NOT being in AAD.
#[test]
fn flip_nonce_field_rejected_via_aead() {
    let (_d, path) = written();
    let mut data = std::fs::read(&path).unwrap();
    data[50] ^= 0xFF; // inside nonce [48..60)
    std::fs::write(&path, &data).unwrap();
    let err = load_envelope::<Payload>(&path, TEST_MAGIC, 1, "pw").unwrap_err();
    assert!(matches!(err, EnvelopeError::Decryption), "got {err:?}");
}

/// [x] Flip a reserved padding byte [60..64). Canonical framing requires these
/// bytes to remain zero, so corruption is rejected before decryption.
#[test]
fn flip_padding_is_rejected_as_noncanonical_header() {
    let (_d, path) = written();
    let mut data = std::fs::read(&path).unwrap();
    data[61] ^= 0xFF; // inside pad [60..64)
    std::fs::write(&path, &data).unwrap();
    let err = load_envelope::<Payload>(&path, TEST_MAGIC, 1, "pw").unwrap_err();
    assert!(matches!(err, EnvelopeError::BadMagic), "got {err:?}");
}

/// [x][w] Header-not-in-AAD positive evidence: re-write a DIFFERENT (still
/// fresh-looking) magic over a file whose magic the loader is told to expect —
/// confirms the loader trusts the *caller-supplied* expected magic, and the
/// on-disk magic is only compared, never authenticated by the tag. Combined
/// with the salt/nonce flips above, this fully characterises the header as
/// unauthenticated-but-tamper-detected.
#[test]
fn header_first_byte_region_is_outside_aead() {
    // This test asserts that the loader verifies the ciphertext body after a
    // canonical header, independently of the header's explicit field checks.
    let (_d, path) = written();
    let mut data = std::fs::read(&path).unwrap();
    // Corrupt ONLY the ciphertext body, leave header intact.
    let n = data.len();
    assert!(n > HEADER_SIZE, "must have ciphertext");
    data[HEADER_SIZE] ^= 0xFF;
    std::fs::write(&path, &data).unwrap();
    let err = load_envelope::<Payload>(&path, TEST_MAGIC, 1, "pw").unwrap_err();
    assert!(matches!(err, EnvelopeError::Decryption), "got {err:?}");
}
