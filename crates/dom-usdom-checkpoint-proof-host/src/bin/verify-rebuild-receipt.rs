//! Verify one rebuild receipt and publish a create-once verification record.

#![deny(unsafe_code)]

use std::env;
use std::path::Path;

use dom_usdom_checkpoint_proof_host::verify_rebuild_receipt;
use dom_wallet_crypto::{read_captured_bytes, save_private_bytes_noclobber};
use sha2::{Digest, Sha256};

const MAX_PREDECESSOR_BYTES: usize = 4 * 1024 * 1024;

fn publish_record(path: &Path, bytes: &[u8]) -> Result<(), String> {
    save_private_bytes_noclobber(path, bytes)
        .map_err(|error| format!("cannot durably create verification record: {error}"))
}

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args_os().collect();
    if args.len() != 8 {
        return Err(
            "usage: verifier RECEIPT RECEIPT_SHA256 IMAGE_ID JOURNAL PREDECESSOR PREDECESSOR_SHA256 RECORD"
                .into(),
        );
    }
    let text = |index: usize| args[index].to_str().ok_or("argument is not UTF-8");
    let receipt = Path::new(&args[1]);
    let receipt_sha = text(2)?;
    let image_id = text(3)?;
    let journal = text(4)?;
    let predecessor_path = Path::new(&args[5]);
    let predecessor_sha = text(6)?;
    if predecessor_sha == "0".repeat(64)
        || predecessor_sha.len() != 64
        || !predecessor_sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("predecessor SHA-256 is not canonical".into());
    }
    let predecessor = read_captured_bytes(predecessor_path, MAX_PREDECESSOR_BYTES)
        .map_err(|error| format!("cannot capture predecessor: {error}"))?;
    if format!("{:x}", Sha256::digest(&predecessor)) != predecessor_sha {
        return Err("predecessor SHA-256 mismatch".into());
    }
    let receipt_bytes = verify_rebuild_receipt(receipt, receipt_sha, image_id, journal)?;
    let record = serde_json::json!({
        "schema": "usdom-rebuild-receipt-verification-v1",
        "receiptSha256": receipt_sha,
        "receiptBytes": receipt_bytes,
        "methodImageId": image_id,
        "journal": journal,
        "predecessorSha256": predecessor_sha,
        "cryptographicallyVerified": true
    });
    let mut encoded = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
    encoded.push(b'\n');
    publish_record(Path::new(&args[7]), &encoded)
}

#[cfg(test)]
mod tests {
    use super::publish_record;
    use std::fs;

    #[test]
    fn verification_record_is_owner_only_durable_and_create_once() {
        let directory = tempfile::tempdir().unwrap();
        let record = directory.path().join("verification.json");
        publish_record(&record, b"first\n").unwrap();
        assert_eq!(fs::read(&record).unwrap(), b"first\n");
        assert!(publish_record(&record, b"second\n").is_err());
        assert_eq!(fs::read(&record).unwrap(), b"first\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&record).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn verification_record_rejects_symlink_destination() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let record = directory.path().join("verification.json");
        fs::write(&target, b"unchanged").unwrap();
        symlink(&target, &record).unwrap();
        assert!(publish_record(&record, b"replacement\n").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("rebuild receipt verification failed: {error}");
        std::process::exit(1);
    }
}
