//! Owner-only text-secret loading for standalone node processes.
//!
//! Secrets are named by a non-secret environment variable or command-line
//! path, but their contents never cross argv or the process environment. The
//! loader rejects symlinks, group/other access, replacement during open,
//! unbounded input, and invalid UTF-8 before returning the secret to its
//! in-process consumer.

use std::path::Path;

use dom_wallet_crypto::read_private_bytes;
use zeroize::Zeroize;

/// Read one bounded UTF-8 secret from an owner-only regular file.
///
/// One terminal LF or CRLF is ignored so files created by ordinary secret
/// provisioning tools are accepted. Embedded line endings are left to the
/// caller's format-specific validation. `description` must be a static,
/// non-secret label used only in redacted diagnostics.
pub fn load_owner_only_utf8_secret_file(
    path: &Path,
    description: &'static str,
    minimum_bytes: u64,
    maximum_bytes: u64,
) -> anyhow::Result<String> {
    if minimum_bytes == 0 || maximum_bytes < minimum_bytes {
        anyhow::bail!("invalid {description} secret-file bounds");
    }

    let file_bound = maximum_bytes
        .checked_add(2)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| anyhow::anyhow!("invalid {description} secret-file bound"))?;
    let mut raw = read_private_bytes(path, file_bound)
        .map_err(|error| anyhow::anyhow!("cannot capture {description} file: {error}"))?;
    // Transfer the sole plaintext allocation into the String. Copying from the
    // Zeroizing buffer would temporarily retain two secret allocations, and a
    // failed UTF-8 conversion would otherwise drop the copied bytes unzeroed.
    let bytes = std::mem::take(&mut *raw);
    let mut secret = match String::from_utf8(bytes) {
        Ok(secret) => secret,
        Err(error) => {
            let mut invalid = error.into_bytes();
            invalid.zeroize();
            anyhow::bail!("{description} file is not valid UTF-8");
        }
    };
    // Retain the single String allocation that becomes the caller-owned
    // secret. Creating a trimmed copy would leave the original plaintext
    // allocation behind when it is freed.
    if secret.ends_with("\r\n") {
        secret.truncate(secret.len() - 2);
    } else if secret.ends_with('\n') {
        secret.truncate(secret.len() - 1);
    }
    let length = secret.len() as u64;
    if length < minimum_bytes || length > maximum_bytes {
        secret.zeroize();
        anyhow::bail!("{description} must contain {minimum_bytes}..={maximum_bytes} bytes");
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::load_owner_only_utf8_secret_file;

    #[cfg(unix)]
    fn secret_file(contents: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("secret fixture directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private secret fixture directory");
        let path = directory.path().join("secret");
        std::fs::write(&path, contents).expect("write secret fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("secure secret fixture");
        (directory, path)
    }

    #[cfg(unix)]
    #[test]
    fn accepts_owner_only_bounded_utf8_and_one_newline() {
        let (_directory, path) = secret_file(b"correct horse battery staple\n");
        assert_eq!(
            load_owner_only_utf8_secret_file(&path, "test secret", 1, 64).unwrap(),
            "correct horse battery staple"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_insecure_mode_invalid_utf8_and_oversize() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let (_directory, path) = secret_file(b"valid-secret");
        let link = path.with_extension("link");
        symlink(&path, &link).expect("symlink fixture");
        assert!(load_owner_only_utf8_secret_file(&link, "test secret", 1, 64).is_err());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("insecure fixture mode");
        assert!(load_owner_only_utf8_secret_file(&path, "test secret", 1, 64).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("restore fixture mode");

        std::fs::write(&path, [0xff]).expect("invalid UTF-8 fixture");
        assert!(load_owner_only_utf8_secret_file(&path, "test secret", 1, 64).is_err());
        std::fs::write(&path, [b'x'; 65]).expect("oversized fixture");
        assert!(load_owner_only_utf8_secret_file(&path, "test secret", 1, 64).is_err());

        std::fs::write(&path, b"valid-secret").expect("restore fixture");
        let hardlink = path.with_extension("hardlink");
        std::fs::hard_link(&path, &hardlink).expect("hard-link fixture");
        assert!(load_owner_only_utf8_secret_file(&path, "test secret", 1, 64).is_err());
    }
}
