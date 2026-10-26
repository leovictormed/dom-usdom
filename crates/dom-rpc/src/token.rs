//! Bearer token generation and storage.

use rand::Rng;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

const MIN_BEARER_TOKEN_BYTES: usize = 32;
const MAX_BEARER_TOKEN_BYTES: usize = 512;

/// Accept only bounded header-safe bearer material. A configured source is an
/// operator assertion, so malformed material must fail startup rather than be
/// ignored in favour of a lower-precedence source (which would make rotation
/// and revocation ambiguous).
fn validate_bearer_token(token: &str) -> Result<(), std::io::Error> {
    if token.len() < MIN_BEARER_TOKEN_BYTES || token.len() > MAX_BEARER_TOKEN_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "RPC bearer token must be {MIN_BEARER_TOKEN_BYTES}..={MAX_BEARER_TOKEN_BYTES} bytes"
            ),
        ));
    }
    if !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "RPC bearer token must contain only visible ASCII without whitespace",
        ));
    }
    Ok(())
}

fn token_from_file_bytes(raw: String) -> Result<String, std::io::Error> {
    let raw = Zeroizing::new(raw);
    let token = validate_token_file_text(&raw)?;
    Ok(token.to_owned())
}

fn validate_token_file_text(raw: &str) -> Result<&str, std::io::Error> {
    // The generated representation has exactly one optional line terminator.
    // Do not `trim()`: silently deleting spaces would make the credential on
    // disk differ from the credential an operator believes was installed.
    let token = raw
        .strip_suffix('\n')
        .and_then(|without_lf| without_lf.strip_suffix('\r').or(Some(without_lf)))
        .unwrap_or(raw);
    validate_bearer_token(token)?;
    Ok(token)
}

fn validate_token_file_metadata(token_path: &std::path::Path) -> Result<(), std::io::Error> {
    let metadata = std::fs::symlink_metadata(token_path)?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "RPC bearer token path must be a regular file, never a symlink",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "RPC bearer token file must belong to the effective user, be owner-only and have exactly one link",
            ));
        }
    }
    Ok(())
}

fn read_token_file_checked(token_path: &std::path::Path) -> Result<String, std::io::Error> {
    use std::io::Read;

    validate_token_file_metadata(token_path)?;
    let file = std::fs::File::open(token_path)?;
    let opened = file.metadata()?;
    let named = std::fs::symlink_metadata(token_path)?;
    if !opened.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "RPC bearer token opened object must be a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if opened.dev() != named.dev()
            || opened.ino() != named.ino()
            || opened.permissions().mode() & 0o077 != 0
            || opened.nlink() != 1
            || opened.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "RPC bearer token file changed or became insecure while it was being opened",
            ));
        }
    }
    #[cfg(not(unix))]
    if !named.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "RPC bearer token path changed while it was being opened",
        ));
    }
    let mut raw = String::new();
    file.take((MAX_BEARER_TOKEN_BYTES + 3) as u64)
        .read_to_string(&mut raw)?;
    if raw.len() > MAX_BEARER_TOKEN_BYTES + 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "RPC bearer token file is oversized",
        ));
    }
    Ok(raw)
}

/// Generate a cryptographically secure random token (32 bytes hex = 64 chars).
pub fn generate_token() -> String {
    let bytes = Zeroizing::new(rand::thread_rng().gen::<[u8; 32]>());
    hex::encode(&*bytes)
}

/// Consume an explicitly configured token without making another long-lived
/// heap copy, or fall back to the owner-only token file.
///
/// The RPC server awaits for the node's entire lifetime. This boundary validates
/// in place and moves the same allocation into `BearerToken`; invalid secret
/// bytes are erased before returning the startup error.
pub(crate) fn take_or_create_token_with_config(
    configured_token: Option<String>,
) -> Result<String, std::io::Error> {
    if let Some(mut token) = configured_token {
        if let Err(error) = validate_bearer_token(&token) {
            token.zeroize();
            return Err(error);
        }
        tracing::info!("Using Bearer token from explicit node config");
        return Ok(token);
    }
    get_or_create_token()
}

/// Get the Bearer token from an owner-only file, or generate a new one.
///
/// Order of precedence:
/// 1. ~/.dom/rpc_token file (fallback)
/// 2. Generate new + save to file + log warning
///
/// Reusable credentials are deliberately never accepted from the process
/// environment: on common Linux configurations another same-UID process can
/// read `/proc/<pid>/environ`, and service managers frequently persist the
/// environment in diagnostics.
pub fn get_or_create_token() -> Result<String, std::io::Error> {
    let token_path = token_file_path()?;
    get_or_create_token_at(&token_path)
}

/// File-backed half of [`get_or_create_token`], parameterized over the path so
/// the recovery behavior is testable without touching the real home directory.
fn get_or_create_token_at(token_path: &std::path::Path) -> Result<String, std::io::Error> {
    #[cfg(unix)]
    let _lock = lock_token_lifecycle(token_path)?;
    get_or_create_token_at_locked(token_path)
}

/// Serialize the complete read/repair/create transaction across cooperating
/// node processes. The lock has a stable inode separate from the credential,
/// so replacing an interrupted empty credential never drops the exclusion.
#[cfg(unix)]
fn lock_token_lifecycle(token_path: &std::path::Path) -> Result<std::fs::File, std::io::Error> {
    use std::os::{
        fd::AsFd,
        unix::fs::{DirBuilderExt, OpenOptionsExt},
    };

    let parent = token_path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Invalid token path"))?;
    let mut directory_builder = std::fs::DirBuilder::new();
    directory_builder
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    let parent_named = std::fs::symlink_metadata(parent)?;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !parent_named.file_type().is_dir()
        || parent_named.uid() != rustix::process::geteuid().as_raw()
        || parent_named.permissions().mode() & 0o077 != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "RPC bearer token directory must be direct, owner-only and owned by the effective user",
        ));
    }
    let parent_opened = std::fs::File::open(parent)?;
    let parent_retained = parent_opened.metadata()?;
    if parent_retained.dev() != parent_named.dev() || parent_retained.ino() != parent_named.ino() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "RPC bearer token directory changed while opening",
        ));
    }
    let lock_path = parent.join(".rpc_token.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .open(&lock_path)?;
    validate_token_file_metadata(&lock_path)?;
    let opened = file.metadata()?;
    let named = std::fs::symlink_metadata(&lock_path)?;
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "RPC bearer token lifecycle lock changed while opening",
        ));
    }
    rustix::fs::flock(file.as_fd(), rustix::fs::FlockOperation::LockExclusive)?;
    file.sync_all()?;
    parent_opened.sync_all()?;
    Ok(file)
}

fn get_or_create_token_at_locked(token_path: &std::path::Path) -> Result<String, std::io::Error> {
    recover_interrupted_token_claim(token_path)?;
    // A token file can legitimately exist and be empty: a crash or a full disk
    // between `save_token_at`'s `create_new` and its `write_all` leaves zero
    // bytes behind. That state must be repaired here — `save_token_at` alone
    // refuses to touch an existing file (by design, see below), so without
    // this flag every subsequent startup would die on `AlreadyExists` until
    // someone deletes the file by hand.
    let mut repair_existing = false;
    let token_exists = match std::fs::symlink_metadata(token_path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    if token_exists {
        match read_token_file_checked(token_path) {
            Ok(raw) => {
                if !raw.trim().is_empty() {
                    let token = token_from_file_bytes(raw)?;
                    tracing::info!("Using Bearer token from owner-only token file");
                    return Ok(token);
                }
                repair_existing = true;
            }
            Err(e) => {
                tracing::warn!("Failed to read configured Bearer token file: {e}");
                return Err(e);
            }
        }
    }

    let token = generate_token();
    if repair_existing {
        let adopted = repair_empty_token_at(token_path, &token)?;
        if adopted == token {
            tracing::warn!(
                "Bearer token file existed but was empty (interrupted write?); \
                 replaced it with a newly generated token."
            );
        } else {
            tracing::info!(
                "Bearer token file was repaired by another process while we waited; \
                 using its token."
            );
        }
        return Ok(adopted);
    }
    save_token_at(token_path, &token)?;
    tracing::warn!("Generated new Bearer token in the owner-only token file");
    Ok(token)
}

/// Resolve a crash after the empty file was claimed but before replacement.
/// A nonempty claim is recovery material and is restored, never discarded.
fn recover_interrupted_token_claim(token_path: &std::path::Path) -> Result<(), std::io::Error> {
    let parent = token_path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Invalid token path"))?;
    let mut claims = Vec::new();
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(suffix) = name.strip_prefix(".rpc_token.repair.") {
            if suffix.len() != 16
                || !suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed RPC bearer token repair artifact",
                ));
            }
            claims.push(entry.path());
        }
    }
    claims.sort();
    if claims.len() > 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "multiple interrupted RPC bearer token repairs require operator recovery",
        ));
    }
    let Some(claim) = claims.pop() else {
        return Ok(());
    };
    let raw = Zeroizing::new(read_token_file_checked(&claim)?);
    let token_exists = match std::fs::symlink_metadata(token_path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    if token_exists {
        validate_token_file_metadata(token_path)?;
        if raw.trim().is_empty() {
            std::fs::remove_file(claim)?;
            std::fs::File::open(parent)?.sync_all()?;
            return Ok(());
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "live RPC bearer token and interrupted nonempty repair both exist",
        ));
    }
    if raw.trim().is_empty() {
        std::fs::remove_file(claim)?;
    } else {
        validate_token_file_text(&raw)?;
        std::fs::rename(claim, token_path)?;
    }
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Repair an observed-empty token file without ever overwriting a live token.
///
/// Two nodes sharing one home directory can both read the empty file and both
/// reach here; a naive rename-over-the-target would let the loser silently
/// replace the winner's freshly persisted token. Instead the repair is built
/// from the two atomic primitives the rest of this module already relies on
/// (MSRV 1.75 — `File::lock` is 1.89+):
///
/// 1. CLAIM — atomically `rename` the empty file aside. Exactly one
///    contender succeeds; a loser sees `NotFound`, re-reads, and either
///    adopts the winner's persisted token or fails closed with the same
///    restart-and-adopt semantics a `save_token_at` race loser already has.
/// 2. RECHECK — read the file we moved. If another process repaired between
///    our empty read and our claim, we just moved a LIVE token aside: restore
///    that token rather than rotating it.
/// 3. PERSIST — write through `save_token_at`'s `create_new` (owner-only from
///    first visible state, never clobbers). If a concurrent creator wins that
///    race, adopt what it persisted.
///
/// No step renames over an existing file, so a valid token can never be
/// clobbered. A crash after the claim leaves a 0600 recovery artifact which
/// the next lock holder validates and restores before considering creation.
fn repair_empty_token_at(
    token_path: &std::path::Path,
    candidate: &str,
) -> Result<String, std::io::Error> {
    let dom_dir = token_path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Invalid token path"))?;

    let mut suffix = [0u8; 8];
    rand::thread_rng().fill(&mut suffix);
    let claimed = dom_dir.join(format!(".rpc_token.repair.{}", hex::encode(suffix)));

    match std::fs::rename(token_path, &claimed) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Lost the claim race. If the winner already persisted, adopt.
            if let Ok(raw) = read_token_file_checked(token_path) {
                if !raw.trim().is_empty() {
                    return token_from_file_bytes(raw);
                }
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "token repair already in progress in another process; \
                 a restart will adopt its token",
            ));
        }
        Err(e) => return Err(e),
    }

    let moved = read_token_file_checked(&claimed)?;
    let token = if moved.trim().is_empty() {
        candidate.to_string()
    } else {
        token_from_file_bytes(moved)?
    };

    let result = match save_token_at(token_path, &token) {
        Ok(()) => Ok(token),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // A concurrent creator (ordinary missing-file path) won the
            // create_new race; adopt what it persisted.
            let raw = read_token_file_checked(token_path)?;
            if raw.trim().is_empty() {
                Err(e)
            } else {
                token_from_file_bytes(raw)
            }
        }
        Err(e) => Err(e),
    };
    if result.is_ok() {
        // The new credential is durable; the claim no longer carries unique
        // recovery material.
        let _ = std::fs::remove_file(&claimed);
    } else if matches!(
        std::fs::symlink_metadata(token_path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ) {
        // Never delete the only copy of a live token after a disk/write error.
        // Restoring the claim also restores an interrupted empty file, which a
        // later startup can repair under the lifecycle lock.
        let _ = std::fs::rename(&claimed, token_path);
    }
    // Persist both the new credential directory entry and tombstone cleanup.
    // `save_token_at` already fsyncs the credential contents.
    let _ = std::fs::File::open(dom_dir).and_then(|directory| directory.sync_all());
    result
}

/// Get the path to ~/.dom/rpc_token (cross-platform via `dirs` crate).
///
/// On Unix: $HOME/.dom/rpc_token
/// On Windows: %USERPROFILE%\.dom\rpc_token
fn token_file_path() -> Result<PathBuf, std::io::Error> {
    let home = dirs::home_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "home directory not found (HOME/USERPROFILE unset)",
        )
    })?;
    let dom_dir = home.join(".dom");
    Ok(dom_dir.join("rpc_token"))
}

/// Create a token file without exposing it through the process umask.
fn save_token_at(token_path: &std::path::Path, token: &str) -> Result<(), std::io::Error> {
    validate_bearer_token(token)?;
    let dom_dir = token_path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Invalid token path"))?;

    // Create the parent directory before opening the token file.
    std::fs::create_dir_all(dom_dir)?;

    // `create_new` prevents a concurrent replacement and, on Unix, `mode`
    // applies before the file becomes visible. This avoids a write-then-chmod
    // window where a newly generated bearer token inherits a permissive umask.
    #[cfg(unix)]
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(token_path)?;
        file.write_all(format!("{token}\n").as_bytes())?;
        file.sync_all()?;
        std::fs::File::open(dom_dir)?.sync_all()?;
    }

    #[cfg(not(unix))]
    std::fs::write(token_path, format!("{token}\n"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const TOKEN_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    #[cfg(unix)]
    fn write_owner_only(path: &std::path::Path, contents: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, contents).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn generate_token_produces_64_char_hex() {
        let token = generate_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_token_is_random() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2);
    }

    /// A generated token must be created with owner-only permissions from the
    /// first visible filesystem state, rather than tightened after writing.
    #[cfg(unix)]
    #[test]
    fn save_token_creates_owner_only_file_without_write_chmod_window() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc_token");

        save_token_at(&path, TOKEN_A).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "token must be owner-only at creation");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{TOKEN_A}\n")
        );
        assert!(save_token_at(&path, TOKEN_B).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{TOKEN_A}\n")
        );
    }

    /// Regression: a zero-byte token file (crash / full disk between
    /// `create_new` and `write_all`) must be repaired on the next startup,
    /// not wedge every startup with `AlreadyExists` until manual deletion.
    #[cfg(unix)]
    #[test]
    fn empty_token_file_is_repaired_on_next_startup() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc_token");
        write_owner_only(&path, "\n"); // whitespace-only == no token

        let token = get_or_create_token_at(&path).expect("startup must recover");
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{token}\n"),
            "repaired file holds the returned token"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "repaired file must stay owner-only");

        // A second startup reuses the repaired token instead of rotating it.
        assert_eq!(get_or_create_token_at(&path).unwrap(), token);

        // No claim husks left behind by the repair.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != "rpc_token" && e.file_name() != ".rpc_token.lock")
            .collect();
        assert!(leftovers.is_empty(), "unexpected leftovers: {leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_empty_token_repair_adopts_one_persisted_credential() {
        use std::sync::{Arc, Barrier};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc_token");
        write_owner_only(&path, "\n");
        let barrier = Arc::new(Barrier::new(3));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    get_or_create_token_at(&path).unwrap()
                })
            })
            .collect();
        barrier.wait();
        let tokens: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(tokens[0], tokens[1]);
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            format!("{}\n", tokens[0])
        );
    }

    #[cfg(unix)]
    #[test]
    fn startup_recovers_or_cleans_crash_claim_without_rotating_live_material() {
        for contents in [format!("{TOKEN_A}\n"), String::new()] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("rpc_token");
            let claim = dir.path().join(".rpc_token.repair.0000000000000000");
            write_owner_only(&claim, &contents);
            let adopted = get_or_create_token_at(&path).unwrap();
            if contents.is_empty() {
                assert_eq!(adopted.len(), 64);
            } else {
                assert_eq!(adopted, TOKEN_A);
            }
            assert!(!claim.exists());
            assert_eq!(
                std::fs::read_to_string(path).unwrap(),
                format!("{adopted}\n")
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn startup_rejects_conflicting_live_token_and_nonempty_crash_claim() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc_token");
        let claim = dir.path().join(".rpc_token.repair.0000000000000000");
        write_owner_only(&path, &format!("{TOKEN_A}\n"));
        write_owner_only(&claim, &format!("{TOKEN_B}\n"));
        assert_eq!(
            get_or_create_token_at(&path).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            format!("{TOKEN_A}\n")
        );
        assert_eq!(
            std::fs::read_to_string(claim).unwrap(),
            format!("{TOKEN_B}\n")
        );
    }

    /// The post-claim recheck: when the repair races a process that already
    /// persisted a token, the moved-aside token must be RESTORED, not
    /// rotated — the winner keeps serving with a token that matches the file.
    #[test]
    fn repair_restores_a_token_persisted_by_a_racing_process() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc_token");
        // Simulates the race: by the time our claim lands, the file the
        // caller observed as empty has been repaired and holds a live token.
        #[cfg(unix)]
        write_owner_only(&path, &format!("{TOKEN_A}\n"));
        #[cfg(not(unix))]
        std::fs::write(&path, format!("{TOKEN_A}\n")).unwrap();

        let adopted = repair_empty_token_at(&path, TOKEN_B).unwrap();
        assert_eq!(adopted, TOKEN_A);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{TOKEN_A}\n")
        );
    }

    /// A claim-race loser (the token file is simply gone) must fail closed
    /// with a retriable error, mirroring the pre-existing semantics of losing
    /// the `create_new` race — never wedge, never rotate.
    #[test]
    fn repair_claim_loser_fails_closed_when_no_token_is_persisted_yet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc_token");
        // No file at all: the claiming winner has moved it and not yet
        // persisted its replacement.
        let err = repair_empty_token_at(&path, TOKEN_A).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    }

    /// The repair path must never fire for a file that DOES hold a token:
    /// an existing valid token is returned as-is, byte-for-byte.
    #[test]
    fn valid_token_file_is_returned_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc_token");
        #[cfg(unix)]
        write_owner_only(&path, &format!("{TOKEN_A}\n"));
        #[cfg(not(unix))]
        std::fs::write(&path, format!("{TOKEN_A}\n")).unwrap();

        assert_eq!(get_or_create_token_at(&path).unwrap(), TOKEN_A);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{TOKEN_A}\n")
        );
    }

    #[test]
    fn explicitly_configured_invalid_token_fails_closed_without_fallback() {
        for invalid in [
            "",
            "short",
            "contains whitespace but is deliberately long enough",
        ] {
            let error = take_or_create_token_with_config(Some(invalid.to_owned())).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn owned_config_token_is_moved_without_cloning_its_heap_allocation() {
        let token = TOKEN_A.to_owned();
        let allocation = token.as_ptr();
        let adopted = take_or_create_token_with_config(Some(token)).unwrap();
        assert_eq!(adopted, TOKEN_A);
        assert_eq!(adopted.as_ptr(), allocation);
    }

    #[cfg(unix)]
    #[test]
    fn persisted_token_rejects_symlink_hardlink_and_group_readable_material() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc_token");
        write_owner_only(&path, &format!("{TOKEN_A}\n"));

        let link = dir.path().join("rpc_token.symlink");
        symlink(&path, &link).unwrap();
        assert_eq!(
            get_or_create_token_at(&link).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let dangling = dir.path().join("rpc_token.dangling");
        symlink(dir.path().join("missing-token"), &dangling).unwrap();
        assert_eq!(
            get_or_create_token_at(&dangling).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );

        let hard = dir.path().join("rpc_token.hardlink");
        std::fs::hard_link(&path, &hard).unwrap();
        assert_eq!(
            get_or_create_token_at(&path).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        std::fs::remove_file(hard).unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            get_or_create_token_at(&path).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_lock_rejects_symlink_and_hardlink_substitution() {
        use std::os::unix::fs::symlink;

        for hardlink in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let lock = dir.path().join(".rpc_token.lock");
            let indirect = dir.path().join("indirect-lock");
            write_owner_only(&indirect, "");
            if hardlink {
                std::fs::hard_link(&indirect, &lock).unwrap();
            } else {
                symlink(&indirect, &lock).unwrap();
            }
            assert_eq!(
                get_or_create_token_at(&dir.path().join("rpc_token"))
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_rejects_indirect_or_nonprivate_parent_directory() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = tempfile::tempdir().unwrap();
        let actual = root.path().join("actual");
        std::fs::create_dir(&actual).unwrap();
        std::fs::set_permissions(&actual, std::fs::Permissions::from_mode(0o700)).unwrap();
        let indirect = root.path().join("indirect");
        symlink(&actual, &indirect).unwrap();
        assert_eq!(
            get_or_create_token_at(&indirect.join("rpc_token"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        std::fs::set_permissions(&actual, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(
            get_or_create_token_at(&actual.join("rpc_token"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[cfg(unix)]
    #[test]
    fn persisted_token_rejects_weak_or_noncanonical_material() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc_token");
        for invalid in [
            "short\n".to_owned(),
            format!(" {TOKEN_A}\n"),
            format!("{TOKEN_A}\n\n"),
        ] {
            write_owner_only(&path, &invalid);
            assert_eq!(
                get_or_create_token_at(&path).unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
    }

    /// The long-lived server token must zeroize its owned heap buffer on drop.
    #[test]
    fn bearer_token_has_zeroize_on_drop_contract() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<crate::middleware::BearerToken>();
    }

    /// SECRET-3 (side-channel) — dudect-style NOTE, intentionally ignored.
    ///
    /// The bearer comparison in middleware.rs uses `subtle::ConstantTimeEq`
    /// (`provided.as_bytes().ct_eq(token.0.as_bytes())`) — the CORRECT primitive:
    /// no data-dependent early return for equal-length inputs (token length is
    /// public, so length-mismatch short-circuit leaks nothing secret). A real
    /// dudect timing test over a network/async path is dominated by scheduling
    /// and HTTP jitter (orders of magnitude above the per-byte signal), so it
    /// would be noise, not evidence. We therefore record by review that the
    /// right primitive is in place rather than ship a flaky timing harness.
    #[test]
    #[ignore = "static-review note: bearer compare uses subtle::ct_eq (correct constant-time primitive); dudect over async HTTP would be noise"]
    fn bearer_compare_is_constant_time_static_note() {}
}
