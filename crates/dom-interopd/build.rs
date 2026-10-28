use std::env;
use std::fs;
use std::path::PathBuf;

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let repository = manifest_dir.join("../..");
    let lockfile = repository.join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lockfile.display());
    println!("cargo:rerun-if-env-changed=DOM_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=USDOM_RELEASE_BUILD");
    let explicit = env::var("DOM_BUILD_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let release_build = env::var_os("USDOM_RELEASE_BUILD").is_some();
    if release_build
        && !explicit
            .as_deref()
            .is_some_and(is_canonical_source_authority)
    {
        panic!("release build requires DOM_BUILD_COMMIT=sha256:<64 lowercase hex>");
    }
    // Release identity comes from the descriptor-bound source authority supplied
    // by the authenticated builder. Build scripts never execute a PATH-selected
    // Git binary. Development builds remain explicitly non-authoritative.
    let authoritative = explicit
        .as_deref()
        .is_some_and(is_canonical_source_authority);
    let commit = explicit.unwrap_or_else(|| "unknown".to_owned());
    let dirty = !authoritative;
    let lock_digest = fs::read(&lockfile)
        .ok()
        .and_then(|bytes| blake2b_256_hex(&bytes))
        .unwrap_or_else(|| "unavailable".to_owned());

    println!("cargo:rustc-env=DOM_INTEROP_GIT_COMMIT={commit}");
    println!("cargo:rustc-env=DOM_INTEROP_GIT_DIRTY={dirty}");
    println!("cargo:rustc-env=DOM_INTEROP_CARGO_LOCK_BLAKE2B256={lock_digest}");
    println!(
        "cargo:rustc-env=DOM_INTEROP_BUILD_TARGET={}",
        env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned())
    );
    println!(
        "cargo:rustc-env=DOM_INTEROP_BUILD_PROFILE={}",
        env::var("PROFILE").unwrap_or_else(|_| "unknown".to_owned())
    );
}

fn is_canonical_source_authority(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn blake2b_256_hex(bytes: &[u8]) -> Option<String> {
    let mut hash = Blake2bVar::new(32).ok()?;
    hash.update(bytes);
    let mut digest = [0u8; 32];
    hash.finalize_variable(&mut digest).ok()?;
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").ok()?;
    }
    Some(encoded)
}
