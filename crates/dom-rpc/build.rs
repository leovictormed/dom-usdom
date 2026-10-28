use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=DOM_BUILD_COMMIT");

    let release_build = env::var_os("USDOM_RELEASE_BUILD").is_some();
    let explicit = env::var("DOM_BUILD_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty());
    if release_build
        && !explicit
            .as_deref()
            .is_some_and(is_canonical_source_authority)
    {
        panic!("release build requires DOM_BUILD_COMMIT=sha256:<64 lowercase hex>");
    }
    // Builds without an authenticated source identity are explicitly
    // non-authoritative. Never execute a PATH-selected Git binary here.
    let commit = explicit.unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=DOM_RPC_BUILD_COMMIT={commit}");
}

fn is_canonical_source_authority(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
