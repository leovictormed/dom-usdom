#!/usr/bin/env python3
"""Enforce the production finalized-burn program's deterministic dependency boundary."""

from __future__ import annotations

import hashlib
import re
import json
import os
import stat
import tomllib
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
MANIFEST = REPO / "crates/dom-usdom-finalized-burn-program/Cargo.toml"
SOURCE = REPO / "crates/dom-usdom-finalized-burn-program/src/lib.rs"
AUTHORITY = REPO / "labs/usdom-reserve/config/finalized-burn-dependency-authority.json"
TOOLCHAIN_LOCK = REPO / "labs/usdom-reserve/config/mainnet-toolchain-lock.json"
EXPECTED_RUNTIME_FILES = {
    "/etc/ld.so.cache",
    "/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo",
    "/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc",
    "/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/libLLVM.so.22.1-rust-1.98.0-stable",
    "/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/librustc_driver-28a98848f7a7c026.so",
    "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libdl.so.2",
    "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
    "/usr/lib/x86_64-linux-gnu/libm.so.6",
    "/usr/lib/x86_64-linux-gnu/libpthread.so.0",
    "/usr/lib/x86_64-linux-gnu/librt.so.1",
    "/usr/lib/x86_64-linux-gnu/libz.so.1.3",
    "/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2",
    "/usr/lib/x86_64-linux-gnu/libexpat.so.1.9.1",
    "/usr/bin/git",
    "/usr/bin/python3.12",
}
REQUIRED_PYTHON_MODULES = {
    "argparse", "hashlib", "json", "pathlib", "re", "subprocess", "tomllib",
}

FORBIDDEN_PACKAGES = {
    "dom-chain",
    "dom-crypto",
    "dom-store",
    "dom-pow",
    "grin_secp256k1zkp",
    "lmdb-rkv",
    "lmdb-rkv-sys",
    "randomx-rs",
    "ring",
    "secp256k1-sys",
    "secp256k1-zkp",
    "secp256k1-zkp-sys",
    "tokio",
    "reqwest",
    "ureq",
    "hyper",
    "jsonrpsee",
    "web3",
    "ethers-providers",
    "alloy-provider",
    "alloy-rpc-client",
    "alloy-transport-http",
}
REQUIRED_PACKAGES = {
    "dom-core",
    "ethereum_hashing",
    "ssz_types",
    "tree_hash",
    "dom-usdom-finalized-burn-program",
    "dom-usdom-state",
    "usdom-ethereum-finality-experiment",
}
EXPECTED_LOCAL_PACKAGES = {
    ("ethereum_hashing", "0.7.0"): REPO / "crates/dom-ethereum-hashing/Cargo.toml",
    ("tree_hash", "0.10.0"): REPO / "crates/dom-ethereum-tree-hash/Cargo.toml",
    ("ssz_types", "0.11.0"): REPO / "crates/dom-ethereum-ssz-types/Cargo.toml",
}
FORBIDDEN_SOURCE = [
    r"std::fs",
    r"std::net",
    r"std::process",
    r"std::thread",
    r"std::time",
    r"std::env",
    r"unsafe\s*\{",
]


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def read_regular_snapshot(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"cannot open authority input {path}: {error.strerror}")
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail(f"authority input is not a unique regular file: {path}")
        if before.st_uid not in {0, os.geteuid()} or mode & 0o022:
            fail(f"authority input has unsafe owner or mode: {path}")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            fail(f"authority input changed while being read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def read_utf8_snapshot(path: Path) -> str:
    try:
        return read_regular_snapshot(path).decode("utf-8", "strict")
    except UnicodeDecodeError:
        fail(f"authority input is not strict UTF-8: {path}")


def sha256(path: Path) -> str:
    return hashlib.sha256(read_regular_snapshot(path)).hexdigest()


def strict_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"dependency authority contains duplicate JSON key: {key}")
        result[key] = value
    return result


def require_authenticated_launcher() -> None:
    if not sys.flags.isolated or not sys.flags.no_site:
        fail("boundary checker requires isolated Python (-I -S) through the authenticated dispatcher")
    lock = json.loads(read_utf8_snapshot(TOOLCHAIN_LOCK), object_pairs_hook=strict_object)
    matches = [entry for entry in lock.get("files", [])
               if entry.get("path") == "scripts/mainnet-tool-dispatcher"]
    if len(matches) != 1 or not re.fullmatch(r"[0-9a-f]{64}", matches[0].get("sha256", "")):
        fail("toolchain lock must contain exactly one authenticated dispatcher")
    parent_pid = os.getppid()
    try:
        descriptor = os.open(f"/proc/{parent_pid}/exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError as error:
        fail(f"cannot authenticate boundary checker launcher: {error.strerror}")
    try:
        info = os.fstat(descriptor)
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o755 or digest.hexdigest() != matches[0]["sha256"]):
            fail("boundary checker launcher is not the authenticated dispatcher")
    finally:
        os.close(descriptor)
    if os.getppid() != parent_pid:
        fail("authenticated dispatcher exited during boundary checker launch")


def dependency_closure(*, verify_python_runtime: bool = False) -> tuple[set[str], dict[str, str]]:
    authority = json.loads(read_utf8_snapshot(AUTHORITY), object_pairs_hook=strict_object)
    if set(authority) != {"schema", "rootPackage", "edgeKinds", "command", "cargoLockSha256", "runtimeFiles", "pythonModules", "manifests", "packages"}:
        fail("dependency authority schema is not closed")
    if authority["schema"] != "usdom-finalized-burn-dependency-authority/v3" \
            or authority["rootPackage"] != "dom-usdom-finalized-burn-program" \
            or authority["edgeKinds"] != ["normal"]:
        fail("dependency authority identity is invalid")
    expected_command = ["cargo", "tree", "--offline", "--locked", "-p",
                        "dom-usdom-finalized-burn-program", "--edges", "normal",
                        "--prefix", "none", "--format", "{p}"]
    if authority["command"] != expected_command:
        fail("dependency authority command is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", authority["cargoLockSha256"]) \
            or authority["cargoLockSha256"] != sha256(REPO / "Cargo.lock"):
        fail("dependency authority Cargo.lock identity drifted")
    runtime_files = authority["runtimeFiles"]
    if not isinstance(runtime_files, list) or not runtime_files or any(
            not isinstance(entry, dict) or set(entry) != {"path", "sha256"}
            or not isinstance(entry["path"], str) or not Path(entry["path"]).is_absolute()
            or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
            for entry in runtime_files):
        fail("dependency authority runtime entries are malformed")
    runtime_paths = [entry["path"] for entry in runtime_files]
    if runtime_paths != sorted(set(runtime_paths)):
        fail("dependency authority runtime set is noncanonical")
    if set(runtime_paths) != EXPECTED_RUNTIME_FILES:
        fail("dependency authority runtime closure is incomplete")
    for entry in runtime_files:
        if sha256(Path(entry["path"])) != entry["sha256"]:
            fail(f"dependency authority runtime identity drifted: {entry['path']}")
    python_modules = authority["pythonModules"]
    if not isinstance(python_modules, list) or not python_modules or any(
            not isinstance(entry, dict) or set(entry) != {"module", "path", "sha256"}
            or not isinstance(entry["module"], str) or not re.fullmatch(r"[A-Za-z0-9_.]+", entry["module"])
            or not isinstance(entry["path"], str) or not Path(entry["path"]).is_absolute()
            or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
            for entry in python_modules):
        fail("dependency authority Python module entries are malformed")
    module_keys = [(entry["module"], entry["path"]) for entry in python_modules]
    if module_keys != sorted(set(module_keys)):
        fail("dependency authority Python module closure is noncanonical")
    if not REQUIRED_PYTHON_MODULES <= {entry["module"].split(".", 1)[0] for entry in python_modules}:
        fail("dependency authority Python module closure is incomplete")
    for entry in python_modules:
        if sha256(Path(entry["path"])) != entry["sha256"]:
            fail(f"dependency authority Python module identity drifted: {entry['module']}")
    if verify_python_runtime:
        authorized_paths = {entry["path"]: entry["sha256"] for entry in python_modules}
        loaded_paths = set()
        stdlib = Path("/usr/lib/python3.12")
        for module in sys.modules.values():
            raw_path = getattr(module, "__file__", None)
            if not isinstance(raw_path, str):
                continue
            path = Path(os.path.realpath(raw_path))
            if path != stdlib and stdlib not in path.parents:
                continue
            loaded_paths.add(str(path))
        missing_runtime = sorted(loaded_paths - set(authorized_paths))
        if missing_runtime:
            fail("boundary checker loaded unauthorized Python modules: " + ", ".join(missing_runtime))
        for path in loaded_paths:
            if sha256(Path(path)) != authorized_paths[path]:
                fail(f"boundary checker Python runtime drifted: {path}")
    if not isinstance(authority["manifests"], list) or any(
            not isinstance(entry, dict) or set(entry) != {"path", "sha256"}
            or not isinstance(entry["path"], str)
            or not re.fullmatch(r"(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._/+@-]+", entry["path"])
            for entry in authority["manifests"]):
        fail("dependency authority manifest entries are malformed")
    manifest_hashes = {entry["path"]: entry["sha256"] for entry in authority["manifests"]}
    if len(manifest_hashes) != len(authority["manifests"]):
        fail("dependency authority contains duplicate manifests")
    if len(manifest_hashes) != 234:
        fail("dependency authority manifest inventory drifted")
    for relative, expected in manifest_hashes.items():
        if not re.fullmatch(r"[0-9a-f]{64}", expected) or sha256(REPO / relative) != expected:
            fail(f"dependency authority manifest identity drifted: {relative}")
    packages = authority["packages"]
    if packages != sorted(set(packages)) or not all(
            isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]+", value) for value in packages):
        fail("dependency authority package set is noncanonical")
    return set(packages), manifest_hashes


def verify_local_ethereum_hash_stack(manifest_hashes: dict[str, str]) -> None:
    for identity, expected_manifest in EXPECTED_LOCAL_PACKAGES.items():
        relative = expected_manifest.relative_to(REPO).as_posix()
        package = tomllib.loads(read_utf8_snapshot(expected_manifest)).get("package", {})
        if relative not in manifest_hashes or (package.get("name"), package.get("version")) != identity:
            fail(f"proof graph does not use path-pinned {identity[0]} {identity[1]}")


def main() -> None:
    require_authenticated_launcher()
    manifest = read_utf8_snapshot(MANIFEST)
    source = read_utf8_snapshot(SOURCE)
    if "dom-chain" in manifest.split("[dev-dependencies]", 1)[0]:
        fail("production manifest still depends on dom-chain")
    for marker in [
        'b"UDFINL03"',
        "FINALIZED_BURN_PROVER_INPUT_VERSION: u16 = 4",
        "verify_finalized_burn_inclusion",
        "verify_checkpoint_witness",
        "BurnStateWitnessV2::from_bytes",
    ]:
        if marker not in source:
            fail(f"missing portable relation marker: {marker}")
    for pattern in FORBIDDEN_SOURCE:
        if re.search(pattern, source):
            fail(f"program source contains forbidden host API: {pattern}")
    graph, manifest_hashes = dependency_closure(verify_python_runtime=True)
    verify_local_ethereum_hash_stack(manifest_hashes)
    missing = sorted(REQUIRED_PACKAGES - graph)
    if missing:
        fail("program dependency graph omitted " + ", ".join(missing))
    forbidden = sorted(FORBIDDEN_PACKAGES & graph)
    if forbidden:
        fail("program dependency graph contains " + ", ".join(forbidden))
    print(
        "PASS: UDFINL04 normal dependency graph contains "
        f"{len(graph)} packages; uses the path-pinned pure-Rust Ethereum hash stack; "
        "and excludes node, native secp256k1, ring, LMDB, RandomX, async and RPC authority"
    )
    print(
        "the deterministic positive raw Ethereum witness and selected RISC Zero "
        "guest execution benchmark are checked separately"
    )


if __name__ == "__main__":
    main()
