#!/usr/bin/env python3
"""Enforce the production finalized-burn program's deterministic dependency boundary."""

from __future__ import annotations

import re
import json
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
MANIFEST = REPO / "crates/dom-usdom-finalized-burn-program/Cargo.toml"
SOURCE = REPO / "crates/dom-usdom-finalized-burn-program/src/lib.rs"

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


def packages() -> set[str]:
    result = subprocess.run(
        [
            "cargo",
            "tree",
            "--offline",
            "--locked",
            "-p",
            "dom-usdom-finalized-burn-program",
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ],
        cwd=REPO,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    found: set[str] = set()
    for line in result.stdout.splitlines():
        match = re.match(r"^([^ ]+) v[0-9]", line)
        if match:
            found.add(match.group(1))
    return found


def verify_local_ethereum_hash_stack() -> None:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--offline",
            "--locked",
            "--format-version",
            "1",
        ],
        cwd=REPO,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    metadata = json.loads(result.stdout)
    packages_by_id = {package["id"]: package for package in metadata["packages"]}
    nodes_by_id = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    roots = [
        package["id"]
        for package in metadata["packages"]
        if package["name"] == "dom-usdom-finalized-burn-program"
    ]
    if len(roots) != 1:
        fail("unable to identify one finalized-burn program package")
    closure: set[str] = set()
    pending = roots
    while pending:
        package_id = pending.pop()
        if package_id in closure:
            continue
        closure.add(package_id)
        pending.extend(dependency["pkg"] for dependency in nodes_by_id[package_id]["deps"])
    for identity, expected_manifest in EXPECTED_LOCAL_PACKAGES.items():
        matches = [
            package
            for package_id, package in packages_by_id.items()
            if package_id in closure
            and (package["name"], package["version"]) == identity
        ]
        if len(matches) != 1:
            fail(f"proof graph must contain exactly one {identity[0]} {identity[1]}")
        package = matches[0]
        if package["source"] is not None or Path(package["manifest_path"]).resolve() != expected_manifest:
            fail(f"proof graph does not use path-pinned {identity[0]} {identity[1]}")


def main() -> None:
    manifest = MANIFEST.read_text()
    source = SOURCE.read_text()
    if "dom-chain" in manifest.split("[dev-dependencies]", 1)[0]:
        fail("production manifest still depends on dom-chain")
    for marker in [
        'b"UDFINL03"',
        "FINALIZED_BURN_PROVER_INPUT_VERSION: u16 = 3",
        "verify_finalized_burn_inclusion",
        "verify_checkpoint_witness",
        "BurnStateWitnessV2::from_bytes",
    ]:
        if marker not in source:
            fail(f"missing portable relation marker: {marker}")
    for pattern in FORBIDDEN_SOURCE:
        if re.search(pattern, source):
            fail(f"program source contains forbidden host API: {pattern}")
    graph = packages()
    verify_local_ethereum_hash_stack()
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
    try:
        main()
    except subprocess.TimeoutExpired as error:
        fail(f"Cargo dependency graph command timed out after {error.timeout} seconds")
    except subprocess.CalledProcessError as error:
        sys.stderr.write(error.stderr)
        fail(f"cargo tree failed with exit code {error.returncode}")
