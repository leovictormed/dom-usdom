#!/usr/bin/env python3
"""Enforce the deterministic UDCPST03/context dependency boundary."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
MANIFEST = REPO / "crates/dom-usdom-checkpoint-statement/Cargo.toml"
SOURCE = REPO / "crates/dom-usdom-checkpoint-statement/src/lib.rs"
FORBIDDEN_PACKAGES = {
    "dom-chain", "dom-store", "dom-pow", "lmdb-rkv", "lmdb-rkv-sys",
    "randomx-rs", "tokio", "reqwest", "ureq", "hyper", "jsonrpsee",
    "web3", "ethers-providers", "alloy-provider", "alloy-rpc-client",
}
FORBIDDEN_SOURCE = [
    r"std::fs", r"std::net", r"std::process", r"std::thread", r"std::time",
    r"std::env", r"unsafe\s*\{",
]


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def packages() -> set[str]:
    result = subprocess.run(
        ["cargo", "tree", "--offline", "--locked", "-p",
         "dom-usdom-checkpoint-statement", "--edges", "normal", "--prefix", "none",
         "--format", "{p}"],
        cwd=REPO, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=120,
    )
    found: set[str] = set()
    for line in result.stdout.splitlines():
        match = re.match(r"^([^ ]+) v[0-9]", line)
        if match:
            found.add(match.group(1))
    return found


def main() -> None:
    manifest = MANIFEST.read_text()
    source = SOURCE.read_text()
    if "dom-chain" in manifest.split("[dev-dependencies]", 1)[0]:
        fail("statement manifest depends on dom-chain")
    for marker in [
        'b"UDCPST03"', "CHECKPOINT_STATEMENT_BYTES: usize = 514",
        'b"UDCCTX02"', "CHECKPOINT_CONTEXT_BYTES", "required_historical_seed_heights",
        "DOMCheckpoint(bytes32 bridgeDomain", "hash_canonical_statement",
    ]:
        if marker not in source:
            fail(f"missing public-statement marker: {marker}")
    for pattern in FORBIDDEN_SOURCE:
        if re.search(pattern, source):
            fail(f"statement library contains forbidden host API: {pattern}")
    graph = packages()
    if "dom-usdom-checkpoint-statement" not in graph or "sha3" not in graph:
        fail("statement graph omits its crate or Keccak implementation")
    forbidden = sorted(FORBIDDEN_PACKAGES & graph)
    if forbidden:
        fail("statement dependency graph contains " + ", ".join(forbidden))
    print(
        "PASS: UDCPST03/context normal dependency graph contains "
        f"{len(graph)} packages and excludes DOM node, storage, RandomX, async and RPC authority"
    )
    print("the private consensus-extension proof relation remains a separate required program")


if __name__ == "__main__":
    try:
        main()
    except subprocess.TimeoutExpired as error:
        fail(f"Cargo dependency graph command timed out after {error.timeout} seconds")
    except subprocess.CalledProcessError as error:
        sys.stderr.write(error.stderr)
        fail(f"cargo tree failed with exit code {error.returncode}")
