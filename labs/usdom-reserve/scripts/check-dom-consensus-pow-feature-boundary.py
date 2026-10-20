#!/usr/bin/env python3
"""Enforce native backend isolation without weakening node defaults."""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CONSENSUS_MANIFEST = REPO / "crates/dom-consensus/Cargo.toml"
POW_MANIFEST = REPO / "crates/dom-pow/Cargo.toml"
BLOCK = REPO / "crates/dom-consensus/src/block.rs"


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def tree(package: str, *extra: str) -> str:
    result = subprocess.run(
        ["cargo", "tree", "--offline", "--locked", "-p", package, *extra, "--edges", "normal,build"],
        cwd=REPO,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout


def main() -> None:
    consensus = CONSENSUS_MANIFEST.read_text()
    pow_manifest = POW_MANIFEST.read_text()
    block = BLOCK.read_text()
    for marker in [
        'default = ["native-crypto", "native-randomx"]',
        'native-crypto = ["dom-crypto/native-backend"]',
        'native-randomx = ["dom-pow/native-randomx"]',
        'portable-crypto = ["dom-crypto/portable-verifier"]',
        'dom-pow = { workspace = true, default-features = false }',
        'dom-crypto = { path = "../dom-crypto", default-features = false }',
    ]:
        if marker not in consensus:
            fail(f"missing consensus feature marker: {marker}")
    if 'default = ["native-randomx"]' not in pow_manifest:
        fail("dom-pow default no longer retains native RandomX")
    if block.count('#[cfg(feature = "native-randomx")]') < 3:
        fail("native RandomX imports and validators are not feature-gated")

    portable = tree(
        "dom-consensus", "--no-default-features", "--features", "portable-crypto"
    )
    forbidden = [
        "getrandom v",
        "grin_secp256k1zkp",
        "randomx-rs",
        "secp256k1-sys",
        "secp256k1-zkp-sys",
    ]
    for package in forbidden:
        if package in portable:
            fail(f"portable consensus graph still contains {package}")
    if "dom-bulletproof-portable" not in portable:
        fail("portable consensus graph lost the pure-Rust Bulletproof verifier")
    normal = tree("dom-consensus")
    if "randomx-rs" not in normal:
        fail("default consensus graph lost native RandomX")
    node = tree("dom-node")
    if "randomx-rs" not in node:
        fail("default node graph lost native RandomX")
    print(
        "PASS: dom-consensus portable graph excludes native crypto, OS RNG, and RandomX; "
        "default consensus and node graphs retain native RandomX"
    )


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.stderr or str(error)) from error
