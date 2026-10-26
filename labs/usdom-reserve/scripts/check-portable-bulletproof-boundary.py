#!/usr/bin/env python3
"""Fail closed if the portable DOM Bulletproof boundary drifts."""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CRATE = REPO / "crates/dom-bulletproof-portable"
GENERATORS = CRATE / "src/generators.rs"
VERIFIER = CRATE / "src/verifier.rs"
CRYPTO_MANIFEST = REPO / "crates/dom-crypto/Cargo.toml"
CONSENSUS_MANIFEST = REPO / "crates/dom-consensus/Cargo.toml"
EXPECTED_GENERATOR_SHA256 = (
    "7e4332307e2b6bd8788ddfa76641e92645edae37c6a33ec2dea12a843d36255d"
)


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def run(*command: str) -> str:
    result = subprocess.run(
        command,
        cwd=REPO,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    return result.stdout


def main() -> None:
    manifest = (CRATE / "Cargo.toml").read_text()
    crypto = CRYPTO_MANIFEST.read_text()
    consensus = CONSENSUS_MANIFEST.read_text()
    verifier = VERIFIER.read_text()
    generators = GENERATORS.read_text()

    if "#![no_std]" not in (CRATE / "src/lib.rs").read_text():
        fail("portable crate lost no_std")
    for forbidden in ["unsafe {", "extern \"C\"", "rand::", "getrandom"]:
        if forbidden in verifier or forbidden in generators:
            fail(f"portable source contains forbidden marker {forbidden!r}")
    for marker in [
        'k256 = { version = "0.13", default-features = false',
        'sha2 = { version = "0.10", default-features = false',
    ]:
        if marker not in manifest:
            fail(f"portable manifest lost marker: {marker}")
    for marker in [
        'portable-verifier = ["dep:dom-bulletproof-portable"]',
        'default = ["native-backend"]',
    ]:
        if marker not in crypto:
            fail(f"dom-crypto feature boundary lost marker: {marker}")
    if 'portable-crypto = ["dom-crypto/portable-verifier"]' not in consensus:
        fail("dom-consensus lost portable crypto feature")

    generator_bytes = bytes(
        int(value, 16) for value in re.findall(r"0x([0-9a-f]{2})", generators)
    )
    if len(generator_bytes) != 256 * 33:
        fail(f"generator table is {len(generator_bytes)} bytes, expected 8448")
    actual_hash = hashlib.sha256(generator_bytes).hexdigest()
    if actual_hash != EXPECTED_GENERATOR_SHA256:
        fail(f"generator table hash drifted to {actual_hash}")

    tree = run(
        "cargo",
        "tree",
        "--offline",
        "--locked",
        "-p",
        "dom-consensus",
        "--no-default-features",
        "--features",
        "portable-crypto",
        "--edges",
        "normal,build",
    )
    for forbidden in [
        "getrandom v",
        "grin_secp256k1zkp",
        "randomx-rs",
        "secp256k1-sys",
        "secp256k1-zkp-sys",
    ]:
        if forbidden in tree:
            fail(f"portable dependency graph contains {forbidden}")
    if "dom-bulletproof-portable" not in tree:
        fail("portable dependency graph does not contain the verifier")

    run(
        "cargo",
        "check",
        "--offline",
        "--locked",
        "-p",
        "dom-consensus",
        "--no-default-features",
        "--features",
        "portable-crypto",
    )
    print(
        "PASS: frozen generator table, pure-Rust verifier source, portable dependency graph, "
        "and dom-consensus portable feature are intact"
    )


if __name__ == "__main__":
    try:
        main()
    except subprocess.TimeoutExpired as error:
        fail(f"Cargo dependency graph command timed out after {error.timeout} seconds")
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.stderr or str(error)) from error
