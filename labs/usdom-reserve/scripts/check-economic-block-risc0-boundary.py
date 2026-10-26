#!/usr/bin/env python3
"""Verify the complete economic-block recursive guest and pinned chunk relation."""

import hashlib
import json
import shutil
import struct
import subprocess
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
GUEST = REPO / "crates/dom-usdom-economic-block-risc0-guest"
EXPECTED_LOCK = "e9e3696164e4cef4d20194457333c48fea709ab2960ba387e60720831e5ee745"
EXPECTED_ELF = "e863f8ddc042a0692f8ceebc8d0c074e6812087bc9c06a5cd1710ac0c7bfda2f"
EXPECTED_BINARY = "e16e6aea7d470baad85bec45578e0960c02c2d47bce267e26141a2f3fa4a6c1f"
EXPECTED_IMAGE_ID = "03dc111fee3c42a772f142c80d4a921a19bde10f932f86c888606503a28c22a7"
CHUNK_IMAGE_ID = "67d286e04444b52305ec409de3c0d22b2131a42f2aa6706f087ace253048e350"


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    manifest = tomllib.loads((GUEST / "Cargo.toml").read_text())
    if manifest["dependencies"]["risc0-zkvm"] != {
        "version": "=3.0.6", "default-features": False, "features": ["std"]
    }:
        fail("unexpected risc0-zkvm dependency profile")
    if manifest["dependencies"]["dom-usdom-economic-block-program"] != {
        "path": "../dom-usdom-economic-block-program", "features": ["risc0-recursion"]
    }:
        fail("block guest must enable recursive receipt verification")

    source = (GUEST / "src/main.rs").read_text()
    expected_chunk_bytes = ", ".join(
        f"0x{CHUNK_IMAGE_ID[index:index + 2]}" for index in range(0, len(CHUNK_IMAGE_ID), 2)
    )
    if expected_chunk_bytes not in " ".join(source.split()):
        fail("compile-time chunk ImageID differs from reviewed candidate")
    markers = [
        "EconomicBlockTransition::from_bytes", "EconomicChunkChain::from_bytes",
        "validate_economic_block_chain", "verify_economic_chunk_receipts_in_guest",
        "env::commit_slice(&execution.block_commitment())",
    ]
    for marker in markers:
        if marker not in source:
            fail(f"guest relation marker missing: {marker}")
    if source.index(markers[3]) > source.index(markers[4]):
        fail("block commitment is published before chunk receipt verification")

    for path, expected in [
        (GUEST / "Cargo.lock", EXPECTED_LOCK),
        (GUEST / "elfs/usdom-economic-block.elf", EXPECTED_ELF),
        (GUEST / "elfs/usdom-economic-block.bin", EXPECTED_BINARY),
    ]:
        if sha256(path) != expected:
            fail(f"artifact drift: {path.name}")
    if (GUEST / "elfs/usdom-economic-block.iid").read_text().strip() != EXPECTED_IMAGE_ID:
        fail("block ImageID drift")
    binary = (GUEST / "elfs/usdom-economic-block.bin").read_bytes()
    if len(binary) < 20 or binary[:4] != b"R0BF":
        fail("candidate is not a RISC Zero ProgramBinary")
    version, header_len = struct.unpack_from("<II", binary, 4)
    if version != 1 or header_len == 0:
        fail("unexpected ProgramBinary framing")

    cargo = shutil.which("cargo") or str(Path.home() / ".cargo/bin/cargo")
    tree = subprocess.run(
        [cargo, "+risc0", "tree", "--locked", "--target", "riscv32im-risc0-zkvm-elf",
         "-p", "dom-usdom-economic-block-risc0-guest"],
        cwd=REPO, check=True, capture_output=True, text=True, timeout=120,
    ).stdout
    for forbidden in ["randomx-rs", "secp256k1-zkp-sys", "grin_secp256k1zkp", "dom-chain"]:
        if forbidden in tree:
            fail(f"non-portable dependency entered block guest graph: {forbidden}")

    provenance = json.loads((GUEST / "PROVENANCE.json").read_text())
    for key, value in {
        "cargoLockSha256": EXPECTED_LOCK, "userElfSha256": EXPECTED_ELF,
        "programBinarySha256": EXPECTED_BINARY, "imageId": EXPECTED_IMAGE_ID,
        "pinnedChunkImageId": CHUNK_IMAGE_ID, "maximumChunksPerBlock": 80,
        "maximumChainBytes": 18412, "cleanLocalRebuildsByteIdentical": True,
        "positiveReceiptExecuted": False, "productionApproved": False,
    }.items():
        if provenance.get(key) != value:
            fail(f"provenance drift: {key}")

    print(f"PASS: complete economic block guest pins chunk ImageID {CHUNK_IMAGE_ID}; ImageID {EXPECTED_IMAGE_ID}")


if __name__ == "__main__":
    try:
        main()
    except subprocess.TimeoutExpired as error:
        fail(f"Cargo dependency graph command timed out after {error.timeout} seconds")
