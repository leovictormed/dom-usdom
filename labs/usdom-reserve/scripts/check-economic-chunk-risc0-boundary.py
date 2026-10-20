#!/usr/bin/env python3
"""Verify the bounded economic-chunk guest and frozen candidate artifact."""

import hashlib
import json
import shutil
import struct
import subprocess
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
GUEST = REPO / "crates/dom-usdom-economic-chunk-risc0-guest"
EXPECTED_LOCK = "e9e3696164e4cef4d20194457333c48fea709ab2960ba387e60720831e5ee745"
EXPECTED_ELF = "eb4091a118e19205ae4ff6d776e18e811aa2a80063695e768be2a26be45fb3a0"
EXPECTED_BINARY = "5e7bc30f65ab4eae7c8b19a8c1c386cd023cd648c85f64008be2bd4729231842"
EXPECTED_IMAGE_ID = "67d286e04444b52305ec409de3c0d22b2131a42f2aa6706f087ace253048e350"


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
    if manifest["dependencies"]["dom-usdom-checkpoint-program"] != {
        "path": "../dom-usdom-checkpoint-program", "features": ["economic-chunks"]
    }:
        fail("chunk guest must enable only bounded economic execution")

    source = (GUEST / "src/main.rs").read_text()
    for marker in [
        "EconomicChunkTransition::from_bytes", "EconomicChunkWitness::from_bytes",
        "execute_economic_chunk_portable", "assert_eq!(executed, transition",
        "env::commit_slice(&executed.commitment()",
    ]:
        if marker not in source:
            fail(f"guest relation marker missing: {marker}")
    for forbidden in ["unsafe {", "std::fs", "std::net", "std::process"]:
        if forbidden in source:
            fail(f"forbidden guest capability: {forbidden}")

    for path, expected in [
        (GUEST / "Cargo.lock", EXPECTED_LOCK),
        (GUEST / "elfs/usdom-economic-chunk.elf", EXPECTED_ELF),
        (GUEST / "elfs/usdom-economic-chunk.bin", EXPECTED_BINARY),
    ]:
        if sha256(path) != expected:
            fail(f"artifact drift: {path.name}")
    if (GUEST / "elfs/usdom-economic-chunk.iid").read_text().strip() != EXPECTED_IMAGE_ID:
        fail("chunk ImageID drift")
    binary = (GUEST / "elfs/usdom-economic-chunk.bin").read_bytes()
    if len(binary) < 20 or binary[:4] != b"R0BF":
        fail("candidate is not a RISC Zero ProgramBinary")
    version, header_len = struct.unpack_from("<II", binary, 4)
    if version != 1 or header_len == 0:
        fail("unexpected ProgramBinary framing")

    cargo = shutil.which("cargo") or str(Path.home() / ".cargo/bin/cargo")
    tree = subprocess.run(
        [cargo, "+risc0", "tree", "--locked", "--target", "riscv32im-risc0-zkvm-elf",
         "-p", "dom-usdom-economic-chunk-risc0-guest"],
        cwd=REPO, check=True, capture_output=True, text=True,
    ).stdout
    for forbidden in ["randomx-rs", "secp256k1-zkp-sys", "grin_secp256k1zkp", "dom-chain"]:
        if forbidden in tree:
            fail(f"non-portable dependency entered chunk guest graph: {forbidden}")

    provenance = json.loads((GUEST / "PROVENANCE.json").read_text())
    for key, value in {
        "cargoLockSha256": EXPECTED_LOCK, "userElfSha256": EXPECTED_ELF,
        "programBinarySha256": EXPECTED_BINARY, "imageId": EXPECTED_IMAGE_ID,
        "maximumKeysPerChunk": 512, "maximumWitnessBytes": 4232743,
        "cleanLocalRebuildsByteIdentical": True, "positiveReceiptExecuted": False,
        "productionApproved": False,
    }.items():
        if provenance.get(key) != value:
            fail(f"provenance drift: {key}")

    print(f"PASS: economic chunk guest; ELF {EXPECTED_ELF}; ProgramBinary {EXPECTED_BINARY}; ImageID {EXPECTED_IMAGE_ID}")


if __name__ == "__main__":
    main()
