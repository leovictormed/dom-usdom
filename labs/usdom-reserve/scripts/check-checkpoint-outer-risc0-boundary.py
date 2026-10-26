#!/usr/bin/env python3
"""Verify the candidate outer checkpoint guest and recursive authority boundary."""

from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
GUEST = REPO / "crates/dom-usdom-checkpoint-outer-risc0-guest"
EXPECTED_LOCK = "e9e3696164e4cef4d20194457333c48fea709ab2960ba387e60720831e5ee745"
EXPECTED_ELF = "37c6c0b315fc301a0587708a1589da0a2cb6d3e1a30b0941431251c1b43224a4"
EXPECTED_BINARY = "8f9d0f1753172a9c1d3be22d105d08ea890cd566f18a81fb54c557f620f59b09"
EXPECTED_IMAGE_ID = "e59d68487386939b2ac379f04528acb6b3138697e17adfda3ad23ebe195af3df"
SEGMENT_IMAGE_ID = "4e711490f3ab7dde97636687972456da58da4287ce5017e38d4acaa7263a02d6"


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
        "path": "../dom-usdom-checkpoint-program",
        "features": ["outer-execution", "risc0-recursion"],
    }:
        fail("outer guest must enable only outer composition and recursion")

    source = (GUEST / "src/main.rs").read_text()
    expected_segment_bytes = ", ".join(
        f"0x{SEGMENT_IMAGE_ID[index:index + 2]}"
        for index in range(0, len(SEGMENT_IMAGE_ID), 2)
    )
    compact_source = " ".join(source.split())
    if expected_segment_bytes not in compact_source:
        fail("compile-time segment ImageID differs from reviewed candidate")
    markers = [
        "CheckpointStatementV6::from_bytes",
        "CheckpointOuterChain::from_bytes",
        "validate_checkpoint_outer_chain_v6",
        "verify_checkpoint_segment_receipts_in_guest(executed.segment_receipts())",
        "env::commit_slice(&executed.statement_hash())",
    ]
    for marker in markers:
        if marker not in source:
            fail(f"outer relation marker missing: {marker}")
    if source.index(markers[3]) > source.index(markers[4]):
        fail("statement hash is committed before recursive receipt verification")
    for forbidden in ["unsafe {", "std::fs", "std::net", "std::process"]:
        if forbidden in source:
            fail(f"forbidden guest capability: {forbidden}")

    for path, expected in [
        (GUEST / "Cargo.lock", EXPECTED_LOCK),
        (GUEST / "elfs/usdom-checkpoint-outer.elf", EXPECTED_ELF),
        (GUEST / "elfs/usdom-checkpoint-outer.bin", EXPECTED_BINARY),
    ]:
        if sha256(path) != expected:
            fail(f"artifact drift: {path.name}")
    if (GUEST / "elfs/usdom-checkpoint-outer.iid").read_text().strip() != EXPECTED_IMAGE_ID:
        fail("outer ImageID drift")
    binary = (GUEST / "elfs/usdom-checkpoint-outer.bin").read_bytes()
    if len(binary) < 20 or binary[:4] != b"R0BF":
        fail("outer artifact is not a RISC Zero ProgramBinary")
    version, header_len = struct.unpack_from("<II", binary, 4)
    if version != 1 or header_len == 0:
        fail("unexpected outer ProgramBinary framing")

    cargo = shutil.which("cargo") or str(Path.home() / ".cargo/bin/cargo")
    tree = subprocess.run(
        [cargo, "+risc0", "tree", "--locked", "--target",
         "riscv32im-risc0-zkvm-elf", "-p",
         "dom-usdom-checkpoint-outer-risc0-guest"],
        cwd=REPO, check=True, capture_output=True, text=True, timeout=120,
    ).stdout
    for forbidden in [
        "randomx-rs", "secp256k1-zkp-sys", "grin_secp256k1zkp",
        "dom-chain", "dom-consensus", "dom-pow",
    ]:
        if forbidden in tree:
            fail(f"non-portable or unnecessary dependency entered outer graph: {forbidden}")

    provenance = json.loads((GUEST / "PROVENANCE.json").read_text())
    for key, value in {
        "cargoLockSha256": EXPECTED_LOCK,
        "userElfSha256": EXPECTED_ELF,
        "programBinarySha256": EXPECTED_BINARY,
        "imageId": EXPECTED_IMAGE_ID,
        "pinnedSegmentImageId": SEGMENT_IMAGE_ID,
        "maximumSegments": 720,
        "maximumChainBytes": 1670412,
        "segmentBlockCountRange": [1, 32],
        "canonicalTargetBoundaryRequired": True,
        "confirmationSuffixRequired": True,
        "hostRandomnessEnabled": False,
        "cleanLocalRebuildsByteIdentical": True,
        "positiveReceiptExecuted": False,
        "productionApproved": False,
    }.items():
        if provenance.get(key) != value:
            fail(f"provenance drift: {key}")

    requirements = json.loads(
        (REPO / "labs/usdom-reserve/config/production-requirements.json").read_text()
    )
    if requirements.get("external_audit_required_by_release_gate") is not False:
        fail("external audit was reintroduced as a release blocker")
    if requirements.get("absolute_zero_risk_required_by_release_gate") is not False:
        fail("absolute zero risk was reintroduced as a release blocker")

    print(
        "PASS: outer checkpoint guest pins complete segment ImageID "
        f"{SEGMENT_IMAGE_ID}; ELF {EXPECTED_ELF}; ProgramBinary {EXPECTED_BINARY}; "
        f"outer ImageID {EXPECTED_IMAGE_ID}"
    )


if __name__ == "__main__":
    try:
        main()
    except subprocess.TimeoutExpired as error:
        fail(f"Cargo dependency graph command timed out after {error.timeout} seconds")
