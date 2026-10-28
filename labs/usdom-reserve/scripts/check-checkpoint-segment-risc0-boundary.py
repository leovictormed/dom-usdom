#!/usr/bin/env python3
"""Verify the complete checkpoint-segment guest boundary and candidate artifact."""

from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
GUEST = REPO / "crates/dom-usdom-checkpoint-segment-risc0-guest"
EXPECTED_LOCK = "e9e3696164e4cef4d20194457333c48fea709ab2960ba387e60720831e5ee745"
EXPECTED_ELF = "5f4d087842d61a463a93242c88efa6ff3c54b52a4e176b1b9a225cc2a8ee7092"
EXPECTED_BINARY = "426cc782490b8d680e5bd2266cc4a03b3e731194d92eda44875ea5d552cb5f74"
EXPECTED_IMAGE_ID = "371e408b360a0e4a0aae2cb994bddb2d66afcc5891a7ed574fa83119734bfbf7"
ECONOMIC_BLOCK_IMAGE_ID = "03dc111fee3c42a772f142c80d4a921a19bde10f932f86c888606503a28c22a7"


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    manifest = tomllib.loads((GUEST / "Cargo.toml").read_text())
    if manifest["dependencies"]["risc0-zkvm"] != {
        "version": "=3.0.6",
        "default-features": False,
        "features": ["std"],
    }:
        fail("unexpected risc0-zkvm dependency profile")
    checkpoint = manifest["dependencies"]["dom-usdom-checkpoint-program"]
    if checkpoint != {
        "path": "../dom-usdom-checkpoint-program",
        "features": ["economic-chunks", "risc0-recursion"],
    }:
        fail("guest must enable the full portable executor and receipt recursion")

    source = (GUEST / "src/main.rs").read_text()
    expected_economic_bytes = ", ".join(
        f"0x{ECONOMIC_BLOCK_IMAGE_ID[index:index + 2]}"
        for index in range(0, len(ECONOMIC_BLOCK_IMAGE_ID), 2)
    )
    if expected_economic_bytes not in " ".join(source.split()):
        fail("compile-time economic-block ImageID differs from reviewed candidate")
    for marker in [
        "CheckpointSegmentTransition::from_bytes",
        "CheckpointSegmentPolicyInput::from_bytes",
        "CheckpointSegmentNativeStateOpening::from_bytes",
        "CheckpointSegmentPrivateInput::from_bytes",
        "execute_checkpoint_segment_portable",
        "verify_checkpoint_segment_randomx_bindings_in_guest",
        "verify_checkpoint_economic_block_receipts_in_guest",
        "env::commit_slice(&executed.transition_commitment())",
    ]:
        if marker not in source:
            fail(f"guest relation marker missing: {marker}")
    for forbidden in ["unsafe {", "std::fs", "std::net", "std::process"]:
        if forbidden in source:
            fail(f"forbidden guest capability: {forbidden}")

    for path, expected in [
        (GUEST / "Cargo.lock", EXPECTED_LOCK),
        (GUEST / "elfs/usdom-checkpoint-segment.elf", EXPECTED_ELF),
        (GUEST / "elfs/usdom-checkpoint-segment.bin", EXPECTED_BINARY),
    ]:
        if sha256(path) != expected:
            fail(f"artifact drift: {path.name}")
    if (GUEST / "elfs/usdom-checkpoint-segment.iid").read_text().strip() != EXPECTED_IMAGE_ID:
        fail("candidate ImageID drift")
    binary = (GUEST / "elfs/usdom-checkpoint-segment.bin").read_bytes()
    if len(binary) < 20 or binary[:4] != b"R0BF":
        fail("candidate is not a RISC Zero ProgramBinary")
    version, header_len = struct.unpack_from("<II", binary, 4)
    if version != 1 or header_len == 0:
        fail("unexpected ProgramBinary framing")

    cargo = shutil.which("cargo") or str(Path.home() / ".cargo/bin/cargo")
    tree = subprocess.run(
        [
            cargo, "+risc0", "tree", "--locked", "--target",
            "riscv32im-risc0-zkvm-elf", "-p",
            "dom-usdom-checkpoint-segment-risc0-guest",
        ],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    ).stdout
    for forbidden in ["randomx-rs", "secp256k1-zkp-sys", "grin_secp256k1zkp", "dom-chain"]:
        if forbidden in tree:
            fail(f"non-portable dependency entered guest graph: {forbidden}")

    provenance = json.loads((GUEST / "PROVENANCE.json").read_text())
    expected = {
        "cargoLockSha256": EXPECTED_LOCK,
        "userElfSha256": EXPECTED_ELF,
        "programBinarySha256": EXPECTED_BINARY,
        "imageId": EXPECTED_IMAGE_ID,
        "randomxReceiptImageIdStatePinned": True,
        "economicBlockReceiptImageIdPinned": True,
        "pinnedEconomicBlockImageId": ECONOMIC_BLOCK_IMAGE_ID,
        "hostRandomnessEnabled": False,
        "cleanLocalRebuildsByteIdentical": True,
        "positiveReceiptExecuted": False,
        "outerCheckpointVerifierImage": False,
    }
    for key, value in expected.items():
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
        "PASS: complete portable checkpoint-segment guest; "
        f"ELF SHA-256 {EXPECTED_ELF}; ProgramBinary SHA-256 {EXPECTED_BINARY}; "
        f"ImageID {EXPECTED_IMAGE_ID}; receipt/cost/outer authority remain explicit"
    )


if __name__ == "__main__":
    try:
        main()
    except subprocess.TimeoutExpired as error:
        fail(f"Cargo dependency graph command timed out after {error.timeout} seconds")
