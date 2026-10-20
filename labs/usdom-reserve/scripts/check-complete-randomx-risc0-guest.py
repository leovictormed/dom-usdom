#!/usr/bin/env python3
"""Verify the complete portable RandomX candidate guest and pinned artifacts."""

from __future__ import annotations

import hashlib
import json
import struct
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
GUEST = REPO / "crates/dom-usdom-randomx-risc0-guest"
EXPECTED_LOCK = "745b3c37903c47e71d55b640909e745922e97f5c05afab6970cb8f0aec7edf84"
EXPECTED_ELF = "1a8e491304763477094da84ff0701ea18d935600a3b3a79eb1c1250facd6903f"
EXPECTED_BINARY = "0601bf022575b060edaeb0b32414b2f53e72f39d2284028069099414653591dd"
EXPECTED_IMAGE_ID = "8efa49d4fe0f616840013adb1d3029ef71642099cb336c577a2691f7eea1dc24"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def main() -> None:
    manifest = tomllib.loads((GUEST / "Cargo.toml").read_text())
    if manifest["dependencies"]["risc0-zkvm"] != {
        "version": "=3.0.6", "default-features": False, "features": ["std"]
    }:
        fail("unexpected risc0-zkvm dependency profile")
    portable = manifest["dependencies"]["dom-usdom-randomx-portable"]
    if portable != {"path": "../dom-usdom-randomx-portable"}:
        fail("complete guest must use the local portable relation")
    checkpoint = manifest["dependencies"]["dom-usdom-checkpoint-statement"]
    if checkpoint != {"path": "../dom-usdom-checkpoint-statement"}:
        fail("complete guest must use the canonical checkpoint statement")

    for path, expected in [
        (GUEST / "Cargo.lock", EXPECTED_LOCK),
        (GUEST / "elfs/usdom-randomx.elf", EXPECTED_ELF),
        (GUEST / "elfs/usdom-randomx.bin", EXPECTED_BINARY),
    ]:
        if sha256(path) != expected:
            fail(f"artifact drift: {path.name}")
    if (GUEST / "elfs/usdom-randomx.iid").read_text().strip() != EXPECTED_IMAGE_ID:
        fail("candidate ImageID drift")

    binary = (GUEST / "elfs/usdom-randomx.bin").read_bytes()
    if len(binary) < 20 or binary[:4] != b"R0BF":
        fail("candidate is not a RISC Zero ProgramBinary")
    version, header_len = struct.unpack_from("<II", binary, 4)
    if version != 1 or header_len == 0:
        fail("unexpected ProgramBinary framing")

    source = (GUEST / "src/main.rs").read_text()
    for marker in [
        "CheckpointRandomXStatement::from_bytes", "build_randomx_argon_cache",
        "calculate_randomx_light_hash", "statement.randomx_hash",
        ".commitment()", "env::commit_slice(&journal)",
        "risc0_zkvm::guest::entry!(guest_main)",
    ]:
        if marker not in source:
            fail(f"complete relation marker missing: {marker}")
    for forbidden in ["unsafe {", "std::fs", "std::net", "std::process"]:
        if forbidden in source:
            fail(f"forbidden guest capability: {forbidden}")

    provenance = json.loads((GUEST / "PROVENANCE.json").read_text())
    for key, value in {
        "schema": "dom-usdom-randomx-risc0-guest-provenance-v2",
        "cargoLockSha256": EXPECTED_LOCK,
        "statementSchema": "UDCRXST1",
        "statementBytes": 384,
        "journalSchema": "keccak256-DOM:checkpoint-randomx-statement:v1",
        "journalBytes": 32,
        "userElfSha256": EXPECTED_ELF,
        "programBinarySha256": EXPECTED_BINARY,
        "candidateImageId": EXPECTED_IMAGE_ID,
        "stableStatementBoundary": "dom-usdom-checkpoint-statement",
        "aggregateAssumptionJournalCompatible": True,
        "cleanLocalRebuildsByteIdentical": True,
        "positiveReceiptExecuted": False,
        "provingCostMeasured": False,
        "productionApproved": False,
    }.items():
        if provenance.get(key) != value:
            fail(f"provenance drift: {key}")

    requirements = json.loads(
        (REPO / "labs/usdom-reserve/config/production-requirements.json").read_text()
    )
    if requirements.get("production_checkpoint_guest_randomx_relation_implemented") is not True:
        fail("complete RandomX relation is not recorded")
    if requirements.get("production_checkpoint_randomx_complete_guest_accepts_udcrxst1") is not True:
        fail("complete guest UDCRXST1 parsing is not recorded")
    if requirements.get("production_checkpoint_randomx_complete_guest_journal_matches_aggregate_assumption") is not True:
        fail("complete guest journal compatibility is not recorded")
    if requirements.get("production_checkpoint_randomx_proof_receipt_implemented") is not False:
        fail("missing positive receipt must remain explicit")
    if requirements.get("external_audit_required_by_release_gate") is not False:
        fail("external audit was reintroduced as a release blocker")
    if requirements.get("absolute_zero_risk_required_by_release_gate") is not False:
        fail("absolute zero risk was reintroduced as a release blocker")

    print(
        "PASS: complete portable RandomX candidate guest; "
        f"ELF SHA-256 {EXPECTED_ELF}; ProgramBinary SHA-256 {EXPECTED_BINARY}; "
        f"ImageID {EXPECTED_IMAGE_ID}; receipt/cost/production approval remain false"
    )


if __name__ == "__main__":
    main()
