#!/usr/bin/env python3
"""Bind stage-233 positive finalized-burn claims to exact local evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


RESERVE = Path(__file__).resolve().parents[1]
REPO = RESERVE.parents[1]
REQUIREMENTS = RESERVE / "config/production-requirements.json"
TEST = REPO / "crates/dom-usdom-finalized-burn-program/tests/raw_checkpoint_positive.rs"
PROGRAM = REPO / "crates/dom-usdom-finalized-burn-program/src/lib.rs"
FINALITY = REPO / "labs/usdom-ethereum-finality/src/lib.rs"
GUEST = REPO / "crates/dom-usdom-finalized-burn-risc0-guest"
RESULTS = RESERVE / "results-stage233-2026-10-20"

INPUT_SHA = "975383b1ad8dbf8e7ec471673314e6b26250ca6e325456f8380cbaef3529ff4e"
JOURNAL = "881ebff15b6a4ee9939138160651119b4107713397d362b550355aae22fafaf8"
PROGRAM_SHA = "438adf4a9a50832da0dfbb77c0b8588d9ba1fbb41d216875e874dfa1db5dfcb0"
IMAGE_ID = "3975a5f01dc85b6e89925913c5555ade4aefb951c65261142384fd829a70f88a"


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def require_text(text: str, markers: list[str], label: str) -> None:
    for marker in markers:
        if marker not in text:
            fail(f"{label} omitted {marker}")


def main() -> None:
    requirements = json.loads(REQUIREMENTS.read_text())
    expected = {
        "production_finalized_burn_guest_positive_raw_witness_executed": True,
        "production_finalized_burn_guest_benchmarked": True,
        "production_finalized_burn_raw_checkpoint_positive_vector": True,
        "production_finalized_burn_canonical_replay_slot_enforced": True,
        "production_finalized_burn_positive_evidence_checker_implemented": True,
        "production_finalized_burn_positive_vector_sha256": INPUT_SHA,
        "production_finalized_burn_positive_vector_bytes": 64070,
        "production_finalized_burn_positive_vector_public_output": JOURNAL,
        "production_finalized_burn_guest_execution_cycles": 562418750,
        "production_finalized_burn_guest_execution_segments": 570,
        "production_finalized_burn_guest_execution_segment_po2": 20,
    }
    for key, value in expected.items():
        if requirements.get(key) != value:
            fail(f"requirements mismatch for {key}")

    test = TEST.read_text()
    require_text(
        test,
        [
            "raw_ethereum_checkpoint_executes_udfinl02_end_to_end",
            "checkpoint_witness_replay_slot",
            INPUT_SHA,
            JOURNAL,
            "assert!(checkpoint_witness_replay_slot(&noncanonical_clock).is_err())",
            "FinalizedBurnProverInput::from_bytes(&wrong_replay_ceiling).is_err()",
        ],
        "positive vector test",
    )
    if "unsafe_test_only_verified_checkpoint" in test:
        fail("positive vector bypasses raw Ethereum verification")

    require_text(
        FINALITY.read_text(),
        [
            "canonical_transcript_replay_slot",
            "accepted.current_slot == accepted.update.signature_slot",
        ],
        "finality replay boundary",
    )
    program = PROGRAM.read_text()
    require_text(program, ["checkpoint_witness_replay_slot"], "UDFINL02 program")
    if "checkpoint_witness_finalized_slot" in program:
        fail("UDFINL02 still equates replay ceiling with finalized slot")

    artifact = GUEST / "elfs/usdom-finalized-burn.elf"
    if hashlib.sha256(artifact.read_bytes()).hexdigest() != PROGRAM_SHA:
        fail("positive guest ProgramBinary drift")
    if (GUEST / "elfs/usdom-finalized-burn.iid").read_bytes().hex() != IMAGE_ID:
        fail("positive guest ImageID drift")

    execution = (RESULTS / "guest-positive-execution.txt").read_text()
    require_text(
        execution,
        [
            "mode=execute",
            "segments=570",
            "user_cycles=562418750",
            "input_bytes=64070",
            f"input_sha256={INPUT_SHA}",
            f"journal={JOURNAL}",
            "segments_po2_20=570",
            "Exit status: 0",
        ],
        "guest execution evidence",
    )
    reproducible = (RESULTS / "reproducible-build.txt").read_text()
    require_text(reproducible, ["builds=2", "byte_identical=true", f"image_id={IMAGE_ID}"], "build evidence")
    if reproducible.count(PROGRAM_SHA) != 3:
        fail("reproducible build evidence does not bind all three byte-identical artifacts")

    print(
        "PASS: canonical raw checkpoint vector, byte-identical guest build and "
        "positive 562418750-cycle RISC Zero execution evidence are bound"
    )


if __name__ == "__main__":
    main()
