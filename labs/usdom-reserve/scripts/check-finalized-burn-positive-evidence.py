#!/usr/bin/env python3
"""Bind stage-273 positive finalized-burn claims to exact local evidence."""

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
RESULTS = RESERVE / "results-stage273-2026-10-20"

INPUT_SHA = "bdcd115207f47fd31e6e7b211ad2e2812ea7c5fa22fa4310ffae9b4cce949f5e"
JOURNAL = "c0461e1c2bcff62d1dfd8e8fed0b094b5d19c2744cf9bad34c8ae3722e7eaef4"
PROGRAM_SHA = "883ec39b03e3a0703e592026fc7d92a15ce7d949cb937551c5dd8360184cde21"
IMAGE_ID = "2e26f74497b54b680dfff4c116d56280d016f01d0125329f49bf6d744b1c18ea"


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
        "production_finalized_burn_positive_vector_bytes": 64782,
        "production_finalized_burn_positive_vector_public_output": JOURNAL,
        "production_finalized_burn_guest_execution_cycles": 571308757,
        "production_finalized_burn_guest_execution_segments": 580,
        "production_finalized_burn_guest_execution_segment_po2": 20,
    }
    for key, value in expected.items():
        if requirements.get(key) != value:
            fail(f"requirements mismatch for {key}")

    test = TEST.read_text()
    require_text(
        test,
        [
            "raw_ethereum_checkpoint_executes_udfinl04_end_to_end",
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
    require_text(
        program,
        [
            "checkpoint_witness_replay_slot",
            "CheckpointStatementV6",
            "execute_with_checkpoint_assumption",
            "CHECKPOINT_OUTER_IMAGE_ID",
        ],
        "UDFINL04 program",
    )
    if "checkpoint_witness_finalized_slot" in program:
        fail("UDFINL04 still equates replay ceiling with finalized slot")

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
            "segments=580",
            "user_cycles=571308757",
            "input_bytes=64782",
            f"input_sha256={INPUT_SHA}",
            f"journal={JOURNAL}",
            "segments_po2_20=579",
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
        "positive 571308757-cycle RISC Zero execution evidence are bound"
    )


if __name__ == "__main__":
    main()
