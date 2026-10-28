#!/usr/bin/env python3
"""Bind stage-273 positive finalized-burn claims to exact local evidence."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


RESERVE = Path(__file__).resolve().parents[1]
REPO = RESERVE.parents[1]
REQUIREMENTS = RESERVE / "config/production-requirements.json"
TEST = REPO / "crates/dom-usdom-finalized-burn-program/tests/raw_checkpoint_positive.rs"
PROGRAM = REPO / "crates/dom-usdom-finalized-burn-program/src/lib.rs"
FINALITY = REPO / "labs/usdom-ethereum-finality/src/lib.rs"
GUEST = REPO / "crates/dom-usdom-finalized-burn-risc0-guest"
RESULTS = RESERVE / "results-stage1468-2026-10-27"

INPUT_SHA = "6128efcc1a95b331728bf2571cbfe22508599e7e3af17d3d611226c81f704789"
JOURNAL = "c0461e1c2bcff62d1dfd8e8fed0b094b5d19c2744cf9bad34c8ae3722e7eaef4"
CHECKPOINT_JOURNAL = "735fbcd6b6585826f52bcff5f28952cda395d27cada51744d014ad9bd403f1ea"
CHECKPOINT_IMAGE_ID = "311d58dadcb97cac783e3ec0efe3c4570f42b944cbda1e48aeb56b055682257b"
PROGRAM_SHA = "bf3202187d7c0643204bcb936b34a53b41b871cc4d633781dc96956c7de9d511"
IMAGE_ID = "f0d9c98287719bf6fca6626ab96f0b14e305662873a9e3b5d4894a50f206a1ae"
HARNESS_SHA = "43833267dac2a37ecb69963bb8f2a7bd5f0e5ee2aa04313548fa35cd1256a0fd"


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def require_text(text: str, markers: list[str], label: str) -> None:
    for marker in markers:
        if marker not in text:
            fail(f"{label} omitted {marker}")


def parse_unique_fields(text: str, names: set[str], label: str) -> dict[str, str]:
    """Parse an exact, contradiction-free subset of line-oriented evidence."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([a-zA-Z][a-zA-Z0-9_]*)=(\S+)", line)
        if match is None or match.group(1) not in names:
            continue
        name, value = match.groups()
        if name in fields:
            fail(f"{label} repeats {name}")
        fields[name] = value
    missing = sorted(names - fields.keys())
    if missing:
        fail(f"{label} omitted exact fields: {', '.join(missing)}")
    return fields


def require_exact_fields(
    text: str, expected: dict[str, str], label: str
) -> None:
    actual = parse_unique_fields(text, set(expected), label)
    for name, value in expected.items():
        if actual[name] != value:
            fail(f"{label} mismatch for {name}")


def main() -> None:
    requirements = json.loads(REQUIREMENTS.read_text())
    expected = {
        "production_finalized_burn_guest_positive_raw_witness_executed": True,
        "production_finalized_burn_guest_benchmarked": True,
        "production_finalized_burn_raw_checkpoint_positive_vector": True,
        "production_finalized_burn_canonical_replay_slot_enforced": True,
        "production_finalized_burn_positive_evidence_checker_implemented": True,
        "production_finalized_burn_positive_vector_sha256": INPUT_SHA,
        "production_finalized_burn_positive_vector_bytes": 64815,
        "production_finalized_burn_positive_vector_public_output": JOURNAL,
        "production_finalized_burn_guest_execution_cycles": 581398127,
        "production_finalized_burn_guest_execution_segments": 590,
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

    harness = RESULTS / "execution-harness.rs"
    if hashlib.sha256(harness.read_bytes()).hexdigest() != HARNESS_SHA:
        fail("execution harness drift")
    harness_text = harness.read_text()
    require_text(
        harness_text,
        [
            "execute_with_checkpoint_assumption(&input)",
            "ReceiptClaim::ok(*checkpoint.image_id(), checkpoint.journal().to_vec())",
            "builder.add_assumption(assumption)",
            'println!("assumption_mode=unresolved_execution_claim")',
        ],
        "execution harness",
    )
    if "FakeReceipt" in harness_text:
        fail("execution harness uses a fake receipt")

    execution = (RESULTS / "guest-positive-execution.txt").read_text()
    require_exact_fields(
        execution,
        {
            "mode": "execute",
            "assumption_mode": "unresolved_execution_claim",
            "checkpoint_image_id": CHECKPOINT_IMAGE_ID,
            "checkpoint_journal": CHECKPOINT_JOURNAL,
            "segments": "590",
            "user_cycles": "581398127",
            "input_bytes": "64815",
            "input_sha256": INPUT_SHA,
            "journal": JOURNAL,
            "segments_po2_20": "589",
        },
        "guest execution evidence",
    )
    if execution.count("Exit status: 0") != 1:
        fail("guest execution evidence lacks one exact successful exit status")
    reproducible = (RESULTS / "reproducible-build.txt").read_text()
    require_exact_fields(
        reproducible,
        {
            "builds": "2",
            "byte_identical": "true",
            "build1_program_binary_sha256": PROGRAM_SHA,
            "build2_program_binary_sha256": PROGRAM_SHA,
            "checked_in_program_binary_sha256": PROGRAM_SHA,
            "image_id": IMAGE_ID,
        },
        "build evidence",
    )

    print(
        "PASS: canonical raw checkpoint vector, byte-identical guest build and "
        "positive 581398127-cycle RISC Zero execution-only evidence are bound; "
        "the recursive receipt remains a separate gate"
    )


if __name__ == "__main__":
    main()
