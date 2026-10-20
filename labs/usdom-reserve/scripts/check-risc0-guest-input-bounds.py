#!/usr/bin/env python3
"""Require host-controlled RISC Zero input lengths to be bounded before allocation."""

from __future__ import annotations

import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
GUEST_ROOTS = {
    "dom-usdom-checkpoint-outer-risc0-guest",
    "dom-usdom-checkpoint-segment-risc0-guest",
    "dom-usdom-economic-block-risc0-guest",
    "dom-usdom-economic-chunk-risc0-guest",
    "dom-usdom-finalized-burn-risc0-guest",
    "dom-usdom-randomx-aggregate-risc0-guest",
    "dom-usdom-randomx-risc0-guest",
}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def require_order(source: str, markers: list[str], label: str) -> None:
    positions: list[int] = []
    for marker in markers:
        index = source.find(marker)
        if index < 0:
            fail(f"{label}: missing boundary marker {marker!r}")
        positions.append(index)
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        fail(f"{label}: input boundary operations are out of order")


def require_helper_boundary(source: str, label: str, limits: list[str]) -> None:
    if source.count("let length: u32 = env::read();") != 1:
        fail(f"{label}: expected exactly one bounded dynamic-input reader")
    require_order(
        source,
        [
            "fn read_bounded(maximum: usize, label: &str) -> Vec<u8>",
            "let length: u32 = env::read();",
            "assert!(length > 0 && length <= maximum",
            "let mut bytes = vec![0u8; length];",
            "env::read_slice(&mut bytes);",
        ],
        label,
    )
    compact_source = "".join(source.split())
    for limit in limits:
        if "".join(f"read_bounded({limit}".split()) not in compact_source:
            fail(f"{label}: dynamic input is not bound by {limit}")


def require_direct_boundary(
    source: str,
    label: str,
    variable: str,
    maximum: str,
    allocation: str,
    read: str,
) -> None:
    if source.count("env::read();") != 1:
        fail(f"{label}: expected exactly one bounded dynamic-input reader")
    require_order(
        source,
        [
            f"let {variable}: u32 = env::read();",
            f"{variable} > 0 && {variable} <= {maximum}",
            allocation,
            read,
        ],
        label,
    )


def check_sources() -> None:
    discovered = {
        path.parent.parent.name
        for path in (REPO / "crates").glob("dom-usdom-*-risc0-guest/src/main.rs")
    }
    if discovered != GUEST_ROOTS:
        fail(
            "RISC Zero guest inventory changed without input-boundary review: "
            f"missing={sorted(GUEST_ROOTS - discovered)}, new={sorted(discovered - GUEST_ROOTS)}"
        )

    sources = {
        name: (REPO / "crates" / name / "src/main.rs").read_text(encoding="utf-8")
        for name in sorted(GUEST_ROOTS)
    }

    require_helper_boundary(
        sources["dom-usdom-checkpoint-outer-risc0-guest"],
        "checkpoint outer guest",
        [
            "MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES,",
            "MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES,",
            "MAX_CHECKPOINT_OUTER_CHAIN_BYTES,",
        ],
    )
    require_helper_boundary(
        sources["dom-usdom-checkpoint-segment-risc0-guest"],
        "checkpoint segment guest",
        [
            "MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES,",
            "MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES,",
            "MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,",
        ],
    )
    require_helper_boundary(
        sources["dom-usdom-economic-chunk-risc0-guest"],
        "economic chunk guest",
        [
            'MAX_CHECKPOINT_SEGMENT_PACKAGE_BYTES, "DOM v4 package"',
            'MAX_ECONOMIC_CHUNK_WITNESS_BYTES, "economic chunk witness"',
        ],
    )
    require_direct_boundary(
        sources["dom-usdom-economic-block-risc0-guest"],
        "economic block guest",
        "length",
        "MAX_ECONOMIC_CHUNK_CHAIN_BYTES",
        "let mut chain_bytes = vec![0u8; length];",
        "env::read_slice(&mut chain_bytes);",
    )
    require_direct_boundary(
        sources["dom-usdom-finalized-burn-risc0-guest"],
        "finalized burn guest",
        "input_len",
        "MAX_FINALIZED_BURN_PROVER_INPUT_BYTES",
        "let mut input = vec![0u8; input_len];",
        "env::read_slice(&mut input);",
    )
    require_direct_boundary(
        sources["dom-usdom-randomx-aggregate-risc0-guest"],
        "RandomX aggregate guest",
        "private_input_len",
        "MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES",
        "let mut private_input_bytes = vec![0u8; private_input_len];",
        "env::read_slice(&mut private_input_bytes);",
    )

    fixed = sources["dom-usdom-randomx-risc0-guest"]
    if "env::read();" in fixed or "Vec::with_capacity" in fixed or "vec![" in fixed:
        fail("complete RandomX guest must retain fixed-size host input")
    require_order(
        fixed,
        [
            "let mut statement_bytes = [0u8; CHECKPOINT_RANDOMX_STATEMENT_BYTES];",
            "env::read_slice(&mut statement_bytes);",
            "CheckpointRandomXStatement::from_bytes(&statement_bytes)",
        ],
        "complete RandomX guest",
    )


def self_test() -> None:
    safe = """
fn read_bounded(maximum: usize, label: &str) -> Vec<u8> {
    let length: u32 = env::read();
    assert!(length > 0 && length <= maximum, "invalid {label} length");
    let mut bytes = vec![0u8; length];
    env::read_slice(&mut bytes);
    bytes
}
let input = read_bounded(MAX_INPUT_BYTES, "input");
"""
    require_helper_boundary(safe, "self-test safe", ['MAX_INPUT_BYTES, "input"'])
    unsafe = safe.replace(
        'assert!(length > 0 && length <= maximum, "invalid {label} length");\n'
        "    let mut bytes = vec![0u8; length];",
        "let mut bytes = vec![0u8; length];\n"
        '    assert!(length > 0 && length <= maximum, "invalid {label} length");',
    )
    try:
        require_helper_boundary(unsafe, "self-test unsafe", ['MAX_INPUT_BYTES, "input"'])
    except SystemExit as error:
        if "out of order" not in str(error):
            raise
    else:
        raise AssertionError("pre-bound allocation mutation was accepted")
    print("PASS: RISC Zero guest input-boundary checker rejects pre-bound allocation")


def main(arguments: list[str]) -> None:
    if arguments == ["--self-test"]:
        self_test()
    elif not arguments:
        check_sources()
        print("PASS: all 7 RISC Zero guests bound host input before allocation")
    else:
        raise SystemExit("Usage: check-risc0-guest-input-bounds.py [--self-test]")


if __name__ == "__main__":
    main(sys.argv[1:])
