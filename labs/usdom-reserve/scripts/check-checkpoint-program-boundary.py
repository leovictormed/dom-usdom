#!/usr/bin/env python3
"""Enforce the checkpoint program's pure/default and host/reference split."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
MANIFEST = REPO / "crates/dom-usdom-checkpoint-program/Cargo.toml"
SOURCE = REPO / "crates/dom-usdom-checkpoint-program/src/lib.rs"
REFERENCE = REPO / "crates/dom-usdom-checkpoint-program/src/reference.rs"
FORBIDDEN_DEFAULT = {
    "dom-chain", "dom-consensus", "dom-store", "dom-pow", "randomx-rs",
    "primitive-types", "getrandom", "lmdb-rkv", "lmdb-rkv-sys", "tokio",
    "reqwest", "hyper", "jsonrpsee", "dom-usdom-state", "dom-usdom-privacy",
}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def packages(*extra: str) -> set[str]:
    command = [
        "cargo", "tree", "--offline", "--locked", "-p",
        "dom-usdom-checkpoint-program", *extra, "--edges", "normal",
        "--prefix", "none", "--format", "{p}",
    ]
    result = subprocess.run(
        command, cwd=REPO, check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=120,
    )
    found: set[str] = set()
    for line in result.stdout.splitlines():
        match = re.match(r"^([^ ]+) v[0-9]", line)
        if match:
            found.add(match.group(1))
    return found


def main() -> None:
    manifest = MANIFEST.read_text(encoding="utf-8")
    source = SOURCE.read_text(encoding="utf-8")
    reference = REFERENCE.read_text(encoding="utf-8")
    for marker in [
        'default = []', 'segment-bindings = []', 'host-reference = [', 'dep:dom-chain',
        'pub struct EconomicState', 'pub fn context_root',
        'checkpoint_economic_state_root', 'sparse_root',
        'checkpoint_segment_randomx_bindings',
        'checkpoint_segment_header_projection',
    ]:
        if marker not in manifest + source:
            fail(f"missing checkpoint-program boundary marker: {marker}")
    for marker in [
        "execute_checkpoint_extension",
        "verify_usdom_v4_serialized_candidate_for_schedule",
        "validate_header_syntax_v4_scheduled",
        "validate_median_time_past",
        "validate_pow_for_network",
        "compute_expected_target",
        "target_to_difficulty_for_network_height",
        "checked_accumulated_difficulty",
        "apply_block",
    ]:
        if marker not in reference:
            fail(f"host reference omits authoritative rule: {marker}")
    default_graph = packages()
    forbidden = sorted(default_graph & FORBIDDEN_DEFAULT)
    if forbidden:
        fail("default checkpoint-program graph contains " + ", ".join(forbidden))
    segment_graph = packages("--features", "segment-bindings")
    forbidden = sorted(segment_graph & FORBIDDEN_DEFAULT)
    if forbidden:
        fail("segment-binding graph contains " + ", ".join(forbidden))
    if segment_graph != default_graph:
        fail("segment-bindings unexpectedly changes the normal dependency graph")
    host_graph = packages("--features", "host-reference")
    for required in ["dom-chain", "dom-pow", "dom-usdom-state", "dom-usdom-privacy"]:
        if required not in host_graph:
            fail(f"host reference graph omits {required}")
    print(
        "PASS: checkpoint program default and segment-binding graphs are pure; "
        "the explicit host reference reuses authoritative DOM consensus/native validators"
    )


if __name__ == "__main__":
    try:
        main()
    except subprocess.TimeoutExpired as error:
        fail(f"Cargo dependency graph command timed out after {error.timeout} seconds")
    except subprocess.CalledProcessError as error:
        sys.stderr.write(error.stderr)
        fail(f"cargo tree failed with exit code {error.returncode}")
