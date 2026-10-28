#!/usr/bin/env python3
"""Fail closed unless every current checkpoint/burn artifact implements V6/V4."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def load_json(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def sha256(relative: str) -> str:
    digest = hashlib.sha256()
    with (ROOT / relative).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def raw_iid(relative: str) -> str:
    encoded = (ROOT / relative).read_bytes()
    if len(encoded) == 32:
        return encoded.hex()
    try:
        value = encoded.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise ValueError(f"noncanonical ImageID file: {relative}") from error
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"noncanonical ImageID file: {relative}")
    return value


def rust_byte_array(source: str, constant: str) -> str | None:
    match = re.search(
        rf"(?:pub\s+)?const\s+{re.escape(constant)}\s*:\s*\[u8;\s*32\]\s*=\s*\[(.*?)\];",
        source,
        re.S,
    )
    if not match:
        return None
    values = re.findall(r"0x([0-9a-fA-F]{2})", match.group(1))
    return "".join(values).lower() if len(values) == 32 else None


def quoted_constant(source: str, constant: str) -> str | None:
    match = re.search(
        rf"const\s+{re.escape(constant)}\s*:\s*&str\s*=\s*\"([0-9a-f]{{64}})\"",
        source,
    )
    return match.group(1) if match else None


def integer_constant(source: str, constant: str) -> int:
    match = re.search(
        rf"(?:pub\s+)?const\s+{re.escape(constant)}\s*:\s*(?:usize|u32)\s*=\s*([0-9_]+)\s*;",
        source,
    )
    if not match:
        raise ValueError(f"cannot derive Rust constant {constant}")
    return int(match.group(1).replace("_", ""))


def canonical_outer_bounds() -> tuple[int, int]:
    """Derive transition/outer sizes from the Rust wire-format leaves."""
    statement = (ROOT / "crates/dom-usdom-checkpoint-statement/src/lib.rs").read_text()
    program = (ROOT / "crates/dom-usdom-checkpoint-program/src/lib.rs").read_text()
    outer = (ROOT / "crates/dom-usdom-checkpoint-program/src/outer.rs").read_text()
    header_count = integer_constant(statement, "CHECKPOINT_CONTEXT_HEADER_COUNT")
    seed_count = integer_constant(statement, "CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS")
    max_span = integer_constant(statement, "MAX_CONTEXT_SPAN")
    state_prefix = integer_constant(program, "CHECKPOINT_SEGMENT_STATE_PREFIX_BYTES")
    transition_prefix = integer_constant(program, "CHECKPOINT_SEGMENT_TRANSITION_PREFIX_BYTES")
    outer_header = integer_constant(outer, "OUTER_CHAIN_HEADER_BYTES")
    context_bytes = 8 + 2 + 8 + 32 + 4 + 32 + header_count * (8 + 32 + 8) + 1 + seed_count * (8 + 32)
    transition_bytes = transition_prefix + 2 * (state_prefix + context_bytes)
    return transition_bytes, outer_header + max_span * transition_bytes


def audit() -> dict:
    failures: list[str] = []
    segment = load_json("crates/dom-usdom-checkpoint-segment-risc0-guest/PROVENANCE.json")
    outer = load_json("crates/dom-usdom-checkpoint-outer-risc0-guest/PROVENANCE.json")
    burn = load_json("crates/dom-usdom-finalized-burn-risc0-guest/PROVENANCE.json")
    requirements = load_json("labs/usdom-reserve/config/production-requirements.json")
    verifier_template = load_json("labs/usdom-reserve/config/checkpoint-verifier.unconfigured.json")
    transition_bytes, maximum_outer_chain_bytes = canonical_outer_bounds()

    segment_iid = raw_iid(
        "crates/dom-usdom-checkpoint-segment-risc0-guest/elfs/usdom-checkpoint-segment.iid"
    )
    outer_iid = raw_iid(
        "crates/dom-usdom-checkpoint-outer-risc0-guest/elfs/usdom-checkpoint-outer.iid"
    )
    burn_iid = raw_iid(
        "crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.iid"
    )

    expected = [
        (segment.get("transitionSchema") == "UDCSTN04", "segment provenance is not UDCSTN04"),
        (outer.get("statementSchema") == "UDCPST06", "outer provenance is not UDCPST06"),
        (
            outer.get("segmentTransitionSchema") == "UDCSTN04",
            "outer provenance does not consume UDCSTN04",
        ),
        (
            outer.get("journalSchema") == "solidity-checkpoint-statement-v6-hash",
            "outer provenance does not commit the V6/V4 statement hash",
        ),
        (segment.get("imageId") == segment_iid, "segment provenance/ImageID file mismatch"),
        (outer.get("imageId") == outer_iid, "outer provenance/ImageID file mismatch"),
        (burn.get("imageId") == burn_iid, "burn provenance/ImageID file mismatch"),
        (
            outer.get("pinnedSegmentImageId") == segment_iid,
            "outer provenance pins a different segment ImageID",
        ),
        (
            burn.get("statementSchema") == "UDFINL04",
            "burn provenance does not name the current burn input schema",
        ),
        (
            burn.get("checkpointStatementSchema") == "UDCPST06",
            "burn provenance does not bind UDCPST06",
        ),
        (
            burn.get("checkpointOuterImageId") == outer_iid,
            "burn provenance does not pin the rebuilt outer ImageID",
        ),
    ]

    artifact_hashes = [
        (segment, "programBinarySha256", "crates/dom-usdom-checkpoint-segment-risc0-guest/elfs/usdom-checkpoint-segment.bin"),
        (outer, "programBinarySha256", "crates/dom-usdom-checkpoint-outer-risc0-guest/elfs/usdom-checkpoint-outer.bin"),
        (burn, "programBinarySha256", "crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.elf"),
    ]
    for provenance, field, path in artifact_hashes:
        expected.append((provenance.get(field) == sha256(path), f"{path} hash differs from provenance"))

    outer_guest = (ROOT / "crates/dom-usdom-checkpoint-outer-risc0-guest/src/main.rs").read_text()
    proof_host = (ROOT / "crates/dom-usdom-checkpoint-proof-host/src/lib.rs").read_text()
    burn_program = (ROOT / "crates/dom-usdom-finalized-burn-program/src/lib.rs").read_text()
    sdk = (ROOT / "labs/usdom-reserve/sdk/checkpoint-submission.mjs").read_text()
    verifier_sdk = (ROOT / "labs/usdom-reserve/sdk/checkpoint-verifier-config.mjs").read_text()
    expected.extend(
        [
            (rust_byte_array(outer_guest, "SEGMENT_IMAGE_ID") == segment_iid, "outer source segment ImageID drift"),
            (quoted_constant(proof_host, "SEGMENT_IMAGE_ID") == segment_iid, "proof host segment ImageID drift"),
            (quoted_constant(proof_host, "OUTER_IMAGE_ID") == outer_iid, "proof host outer ImageID drift"),
            (rust_byte_array(burn_program, "CHECKPOINT_OUTER_IMAGE_ID") == outer_iid, "burn program outer ImageID drift"),
            (
                re.search(r"const outerImageId='([0-9a-f]{64})'", sdk).group(1) == outer_iid
                if re.search(r"const outerImageId='([0-9a-f]{64})'", sdk)
                else False,
                "SDK outer ImageID drift",
            ),
            (
                requirements.get("production_checkpoint_outer_pinned_segment_image_id") == segment_iid,
                "production requirements segment ImageID drift",
            ),
            (
                requirements.get("production_checkpoint_outer_guest_candidate_image_id") == outer_iid,
                "production requirements outer ImageID drift",
            ),
            (
                requirements.get("production_checkpoint_registry_risc0_evm_adapter_image_id_pinned") is True,
                "checkpoint EVM adapter ImageID is not declared pinned",
            ),
            (
                requirements.get("production_checkpoint_recursive_segment_transition_statement_magic")
                == "UDCSTN04",
                "production requirements segment transition magic is stale",
            ),
            (
                requirements.get("production_checkpoint_recursive_segment_transition_statement_bytes")
                == transition_bytes,
                "production requirements segment transition size is stale",
            ),
            (
                requirements.get("production_checkpoint_recursive_segment_transition_statement_commitment")
                == "keccak256-DOM:checkpoint-segment-transition:v4",
                "production requirements segment transition domain is stale",
            ),
            (
                requirements.get("production_checkpoint_verifier_manifest_schema")
                == "usdom-checkpoint-verifier-config-v8",
                "production requirements verifier manifest schema is stale",
            ),
            (
                requirements.get("production_checkpoint_outer_maximum_chain_bytes")
                == maximum_outer_chain_bytes,
                "production requirements outer chain bound is stale",
            ),
            (verifier_template.get("statementVersion") == "6", "verifier template statementVersion is not 6"),
            (
                verifier_template.get("transitionCommitmentVersion") == "4",
                "verifier template transitionCommitmentVersion is not 4",
            ),
            (
                verifier_template.get("publicStatementBytes") == "551",
                "verifier template publicStatementBytes is not 551",
            ),
            (
                verifier_template.get("segmentTransitionVersion") == "4",
                "verifier template segmentTransitionVersion is not 4",
            ),
            (
                verifier_template.get("segmentTransitionBytes") == "2320",
                "verifier template segmentTransitionBytes is not 2320",
            ),
            (
                "DOM:checkpoint-segment-transition:v4" in verifier_sdk,
                "verifier SDK transition domain is not v4",
            ),
            (
                "c.statementVersion!==6n" in verifier_sdk,
                "verifier SDK does not require statementVersion 6",
            ),
            (
                "c.transitionCommitmentVersion!==4n" in verifier_sdk,
                "verifier SDK does not require transitionCommitmentVersion 4",
            ),
            (
                "c.segmentTransitionVersion!==4n" in verifier_sdk,
                "verifier SDK does not require segmentTransitionVersion 4",
            ),
            (
                "c.segmentTransitionBytes!==2320n" in verifier_sdk,
                "verifier SDK does not require 2320-byte segment transitions",
            ),
        ]
    )
    for condition, message in expected:
        if not condition:
            failures.append(message)

    return {
        "schema": "usdom-checkpoint-v6-artifact-chain-audit-v1",
        "ready": not failures,
        "segmentImageId": segment_iid,
        "outerImageId": outer_iid,
        "finalizedBurnImageId": burn_iid,
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--audit-current",
        action="store_true",
        help="report stale state without relaxing the default release failure",
    )
    args = parser.parse_args()
    report = audit()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ready"] or args.audit_current else 1


if __name__ == "__main__":
    raise SystemExit(main())
