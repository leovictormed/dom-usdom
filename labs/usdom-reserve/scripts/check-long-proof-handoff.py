#!/usr/bin/env python3
"""Authenticate a long-proof terminal record without controlling its process."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from durable_create_once import install_create_once


HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def fail(message: str) -> None:
    raise ValueError(message)


def strict_pairs(pairs: list[tuple[str, object]]) -> dict:
    value: dict = {}
    for key, item in pairs:
        if key in value:
            fail(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def reject_json_float(value: str) -> object:
    fail(f"JSON floating-point number is forbidden: {value}")


def exact(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        fail(f"{label} must use the exact supported schema")
    return value


def load_direct(path: Path, root: Path, label: str) -> tuple[dict, str]:
    resolved = path.resolve(strict=True)
    if resolved.parent != root and root not in resolved.parents:
        fail(f"{label} escapes the run directory")
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        fail(f"{label} must be one direct regular file")
    raw = path.read_bytes()
    return json.loads(raw, object_pairs_hook=strict_pairs, parse_float=reject_json_float), \
        hashlib.sha256(raw).hexdigest()


def hash_direct(path: Path, root: Path, label: str) -> str:
    resolved = path.resolve(strict=True)
    if resolved.parent != root and root not in resolved.parents:
        fail(f"{label} escapes the run directory")
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        fail(f"{label} must be one direct regular file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference(root: Path, value: object, label: str) -> tuple[Path, str]:
    item = exact(value, {"path", "sha256"}, label)
    if not isinstance(item["path"], str) or Path(item["path"]).is_absolute() or ".." in Path(item["path"]).parts:
        fail(f"{label} path must be canonical and relative")
    if not HEX64.fullmatch(str(item["sha256"])):
        fail(f"{label} SHA-256 is malformed")
    return root / item["path"], item["sha256"]


def process_identity(pid: int) -> tuple[str, str] | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        # comm may contain spaces and parentheses; fields following its last ')' are stable.
        start_ticks = stat[stat.rfind(")") + 2 :].split()[19]
        command = Path(f"/proc/{pid}/cmdline").read_bytes()
        return start_ticks, hashlib.sha256(command).hexdigest()
    except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError):
        return None


def inspect(run_root: Path, expected_commit: str, expected_tree: str, expected_schema: str) -> dict:
    root = run_root.resolve(strict=True)
    manifest, manifest_sha = load_direct(root / "run-manifest.json", root, "run manifest")
    exact(manifest, {"schema", "pid", "processStartTicks", "commandSha256", "sourceCommit",
                     "sourceTree", "proofSchema", "startedUnix"}, "run manifest")
    if manifest["schema"] != "usdom-long-proof-run-v1" or not isinstance(manifest["pid"], int) or manifest["pid"] <= 1:
        fail("run manifest identity is invalid")
    for field in ("processStartTicks", "startedUnix"):
        if not isinstance(manifest[field], str) or not manifest[field].isdigit():
            fail(f"run manifest {field} is not canonical")
    if not HEX64.fullmatch(str(manifest["commandSha256"])) or not HEX40.fullmatch(str(manifest["sourceCommit"])) \
            or not HEX40.fullmatch(str(manifest["sourceTree"])) or not isinstance(manifest["proofSchema"], str):
        fail("run manifest cryptographic identity is invalid")
    identity = process_identity(manifest["pid"])
    same_process = identity == (manifest["processStartTicks"], manifest["commandSha256"])
    terminal_path = root / "terminal.json"
    if not terminal_path.exists():
        if not same_process:
            fail("nonterminal run has no live process with the authenticated identity")
        return {"schema": "usdom-long-proof-handoff-v1", "classification": "active",
                "releaseAllowed": False, "promotionAllowed": False, "runManifestSha256": manifest_sha,
                "proofSchema": manifest["proofSchema"], "reason": "authenticated proof process is still active"}
    if same_process:
        fail("terminal record exists while the authenticated process is still active")
    terminal, terminal_sha = load_direct(terminal_path, root, "terminal record")
    exact(terminal, {"schema", "runManifestSha256", "exitStatus", "finishedUnix", "receiptIndex",
                     "status", "target"}, "terminal record")
    if terminal["schema"] != "usdom-long-proof-terminal-v1" or terminal["runManifestSha256"] != manifest_sha:
        fail("terminal record is not bound to the run manifest")
    if not isinstance(terminal["exitStatus"], int) or terminal["exitStatus"] < 0 or terminal["exitStatus"] > 255 \
            or not isinstance(terminal["finishedUnix"], str) or not terminal["finishedUnix"].isdigit() \
            or int(terminal["finishedUnix"]) < int(manifest["startedUnix"]):
        fail("terminal timing or exit status is invalid")
    artifacts: dict[str, tuple[dict, str]] = {}
    for field in ("receiptIndex", "status"):
        path, expected = reference(root, terminal[field], field)
        value, actual = load_direct(path, root, field)
        if actual != expected:
            fail(f"{field} differs from its terminal SHA-256")
        artifacts[field] = value, actual
    target_path, target_expected = reference(root, terminal["target"], "target")
    target_actual = hash_direct(target_path, root, "target")
    if target_actual != target_expected:
        fail("target differs from its terminal SHA-256")
    index = exact(artifacts["receiptIndex"][0], {"schema", "proofSchema", "receipts"}, "receipt index")
    status = exact(artifacts["status"][0], {"schema", "complete", "proofSchema", "receiptCount",
                                                   "targetSha256"}, "proof status")
    receipts = index["receipts"]
    if index["schema"] != "usdom-long-proof-receipt-index-v1" or not isinstance(receipts, list) or not receipts:
        fail("receipt index is empty or unsupported")
    seen: set[str] = set()
    for number, item in enumerate(receipts):
        item = exact(item, {"path", "sha256", "status"}, f"receipt {number}")
        path, expected = reference(root, {"path": item["path"], "sha256": item["sha256"]}, f"receipt {number}")
        if item["status"] != "verified" or item["path"] in seen:
            fail("receipts must be uniquely named and verified")
        seen.add(item["path"])
        actual = hash_direct(path, root, f"receipt {number}")
        if actual != expected:
            fail(f"receipt {number} differs from its index hash")
    if status["schema"] != "usdom-long-proof-status-v1" or status["complete"] is not True \
            or status["proofSchema"] != index["proofSchema"] or status["receiptCount"] != len(receipts) \
            or status["targetSha256"] != target_actual or manifest["proofSchema"] != index["proofSchema"]:
        fail("proof status, receipts and target do not form one complete result")
    current = (manifest["sourceCommit"] == expected_commit and manifest["sourceTree"] == expected_tree
               and manifest["proofSchema"] == expected_schema)
    succeeded = terminal["exitStatus"] == 0
    classification = "current-complete" if current and succeeded else "historical-stale" if succeeded else "failed-stale"
    return {"schema": "usdom-long-proof-handoff-v1", "classification": classification,
            "releaseAllowed": True, "promotionAllowed": current and succeeded,
            "runManifestSha256": manifest_sha, "terminalSha256": terminal_sha,
            "proofSchema": manifest["proofSchema"],
            "reason": "authenticated terminal result may release old locks/target; promotion follows classification"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-directory", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-source-tree", required=True)
    parser.add_argument("--expected-proof-schema", required=True)
    parser.add_argument("--recipe")
    args = parser.parse_args()
    try:
        result = inspect(Path(args.run_directory), args.expected_source_commit,
                         args.expected_source_tree, args.expected_proof_schema)
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.recipe:
            target = Path(args.recipe)
            install_create_once(target,encoded.encode(),mode=0o600,maximum=2*1024*1024,
                                private_parent=True,allow_equal=True)
        print(encoded, end="")
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as error:
        print(f"long-proof handoff refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
