#!/usr/bin/env python3
"""Validate the operational stage inventory; refuse materialization without receipt verification."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PATH = ROOT / "labs/usdom-reserve/config/checkpoint-rebuild-v3-stage-template.json"
ORDER = ["segment","pin-segment","outer","pin-outer","finalized-burn","pin-finalized-burn","receipts","gate"]

value = json.loads(PATH.read_text(encoding="utf-8"))
if set(value) != {"schema","materializable","reason","stages","availableConcreteCheckers","receiptCryptographicVerifierExecutable","receiptAggregatorExecutable","receiptVerificationOrder"}:
    raise SystemExit("invalid rebuild stage template schema")
if value["schema"] != "usdom-checkpoint-rebuild-v3-stage-template-v1" or [x.get("name") for x in value["stages"]] != ORDER:
    raise SystemExit("invalid rebuild stage order")
if value["receiptVerificationOrder"] != ["producer","verify-only-per-receipt","aggregate"]:
    raise SystemExit("invalid receipt verification pipeline order")
for stage in value["stages"]:
    if set(stage) != {"name","artifactRoles","requiredVerifications"} or not stage["artifactRoles"] or not stage["requiredVerifications"]:
        raise SystemExit(f"invalid stage inventory: {stage.get('name')}")
for relative in value["availableConcreteCheckers"].values():
    target = ROOT / relative
    if not target.is_file() or target.is_symlink():
        raise SystemExit(f"missing concrete checker: {relative}")
if value["receiptCryptographicVerifierExecutable"] is None or value["receiptAggregatorExecutable"] is None:
    if value["materializable"] is not False:
        raise SystemExit("template cannot be materializable without a cryptographic receipt verifier")
    print("PASS: stage inventory valid; production manifest intentionally impossible until receipt verifier and aggregator executables are pinned")
else:
    raise SystemExit("receipt verifier path must be reviewed and pinned before materialization is enabled")
