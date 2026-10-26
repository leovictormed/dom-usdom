#!/usr/bin/env python3
"""Structural gate for the Ethereum-authorized DOM reorg floor."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
chain = (ROOT / "crates/dom-chain/src/chain_state.rs").read_text()
floor = (ROOT / "crates/dom-chain/src/ethereum_checkpoint_poc.rs").read_text()

def need(text, token, label):
    if token not in text:
        raise SystemExit(f"missing {label}: {token}")

need(floor, "ancestor_height < checkpoint.height", "strict reorg-floor comparison")
need(floor, 'rejected("reorg would undo checkpoint")', "fail-closed rejection")
need(floor, "ensure_current(store, tip_height)?", "canonical floor validation")
need(floor, "external restart checkpoint floor is required", "anti-rollback restart floor")
need(floor, "canonical history conflicts with required floor", "restart ancestry binding")

for function in (
    "promote_heavier_known_tip",
    "promote_usdom_v4_known_tip_for_schedule_inner",
    "promote_usdom_v2_known_tip_for_schedule",
):
    body = chain.split(f"fn {function}", 1)[1].split("\n    }", 1)[0]
    need(body, "ensure_checkpoint_floor", f"{function} floor refresh")
    need(body, "check_reorg", f"{function} reorg barrier")

for function in ("validate_ibd_headers_batch_with_mode", "validate_snapshot"):
    if f"fn {function}" in chain:
        body = chain.split(f"fn {function}", 1)[1].split("\n    }", 1)[0]
        need(body, "ensure_checkpoint_floor_readonly", f"{function} floor validation")

print("DOM checkpoint reorg-barrier gate: PASS")
