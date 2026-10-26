#!/usr/bin/env python3
"""Require both wallet recovery builds to reauthenticate Cargo after execution."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
for relative in (
    "labs/usdom-reserve/scripts/prepare-native-receiving-wallet.sh",
    "labs/usdom-reserve/scripts/drill-closed-mainnet-wallet-recovery.sh",
):
    text = (ROOT / relative).read_text(encoding="utf-8")
    build = text.find('"$CARGO_BIN" build')
    post = text.find("assert_cargo_unchanged", build)
    if build < 0 or post <= build:
        raise SystemExit(f"{relative}: Cargo is not reauthenticated after build")

print("stage1059 wallet recovery Cargo TOCTOU gate: PASS")
