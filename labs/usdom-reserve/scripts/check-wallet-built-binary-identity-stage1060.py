#!/usr/bin/env python3
"""Require credential-bearing wallet workflows to pin every built executable."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
checks = {
    "labs/usdom-reserve/scripts/prepare-native-receiving-wallet.sh": (
        'test ! -L "$WALLET_RECOVERY_BIN"',
        "wallet_recovery_identity=$(stat -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h'",
        'assert_wallet_recovery_binary_unchanged',
    ),
    "labs/usdom-reserve/scripts/drill-closed-mainnet-wallet-recovery.sh": (
        'test ! -L "$built_binary"',
        "keystore_binary_identity=$(stat -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h'",
        "recovery_binary_identity=$(stat -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h'",
    ),
}
for relative, markers in checks.items():
    text = (ROOT / relative).read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"{relative}: missing built-binary identity check: {marker}")

print("stage1060 wallet built-binary identity gate: PASS")
