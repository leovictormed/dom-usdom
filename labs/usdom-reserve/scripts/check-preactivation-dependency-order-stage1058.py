#!/usr/bin/env python3
"""Guard the Registry-before-reserve production materialization dependency."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
core = (ROOT / "labs/usdom-reserve/sdk/production-preactivation-core.mjs").read_text()
pins = (ROOT / "labs/usdom-reserve/sdk/production-solidity-pins.mjs").read_text()

for marker in (
    "reservePreActivationConfigHash:null",
    "Registry runtime hash",
    "pre-activation owner set must use canonical ascending order",
):
    if marker not in core:
        raise SystemExit(f"preactivation dependency gate: missing {marker}")

for marker in (
    "checkpointRegistry:releaseConfig.checkpointRegistry",
    "checkpointRegistryRuntimeCodeHash:releaseConfig.checkpointRegistryRuntimeCodeHash",
    "checkpointRegistryConfigHash:releaseConfig.checkpointRegistryConfigHash",
):
    if marker not in pins:
        raise SystemExit(f"production Solidity pins gate: missing {marker}")

print("stage1058 preactivation dependency-order gate: PASS")
