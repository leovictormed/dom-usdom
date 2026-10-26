#!/usr/bin/env python3
"""Fail-closed structural gate for graceful/emergency lifecycle observations."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]

def require(path, *needles):
    text = (ROOT / path).read_text()
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{path}: missing {missing}")

require("labs/usdom-reserve/sdk/checkpoint-finalized-event-collector.mjs",
        "function gracefullyShutdown() view returns (bool)",
        "function latestIssuanceClosed() view returns (bool)",
        "function latestTotalIssued() view returns (uint128)",
        "function latestTotalBurned() view returns (uint128)",
        "gracefullyShutdown:Boolean(gracefullyShutdown[0])",
        "latestIssuanceClosed:Boolean(latestIssuanceClosed[0])")
require("labs/usdom-reserve/sdk/checkpoint-finalized-event-report.mjs",
        "checkpoint-finalized-event-observation-v2",
        "checkpoint-finalized-event-report-v2",
        "source.state.halted!==false",
        "source.state.halted&&source.state.gracefullyShutdown",
        "source.state.gracefullyShutdown&&(!source.state.latestIssuanceClosed||totalBurned!==totalIssued)")
require("labs/usdom-reserve/test/node/checkpoint-finalized-event-report.test.mjs",
        "distinguishes authenticated graceful closure from emergency halt",
        "gracefullyShutdown:true", "latestIssuanceClosed:true")
require("labs/usdom-reserve/test/node/checkpoint-finalized-event-collector.test.mjs",
        "latestIssuanceClosed:[false]", "latestTotalIssued:[100n]", "latestTotalBurned:[20n]")
print("stage1046 graceful shutdown readiness gate: ok")
