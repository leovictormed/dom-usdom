#!/usr/bin/env python3
"""Fail closed if reserve tooling drops the immutable checkpoint Registry identity."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def require(path: str, needles: tuple[str, ...]) -> None:
    text = (ROOT / path).read_text(encoding="utf-8")
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"{path}: missing required Registry binding: {needle}")


FIELDS = (
    "checkpointRegistry",
    "checkpointRegistryRuntimeCodeHash",
    "checkpointRegistryConfigHash",
)

require("labs/usdom-reserve/sdk/configuration.mjs", FIELDS)
require("labs/usdom-reserve/sdk/compiled-runtime.mjs", FIELDS)
require("labs/usdom-reserve/sdk/mainnet-readiness.mjs", FIELDS)
require("labs/usdom-reserve/sdk/finalized-burn-submission.mjs", FIELDS)
require("labs/usdom-reserve/sdk/production-release-core.mjs", FIELDS)
require(
    "labs/usdom-reserve/sdk/compiled-runtime.mjs",
    ("tuple(address token,address verifier,address checkpointRegistry,bytes32 domDomain",),
)
require(
    "labs/usdom-reserve/sdk/production-release-core.mjs",
    (
        "const registry=checkpointRegistryConfigHash({",
        "const reserve=proofReserveDeploymentConfigHash({",
        "result.checkpointRegistryRuntimeCodeHash===null && deferReserveArtifact",
    ),
)
require("labs/usdom-reserve/test/node/configuration.test.mjs", FIELDS)
require("labs/usdom-reserve/test/node/compiled-runtime.test.mjs", FIELDS)
require("labs/usdom-reserve/test/node/finalized-burn-submission.test.mjs", FIELDS)

print("stage1056 reserve/Registry immutable identity gate: PASS")
