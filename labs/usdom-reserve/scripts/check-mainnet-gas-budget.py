#!/usr/bin/env python3
"""Structural release gate for Ethereum code, calldata, gas and ETH budgets."""

from pathlib import Path
import json
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
NAMES = ("finalizedBurnVerifier", "checkpointVerifier", "checkpointRegistry", "reserve")
CONTRACTS = ("DOMFinalizedBurnRiscZeroVerifier", "DOMCheckpointRiscZeroVerifier",
             "DOMCheckpointRegistry", "USDOMProofReserve")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def audit(root: Path = ROOT) -> dict:
    sdk = (root / "sdk/mainnet-deployment-execution.mjs").read_text()
    deploy = (root / "scripts/execute-mainnet-deployment.sh").read_text()
    safe = (root / "sdk/safe-control-recovery-envelope.mjs").read_text()
    reserve = (root / "contracts/USDOMProofReserve.sol").read_text()
    publication = (root / "scripts/check-solidity-artifact-publication.py").read_text()
    match = re.search(r"const auditedCreateGas=\{finalizedBurnVerifier:([0-9_]+)n,checkpointVerifier:([0-9_]+)n,\s*checkpointRegistry:([0-9_]+)n,reserve:([0-9_]+)n\};", sdk)
    require(match is not None, "deployment gas ceilings are not canonical")
    ceilings = dict(zip(NAMES, (int(value.replace("_", "")) for value in match.groups())))
    sequence_match = re.search(r"MAINNET_DEPLOYMENT_SEQUENCE_MAX_GAS_LIMIT=([0-9_]+)n", sdk)
    require(sequence_match is not None, "deployment sequence gas cap is absent")
    sequence_cap = int(sequence_match.group(1).replace("_", ""))
    # Even a one-byte initcode incurs the transaction base, one EIP-3860 word
    # and calldata. Prove the four buffered policies can coexist before a real
    # release package supplies the larger exact initcodes.
    minimum_calldata_gas = 21_000 + 2 + 4
    minimum_sequence = sum(((ceiling + minimum_calldata_gas) * 125 + 99) // 100
                           for ceiling in ceilings.values())
    require(minimum_sequence <= sequence_cap,
            "aggregate deployment cap is mathematically below its component policies")
    require("bytes.length>49_152-8_192" in sdk, "runtime planner lacks EIP-3860 margin")
    require("(measuredMaximum*125n+99n)/100n" in sdk, "deployment planner lacks 25 percent buffer")
    for marker in ("EIP170_RUNTIME_LIMIT = 24_576", "EIP3860_INITCODE_LIMIT = 49_152",
                   "MIN_RUNTIME_MARGIN = 4_096", "MIN_INITCODE_MARGIN = 8_192"):
        require(marker in publication, f"publication gate lacks {marker}")
    for marker in ("gas_limit * 2 <= minimum_block_gas_limit",
                   "presign_gas_limit * 2 <= presign_minimum_block_gas_limit",
                   "for(let i=0;i<12;i++)fee=(fee*9n+7n)/8n",
                   "600000000000000000n", "check-mainnet-deployment-sequence-cost.mjs"):
        require(marker in deploy, f"deployment ceremony lacks {marker}")
    for marker in ("SAFE_RECOVERY_MAX_GAS_LIMIT=500_000n", "SAFE_RECOVERY_INCLUSION_BLOCKS=12",
                   "(maximumEstimate*125n+99n)/100n", "maximumCost=gasLimit*maxFeePerGas"):
        require(marker in safe, f"Safe envelope lacks {marker}")
    require("MAX_PRUNE_BATCH = 256" in reserve and "MAX_PROOF_BYTES = EVM_PROOF_BYTES" in reserve,
            "queue/prune or proof calldata bounds drifted")
    # bytes4 selector + ABI offset + length + 256 bytes32 candidates = 8,260 bytes.
    require(4 + 32 + 32 + 256 * 32 <= 16 * 1024, "worst-case prune calldata exceeds policy")

    diagnostics = []
    for logical, contract in zip(NAMES, CONTRACTS):
        artifact = root / "out" / f"{contract}.sol" / f"{contract}.json"
        if not artifact.is_file():
            diagnostics.append({"name": logical, "status": "refresh-required"})
            continue
        value = json.loads(artifact.read_text())
        creation = len(value["bytecode"]["object"].removeprefix("0x")) // 2
        runtime = len(value["deployedBytecode"]["object"].removeprefix("0x")) // 2
        require(runtime < 24_576 and creation < 49_152, f"stale {logical} artifact already exceeds EIP hard limit")
        require(ceilings[logical] >= runtime * 200,
                f"{logical} gas ceiling is below unavoidable runtime code-deposit gas")
        diagnostics.append({"name": logical, "status": "stale-diagnostic-only",
                            "creationBytes": creation, "runtimeBytes": runtime,
                            "runtimeHeadroomBytes": 24_576 - runtime})
    requirements = json.loads((root / "config/production-requirements.json").read_text())
    evidence_keys = ("production_finalized_burn_evm_verification_gas_measured",
                "production_checkpoint_outer_evm_verification_gas_measured",
                "production_queue_withdrawal_worst_case_gas_measured",
                "production_prune_expired_256_worst_case_gas_measured",
                "production_prune_discardable_256_worst_case_gas_measured",
                "production_safe_admin_overhead_gas_measured")
    for key in evidence_keys:
        require(key in requirements and isinstance(requirements[key], bool), f"missing gas evidence requirement {key}")
    return {"ceilings": ceilings, "artifacts": diagnostics,
            "freshMeasurementsRequired": True,
            "gasEvidenceComplete": all(requirements[key] for key in evidence_keys)}


def self_test() -> None:
    report = audit()
    require(report["freshMeasurementsRequired"] is True, "fresh rebuild requirement disappeared")
    require(report["ceilings"]["reserve"] >= 4_800_000, "reserve ceiling regression was accepted")


try:
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        print("PASS: mainnet gas budget checker self-test")
    elif sys.argv[1:]:
        raise ValueError("usage: check-mainnet-gas-budget.py [--self-test]")
    else:
        result = audit()
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as error:
    print(f"mainnet gas budget rejected: {error}", file=sys.stderr)
    raise SystemExit(1)
