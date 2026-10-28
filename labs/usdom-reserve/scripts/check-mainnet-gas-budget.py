#!/usr/bin/env python3
"""Structural release gate for Ethereum code, calldata, gas and ETH budgets."""

from pathlib import Path, PurePosixPath
import errno
import json
import os
import re
import stat
import sys
import tempfile
import hashlib

ROOT = Path(__file__).resolve().parents[1]
NAMES = ("finalizedBurnVerifier", "checkpointVerifier", "checkpointRegistry", "reserve")
CONTRACTS = ("DOMFinalizedBurnRiscZeroVerifier", "DOMCheckpointRiscZeroVerifier",
             "DOMCheckpointRegistry", "USDOMProofReserve")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def direct_bytes(root: Path, name: str, maximum: int) -> bytes:
    relative = PurePosixPath(name)
    require(bool(name) and "\\" not in name and not relative.is_absolute()
            and relative.as_posix() == name and all(part not in {"", ".", ".."} for part in relative.parts),
            f"invalid gas-budget input path: {name}")
    nofollow = getattr(os, "O_NOFOLLOW", 0); cloexec = getattr(os, "O_CLOEXEC", 0)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow | cloexec
    opened = []; descriptor = None
    try:
        parent = os.open(root, flags); opened.append(parent)
        for component in relative.parts[:-1]:
            parent = os.open(component, flags, dir_fd=parent); opened.append(parent)
        descriptor = os.open(relative.parts[-1], os.O_RDONLY | nofollow | cloexec, dir_fd=parent)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
                and 0 < before.st_size <= maximum, f"gas-budget input file policy mismatch: {name}")
        payload = bytearray()
        while len(payload) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(payload)))
            if not chunk: break
            payload.extend(chunk)
        after = os.fstat(descriptor); path_after = os.stat(relative.parts[-1], dir_fd=parent, follow_symlinks=False)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(len(payload) == before.st_size and identity(before) == identity(after)
                and (path_after.st_dev, path_after.st_ino) == (before.st_dev, before.st_ino),
                f"gas-budget input changed while read: {name}")
        return bytes(payload)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.EMLINK, errno.ENOTDIR}:
            raise ValueError(f"gas-budget input path is indirect: {name}") from error
        raise
    finally:
        if descriptor is not None: os.close(descriptor)
        for item in reversed(opened): os.close(item)


def direct_text(root: Path, name: str, maximum: int) -> str:
    return direct_bytes(root, name, maximum).decode("utf-8")


def strict_json(root: Path, name: str, maximum: int) -> object:
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, f"{name} contains duplicate JSON key: {key}")
            value[key] = item
        return value
    return json.loads(direct_text(root, name, maximum), object_pairs_hook=pairs)


def canonical_artifact_fingerprint(value: dict) -> str:
    require(isinstance(value, dict) and isinstance(value.get("abi"), list),
            "Solidity artifact lacks ABI")
    creation = value.get("bytecode", {}).get("object")
    runtime = value.get("deployedBytecode", {}).get("object")
    for item in (creation, runtime):
        require(isinstance(item, str) and re.fullmatch(r"0x[0-9a-fA-F]+", item) is not None
                and len(item) % 2 == 0, "Solidity artifact lacks canonical executable content")
    # Match JSON.stringify used by solidityArtifactExecutableFingerprint: compact
    # UTF-8 JSON, insertion order fixed here, non-ASCII emitted literally.
    canonical = json.dumps({"abi": value["abi"], "creationBytecode": creation.lower(),
                            "runtimeBytecode": runtime.lower()},
                           ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def validate_local_evidence(root: Path, ceilings: dict, sequence_cap: int, artifacts: dict) -> dict:
    evidence = strict_json(root, "docs/LOCAL-DEPLOYMENT-GAS-MEASUREMENT-2026-10-26.json",
                           4 * 1024 * 1024)
    require(set(evidence) == {"schema", "network", "node", "anvil", "runs", "supportArtifacts",
                              "contracts", "aggregate", "limitations"},
            "local deployment gas evidence schema drifted")
    require(evidence["schema"] == "usdom-local-deployment-gas-measurement/v2"
            and evidence["network"] == "anvil-local-chain-31337" and evidence["runs"] == 2,
            "local deployment gas evidence identity is invalid")
    require(set(evidence["contracts"]) == set(NAMES), "local gas contract set is incomplete")
    measured = planned = 0
    diagnostics = []
    for logical in NAMES:
        observed = evidence["contracts"][logical]; artifact = artifacts[logical]
        require(observed.get("artifactPath") == artifact["path"],
                f"local {logical} artifact path drifted")
        require(observed.get("artifactExecutableSha256") == artifact["fingerprint"],
                f"local {logical} executable artifact is stale")
        require(observed.get("runtimeBytes") == artifact["runtimeBytes"],
                f"local {logical} runtime size is stale")
        require(isinstance(observed.get("initcodeBytes"), int)
                and observed["initcodeBytes"] >= artifact["creationBytes"],
                f"local {logical} initcode size is invalid")
        values = {}
        for field in ("gasUsed", "auditedCreateGasCeiling", "measuredMargin", "plannedGasLimit"):
            raw = observed.get(field)
            require(isinstance(raw, str) and re.fullmatch(r"(?:0|[1-9][0-9]*)", raw) is not None,
                    f"local {logical} {field} is not canonical")
            values[field] = int(raw)
        require(values["gasUsed"] > 0 and values["auditedCreateGasCeiling"] == ceilings[logical]
                and values["gasUsed"] + values["measuredMargin"] == ceilings[logical]
                and values["measuredMargin"] >= 0 and values["plannedGasLimit"] > values["gasUsed"],
                f"local {logical} gas accounting is inconsistent")
        measured += values["gasUsed"]; planned += values["plannedGasLimit"]
        diagnostics.append({"name": logical, "status": "local-reproducible-current",
                            "creationBytes": artifact["creationBytes"],
                            "runtimeBytes": artifact["runtimeBytes"],
                            "runtimeHeadroomBytes": 24_576 - artifact["runtimeBytes"],
                            "localCreateGasUsed": values["gasUsed"],
                            "localCreateGasMargin": values["measuredMargin"]})
    aggregate = evidence["aggregate"]
    require(str(measured) == aggregate.get("measuredGas") and str(planned) == aggregate.get("plannedGasLimit")
            and str(sequence_cap) == aggregate.get("sequenceGasLimit")
            and str(sequence_cap - planned) == aggregate.get("policyMargin") and planned <= sequence_cap,
            "local deployment gas aggregate is inconsistent")
    require(evidence["limitations"] == ["local chain bypasses chain-id-1 production-pin branches",
            "support contracts are deterministic test doubles; no mainnet RPC or external deployment occurred"],
            "local evidence limitations were weakened")
    return {"diagnostics": diagnostics,
            "sha256": hashlib.sha256(direct_bytes(root,
                "docs/LOCAL-DEPLOYMENT-GAS-MEASUREMENT-2026-10-26.json", 4 * 1024 * 1024)).hexdigest()}


def audit(root: Path = ROOT) -> dict:
    sdk = direct_text(root, "sdk/mainnet-deployment-execution.mjs", 4 * 1024 * 1024)
    deploy = direct_text(root, "scripts/execute-mainnet-deployment.sh", 4 * 1024 * 1024)
    safe = direct_text(root, "sdk/safe-control-recovery-envelope.mjs", 4 * 1024 * 1024)
    reserve = direct_text(root, "contracts/USDOMProofReserve.sol", 4 * 1024 * 1024)
    publication = direct_text(root, "scripts/check-solidity-artifact-publication.py", 4 * 1024 * 1024)
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

    artifact_inputs = {}
    for logical, contract in zip(NAMES, CONTRACTS):
        artifact = root / "out" / f"{contract}.sol" / f"{contract}.json"
        if not artifact.is_file():
            raise ValueError(f"current {logical} artifact is absent; local gas evidence cannot be authenticated")
        value = strict_json(root, artifact.relative_to(root).as_posix(), 8 * 1024 * 1024)
        creation = len(value["bytecode"]["object"].removeprefix("0x")) // 2
        runtime = len(value["deployedBytecode"]["object"].removeprefix("0x")) // 2
        require(runtime < 24_576 and creation < 49_152, f"stale {logical} artifact already exceeds EIP hard limit")
        require(ceilings[logical] >= runtime * 200,
                f"{logical} gas ceiling is below unavoidable runtime code-deposit gas")
        artifact_inputs[logical] = {"path": artifact.relative_to(root).as_posix(),
            "fingerprint": canonical_artifact_fingerprint(value), "creationBytes": creation,
            "runtimeBytes": runtime}
    local = validate_local_evidence(root, ceilings, sequence_cap, artifact_inputs)
    requirements = strict_json(root, "config/production-requirements.json", 4 * 1024 * 1024)
    require(isinstance(requirements, dict), "production requirements must be an object")
    evidence_keys = ("production_finalized_burn_evm_verification_gas_measured",
                "production_checkpoint_outer_evm_verification_gas_measured",
                "production_queue_withdrawal_worst_case_gas_measured",
                "production_prune_expired_256_worst_case_gas_measured",
                "production_prune_discardable_256_worst_case_gas_measured",
                "production_safe_admin_overhead_gas_measured")
    for key in evidence_keys:
        require(key in requirements and isinstance(requirements[key], bool), f"missing gas evidence requirement {key}")
    production_complete = all(requirements[key] for key in evidence_keys)
    return {"ceilings": ceilings, "artifacts": local["diagnostics"],
            "localReproducibleEvidenceCurrent": True,
            "localEvidenceSha256": local["sha256"],
            "productionRpcMeasurementsRequired": not production_complete,
            "freshMeasurementsRequired": not production_complete,
            "gasEvidenceComplete": production_complete}


def self_test() -> None:
    report = audit()
    require(report["localReproducibleEvidenceCurrent"] is True,
            "current local reproducible evidence disappeared")
    require(report["freshMeasurementsRequired"] is True, "fresh rebuild requirement disappeared")
    require(report["productionRpcMeasurementsRequired"] is True,
            "production RPC requirement disappeared")
    require(report["ceilings"]["reserve"] >= 4_800_000, "reserve ceiling regression was accepted")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); (root / "duplicate.json").write_text('{"x":1,"x":2}')
        try: strict_json(root, "duplicate.json", 1024)
        except ValueError as error: require("duplicate JSON key" in str(error), "wrong duplicate-key diagnosis")
        else: raise ValueError("duplicate gas-budget JSON authority was accepted")
        (root / "source").write_text("x"); os.link(root / "source", root / "hard")
        try: direct_bytes(root, "hard", 1024)
        except ValueError as error: require("policy mismatch" in str(error), "wrong hardlink diagnosis")
        else: raise ValueError("hard-linked gas-budget input was accepted")
    # Exercise the semantic validator independently of the checked-in evidence:
    # an executable fingerprint, aggregate or limitation edit must fail closed.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); (root / "docs").mkdir()
        ceilings = {name: 1000 for name in NAMES}; sequence = 8000
        artifacts = {name: {"path": f"out/{name}.json", "fingerprint": "a" * 64,
                            "creationBytes": 10, "runtimeBytes": 8} for name in NAMES}
        contracts = {name: {"artifactPath": f"out/{name}.json",
            "artifactExecutableSha256": "a" * 64, "initcodeSha256": "b" * 64,
            "initcodeBytes": 12, "runtimeCodeHash": "0x" + "c" * 64, "runtimeBytes": 8,
            "gasUsed": "900", "auditedCreateGasCeiling": "1000", "measuredMargin": "100",
            "plannedGasLimit": "1200"} for name in NAMES}
        base = {"schema": "usdom-local-deployment-gas-measurement/v2",
            "network": "anvil-local-chain-31337", "node": {}, "anvil": {}, "runs": 2,
            "supportArtifacts": {}, "contracts": contracts,
            "aggregate": {"measuredGas": "3600", "plannedGasLimit": "4800",
                          "sequenceGasLimit": "8000", "policyMargin": "3200"},
            "limitations": ["local chain bypasses chain-id-1 production-pin branches",
                "support contracts are deterministic test doubles; no mainnet RPC or external deployment occurred"]}
        target = root / "docs" / "LOCAL-DEPLOYMENT-GAS-MEASUREMENT-2026-10-26.json"
        target.write_text(json.dumps(base))
        validate_local_evidence(root, ceilings, sequence, artifacts)
        for mutate, diagnosis in [
            (lambda value: value["contracts"][NAMES[0]].update(
                artifactExecutableSha256="d" * 64), "artifact is stale"),
            (lambda value: value["aggregate"].update(measuredGas="3601"), "aggregate"),
            (lambda value: value["limitations"].clear(), "limitations")]:
            changed = json.loads(json.dumps(base)); mutate(changed); target.write_text(json.dumps(changed))
            try: validate_local_evidence(root, ceilings, sequence, artifacts)
            except ValueError as error: require(diagnosis in str(error), "wrong local evidence diagnosis")
            else: raise ValueError("tampered local gas evidence was accepted")


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
