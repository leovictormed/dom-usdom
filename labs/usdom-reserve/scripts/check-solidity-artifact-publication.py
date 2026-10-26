#!/usr/bin/env python3
"""Reject stale compiler/EVM policy and legacy paths at publication boundaries."""

from __future__ import annotations

import json
import re
import stat
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SOLC = "0.8.37"
EXPECTED_COMPILER = "0.8.37+commit.f401782d"
EXPECTED_EVM = "cancun"
PRODUCTION = (
    "USDOMProofReserve",
    "DOMCheckpointRegistry",
    "DOMFinalizedBurnRiscZeroVerifier",
    "DOMCheckpointRiscZeroVerifier",
)
EXPECTED_SOURCES = {
    "USDOMProofReserve": {
        "contracts/IUSDTPolicy.sol", "contracts/USDOMProofReserve.sol",
        "vendor/openzeppelin-contracts-5.6.1/token/ERC20/IERC20.sol",
        "vendor/openzeppelin-contracts-5.6.1/token/ERC20/extensions/IERC20Metadata.sol",
        "vendor/openzeppelin-contracts-5.6.1/utils/ReentrancyGuard.sol",
        "vendor/openzeppelin-contracts-5.6.1/utils/StorageSlot.sol",
    },
    "DOMCheckpointRegistry": {"contracts/DOMCheckpointRegistry.sol"},
    "DOMFinalizedBurnRiscZeroVerifier": {
        "contracts/DOMFinalizedBurnRiscZeroVerifier.sol", "contracts/IRiscZeroVerifierV3.sol",
        "contracts/IUSDTPolicy.sol", "contracts/USDOMProofReserve.sol",
        "vendor/openzeppelin-contracts-5.6.1/token/ERC20/IERC20.sol",
        "vendor/openzeppelin-contracts-5.6.1/token/ERC20/extensions/IERC20Metadata.sol",
        "vendor/openzeppelin-contracts-5.6.1/utils/ReentrancyGuard.sol",
        "vendor/openzeppelin-contracts-5.6.1/utils/StorageSlot.sol",
    },
    "DOMCheckpointRiscZeroVerifier": {
        "contracts/DOMCheckpointRegistry.sol", "contracts/DOMCheckpointRiscZeroVerifier.sol",
        "contracts/IRiscZeroVerifierV3.sol",
    },
}
KECCAK_ROUNDS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
KECCAK_ROTATION = (0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14)
MASK64 = (1 << 64) - 1
EIP170_RUNTIME_LIMIT = 24_576
EIP3860_INITCODE_LIMIT = 49_152
MIN_RUNTIME_MARGIN = 4_096
MIN_INITCODE_MARGIN = 8_192
# All production constructors use fixed-size tuples. This deliberately reserves
# far more than their current ABI suffix so the raw artifact cannot approach
# EIP-3860 through later constructor-field growth without failing this gate.
MAX_CONSTRUCTOR_ARGUMENT_BYTES = 4_096


def fail(message: str) -> None:
    raise SystemExit(message)


def beneath_legacy(path: str) -> bool:
    parts = Path(path).parts
    return bool(parts) and (parts[0] == "results" or parts[0].startswith("results-stage"))


def keccak256(payload: bytes) -> str:
    state = [0] * 25
    padded = bytearray(payload)
    padded.append(0x01)
    padded.extend(b"\0" * ((135 - len(padded)) % 136))
    padded.append(0x80)
    for offset in range(0, len(padded), 136):
        block = padded[offset:offset + 136]
        for lane in range(17):
            state[lane] ^= int.from_bytes(block[lane * 8:lane * 8 + 8], "little")
        for constant in KECCAK_ROUNDS:
            columns = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
                       for x in range(5)]
            for x in range(5):
                delta = columns[(x - 1) % 5] ^ ((columns[(x + 1) % 5] << 1)
                                                | (columns[(x + 1) % 5] >> 63)) & MASK64
                for y in range(5):
                    state[x + 5 * y] ^= delta
            rotated = [0] * 25
            for x in range(5):
                for y in range(5):
                    lane = state[x + 5 * y]
                    rotation = KECCAK_ROTATION[x + 5 * y]
                    lane = ((lane << rotation) | (lane >> ((64 - rotation) % 64))) & MASK64
                    rotated[y + 5 * ((2 * x + 3 * y) % 5)] = lane
            for x in range(5):
                for y in range(5):
                    state[x + 5 * y] = rotated[x + 5 * y] ^ (
                        (~rotated[(x + 1) % 5 + 5 * y]) & rotated[(x + 2) % 5 + 5 * y])
            state[0] ^= constant
    digest = b"".join(lane.to_bytes(8, "little") for lane in state[:4])
    return "0x" + digest.hex()


def immutable_ids(value: object) -> set[str]:
    result: set[str] = set()
    if isinstance(value, list):
        for child in value:
            result.update(immutable_ids(child))
    elif isinstance(value, dict):
        if value.get("nodeType") == "VariableDeclaration" and value.get("mutability") == "immutable":
            result.add(str(value.get("id")))
        for child in value.values():
            result.update(immutable_ids(child))
    return result


def artifact_policy(root: Path, path: Path, name: str) -> None:
    try:
        artifact = json.loads(path.read_bytes())
        metadata = artifact["metadata"]
        settings = metadata["settings"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        fail(f"malformed publishable {name} artifact: {error}")
    if metadata.get("compiler", {}).get("version") != EXPECTED_COMPILER:
        fail(f"stale compiler in publishable {name} artifact")
    if settings.get("evmVersion") != EXPECTED_EVM:
        fail(f"stale EVM in publishable {name} artifact")
    if settings.get("optimizer") != {"enabled": True, "runs": 1}:
        fail(f"unexpected optimizer in publishable {name} artifact")
    if settings.get("metadata", {}).get("bytecodeHash") != "none" or settings.get("viaIR") is not True:
        fail(f"unexpected metadata/via-IR policy in publishable {name} artifact")
    target = {f"contracts/{name}.sol": name}
    if settings.get("compilationTarget") != target:
        fail(f"ambiguous compilation target in publishable {name} artifact")
    if settings.get("libraries") != {}:
        fail(f"linked metadata library in publishable {name} artifact")
    if artifact.get("bytecode", {}).get("linkReferences") != {} or artifact.get("deployedBytecode", {}).get("linkReferences") != {}:
        fail(f"linked bytecode library in publishable {name} artifact")
    creation = artifact.get("bytecode", {}).get("object")
    runtime = artifact.get("deployedBytecode", {}).get("object")
    if (not isinstance(creation, str) or not re.fullmatch(r"(?:0x)?[0-9a-fA-F]*", creation)
            or len(creation.removeprefix("0x")) % 2):
        fail(f"malformed creation bytecode in publishable {name} artifact")
    if (not isinstance(runtime, str) or not re.fullmatch(r"(?:0x)?[0-9a-fA-F]*", runtime)
            or len(runtime.removeprefix("0x")) % 2):
        fail(f"malformed runtime in publishable {name} artifact")
    creation_size = len(creation.removeprefix("0x")) // 2
    runtime_size = len(runtime.removeprefix("0x")) // 2
    if runtime_size > EIP170_RUNTIME_LIMIT - MIN_RUNTIME_MARGIN:
        fail(f"publishable {name} runtime lacks the required EIP-170 safety margin")
    if creation_size + MAX_CONSTRUCTOR_ARGUMENT_BYTES > EIP3860_INITCODE_LIMIT - MIN_INITCODE_MARGIN:
        fail(f"publishable {name} initcode lacks the required EIP-3860 safety margin")

    sources = metadata.get("sources")
    if not isinstance(sources, dict) or set(sources) != EXPECTED_SOURCES[name]:
        fail(f"unexpected source set in publishable {name} artifact")
    for source_name, source_metadata in sources.items():
        source_path = root / source_name
        try:
            mode = source_path.lstat().st_mode
            payload = source_path.read_bytes()
        except OSError as error:
            fail(f"publishable {name} source cannot be read: {error}")
        if not stat.S_ISREG(mode) or source_path.is_symlink():
            fail(f"publishable {name} source is not a direct regular file")
        if keccak256(payload) != source_metadata.get("keccak256"):
            fail(f"source hash mismatch in publishable {name} artifact: {source_name}")

    references = artifact.get("deployedBytecode", {}).get("immutableReferences")
    expected_ids = immutable_ids(artifact.get("ast"))
    if not isinstance(references, dict) or set(references) != expected_ids:
        fail(f"immutable reference/declaration mismatch in publishable {name} artifact")
    runtime_size = len(runtime.removeprefix("0x")) // 2
    occupied: set[int] = set()
    for reference_id, locations in references.items():
        if not isinstance(locations, list) or not locations:
            fail(f"empty immutable reference {reference_id} in publishable {name} artifact")
        for location in locations:
            if set(location) != {"start", "length"} or location["length"] != 32:
                fail(f"malformed immutable reference {reference_id} in publishable {name} artifact")
            start = location["start"]
            if not isinstance(start, int) or start < 0 or start + 32 > runtime_size:
                fail(f"out-of-bounds immutable reference {reference_id} in publishable {name} artifact")
            interval = set(range(start, start + 32))
            if occupied & interval:
                fail(f"overlapping immutable references in publishable {name} artifact")
            occupied.update(interval)


def check(root: Path = ROOT) -> None:
    foundry = tomllib.loads((root / "foundry.toml").read_text())
    profile = foundry.get("profile", {}).get("default", {})
    if profile.get("solc_version") != EXPECTED_SOLC or profile.get("evm_version") != EXPECTED_EVM:
        fail("Foundry compiler/EVM policy is stale")
    if (profile.get("optimizer"), profile.get("optimizer_runs"), profile.get("via_ir"),
            profile.get("bytecode_hash")) != (True, 1, True, "none"):
        fail("Foundry optimizer/metadata policy is stale")

    for name in PRODUCTION:
        source = (root / "contracts" / f"{name}.sol").read_text()
        if not re.search(rf"(?m)^pragma solidity {re.escape(EXPECTED_SOLC)};$", source):
            fail(f"{name} does not use the exact production compiler pragma")
        artifact = root / "out" / f"{name}.sol" / f"{name}.json"
        if artifact.exists():
            matches = sorted((root / "out").rglob(f"{name}.json"))
            if matches != [artifact]:
                fail(f"shadow or duplicate publishable artifact for {name}")
            artifact_policy(root, artifact, name)

    runtime = (root / "sdk" / "compiled-runtime.mjs").read_text()
    if f"const expectedCompiler='{EXPECTED_COMPILER}';" not in runtime or f"evmVersion:'{EXPECTED_EVM}'" not in runtime:
        fail("compiled-runtime artifact policy is stale")

    ignored = (root / ".gitignore").read_text().splitlines()
    if "results/" not in ignored:
        fail("legacy results are not excluded from publication")
    manifest_source = (root / "scripts" / "source-manifest.py").read_text()
    if 'top == "results"' not in manifest_source or 'top.startswith("results-stage")' not in manifest_source:
        fail("source manifest does not exclude legacy result trees")
    for manifest_name in ("MANIFEST.sha256", "PROOF-PROGRAM-MANIFEST.sha256"):
        manifest = (root / manifest_name).read_text()
        for line in manifest.splitlines():
            fields = line.split("  ", 1)
            if len(fields) == 2 and beneath_legacy(fields[1]):
                fail(f"{manifest_name} publishes legacy result path {fields[1]}")

    evidence = json.loads((root / "config" / "mainnet-release-evidence.unconfigured.json").read_text())
    canonical_artifacts = {
        "reserveArtifact": "out/USDOMProofReserve.sol/USDOMProofReserve.json",
        "checkpointRegistryArtifact": "out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json",
        "verifierArtifact": "out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json",
        "checkpointVerifierArtifact": "out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json",
    }
    for key, value in evidence.items():
        if isinstance(value, dict) and isinstance(value.get("path"), str) and beneath_legacy(value["path"]):
            fail(f"release evidence {key} points into legacy results")
        if key in canonical_artifacts and value is not None:
            if not isinstance(value, dict) or value.get("path") != canonical_artifacts[key]:
                fail(f"release evidence {key} does not select its sole canonical artifact")
    if (root / "results" / "build-identity.json").exists():
        fail("orphan prototype build identity is not quarantined")


def self_test() -> None:
    assert keccak256(b"") == "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for item in ("contracts", "sdk", "scripts", "config", "results", "out"):
            (root / item).mkdir()
        (root / "foundry.toml").write_text('[profile.default]\nsolc_version="0.8.37"\nevm_version="cancun"\noptimizer=true\noptimizer_runs=1\nvia_ir=true\nbytecode_hash="none"\n')
        (root / ".gitignore").write_text("results/\n")
        (root / "sdk" / "compiled-runtime.mjs").write_text("const expectedCompiler='0.8.37+commit.f401782d';\nconst x={evmVersion:'cancun'};\n")
        (root / "scripts" / "source-manifest.py").write_text('top == "results"\ntop.startswith("results-stage")\n')
        (root / "config" / "mainnet-release-evidence.unconfigured.json").write_text("{}")
        (root / "MANIFEST.sha256").write_text("")
        (root / "PROOF-PROGRAM-MANIFEST.sha256").write_text("")
        for name in PRODUCTION:
            (root / "contracts" / f"{name}.sol").write_text("// SPDX-License-Identifier: MIT\npragma solidity 0.8.37;\n")
        source_metadata = {}
        for source_name in EXPECTED_SOURCES["USDOMProofReserve"]:
            source_path = root / source_name
            source_path.parent.mkdir(parents=True, exist_ok=True)
            if not source_path.exists():
                source_path.write_text("// SPDX-License-Identifier: MIT\npragma solidity 0.8.37;\n")
            source_metadata[source_name] = {"keccak256": keccak256(source_path.read_bytes())}
        artifact_path = root / "out" / "USDOMProofReserve.sol" / "USDOMProofReserve.json"
        artifact_path.parent.mkdir()
        artifact = {
            "ast": {"nodeType": "VariableDeclaration", "mutability": "immutable", "id": 1},
            "bytecode": {"object": "00" * 64, "linkReferences": {}},
            "deployedBytecode": {"object": "00" * 32, "linkReferences": {},
                                 "immutableReferences": {"1": [{"start": 0, "length": 32}]}},
            "metadata": {"compiler": {"version": EXPECTED_COMPILER}, "sources": source_metadata,
                         "settings": {"evmVersion": EXPECTED_EVM,
                                      "optimizer": {"enabled": True, "runs": 1},
                                      "metadata": {"bytecodeHash": "none"}, "viaIR": True,
                                      "libraries": {}, "compilationTarget": {
                                          "contracts/USDOMProofReserve.sol": "USDOMProofReserve"}}}}
        artifact_path.write_text(json.dumps(artifact))
        check(root)
        artifact["metadata"]["compiler"]["version"] = "0.8.24+commit.e11b9ed9"
        artifact_path.write_text(json.dumps(artifact))
        try:
            check(root)
        except SystemExit as error:
            assert "stale compiler" in str(error)
        else:
            raise AssertionError("stale artifact compiler was accepted")
        artifact["metadata"]["compiler"]["version"] = EXPECTED_COMPILER
        artifact_path.write_text(json.dumps(artifact))
        shadow = root / "out" / "shadow.sol" / "USDOMProofReserve.json"
        shadow.parent.mkdir()
        shadow.write_text(json.dumps(artifact))
        try:
            check(root)
        except SystemExit as error:
            assert "shadow or duplicate" in str(error)
        else:
            raise AssertionError("duplicate artifact was accepted")
        shadow.unlink()
        reserve_source = artifact["metadata"]["sources"]["contracts/USDOMProofReserve.sol"]
        valid_source_hash = reserve_source["keccak256"]
        reserve_source["keccak256"] = "0x" + "00" * 32
        artifact_path.write_text(json.dumps(artifact))
        try:
            check(root)
        except SystemExit as error:
            assert "source hash mismatch" in str(error)
        else:
            raise AssertionError("stale source hash was accepted")
        reserve_source["keccak256"] = valid_source_hash
        artifact["bytecode"]["linkReferences"] = {"x.sol": {"L": [{"start": 0, "length": 20}]}}
        artifact_path.write_text(json.dumps(artifact))
        try:
            check(root)
        except SystemExit as error:
            assert "linked bytecode library" in str(error)
        else:
            raise AssertionError("linked artifact was accepted")
        artifact["bytecode"]["linkReferences"] = {}
        artifact["deployedBytecode"]["immutableReferences"]["1"][0]["length"] = 31
        artifact_path.write_text(json.dumps(artifact))
        try:
            check(root)
        except SystemExit as error:
            assert "malformed immutable reference" in str(error)
        else:
            raise AssertionError("malformed immutable layout was accepted")
        artifact["deployedBytecode"]["immutableReferences"]["1"][0]["length"] = 32
        artifact_path.write_text(json.dumps(artifact))
        valid_runtime = artifact["deployedBytecode"]["object"]
        artifact["deployedBytecode"]["object"] = "00" * (EIP170_RUNTIME_LIMIT - MIN_RUNTIME_MARGIN + 1)
        artifact_path.write_text(json.dumps(artifact))
        try:
            check(root)
        except SystemExit as error:
            assert "EIP-170 safety margin" in str(error)
        else:
            raise AssertionError("near-limit runtime was accepted")
        artifact["deployedBytecode"]["object"] = valid_runtime
        valid_creation = artifact["bytecode"]["object"]
        artifact["bytecode"]["object"] = "00" * (
            EIP3860_INITCODE_LIMIT - MIN_INITCODE_MARGIN - MAX_CONSTRUCTOR_ARGUMENT_BYTES + 1)
        artifact_path.write_text(json.dumps(artifact))
        try:
            check(root)
        except SystemExit as error:
            assert "EIP-3860 safety margin" in str(error)
        else:
            raise AssertionError("near-limit initcode was accepted")
        artifact["bytecode"]["object"] = valid_creation
        artifact_path.write_text(json.dumps(artifact))
        original = (root / "foundry.toml").read_text()
        (root / "foundry.toml").write_text(original.replace("cancun", "shanghai"))
        try:
            check(root)
        except SystemExit as error:
            assert "compiler/EVM policy is stale" in str(error)
        else:
            raise AssertionError("stale EVM was accepted")
        (root / "foundry.toml").write_text(original)
        (root / "config" / "mainnet-release-evidence.unconfigured.json").write_text(
            '{"reserveArtifact":{"path":"results/build-identity.json"}}')
        try:
            check(root)
        except SystemExit as error:
            assert "points into legacy results" in str(error)
        else:
            raise AssertionError("legacy release evidence was accepted")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        print("PASS: Solidity artifact publication checker self-test")
    elif sys.argv[1:]:
        fail("usage: check-solidity-artifact-publication.py [--self-test]")
    else:
        check()
        print("PASS: publishable Solidity artifacts and manifests use current compiler/EVM policy")
