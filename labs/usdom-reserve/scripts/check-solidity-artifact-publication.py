#!/usr/bin/env python3
"""Reject stale compiler/EVM policy and legacy paths at publication boundaries."""

from __future__ import annotations

import errno
import json
import os
import re
import stat
import sys
import tempfile
import tomllib
from pathlib import Path, PurePosixPath

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
        "contracts/IDOMFinalizedBurnVerifier.sol", "contracts/IUSDTPolicy.sol",
        "contracts/USDOMProofReserve.sol",
        "vendor/openzeppelin-contracts-5.6.1/token/ERC20/IERC20.sol",
        "vendor/openzeppelin-contracts-5.6.1/token/ERC20/extensions/IERC20Metadata.sol",
        "vendor/openzeppelin-contracts-5.6.1/utils/ReentrancyGuard.sol",
        "vendor/openzeppelin-contracts-5.6.1/utils/StorageSlot.sol",
    },
    "DOMCheckpointRegistry": {
        "contracts/DOMCheckpointRegistry.sol", "contracts/IDOMCheckpointVerifier.sol",
    },
    "DOMFinalizedBurnRiscZeroVerifier": {
        "contracts/DOMFinalizedBurnRiscZeroVerifier.sol", "contracts/IDOMFinalizedBurnVerifier.sol",
        "contracts/IRiscZeroVerifierV3.sol",
    },
    "DOMCheckpointRiscZeroVerifier": {
        "contracts/DOMCheckpointRiscZeroVerifier.sol", "contracts/IDOMCheckpointVerifier.sol",
        "contracts/IRiscZeroVerifierV3.sol",
    },
}
IMPORT = re.compile(r'(?m)^\s*import\s+(?:[^;]*?\s+from\s+)?["\']([^"\']+)["\']\s*;')
DECLARATION = re.compile(r'(?m)^\s*(?:abstract\s+)?(?:contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)\b')
FORBIDDEN_GRAPH_EDGES = {
    "USDOMProofReserve": {
        "contracts/DOMCheckpointRegistry.sol", "contracts/DOMFinalizedBurnRiscZeroVerifier.sol",
    },
    "DOMCheckpointRegistry": {
        "contracts/USDOMProofReserve.sol", "contracts/DOMCheckpointRiscZeroVerifier.sol",
    },
    "DOMFinalizedBurnRiscZeroVerifier": {"contracts/USDOMProofReserve.sol"},
    "DOMCheckpointRiscZeroVerifier": {"contracts/DOMCheckpointRegistry.sol"},
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


def direct_bytes(root: Path, name: str, maximum: int) -> bytes:
    relative = PurePosixPath(name)
    if (not name or "\\" in name or relative.is_absolute() or relative.as_posix() != name
            or any(part in {"", ".", ".."} for part in relative.parts)):
        fail(f"invalid publication path: {name}")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow | cloexec
    opened: list[int] = []
    descriptor = None
    try:
        parent = os.open(root, directory_flags)
        opened.append(parent)
        for component in relative.parts[:-1]:
            parent = os.open(component, directory_flags, dir_fd=parent)
            opened.append(parent)
        descriptor = os.open(relative.parts[-1], os.O_RDONLY | nofollow | cloexec, dir_fd=parent)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.geteuid() or before.st_size < 1 or before.st_size > maximum):
            fail(f"publication file policy mismatch: {name}")
        payload = bytearray()
        while len(payload) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        path_after = os.stat(relative.parts[-1], dir_fd=parent, follow_symlinks=False)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        if (len(payload) != before.st_size or identity(before) != identity(after)
                or (path_after.st_dev, path_after.st_ino) != (before.st_dev, before.st_ino)):
            fail(f"publication file changed while read: {name}")
        return bytes(payload)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.EMLINK, errno.ENOTDIR}:
            fail(f"publication path is indirect: {name}")
        fail(f"publication file cannot be opened directly: {name}: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for item in reversed(opened):
            os.close(item)


def strict_json(payload: bytes, label: str) -> object:
    try:
        text = payload.decode("utf-8")
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    fail(f"{label} contains duplicate JSON key: {key}")
                result[key] = value
            return result
        return json.loads(text, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not strict UTF-8 JSON: {error}")


def direct_text(root: Path, name: str, maximum: int, label: str) -> str:
    try:
        return direct_bytes(root, name, maximum).decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"{label} is not UTF-8: {error}")


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


def resolve_import(importer: str, imported: str) -> str:
    """Resolve only the publication compiler's single reviewed remapping."""
    if imported.startswith("@openzeppelin/contracts/"):
        resolved = "vendor/openzeppelin-contracts-5.6.1/" + imported.removeprefix(
            "@openzeppelin/contracts/")
    elif imported.startswith("./") or imported.startswith("../"):
        resolved = str(PurePosixPath(importer).parent.joinpath(imported))
    else:
        fail(f"unsupported publishable Solidity import: {importer} -> {imported}")
    parts: list[str] = []
    for part in PurePosixPath(resolved).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                fail(f"publishable Solidity import escapes project: {importer} -> {imported}")
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def source_graph_policy(name: str, target: str, payloads: dict[str, bytes]) -> None:
    """Prove the compiler metadata is the exact acyclic import closure.

    This closes two distinct release hazards: an artifact cannot smuggle an
    unreferenced source into its declared authority set, and a verifier adapter
    cannot acquire a dependency on the downstream contract that embeds the
    adapter's own runtime/configuration hashes.
    """
    graph: dict[str, set[str]] = {}
    declarations: dict[str, str] = {}
    for source_name, payload in payloads.items():
        try:
            source = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            fail(f"publishable Solidity source is not UTF-8: {source_name}: {error}")
        edges = {resolve_import(source_name, item) for item in IMPORT.findall(source)}
        missing = edges - payloads.keys()
        if missing:
            fail(f"metadata omits imported source in {name}: {source_name} -> {sorted(missing)[0]}")
        graph[source_name] = edges
        for declaration in DECLARATION.findall(source):
            previous = declarations.get(declaration)
            if previous is not None:
                fail(f"duplicate Solidity declaration in {name}: {declaration} ({previous}, {source_name})")
            declarations[declaration] = source_name

    visiting: set[str] = set()
    visited: set[str] = set()
    reachable: set[str] = set()

    def visit(source_name: str) -> None:
        if source_name in visiting:
            fail(f"circular Solidity import in {name}: {source_name}")
        if source_name in visited:
            reachable.add(source_name)
            return
        visiting.add(source_name)
        reachable.add(source_name)
        for dependency in sorted(graph[source_name]):
            visit(dependency)
        visiting.remove(source_name)
        visited.add(source_name)

    visit(target)
    orphaned = payloads.keys() - reachable
    if orphaned:
        fail(f"unreachable metadata source in {name}: {sorted(orphaned)[0]}")
    forbidden = reachable & FORBIDDEN_GRAPH_EDGES[name]
    if forbidden:
        fail(f"self-referential Solidity source dependency in {name}: {sorted(forbidden)[0]}")

    target_source = payloads[target].decode("utf-8")
    forbidden_own_pins = {
        "USDOMProofReserve": ("PRODUCTION_RESERVE_RUNTIME_CODE_HASH", "PRODUCTION_RESERVE_INITCODE_HASH",
                               "PRODUCTION_RESERVE_CONFIG_HASH"),
        "DOMCheckpointRegistry": ("PRODUCTION_CHECKPOINT_RUNTIME_CODE_HASH",
                                   "PRODUCTION_CHECKPOINT_INITCODE_HASH"),
        "DOMFinalizedBurnRiscZeroVerifier": ("PRODUCTION_FINALIZED_BURN_RUNTIME_CODE_HASH",
                                              "PRODUCTION_FINALIZED_BURN_INITCODE_HASH"),
        "DOMCheckpointRiscZeroVerifier": ("PRODUCTION_CHECKPOINT_VERIFIER_RUNTIME_CODE_HASH",
                                           "PRODUCTION_CHECKPOINT_VERIFIER_INITCODE_HASH"),
    }[name]
    for identifier in forbidden_own_pins:
        if re.search(rf"\b{re.escape(identifier)}\b", target_source):
            fail(f"{name} embeds its own derived bytecode/configuration identity: {identifier}")


def artifact_policy(root: Path, path: Path, name: str) -> None:
    try:
        relative = path.relative_to(root).as_posix()
        artifact = strict_json(direct_bytes(root, relative, 8 * 1024 * 1024), f"publishable {name} artifact")
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
    source_payloads: dict[str, bytes] = {}
    for source_name, source_metadata in sources.items():
        try:
            payload = direct_bytes(root, source_name, 4 * 1024 * 1024)
        except SystemExit as error:
            fail(f"publishable {name} source cannot be read: {error}")
        if keccak256(payload) != source_metadata.get("keccak256"):
            fail(f"source hash mismatch in publishable {name} artifact: {source_name}")
        source_payloads[source_name] = payload
    source_graph_policy(name, f"contracts/{name}.sol", source_payloads)

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
    foundry = tomllib.loads(direct_text(root, "foundry.toml", 1024 * 1024, "Foundry configuration"))
    profile = foundry.get("profile", {}).get("default", {})
    if profile.get("solc_version") != EXPECTED_SOLC or profile.get("evm_version") != EXPECTED_EVM:
        fail("Foundry compiler/EVM policy is stale")
    if (profile.get("optimizer"), profile.get("optimizer_runs"), profile.get("via_ir"),
            profile.get("bytecode_hash")) != (True, 1, True, "none"):
        fail("Foundry optimizer/metadata policy is stale")

    for name in PRODUCTION:
        source = direct_text(root, f"contracts/{name}.sol", 4 * 1024 * 1024,
                             f"{name} source")
        if not re.search(rf"(?m)^pragma solidity {re.escape(EXPECTED_SOLC)};$", source):
            fail(f"{name} does not use the exact production compiler pragma")
        artifact = root / "out" / f"{name}.sol" / f"{name}.json"
        if artifact.exists():
            matches = sorted((root / "out").rglob(f"{name}.json"))
            if matches != [artifact]:
                fail(f"shadow or duplicate publishable artifact for {name}")
            artifact_policy(root, artifact, name)

    runtime = direct_text(root, "sdk/compiled-runtime.mjs", 4 * 1024 * 1024,
                          "compiled runtime policy")
    if f"const expectedCompiler='{EXPECTED_COMPILER}';" not in runtime or f"evmVersion:'{EXPECTED_EVM}'" not in runtime:
        fail("compiled-runtime artifact policy is stale")

    ignored = direct_text(root, ".gitignore", 1024 * 1024, "publication ignore policy").splitlines()
    if "results/" not in ignored:
        fail("legacy results are not excluded from publication")
    manifest_source = direct_text(root, "scripts/source-manifest.py", 4 * 1024 * 1024,
                                  "source manifest policy")
    if 'top == "results"' not in manifest_source or 'top.startswith("results-stage")' not in manifest_source:
        fail("source manifest does not exclude legacy result trees")
    for manifest_name in ("MANIFEST.sha256", "PROOF-PROGRAM-MANIFEST.sha256"):
        manifest = (root / manifest_name).read_text()
        for line in manifest.splitlines():
            fields = line.split("  ", 1)
            if len(fields) == 2 and beneath_legacy(fields[1]):
                fail(f"{manifest_name} publishes legacy result path {fields[1]}")

    evidence = strict_json(direct_bytes(root, "config/mainnet-release-evidence.unconfigured.json",
                                        4 * 1024 * 1024), "mainnet release evidence")
    if not isinstance(evidence, dict):
        fail("mainnet release evidence must be an object")
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
        target_source = root / "contracts" / "USDOMProofReserve.sol"
        target_source.write_text("""// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;
import {IDOMFinalizedBurnVerifier} from "./IDOMFinalizedBurnVerifier.sol";
import {IUSDTPolicy} from "./IUSDTPolicy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
contract USDOMProofReserve {}
""")
        # Model the reviewed transitive OpenZeppelin edge in the synthetic graph.
        guard_source = root / "vendor/openzeppelin-contracts-5.6.1/utils/ReentrancyGuard.sol"
        guard_source.write_text("""// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;
import {StorageSlot} from "./StorageSlot.sol";
abstract contract ReentrancyGuard {}
""")
        metadata_source = root / "vendor/openzeppelin-contracts-5.6.1/token/ERC20/extensions/IERC20Metadata.sol"
        metadata_source.write_text("""// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;
import {IERC20} from "../IERC20.sol";
interface IERC20Metadata is IERC20 {}
""")
        for source_name in source_metadata:
            source_metadata[source_name]["keccak256"] = keccak256((root / source_name).read_bytes())
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
        canonical_artifact = artifact_path.read_text()
        policy_path = root / "contracts" / "IUSDTPolicy.sol"
        canonical_policy = policy_path.read_bytes()
        policy_path.write_text('pragma solidity 0.8.37;\nimport "./USDOMProofReserve.sol";\n')
        artifact["metadata"]["sources"]["contracts/IUSDTPolicy.sol"]["keccak256"] = keccak256(
            policy_path.read_bytes())
        artifact_path.write_text(json.dumps(artifact))
        try:
            check(root)
        except SystemExit as error:
            assert "circular Solidity import" in str(error)
        else:
            raise AssertionError("circular publishable source graph was accepted")
        policy_path.write_text('pragma solidity 0.8.37;\ninterface USDOMProofReserve {}\n')
        artifact["metadata"]["sources"]["contracts/IUSDTPolicy.sol"]["keccak256"] = keccak256(
            policy_path.read_bytes())
        artifact_path.write_text(json.dumps(artifact))
        try:
            check(root)
        except SystemExit as error:
            assert "duplicate Solidity declaration" in str(error)
        else:
            raise AssertionError("duplicate interface/contract declaration was accepted")
        policy_path.write_bytes(canonical_policy)
        artifact["metadata"]["sources"]["contracts/IUSDTPolicy.sol"]["keccak256"] = keccak256(canonical_policy)
        target_canonical = target_source.read_text()
        target_source.write_text(target_canonical.replace("contract USDOMProofReserve {}",
            "bytes32 constant PRODUCTION_RESERVE_RUNTIME_CODE_HASH = bytes32(0);\n"
            "contract USDOMProofReserve {}"))
        artifact["metadata"]["sources"]["contracts/USDOMProofReserve.sol"]["keccak256"] = keccak256(
            target_source.read_bytes())
        artifact_path.write_text(json.dumps(artifact))
        try:
            check(root)
        except SystemExit as error:
            assert "embeds its own derived bytecode/configuration identity" in str(error)
        else:
            raise AssertionError("self-referential runtime identity was accepted")
        target_source.write_text(target_canonical)
        artifact["metadata"]["sources"]["contracts/USDOMProofReserve.sol"]["keccak256"] = keccak256(
            target_source.read_bytes())
        artifact_path.write_text(json.dumps(artifact))
        canonical_artifact = artifact_path.read_text()
        artifact_path.write_text(canonical_artifact.replace('"metadata":', '"metadata":null,"metadata":', 1))
        try:
            check(root)
        except SystemExit as error:
            assert "duplicate JSON key" in str(error)
        else:
            raise AssertionError("duplicate artifact authority was accepted")
        artifact_path.write_text(canonical_artifact)
        hardlink = root / "contracts" / "hardlinked-reserve.sol"
        os.link(root / "contracts" / "USDOMProofReserve.sol", hardlink)
        try:
            check(root)
        except SystemExit as error:
            assert "file policy mismatch" in str(error)
        else:
            raise AssertionError("hard-linked artifact source was accepted")
        hardlink.unlink()
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
            '{"reserveArtifact":null,"reserveArtifact":{"path":"out/USDOMProofReserve.sol/USDOMProofReserve.json"}}')
        try:
            check(root)
        except SystemExit as error:
            assert "duplicate JSON key" in str(error)
        else:
            raise AssertionError("duplicate release-evidence authority was accepted")
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
