#!/usr/bin/env python3
"""Fail if the experimental DOM checkpoint path acquires RPC/network authority."""

from __future__ import annotations

import re
import subprocess
import sys
import hashlib
import json
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
MANIFEST = REPO / "crates/dom-chain/Cargo.toml"
SOURCE = REPO / "crates/dom-chain/src/ethereum_checkpoint_poc.rs"
FINALITY_SOURCE = REPO / "labs/usdom-ethereum-finality/src/lib.rs"
VERIFIER_ADAPTER = REPO / "crates/dom-ethereum-consensus-core"
VERIFIER_UPSTREAM = (
    REPO
    / "labs/usdom-ethereum-finality/vendor/helios/ethereum/consensus-core/src"
)

# These packages would turn an RPC response or an operational EVM adapter into
# a consensus input. A future authenticated verifier must receive explicit
# review and replace this guard deliberately instead of bypassing it silently.
FORBIDDEN_PACKAGES = {
    "adapter-evm",
    "evm-actuator",
    "ureq",
    "reqwest",
    "hyper",
    "jsonrpsee",
    "web3",
    "ethers-providers",
    "alloy-provider",
    "alloy-rpc-client",
    "alloy-transport-http",
}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def cargo_tree(features: str) -> set[str]:
    command = [
        "cargo",
        "tree",
        "--offline",
        "--locked",
        "-p",
        "dom-chain",
        "--features",
        features,
        "--edges",
        "normal",
        "--prefix",
        "none",
        "--format",
        "{p}",
    ]
    result = subprocess.run(
        command,
        cwd=REPO,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    packages: set[str] = set()
    for line in result.stdout.splitlines():
        match = re.match(r"^([^ ]+) v[0-9]", line)
        if match:
            packages.add(match.group(1))
    if "dom-chain" not in packages:
        fail("cargo tree did not contain dom-chain")
    return packages


def check_source_guards() -> None:
    manifest = MANIFEST.read_text()
    source = SOURCE.read_text()
    required_manifest = [
        'ethereum-checkpoint-poc = ["dep:sha3"]',
        'ethereum-checkpoint-verified-poc = [',
        '"dep:usdom-ethereum-finality-experiment",',
        "sha3 = { version = \"0.10\"",
    ]
    for needle in required_manifest:
        if needle not in manifest:
            fail(f"missing explicit feature boundary: {needle}")
    if re.search(r"(?m)^default\s*=.*ethereum-checkpoint-poc", manifest):
        fail("checkpoint experiment became a default feature")
    if re.search(r"(?m)^default\s*=.*ethereum-checkpoint-verified-poc", manifest):
        fail("verified checkpoint experiment became a default feature")
    required_source = [
        "TEST ORACLE",
        "network_magic != NETWORK_MAGIC_REGTEST",
        "test oracle is regtest-only",
        "Does not verify any Ethereum signature, finality, receipt or state proof.",
        "install_from_verified_handoff",
    ]
    for needle in required_source:
        if needle not in source:
            fail(f"missing fail-closed source marker: {needle}")
    finality_source = FINALITY_SOURCE.read_text()
    if 'compile_error!("unsafe-test-oracle is forbidden in release builds")' not in finality_source:
        fail("unsafe checkpoint fixture is not forbidden in release builds")


def check_verifier_source_pin() -> None:
    provenance = json.loads((VERIFIER_ADAPTER / "UPSTREAM.json").read_text())
    expected = {item["path"]: item["sha256"] for item in provenance["files"]}
    actual_paths = {
        f"src/{path.relative_to(VERIFIER_ADAPTER / 'src').as_posix()}"
        for path in (VERIFIER_ADAPTER / "src").rglob("*.rs")
    }
    if actual_paths != set(expected):
        fail("Ethereum consensus adapter source set differs from provenance manifest")
    for relative, digest in expected.items():
        adapter = VERIFIER_ADAPTER / relative
        upstream = VERIFIER_UPSTREAM / Path(relative).relative_to("src")
        adapter_hash = hashlib.sha256(adapter.read_bytes()).hexdigest()
        upstream_hash = hashlib.sha256(upstream.read_bytes()).hexdigest()
        if adapter_hash != digest or upstream_hash != digest:
            fail(f"Ethereum consensus adapter source drift: {relative}")


def main() -> None:
    check_source_guards()
    check_verifier_source_pin()
    packages = cargo_tree("ethereum-checkpoint-poc")
    verified_packages = cargo_tree("ethereum-checkpoint-verified-poc")
    for label, graph in (("barrier", packages), ("verified handoff", verified_packages)):
        forbidden = sorted(graph & FORBIDDEN_PACKAGES)
        if forbidden:
            fail(f"{label} dependency graph contains " + ", ".join(forbidden))
    if "usdom-ethereum-finality-experiment" not in verified_packages:
        fail("verified handoff graph omitted the concrete Ethereum verifier")
    print(
        "PASS: experimental checkpoint remains opt-in/regtest-only; "
        f"{len(packages)} normal dependency packages contain no RPC/EVM authority"
    )
    print(
        "PASS: optional verified handoff contains the concrete proof verifier; "
        f"{len(verified_packages)} packages contain no RPC/EVM authority"
    )
    print("production readiness remains false; native USDOM consensus state is absent")


if __name__ == "__main__":
    try:
        main()
    except subprocess.TimeoutExpired as error:
        fail(f"Cargo dependency graph command timed out after {error.timeout} seconds")
    except subprocess.CalledProcessError as error:
        sys.stderr.write(error.stderr)
        fail(f"cargo tree failed with exit code {error.returncode}")
