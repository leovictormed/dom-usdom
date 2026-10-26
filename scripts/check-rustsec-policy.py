#!/usr/bin/env python3
"""Fail-closed RustSec policy for the pinned DOM/USD₮ production graph.

Compatible security releases must be present. The small exception set is
accepted only while its exact crate checksums, sole direct parents and
application reachability constraints remain unchanged. This script never
builds, signs, deploys, broadcasts or handles secrets.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"

PATCHED = {
    ("quinn-proto", "0.11.19"): "0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe",
    ("rustls", "0.23.46"): "48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf",
    ("rustls-webpki", "0.103.16"): "4443b1b6d39d7c663139942cc4558262562d2c84123bb6282ef177009ca8b281",
    ("webpki-roots", "1.0.10"): "1c1c8e20c8a38fc7d65abfe74eb7280e4aa667e8eec8bc84996d2874810748d9",
}

EXCEPTIONS = {
    ("rsa", "0.9.10"): (
        "b8573f03f5883dcaebdfcf4725caa1ecb9c15b2ef50c43a07b816e06799bb12d",
        {("rzup", "0.5.2")},
        {"RUSTSEC-2023-0071"},
    ),
    ("ruzstd", "0.7.3"): (
        "fad02996bfc73da3e301efe90b1837be9ed8f4a462b6ed410aa35d00381de89f",
        {("object", "0.36.7")},
        {"RUSTSEC-2026-0344"},
    ),
    ("tracing-subscriber", "0.2.25"): (
        "0e0d2eaa99c3c2e41547cfa109e910a68ea03823cccad4a0525dcbc9b01e8c71",
        {("ark-relations", "0.5.1")},
        {"RUSTSEC-2025-0055"},
    ),
    ("zip", "2.4.2"): (
        "fabe6324e908f85a1c52063ce7aa26b68dcb7eb6dbc83a2d148403c9bc3eba50",
        {("risc0-circuit-recursion", "4.0.5")},
        {"RUSTSEC-2026-0367", "RUSTSEC-2026-0368", "RUSTSEC-2026-0369"},
    ),
}

UNMAINTAINED_EXCEPTIONS = {
    "RUSTSEC-2024-0388",  # derivative, pinned by Arkworks
    "RUSTSEC-2024-0436",  # paste, existing build-time macro exception
    "RUSTSEC-2025-0141",  # bincode, existing upstream-maintenance exception
}

FORBIDDEN_PACKAGES = {
    ("quinn-proto", "0.11.15"),
    ("rustls", "0.23.40"),
    ("rustls-webpki", "0.103.13"),
    ("webpki-roots", "1.0.7"),
}

FORBIDDEN_CRATES = {"serde_yaml", "unsafe-libyaml"}
DIRECTLY_FORBIDDEN = {"rsa", "ruzstd", "rzup", "zip"}

HOST_VALIDATION_MARKERS = {
    "crates/dom-usdom-finalized-burn-proof-host/src/lib.rs": (
        "fn validate_guest_artifacts(",
        "if sha256(&program) != PROGRAM_SHA256",
    ),
    "crates/dom-usdom-randomx-proof-host/src/lib.rs": (
        "fn validate_artifact(",
        "validate_artifact(paths.elf, MAX_ELF_BYTES, EXPECTED_ELF_SHA256)?;",
    ),
    "crates/dom-usdom-randomx-proof-host/src/aggregate.rs": (
        "fn validate_artifact(",
        "AGGREGATE_PROGRAM_SHA256",
    ),
    "crates/dom-usdom-economic-proof-host/src/lib.rs": (
        "checked_artifact(paths.chunk_elf, EXPECTED_CHUNK_ELF_SHA256)?;",
        "checked_artifact(paths.block_elf, EXPECTED_BLOCK_ELF_SHA256)?;",
    ),
    "crates/dom-usdom-checkpoint-proof-host/src/lib.rs": (
        "checked_artifact(paths.segment_elf, SEGMENT_ELF_SHA256, MAX_ARTIFACT_BYTES)?;",
        "checked_artifact(paths.outer_elf, OUTER_ELF_SHA256, MAX_ARTIFACT_BYTES)?;",
    ),
}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def dependency_name_version(value: str, by_name: dict[str, list[dict]]) -> tuple[str, str] | None:
    parts = value.split()
    name = parts[0]
    if len(parts) >= 2 and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][^ ]+)?", parts[1]):
        return name, parts[1]
    candidates = by_name.get(name, [])
    if len(candidates) == 1:
        return name, candidates[0]["version"]
    return None


def nested_dependency_names(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"dependencies", "dev-dependencies", "build-dependencies"} and isinstance(child, dict):
                found.update(child)
            found.update(nested_dependency_names(child))
    elif isinstance(value, list):
        for child in value:
            found.update(nested_dependency_names(child))
    return found


def policy_check() -> tuple[str, ...]:
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    packages = lock["package"]
    by_name: dict[str, list[dict]] = {}
    by_identity: dict[tuple[str, str], dict] = {}
    for package in packages:
        by_name.setdefault(package["name"], []).append(package)
        identity = (package["name"], package["version"])
        if identity in by_identity:
            fail(f"ambiguous duplicate lock identity {identity}")
        by_identity[identity] = package

    for identity in FORBIDDEN_PACKAGES:
        if identity in by_identity:
            fail(f"known vulnerable package remains locked: {identity[0]} {identity[1]}")
    for name in FORBIDDEN_CRATES:
        if name in by_name:
            fail(f"forbidden abandoned parser remains locked: {name}")

    for identity, checksum in PATCHED.items():
        package = by_identity.get(identity)
        if package is None:
            fail(f"required patched package missing: {identity[0]} {identity[1]}")
        if package.get("source") != REGISTRY or package.get("checksum") != checksum:
            fail(f"patched package identity changed: {identity[0]} {identity[1]}")

    parents: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for parent in packages:
        parent_id = (parent["name"], parent["version"])
        for dependency in parent.get("dependencies", []):
            child = dependency_name_version(dependency, by_name)
            if child is not None:
                parents.setdefault(child, set()).add(parent_id)

    vulnerability_ids: set[str] = set()
    for identity, (checksum, expected_parents, advisory_ids) in EXCEPTIONS.items():
        package = by_identity.get(identity)
        if package is None:
            fail(f"exception package disappeared; remove its waiver: {identity[0]} {identity[1]}")
        if package.get("source") != REGISTRY or package.get("checksum") != checksum:
            fail(f"exception package identity changed: {identity[0]} {identity[1]}")
        if parents.get(identity, set()) != expected_parents:
            fail(
                f"exception reachability changed for {identity[0]} {identity[1]}: "
                f"{sorted(parents.get(identity, set()))}"
            )
        vulnerability_ids.update(advisory_ids)

    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]
    member_roots = [ROOT / member for member in workspace["members"]]
    manifests = [ROOT / "Cargo.toml"] + sorted(root / "Cargo.toml" for root in member_roots)
    for manifest in manifests:
        parsed = tomllib.loads(manifest.read_text())
        direct = nested_dependency_names(parsed)
        forbidden = direct & DIRECTLY_FORBIDDEN
        if forbidden:
            fail(f"direct use of exception-only crate in {manifest.relative_to(ROOT)}: {sorted(forbidden)}")
        for line in manifest.read_text().splitlines():
            if re.match(r"\s*risc0-zkvm\s*=", line):
                if 'version = "=3.0.6"' not in line or "default-features = false" not in line:
                    fail(f"unpinned or default-enabled risc0-zkvm dependency in {manifest.relative_to(ROOT)}")

    rust_sources = [path for root in member_roots for path in (root / "src").rglob("*.rs")]
    for source in rust_sources:
        text = source.read_text(errors="strict")
        if "rzup::" in text or "rsa::RsaPrivateKey" in text or "zip::ZipArchive" in text:
            fail(f"application source directly reaches an exception-only API: {source.relative_to(ROOT)}")

    for relative, markers in HOST_VALIDATION_MARKERS.items():
        text = (ROOT / relative).read_text()
        for marker in markers:
            if marker not in text:
                fail(f"hash-pinned RISC Zero artifact validation changed in {relative}")

    deny = tomllib.loads((ROOT / "deny.toml").read_text())
    configured = set(deny["advisories"]["ignore"])
    required = vulnerability_ids | UNMAINTAINED_EXCEPTIONS
    if configured != required:
        fail(f"deny.toml advisory exceptions differ: expected {sorted(required)}, got {sorted(configured)}")

    return tuple(sorted(vulnerability_ids))


def execute_tools(vulnerability_ids: tuple[str, ...]) -> None:
    subprocess.run(["cargo", "deny", "check"], cwd=ROOT, check=True)
    command = ["cargo", "audit"]
    for advisory_id in vulnerability_ids:
        command.extend(("--ignore", advisory_id))
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute-tools", action="store_true")
    arguments = parser.parse_args()
    vulnerability_ids = policy_check()
    if arguments.execute_tools:
        execute_tools(vulnerability_ids)
    print(
        "PASS: RustSec policy pins four patched network dependencies, rejects unsafe YAML, "
        f"and fail-closes {len(vulnerability_ids)} reachability-scoped advisory exceptions"
    )


if __name__ == "__main__":
    main()
