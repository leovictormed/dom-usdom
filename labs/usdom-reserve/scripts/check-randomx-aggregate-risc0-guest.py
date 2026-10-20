#!/usr/bin/env python3
"""Verify the pinned candidate RandomX aggregate guest and artifact."""

from __future__ import annotations

import hashlib
import json
import struct
import tomllib
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
GUEST = REPO / "crates/dom-usdom-randomx-aggregate-risc0-guest"
MANIFEST = GUEST / "Cargo.toml"
SOURCE = GUEST / "src/main.rs"
README = GUEST / "README.md"
ARTIFACT = GUEST / "elfs/usdom-randomx-aggregate.bin"
IID = GUEST / "elfs/usdom-randomx-aggregate.iid"
PROVENANCE = GUEST / "PROVENANCE.json"
GUEST_LOCK = GUEST / "Cargo.lock"

EXPECTED_USER_ELF_SHA = "192c97830e7e1c390c025c137480268e0f75dfc96184738fb6a14c8e13e81c6b"
EXPECTED_ARTIFACT_SHA = "3dad95bf467a807c7ef033f88595ea44f14578dca4c7558ad95b7ad76c0d198f"
EXPECTED_IMAGE_ID = "08abf768e699ecb9d5cd2abc7603368103bcd3ee61afe9066d8a77272ac02ebf"
EXPECTED_BUILD_LOCK_SHA = "745b3c37903c47e71d55b640909e745922e97f5c05afab6970cb8f0aec7edf84"


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def package_versions(lock: dict, name: str) -> list[str]:
    return sorted({
        package["version"] for package in lock["package"] if package["name"] == name
    })


def verify_program_binary_framing(data: bytes) -> tuple[int, int]:
    if len(data) < 20 or data[:4] != b"R0BF":
        fail("program artifact is not a RISC Zero ProgramBinary")
    version, header_len = struct.unpack_from("<II", data, 4)
    if version != 1 or header_len == 0:
        fail("unexpected RISC Zero ProgramBinary framing")
    cursor = 12 + header_len
    if cursor + 4 > len(data):
        fail("truncated ProgramBinary header")
    user_len = struct.unpack_from("<I", data, cursor)[0]
    cursor += 4
    kernel_len = len(data) - cursor - user_len
    if user_len == 0 or kernel_len == 0:
        fail("ProgramBinary must contain nonempty user and kernel ELFs")
    return user_len, kernel_len


def main() -> None:
    manifest = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest["dependencies"]["risc0-zkvm"] != {
        "version": "=3.0.6",
        "default-features": False,
        "features": ["std", "getrandom"],
    }:
        fail("risc0-zkvm dependency is not exactly pinned to the reviewed profile")
    checkpoint = manifest["dependencies"]["dom-usdom-checkpoint-program"]
    if checkpoint != {
        "path": "../dom-usdom-checkpoint-program",
        "features": ["segment-bindings", "risc0-recursion"],
    }:
        fail("guest must enable the exact portable binding and recursion features")
    if manifest.get("bin", []) != [{
        "name": "usdom-randomx-aggregate",
        "path": "src/main.rs",
        "test": False,
        "bench": False,
    }]:
        fail("guest binary must be excluded from native test and benchmark harnesses")

    if sha256(GUEST_LOCK) != EXPECTED_BUILD_LOCK_SHA:
        fail("guest build-lock snapshot drift")
    lock = tomllib.loads(GUEST_LOCK.read_text(encoding="utf-8"))
    for package, versions in {
        "risc0-zkvm": ["3.0.6"],
        "risc0-binfmt": ["3.0.5"],
        "risc0-zkvm-platform": ["2.2.3"],
        "risc0-zkos-v1compat": ["2.2.3"],
    }.items():
        if package_versions(lock, package) != versions:
            fail(f"unexpected {package} versions in Cargo.lock")

    source = SOURCE.read_text(encoding="utf-8")
    for marker in [
        "#![no_main]",
        "CHECKPOINT_SEGMENT_TRANSITION_BYTES",
        "MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES",
        "checkpoint_segment_randomx_aggregate",
        "verify_checkpoint_segment_randomx_bindings_in_guest(&bindings)",
        "env::commit_slice(&aggregate.commitment()",
        "risc0_zkvm::guest::entry!(guest_main)",
    ]:
        if marker not in source:
            fail(f"guest source omitted required marker: {marker}")
    for forbidden in [
        "std::fs", "std::net", "std::process", "unsafe {",
        "execute_checkpoint_extension", "apply_native_usdom", "DOMCheckpointRiscZeroVerifier",
    ]:
        if forbidden in source:
            fail(f"guest source contains forbidden capability or outer-authority marker: {forbidden}")
    readme = README.read_text(encoding="utf-8")
    for warning in [
        "not a checkpoint transition proof",
        "must never be configured as the Ethereum checkpoint verifier's",
    ]:
        if warning not in readme:
            fail(f"README omitted component-boundary warning: {warning}")

    artifact = ARTIFACT.read_bytes()
    if hashlib.sha256(artifact).hexdigest() != EXPECTED_ARTIFACT_SHA:
        fail("committed RISC Zero ProgramBinary drift")
    user_len, kernel_len = verify_program_binary_framing(artifact)
    if IID.read_text(encoding="ascii").strip() != EXPECTED_IMAGE_ID:
        fail("committed ImageID drift")

    provenance = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    expected_provenance = {
        "schema": "dom-usdom-randomx-aggregate-risc0-guest-provenance-v1",
        "risc0ZkvmVersion": "3.0.6",
        "risc0BinfmtVersion": "3.0.5",
        "risc0PlatformVersion": "2.2.3",
        "risc0V1CompatVersion": "2.2.3",
        "guestRustVersion": "1.97.0-dev-e638c6cfe-2026-07-15",
        "guestLlvmVersion": "22.1.6",
        "cargoLockSha256": EXPECTED_BUILD_LOCK_SHA,
        "userElfSha256": EXPECTED_USER_ELF_SHA,
        "programBinarySha256": EXPECTED_ARTIFACT_SHA,
        "imageId": EXPECTED_IMAGE_ID,
        "cleanLocalRebuildsByteIdentical": True,
        "productionApproved": False,
        "outerCheckpointVerifierImage": False,
    }
    if provenance != expected_provenance:
        fail("guest provenance record drift")

    print(
        "PASS: pinned candidate RISC Zero 3.0.6 RandomX aggregate guest; "
        f"ProgramBinary {len(artifact)} bytes (user {user_len}, kernel {kernel_len}); "
        f"SHA-256 {EXPECTED_ARTIFACT_SHA}; ImageID {EXPECTED_IMAGE_ID}; "
        f"build lock {EXPECTED_BUILD_LOCK_SHA}; component-only and productionApproved=false"
    )


if __name__ == "__main__":
    main()
