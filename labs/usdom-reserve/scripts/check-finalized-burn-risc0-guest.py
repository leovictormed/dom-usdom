#!/usr/bin/env python3
"""Verify the pinned RISC Zero finalized-burn guest and committed artifact."""

from __future__ import annotations

import hashlib
import json
import struct
import tomllib
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
GUEST = REPO / "crates/dom-usdom-finalized-burn-risc0-guest"
MANIFEST = GUEST / "Cargo.toml"
SOURCE = GUEST / "src/main.rs"
ARTIFACT = GUEST / "elfs/usdom-finalized-burn.elf"
IID = GUEST / "elfs/usdom-finalized-burn.iid"
PROVENANCE = GUEST / "PROVENANCE.json"
GUEST_LOCK = GUEST / "Cargo.lock"

EXPECTED_ARTIFACT_SHA = "bf3202187d7c0643204bcb936b34a53b41b871cc4d633781dc96956c7de9d511"
EXPECTED_IMAGE_ID = "f0d9c98287719bf6fca6626ab96f0b14e305662873a9e3b5d4894a50f206a1ae"
EXPECTED_BUILD_LOCK_SHA = "4b121d8cd50110e8235933ac405b7dfac3bb92d43f959082af638a24ea539765"
EXPECTED_BUILDER_DIGEST = "sha256:7ae0a27fa72b10fb5c1066005bd949ae43dc4ead8a284f2d6572b99c82ab4468"


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def package_versions(lock: dict, name: str) -> list[str]:
    return sorted(
        package["version"]
        for package in lock["package"]
        if package["name"] == name
    )


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
    dependency = manifest["dependencies"]["risc0-zkvm"]
    if dependency != {
        "version": "=3.0.6",
        "default-features": False,
        "features": ["std"],
    }:
        fail("risc0-zkvm dependency is not exactly pinned to the reviewed profile")
    binaries = manifest.get("bin", [])
    if binaries != [
        {
            "name": "usdom-finalized-burn",
            "path": "src/main.rs",
            "test": False,
            "bench": False,
        }
    ]:
        fail("guest binary must be excluded from native test and benchmark harnesses")

    if sha256(GUEST_LOCK) != EXPECTED_BUILD_LOCK_SHA:
        fail("guest build-lock snapshot drift")
    lock = tomllib.loads(GUEST_LOCK.read_text(encoding="utf-8"))
    expected_versions = {
        "risc0-zkvm": ["3.0.6"],
        "risc0-binfmt": ["3.0.5"],
        "risc0-zkvm-platform": ["2.2.3"],
    }
    for package, versions in expected_versions.items():
        if package_versions(lock, package) != versions:
            fail(f"unexpected {package} versions in Cargo.lock")

    source = SOURCE.read_text(encoding="utf-8")
    for marker in [
        "#![no_main]",
        "MAX_FINALIZED_BURN_PROVER_INPUT_BYTES",
        "env::read_slice(&mut input)",
        "execute_with_checkpoint_assumption(&input)",
        "env::verify(",
        "checkpoint.image_id()",
        "checkpoint.journal()",
        "env::commit_slice(execution.output().as_bytes())",
        "risc0_zkvm::guest::entry!(guest_main)",
    ]:
        if marker not in source:
            fail(f"guest source omitted required marker: {marker}")
    for forbidden in ["std::fs", "std::net", "std::process", "unsafe {"]:
        if forbidden in source:
            fail(f"guest source contains forbidden host capability: {forbidden}")

    artifact = ARTIFACT.read_bytes()
    if hashlib.sha256(artifact).hexdigest() != EXPECTED_ARTIFACT_SHA:
        fail("committed RISC Zero program artifact drift")
    user_len, kernel_len = verify_program_binary_framing(artifact)
    if IID.read_bytes().hex() != EXPECTED_IMAGE_ID:
        fail("committed ImageID drift")

    provenance = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    expected_provenance = {
        "schema": "dom-usdom-finalized-burn-risc0-guest-provenance-v2",
        "risc0ZkvmVersion": "3.0.6",
        "risc0BinfmtVersion": "3.0.5",
        "risc0PlatformVersion": "2.2.3",
        "guestRustVersion": "1.97.0",
        "builderImage": "docker.io/risczero/risc0-guest-builder:r0.1.97.0",
        "builderImageDigest": EXPECTED_BUILDER_DIGEST,
        "cargoLockSha256": EXPECTED_BUILD_LOCK_SHA,
        "programBinarySha256": EXPECTED_ARTIFACT_SHA,
        "imageId": EXPECTED_IMAGE_ID,
        "workspaceCargoLockSha256": "8ddb926652b8fd54a38926ee9dd202657c5d7cd50fbaa765a5d1ee39db2c0106",
        "sourceManifestSha256": "08ad4751e4540705eaf43bfd8cebb5738b924cbdccab22be52bed33b62970be7",
        "reproducibleBuilds": 2,
        "byteIdentical": True,
        "guestRustReleaseAssetSha256": "100b597d605b706bec94e1d32bfaaf5851df8d75173f986d4b56a3e90916be53",
        "productionApproved": False,
        "statementSchema": "UDFINL04",
        "checkpointStatementSchema": "UDCPST06",
        "checkpointOuterImageId": "311d58dadcb97cac783e3ec0efe3c4570f42b944cbda1e48aeb56b055682257b",
    }
    if provenance != expected_provenance:
        fail("guest provenance record drift")

    print(
        "PASS: pinned RISC Zero 3.0.6 finalized-burn guest; "
        f"ProgramBinary {len(artifact)} bytes (user {user_len}, kernel {kernel_len}); "
        f"SHA-256 {EXPECTED_ARTIFACT_SHA}; ImageID {EXPECTED_IMAGE_ID}; "
        f"build lock {EXPECTED_BUILD_LOCK_SHA}"
    )


if __name__ == "__main__":
    main()
