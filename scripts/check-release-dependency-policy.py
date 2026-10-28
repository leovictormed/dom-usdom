#!/usr/bin/env python3
"""Static, network-free release dependency identity policy."""

from __future__ import annotations

import json
import hashlib
import base64
import binascii
import os
from pathlib import Path
import posixpath
import re
import stat
import sys
import tempfile
import tomllib
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SOURCE = re.compile(r"git\+https://[^?#]+\?rev=([0-9a-f]{40})#([0-9a-f]{40})")
NPM_INTEGRITY = re.compile(r"sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}")
CARGO_CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
CARGO_PACKAGE_NAME = re.compile(r"[A-Za-z0-9_-]+")
CARGO_SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
MAX_CARGO_LOCK_BYTES = 64 * 1024 * 1024
MAX_CARGO_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_NPM_LOCK_BYTES = 64 * 1024 * 1024
NPM_INSTALL_SCRIPT_ALLOWLIST = {
    "labs/usdom-ethereum-finality/vendor/helios/helios-ts/package-lock.json": {
        "node_modules/esbuild": ("0.25.12", "sha512-bbPBYYrtZbkt6Os6FiTLCTFxvq4tt3JKall1vRwshA3fdVztsLAatFaZobhkBC8/BrPetoa0oksYoKXoG4ryJg=="),
        "node_modules/fsevents": ("2.3.3", "sha512-5xoDfX+fL7faATnagmWPpbFtwh/R77WmMMqqHGS65C3vvB0YHrgF+B1YmZ3441tMj5n63k0212XNoJwzlhffQw=="),
        "node_modules/wasm-pack": ("0.13.1", "sha512-P9exD4YkjpDbw68xUhF3MDm/CC/3eTmmthyG5bHJ56kalxOTewOunxTke4SyF8MTXV6jUtNjXggPgrGmMtczGg==")},
    "labs/usdom-ethereum-finality/vendor/helios/helios-ts/example/package-lock.json": {
        "node_modules/esbuild": ("0.25.5", "sha512-P8OtKZRv/5J5hhz0cUAdu/cLuPIKXpQl1R9pZtvmHWQvrAUVd0UNIPT4IB4W3rNOqVO0rlqHmCIbSwxh/c9yUQ=="),
        "node_modules/fsevents": ("2.3.3", "sha512-5xoDfX+fL7faATnagmWPpbFtwh/R77WmMMqqHGS65C3vvB0YHrgF+B1YmZ3441tMj5n63k0212XNoJwzlhffQw==")},
    "vendor/dom-wallet-v3/frontend/package-lock.json": {
        "node_modules/esbuild": ("0.25.0", "sha512-BXq5mqc8ltbaN34cDqWuYKyNhX8D/Z0J1xdtdQ8UcIIIyJyz+ZMKUt58tF3SrZ85jcfN/PZYhjR5uDQAYNVbuw=="),
        "node_modules/fsevents": ("2.3.2", "sha512-xiqMQR4xAeHTuB9uWm+fFRcIOgKBMiOBP+eXiyT7jsgVCq1bkVygt00oASowB7EdtpOHaaPgKt812P9ab+DDKA==")},
    "labs/usdom-reserve/package-lock.json": {},
    "labs/usdom-reserve/containers/risc0-snarkjs/package-lock.json": {},
}
NPM_LOCAL_ENTRY_ALLOWLIST = {
    "labs/usdom-ethereum-finality/vendor/helios/helios-ts/example/package-lock.json": {".."},
}
NPM_UNLOCKED_MANIFEST_ALLOWLIST = {
    "labs/usdom-reserve/vendor/openzeppelin-contracts-5.6.1/package.json":
        ("openzeppelin-solidity", "5.6.1", "9fd0264492a51d33f01f3dff30b286dda1baee34b10f63803892234473ea2979"),
}
CARGO_PATCH_ALLOWLIST = {
    "labs/usdom-ethereum-finality/vendor/helios/Cargo.toml": {
        "crates-io": {
            "ethereum_hashing": {
                "git": "https://github.com/ncitron/ethereum_hashing",
                "rev": "7ee70944ed4fabe301551da8c447e4f4ae5e6c35",
            }
        }
    }
}
CARGO_CONFIG_ALLOWLIST = {
    "labs/usdom-ethereum-finality/vendor/helios/.cargo/config.toml":
        "cae92036fb55184b21189331f067dea7b69f400fbc3eeace3dd9b3a180357148"
}
CARGO_BUILD_SCRIPT_ALLOWLIST = {
    "crates/adapters/btc-secp-c1a/build.rs": "f41eda3386079e075ea0f2cbb28b97f4ee12271250f27f45ce12d74ca73af295",
    "crates/adapters/btc-secp-sys/build.rs": "3c91bbfcf3245c8f26d0ec866a07b404be8ead96a76f3fb6d95a80b341753aec",
    "crates/dom-interopd/build.rs": "8d35d308b53ecc529c025e403023008798d8c3ff206907dd82df972307bdce16",
    "crates/dom-rpc/build.rs": "8962aed292be3a5bbf0a324bea72b0c25530fce2c3415742e3144f54e55d369c",
    "vendor/dom-wallet-v3/src-tauri/build.rs": "5df69c634117873f14d2d589805651d34e89812ad359432f3253c90961c35467",
    "wallet-desktop/src-tauri/build.rs": "6aeeab41bc35efde4e3c2b644a6248f7fc06d24ae30b75c0d33491cbb0c1fa31",
}
CARGO_NATIVE_LINKS_ALLOWLIST = {
    "crates/adapters/btc-secp-c1a/Cargo.toml": "dominterop_secp_c1a_harness",
    "crates/adapters/btc-secp-sys/Cargo.toml": "dominterop_secp_v0_10_0",
}
CARGO_PROFILE_MANIFEST_ALLOWLIST = {
    "Cargo.toml", "crates/dom-wallet/fuzz/Cargo.toml",
    "labs/usdom-ethereum-finality/vendor/helios/Cargo.toml",
    "wallet-desktop/src-tauri/Cargo.toml",
}
CARGO_PACKAGE_FILTER_ALLOWLIST = {
    "labs/usdom-ethereum-finality/vendor/helios/Cargo.toml": {"exclude": ["benches"]}
}
CARGO_UNLOCKED_WORKSPACE_ALLOWLIST = {
    "crates/dom-crypto/fuzz/corpus_gen/Cargo.toml": ("corpus_gen", "0.0.0"),
    "crates/dom-wallet-recovery/fuzz/Cargo.toml": ("dom-wallet-recovery-fuzz", "0.0.0"),
}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def read_direct_text(path: Path, label: str, maximum: int) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before_path = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"cannot open {label} directly: {error}")
    try:
        before = os.fstat(descriptor)
        if ((before_path.st_dev, before_path.st_ino) != (before.st_dev, before.st_ino)
                or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.geteuid() or before.st_mode & 0o022):
            fail(f"unsafe descriptor identity or permissions for {label}")
        chunks: list[bytes] = []; size = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk); size += len(chunk)
            if size > maximum:
                fail(f"{label} exceeds {maximum} bytes")
        after = os.fstat(descriptor)
        identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
                           "st_uid", "st_mode", "st_nlink")
        if any(getattr(before, field) != getattr(after, field) for field in identity_fields):
            fail(f"{label} changed while being read")
        try:
            return b"".join(chunks).decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            fail(f"{label} is not canonical UTF-8 text: {error}")
    finally:
        os.close(descriptor)


def strict_json(text: str, label: str) -> object:
    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                fail(f"duplicate JSON key in {label}: {key}")
            value[key] = item
        return value
    try:
        return json.loads(text, object_pairs_hook=object_pairs)
    except (json.JSONDecodeError, UnicodeError) as error:
        fail(f"invalid JSON in {label}: {error}")


def strict_toml(text: str, label: str) -> dict[str, object]:
    try:
        value = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        fail(f"invalid or duplicate TOML in {label}: {error}")
    if not isinstance(value, dict):
        fail(f"TOML root is not an object in {label}")
    return value


def validate_npm_integrity(value: object, label: str) -> None:
    if not isinstance(value, str) or NPM_INTEGRITY.fullmatch(value) is None:
        fail(f"npm package lacks canonical integrity in {label}")
    algorithm, encoded = value.split("-", 1); lengths = {"sha256": 32, "sha384": 48, "sha512": 64}
    try:
        digest = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        fail(f"npm integrity is not canonical base64 in {label}")
    if len(digest) != lengths[algorithm] or base64.b64encode(digest).decode() != encoded:
        fail(f"npm integrity digest length or encoding is invalid in {label}")


def validate_npm_registry_url(value: object, label: str) -> None:
    if not isinstance(value, str): fail(f"npm resolved source is not a string in {label}")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org"
            or parsed.username is not None or parsed.password is not None or parsed.port is not None
            or parsed.query or parsed.fragment or not parsed.path.startswith("/")
            or not parsed.path.endswith(".tgz")):
        fail(f"noncanonical npm registry source in {label}")


def validate_npm_registry_binding(entry_name: str, package: dict[str, object], label: str) -> None:
    version = package.get("version"); resolved = package.get("resolved")
    if (not isinstance(version, str) or not version
            or re.fullmatch(r"[0-9A-Za-z.+-]+", version) is None
            or not entry_name.startswith("node_modules/") or "//" in entry_name
            or any(part in ("", ".", "..") for part in entry_name.split("/"))):
        fail(f"npm package identity is invalid in {label}")
    package_name = entry_name.rsplit("node_modules/", 1)[-1]
    if not package_name or package_name.startswith("node_modules/"):
        fail(f"npm package path is invalid in {label}")
    leaf = package_name.rsplit("/", 1)[-1]
    validate_npm_registry_url(resolved, label)
    expected_path = f"/{package_name}/-/{leaf}-{version}.tgz"
    if unquote(urlsplit(resolved).path) != expected_path:
        fail(f"npm package name/version is disconnected from resolved archive in {label}")
    validate_npm_integrity(package.get("integrity"), label)


def npm_atomic_requirement_satisfied(requirement: str, version: object) -> bool:
    match = re.fullmatch(r"([~^]?)(\d+)(?:\.(\d+))?(?:\.(\d+))?(-[0-9A-Za-z.-]+)?", requirement)
    actual = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?", version) if isinstance(version, str) else None
    if match is None or actual is None: return False
    operator, major, minor, patch, prerelease = match.groups()
    lower = (int(major), int(minor or 0), int(patch or 0)); current = tuple(map(int, actual.groups()[:3]))
    if prerelease is not None and current == lower and actual.group(4) != prerelease: return False
    if prerelease is None and actual.group(4) is not None: return False
    specified = 1 + (minor is not None) + (patch is not None)
    if operator == "":
        return current[:specified] == lower[:specified] and (specified < 3 or actual.group(4) == prerelease)
    if operator == "~":
        upper = (lower[0] + 1, 0, 0) if specified == 1 else (lower[0], lower[1] + 1, 0)
    elif lower[0] > 0:
        upper = (lower[0] + 1, 0, 0)
    elif specified == 1:
        upper = (1, 0, 0)
    elif lower[1] > 0:
        upper = (0, lower[1] + 1, 0)
    else:
        upper = (0, 0, lower[2] + 1)
    return lower <= current < upper


def npm_requirement_satisfied(requirement: str, version: object) -> bool:
    actual = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?", version) if isinstance(version, str) else None
    if actual is None:
        return False
    current = tuple(map(int, actual.groups()[:3]))
    for alternative in requirement.split("||"):
        atoms = alternative.strip().split()
        if not atoms:
            continue
        accepted = True
        for atom in atoms:
            if atom == "*":
                accepted = actual.group(4) is None
                if not accepted:
                    break
                continue
            if atom.startswith(">="):
                minimum = re.fullmatch(r">=(\d+)\.(\d+)\.(\d+)", atom)
                accepted = (minimum is not None and actual.group(4) is None
                            and current >= tuple(map(int, minimum.groups())))
            else:
                accepted = npm_atomic_requirement_satisfied(atom, version)
            if not accepted:
                break
        if accepted:
            return True
    return False


def validate_npm_dependency_closure(packages: dict[str, object], label: str,
                                    skipped_entries: set[str]) -> None:
    keys = set(packages)
    def resolves(entry: str, dependency: str) -> str | None:
        if entry == "":
            candidate = f"node_modules/{dependency}"
            return candidate if candidate in keys else None
        current = entry
        while True:
            candidate = f"{current}/node_modules/{dependency}"
            if candidate in keys: return candidate
            marker = "/node_modules/"
            if marker not in current:
                candidate = f"node_modules/{dependency}"
                return candidate if candidate in keys else None
            current = current.rsplit(marker, 1)[0]
    for entry, package in packages.items():
        if entry in skipped_entries: continue
        if not isinstance(package, dict): fail(f"npm package entry is not an object in {label}: {entry}")
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            dependencies = package.get(section, {})
            if not isinstance(dependencies, dict):
                fail(f"npm {section} is not an object in {label}: {entry}")
            for dependency, requirement in dependencies.items():
                resolved = resolves(entry, dependency) if isinstance(dependency, str) else None
                optional_peer = (section == "peerDependencies"
                                 and package.get("peerDependenciesMeta", {}).get(dependency)
                                 == {"optional": True})
                if optional_peer and resolved is None:
                    continue
                if (not isinstance(dependency, str)
                        or re.fullmatch(r"(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+", dependency) is None
                        or not isinstance(requirement, str) or not requirement.strip()
                        or resolved is None
                        or not isinstance(packages.get(resolved), dict)
                        or not npm_requirement_satisfied(requirement, packages[resolved].get("version"))):
                    fail(f"npm dependency closure is invalid in {label}: {entry} -> {dependency}")


def validate_npm_package_metadata(package: dict[str, object], label: str) -> None:
    for flag in ("hasInstallScript", "dev", "optional", "devOptional", "inBundle", "extraneous"):
        if flag in package and not isinstance(package[flag], bool):
            fail(f"npm package boolean flag is invalid in {label}: {flag}")
    for selector in ("os", "cpu", "libc"):
        values = package.get(selector)
        if values is not None and (not isinstance(values, list) or len(values) != len(set(values))
                                   or any(not isinstance(item, str) or not item for item in values)):
            fail(f"npm platform selector is invalid in {label}: {selector}")
    engines = package.get("engines")
    if engines is not None and (not isinstance(engines, dict)
                                or any(not isinstance(key, str) or not key
                                       or not isinstance(value, str) or not value
                                       for key, value in engines.items())):
        fail(f"npm engine policy is invalid in {label}")
    peer_meta = package.get("peerDependenciesMeta", {})
    peers = package.get("peerDependencies", {})
    if not isinstance(peer_meta, dict) or not isinstance(peers, dict):
        fail(f"npm peer dependency metadata is invalid in {label}")
    for dependency, metadata in peer_meta.items():
        if not isinstance(dependency, str) or not dependency or metadata != {"optional": True}:
            fail(f"npm peer dependency metadata is disconnected in {label}: {dependency}")
    binaries = package.get("bin", {})
    if not isinstance(binaries, dict): fail(f"npm binary inventory is invalid in {label}")
    for command, target in binaries.items():
        if (not isinstance(command, str)
                or re.fullmatch(r"(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+", command) is None
                or not isinstance(target, str) or not target or target.startswith("/")
                or "\\" in target or any(part in ("", ".", "..") for part in target.split("/"))):
            fail(f"npm binary target is invalid in {label}: {command}")


def validate_npm_install_script_inventory(
        observed: dict[str, tuple[object, object]],
        expected: dict[str, tuple[str, str]], label: str) -> None:
    if observed != expected:
        fail(f"npm install-script identity set differs in {label}: {sorted(observed)}")


def validate_npm_manifest_binding(manifest: object, root_package: dict[str, object], label: str) -> None:
    if not isinstance(manifest, dict): fail(f"npm package manifest root is invalid in {label}")
    if (not isinstance(manifest.get("name"), str) or not isinstance(manifest.get("version"), str)
            or manifest["name"] != root_package.get("name")
            or manifest["version"] != root_package.get("version")):
        fail(f"npm manifest identity differs from lock root in {label}")
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        declared = manifest.get(section, {}); locked = root_package.get(section, {})
        if (not isinstance(declared, dict)
                or any(not isinstance(key, str) or not key or not isinstance(value, str) or not value
                       for key, value in declared.items()) or declared != locked):
            fail(f"npm manifest {section} differs from lock root in {label}")
    scripts = manifest.get("scripts", {})
    if (not isinstance(scripts, dict)
            or any(not isinstance(key, str) or not key or not isinstance(value, str) or not value
                   for key, value in scripts.items())):
        fail(f"npm manifest scripts are invalid in {label}")
    lifecycle = sorted(set(scripts) & {"preinstall", "install", "postinstall", "prepare"})
    if lifecycle: fail(f"npm root install lifecycle scripts are forbidden in {label}: {lifecycle}")


def validate_npm_manifest_inventory(manifests: set[str], locks: set[str]) -> None:
    locked_manifests = {str(Path(lock).with_name("package.json")) for lock in locks}
    expected = locked_manifests | set(NPM_UNLOCKED_MANIFEST_ALLOWLIST)
    if manifests != expected:
        fail(f"npm manifest/lock inventory differs: missing={sorted(expected-manifests)}, extra={sorted(manifests-expected)}")


def validate_unlocked_npm_manifest(
        text: str, label: str, expected: tuple[str, str, str]) -> None:
    value = strict_json(text, label)
    identity = (value.get("name"), value.get("version")) if isinstance(value, dict) else (None, None)
    digest = hashlib.sha256(text.encode()).hexdigest()
    if identity != expected[:2] or digest != expected[2]:
        fail(f"reviewed non-installable npm manifest identity or content differs: {label}")


def validate_cargo_package_identities(packages: object, label: str) -> list[dict[str, object]]:
    if not isinstance(packages, list):
        fail(f"Cargo package inventory is not an array in {label}")
    seen: set[tuple[str, str, str | None]] = set()
    result: list[dict[str, object]] = []
    for package in packages:
        if not isinstance(package, dict):
            fail(f"Cargo package entry is not an object in {label}")
        name, version, source = package.get("name"), package.get("version"), package.get("source")
        if (not isinstance(name, str) or CARGO_PACKAGE_NAME.fullmatch(name) is None
                or not isinstance(version, str) or CARGO_SEMVER.fullmatch(version) is None):
            fail(f"Cargo package identity is invalid in {label}")
        if source is not None and not isinstance(source, str):
            fail(f"Cargo package source is invalid in {label}: {name} {version}")
        identity = (name, version, source)
        if identity in seen:
            fail(f"duplicate Cargo package identity in {label}: {identity}")
        seen.add(identity)
        result.append(package)
    return result


def validate_cargo_dependency_closure(packages: list[dict[str, object]], label: str) -> None:
    by_name: dict[str, list[dict[str, object]]] = {}
    by_identity: dict[tuple[str, str], dict[str, object]] = {}
    for package in packages:
        name, version = package["name"], package["version"]
        by_name.setdefault(name, []).append(package); by_identity[(name, version)] = package
    for package in packages:
        dependencies = package.get("dependencies", [])
        if (not isinstance(dependencies, list)
                or any(not isinstance(item, str) or not item for item in dependencies)
                or len(dependencies) != len(set(dependencies))):
            fail(f"Cargo dependency inventory is invalid in {label}: {package['name']}")
        for dependency in dependencies:
            parts = dependency.rsplit(" ", 1)
            name = parts[0]
            if re.fullmatch(r"[A-Za-z0-9_-]+", name) is None:
                fail(f"Cargo dependency identity is malformed in {label}: {dependency}")
            if len(parts) == 2:
                target = by_identity.get((name, parts[1]))
            else:
                candidates = by_name.get(name, []); target = candidates[0] if len(candidates) == 1 else None
            if target is None:
                fail(f"Cargo dependency is absent or ambiguous in {label}: {dependency}")


def validate_cargo_package_source(package: dict[str, object], label: str) -> bool:
    source = package.get("source")
    if source is None:
        if "checksum" in package:
            fail(f"local Cargo package carries a disconnected checksum in {label}: "
                 f"{package.get('name')} {package.get('version')}")
        return False
    identity = f"{package.get('name')} {package.get('version')} in {label}"
    if source.startswith("registry+"):
        if source != CARGO_CRATES_IO_SOURCE:
            fail(f"package uses an unreviewed Cargo registry: {identity}: {source}")
        if not SHA256.fullmatch(package.get("checksum", "")):
            fail(f"registry package lacks canonical checksum: {identity}")
        return False
    if source.startswith("git+"):
        if "checksum" in package:
            fail(f"Git Cargo package carries a registry checksum: {identity}")
        match = GIT_SOURCE.fullmatch(source)
        if match is None or match.group(1) != match.group(2):
            fail(f"git package is not locked to one exact rev: {identity}: {source}")
        return True
    fail(f"unsupported Cargo source: {identity}: {source}")


def cargo_manifest_git_pins(parsed: object) -> set[tuple[str, str]]:
    pins: set[tuple[str, str]] = set()
    def walk(value: object) -> None:
        if isinstance(value, dict):
            git, rev = value.get("git"), value.get("rev")
            if isinstance(git, str) and isinstance(rev, str):
                pins.add((git, rev))
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(parsed)
    return pins


def validate_cargo_git_pin_closure(
        manifest_pins: set[tuple[str, str]], lock_pins: set[tuple[str, str]]) -> None:
    missing = manifest_pins - lock_pins
    if missing:
        fail(f"Cargo manifest Git pins are absent from every reviewed lock: {sorted(missing)}")


def validate_manifest_dependencies(parsed: object, manifest: Path, root: Path = ROOT,
                                   workspace_dependencies: set[str] | None = None) -> None:
    dependency_tables = {"dependencies", "dev-dependencies", "build-dependencies"}

    def walk(value: object) -> None:
        if not isinstance(value, dict):
            return
        for key, child in value.items():
            if key in dependency_tables:
                if not isinstance(child, dict):
                    fail(f"Cargo dependency table is invalid in {manifest.relative_to(root)}")
                for dependency, specification in child.items():
                    if not isinstance(dependency, str) or not dependency:
                        fail(f"Cargo dependency name is invalid in {manifest.relative_to(root)}")
                    if not isinstance(specification, dict):
                        continue
                    if specification.get("workspace") is True:
                        if workspace_dependencies is not None and dependency not in workspace_dependencies:
                            fail(f"unknown inherited workspace dependency in {manifest.relative_to(root)}: {dependency}")
                        if any(selector in specification for selector in
                               ("git", "path", "version", "registry", "branch", "tag", "rev")):
                            fail(f"workspace dependency overrides its source in {manifest.relative_to(root)}: {dependency}")
                    git = specification.get("git")
                    if "registry" in specification:
                        fail(f"alternate Cargo registry dependency is forbidden in "
                             f"{manifest.relative_to(root)}: {dependency}")
                    if git is not None:
                        rev = specification.get("rev")
                        if (not isinstance(git, str) or not git.startswith("https://")
                                or "?" in git or "#" in git
                                or not isinstance(rev, str)
                                or re.fullmatch(r"[0-9a-f]{40}", rev) is None
                                or "branch" in specification or "tag" in specification):
                            fail(f"git dependency lacks exact HTTPS revision in {manifest.relative_to(root)}: {dependency}")
                    path = specification.get("path")
                    if path is not None:
                        if not isinstance(path, str) or not path:
                            fail(f"Cargo dependency path is invalid in {manifest.relative_to(root)}: {dependency}")
                        target = (manifest.parent / path).resolve()
                        if not target.is_relative_to(root.resolve()):
                            fail(f"Cargo dependency path escapes repository in {manifest.relative_to(root)}: {dependency}")
            walk(child)
    walk(parsed)


def validate_manifest_overrides(parsed: object, manifest: Path, root: Path = ROOT) -> None:
    if not isinstance(parsed, dict):
        return
    name = manifest.relative_to(root).as_posix()
    patch = parsed.get("patch", {})
    if patch != CARGO_PATCH_ALLOWLIST.get(name, {}):
        fail(f"Cargo patch set differs from reviewed policy in {name}")
    if "replace" in parsed:
        fail(f"Cargo replace table is forbidden in {name}")


def validate_workspace_paths(parsed: object, manifest: Path, root: Path = ROOT) -> None:
    if not isinstance(parsed, dict) or "workspace" not in parsed:
        return
    workspace = parsed["workspace"]
    if not isinstance(workspace, dict):
        fail(f"Cargo workspace is not an object in {manifest.relative_to(root)}")
    for field in ("members", "exclude", "default-members"):
        values = workspace.get(field, [])
        if not isinstance(values, list) or any(not isinstance(item, str) or not item for item in values):
            fail(f"Cargo workspace {field} is invalid in {manifest.relative_to(root)}")
        if len(values) != len(set(values)):
            fail(f"duplicate Cargo workspace {field} in {manifest.relative_to(root)}")
        for item in values:
            normalized = posixpath.normpath(item)
            if ("\\" in item or item.startswith("/") or normalized == ".."
                    or normalized.startswith("../")):
                fail(f"Cargo workspace {field} escapes repository in {manifest.relative_to(root)}: {item}")


def validate_package_execution_surface(parsed: object, manifest: Path, root: Path = ROOT) -> None:
    if not isinstance(parsed, dict): return
    name = manifest.relative_to(root).as_posix(); package = parsed.get("package", {})
    if not isinstance(package, dict): fail(f"Cargo package table is invalid in {name}")
    build = package.get("build"); build_name = (manifest.parent / "build.rs").relative_to(root).as_posix()
    allowlisted = build_name in CARGO_BUILD_SCRIPT_ALLOWLIST
    if build not in (None, "build.rs", False) or (build is False and allowlisted):
        fail(f"Cargo build-script declaration differs from reviewed policy in {name}")
    if build == "build.rs" and not allowlisted: fail(f"unreviewed Cargo build script in {name}")
    if package.get("links") != CARGO_NATIVE_LINKS_ALLOWLIST.get(name):
        fail(f"Cargo native links surface differs from reviewed policy in {name}")
    library = parsed.get("lib", {})
    if isinstance(library, dict) and library.get("proc-macro") is True:
        fail(f"unreviewed local proc-macro crate in {name}")


def validate_package_build_policy(parsed: object, manifest: Path, root: Path = ROOT) -> None:
    if not isinstance(parsed, dict): return
    name = manifest.relative_to(root).as_posix(); package = parsed.get("package", {})
    filters = {key: package[key] for key in ("include", "exclude") if isinstance(package, dict) and key in package}
    if filters != CARGO_PACKAGE_FILTER_ALLOWLIST.get(name, {}):
        fail(f"Cargo package include/exclude differs from reviewed policy in {name}")
    has_profiles = "profile" in parsed
    if has_profiles != (name in CARGO_PROFILE_MANIFEST_ALLOWLIST):
        fail(f"Cargo profile authority differs from reviewed policy in {name}")
    workspace = parsed.get("workspace")
    if name == "Cargo.toml":
        if not isinstance(workspace, dict) or workspace.get("resolver") != "2":
            fail("root Cargo workspace resolver is not version 2")
        workspace_package = workspace.get("package", {}) if isinstance(workspace, dict) else {}
        if workspace_package.get("edition") != "2021" or workspace_package.get("rust-version") != "1.75":
            fail("root Cargo edition/rust-version authority differs from policy")
        profiles = parsed.get("profile", {})
        release = profiles.get("release", {}) if isinstance(profiles, dict) else {}
        validation = profiles.get("release-validation", {}) if isinstance(profiles, dict) else {}
        development = profiles.get("dev", {}) if isinstance(profiles, dict) else {}
        if (release.get("opt-level") != 3 or release.get("lto") != "fat"
                or release.get("codegen-units") != 1 or release.get("panic") != "abort"
                or release.get("overflow-checks") is not True
                or validation.get("inherits") != "release" or validation.get("debug") != 1
                or development.get("overflow-checks") is not True
                or any(key in profile for profile in profiles.values() if isinstance(profile, dict)
                       for key in ("package", "build-override"))):
            fail("root Cargo profile safety policy differs from reviewed settings")


def validate_feature_surface(parsed: object, manifest: Path, root: Path = ROOT) -> None:
    if not isinstance(parsed, dict): return
    name = manifest.relative_to(root).as_posix(); features = parsed.get("features", {})
    if not isinstance(features, dict): fail(f"Cargo features table is invalid in {name}")
    references: set[str] = set()
    for feature, values in features.items():
        if not isinstance(feature, str) or re.fullmatch(r"[A-Za-z0-9_-]+", feature) is None:
            fail(f"Cargo feature name is invalid in {name}")
        if (not isinstance(values, list) or len(values) != len(set(values))
                or any(not isinstance(item, str)
                       or re.fullmatch(r"[A-Za-z0-9_+?./:-]+", item) is None
                       or ".." in item for item in values)):
            fail(f"Cargo feature members are invalid in {name}: {feature}")
        references.update(values)
    optional: set[str] = set()
    def walk(value: object) -> None:
        if not isinstance(value, dict): return
        for key, child in value.items():
            if key in {"dependencies", "dev-dependencies", "build-dependencies"} and isinstance(child, dict):
                for dependency, specification in child.items():
                    if isinstance(specification, dict):
                        if "optional" in specification and not isinstance(specification["optional"], bool):
                            fail(f"Cargo optional dependency flag is invalid in {name}: {dependency}")
                        if "default-features" in specification and not isinstance(specification["default-features"], bool):
                            fail(f"Cargo default-features flag is invalid in {name}: {dependency}")
                        dependency_features = specification.get("features", [])
                        if (not isinstance(dependency_features, list)
                                or len(dependency_features) != len(set(dependency_features))
                                or any(not isinstance(item, str) or not item for item in dependency_features)):
                            fail(f"Cargo dependency feature list is invalid in {name}: {dependency}")
                        if specification.get("optional") is True: optional.add(dependency)
            walk(child)
    walk(parsed)
    missing = sorted(dependency for dependency in optional if f"dep:{dependency}" not in references)
    if missing: fail(f"optional dependencies expose implicit features in {name}: {missing}")


def validate_target_surface(parsed: object, manifest: Path, root: Path = ROOT) -> None:
    if not isinstance(parsed, dict): return
    name = manifest.relative_to(root).as_posix(); feature_names = set(parsed.get("features", {}))
    package = parsed.get("package", {})
    for flag in ("autobins", "autoexamples", "autotests", "autobenches"):
        if isinstance(package, dict) and flag in package and not isinstance(package[flag], bool):
            fail(f"Cargo target discovery flag is invalid in {name}: {flag}")
    groups = [("lib", [parsed["lib"]] if "lib" in parsed else [])]
    groups.extend((kind, parsed.get(kind, [])) for kind in ("bin", "example", "bench", "test"))
    for kind, targets in groups:
        if not isinstance(targets, list) or any(not isinstance(target, dict) for target in targets):
            fail(f"Cargo {kind} target inventory is invalid in {name}")
        names: set[str] = set()
        for target in targets:
            target_name = target.get("name")
            if target_name is not None:
                if not isinstance(target_name, str) or not target_name or target_name in names:
                    fail(f"Cargo {kind} target name is invalid or duplicate in {name}")
                names.add(target_name)
            required = target.get("required-features", [])
            if (not isinstance(required, list) or len(required) != len(set(required))
                    or any(not isinstance(item, str) or item not in feature_names for item in required)):
                fail(f"Cargo {kind} required-features are invalid in {name}")
            path = target.get("path")
            if path is not None:
                if not isinstance(path, str) or not path:
                    fail(f"Cargo {kind} target path is invalid in {name}")
                candidate = manifest.parent / path; resolved = candidate.resolve()
                if (not resolved.is_relative_to(manifest.parent.resolve()) or candidate.is_symlink()
                        or not candidate.is_file()):
                    fail(f"Cargo {kind} target escapes or is not a direct file in {name}")


def release_files(filename: str, excluded_directories: frozenset[str]) -> list[Path]:
    """Find release inputs without ever descending into generated trees."""
    matches: list[Path] = []

    def traversal_error(error: OSError) -> None:
        fail(f"cannot traverse release dependency graph: {error}")

    for directory, child_directories, files in os.walk(
        ROOT, topdown=True, followlinks=False, onerror=traversal_error
    ):
        for child in child_directories:
            child_path = Path(directory) / child
            if child not in excluded_directories and child_path.is_symlink():
                fail(f"symlink directory can hide release dependencies: {relative(child_path)}")
        child_directories[:] = sorted(
            child for child in child_directories if child not in excluded_directories
        )
        if filename in files:
            candidate = Path(directory) / filename
            if candidate.is_symlink() or not candidate.is_file():
                fail(f"release dependency input is not a regular file: {relative(candidate)}")
            matches.append(candidate)
    return sorted(matches)


def cargo_locks() -> tuple[int, int, set[tuple[str, str]]]:
    locks = release_files("Cargo.lock", frozenset({".git", "node_modules", "target"}))
    package_count = 0
    git_count = 0
    git_pins: set[tuple[str, str]] = set()
    for lock in locks:
        data = strict_toml(read_direct_text(lock, relative(lock), MAX_CARGO_LOCK_BYTES), relative(lock))
        if set(data) != {"version", "package"} or data.get("version") not in (3, 4):
            fail(f"Cargo lockfile schema/version differs in {relative(lock)}")
        packages = validate_cargo_package_identities(data.get("package"), relative(lock))
        validate_cargo_dependency_closure(packages, relative(lock))
        for package in packages:
            package_count += 1
            git_count += int(validate_cargo_package_source(package, relative(lock)))
            source = package.get("source")
            if isinstance(source, str) and source.startswith("git+"):
                match = GIT_SOURCE.fullmatch(source)
                assert match is not None
                git_pins.add((source[4:source.index("?rev=")], match.group(1)))
    return len(locks), package_count, git_pins


def cargo_manifests() -> tuple[int, set[tuple[str, str]]]:
    manifests = release_files("Cargo.toml", frozenset({".git", "node_modules", "target"}))
    parsed_manifests: list[tuple[Path, dict[str, object]]] = []
    git_pins: set[tuple[str, str]] = set()
    for manifest in manifests:
        text = read_direct_text(manifest, relative(manifest), MAX_CARGO_MANIFEST_BYTES)
        if re.search(r"\b(?:branch|tag)\s*=", text):
            fail(f"floating git selector in {relative(manifest)}")
        for table in re.finditer(r"\{[^{}]*\bgit\s*=\s*\"[^\"]+\"[^{}]*\}", text):
            value = table.group(0)
            match = re.search(r"\brev\s*=\s*\"([0-9a-f]{40})\"", value)
            if match is None:
                fail(f"git dependency lacks exact 40-hex rev in {relative(manifest)}")
        parsed = strict_toml(text, relative(manifest))
        parsed_manifests.append((manifest, parsed))
        git_pins.update(cargo_manifest_git_pins(parsed))
    root_record = next((parsed for manifest, parsed in parsed_manifests if manifest == ROOT / "Cargo.toml"), None)
    if root_record is None:
        fail("root Cargo.toml is absent from release manifest inventory")
    workspace_table = root_record.get("workspace", {})
    workspace_dependencies = set(workspace_table.get("dependencies", {})) if isinstance(workspace_table, dict) else set()
    workspace_members = set(workspace_table.get("members", [])) if isinstance(workspace_table, dict) else set()
    for manifest, parsed in parsed_manifests:
        relative_parent = manifest.parent.relative_to(ROOT).as_posix()
        inherited = workspace_dependencies if manifest == ROOT / "Cargo.toml" or relative_parent in workspace_members else None
        validate_manifest_dependencies(parsed, manifest, root=ROOT, workspace_dependencies=inherited)
        validate_manifest_overrides(parsed, manifest, root=ROOT)
        validate_workspace_paths(parsed, manifest, root=ROOT)
        validate_package_execution_surface(parsed, manifest, root=ROOT)
        validate_package_build_policy(parsed, manifest, root=ROOT)
        validate_feature_surface(parsed, manifest, root=ROOT)
        validate_target_surface(parsed, manifest, root=ROOT)
        defaults = parsed.get("features", {}).get("default", [])
        forbidden = {str(value) for value in defaults if any(
            token in str(value).lower() for token in ("unsafe", "test", "fuzz", "fault"))}
        if forbidden:
            fail(f"test/unsafe feature enabled by default in {relative(manifest)}: {sorted(forbidden)}")
    for member in workspace_members:
        member_manifest = ROOT / member / "Cargo.toml"
        if member_manifest.is_symlink() or not member_manifest.is_file():
            fail(f"root workspace member lacks a direct Cargo.toml: {member}")
    lock_names = {relative(path) for path in release_files(
        "Cargo.lock", frozenset({".git", "node_modules", "target"}))}
    validate_cargo_workspace_lock_inventory(parsed_manifests, lock_names, root=ROOT)
    return len(manifests), git_pins


def validate_build_script_inventory() -> None:
    scripts: dict[str, str] = {}
    for path in release_files("build.rs", frozenset({".git", "node_modules", "target"})):
        name = relative(path)
        text = read_direct_text(path, name, MAX_CARGO_MANIFEST_BYTES)
        validate_build_script_execution(text, name)
        payload = text.encode()
        scripts[name] = hashlib.sha256(payload).hexdigest()
    validate_build_script_hashes(scripts, CARGO_BUILD_SCRIPT_ALLOWLIST)


def validate_build_script_execution(text: str, name: str) -> None:
    """Build scripts may use reviewed crates, but cannot spawn ambient executables directly."""
    if re.search(r"\b(?:std::)?process::Command\b|\bCommand\s*::\s*new\b", text):
        fail(f"Cargo build script executes an ambient child process: {name}")


def validate_build_script_hashes(observed: dict[str, str], expected: dict[str, str]) -> None:
    if observed != expected:
        fail(f"Cargo build-script identities differ from reviewed policy: {sorted(observed)}")


def validate_cargo_workspace_lock_inventory(
        parsed_manifests: list[tuple[Path, dict[str, object]]], lock_names: set[str],
        root: Path = ROOT) -> None:
    manifests = {manifest.relative_to(root).as_posix(): parsed
                 for manifest, parsed in parsed_manifests}
    for lock in lock_names:
        if str(Path(lock).with_name("Cargo.toml")) not in manifests:
            fail(f"Cargo lock lacks an adjacent reviewed manifest: {lock}")
    unlocked: dict[str, tuple[object, object]] = {}
    for name, parsed in manifests.items():
        if "workspace" not in parsed: continue
        if str(Path(name).with_name("Cargo.lock")) not in lock_names:
            package = parsed.get("package", {})
            unlocked[name] = ((package.get("name"), package.get("version"))
                              if isinstance(package, dict) else (None, None))
    if unlocked != CARGO_UNLOCKED_WORKSPACE_ALLOWLIST:
        fail(f"Cargo workspace/lock inventory differs from reviewed policy: {unlocked}")


def reject_cargo_source_configs(root: Path = ROOT) -> None:
    found: dict[str, str] = {}
    for directory, children, files in os.walk(root, topdown=True, followlinks=False):
        children[:] = sorted(child for child in children if child not in {".git", "node_modules", "target"})
        path = Path(directory)
        if path.name == ".cargo":
            credential_files = sorted(set(files) & {"credentials", "credentials.toml"})
            if credential_files:
                fail(f"repository Cargo credentials are forbidden: "
                     f"{[str((path / name).relative_to(root)) for name in credential_files]}")
            for filename in ("config", "config.toml"):
                if filename in files:
                    candidate = path / filename; name = candidate.relative_to(root).as_posix()
                    payload = read_direct_text(candidate, name, MAX_CARGO_MANIFEST_BYTES).encode()
                    found[name] = hashlib.sha256(payload).hexdigest()
            children[:] = []
    if found != CARGO_CONFIG_ALLOWLIST:
        fail(f"repository Cargo config set differs from reviewed policy: {sorted(found)}")


def npm_locks() -> tuple[int, int]:
    locks = release_files("package-lock.json", frozenset({".git", "node_modules", "target"}))
    if {relative(p) for p in locks} != set(NPM_INSTALL_SCRIPT_ALLOWLIST):
        fail("package-lock set differs from the reviewed release policy")
    manifests = release_files("package.json", frozenset({".git", "node_modules", "target"}))
    validate_npm_manifest_inventory({relative(path) for path in manifests}, {relative(path) for path in locks})
    for name, identity in NPM_UNLOCKED_MANIFEST_ALLOWLIST.items():
        text = read_direct_text(ROOT / name, name, MAX_NPM_LOCK_BYTES)
        validate_unlocked_npm_manifest(text, name, identity)
    entries = 0
    for lock in locks:
        data = strict_json(read_direct_text(lock, relative(lock), MAX_NPM_LOCK_BYTES), relative(lock))
        if not isinstance(data, dict):
            fail(f"npm lockfile root is not an object in {relative(lock)}")
        if set(data) != {"name", "version", "lockfileVersion", "requires", "packages"}:
            fail(f"npm lockfile top-level schema differs in {relative(lock)}")
        if data.get("lockfileVersion") != 3 or data.get("requires") is not True:
            fail(f"unsupported npm lockfile version in {relative(lock)}")
        install_scripts: dict[str, tuple[object, object]] = {}
        packages = data.get("packages")
        if not isinstance(packages, dict):
            fail(f"npm package inventory is not an object in {relative(lock)}")
        root_package = packages.get("")
        if (not isinstance(data.get("name"), str) or not isinstance(data.get("version"), str)
                or not isinstance(root_package, dict) or root_package.get("name") != data["name"]
                or root_package.get("version") != data["version"]):
            fail(f"npm root package identity is disconnected in {relative(lock)}")
        manifest_path = lock.with_name("package.json")
        manifest_name = relative(manifest_path)
        manifest = strict_json(read_direct_text(manifest_path, manifest_name, MAX_NPM_LOCK_BYTES), manifest_name)
        validate_npm_manifest_binding(manifest, root_package, manifest_name)
        for name, package in packages.items():
            if not isinstance(package, dict):
                fail(f"npm package entry is not an object in {relative(lock)}: {name}")
            validate_npm_package_metadata(package, f"{relative(lock)}: {name or '<root>'}")
            if not name:
                continue
            if "link" in package:
                fail(f"npm link entry is forbidden in {relative(lock)}: {name}")
            entries += 1
            if package.get("hasInstallScript"):
                install_scripts[name] = (package.get("version"), package.get("integrity"))
            resolved = package.get("resolved")
            if resolved is None:
                if name not in NPM_LOCAL_ENTRY_ALLOWLIST.get(relative(lock), set()):
                    fail(f"unreviewed local npm package entry in {relative(lock)}: {name}")
            else:
                validate_npm_registry_binding(name, package, f"{relative(lock)}: {name}")
        validate_npm_dependency_closure(
            packages, relative(lock), NPM_LOCAL_ENTRY_ALLOWLIST.get(relative(lock), set()))
        expected = NPM_INSTALL_SCRIPT_ALLOWLIST[relative(lock)]
        validate_npm_install_script_inventory(install_scripts, expected, relative(lock))
    return len(locks), entries


def self_test() -> None:
    for text in ('{"packages":{},"packages":{}}', '{"a":1,"nested":{"x":1,"x":2}}'):
        try:
            strict_json(text, "fixture")
        except SystemExit as error:
            assert "duplicate JSON key" in str(error)
        else:
            raise AssertionError("duplicate JSON key was accepted")
    try:
        strict_toml("[dependencies]\na='1'\na='2'\n", "fixture")
    except SystemExit as error:
        assert "invalid or duplicate TOML" in str(error)
    else:
        raise AssertionError("duplicate TOML key was accepted")
    validate_npm_integrity("sha512-" + base64.b64encode(bytes(64)).decode(), "fixture")
    validate_npm_registry_url("https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz", "fixture")
    npm_package = {"version": "1.0.0", "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz",
                   "integrity": "sha512-" + base64.b64encode(bytes(64)).decode()}
    validate_npm_registry_binding("node_modules/@scope/pkg", npm_package, "fixture")
    for requirement, version in (("1", "1.9.0"), ("^1.2.3", "1.9.0"),
                                 ("^0.2.1", "0.2.9"), ("~1.2.3", "1.2.9"),
                                 (">=5.0.4", "5.8.3"), ("^3 >=3.22.0", "3.23.1"),
                                 ("^3 || ^4", "4.1.0"), ("*", "9.0.0")):
        assert npm_requirement_satisfied(requirement, version)
    for requirement, version in (("1", "2.0.0"), ("^1.2.3", "2.0.0"),
                                 ("^0.2.1", "0.3.0"), ("~1.2.3", "1.3.0"),
                                 ("^1.0.0", "1.1.0-beta.1"), (">=5.0.4", "5.0.3"),
                                 ("^3 >=3.22.0", "3.21.9"), ("^3 || ^4", "5.0.0"),
                                 ("*", "9.0.0-beta.1")):
        assert not npm_requirement_satisfied(requirement, version)
    for integrity in ("sha512-QQ==", "sha256-not_base64", "sha512-" + base64.b64encode(bytes(32)).decode()):
        try:
            validate_npm_integrity(integrity, "fixture")
        except SystemExit:
            pass
        else:
            raise AssertionError("invalid npm integrity was accepted")
    for source in (
        "https://registry.npmjs.org.evil/pkg.tgz",
        "https://user@registry.npmjs.org/pkg.tgz",
        "https://registry.npmjs.org:443/pkg.tgz",
        "https://registry.npmjs.org/pkg.tgz?redirect=1",
    ):
        try:
            validate_npm_registry_url(source, "fixture")
        except SystemExit:
            pass
        else:
            raise AssertionError("invalid npm registry URL was accepted")
    for entry, mutate in (
        ("node_modules/../pkg", {}),
        ("node_modules/@scope/other", {}),
        ("node_modules/@scope/pkg", {"version": "2.0.0"}),
    ):
        try:
            validate_npm_registry_binding(entry, {**npm_package, **mutate}, "fixture")
        except SystemExit:
            pass
        else:
            raise AssertionError("disconnected npm package archive was accepted")
    npm_closure = {"": {"dependencies": {"a": "^1"}}, "node_modules/a": {
        "version": "1.2.0", "dependencies": {"b": "1"}, "peerDependencies": {"peer": "^2"},
        "peerDependenciesMeta": {"absent": {"optional": True}},
        }, "node_modules/b": {"version": "1.9.0"}, "node_modules/peer": {"version": "2.1.0"}}
    # Optional peers may be absent, but their metadata must still bind to a declaration.
    npm_closure["node_modules/a"]["peerDependencies"]["absent"] = "^3"
    validate_npm_dependency_closure(npm_closure, "fixture", set())
    for changed in (
        {"": {"dependencies": {"missing": "1"}}},
        {"": {"dependencies": {"../escape": "1"}}, "node_modules/../escape": {"version": "1.0.0"}},
        {"": {"dependencies": {"a": 1}}, "node_modules/a": {"version": "1.0.0"}},
        {"": {"dependencies": []}},
        {"": {"dependencies": {"a": "^2"}}, "node_modules/a": {"version": "1.9.0"}},
        {"": {"peerDependencies": {"missing": "^1"}}},
        {"": {"peerDependencies": {"peer": "^2"}}, "node_modules/peer": {"version": "1.9.0"}},
    ):
        try:
            validate_npm_dependency_closure(changed, "fixture", set())
        except SystemExit:
            pass
        else:
            raise AssertionError("disconnected npm dependency graph was accepted")
    validate_npm_package_metadata({"dev": True, "os": ["linux"], "bin": {"tool": "bin/tool.js"}}, "fixture")
    for metadata in (
        {"hasInstallScript": "true"},
        {"os": ["linux", "linux"]},
        {"peerDependenciesMeta": {"peer": {"optional": False}}},
        {"bin": {"tool": "../escape"}},
        {"bin": "bin/tool.js"},
    ):
        try:
            validate_npm_package_metadata(metadata, "fixture")
        except SystemExit:
            pass
        else:
            raise AssertionError("unsafe npm package metadata was accepted")
    reviewed_script = {"node_modules/tool": ("1.2.3", "sha512-" + base64.b64encode(bytes(64)).decode())}
    validate_npm_install_script_inventory(reviewed_script, reviewed_script, "fixture")
    for changed in (
        {"node_modules/tool": ("1.2.4", reviewed_script["node_modules/tool"][1])},
        {"node_modules/tool": ("1.2.3", "sha512-" + base64.b64encode(bytes([1]) * 64).decode())},
        {"node_modules/other": reviewed_script["node_modules/tool"]},
    ):
        try:
            validate_npm_install_script_inventory(changed, reviewed_script, "fixture")
        except SystemExit:
            pass
        else:
            raise AssertionError("unreviewed npm install-script identity was accepted")
    npm_manifest = {"name": "app", "version": "1.0.0", "dependencies": {"a": "^1"},
                    "scripts": {"test": "node --test"}}
    npm_root = {"name": "app", "version": "1.0.0", "dependencies": {"a": "^1"}}
    validate_npm_manifest_binding(npm_manifest, npm_root, "fixture")
    for changed in (
        {**npm_manifest, "version": "2.0.0"},
        {**npm_manifest, "dependencies": {"a": "^2"}},
        {**npm_manifest, "devDependencies": []},
        {**npm_manifest, "scripts": {"prepare": "download-tool"}},
        {**npm_manifest, "scripts": {"test": 1}},
    ):
        try:
            validate_npm_manifest_binding(changed, npm_root, "fixture")
        except SystemExit:
            pass
        else:
            raise AssertionError("npm manifest/lock drift was accepted")
    locked = {"app/package-lock.json"}
    expected_manifests = {"app/package.json", *NPM_UNLOCKED_MANIFEST_ALLOWLIST}
    validate_npm_manifest_inventory(expected_manifests, locked)
    for changed in (expected_manifests | {"hidden/package.json"}, expected_manifests - {"app/package.json"}):
        try:
            validate_npm_manifest_inventory(changed, locked)
        except SystemExit:
            pass
        else:
            raise AssertionError("unpaired npm manifest inventory was accepted")
    unlocked_text = '{"name":"vendored","version":"1.0.0"}\n'
    unlocked_identity = ("vendored", "1.0.0", hashlib.sha256(unlocked_text.encode()).hexdigest())
    validate_unlocked_npm_manifest(unlocked_text, "fixture", unlocked_identity)
    for changed in (
        '{"name":"vendored","version":"1.0.1"}\n',
        '{"name":"vendored","version":"1.0.0","scripts":{"install":"run"}}\n',
        unlocked_text.rstrip(),
    ):
        try:
            validate_unlocked_npm_manifest(changed, "fixture", unlocked_identity)
        except SystemExit:
            pass
        else:
            raise AssertionError("modified unlocked npm manifest was accepted")
    package = {"name": "crate", "version": "1.0.0", "source": "registry+https://example.invalid"}
    try:
        validate_cargo_package_identities([package, dict(package)], "fixture")
    except SystemExit as error:
        assert "duplicate Cargo package identity" in str(error)
    else:
        raise AssertionError("duplicate Cargo package identity was accepted")
    for invalid in ([{"name": "", "version": "1.0.0"}],
                    [{"name": "../crate", "version": "1.0.0"}],
                    [{"name": "crate", "version": "01.0.0"}],
                    [{"name": "crate", "version": "1"}],
                    [{"name": "crate", "version": 1}], [{}]):
        try:
            validate_cargo_package_identities(invalid, "fixture")
        except SystemExit:
            pass
        else:
            raise AssertionError("invalid Cargo package identity was accepted")
    validate_cargo_package_source({"name": "crate", "version": "1.0.0",
        "source": CARGO_CRATES_IO_SOURCE, "checksum": "0" * 64}, "fixture")
    for unsafe_source in (
        {"name": "crate", "version": "1.0.0",
         "source": "registry+https://packages.example.invalid/index", "checksum": "0" * 64},
        {"name": "crate", "version": "1.0.0", "source": CARGO_CRATES_IO_SOURCE},
        {"name": "local", "version": "1.0.0", "checksum": "0" * 64},
        {"name": "git", "version": "1.0.0",
         "source": "git+https://example.invalid/repository?rev=" + "1" * 40 + "#" + "1" * 40,
         "checksum": "0" * 64},
    ):
        try:
            validate_cargo_package_source(unsafe_source, "fixture")
        except SystemExit:
            pass
        else:
            raise AssertionError("unreviewed or unchecksummed Cargo registry was accepted")
    manifest_git = {("https://example.invalid/repository", "1" * 40)}
    assert cargo_manifest_git_pins({"target": {"cfg(unix)": {"dependencies": {
        "crate": {"git": "https://example.invalid/repository", "rev": "1" * 40}}}}}) == manifest_git
    validate_cargo_git_pin_closure(manifest_git, manifest_git | {
        ("https://example.invalid/transitive", "2" * 40)})
    try:
        validate_cargo_git_pin_closure(manifest_git, set())
    except SystemExit:
        pass
    else:
        raise AssertionError("Cargo manifest Git pin disconnected from all locks was accepted")
    cargo_packages = [
        {"name": "a", "version": "1.0.0"}, {"name": "a", "version": "2.0.0"},
        {"name": "b", "version": "1.0.0", "dependencies": ["a 1.0.0"]},
        {"name": "c", "version": "1.0.0", "dependencies": ["b"]},
    ]
    validate_cargo_dependency_closure(cargo_packages, "fixture")
    for dependency in (["missing"], ["a"], ["a 3.0.0"], ["../a"], ["b", "b"]):
        changed = [dict(package) for package in cargo_packages]
        changed[-1]["dependencies"] = dependency
        try:
            validate_cargo_dependency_closure(changed, "fixture")
        except SystemExit:
            pass
        else:
            raise AssertionError("invalid Cargo lock dependency edge was accepted")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); crate = root / "crate"; crate.mkdir(); (crate / "Cargo.toml").write_text("[package]\nname='crate'\nversion='1.0.0'\n")
        manifest = root / "Cargo.toml"
        manifest.write_text("ok\n")
        assert read_direct_text(manifest, "fixture", 3) == "ok\n"
        symlink = root / "symlink"; symlink.symlink_to(manifest)
        hardlink = root / "hardlink"; os.link(manifest, hardlink)
        for unsafe in (symlink, hardlink):
            try:
                read_direct_text(unsafe, "fixture", 16)
            except SystemExit:
                pass
            else:
                raise AssertionError("unsafe dependency-policy input was accepted")
        hardlink.unlink()
        try:
            read_direct_text(manifest, "fixture", 2)
        except SystemExit as error:
            assert "exceeds" in str(error)
        else:
            raise AssertionError("oversized dependency-policy input was accepted")
        valid = tomllib.loads("[dependencies]\nlocal={path='crate'}\nremote={git='https://example.invalid/repo',rev='0123456789abcdef0123456789abcdef01234567'}\n")
        validate_manifest_dependencies(valid, manifest, root)
        invalid_manifests = [
            "[dependencies.remote]\ngit='https://example.invalid/repo'\n",
            "[target.'cfg(unix)'.dev-dependencies.remote]\ngit='ssh://example.invalid/repo'\nrev='0123456789abcdef0123456789abcdef01234567'\n",
            "[build-dependencies.local]\npath='../escape'\n",
            "[dependencies.remote]\nversion='1'\nregistry='private'\n",
        ]
        for source in invalid_manifests:
            try:
                validate_manifest_dependencies(tomllib.loads(source), manifest, root)
            except SystemExit:
                pass
            else:
                raise AssertionError("unsafe Cargo dependency declaration was accepted")
        for inherited in (
            {"dependencies": {"unknown": {"workspace": True}}},
            {"dependencies": {"known": {"workspace": True, "version": "1"}}},
        ):
            try:
                validate_manifest_dependencies(inherited, manifest, root, {"known"})
            except SystemExit:
                pass
            else:
                raise AssertionError("unsafe workspace dependency inheritance was accepted")
        validate_workspace_paths({"workspace": {"members": ["crate"]}}, manifest, root)
        for workspace in (
            {"workspace": {"members": ["crate", "crate"]}},
            {"workspace": {"members": ["../escape"]}},
            {"workspace": {"exclude": "crate"}},
        ):
            try:
                validate_workspace_paths(workspace, manifest, root)
            except SystemExit:
                pass
            else:
                raise AssertionError("unsafe Cargo workspace path inventory was accepted")
        allowed_patch = root / "labs/usdom-ethereum-finality/vendor/helios/Cargo.toml"
        allowed_patch.parent.mkdir(parents=True)
        validate_manifest_overrides({"patch": CARGO_PATCH_ALLOWLIST["labs/usdom-ethereum-finality/vendor/helios/Cargo.toml"]}, allowed_patch, root)
        for overrides in ({"replace": {}}, {"patch": {"crates-io": {"crate": {"path": "crate"}}}}):
            try:
                validate_manifest_overrides(overrides, manifest, root)
            except SystemExit:
                pass
            else:
                raise AssertionError("unreviewed Cargo source override was accepted")
        cargo_config = root / ".cargo"; cargo_config.mkdir(); (cargo_config / "config.toml").write_text("[source.crates-io]\nreplace-with='mirror'\n")
        try:
            reject_cargo_source_configs(root)
        except SystemExit:
            pass
        else:
            raise AssertionError("Cargo source replacement config was accepted")
        cargo_config.joinpath("config.toml").unlink()
        cargo_config.joinpath("credentials.toml").write_text("[registry]\ntoken='secret'\n")
        try:
            reject_cargo_source_configs(root)
        except SystemExit as error:
            assert "credentials are forbidden" in str(error)
        else:
            raise AssertionError("repository Cargo credentials were accepted")
        for execution in (
            {"package": {"build": "generate.py"}},
            {"package": {"links": "native"}},
            {"package": {}, "lib": {"proc-macro": True}},
        ):
            try:
                validate_package_execution_surface(execution, manifest, root)
            except SystemExit:
                pass
            else:
                raise AssertionError("unreviewed Cargo execution surface was accepted")
        reviewed_build = {"crate/build.rs": "0" * 64}
        validate_build_script_hashes(reviewed_build, reviewed_build)
        for changed in (
            {"crate/build.rs": "1" * 64},
            {"other/build.rs": "0" * 64},
            {},
        ):
            try:
                validate_build_script_hashes(changed, reviewed_build)
            except SystemExit:
                pass
            else:
                raise AssertionError("unreviewed Cargo build-script identity was accepted")
        for build_policy in (
            {"package": {"include": ["src/**"]}},
            {"package": {}, "profile": {"release": {"overflow-checks": False}}},
        ):
            try:
                validate_package_build_policy(build_policy, crate / "Cargo.toml", root)
            except SystemExit:
                pass
            else:
                raise AssertionError("unreviewed Cargo package/profile policy was accepted")
        for feature_policy in (
            {"dependencies": {"secret": {"version": "1", "optional": True}}},
            {"features": {"default": ["feature", "feature"]}},
            {"dependencies": {"crate": {"version": "1", "default-features": "false"}}},
        ):
            try:
                validate_feature_surface(feature_policy, manifest, root)
            except SystemExit:
                pass
            else:
                raise AssertionError("unsafe Cargo feature surface was accepted")
        for target_policy in (
            {"lib": {"path": "../escape.rs"}},
            {"features": {}, "bin": [{"name": "tool", "required-features": ["missing"]}]},
            {"bin": [{"name": "tool"}, {"name": "tool"}]},
        ):
            try:
                validate_target_surface(target_policy, manifest, root)
            except SystemExit:
                pass
            else:
                raise AssertionError("unsafe Cargo target surface was accepted")
        unlocked_records = []
        for name, (package_name, version) in CARGO_UNLOCKED_WORKSPACE_ALLOWLIST.items():
            unlocked_records.append((root / name, {"workspace": {}, "package": {
                "name": package_name, "version": version}}))
        validate_cargo_workspace_lock_inventory(unlocked_records, set(), root)
        for records, locks in (
            (unlocked_records + [(root / "hidden/Cargo.toml", {"workspace": {}, "package": {
                "name": "hidden", "version": "1"}})], set()),
            (unlocked_records, {"orphan/Cargo.lock"}),
        ):
            try:
                validate_cargo_workspace_lock_inventory(records, locks, root)
            except SystemExit:
                pass
            else:
                raise AssertionError("unpaired Cargo workspace/lock inventory was accepted")
    print("PASS: strict dependency-lock parser adversarial self-test")


def main() -> None:
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if sys.argv[1:]:
        fail("usage: check-release-dependency-policy.py [--self-test]")
    reject_cargo_source_configs()
    validate_build_script_inventory()
    cargo_lock_count, cargo_packages, locked_git_pins = cargo_locks()
    manifest_count, manifest_git_pins = cargo_manifests()
    validate_cargo_git_pin_closure(manifest_git_pins, locked_git_pins)
    npm_lock_count, npm_entries = npm_locks()
    print(f"PASS: {cargo_lock_count} Cargo locks/{cargo_packages} entries, "
          f"{manifest_count} manifests and {npm_lock_count} npm locks/{npm_entries} entries are pinned")


if __name__ == "__main__":
    main()
