#!/usr/bin/env python3
"""Static, network-free release dependency identity policy."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SOURCE = re.compile(r"git\+https://[^?#]+\?rev=([0-9a-f]{40})#([0-9a-f]{40})")
NPM_INTEGRITY = re.compile(r"sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}")
NPM_INSTALL_SCRIPT_ALLOWLIST = {
    "labs/usdom-ethereum-finality/vendor/helios/helios-ts/package-lock.json": {
        "node_modules/esbuild", "node_modules/fsevents", "node_modules/wasm-pack"},
    "labs/usdom-ethereum-finality/vendor/helios/helios-ts/example/package-lock.json": {
        "node_modules/esbuild", "node_modules/fsevents"},
    "vendor/dom-wallet-v3/frontend/package-lock.json": {
        "node_modules/esbuild", "node_modules/fsevents"},
    "labs/usdom-reserve/package-lock.json": set(),
}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


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


def cargo_locks() -> tuple[int, int]:
    locks = release_files("Cargo.lock", frozenset({".git", "node_modules", "target"}))
    package_count = 0
    git_count = 0
    for lock in locks:
        data = tomllib.loads(lock.read_text())
        for package in data.get("package", []):
            package_count += 1
            source = package.get("source")
            if source is None:
                continue
            identity = f"{package.get('name')} {package.get('version')} in {relative(lock)}"
            if source.startswith("registry+"):
                if not SHA256.fullmatch(package.get("checksum", "")):
                    fail(f"registry package lacks canonical checksum: {identity}")
            elif source.startswith("git+"):
                git_count += 1
                match = GIT_SOURCE.fullmatch(source)
                if match is None or match.group(1) != match.group(2):
                    fail(f"git package is not locked to one exact rev: {identity}: {source}")
            else:
                fail(f"unsupported Cargo source: {identity}: {source}")
    return len(locks), package_count


def cargo_manifests() -> int:
    manifests = release_files("Cargo.toml", frozenset({".git", "node_modules", "target"}))
    for manifest in manifests:
        text = manifest.read_text()
        if re.search(r"\b(?:branch|tag)\s*=", text):
            fail(f"floating git selector in {relative(manifest)}")
        for table in re.finditer(r"\{[^{}]*\bgit\s*=\s*\"[^\"]+\"[^{}]*\}", text):
            value = table.group(0)
            match = re.search(r"\brev\s*=\s*\"([0-9a-f]{40})\"", value)
            if match is None:
                fail(f"git dependency lacks exact 40-hex rev in {relative(manifest)}")
        parsed = tomllib.loads(text)
        defaults = parsed.get("features", {}).get("default", [])
        forbidden = {str(value) for value in defaults if any(
            token in str(value).lower() for token in ("unsafe", "test", "fuzz", "fault"))}
        if forbidden:
            fail(f"test/unsafe feature enabled by default in {relative(manifest)}: {sorted(forbidden)}")
    return len(manifests)


def npm_locks() -> tuple[int, int]:
    locks = release_files("package-lock.json", frozenset({".git", "node_modules", "target"}))
    if {relative(p) for p in locks} != set(NPM_INSTALL_SCRIPT_ALLOWLIST):
        fail("package-lock set differs from the reviewed release policy")
    entries = 0
    for lock in locks:
        data = json.loads(lock.read_text())
        if data.get("lockfileVersion") != 3:
            fail(f"unsupported npm lockfile version in {relative(lock)}")
        install_scripts: set[str] = set()
        for name, package in data.get("packages", {}).items():
            if not name or package.get("link"):
                continue
            entries += 1
            if package.get("hasInstallScript"):
                install_scripts.add(name)
            resolved = package.get("resolved")
            if resolved is not None:
                if not str(resolved).startswith("https://registry.npmjs.org/"):
                    fail(f"non-registry npm source in {relative(lock)}: {name}")
                if NPM_INTEGRITY.fullmatch(str(package.get("integrity", ""))) is None:
                    fail(f"npm package lacks canonical integrity in {relative(lock)}: {name}")
        expected = NPM_INSTALL_SCRIPT_ALLOWLIST[relative(lock)]
        if install_scripts != expected:
            fail(f"npm install-script set differs in {relative(lock)}: {sorted(install_scripts)}")
    return len(locks), entries


def main() -> None:
    cargo_lock_count, cargo_packages = cargo_locks()
    manifest_count = cargo_manifests()
    npm_lock_count, npm_entries = npm_locks()
    print(f"PASS: {cargo_lock_count} Cargo locks/{cargo_packages} entries, "
          f"{manifest_count} manifests and {npm_lock_count} npm locks/{npm_entries} entries are pinned")


if __name__ == "__main__":
    main()
