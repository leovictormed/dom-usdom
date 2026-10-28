#!/usr/bin/env python3
"""Validate the exact Git index intended for a public DOM/USD0M commit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

EXPECTED_NAME = "Soren Planck"
EXPECTED_EMAIL = "sorenplanck@tutamail.com"
FORBIDDEN_COMPONENTS = {
    ".codex", ".agents", "node_modules", "target", "out", "out-fork",
    "cache-fork", "broadcast", "private-evidence", "operator-evidence",
    "secrets", "secret", "credentials",
}
FORBIDDEN_SUFFIXES = {
    ".age", ".auth", ".bak", ".gpg", ".jks", ".key", ".kdbx",
    ".keystore", ".log", ".mnemonic", ".old", ".orig", ".p12",
    ".pem", ".pfx", ".rej", ".save", ".seed", ".secret", ".tmp",
    ".token", ".wif",
}
LICENSE_NAMES = {"license", "license.md", "license.txt", "copying", "notice"}
ALLOWED_DEPENDENCY_LICENSES = {
    "labs/usdom-reserve/node_modules/@walletconnect/sign-client/LICENSE.md",
}


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args])


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def index_paths(repo: Path) -> tuple[set[str], list[str], bytes]:
    raw_index = git(repo, "ls-files", "--stage", "-z")
    entries = raw_index.split(b"\0")
    paths: set[str] = set()
    errors: list[str] = []
    for entry in entries:
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        _mode, _object, stage = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8", errors="strict")
        if stage != "0":
            fail(errors, f"unmerged index entry: {path}")
        paths.add(path)
    return paths, errors, raw_index


def forbidden_path(path: str) -> bool:
    if path in ALLOWED_DEPENDENCY_LICENSES:
        return False
    parts = PurePosixPath(path).parts
    lower_parts = tuple(part.lower() for part in parts)
    if any(part in FORBIDDEN_COMPONENTS or part.startswith("results-stage")
           for part in lower_parts):
        return True
    if "results" in lower_parts:
        return True
    if len(lower_parts) >= 2 and lower_parts[-2:] == ("docs", "continuation-state.md"):
        return True
    name = lower_parts[-1]
    if name in {".env", ".netrc", ".npmrc", "wallet.dat", "cookie", ".cookie"}:
        return True
    if name.startswith(".env.") and not name.endswith(".example"):
        return True
    return any(name.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES)


def inventory_sources(repo: Path) -> set[str]:
    inventory_path = repo / "labs/usdom-reserve/config/rebuild-v3-critical-source-inventory.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    prefix = "labs/usdom-reserve/"
    required = {prefix + path for path in inventory["criticalSources"]}
    required.add(prefix + "config/rebuild-v3-critical-source-inventory.json")
    return required


def vendor_roots(paths: set[str]) -> set[str]:
    roots: set[str] = set()
    for path in paths:
        parts = PurePosixPath(path).parts
        for index, part in enumerate(parts[:-1]):
            if part == "vendor" and index + 1 < len(parts):
                roots.add("/".join(parts[:index + 2]))
                break
    return roots


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args()
    repo = Path(git(args.root.resolve(), "rev-parse", "--show-toplevel").decode().strip())
    paths, errors, raw_index = index_paths(repo)

    for path in sorted(paths):
        if forbidden_path(path):
            fail(errors, f"local/private path is indexed for publication: {path}")

    required = {"LICENSE", "Cargo.toml", "Cargo.lock", ".gitignore"} | inventory_sources(repo)
    for path in sorted(required - paths):
        fail(errors, f"required source or license is absent from index: {path}")

    for root in sorted(vendor_roots(paths)):
        direct_files = {
            PurePosixPath(path).name.lower()
            for path in paths
            if PurePosixPath(path).parent.as_posix() == root
        }
        if not (direct_files & LICENSE_NAMES):
            fail(errors, f"vendored package lacks an indexed top-level license: {root}")

    name = git(repo, "config", "user.name").decode().strip()
    email = git(repo, "config", "user.email").decode().strip()
    if (name, email) != (EXPECTED_NAME, EXPECTED_EMAIL):
        fail(errors, f"Git identity must be exactly {EXPECTED_NAME} <{EXPECTED_EMAIL}>")

    # This digest is stable for the exact index and can be reviewed before a
    # local commit without creating a commit or invoking a remote operation.
    import hashlib
    package_digest = hashlib.sha256(raw_index).hexdigest()

    for error in errors:
        print(f"publication package rejected: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"PUBLICATION_PACKAGE = PASS files={len(paths)} indexPackageSha256={package_digest}")
    print("PUSH = DISABLED (this checker has no remote operation)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
