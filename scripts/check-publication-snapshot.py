#!/usr/bin/env python3
"""Fail closed when a public Git snapshot contains local/private artifacts."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from urllib.parse import urlsplit

SENSITIVE_NAMES = {
    ".env", ".netrc", ".npmrc", "authorized_keys", "id_dsa", "id_ecdsa",
    "id_ed25519", "id_rsa", "wallet.dat", "debug.log", "cookie", ".cookie",
}
SENSITIVE_SUFFIXES = (
    ".age", ".auth", ".bak", ".credential", ".credentials", ".gpg", ".jks",
    ".der", ".key", ".kdbx", ".keystore", ".mnemonic", ".old", ".orig",
    ".ovpn", ".p12", ".pem", ".pfx", ".rej", ".save", ".seed", ".secret",
    ".swp", ".swo", ".tmp", ".token", ".wif", "~",
)
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(rb"(?i)\b(?:private[_-]?key|secret[_-]?key|seed[_-]?phrase|mnemonic|bearer[_-]?token)\s*[:=]\s*['\"]?(?:0x)?[0-9a-f]{64}\b"),
    re.compile(rb'(?is)"crypto"\s*:\s*\{.{0,8192}"ciphertext"\s*:\s*"[0-9a-f]{32,}"'),
)
LOCAL_ONLY_COMPONENTS = {
    "__pycache__", ".codex", ".agents", "node_modules", "target",
}


def local_only_path(relative: str) -> bool:
    parts = Path(relative).parts
    if any(part in LOCAL_ONLY_COMPONENTS or part.startswith("results-stage") for part in parts):
        return True
    # These are generated USDOM laboratory roots, but names such as `cache`
    # are also legitimate source-module names in vendored implementations.
    if any(part in {"cache", "cache-fork", "out", "out-fork"} for part in parts):
        if parts[0] in {"cache", "cache-fork", "out", "out-fork"} \
                or parts[:2] == ("labs", "usdom-reserve"):
            return True
    if "results" in parts:
        return True
    return len(parts) >= 2 and parts[-2:] == ("docs", "CONTINUATION-STATE.md")


def fail(message: str) -> None:
    print(f"publication snapshot rejected: {message}", file=sys.stderr)


def inspect(root: Path, verify_index: bool) -> list[str]:
    errors: list[str] = []
    root = root.resolve(strict=True)
    expected: set[str] = set()
    uid = os.getuid()
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        relative_directory = Path(directory).relative_to(root)
        if relative_directory == Path(".git"):
            names.clear(); files.clear(); continue
        if ".git" in names:
            names.remove(".git")
        for name in list(names) + files:
            path = Path(directory, name)
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if local_only_path(relative):
                errors.append(f"local-only path is not publishable: {relative}")
                if name in names:
                    names.remove(name)
                continue
            if stat.S_ISLNK(metadata.st_mode):
                errors.append(f"symbolic link is not publishable: {relative}")
                if name in names: names.remove(name)
                continue
            if metadata.st_uid != uid:
                errors.append(f"path is not owned by the publisher: {relative}")
            if metadata.st_mode & 0o022:
                errors.append(f"group/world-writable path: {relative}")
            if name in files:
                if not stat.S_ISREG(metadata.st_mode):
                    errors.append(f"non-regular file: {relative}")
                    continue
                expected.add(relative)
                if metadata.st_nlink != 1:
                    errors.append(f"multiply-linked file is not publishable: {relative}")
                if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
                    errors.append(f"special permission bits on file: {relative}")
                executable = metadata.st_mode & 0o111
                if executable:
                    with path.open("rb") as source:
                        first_line = source.readline(4096)
                    if not (first_line.startswith(b"#!") or first_line.startswith(b"\x7fELF")):
                        errors.append(f"executable file lacks a shebang or ELF header: {relative}")
                lower = name.lower()
                if (lower in SENSITIVE_NAMES
                        or (lower.startswith(".env.") and not lower.endswith(".example"))
                        or lower.endswith(SENSITIVE_SUFFIXES)):
                    errors.append(f"sensitive/local filename: {relative}")
                if metadata.st_size >= 95 * 1024 * 1024:
                    errors.append(f"oversized file ({metadata.st_size} bytes): {relative}")
                    # Do not turn a rejection into an avoidable unbounded read.
                    continue
                data = path.read_bytes()
                for pattern in SECRET_PATTERNS:
                    if pattern.search(data):
                        errors.append(f"secret-shaped content: {relative}")
                        break
                text = data.decode("utf-8", errors="ignore")
                for raw in re.findall(r'https?://[^\s"\'<>\\`]+', text):
                    try:
                        parsed = urlsplit(raw.rstrip("),.;"))
                    except ValueError:
                        # A malformed public URL is not a credential finding.
                        # Fail closed only when its authority is credential-shaped.
                        authority = raw.split("://", 1)[-1].split("/", 1)[0]
                        if "@" in authority:
                            errors.append(f"malformed credential-bearing URL: {relative}")
                        continue
                    if parsed.username is None and parsed.password is None:
                        continue
                    host = (parsed.hostname or "").lower()
                    if host not in {"localhost", "127.0.0.1", "::1", "host"} \
                            and not host.endswith((".example", ".invalid")):
                        errors.append(f"credential-bearing URL: {relative}")
    if verify_index:
        indexed = set(subprocess.check_output(
            ["git", "-C", str(root), "ls-files", "-z"], text=False
        ).decode("utf-8").rstrip("\0").split("\0"))
        indexed.discard("")
        for relative in sorted(expected - indexed):
            errors.append(f"snapshot file is outside the Git index: {relative}")
        for relative in sorted(indexed - expected):
            errors.append(f"Git index entry is outside the inspected snapshot: {relative}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--verify-git-index", action="store_true")
    args = parser.parse_args()
    errors = inspect(args.root, args.verify_git_index)
    for error in errors:
        fail(error)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
