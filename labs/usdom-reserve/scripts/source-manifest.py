#!/usr/bin/env python3
"""Write or verify the complete deterministic USDOM source manifest."""

from __future__ import annotations

import hashlib
import errno
import os
import re
import stat
import sys
import tempfile
import secrets
from unittest.mock import patch
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"
EXCLUDED_DIRECTORIES = {
    "__pycache__",
    "cache",
    "cache-fork",
    "evidence",
    "node_modules",
    "out",
    "out-fork",
}
EXCLUDED_FILES = {
    "config/mainnet-release-evidence.unconfigured.json",
    "config/operator-intent.json",
    "docs/CONTINUATION-STATE.md",
}
LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")


def included_files(root: Path = ROOT, manifest: Path = MANIFEST) -> list[Path]:
    result: list[Path] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        top = relative.parts[0]
        if (
            top in EXCLUDED_DIRECTORIES
            or "__pycache__" in relative.parts[:-1]
            or top == "results"
            or top.startswith("results-stage")
        ):
            continue
        if relative.as_posix() in EXCLUDED_FILES:
            continue
        if path == manifest:
            continue
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise SystemExit(f"symbolic link is forbidden in source manifest scope: {relative!s}")
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise SystemExit(f"non-regular file is forbidden in source manifest scope: {relative!s}")
        if "\n" in relative.as_posix() or "\r" in relative.as_posix():
            raise SystemExit(f"unsupported newline in source path: {relative!s}")
        result.append(relative)
    return sorted(result, key=lambda value: value.as_posix().encode())


def validate_relative(relative: Path) -> str:
    name = relative.as_posix()
    if (
        relative.is_absolute()
        or name in {"", "."}
        or "\\" in name
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise SystemExit(f"invalid source manifest path: {name}")
    return name


def open_beneath(root: Path, relative: Path) -> tuple[int, int, list[int]]:
    """Open a file beneath a stable root without following any path component."""
    name = validate_relative(relative)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow | cloexec
    opened: list[int] = []
    try:
        parent = os.open(root, directory_flags)
        opened.append(parent)
        for component in relative.parts[:-1]:
            parent = os.open(component, directory_flags, dir_fd=parent)
            opened.append(parent)
        descriptor = os.open(relative.parts[-1], os.O_RDONLY | nofollow | cloexec, dir_fd=parent)
    except OSError as error:
        for opened_descriptor in reversed(opened):
            os.close(opened_descriptor)
        if error.errno in {errno.ELOOP, errno.EMLINK, errno.ENOTDIR}:
            raise SystemExit(f"symbolic link is forbidden in source manifest scope: {name}") from error
        raise SystemExit(f"source manifest file cannot be opened directly: {name}") from error
    return descriptor, parent, opened


def direct_bytes(relative: Path, root: Path = ROOT) -> bytes:
    name = validate_relative(relative)
    descriptor, parent, opened = open_beneath(root, relative)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SystemExit(f"non-regular file is forbidden in source manifest scope: {name}")
        if before.st_nlink != 1:
            raise SystemExit(f"hard-linked file is forbidden in source manifest scope: {name}")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size,
                           before.st_mtime_ns, before.st_ctime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size,
                          after.st_mtime_ns, after.st_ctime_ns)
        if identity_after != identity_before:
            raise SystemExit(f"source manifest file changed while hashing: {name}")
        try:
            path_after = os.stat(relative.parts[-1], dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            raise SystemExit(f"source manifest path changed while hashing: {name}") from error
        if (not stat.S_ISREG(path_after.st_mode)
                or (path_after.st_dev, path_after.st_ino) != (before.st_dev, before.st_ino)):
            raise SystemExit(f"source manifest path changed while hashing: {name}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)
        for opened_descriptor in reversed(opened):
            os.close(opened_descriptor)


def digest(relative: Path, root: Path = ROOT) -> str:
    """Hash one canonical in-root regular file without following substitutions."""
    return hashlib.sha256(direct_bytes(relative, root)).hexdigest()


def write_manifest(content: str, root: Path = ROOT, manifest: Path = MANIFEST) -> None:
    relative = manifest.relative_to(root)
    if len(relative.parts) != 1:
        raise SystemExit("source manifest must be a direct child of its root")
    root_descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                              | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    temporary = f".MANIFEST.sha256.{secrets.token_hex(12)}"
    descriptor = None
    try:
        try:
            existing = os.stat(relative.name, dir_fd=root_descriptor, follow_symlinks=False)
            if not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1:
                raise SystemExit("source manifest target is not a direct singly-linked regular file")
        except FileNotFoundError:
            pass
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=root_descriptor)
        payload = content.encode("utf-8")
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, relative.name, src_dir_fd=root_descriptor, dst_dir_fd=root_descriptor)
        os.fsync(root_descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=root_descriptor)
        except FileNotFoundError:
            pass
        os.close(root_descriptor)


def render_paths(paths: list[Path], root: Path = ROOT, manifest: Path = MANIFEST) -> str:
    rendered = "".join(f"{digest(path, root)}  {path.as_posix()}\n" for path in paths)
    if included_files(root, manifest) != paths:
        raise SystemExit("source manifest path set changed while hashing")
    return rendered


def render(root: Path = ROOT, manifest: Path = MANIFEST) -> str:
    return render_paths(included_files(root, manifest), root, manifest)


def verify(root: Path = ROOT, manifest: Path = MANIFEST, *, quiet: bool = False) -> None:
    try:
        manifest_relative = manifest.relative_to(root)
    except ValueError as error:
        raise SystemExit("source manifest is outside its root") from error
    try:
        lines = direct_bytes(manifest_relative, root).decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise SystemExit("source manifest is not UTF-8") from error
    parsed: list[tuple[str, str]] = []
    for number, line in enumerate(lines, 1):
        match = LINE.fullmatch(line)
        if match is None:
            raise SystemExit(f"malformed source manifest line {number}")
        parsed.append((match.group(1), match.group(2)))
    names = [name for _, name in parsed]
    expected_names = [path.as_posix() for path in included_files(root, manifest)]
    if names != expected_names:
        missing = sorted(set(expected_names) - set(names))
        extra = sorted(set(names) - set(expected_names))
        raise SystemExit(f"source manifest path set/order mismatch: missing={missing}, extra={extra}")
    for expected_digest, name in parsed:
        actual = digest(Path(name), root)
        if actual != expected_digest:
            raise SystemExit(f"source manifest digest mismatch: {name}")
    if [path.as_posix() for path in included_files(root, manifest)] != expected_names:
        raise SystemExit("source manifest path set changed while hashing")
    if not quiet:
        print(f"PASS: {len(parsed)} source files are complete, ordered and SHA-256 verified")


def expect_failure(callable_, expected: str) -> None:
    try:
        callable_()
    except SystemExit as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"expected failure containing {expected!r}")


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        manifest = root / "MANIFEST.sha256"
        (root / "docs").mkdir()
        (root / "config").mkdir()
        (root / "evidence").mkdir()
        (root / "a.txt").write_text("a\n", encoding="utf-8")
        (root / "docs" / "b.txt").write_text("b\n", encoding="utf-8")
        production_requirements = root / "config" / "production-requirements.json"
        production_requirements.write_text("{}\n", encoding="utf-8")
        release_evidence = root / "config" / "mainnet-release-evidence.unconfigured.json"
        release_evidence.write_text("{}\n", encoding="utf-8")
        operator_intent = root / "config" / "operator-intent.json"
        operator_intent.write_text("{}\n", encoding="utf-8")
        evidence = root / "evidence" / "attestation.json"
        evidence.write_text("{}\n", encoding="utf-8")
        bytecode_cache = root / "scripts" / "__pycache__"
        bytecode_cache.mkdir(parents=True)
        cached_bytecode = bytecode_cache / "source-manifest.cpython-312.pyc"
        cached_bytecode.write_bytes(b"regenerable bytecode\n")
        continuation = root / "docs" / "CONTINUATION-STATE.md"
        continuation.write_text("mutable operational checkpoint\n", encoding="utf-8")
        assert continuation.relative_to(root) not in included_files(root, manifest)
        assert release_evidence.relative_to(root) not in included_files(root, manifest)
        assert operator_intent.relative_to(root) not in included_files(root, manifest)
        assert evidence.relative_to(root) not in included_files(root, manifest)
        assert cached_bytecode.relative_to(root) not in included_files(root, manifest)
        assert production_requirements.relative_to(root) in included_files(root, manifest)
        manifest.write_text(render(root, manifest), encoding="utf-8")
        verify(root, manifest, quiet=True)

        saved_manifest = root / "saved-manifest"
        manifest.rename(saved_manifest)
        os.symlink(saved_manifest, manifest)
        expect_failure(lambda: verify(root, manifest, quiet=True), "symbolic link is forbidden")
        expect_failure(lambda: write_manifest("invalid\n", root, manifest), "not a direct singly-linked")
        manifest.unlink()
        saved_manifest.rename(manifest)

        real_directory = root / "real-directory"
        real_directory.mkdir()
        (real_directory / "nested.txt").write_text("nested\n", encoding="utf-8")
        os.symlink(real_directory, root / "linked-directory")
        expect_failure(lambda: digest(Path("linked-directory/nested.txt"), root),
                       "symbolic link is forbidden")
        (root / "linked-directory").unlink()
        (real_directory / "nested.txt").unlink()
        real_directory.rmdir()

        (root / "a.txt").write_text("altered\n", encoding="utf-8")
        expect_failure(lambda: verify(root, manifest, quiet=True), "digest mismatch")
        (root / "a.txt").write_text("a\n", encoding="utf-8")
        verify(root, manifest, quiet=True)

        (root / "extra.txt").write_text("extra\n", encoding="utf-8")
        expect_failure(lambda: verify(root, manifest, quiet=True), "path set/order mismatch")
        (root / "extra.txt").unlink()

        os.symlink(root / "a.txt", root / "linked.txt")
        expect_failure(lambda: included_files(root, manifest), "symbolic link is forbidden")
        expect_failure(lambda: digest(Path("linked.txt"), root), "symbolic link is forbidden")
        expect_failure(lambda: digest(Path("../outside.txt"), root), "invalid source manifest path")
        (root / "linked.txt").unlink()

        enumerated = included_files(root, manifest)
        (root / "late.txt").write_text("late\n", encoding="utf-8")
        expect_failure(lambda: render_paths(enumerated, root, manifest), "path set changed")
        (root / "late.txt").unlink()

        os.link(root / "a.txt", root / "hardlinked.txt")
        expect_failure(lambda: digest(Path("hardlinked.txt"), root), "hard-linked file is forbidden")
        (root / "hardlinked.txt").unlink()

        original_read = os.read
        renamed = root / "renamed-a.txt"
        replaced = False

        def replace_path(descriptor: int, count: int) -> bytes:
            nonlocal replaced
            if not replaced:
                replaced = True
                (root / "a.txt").rename(renamed)
                (root / "a.txt").write_text("replacement\n", encoding="utf-8")
            return original_read(descriptor, count)

        with patch("os.read", side_effect=replace_path):
            expect_failure(lambda: digest(Path("a.txt"), root), "changed while hashing")
    print("PASS: source manifest rejects tampering, extra paths and symbolic links")


def main(arguments: list[str]) -> None:
    if arguments == ["--write"]:
        write_manifest(render())
        print(f"WROTE: {len(included_files())} source files to {MANIFEST}")
    elif arguments == ["--self-test"]:
        self_test()
    elif not arguments:
        verify()
    else:
        raise SystemExit("Usage: python3 scripts/source-manifest.py [--write|--self-test]")


if __name__ == "__main__":
    main(sys.argv[1:])
