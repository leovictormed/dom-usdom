#!/usr/bin/env python3
"""Write or verify the complete deterministic USDOM source manifest."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"
EXCLUDED_DIRECTORIES = {
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
        if top in EXCLUDED_DIRECTORIES or top == "results" or top.startswith("results-stage"):
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


def digest(relative: Path, root: Path = ROOT) -> str:
    return hashlib.sha256((root / relative).read_bytes()).hexdigest()


def render(root: Path = ROOT, manifest: Path = MANIFEST) -> str:
    return "".join(
        f"{digest(path, root)}  {path.as_posix()}\n" for path in included_files(root, manifest)
    )


def verify(root: Path = ROOT, manifest: Path = MANIFEST, *, quiet: bool = False) -> None:
    if manifest.is_symlink() or not manifest.is_file():
        raise SystemExit("source manifest is missing")
    lines = manifest.read_text(encoding="utf-8").splitlines()
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
        continuation = root / "docs" / "CONTINUATION-STATE.md"
        continuation.write_text("mutable operational checkpoint\n", encoding="utf-8")
        assert continuation.relative_to(root) not in included_files(root, manifest)
        assert release_evidence.relative_to(root) not in included_files(root, manifest)
        assert operator_intent.relative_to(root) not in included_files(root, manifest)
        assert evidence.relative_to(root) not in included_files(root, manifest)
        assert production_requirements.relative_to(root) in included_files(root, manifest)
        manifest.write_text(render(root, manifest), encoding="utf-8")
        verify(root, manifest, quiet=True)

        (root / "a.txt").write_text("altered\n", encoding="utf-8")
        expect_failure(lambda: verify(root, manifest, quiet=True), "digest mismatch")
        (root / "a.txt").write_text("a\n", encoding="utf-8")
        verify(root, manifest, quiet=True)

        (root / "extra.txt").write_text("extra\n", encoding="utf-8")
        expect_failure(lambda: verify(root, manifest, quiet=True), "path set/order mismatch")
        (root / "extra.txt").unlink()

        os.symlink(root / "a.txt", root / "linked.txt")
        expect_failure(lambda: included_files(root, manifest), "symbolic link is forbidden")
    print("PASS: source manifest rejects tampering, extra paths and symbolic links")


def main(arguments: list[str]) -> None:
    if arguments == ["--write"]:
        MANIFEST.write_text(render(), encoding="utf-8")
        print(f"WROTE: {len(included_files())} source files to {MANIFEST}")
    elif arguments == ["--self-test"]:
        self_test()
    elif not arguments:
        verify()
    else:
        raise SystemExit("Usage: python3 scripts/source-manifest.py [--write|--self-test]")


if __name__ == "__main__":
    main(sys.argv[1:])
