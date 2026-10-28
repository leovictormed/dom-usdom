#!/usr/bin/env python3
"""Bind every USDOM source-manifest entry to an exact blob in a Git tree."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess


LINE = re.compile(rb"^([0-9a-f]{64})  ([^\r\n]+)$")
OID = re.compile(rb"^[0-9a-f]{40}$")


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def begin_blob(process: subprocess.Popen[bytes], specification: str, *, limit: int) -> int:
    assert process.stdin is not None and process.stdout is not None
    process.stdin.write(specification.encode("utf-8") + b"\n")
    process.stdin.flush()
    header = process.stdout.readline(4096)
    if not header or header.endswith(b" missing\n"):
        fail(f"release tree lacks source-manifest blob: {specification}")
    fields = header.rstrip(b"\n").split(b" ")
    if len(fields) != 3 or not OID.fullmatch(fields[0]) or fields[1] != b"blob":
        fail(f"invalid Git object response for source-manifest blob: {specification}")
    try:
        size = int(fields[2])
    except ValueError:
        fail(f"invalid Git object size for source-manifest blob: {specification}")
    if size < 0 or size > limit:
        fail(f"source-manifest blob exceeds bound: {specification}")
    return size


def read_blob(process: subprocess.Popen[bytes], specification: str, *, limit: int) -> bytes:
    assert process.stdout is not None
    size = begin_blob(process, specification, limit=limit)
    payload = process.stdout.read(size)
    if len(payload) != size or process.stdout.read(1) != b"\n":
        fail(f"truncated Git object response for source-manifest blob: {specification}")
    return payload


def hash_blob(process: subprocess.Popen[bytes], specification: str, *, limit: int) -> bytes:
    assert process.stdout is not None
    remaining = begin_blob(process, specification, limit=limit)
    digest = hashlib.sha256()
    while remaining:
        chunk = process.stdout.read(min(1024 * 1024, remaining))
        if not chunk:
            fail(f"truncated Git object response for source-manifest blob: {specification}")
        digest.update(chunk)
        remaining -= len(chunk)
    if process.stdout.read(1) != b"\n":
        fail(f"truncated Git object response for source-manifest blob: {specification}")
    return digest.hexdigest().encode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--project-relative", required=True)
    arguments = parser.parse_args()
    if not os.path.isabs(arguments.git) or not os.path.isfile(arguments.git):
        fail("Git executable is not an absolute regular file")
    if not re.fullmatch(r"[0-9a-f]{40}", arguments.tree):
        fail("release tree is not a canonical Git OID")
    prefix = arguments.project_relative.strip("/")
    if not prefix or prefix != arguments.project_relative or ".." in prefix.split("/"):
        fail("invalid release project path")
    process = subprocess.Popen(
        [arguments.git, "-C", arguments.repository, "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"},
    )
    try:
        manifest = read_blob(
            process, f"{arguments.tree}:{prefix}/MANIFEST.sha256", limit=8 * 1024 * 1024
        )
        entries: list[tuple[bytes, str]] = []
        seen: set[str] = set()
        for number, line in enumerate(manifest.splitlines(), 1):
            match = LINE.fullmatch(line)
            if match is None:
                fail(f"malformed release-tree source manifest line {number}")
            name = match.group(2).decode("utf-8", "strict")
            parts = name.split("/")
            if name in {"", "."} or name.startswith("/") or "\\" in name \
                    or any(part in {"", ".", ".."} for part in parts) or name in seen:
                fail(f"invalid release-tree source manifest path: {name}")
            seen.add(name)
            entries.append((match.group(1), name))
        if not entries or len(entries) > 10_000:
            fail("release-tree source manifest entry count is invalid")
        for expected, name in entries:
            observed = hash_blob(
                process, f"{arguments.tree}:{prefix}/{name}", limit=512 * 1024 * 1024
            )
            if observed != expected:
                fail(f"release-tree source manifest digest mismatch: {name}")
        assert process.stdin is not None
        process.stdin.close()
        if process.wait(timeout=10) != 0:
            stderr = process.stderr.read().decode("utf-8", "replace") if process.stderr else ""
            fail(f"Git object reader failed: {stderr}")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    print(f"PASS: {len(entries)} source-manifest blobs are present in the inspected release tree")


if __name__ == "__main__":
    main()
