#!/usr/bin/env python3
"""Decode and identify every ProgramBinary consumed by a DOM RISC Zero prover."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
ARTIFACTS = (
    ("randomx", "crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.bin", "0601bf022575b060edaeb0b32414b2f53e72f39d2284028069099414653591dd", "8efa49d4fe0f616840013adb1d3029ef71642099cb336c577a2691f7eea1dc24"),
    ("randomx-aggregate", "crates/dom-usdom-randomx-aggregate-risc0-guest/elfs/usdom-randomx-aggregate.bin", "3dad95bf467a807c7ef033f88595ea44f14578dca4c7558ad95b7ad76c0d198f", "08abf768e699ecb9d5cd2abc7603368103bcd3ee61afe9066d8a77272ac02ebf"),
    ("economic-chunk", "crates/dom-usdom-economic-chunk-risc0-guest/elfs/usdom-economic-chunk.bin", "5e7bc30f65ab4eae7c8b19a8c1c386cd023cd648c85f64008be2bd4729231842", "67d286e04444b52305ec409de3c0d22b2131a42f2aa6706f087ace253048e350"),
    ("economic-block", "crates/dom-usdom-economic-block-risc0-guest/elfs/usdom-economic-block.bin", "e16e6aea7d470baad85bec45578e0960c02c2d47bce267e26141a2f3fa4a6c1f", "03dc111fee3c42a772f142c80d4a921a19bde10f932f86c888606503a28c22a7"),
    ("checkpoint-segment", "crates/dom-usdom-checkpoint-segment-risc0-guest/elfs/usdom-checkpoint-segment.bin", "426cc782490b8d680e5bd2266cc4a03b3e731194d92eda44875ea5d552cb5f74", "371e408b360a0e4a0aae2cb994bddb2d66afcc5891a7ed574fa83119734bfbf7"),
    ("checkpoint-outer", "crates/dom-usdom-checkpoint-outer-risc0-guest/elfs/usdom-checkpoint-outer.bin", "ee707b6a1d2a135656ef9ee93a13487b6e1c24bafba8c66e9215708e184b9a90", "311d58dadcb97cac783e3ec0efe3c4570f42b944cbda1e48aeb56b055682257b"),
    # Legacy suffix; this is the packaged ProgramBinary used by the host.
    ("finalized-burn", "crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.elf", "bf3202187d7c0643204bcb936b34a53b41b871cc4d633781dc96956c7de9d511", "f0d9c98287719bf6fca6626ab96f0b14e305662873a9e3b5d4894a50f206a1ae"),
)
MAX_PROGRAM_BYTES = 128 * 1024 * 1024
MAX_DECODER_BYTES = 64 * 1024 * 1024
DECODER_SHA256 = "d2569a1dcbc3fc526edb6d8754323cda7cf9c3743b8549c96a989a7df3f0bacd"


def captured(path: Path) -> bytes:
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError(f"ineligible ProgramBinary: {path}")
    if before.st_size <= 0 or before.st_size > MAX_PROGRAM_BYTES:
        raise ValueError(f"invalid ProgramBinary size: {path}")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_nlink) != (before.st_dev, before.st_ino, 1):
            raise ValueError(f"ProgramBinary changed while opening: {path}")
        data = stream.read(MAX_PROGRAM_BYTES + 1)
        after = os.fstat(stream.fileno())
    if len(data) != before.st_size or len(data) > MAX_PROGRAM_BYTES or (after.st_dev, after.st_ino, after.st_size, after.st_nlink) != (before.st_dev, before.st_ino, before.st_size, 1):
        raise ValueError(f"ProgramBinary changed while reading: {path}")
    return data


def snapshot_decoder(path: Path, directory: Path) -> Path:
    """Copy a stable executable inode into a private, single-link snapshot.

    Cargo intentionally hardlinks `target/debug/<binary>` to its hashed entry in
    `target/debug/deps`. Rejecting every multi-link source therefore made the
    release gate fail permanently. We instead authenticate a stable read of the
    direct regular file, then execute only an owner-private O_EXCL copy whose
    link count is exactly one.
    """
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    source_fd = os.open(path, flags)
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink < 1 or before.st_mode & 0o100 == 0:
            raise ValueError("decoder must be a direct executable regular file")
        if before.st_uid != os.geteuid() or before.st_mode & 0o022:
            raise ValueError("decoder ownership or write permissions are unsafe")
        if before.st_size <= 0 or before.st_size > MAX_DECODER_BYTES:
            raise ValueError("decoder size is invalid")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(source_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError("decoder was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(source_fd, 1):
            raise ValueError("decoder grew while reading")
        after = os.fstat(source_fd)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            raise ValueError("decoder changed while reading")
    finally:
        os.close(source_fd)

    snapshot = directory / "dom-risc0-program-packager"
    destination_fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o500)
    try:
        payload = b"".join(chunks)
        if hashlib.sha256(payload).hexdigest() != DECODER_SHA256:
            raise ValueError("decoder SHA-256 differs from the source-controlled release pin")
        written = 0
        while written < len(payload):
            count = os.write(destination_fd, payload[written:])
            if count <= 0:
                raise ValueError("decoder snapshot write failed")
            written += count
        os.fsync(destination_fd)
        copied = os.fstat(destination_fd)
        if not stat.S_ISREG(copied.st_mode) or copied.st_nlink != 1 or copied.st_size != before.st_size:
            raise ValueError("decoder snapshot is not a single-link regular file")
    finally:
        os.close(destination_fd)
    return snapshot


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decoder", type=Path, default=ROOT / "target/debug/dom-risc0-program-packager")
    args = parser.parse_args()
    decoder = args.decoder.absolute()
    with tempfile.TemporaryDirectory(prefix="usdom-risc0-decoder-") as temporary:
        private_directory = Path(temporary)
        os.chmod(private_directory, 0o700)
        decoder_snapshot = snapshot_decoder(decoder, private_directory)
        for name, relative, expected_sha, expected_iid in ARTIFACTS:
            path = ROOT / relative
            data = captured(path)
            actual_sha = hashlib.sha256(data).hexdigest()
            if actual_sha != expected_sha:
                raise ValueError(f"{name}: SHA-256 mismatch")
            result = subprocess.run(
                [decoder_snapshot, "--verify", path, expected_iid],
                cwd=ROOT, check=True, capture_output=True, text=True,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                timeout=30,
            )
            if result.stdout != expected_iid + "\n" or result.stderr:
                raise ValueError(f"{name}: noncanonical decoder output")
            print(f"ok {name} sha256={actual_sha} image_id={expected_iid}")
    print(f"verified {len(ARTIFACTS)}/{len(ARTIFACTS)} ProgramBinary artifacts")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.TimeoutExpired as error:
        print(f"program-binary check timed out: {error}", file=sys.stderr)
        raise SystemExit(1)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"program-binary check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
