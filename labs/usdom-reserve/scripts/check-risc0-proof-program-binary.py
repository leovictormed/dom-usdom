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

ROOT = Path(__file__).resolve().parents[3]
ARTIFACTS = (
    ("randomx", "crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.bin", "0601bf022575b060edaeb0b32414b2f53e72f39d2284028069099414653591dd", "8efa49d4fe0f616840013adb1d3029ef71642099cb336c577a2691f7eea1dc24"),
    ("randomx-aggregate", "crates/dom-usdom-randomx-aggregate-risc0-guest/elfs/usdom-randomx-aggregate.bin", "3dad95bf467a807c7ef033f88595ea44f14578dca4c7558ad95b7ad76c0d198f", "08abf768e699ecb9d5cd2abc7603368103bcd3ee61afe9066d8a77272ac02ebf"),
    ("economic-chunk", "crates/dom-usdom-economic-chunk-risc0-guest/elfs/usdom-economic-chunk.bin", "5e7bc30f65ab4eae7c8b19a8c1c386cd023cd648c85f64008be2bd4729231842", "67d286e04444b52305ec409de3c0d22b2131a42f2aa6706f087ace253048e350"),
    ("economic-block", "crates/dom-usdom-economic-block-risc0-guest/elfs/usdom-economic-block.bin", "e16e6aea7d470baad85bec45578e0960c02c2d47bce267e26141a2f3fa4a6c1f", "03dc111fee3c42a772f142c80d4a921a19bde10f932f86c888606503a28c22a7"),
    ("checkpoint-segment", "crates/dom-usdom-checkpoint-segment-risc0-guest/elfs/usdom-checkpoint-segment.bin", "c4cc41b0b53d787c46b9293d1515c2d0c4ded982c3ae7b98d33877dd142d2b38", "4e711490f3ab7dde97636687972456da58da4287ce5017e38d4acaa7263a02d6"),
    ("checkpoint-outer", "crates/dom-usdom-checkpoint-outer-risc0-guest/elfs/usdom-checkpoint-outer.bin", "8f9d0f1753172a9c1d3be22d105d08ea890cd566f18a81fb54c557f620f59b09", "e59d68487386939b2ac379f04528acb6b3138697e17adfda3ad23ebe195af3df"),
    # Legacy suffix; this is the packaged ProgramBinary used by the host.
    ("finalized-burn", "crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.elf", "883ec39b03e3a0703e592026fc7d92a15ce7d949cb937551c5dd8360184cde21", "2e26f74497b54b680dfff4c116d56280d016f01d0125329f49bf6d744b1c18ea"),
)
MAX_PROGRAM_BYTES = 128 * 1024 * 1024


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decoder", type=Path, default=ROOT / "target/debug/dom-risc0-program-packager")
    args = parser.parse_args()
    decoder = args.decoder.resolve(strict=True)
    decoder_stat = decoder.stat()
    if not stat.S_ISREG(decoder_stat.st_mode) or decoder_stat.st_nlink != 1 or not os.access(decoder, os.X_OK):
        raise ValueError("decoder must be a direct executable regular file")
    for name, relative, expected_sha, expected_iid in ARTIFACTS:
        path = ROOT / relative
        data = captured(path)
        actual_sha = hashlib.sha256(data).hexdigest()
        if actual_sha != expected_sha:
            raise ValueError(f"{name}: SHA-256 mismatch")
        result = subprocess.run(
            [decoder, "--verify", path, expected_iid],
            cwd=ROOT, check=True, capture_output=True, text=True,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        if result.stdout != expected_iid + "\n" or result.stderr:
            raise ValueError(f"{name}: noncanonical decoder output")
        print(f"ok {name} sha256={actual_sha} image_id={expected_iid}")
    print(f"verified {len(ARTIFACTS)}/{len(ARTIFACTS)} ProgramBinary artifacts")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"program-binary check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
