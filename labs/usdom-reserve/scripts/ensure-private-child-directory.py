#!/usr/bin/env python3
"""Create or verify one owner-only directory below a pinned private root."""

import os
import stat
import sys


def fail(message: str) -> None:
    raise RuntimeError(message)


def directory_identity(fd: int) -> tuple[int, int, int, int]:
    metadata = os.fstat(fd)
    if not stat.S_ISDIR(metadata.st_mode):
        fail("private directory authority is not a directory")
    return metadata.st_dev, metadata.st_ino, metadata.st_uid, stat.S_IMODE(metadata.st_mode)


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: ensure-private-child-directory.py ABSOLUTE_PRIVATE_ROOT CHILD_NAME")
    root, child = sys.argv[1:]
    if not os.path.isabs(root) or os.path.normpath(root) != root:
        fail("private directory root must be an absolute normalized path")
    if child in ("", ".", "..") or os.sep in child or (os.altsep and os.altsep in child):
        fail("private child must be one path component")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    root_fd = os.open(root, flags)
    try:
        root_identity = directory_identity(root_fd)
        if root_identity[2] != os.geteuid() or root_identity[3] != 0o700:
            fail("private directory root must be owned by the caller with mode 0700")
        if os.path.realpath(f"/proc/self/fd/{root_fd}") != root:
            fail("private directory root must be one canonical direct directory")
        try:
            os.mkdir(child, 0o700, dir_fd=root_fd)
            os.fsync(root_fd)
        except FileExistsError:
            pass
        child_fd = os.open(child, flags, dir_fd=root_fd)
        try:
            child_identity = directory_identity(child_fd)
            if child_identity[2] != os.geteuid() or child_identity[3] != 0o700:
                fail("private child directory must be owned by the caller with mode 0700")
            expected = os.path.join(root, child)
            if os.path.realpath(f"/proc/self/fd/{child_fd}") != expected:
                fail("private child directory must be one canonical direct directory")
            root_after = directory_identity(root_fd)
            if root_after != root_identity or os.path.realpath(f"/proc/self/fd/{root_fd}") != root:
                fail("private directory root changed during creation")
            named = os.stat(child, dir_fd=root_fd, follow_symlinks=False)
            if (named.st_dev, named.st_ino, named.st_uid, stat.S_IMODE(named.st_mode)) != child_identity:
                fail("private child directory changed during creation")
        finally:
            os.close(child_fd)
    finally:
        os.close(root_fd)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        print(f"private directory setup failed: {error}", file=sys.stderr)
        sys.exit(1)
