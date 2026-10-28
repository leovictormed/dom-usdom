#!/usr/bin/env python3
"""Publish one immutable, content-addressed public execution plan."""
import hashlib
import os
import secrets
import re
import signal
import stat
import sys
from pathlib import Path


MAXIMUM_BYTES = 16 * 1024 * 1024
PREFIX = "open-claims-execution-plan-v1-"
MAXIMUM_RECOVERABLE_TEMPORARIES = 64
TEMPORARY_PATTERN = re.compile(rf"^\.{re.escape(PREFIX)}([1-9][0-9]*)\.([0-9a-f]{{24}})\.tmp$")


def fail(message):
    raise ValueError(message)


def file_identity(value):
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
        value.st_uid, value.st_gid, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def directory_identity(value):
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid


def read_bounded(descriptor, maximum):
    chunks = []
    size = 0
    while chunk := os.read(descriptor, min(1024 * 1024, maximum + 1 - size)):
        chunks.append(chunk)
        size += len(chunk)
        if size > maximum:
            fail("plan exceeds its size bound")
    return b"".join(chunks)


def process_is_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def recover_temporaries(directory_fd, uid):
    matches = sorted(name for name in os.listdir(directory_fd) if TEMPORARY_PATTERN.fullmatch(name))
    if len(matches) > MAXIMUM_RECOVERABLE_TEMPORARIES:
        fail("too many public plan temporary files")
    changed = False
    for name in matches:
        pid = int(TEMPORARY_PATTERN.fullmatch(name).group(1))
        if process_is_alive(pid):
            continue
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid
            or metadata.st_nlink not in (1, 2)
            or stat.S_IMODE(metadata.st_mode) != 0o644
            or metadata.st_size < 2 or metadata.st_size > MAXIMUM_BYTES
        ):
            fail("public plan temporary file is unsafe")
        if metadata.st_nlink == 2:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
            try:
                contents = read_bounded(descriptor, MAXIMUM_BYTES)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            basename = f"{PREFIX}{hashlib.sha256(contents).hexdigest()}.json"
            try:
                target = os.stat(basename, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                fail("public plan temporary hardlink has no content-addressed target")
            if (
                file_identity(metadata) != file_identity(after)
                or (target.st_dev, target.st_ino) != (metadata.st_dev, metadata.st_ino)
                or target.st_nlink != 2 or not stat.S_ISREG(target.st_mode)
                or target.st_uid != uid or stat.S_IMODE(target.st_mode) != 0o644
            ):
                fail("public plan temporary hardlink is not its content-addressed target")
        os.unlink(name, dir_fd=directory_fd)
        changed = True
    if changed:
        os.fsync(directory_fd)


def main():
    if len(sys.argv) != 5:
        fail("usage: install-content-addressed-public-plan.py CANDIDATE PUBLIC_DIRECTORY EXPECTED_DEVICE EXPECTED_INODE")
    candidate_path, directory_path = map(os.path.abspath, sys.argv[1:3])
    if candidate_path != sys.argv[1] or directory_path != sys.argv[2] \
            or not sys.argv[3].isdigit() or not sys.argv[4].isdigit() \
            or int(sys.argv[3]) <= 0 or int(sys.argv[4]) <= 0:
        fail("plan paths must be absolute and normalized")
    expected_directory_identity = int(sys.argv[3]), int(sys.argv[4])
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    candidate_fd = os.open(candidate_path, flags)
    directory_fd = os.open(directory_path, flags | os.O_DIRECTORY)
    temporary = None
    temporary_fd = None
    target_fd = None
    try:
        candidate_before = os.fstat(candidate_fd)
        if (
            not stat.S_ISREG(candidate_before.st_mode)
            or candidate_before.st_uid != os.getuid()
            or candidate_before.st_nlink != 1
            or stat.S_IMODE(candidate_before.st_mode) != 0o644
            or candidate_before.st_size < 2
            or candidate_before.st_size > MAXIMUM_BYTES
            or os.path.realpath(f"/proc/self/fd/{candidate_fd}") != candidate_path
        ):
            fail("candidate plan identity is invalid")
        contents = read_bounded(candidate_fd, MAXIMUM_BYTES)
        if len(contents) != candidate_before.st_size \
                or file_identity(os.fstat(candidate_fd)) != file_identity(candidate_before):
            fail("candidate plan changed while reading")

        directory_before = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_before.st_mode)
            or directory_before.st_uid != os.getuid()
            or stat.S_IMODE(directory_before.st_mode) != 0o755
            or os.path.realpath(f"/proc/self/fd/{directory_fd}") != directory_path
            or (directory_before.st_dev, directory_before.st_ino)
            != expected_directory_identity
        ):
            fail("public plan directory identity is invalid")
        recover_temporaries(directory_fd, os.getuid())

        digest = hashlib.sha256(contents).hexdigest()
        basename = f"{PREFIX}{digest}.json"
        temporary = f".{PREFIX}{os.getpid()}.{secrets.token_hex(12)}.tmp"
        temporary_fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o644,
            dir_fd=directory_fd,
        )
        written = 0
        while written < len(contents):
            written += os.write(temporary_fd, contents[written:])
        os.fchmod(temporary_fd, 0o644)
        os.fsync(temporary_fd)
        fault = os.environ.get("USDOM_TEST_PLAN_INSTALL_FAULT")
        if fault:
            if not directory_path.startswith("/tmp/usdom-") or fault not in ("after-temporary-fsync", "after-create-once-link"):
                fail("invalid plan installer fault injection")
            if fault == "after-temporary-fsync":
                os.kill(os.getpid(), signal.SIGKILL)
        temporary_stat = os.fstat(temporary_fd)
        if (
            not stat.S_ISREG(temporary_stat.st_mode)
            or temporary_stat.st_uid != os.getuid()
            or temporary_stat.st_nlink != 1
            or stat.S_IMODE(temporary_stat.st_mode) != 0o644
            or temporary_stat.st_size != len(contents)
        ):
            fail("temporary plan identity is invalid")
        try:
            os.link(
                temporary, basename,
                src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if fault == "after-create-once-link":
                os.kill(os.getpid(), signal.SIGKILL)
        except FileExistsError:
            pass
        os.unlink(temporary, dir_fd=directory_fd)
        temporary = None
        os.fsync(directory_fd)

        target_fd = os.open(basename, flags, dir_fd=directory_fd)
        target_before = os.fstat(target_fd)
        installed = read_bounded(target_fd, MAXIMUM_BYTES)
        target_after = os.fstat(target_fd)
        named_target = os.stat(basename, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(target_before.st_mode)
            or target_before.st_uid != os.getuid()
            or target_before.st_nlink != 1
            or stat.S_IMODE(target_before.st_mode) != 0o644
            or file_identity(target_before) != file_identity(target_after)
            or (target_before.st_dev, target_before.st_ino)
            != (named_target.st_dev, named_target.st_ino)
            or installed != contents
            or hashlib.sha256(installed).hexdigest() != digest
        ):
            fail("published content-addressed plan is invalid")
        named_directory = os.stat(directory_path, follow_symlinks=False)
        if (
            not stat.S_ISDIR(named_directory.st_mode)
            or directory_identity(named_directory) != directory_identity(directory_before)
        ):
            fail("public plan directory changed during publication")
        print(str(Path(directory_path) / basename))
    finally:
        if target_fd is not None:
            os.close(target_fd)
        if temporary_fd is not None:
            os.close(temporary_fd)
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)
        os.close(candidate_fd)


try:
    main()
except (OSError, ValueError) as error:
    print(f"content-addressed plan publication failed: {error}", file=sys.stderr)
    raise SystemExit(1)
