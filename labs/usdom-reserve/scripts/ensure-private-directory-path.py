#!/usr/bin/env python3
"""Create one direct owned directory path without following any component."""
import os
import stat
import sys
from pathlib import PurePosixPath


def fail(message):
    raise ValueError(message)


def identity(value):
    return (value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode))


def main():
    if len(sys.argv) not in (2, 3):
        fail("usage: ensure-private-directory-path.py ABSOLUTE_DIRECTORY [0700|0755]")
    raw = sys.argv[1]
    requested = sys.argv[2] if len(sys.argv) == 3 else "0700"
    if requested not in ("0700", "0755"):
        fail("owned directory mode must be 0700 or 0755")
    target_mode = int(requested, 8)
    target = PurePosixPath(raw)
    if not target.is_absolute() or target.as_posix() != raw or target == PurePosixPath("/") \
            or any(part in ("", ".", "..") for part in target.parts[1:]):
        fail("owned directory path must be absolute and normalized")
    uid = os.getuid()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    opened = [descriptor]
    private_authority = False
    try:
        current = PurePosixPath("/")
        for index, component in enumerate(target.parts[1:], 1):
            final = index == len(target.parts) - 1
            parent_before = os.fstat(descriptor)
            current /= component
            created = False
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                mode = target_mode if final else 0o700
                previous_umask = os.umask(0)
                try:
                    try:
                        os.mkdir(component, mode, dir_fd=descriptor)
                        os.fsync(descriptor)
                        created = True
                    except FileExistsError:
                        pass
                finally:
                    os.umask(previous_umask)
                child = os.open(component, flags, dir_fd=descriptor)
            if created:
                # mkdir is filtered by the process umask.  Set the requested
                # mode only through the already authenticated new descriptor;
                # pre-existing directories are never repaired in place.
                os.fchmod(child, target_mode if final else 0o700)
                os.fsync(child)
            metadata = os.fstat(child)
            mode = stat.S_IMODE(metadata.st_mode)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in (0, uid):
                os.close(child)
                fail("owned directory ancestry has unsafe ownership or type")
            world_writable_sticky = metadata.st_uid == 0 and (mode & 0o1000) and current == PurePosixPath("/tmp")
            if not final and mode & 0o022 and not world_writable_sticky:
                os.close(child)
                fail("owned directory ancestry is writable by group or other")
            if not final and private_authority and (metadata.st_uid != uid or mode != 0o700):
                os.close(child)
                fail("private directory ancestry must remain caller-owned mode 0700")
            if final and (metadata.st_uid != uid or mode != target_mode):
                os.close(child)
                fail("owned directory target has wrong owner or mode")
            if created and mode != (target_mode if final else 0o700):
                os.close(child)
                fail("owned directory was not created with its final mode")
            if not final and metadata.st_uid == uid and mode == 0o700:
                private_authority = True
            if identity(os.fstat(descriptor)) != identity(parent_before):
                os.close(child)
                fail("owned directory parent changed during creation")
            named = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if identity(named) != identity(metadata):
                os.close(child)
                fail("owned directory component changed during creation")
            opened.append(child)
            descriptor = child
        if os.readlink(f"/proc/self/fd/{descriptor}") != raw:
            fail("owned directory path is indirect")
    finally:
        for item in reversed(opened):
            os.close(item)


try:
    main()
except (OSError, ValueError) as error:
    print(f"owned directory setup failed: {error}", file=sys.stderr)
    raise SystemExit(1)
