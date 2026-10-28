#!/usr/bin/env python3
"""Review-only generator for the finalized-burn normal dependency authority."""

from __future__ import annotations

import argparse
import errno
import grp
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath


REPO = Path(__file__).resolve().parents[3]
LAB = REPO / "labs/usdom-reserve"
TARGET = LAB / "config/finalized-burn-dependency-authority.json"
TOOLCHAIN_LOCK = LAB / "config/mainnet-toolchain-lock.json"
COMMAND = [
    "cargo", "tree", "--offline", "--locked", "-p",
    "dom-usdom-finalized-burn-program", "--edges", "normal",
    "--prefix", "none", "--format", "{p}",
]
SCHEMA = "usdom-finalized-burn-dependency-authority/v3"
EXPECTED_MANIFESTS = 234
PACKAGE = re.compile(r"[A-Za-z0-9_-]+")
REQUIRED_PYTHON_MODULES = {
    "argparse", "hashlib", "json", "pathlib", "re", "subprocess", "tomllib",
}
RUNTIME_FILES = (
    Path("/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo"),
    Path("/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc"),
    Path("/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/librustc_driver-28a98848f7a7c026.so"),
    Path("/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/libLLVM.so.22.1-rust-1.98.0-stable"),
    Path("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
    Path("/usr/lib/x86_64-linux-gnu/libc.so.6"),
    Path("/usr/lib/x86_64-linux-gnu/libdl.so.2"),
    Path("/usr/lib/x86_64-linux-gnu/libgcc_s.so.1"),
    Path("/usr/lib/x86_64-linux-gnu/libm.so.6"),
    Path("/usr/lib/x86_64-linux-gnu/libpthread.so.0"),
    Path("/usr/lib/x86_64-linux-gnu/librt.so.1"),
    Path("/usr/lib/x86_64-linux-gnu/libz.so.1.3"),
    Path("/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2"),
    Path("/usr/lib/x86_64-linux-gnu/libexpat.so.1.9.1"),
    Path("/usr/bin/git"),
    Path("/usr/bin/python3.12"),
    Path("/etc/ld.so.cache"),
)
RUNTIME_RESOLUTION_INPUTS = {Path("/etc/ld.so.cache")}
LOADER = Path("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
LIBC = Path("/usr/lib/x86_64-linux-gnu/libc.so.6")
CARGO_RUST_RESOLUTION = set(RUNTIME_FILES[:12]) - set(RUNTIME_FILES[:2])
GIT_RESOLUTION = {
    LOADER, LIBC, Path("/usr/lib/x86_64-linux-gnu/libz.so.1.3"),
    Path("/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2"),
}
PYTHON_RESOLUTION = {
    LOADER, LIBC, Path("/usr/lib/x86_64-linux-gnu/libm.so.6"),
    Path("/usr/lib/x86_64-linux-gnu/libz.so.1.3"),
    Path("/usr/lib/x86_64-linux-gnu/libexpat.so.1.9.1"),
}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_regular(path: Path, *, executable: bool = False, private_group_write: bool = False) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"cannot open {path}: {error.strerror}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail(f"unsafe file identity: {path}")
        writable = stat.S_IMODE(before.st_mode) & 0o022
        private_group = False
        if private_group_write and writable == 0o020 and before.st_gid == os.getegid():
            group = grp.getgrgid(before.st_gid)
            private_group = not group.gr_mem
        if before.st_uid not in {0, os.geteuid()} or (writable and not private_group):
            fail(f"unsafe owner or mode: {path}")
        if executable and not stat.S_IMODE(before.st_mode) & 0o100:
            fail(f"tool is not owner-executable: {path}")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            fail(f"file changed while reading: {path}")
        return b"".join(chunks), before
    finally:
        os.close(descriptor)


def open_authenticated_tool(name: str) -> tuple[int, Path]:
    lock_bytes, _ = read_regular(TOOLCHAIN_LOCK)
    lock = json.loads(lock_bytes, object_pairs_hook=strict_object)
    matches = [entry for entry in lock.get("executables", []) if entry.get("name") == name]
    if len(matches) != 1:
        fail(f"toolchain lock must contain exactly one {name}")
    entry = matches[0]
    path = Path(entry["path"])
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        mode = stat.S_IMODE(info.st_mode)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            fail(f"unsafe {name} file identity")
        if info.st_uid not in {0, os.geteuid()} or mode & 0o022 or not mode & 0o100:
            fail(f"unsafe {name} owner or mode")
        if os.path.realpath(path) != entry["realpath"]:
            fail(f"{name} realpath drifted")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        if digest.hexdigest() != entry["sha256"]:
            fail(f"{name} hash drifted")
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.set_inheritable(descriptor, True)
        return descriptor, path
    except BaseException:
        os.close(descriptor)
        raise


def require_authenticated_launcher() -> None:
    if not sys.flags.isolated or not sys.flags.no_site:
        fail("generator requires isolated Python (-I -S) through the authenticated dispatcher")
    lock_bytes, _ = read_regular(TOOLCHAIN_LOCK)
    lock = json.loads(lock_bytes, object_pairs_hook=strict_object)
    matches = [entry for entry in lock.get("files", [])
               if entry.get("path") == "scripts/mainnet-tool-dispatcher"]
    if len(matches) != 1 or not re.fullmatch(r"[0-9a-f]{64}", matches[0].get("sha256", "")):
        fail("toolchain lock must contain exactly one authenticated dispatcher")
    parent_pid = os.getppid()
    parent_identity = proc_process_identity(parent_pid)
    parent_exe = Path(f"/proc/{parent_pid}/exe")
    try:
        descriptor = os.open(parent_exe, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError as error:
        fail(f"cannot authenticate generator launcher: {error.strerror}")
    try:
        info = os.fstat(descriptor)
        mode = stat.S_IMODE(info.st_mode)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or mode != 0o755):
            fail("generator launcher identity is unsafe")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        if digest.hexdigest() != matches[0]["sha256"]:
            fail("generator launcher is not the authenticated dispatcher")
    finally:
        os.close(descriptor)
    if os.getppid() != parent_pid or proc_process_identity(parent_pid) != parent_identity:
        fail("authenticated dispatcher exited during launcher verification")


def proc_process_identity(pid: int) -> tuple[str, int, int]:
    try:
        stat_payload = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields = stat_payload[stat_payload.rfind(")") + 2:].split()
        start_time = fields[19]
        namespace = os.stat(f"/proc/{pid}/ns/pid")
    except (OSError, UnicodeError, IndexError) as error:
        fail(f"cannot capture dispatcher process identity: {error}")
    if not start_time.isdigit():
        fail("dispatcher process start time is malformed")
    return start_time, namespace.st_dev, namespace.st_ino


def python_module_authority() -> tuple[list[dict[str, str]], dict[Path, tuple[bytes, tuple[int, int]]]]:
    entries: list[dict[str, str]] = []
    snapshots: dict[Path, tuple[bytes, tuple[int, int]]] = {}
    seen_paths: set[Path] = set()
    present_names: set[str] = set()
    for name, module in sorted(sys.modules.items()):
        raw_path = getattr(module, "__file__", None)
        if not isinstance(raw_path, str):
            continue
        path = Path(os.path.realpath(raw_path))
        if not (path == Path("/usr/lib/python3.12") or Path("/usr/lib/python3.12") in path.parents):
            continue
        if path in seen_paths:
            continue
        payload, info = read_regular(path)
        seen_paths.add(path)
        present_names.add(name.split(".", 1)[0])
        snapshots[path] = (payload, (info.st_dev, info.st_ino))
        entries.append({"module": name, "path": str(path), "sha256": sha256_bytes(payload)})
    if not REQUIRED_PYTHON_MODULES <= present_names:
        fail("Python runtime omitted a required generator module")
    return entries, snapshots


def open_fixed_system_tool(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"cannot open fixed system tool {path}: {error.strerror}")
    try:
        info = os.fstat(descriptor)
        mode = stat.S_IMODE(info.st_mode)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            fail(f"fixed system tool is not a unique regular file: {path}")
        if info.st_uid != 0 or mode & 0o022 or not mode & 0o100:
            fail(f"fixed system tool has unsafe owner or mode: {path}")
        os.set_inheritable(descriptor, True)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def closed_environment(rustc_fd: int | None = None) -> dict[str, str]:
    account = pwd.getpwuid(os.geteuid())
    cargo_home = Path(account.pw_dir) / ".cargo"
    environment = {
        "HOME": account.pw_dir,
        "CARGO_HOME": str(cargo_home),
        "CARGO_NET_OFFLINE": "true",
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    if rustc_fd is not None:
        environment["RUSTC"] = f"/proc/self/fd/{rustc_fd}"
    return environment


def parse_runtime_trace(payload: bytes) -> set[Path]:
    try:
        lines = payload.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError:
        fail("dynamic loader trace is not strict UTF-8")
    resolved: set[Path] = set()
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("linux-vdso.so.1 "):
            continue
        if "=> not found" in line:
            fail(f"dynamic loader dependency is unresolved: {line}")
        candidate = line.split("=>", 1)[1].strip().split(" ", 1)[0] if "=>" in line else line.split(" ", 1)[0]
        path = Path(candidate)
        if not path.is_absolute():
            fail(f"dynamic loader emitted an unsafe dependency path: {line}")
        resolved.add(Path(os.path.realpath(path)))
    if not resolved:
        fail("dynamic loader emitted an empty dependency closure")
    return resolved


def trace_runtime_resolution(descriptors: tuple[int, ...], expected: set[Path]) -> None:
    resolved: set[Path] = set()
    for descriptor in descriptors:
        environment = closed_environment()
        environment["LD_TRACE_LOADED_OBJECTS"] = "1"
        completed = subprocess.run(
            [f"/proc/self/fd/{descriptor}"], env=environment, pass_fds=(descriptor,),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False,
        )
        if completed.returncode != 0 or completed.stderr:
            detail = completed.stderr.decode("utf-8", "replace")[-1000:]
            fail(f"authenticated dynamic loader trace failed ({completed.returncode}): {detail}")
        resolved.update(parse_runtime_trace(completed.stdout))
    if resolved != expected:
        missing = ", ".join(str(path) for path in sorted(expected - resolved))
        extra = ", ".join(str(path) for path in sorted(resolved - expected))
        fail(f"dynamic loader closure drifted (missing=[{missing}], extra=[{extra}])")


def cargo_config_paths() -> list[Path]:
    names = ("config", "config.toml")
    directories = [REPO / ".cargo"]
    directories.extend(parent / ".cargo" for parent in REPO.parents)
    result = []
    for directory in directories:
        for name in names:
            candidate = directory / name
            if candidate.exists() or candidate.is_symlink():
                result.append(candidate)
    return sorted(set(result))


def validate_cargo_configs() -> dict[Path, tuple[bytes, tuple[int, int]]]:
    snapshots = {}
    for path in cargo_config_paths():
        payload, info = read_regular(path, private_group_write=True)
        try:
            value = tomllib.loads(payload.decode("utf-8", "strict"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            fail(f"Cargo config is not strict TOML: {path}")
        if set(value) - {"build", "target", "profile"}:
            fail(f"Cargo config contains dependency-affecting or executable settings: {path}")
        build = value.get("build", {})
        targets = value.get("target", {})
        profiles = value.get("profile", {})
        if not isinstance(build, dict) or set(build) - {"jobs"}:
            fail(f"Cargo config build settings are not review-safe: {path}")
        if not isinstance(targets, dict) or any(
            not isinstance(settings, dict) or set(settings) - {"rustflags"}
            for settings in targets.values()
        ):
            fail(f"Cargo config target settings are not review-safe: {path}")
        if not isinstance(profiles, dict) or any(
            not isinstance(settings, dict) or set(settings) - {"debug"}
            for settings in profiles.values()
        ):
            fail(f"Cargo config profile settings are not review-safe: {path}")
        snapshots[path] = (payload, (info.st_dev, info.st_ino))
    return snapshots


def revalidate_cargo_configs(snapshots: dict[Path, tuple[bytes, tuple[int, int]]]) -> None:
    if cargo_config_paths() != sorted(snapshots):
        fail("Cargo config inventory changed during authenticated cargo tree")
    for path, (expected, identity) in snapshots.items():
        payload, info = read_regular(path, private_group_write=True)
        if payload != expected or (info.st_dev, info.st_ino) != identity:
            fail(f"Cargo config changed during authenticated cargo tree: {path}")


def git_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_COUNT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
    }


def run_cargo_tree() -> list[str]:
    config_snapshots = validate_cargo_configs()
    descriptor, _ = open_authenticated_tool("cargo")
    rustc_descriptor, _ = open_authenticated_tool("rustc")
    try:
        trace_runtime_resolution((descriptor, rustc_descriptor), CARGO_RUST_RESOLUTION)
        completed = subprocess.run(
            [f"/proc/self/fd/{descriptor}", *COMMAND[1:]], cwd=REPO,
            env=closed_environment(rustc_descriptor), pass_fds=(descriptor, rustc_descriptor), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, check=False,
        )
    finally:
        os.close(descriptor)
        os.close(rustc_descriptor)
    revalidate_cargo_configs(config_snapshots)
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace")[-2000:]
        fail(f"authenticated offline cargo tree failed ({completed.returncode}): {detail}")
    try:
        lines = completed.stdout.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError:
        fail("cargo tree emitted non-UTF-8 output")
    packages: set[str] = set()
    for line in lines:
        fields = line.split()
        if len(fields) < 2 or not PACKAGE.fullmatch(fields[0]) or not fields[1].startswith("v"):
            fail(f"malformed cargo tree line: {line!r}")
        packages.add(fields[0])
    if "dom-usdom-finalized-burn-program" not in packages:
        fail("cargo tree omitted the requested root package")
    return sorted(packages)


def tracked_manifests() -> tuple[list[str], dict[Path, tuple[bytes, tuple[int, int]]]]:
    git = Path("/usr/bin/git")
    descriptor = open_fixed_system_tool(git)
    try:
        trace_runtime_resolution((descriptor,), GIT_RESOLUTION)
        root_check = subprocess.run(
            [f"/proc/self/fd/{descriptor}", "rev-parse", "--path-format=absolute", "--show-toplevel"],
            cwd=REPO, env=git_environment(), pass_fds=(descriptor,), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
        )
        if root_check.returncode != 0 or root_check.stdout.rstrip(b"\n") != os.fsencode(REPO.resolve()):
            fail("Git worktree root does not match the repository authority root")
        index_check = subprocess.run(
            [f"/proc/self/fd/{descriptor}", "rev-parse", "--path-format=absolute", "--git-path", "index"],
            cwd=REPO, env=git_environment(), pass_fds=(descriptor,), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
        )
        if index_check.returncode != 0:
            fail("Git index identity cannot be resolved")
        index_path = Path(os.fsdecode(index_check.stdout.rstrip(b"\n")))
        if not index_path.is_absolute():
            fail("Git index identity is not absolute")
        index_payload, index_info = read_regular(index_path)
        completed = subprocess.run(
            [f"/proc/self/fd/{descriptor}", "ls-files", "-z", "--stage", "--", "Cargo.toml", ":(glob)**/Cargo.toml"],
            cwd=REPO, env=git_environment(),
            pass_fds=(descriptor,), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30, check=False,
        )
        flags_check = subprocess.run(
            [f"/proc/self/fd/{descriptor}", "ls-files", "-v", "-z", "--", "Cargo.toml", ":(glob)**/Cargo.toml"],
            cwd=REPO, env=git_environment(), pass_fds=(descriptor,), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
        )
    finally:
        os.close(descriptor)
    if completed.returncode != 0:
        fail("git ls-files failed: " + completed.stderr.decode("utf-8", "replace")[-1000:])
    paths = parse_git_manifest_inventory(completed.stdout)
    if flags_check.returncode != 0:
        fail("git ls-files flag inventory failed: " + flags_check.stderr.decode("utf-8", "replace")[-1000:])
    flagged_paths = parse_git_manifest_flags(flags_check.stdout)
    paths = sorted(set(paths))
    if flagged_paths != paths:
        fail("Git manifest stage and flag inventories disagree")
    if len(paths) != EXPECTED_MANIFESTS:
        fail(f"tracked Cargo.toml inventory is {len(paths)}, expected {EXPECTED_MANIFESTS}")
    for value in paths:
        pure = PurePosixPath(value)
        if pure.is_absolute() or ".." in pure.parts or pure.name != "Cargo.toml":
            fail(f"unsafe tracked manifest path: {value}")
    index_snapshot = {index_path: (index_payload, (index_info.st_dev, index_info.st_ino))}
    return paths, index_snapshot


def parse_git_manifest_inventory(payload: bytes) -> list[str]:
    paths = []
    try:
        records = [item.decode("utf-8", "strict") for item in payload.split(b"\0") if item]
    except UnicodeDecodeError:
        fail("git manifest inventory is not UTF-8")
    for record in records:
        match = re.fullmatch(r"(\d{6}) [0-9a-f]{40,64} 0\t(.+)", record)
        if not match:
            fail("git manifest inventory contains a malformed stage record")
        if match.group(1) != "100644":
            fail(f"Cargo manifest is not a regular tracked blob: {match.group(2)}")
        paths.append(match.group(2))
    return paths


def parse_git_manifest_flags(payload: bytes) -> list[str]:
    paths = []
    try:
        records = [item.decode("utf-8", "strict") for item in payload.split(b"\0") if item]
    except UnicodeDecodeError:
        fail("git manifest flag inventory is not UTF-8")
    for record in records:
        if not record.startswith("H "):
            fail("Cargo manifest has assume-unchanged, skip-worktree, sparse or non-blob Git state")
        paths.append(record[2:])
    return sorted(set(paths))


def revalidate_source_snapshots(snapshots: dict[Path, tuple[bytes, tuple[int, int]]]) -> None:
    for path, (expected, identity) in snapshots.items():
        payload, info = read_regular(path)
        if payload != expected or (info.st_dev, info.st_ino) != identity:
            fail(f"dependency source changed during authenticated cargo tree: {path}")


def build_authority() -> dict[str, object]:
    lock_path = REPO / "Cargo.lock"
    lock_bytes, lock_info = read_regular(lock_path)
    snapshots = {lock_path: (lock_bytes, (lock_info.st_dev, lock_info.st_ino))}
    python_modules, python_snapshots = python_module_authority()
    snapshots.update(python_snapshots)
    manifests = []
    runtime_files = []
    tracked, index_snapshots = tracked_manifests()
    snapshots.update(index_snapshots)
    for relative in tracked:
        path = REPO / relative
        payload, info = read_regular(path)
        snapshots[path] = (payload, (info.st_dev, info.st_ino))
        manifests.append({"path": relative, "sha256": sha256_bytes(payload)})
    for path in sorted(RUNTIME_FILES):
        payload, info = read_regular(path)
        snapshots[path] = (payload, (info.st_dev, info.st_ino))
        runtime_files.append({"path": str(path), "sha256": sha256_bytes(payload)})
    python_descriptor, _ = open_authenticated_tool("python3")
    try:
        trace_runtime_resolution((python_descriptor,), PYTHON_RESOLUTION)
    finally:
        os.close(python_descriptor)
    packages = run_cargo_tree()
    revalidate_source_snapshots(snapshots)
    return {
        "schema": SCHEMA,
        "rootPackage": "dom-usdom-finalized-burn-program",
        "edgeKinds": ["normal"],
        "command": COMMAND,
        "cargoLockSha256": sha256_bytes(lock_bytes),
        "runtimeFiles": runtime_files,
        "pythonModules": python_modules,
        "manifests": manifests,
        "packages": packages,
    }


def install_create_once(payload: bytes) -> None:
    parent = TARGET.parent
    current = None
    try:
        current, _ = read_regular(TARGET)
    except SystemExit as error:
        if TARGET.exists() or TARGET.is_symlink():
            raise
    if current is not None:
        if current != payload:
            fail("authority exists with different bytes; review and remove it explicitly before regeneration")
        print("PASS: finalized-burn dependency authority already matches canonical bytes")
        return
    directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    temporary = f".{TARGET.name}.new.{os.getpid()}.{os.urandom(8).hex()}"
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory)
        os.write(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, TARGET.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
            existing, _ = read_regular(TARGET)
            if existing != payload:
                fail("authority appeared concurrently with different bytes")
        os.fsync(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)
    print("PASS: created canonical finalized-burn dependency authority atomically")


def main() -> None:
    require_authenticated_launcher()
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true", help="regenerate in memory and compare exact canonical bytes")
    action.add_argument("--write", action="store_true", help="create once atomically; never overwrite an existing authority")
    args = parser.parse_args()
    payload = canonical_json(build_authority())
    if args.check:
        current, _ = read_regular(TARGET)
        if current != payload:
            fail("finalized-burn dependency authority is not the canonical regenerated result")
        print("PASS: finalized-burn dependency authority exactly matches authenticated offline cargo tree")
    else:
        install_create_once(payload)


if __name__ == "__main__":
    main()
