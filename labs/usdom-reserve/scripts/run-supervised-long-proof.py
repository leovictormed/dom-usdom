#!/usr/bin/python3
"""Run one long proof with a durable, non-reusable identity and signal record."""

import argparse
import ctypes
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import resource
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from durable_create_once import install_create_once

MAX_MANIFEST = 1024 * 1024
RUN_ID = re.compile(r"[0-9a-f]{64}\Z")
ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,63}\Z")
DENIED_ENV = {"PATH", "PYTHONPATH", "PYTHONHOME", "BASH_ENV", "ENV", "CDPATH", "GLOBIGNORE"}
DENIED_PREFIXES = ("LD_", "DYLD_")
pending_signal = None
child = None
events_fd = None
MANAGED_SIGNALS = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
PR_SET_CHILD_SUBREAPER = 36


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def strict_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError(f"duplicate JSON key: {key}")
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs)


def direct_regular(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
        os.close(fd)
        raise ValueError(f"unsafe file: {path}")
    data = bytearray()
    while len(data) <= maximum:
        part = os.read(fd, min(65536, maximum + 1 - len(data)))
        if not part:
            break
        data.extend(part)
    after = os.fstat(fd)
    os.close(fd)
    if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError(f"file changed while reading: {path}")
    if len(data) > maximum:
        raise ValueError(f"oversized file: {path}")
    return bytes(data)


def direct_sha256(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    info = os.fstat(fd)
    digest = hashlib.sha256()
    total = 0
    try:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            raise ValueError(f"unsafe bound input: {path}")
        while True:
            part = os.read(fd, min(1024 * 1024, maximum + 1 - total))
            if not part:
                break
            total += len(part)
            if total > maximum:
                raise ValueError(f"oversized bound input: {path}")
            digest.update(part)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError(f"bound input changed while hashing: {path}")
    return digest.hexdigest()


def free_bytes(path):
    info = os.statvfs(path)
    return info.f_bavail * info.f_frsize


def write_all(fd, data):
    view = memoryview(data)
    while view:
        try:
            written = os.write(fd, view)
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError("short write while publishing proof evidence")
        view = view[written:]


def sealed_executable(path, expected_sha256):
    source = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    before = os.fstat(source)
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
            before.st_size > 1024 * 1024 * 1024 or before.st_mode & (stat.S_ISUID | stat.S_ISGID)):
        os.close(source)
        raise ValueError("unsafe executable")
    image = os.memfd_create("usdom-proof-executable", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    digest = hashlib.sha256()
    try:
        while True:
            part = os.read(source, 1024 * 1024)
            if not part:
                break
            digest.update(part)
            view = memoryview(part)
            while view:
                try:
                    written = os.write(image, view)
                except InterruptedError:
                    continue
                if written <= 0:
                    raise OSError("short write while sealing proof executable")
                view = view[written:]
        after = os.fstat(source)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("executable changed while authenticating")
        if digest.hexdigest() != expected_sha256:
            raise ValueError("executable hash mismatch")
        os.fchmod(image, 0o500)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(image, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(image, fcntl.F_GET_SEALS) != seals:
            raise ValueError("immutable executable seals were not applied")
        os.lseek(image, 0, os.SEEK_SET)
        return image
    except Exception:
        os.close(image)
        raise
    finally:
        os.close(source)


def durable_new(path, data, mode=0o400):
    install_create_once(path,data,mode=mode,maximum=1024*1024,
                        private_parent=True,allow_equal=False)


def event(kind, **fields):
    if events_fd is None:
        return
    record = canonical({"at": now(), "event": kind, **fields})
    write_all(events_fd, record)
    os.fsync(events_fd)


def drain_signals():
    global pending_signal
    while True:
        info = signal.sigtimedwait(MANAGED_SIGNALS, 0)
        if info is None:
            return
        number = info.si_signo
        event("supervisor-signal", signal=signal.Signals(number).name,
              senderPid=info.si_pid, senderUid=info.si_uid, signalCode=info.si_code)
        if pending_signal is None:
            pending_signal = number
            if child is not None and child.poll() is None:
                try:
                    os.killpg(child.pid, number)
                    event("signal-forwarded", signal=signal.Signals(number).name, childProcessGroup=child.pid)
                except ProcessLookupError:
                    pass


def process_start_ticks(pid):
    text = Path(f"/proc/{pid}/stat").read_text()
    return text[text.rfind(")") + 2:].split()[19]


def child_signal_setup():
    # Long proof processes handle proving material and authenticated inputs.
    # A crash must not cause the kernel to persist their address space in a
    # core file, including when the supervisor is invoked outside systemd.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    signal.pthread_sigmask(signal.SIG_UNBLOCK, MANAGED_SIGNALS)


def become_child_subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), "prctl(PR_SET_CHILD_SUBREAPER)")


def reap_adopted_children():
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def descendants():
    parent = os.getpid()
    records = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            text = (entry / "stat").read_text()
            fields = text[text.rfind(")") + 2:].split()
            records[int(entry.name)] = (int(fields[1]), fields[19])
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, IndexError):
            continue
    selected = set()
    changed = True
    while changed:
        changed = False
        for pid, (ppid, _) in records.items():
            if pid not in selected and (ppid == parent or ppid in selected):
                selected.add(pid)
                changed = True
    return [(pid, records[pid][1]) for pid in sorted(selected)]


def same_process(pid, start_ticks):
    try:
        return process_start_ticks(pid) == start_ticks
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return False


def terminate_stray_descendants():
    found = descendants()
    if not found:
        reap_adopted_children()
        return False
    event("stray-descendants", processes=[{"pid": pid, "startTicks": ticks} for pid, ticks in found])
    for pid, ticks in found:
        if same_process(pid, ticks):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        reap_adopted_children()
        if not any(same_process(pid, ticks) for pid, ticks in found):
            return True
        time.sleep(0.1)
    survivors = [(pid, ticks) for pid, ticks in found if same_process(pid, ticks)]
    event("stray-descendants-killed", processes=[{"pid": pid, "startTicks": ticks} for pid, ticks in survivors])
    for pid, ticks in survivors:
        if same_process(pid, ticks):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        reap_adopted_children()
        if not any(same_process(pid, ticks) for pid, ticks in survivors):
            return True
        time.sleep(0.1)
    raise RuntimeError("stray proof descendants survived SIGKILL")


def terminate_stray_process_group(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    event("stray-child-process-group", childProcessGroup=pgid)
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        reap_adopted_children()
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.1)
    event("stray-child-process-group-killed", childProcessGroup=pgid)
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return True


def main():
    global child, events_fd
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--command-manifest", required=True)
    parser.add_argument("--expected-supervisor-sha256", required=True)
    parser.add_argument("--termination-grace-seconds", type=int, default=540)
    args = parser.parse_args()
    if not RUN_ID.fullmatch(args.run_id):
        raise ValueError("run-id must be exactly 64 lowercase hexadecimal characters")
    if not RUN_ID.fullmatch(args.expected_supervisor_sha256):
        raise ValueError("expected supervisor SHA-256 is malformed")
    supervisor_sha256 = sha256(direct_regular(Path(__file__).resolve(), 2 * 1024 * 1024))
    if supervisor_sha256 != args.expected_supervisor_sha256:
        raise ValueError("supervisor source differs from installed service pin")
    if not 1 <= args.termination_grace_seconds <= 540:
        raise ValueError("termination grace must be between 1 and 540 seconds")
    os.umask(0o077)
    signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
    become_child_subreaper()
    root = Path(args.state_root)
    if not root.is_absolute():
        raise ValueError("state root must be absolute")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root_stat = root.lstat()
    if (root.resolve(strict=True) != root or root.is_symlink() or not root.is_dir() or root_stat.st_uid != os.getuid()
            or root_stat.st_mode & 0o077):
        raise ValueError("state root is not a private direct directory")
    root_parent_fd = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(root_parent_fd)
    finally:
        os.close(root_parent_fd)
    lock_fd = os.open(root / ".startup.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    lock_info = os.fstat(lock_fd)
    if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1
            or lock_info.st_uid != os.getuid() or lock_info.st_mode & 0o077):
        os.close(lock_fd)
        raise ValueError("startup lock is not a private direct regular file")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise RuntimeError("another supervised proof owns the startup lock") from exc

    manifest_path = Path(args.command_manifest)
    raw = direct_regular(manifest_path, MAX_MANIFEST)
    spec = strict_json(raw.decode("utf-8", "strict"))
    v1 = {"schema", "nonce", "createdUnix", "argv", "cwd", "executableSha256", "environment"}
    v2 = v1 | {"inputs", "limits", "requiredOutput"}
    if (not isinstance(spec, dict) or
            (spec["schema"] == "usdom-supervised-proof-command-v1" and set(spec) != v1) or
            (spec["schema"] == "usdom-supervised-proof-command-v2" and set(spec) != v2) or
            spec["schema"] not in {"usdom-supervised-proof-command-v1", "usdom-supervised-proof-command-v2"}):
        raise ValueError("invalid command manifest schema or fields")
    if canonical(spec) != raw:
        raise ValueError("command manifest is not canonical JSON")
    if sha256(raw) != args.run_id:
        raise ValueError("run-id is not the SHA-256 of the canonical command manifest")
    if not re.fullmatch(r"[0-9a-f]{32}", spec["nonce"]):
        raise ValueError("nonce must be 128-bit lowercase hexadecimal")
    if not isinstance(spec["createdUnix"], int) or spec["createdUnix"] <= 0:
        raise ValueError("invalid createdUnix")
    argv = spec["argv"]
    if not isinstance(argv, list) or not 1 <= len(argv) <= 256 or any(not isinstance(x, str) or not x or "\0" in x or len(x) > 65536 for x in argv):
        raise ValueError("invalid argv")
    executable = Path(argv[0])
    if not executable.is_absolute():
        raise ValueError("argv[0] must be absolute")
    if not re.fullmatch(r"[0-9a-f]{64}", spec["executableSha256"]):
        raise ValueError("invalid executable hash")
    executable_fd = sealed_executable(executable, spec["executableSha256"])
    cwd = Path(spec["cwd"])
    if (not cwd.is_absolute() or cwd.resolve(strict=True) != cwd
            or cwd.is_symlink() or not cwd.is_dir()):
        raise ValueError("cwd must be an absolute direct directory")
    cwd_fd = os.open(cwd, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    bound_inputs = []
    limits = None
    required_output = []
    if spec["schema"] == "usdom-supervised-proof-command-v2":
        inputs = spec["inputs"]
        limits = spec["limits"]
        required_output = spec["requiredOutput"]
        if not isinstance(inputs, list) or not inputs or len(inputs) > 8192:
            raise ValueError("v2 inputs must be one bounded nonempty list")
        if (not isinstance(limits, dict) or set(limits) != {"maxRuntimeSeconds", "maxLogBytes", "minFreeBytes"}
                or not isinstance(required_output, list) or not required_output or len(required_output) > 32):
            raise ValueError("invalid v2 limits or output assertions")
        if (not isinstance(limits["maxRuntimeSeconds"], int) or not 60 <= limits["maxRuntimeSeconds"] <= 86_400
                or not isinstance(limits["maxLogBytes"], int) or not 1024 <= limits["maxLogBytes"] <= 1024 * 1024 * 1024
                or not isinstance(limits["minFreeBytes"], int) or not 1024 * 1024 * 1024 <= limits["minFreeBytes"] <= 1024**5):
            raise ValueError("v2 resource limits are outside policy")
        if any(not isinstance(item, str) or not item or "\0" in item or len(item.encode()) > 4096 for item in required_output):
            raise ValueError("invalid required output assertion")
        seen = set()
        for item in inputs:
            if not isinstance(item, dict) or set(item) != {"path", "sha256", "maxBytes"}:
                raise ValueError("invalid bound input")
            relative = Path(item["path"]) if isinstance(item["path"], str) else Path("/")
            if relative.is_absolute() or ".." in relative.parts or relative.as_posix() in seen:
                raise ValueError("bound input path is not canonical and unique")
            if (not re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])) or
                    not isinstance(item["maxBytes"], int) or not 1 <= item["maxBytes"] <= 64 * 1024 * 1024):
                raise ValueError("invalid bound input hash or bound")
            seen.add(relative.as_posix())
            target = cwd / relative
            if target.resolve(strict=True) != target or direct_sha256(target, item["maxBytes"]) != item["sha256"]:
                raise ValueError(f"bound input identity mismatch: {relative}")
            bound_inputs.append((target, item["maxBytes"], item["sha256"]))
        if min(free_bytes(cwd), free_bytes(root)) < limits["minFreeBytes"]:
            raise ValueError("insufficient free disk before child start")
    supplied_env = spec["environment"]
    if not isinstance(supplied_env, dict):
        raise ValueError("environment must be an object")
    for key, value in supplied_env.items():
        if not ENV_NAME.fullmatch(key) or key in DENIED_ENV or key.startswith(DENIED_PREFIXES):
            raise ValueError(f"unsafe environment name: {key}")
        if not isinstance(value, str) or "\0" in value or len(value) > 65536:
            raise ValueError(f"invalid environment value: {key}")

    runs_dir = root / "runs"
    runs_dir.mkdir(mode=0o700, exist_ok=True)
    runs_stat = runs_dir.lstat()
    if runs_dir.is_symlink() or not runs_dir.is_dir() or runs_stat.st_uid != os.getuid() or runs_stat.st_mode & 0o077:
        raise ValueError("runs root is not a private direct directory")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(root_fd)
    finally:
        os.close(root_fd)
    run_dir = runs_dir / args.run_id
    os.mkdir(run_dir, 0o700)  # Existing identity is deliberately never resumed/reused.
    runs_fd = os.open(runs_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(runs_fd)
    finally:
        os.close(runs_fd)
    events_fd = os.open(run_dir / "events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_CLOEXEC, 0o400)
    drain_signals()
    invocation = os.environ.get("INVOCATION_ID")
    if invocation is not None and not re.fullmatch(r"[0-9a-f]{32}", invocation):
        raise ValueError("invalid systemd INVOCATION_ID")
    runtime = {
        "schema": "usdom-supervised-proof-run-v1", "runId": args.run_id,
        "commandManifestSha256": sha256(raw), "runnerPid": os.getpid(),
        "runnerStartTicks": process_start_ticks(os.getpid()), "startedAt": now(),
        "bootId": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "systemdInvocationId": invocation,
        "supervisorSha256": supervisor_sha256,
        "supervisorPath": str(Path(__file__).resolve()),
    }
    durable_new(run_dir / "run.json", canonical(runtime))
    event("runner-started", runnerPid=os.getpid(), systemdInvocationId=invocation)
    tmp = run_dir / "tmp"
    tmp.mkdir(mode=0o700)
    run_dir_fd = os.open(run_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(run_dir_fd)
    finally:
        os.close(run_dir_fd)
    env = {"HOME": str(root), "TMPDIR": str(tmp), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", **supplied_env}
    output_fd = os.open(run_dir / "process.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o400)
    child_return_code = None
    output_size = 0
    try:
        drain_signals()
        if pending_signal is not None:
            event("child-start-refused-after-signal", signal=signal.Signals(pending_signal).name)
            return_code = -pending_signal
        else:
            child = subprocess.Popen(argv, executable=f"/proc/self/fd/{executable_fd}",
                                     pass_fds=(executable_fd, cwd_fd), cwd=f"/proc/self/fd/{cwd_fd}", env=env,
                                     stdin=subprocess.DEVNULL, stdout=output_fd,
                                     stderr=subprocess.STDOUT, start_new_session=True,
                                     close_fds=True, preexec_fn=child_signal_setup)
            os.close(executable_fd)
            executable_fd = -1
            event("child-started", childPid=child.pid, childStartTicks=process_start_ticks(child.pid))
            deadline = None
            runtime_deadline = time.monotonic() + limits["maxRuntimeSeconds"] if limits else None
            limit_failure = None
            while child.poll() is None:
                drain_signals()
                if limits and limit_failure is None:
                    if time.monotonic() >= runtime_deadline:
                        limit_failure = "runtime limit exceeded"
                    elif os.fstat(output_fd).st_size > limits["maxLogBytes"]:
                        limit_failure = "process log limit exceeded"
                    elif min(free_bytes(cwd), free_bytes(root)) < limits["minFreeBytes"]:
                        limit_failure = "free disk reserve crossed"
                    if limit_failure is not None:
                        event("resource-limit", reason=limit_failure)
                        try:
                            os.killpg(child.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        deadline = time.monotonic() + min(args.termination_grace_seconds, 30)
                if pending_signal is not None and deadline is None:
                    deadline = time.monotonic() + args.termination_grace_seconds
                if deadline is not None and time.monotonic() >= deadline:
                    event("termination-grace-expired", childProcessGroup=child.pid)
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    deadline = None
                time.sleep(0.1)
            return_code = child.returncode
            child_return_code = child.returncode
            drain_signals()
            stray_group = terminate_stray_process_group(child.pid)
            stray_descendants = terminate_stray_descendants()
            if (stray_group or stray_descendants) and return_code == 0:
                return_code = 125
            if pending_signal is not None and return_code >= 0:
                # A cooperative child exit does not make an interrupted proof successful.
                return_code = -pending_signal
            if limit_failure is not None:
                return_code = 124
    finally:
        if executable_fd >= 0:
            os.close(executable_fd)
        os.fsync(output_fd)
        output_size = os.fstat(output_fd).st_size
        os.close(output_fd)
        os.close(cwd_fd)

    child_signal = -child_return_code if child_return_code is not None and child_return_code < 0 else None
    if limits and output_size > limits["maxLogBytes"]:
        event("resource-limit", reason="process log limit exceeded")
        return_code = 124
    if spec["schema"] == "usdom-supervised-proof-command-v2" and return_code == 0:
        for target, maximum, expected_hash in bound_inputs:
            try:
                current_hash = direct_sha256(target, maximum)
            except (OSError, ValueError):
                current_hash = None
            if current_hash != expected_hash:
                event("bound-input-drift", path=str(target.relative_to(cwd)))
                return_code = 125
                break
        if return_code == 0:
            output = direct_regular(run_dir / "process.log", limits["maxLogBytes"])
            missing = [marker for marker in required_output if output.count(marker.encode()) != 1]
            if missing:
                event("required-output-mismatch", missing=missing)
                return_code = 125
    shell_status = 128 + (-return_code) if return_code < 0 else return_code
    stop_request = run_dir / "stop-request.json"
    stop_sha = sha256(direct_regular(stop_request, 65536)) if stop_request.exists() else None
    terminal = {
        "schema": "usdom-supervised-proof-terminal-v1", "runId": args.run_id,
        "runSha256": sha256(direct_regular(run_dir / "run.json", MAX_MANIFEST)),
        "processLogSha256": sha256(direct_regular(run_dir / "process.log", 1024 * 1024 * 1024)),
        "finishedAt": now(), "exitStatus": shell_status,
        "childSignal": signal.Signals(child_signal).name if child_signal else None,
        "supervisorSignal": signal.Signals(pending_signal).name if pending_signal else None,
        "signalSender": "recorded in events.jsonl for supervisor signals; unavailable for child-only signals" if child_signal or pending_signal else None,
        "stopRequestSha256": stop_sha,
    }
    event("runner-terminal", exitStatus=shell_status, childSignal=terminal["childSignal"],
          supervisorSignal=terminal["supervisorSignal"], stopRequestSha256=stop_sha)
    terminal["eventsSha256"] = sha256(direct_regular(run_dir / "events.jsonl", 64 * 1024 * 1024))
    durable_new(run_dir / "terminal.json", canonical(terminal))
    os.fchmod(events_fd, 0o400)
    os.close(events_fd)
    return shell_status


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"supervised proof refused: {error}", file=sys.stderr)
        raise SystemExit(125)
