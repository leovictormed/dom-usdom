#!/usr/bin/env python3
"""Build the checkpoint proof chain in an isolated, atomically published tree."""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


SCHEMA = "usdom-checkpoint-rebuild-orchestrator-v3"
CACHE_SCHEMA = "usdom-offline-cache-manifest-v1"
STAGE_ORDER = (
    "segment", "pin-segment", "outer", "pin-outer", "finalized-burn",
    "pin-finalized-burn", "receipts", "gate",
)
STAGE_CLAIMS = {
    "segment": {"programDecoded", "imageIdRecomputed", "elfProgramPaired"},
    "pin-segment": {"predecessorHashesMatched", "consumerImageIdPinned"},
    "outer": {"programDecoded", "imageIdRecomputed", "segmentImageIdMatched", "journalSchemaMatched"},
    "pin-outer": {"predecessorHashesMatched", "consumerImageIdPinned"},
    "finalized-burn": {"programDecoded", "imageIdRecomputed", "outerImageIdMatched", "journalSchemaMatched"},
    "pin-finalized-burn": {"predecessorHashesMatched", "solidityImageIdPinned"},
    "receipts": {"receiptsCryptographicallyVerified", "methodImageIdsMatched", "journalDigestsMatched", "elfReceiptPairsMatched"},
    "gate": {"completeGraphMatched", "solidityVerifierConstantsMatched", "publicationReady"},
}
ROOT = Path(__file__).resolve().parents[3]
AT_FDCWD = -100
RENAME_NOREPLACE = 1
MAX_CONTROL_JSON_BYTES = 4 * 1024 * 1024


def fail(message: str) -> None:
    raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pinned_json(path: Path, expected_sha: str, label: str) -> dict:
    """Capture one direct control file once; never hash and parse separate opens."""
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        fail(f"{label} expected SHA-256 is malformed")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_CONTROL_JSON_BYTES:
            fail(f"{label} must be a bounded direct single-link file")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"{label} was truncated during its captured read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail(f"{label} grew during its captured read")
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if identity_before != identity_after:
            fail(f"{label} changed during its captured read")
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        fail(f"{label} differs from its pinned SHA-256")
    try:
        return json.loads(raw.decode("utf-8", errors="strict"))
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} is not strict UTF-8") from error


def command(argv: list[str], cwd: Path, env: dict[str, str], expected_sha256: str) -> None:
    """Execute the exact pinned inode, closing the hash-to-exec pathname race."""
    descriptor = os.open(argv[0], os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not before.st_mode & 0o111:
            fail("command executable is not a direct executable single-link file")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        if digest.hexdigest() != expected_sha256:
            fail("command executable differs from its pinned SHA-256")
        os.lseek(descriptor, 0, os.SEEK_SET)
        executable = f"/proc/self/fd/{descriptor}"
        subprocess.run(argv, executable=executable, pass_fds=(descriptor,), cwd=cwd, env=env,
                       check=True, stdin=subprocess.DEVNULL)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            fail("command executable changed while running")
    finally:
        os.close(descriptor)


def git(repo: Path, *argv: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), *argv], text=True, stderr=subprocess.DEVNULL
    ).strip()


def dirty_paths(git_directory: Path, work_tree: Path) -> set[str]:
    encoded = subprocess.check_output(
        ["git", f"--git-dir={git_directory}", f"--work-tree={work_tree}",
         "status", "--porcelain=v1", "-z", "--untracked-files=all"]
    )
    entries = encoded.split(b"\0")
    paths: set[str] = set()
    index = 0
    while index < len(entries) and entries[index]:
        entry = entries[index]
        if len(entry) < 4 or entry[2:3] != b" ":
            fail("candidate git status returned malformed output")
        status = entry[:2]
        try:
            paths.add(entry[3:].decode("utf-8"))
        except UnicodeDecodeError as error:
            raise ValueError("candidate contains a non-UTF-8 changed path") from error
        if b"R" in status or b"C" in status:
            fail("rebuild stages may not rename or copy source paths")
        index += 1
    return paths


def relative(value: str, label: str) -> Path:
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts or str(path) != value:
        fail(f"{label} must be a canonical relative path")
    return path


def direct_directory(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        fail(f"{label} must be an absolute direct directory")
    if path.resolve() != path:
        fail(f"{label} must not contain symbolic-link components")
    mode = path.stat().st_mode
    if mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
        fail(f"{label} must be an immutable non-writable directory")
    return path


def validate_cache_manifest(path: Path, expected_sha: str, root_value: str) -> tuple[Path, list[dict]]:
    if not path.is_absolute():
        fail("offline cache manifest must be absolute")
    value = pinned_json(path, expected_sha, "offline cache manifest")
    if set(value) != {"schema", "root", "entries"} or value.get("schema") != CACHE_SCHEMA:
        fail("offline cache manifest must use the exact supported schema")
    root = direct_directory(root_value, "offline Cargo home")
    if value.get("root") != str(root):
        fail("offline cache root differs from its authenticated manifest")
    entries = value.get("entries")
    if not isinstance(entries, list):
        fail("offline cache entries must be an array")
    expected_paths: list[str] = []
    for index, item in enumerate(entries):
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size", "mode"}:
            fail(f"offline cache entry {index} has an invalid schema")
        rel = relative(item["path"], f"offline cache entry {index}")
        rel_text = str(rel)
        if expected_paths and rel_text <= expected_paths[-1]:
            fail("offline cache entries must be unique and byte-sorted")
        if not re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])):
            fail(f"offline cache entry {index} has a malformed SHA-256")
        if not isinstance(item["size"], int) or item["size"] < 0:
            fail(f"offline cache entry {index} has an invalid size")
        if not isinstance(item["mode"], int) or item["mode"] not in (0o400, 0o500):
            fail(f"offline cache entry {index} has an invalid immutable mode")
        target = root / rel
        info = target.lstat()
        if target.is_symlink() or not target.is_file() or info.st_nlink != 1:
            fail(f"offline cache entry is not a direct single-link file: {rel_text}")
        if stat.S_IMODE(info.st_mode) != item["mode"] or info.st_size != item["size"] or sha256(target) != item["sha256"]:
            fail(f"offline cache entry differs from its manifest: {rel_text}")
        expected_paths.append(rel_text)
    actual_paths: list[str] = []
    for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        for name in directories:
            child = base / name
            if child.is_symlink():
                fail("offline cache contains a symbolic-link directory")
            if child.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
                fail("offline cache contains a writable directory")
        for name in files:
            actual_paths.append(str((base / name).relative_to(root)))
    if sorted(actual_paths) != expected_paths:
        fail("offline cache contents differ from its authenticated inventory")
    return root, entries


def load_manifest(path: Path, expected_sha: str) -> dict:
    value = pinned_json(path, expected_sha, "manifest")
    if set(value) != {"schema", "sourceCommit", "sourceTree", "tools", "environment", "stages"}:
        fail("manifest must use the exact supported schema")
    if value["schema"] != SCHEMA:
        fail("unsupported orchestrator manifest schema")
    if not isinstance(value["sourceCommit"], str) or len(value["sourceCommit"]) != 40:
        fail("sourceCommit must be a full commit identifier")
    if not isinstance(value["sourceTree"], str) or len(value["sourceTree"]) != 40:
        fail("sourceTree must be a full tree identifier")
    if not isinstance(value["tools"], list) or not value["tools"]:
        fail("at least one pinned tool is required")
    environment = value["environment"]
    required_environment = {"cargoHome", "cargoHomeManifest", "cargoHomeManifestSha256", "rustc", "rustdoc"}
    if not isinstance(environment, dict) or set(environment) != required_environment:
        fail("environment must use the exact offline Rust schema")
    for field in ("cargoHome", "cargoHomeManifest", "rustc", "rustdoc"):
        if not isinstance(environment[field], str) or not Path(environment[field]).is_absolute():
            fail(f"environment {field} must be an absolute path")
    if not re.fullmatch(r"[0-9a-f]{64}", str(environment["cargoHomeManifestSha256"])):
        fail("environment cargoHomeManifestSha256 is malformed")
    if not isinstance(value["stages"], list) or [x.get("name") for x in value["stages"]] != list(STAGE_ORDER):
        fail("stages must use the exact dependency order")
    for index, tool in enumerate(value["tools"]):
        if set(tool) != {"path", "sha256"} or not isinstance(tool["path"], str):
            fail(f"tool {index} must use the exact supported schema")
        if len(tool["sha256"]) != 64:
            fail(f"tool {index} has a malformed SHA-256")
    produced: dict[str, str] = {}
    previous_outputs: list[str] = []
    for stage in value["stages"]:
        if set(stage) != {"name", "argv", "verificationArgv", "verificationSteps", "inputs", "outputs", "verification"} or not isinstance(stage["argv"], list) or not stage["argv"]:
            fail(f"stage {stage.get('name')} must use the exact supported schema")
        if not all(isinstance(item, str) and item and "\0" not in item for item in stage["argv"]):
            fail(f"stage {stage['name']} argv is invalid")
        if (
            not isinstance(stage["verificationArgv"], list)
            or not stage["verificationArgv"]
            or stage["verificationArgv"] == stage["argv"]
            or stage["verificationArgv"][0] == stage["argv"][0]
            or not all(
                isinstance(item, str) and item and "\0" not in item
                for item in stage["verificationArgv"]
            )
        ):
            fail(f"stage {stage['name']} must use a distinct verification command")
        if not isinstance(stage["outputs"], list) or not stage["outputs"]:
            fail(f"stage {stage['name']} must declare outputs")
        if not isinstance(stage["verificationSteps"], list) or (stage["name"] != "receipts" and stage["verificationSteps"]):
            fail(f"stage {stage['name']} verification steps are invalid")
        if not isinstance(stage["inputs"], list):
            fail(f"stage {stage['name']} inputs must be an array")
        inputs = [str(relative(item, f"{stage['name']} input")) for item in stage["inputs"]]
        if inputs != previous_outputs:
            fail(f"stage {stage['name']} must consume every output of its immediate predecessor in order")
        for output in stage["outputs"]:
            output = str(relative(output, f"{stage['name']} output"))
            if output in produced:
                fail(f"stage output {output} is also produced by {produced[output]}")
            produced[output] = stage["name"]
        for number, step in enumerate(stage["verificationSteps"]):
            if set(step) != {"argv", "outputs"} or not isinstance(step["argv"], list) or not step["argv"] or not isinstance(step["outputs"], list) or not step["outputs"]:
                fail(f"stage {stage['name']} verification step {number} schema is invalid")
            if step["argv"][0] in (stage["argv"][0], stage["verificationArgv"][0]) or not all(isinstance(item, str) and item and "\0" not in item for item in step["argv"]):
                fail(f"stage {stage['name']} verification step {number} command is not independent")
            for output in step["outputs"]:
                output = str(relative(output, f"{stage['name']} verification-step output"))
                if output in produced:
                    fail(f"stage verification-step output {output} is also produced by {produced[output]}")
                produced[output] = stage["name"]
        verification = str(relative(stage["verification"], f"{stage['name']} verification"))
        if verification in produced:
            fail(f"stage verification {verification} collides with an output")
        produced[verification] = stage["name"]
        previous_outputs = list(stage["outputs"])
    return value


def validate_tools(manifest: dict) -> dict[str, str]:
    pinned: dict[str, str] = {}
    for item in manifest["tools"]:
        path = Path(item["path"])
        if not path.is_absolute() or not path.is_file() or path.is_symlink():
            fail(f"pinned tool is not a direct regular file: {path}")
        mode = path.stat().st_mode
        if not mode & stat.S_IXUSR or sha256(path) != item["sha256"]:
            fail(f"pinned tool identity differs: {path}")
        pinned[str(path)] = item["sha256"]
    return pinned


def validate_environment(manifest: dict, tools: dict[str, str]) -> dict:
    value = manifest["environment"]
    for name in ("rustc", "rustdoc"):
        if value[name] not in tools:
            fail(f"environment {name} is not one of the pinned tools")
    cargo_home, entries = validate_cache_manifest(
        Path(value["cargoHomeManifest"]), value["cargoHomeManifestSha256"], value["cargoHome"]
    )
    return {
        "source": cargo_home,
        "entries": entries,
        "manifest": value["cargoHomeManifest"],
        "manifestSha256": value["cargoHomeManifestSha256"],
        "rustc": value["rustc"],
        "rustdoc": value["rustdoc"],
    }


def materialize_cache(source: Path, entries: list[dict], destination: Path) -> None:
    shutil.copytree(source, destination, symlinks=False)
    actual_paths: list[str] = []
    for directory, directories, files in os.walk(destination, topdown=True, followlinks=False):
        base = Path(directory)
        for name in directories:
            if (base / name).is_symlink():
                fail("materialized offline cache contains a symbolic-link directory")
        for name in files:
            target = base / name
            rel_text = str(target.relative_to(destination))
            if target.is_symlink() or not target.is_file() or target.stat().st_nlink != 1:
                fail(f"materialized offline cache entry is indirect: {rel_text}")
            actual_paths.append(rel_text)
    expected_paths = [item["path"] for item in entries]
    if sorted(actual_paths) != expected_paths:
        fail("materialized offline cache inventory differs")
    for item in entries:
        target = destination / relative(item["path"], "materialized offline cache entry")
        info = target.stat()
        if info.st_size != item["size"] or sha256(target) != item["sha256"]:
            fail(f"materialized offline cache entry differs: {item['path']}")
    for directory, _, files in os.walk(destination, topdown=False, followlinks=False):
        base = Path(directory)
        for name in files:
            target = base / name
            source_mode = stat.S_IMODE(target.stat().st_mode)
            target.chmod(0o700 if source_mode & stat.S_IXUSR else 0o600)
        base.chmod(0o700)


def fsync_tree(root: Path) -> None:
    directories: list[Path] = []
    for directory, child_directories, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        directories.append(base)
        for name in child_directories:
            if (base / name).is_symlink():
                fail("candidate contains a symbolic-link directory")
        for name in files:
            target = base / name
            descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    for directory in reversed(directories):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def seal_tree_read_only(root: Path) -> None:
    for directory, _, files in os.walk(root, topdown=False, followlinks=False):
        base = Path(directory)
        for name in files:
            target = base / name
            mode = stat.S_IMODE(target.stat().st_mode)
            target.chmod(0o500 if mode & stat.S_IXUSR else 0o400)
        base.chmod(0o500)


def make_tree_removable(root: Path) -> None:
    if not root.exists() or root.is_symlink():
        return
    for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        base.chmod(0o700)
        for name in directories:
            child = base / name
            if not child.is_symlink():
                child.chmod(0o700)
        for name in files:
            target = base / name
            if not target.is_symlink():
                target.chmod(0o600)


def rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        fail("renameat2(RENAME_NOREPLACE) is unavailable; refusing non-atomic publication")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(AT_FDCWD, os.fsencode(source), AT_FDCWD, os.fsencode(destination), RENAME_NOREPLACE)
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            fail("output appeared during publication; refusing overwrite")
        if code in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP):
            fail("renameat2(RENAME_NOREPLACE) is unsupported; refusing non-atomic publication")
        raise OSError(code, os.strerror(code), str(destination))


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_handoff(path: Path, expected_sha: str) -> dict:
    value = pinned_json(path, expected_sha, "handoff recipe")
    common = {"schema", "classification", "releaseAllowed", "promotionAllowed",
              "runManifestSha256", "proofSchema", "reason"}
    terminal = common | {"terminalSha256"}
    if set(value) not in (common, terminal) or value.get("schema") != "usdom-long-proof-handoff-v1":
        fail("handoff recipe must use the exact supported schema")
    if value.get("releaseAllowed") is not True or value.get("classification") not in {
        "current-complete", "historical-stale", "failed-stale"
    }:
        fail("handoff recipe does not authorize release of the old proof resources")
    if "terminalSha256" not in value or not all(
        isinstance(value.get(field), str) and re.fullmatch(r"[0-9a-f]{64}", value[field])
        for field in ("runManifestSha256", "terminalSha256")
    ):
        fail("handoff recipe has no authenticated terminal identity")
    if value["classification"] == "current-complete" and value.get("promotionAllowed") is not True:
        fail("current handoff classification has inconsistent promotion authority")
    if value["classification"] != "current-complete" and value.get("promotionAllowed") is not False:
        fail("stale handoff classification has inconsistent promotion authority")
    return value


def snapshot(repo: Path, commit: str, destination: Path) -> None:
    archive = destination.parent / "source.tar"
    with archive.open("wb") as output:
        subprocess.run(
            ["git", "-C", str(repo), "archive", "--format=tar", commit],
            stdout=output, check=True,
        )
    with tarfile.open(archive) as bundle:
        for member in bundle.getmembers():
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk():
                fail("source archive contains an unsafe path or link")
        bundle.extractall(destination, filter="data")


def execute(args: argparse.Namespace) -> dict:
    manifest_path = Path(args.manifest).resolve()
    manifest = load_manifest(manifest_path, args.expected_manifest_sha256)
    handoff_path = Path(args.handoff_recipe).resolve()
    handoff = validate_handoff(handoff_path, args.expected_handoff_sha256)
    repo = Path(args.repository).resolve()
    output = Path(args.output).resolve()
    lock_path = Path(args.lock).resolve()
    if output.exists() or output.is_symlink():
        fail("output already exists; immutable candidate publication refuses overwrite")
    if git(repo, "status", "--porcelain=v1", "--untracked-files=all"):
        fail("source repository is dirty")
    if git(repo, "rev-parse", "HEAD") != manifest["sourceCommit"]:
        fail("HEAD differs from the pinned sourceCommit")
    if git(repo, "rev-parse", "HEAD^{tree}") != manifest["sourceTree"]:
        fail("source tree differs from the pinned sourceTree")
    source_git_directory = Path(git(repo, "rev-parse", "--absolute-git-dir"))
    tools = validate_tools(manifest)
    rust_environment = validate_environment(manifest, tools)
    plan = {"schema": SCHEMA, "sourceCommit": manifest["sourceCommit"],
            "sourceTree": manifest["sourceTree"], "manifestSha256": args.expected_manifest_sha256,
            "handoffSha256": args.expected_handoff_sha256,
            "handoffClassification": handoff["classification"],
            "offlineCargoHomeManifest": rust_environment["manifest"],
            "offlineCargoHomeManifestSha256": rust_environment["manifestSha256"],
            "tools": tools, "stages": [stage["name"] for stage in manifest["stages"]],
            "output": str(output), "published": False}
    if args.dry_run:
        return plan
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("another checkpoint rebuild holds the lock")
        output.parent.mkdir(parents=True, exist_ok=True)
        # A deterministic private workspace permits a crash-safe restart.  Its
        # marker only selects the generation; every skipped producer output is
        # independently reverified below before it can be trusted.
        temporary = output.parent / f".{output.name}.resume-v3"
        resume_marker = temporary / "REBUILD-RESUME.json"
        resumed = temporary.exists()
        if resumed:
            if temporary.is_symlink() or not temporary.is_dir():
                fail("rebuild resume workspace is indirect")
            marker = pinned_json(resume_marker, sha256(resume_marker), "rebuild resume marker")
            if marker != plan:
                fail("rebuild resume workspace belongs to another authenticated generation")
        else:
            temporary.mkdir(mode=0o700)
        try:
            candidate = temporary / "candidate"
            cargo_home = temporary / "cargo-home"
            if not resumed:
                candidate.mkdir()
                snapshot(repo, manifest["sourceCommit"], candidate)
                materialize_cache(rust_environment["source"], rust_environment["entries"], cargo_home)
                resume_marker.write_text(json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n")
                fsync_tree(temporary)
            safe_path = os.pathsep.join(str(Path(path).parent) for path in tools)
            env = {"HOME": str(temporary / "home"), "LANG": "C", "LC_ALL": "C",
                   "PATH": safe_path, "SOURCE_DATE_EPOCH": "0", "TZ": "UTC",
                   "CARGO_HOME": str(cargo_home), "CARGO_NET_OFFLINE": "true",
                   "RUSTC": rust_environment["rustc"], "RUSTDOC": rust_environment["rustdoc"]}
            (temporary / "home").mkdir(mode=0o700)
            published_outputs: dict[str, str] = {}
            for stage in manifest["stages"]:
                executable = stage["argv"][0]
                if executable not in tools:
                    fail(f"stage {stage['name']} uses an unpinned executable")
                authenticated_inputs = {
                    item: sha256(candidate / relative(item, "stage input"))
                    for item in stage["inputs"]
                    if (candidate / relative(item, "stage input")).is_file()
                }
                if len(authenticated_inputs) != len(stage["inputs"]):
                    fail(f"stage {stage['name']} is missing a predecessor output")
                stage_env = {**env, "USDOM_AUTHENTICATED_STAGE_INPUTS": json.dumps(
                    authenticated_inputs, sort_keys=True, separators=(",", ":")
                )}
                before = {item: sha256(candidate / relative(item, "stage output"))
                          for item in stage["outputs"] if (candidate / relative(item, "stage output")).is_file()}
                prior_verification = candidate / relative(stage["verification"], "stage verification")
                stage_resumed = (resumed and len(before) == len(stage["outputs"])
                                 and prior_verification.is_file() and not prior_verification.is_symlink())
                if not stage_resumed:
                    if resumed:
                        for item in stage["outputs"]:
                            target = candidate / relative(item, "incomplete stage output")
                            if target.is_file() and not target.is_symlink():
                                target.unlink()
                        if prior_verification.is_file() and not prior_verification.is_symlink():
                            prior_verification.unlink()
                        for step in stage["verificationSteps"]:
                            for item in step["outputs"]:
                                target = candidate / relative(item, "incomplete verification output")
                                if target.is_file() and not target.is_symlink():
                                    target.unlink()
                        before = {}
                    if validate_tools(manifest) != tools:
                        fail(f"pinned tool set changed before stage {stage['name']}")
                    command(stage["argv"], candidate, stage_env, tools[executable])
                    if validate_tools(manifest) != tools:
                        fail(f"pinned tool set changed during stage {stage['name']}")
                for item, digest in authenticated_inputs.items():
                    target = candidate / relative(item, "stage input")
                    if not target.is_file() or target.is_symlink() or sha256(target) != digest:
                        fail(f"stage {stage['name']} changed authenticated predecessor output {item}")
                for item, digest in published_outputs.items():
                    target = candidate / relative(item, "published stage output")
                    if not target.is_file() or target.is_symlink() or sha256(target) != digest:
                        fail(f"stage {stage['name']} changed earlier stage output {item}")
                for item in stage["outputs"]:
                    target = candidate / relative(item, "stage output")
                    if not target.is_file() or target.is_symlink():
                        fail(f"stage {stage['name']} did not produce direct output {item}")
                    if not stage_resumed and stage["name"] == "receipts" and item in before:
                        fail(f"stage receipts inherited prior-generation output {item}")
                    if not stage_resumed and stage["name"] in ("segment", "outer", "finalized-burn") and before.get(item) == sha256(target):
                        fail(f"stage {stage['name']} left stale output {item}")
                    published_outputs[item] = sha256(target)
                stage_output_names = list(stage["outputs"])
                for number, step in enumerate(stage["verificationSteps"]):
                    step_executable = step["argv"][0]
                    if step_executable not in tools:
                        fail(f"stage {stage['name']} verification step {number} uses an unpinned executable")
                    for item in step["outputs"]:
                        target = candidate / relative(item, "verification-step output")
                        if stage_resumed and target.is_file() and not target.is_symlink():
                            target.unlink()
                        if target.exists() or target.is_symlink():
                            fail(f"stage {stage['name']} verification step {number} output already exists")
                    fixed_before = dict(published_outputs)
                    step_env = {**stage_env, "USDOM_AUTHENTICATED_STAGE_OUTPUTS": json.dumps(
                        {item: published_outputs[item] for item in stage_output_names},
                        sort_keys=True, separators=(",", ":")
                    )}
                    if validate_tools(manifest) != tools:
                        fail(f"pinned tool set changed before verification step {number} of stage {stage['name']}")
                    command(step["argv"], candidate, step_env, tools[step_executable])
                    if validate_tools(manifest) != tools:
                        fail(f"pinned tool set changed during verification step {number} of stage {stage['name']}")
                    for item, digest in fixed_before.items():
                        target = candidate / relative(item, "fixed stage output")
                        if not target.is_file() or target.is_symlink() or sha256(target) != digest:
                            fail(f"stage {stage['name']} verification step {number} changed fixed output {item}")
                    for item in step["outputs"]:
                        target = candidate / relative(item, "verification-step output")
                        if not target.is_file() or target.is_symlink() or target.stat().st_nlink != 1:
                            fail(f"stage {stage['name']} verification step {number} did not create a direct output")
                        published_outputs[item] = sha256(target)
                        stage_output_names.append(item)
                verifier_executable = stage["verificationArgv"][0]
                if verifier_executable not in tools:
                    fail(f"stage {stage['name']} uses an unpinned verification executable")
                verification_env = {**stage_env, "USDOM_AUTHENTICATED_STAGE_OUTPUTS": json.dumps(
                    {item: published_outputs[item] for item in stage_output_names},
                    sort_keys=True, separators=(",", ":")
                )}
                verification_path = candidate / relative(stage["verification"], "stage verification")
                if stage_resumed and verification_path.is_file() and not verification_path.is_symlink():
                    verification_path.unlink()
                if validate_tools(manifest) != tools:
                    fail(f"pinned tool set changed before verification of stage {stage['name']}")
                command(stage["verificationArgv"], candidate, verification_env, tools[verifier_executable])
                if validate_tools(manifest) != tools:
                    fail(f"pinned tool set changed during verification of stage {stage['name']}")
                if not verification_path.is_file() or verification_path.is_symlink() or verification_path.stat().st_nlink != 1:
                    fail(f"stage {stage['name']} did not publish a direct verification record")
                verification = json.loads(verification_path.read_text(encoding="utf-8"))
                expected_verification_keys = {"schema", "stage", "inputs", "outputs", "claims"}
                if set(verification) != expected_verification_keys or verification.get("schema") != "usdom-rebuild-stage-verification-v1" or verification.get("stage") != stage["name"]:
                    fail(f"stage {stage['name']} verification record has an invalid identity")
                expected_inputs = authenticated_inputs
                expected_outputs = {item: published_outputs[item] for item in stage_output_names}
                if verification.get("inputs") != expected_inputs or verification.get("outputs") != expected_outputs:
                    fail(f"stage {stage['name']} verification record does not bind exact artifacts")
                claims = verification.get("claims")
                if not isinstance(claims, dict) or set(claims) != STAGE_CLAIMS[stage["name"]] or not all(value is True for value in claims.values()):
                    fail(f"stage {stage['name']} verification record lacks mandatory semantic checks")
                published_outputs[stage["verification"]] = sha256(verification_path)
                allowed_changes = set(published_outputs)
                unexpected = dirty_paths(source_git_directory, candidate) - allowed_changes
                if unexpected:
                    fail(f"stage {stage['name']} changed undeclared path {sorted(unexpected)[0]}")
            record = temporary / "REBUILD-RESULT.json"
            record.write_text(json.dumps({**plan, "published": True}, indent=2, sort_keys=True) + "\n")
            seal_tree_read_only(temporary)
            fsync_tree(temporary)
            rename_noreplace(temporary, output)
            fsync_directory(output.parent)
            temporary = None
        finally:
            # Preserve an authenticated incomplete generation for restart.  A
            # successful publication moves it atomically and sets temporary to
            # None. Operators may explicitly discard the workspace if desired.
            pass
        return {**plan, "published": True}
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--handoff-recipe", required=True)
    parser.add_argument("--expected-handoff-sha256", required=True)
    parser.add_argument("--repository", default=str(ROOT))
    parser.add_argument("--output", required=True)
    parser.add_argument("--lock", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(execute(args), indent=2, sort_keys=True))
        return 0
    except (ValueError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"checkpoint rebuild refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
