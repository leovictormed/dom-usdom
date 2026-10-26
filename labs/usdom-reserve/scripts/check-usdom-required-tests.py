#!/usr/bin/env python3
"""Reject silent skips in release-critical USDOM tests."""

from pathlib import Path
import re
import stat
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[3]
LONG = ROOT / "crates/dom-usdom-checkpoint-program/tests/v2_checkpoint_extension.rs"
RUNNER = ROOT / "labs/usdom-reserve/scripts/run-checkpoint-390-release-vector.sh"
RANDOMX_RUNNER = ROOT / "labs/usdom-reserve/scripts/run-randomx-cache-release-vector.sh"
RELEASE_RUNNER = ROOT / "labs/usdom-reserve/scripts/run-usdom-release-vectors.sh"
SUPERVISED_PREPARER = ROOT / "labs/usdom-reserve/scripts/prepare-usdom-release-validation-jobs.sh"
SUPERVISOR = ROOT / "labs/usdom-reserve/scripts/run-supervised-long-proof.py"
CI = ROOT / ".github/workflows/ci.yml"

allowed_ignores = [
    ("crates/dom-usdom-checkpoint-program/tests/v2_checkpoint_extension.rs",
     "full 390-block release-vector exercise"),
    ("crates/dom-usdom-privacy/src/verifier.rs",
     "operator benchmark; deterministic setup is intentionally expensive"),
    ("crates/dom-usdom-randomx-portable/src/dataset.rs",
     "allocates and hashes the canonical 256 MiB RandomX cache"),
]

failures = []
found = []
for path in sorted(ROOT.glob("crates/dom-usdom-*/**/*.rs")):
    relative = str(path.relative_to(ROOT))
    for match in re.finditer(r'#\[ignore(?:\s*=\s*"([^"]*)")?\]', path.read_text()):
        found.append((relative, match.group(1) or ""))
if sorted(found) != sorted(allowed_ignores):
    failures.append(f"Rust ignore inventory drift: {found!r}")

for base, patterns in [
    (ROOT / "labs/usdom-reserve/test", (r"\b(?:test|describe|it)\.skip\s*\(",)),
    (ROOT / "labs/usdom-reserve/test", (r"\bvm\.skip\s*\(",)),
]:
    for path in base.rglob("*"):
        if path.suffix in {".js", ".mjs", ".sol"}:
            text = path.read_text()
            if any(re.search(pattern, text) for pattern in patterns):
                failures.append(f"silent Node/Foundry skip: {path.relative_to(ROOT)}")

long_source = LONG.read_text()
runner = RUNNER.read_text() if RUNNER.is_file() else ""
randomx_runner = RANDOMX_RUNNER.read_text() if RANDOMX_RUNNER.is_file() else ""
release_runner = RELEASE_RUNNER.read_text() if RELEASE_RUNNER.is_file() else ""
supervised_preparer = SUPERVISED_PREPARER.read_text() if SUPERVISED_PREPARER.is_file() else ""
supervisor = SUPERVISOR.read_text()
ci = CI.read_text()
workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())
release_validation = workspace.get("profile", {}).get("release-validation", {})
required = {
    "long test remains explicitly classified": '#[ignore = "full 390-block release-vector exercise"]' in long_source,
    "short CI guard is active": "#[test]\n    fn short_390_v6_target_binding_rejects_span_total_and_closure_drift" in
        (ROOT / "crates/dom-usdom-checkpoint-program/src/reference.rs").read_text(),
    "runner selects release-validation": "cargo test --profile release-validation --locked --offline -j1" in runner,
    "runner selects only exact ignored vector": all(token in runner for token in (
        "full_360_plus_30_v2_checkpoint_extension_is_recomputed", "--exact --ignored", "--test-threads=1")),
    "runner requires explicit operator opt-in": 'USDOM_RUN_LONG_RELEASE_TEST-}" != "YES"' in runner,
    "runner is executable": RUNNER.is_file() and bool(RUNNER.stat().st_mode & stat.S_IXUSR),
    "RandomX release runner selects exact canonical cache vector": all(token in randomx_runner for token in (
        "cargo test --profile release-validation --locked --offline -j1",
        "dataset::tests::upstream_randomx_argon2d_cache_vector_matches",
        "--exact --ignored",
    )),
    "RandomX release runner is executable": RANDOMX_RUNNER.is_file()
        and bool(RANDOMX_RUNNER.stat().st_mode & stat.S_IXUSR),
    "aggregate release runner cannot omit either mandatory vector": all(token in release_runner for token in (
        '"$here/run-randomx-cache-release-vector.sh"',
        '"$here/run-checkpoint-390-release-vector.sh"',
    )),
    "aggregate release runner is executable": RELEASE_RUNNER.is_file()
        and bool(RELEASE_RUNNER.stat().st_mode & stat.S_IXUSR),
    "supervised release jobs bind resources, inputs and exact output": all(token in supervised_preparer for token in (
        "--max-runtime-seconds 43200", "--max-runtime-seconds 14400",
        "--max-log-bytes 67108864", "--min-free-bytes 21474836480",
        "--bind-input Cargo.lock", "--require-output 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;'",
        "--locked --offline -j1", "--exact --ignored", "--test-threads=1",
    )),
    "supervised release preparer is executable": SUPERVISED_PREPARER.is_file()
        and bool(SUPERVISED_PREPARER.stat().st_mode & stat.S_IXUSR),
    "authenticated supervisor hashes evidence and fails closed on limits/drift/skip": all(token in supervisor for token in (
        '"processLogSha256"', '"eventsSha256"', 'event("resource-limit"',
        'event("bound-input-drift"', 'event("required-output-mismatch"',
    )),
    "release-validation inherits release": release_validation.get("inherits") == "release",
    "release-validation retains line locations": release_validation.get("debug") == 1,
    "short guard is selected exactly in CI": all(token in ci for token in (
        "cargo test --locked --offline -j1",
        "-p dom-usdom-checkpoint-program --features host-reference",
        "reference::tests::short_390_v6_target_binding_rejects_span_total_and_closure_drift -- --exact",
    )),
}
failures.extend(message for message, condition in required.items() if not condition)

if failures:
    print("USDOM required-test policy: FAIL", file=sys.stderr)
    for failure in failures:
        print(f"- {failure}", file=sys.stderr)
    raise SystemExit(1)
print("USDOM required-test policy: PASS (two mandatory release vectors, one active short CI guard, no silent Node/Foundry skips)")
