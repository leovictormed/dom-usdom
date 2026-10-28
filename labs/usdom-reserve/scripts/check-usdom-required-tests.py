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
NATIVE_PRIVACY_RUNNER = ROOT / "labs/usdom-reserve/scripts/run-native-privacy-production-release-vector.sh"
RELEASE_RUNNER = ROOT / "labs/usdom-reserve/scripts/run-usdom-release-vectors.sh"
SUPERVISED_PREPARER = ROOT / "labs/usdom-reserve/scripts/prepare-usdom-release-validation-jobs.sh"
SUPERVISOR = ROOT / "labs/usdom-reserve/scripts/run-supervised-long-proof.py"
RESULT_MATERIALIZER = ROOT / "labs/usdom-reserve/scripts/materialize-usdom-release-validation-report.py"
RESULT_INSTALLER = ROOT / "labs/usdom-reserve/scripts/materialize-usdom-release-validation-evidence.mjs"
SUPERVISED_EXECUTOR = ROOT / "labs/usdom-reserve/scripts/execute-usdom-release-validation-jobs.sh"
PHASE_GENERATOR = ROOT / "labs/usdom-reserve/scripts/generate-closed-mainnet-phase-command.sh"
READINESS = ROOT / "labs/usdom-reserve/sdk/mainnet-readiness.mjs"
CI = ROOT / ".github/workflows/ci.yml"
PILOT_GATE_STATE_MACHINE = ROOT / "labs/usdom-reserve/test/node/pilot-gate-state-machine-stage1608.test.mjs"
PILOT_GATE_EMERGENCY_CANCEL = ROOT / "labs/usdom-reserve/test/node/pilot-gate-emergency-cancel-stage1610.test.mjs"
OPERATOR_COMMAND_FLOW = ROOT / "labs/usdom-reserve/test/node/operator-command-flow-stage1611.test.mjs"
FINAL_ABI_COLLISION = ROOT / "labs/usdom-reserve/test/node/final-abi-collision-stage1617.test.mjs"
RESERVE_CONSTRUCTOR_EQUIVALENCE = ROOT / "labs/usdom-reserve/test/node/reserve-constructor-equivalence-stage1618.test.mjs"
FINAL_SOLIDITY_REPRODUCIBILITY = ROOT / "labs/usdom-reserve/test/node/solidity-build-reproducibility-stage1614.test.mjs"
CURRENT_OPERATIONAL_CLAIMS = ROOT / "labs/usdom-reserve/test/node/current-operational-claims-stage1628.test.mjs"

allowed_ignores = [
    ("crates/dom-usdom-checkpoint-program/tests/v2_checkpoint_extension.rs",
     "full 390-block release-vector exercise"),
    ("crates/dom-usdom-privacy/src/phase1.rs",
     "production-size algebraic integration; run explicitly for release evidence"),
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
native_privacy_runner = NATIVE_PRIVACY_RUNNER.read_text() if NATIVE_PRIVACY_RUNNER.is_file() else ""
release_runner = RELEASE_RUNNER.read_text() if RELEASE_RUNNER.is_file() else ""
supervised_preparer = SUPERVISED_PREPARER.read_text() if SUPERVISED_PREPARER.is_file() else ""
supervisor = SUPERVISOR.read_text()
result_materializer = RESULT_MATERIALIZER.read_text() if RESULT_MATERIALIZER.is_file() else ""
result_installer = RESULT_INSTALLER.read_text() if RESULT_INSTALLER.is_file() else ""
supervised_executor = SUPERVISED_EXECUTOR.read_text() if SUPERVISED_EXECUTOR.is_file() else ""
phase_generator = PHASE_GENERATOR.read_text() if PHASE_GENERATOR.is_file() else ""
readiness = READINESS.read_text()
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
    "native-privacy release runner selects exact production specialization": all(
        token in native_privacy_runner for token in (
            "cargo test --profile release-validation --locked --offline -j1",
            "-p dom-usdom-privacy",
            "phase1::tests::production_specialization_matches_real_prover_and_all_public_inputs",
            "--exact --ignored",
        )
    ),
    "native-privacy release runner is executable": NATIVE_PRIVACY_RUNNER.is_file()
        and bool(NATIVE_PRIVACY_RUNNER.stat().st_mode & stat.S_IXUSR),
    "aggregate release runner cannot omit any mandatory vector": all(token in release_runner for token in (
        '"$here/run-randomx-cache-release-vector.sh"',
        '"$here/run-checkpoint-390-release-vector.sh"',
        '"$here/run-native-privacy-production-release-vector.sh"',
    )),
    "aggregate release runner is executable": RELEASE_RUNNER.is_file()
        and bool(RELEASE_RUNNER.stat().st_mode & stat.S_IXUSR),
    "supervised release jobs bind resources, inputs and exact output": all(token in supervised_preparer for token in (
        "--max-runtime-seconds 43200", "--max-runtime-seconds 14400",
        "--max-log-bytes 67108864", "--min-free-bytes 21474836480",
        "--bind-input Cargo.lock", "--require-output 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;'",
        "--locked --offline -j1", "--exact --ignored", "--test-threads=1",
        "phase1::tests::production_specialization_matches_real_prover_and_all_public_inputs",
        "USDOM_RELEASE_ID", "USDOM_SOURCE_COMMIT", "USDOM_SOURCE_TAG",
    )),
    "supervised release preparer is executable": SUPERVISED_PREPARER.is_file()
        and bool(SUPERVISED_PREPARER.stat().st_mode & stat.S_IXUSR),
    "authenticated supervisor hashes evidence and fails closed on limits/drift/skip": all(token in supervisor for token in (
        '"processLogSha256"', '"eventsSha256"', 'event("resource-limit"',
        'event("bound-input-drift"', 'event("required-output-mismatch"',
    )),
    "release gate consumes three authenticated supervised results": all(token in result_materializer for token in (
        'KINDS=("checkpoint390","randomxCache","nativePrivacy")', 'terminal["exitStatus"]!=0',
        'terminal["processLogSha256"]', 'terminal["eventsSha256"]', 'release/toolchain environment mismatch',
    )) and "releaseValidationReport" in readiness and "validateReleaseValidationReport" in readiness,
    "release result cannot be synthetic or omit its source closure": all(token in result_materializer for token in (
        "seen!=expected_inputs", "checkpoint-program/src/economic_chunks.rs",
        "randomx-portable/src/bytecode.rs", "dom-usdom-privacy/MANIFEST.sha256",
    )) and all(token in result_installer for token in (
        "materialize-usdom-release-validation-report.py", "reproduced.equals(reportBytes)",
        ".config/usdom-proof/jobs", ".local/state/usdom-proof",
    )),
    "capacity phase executes the three supervised vectors": all(token in supervised_executor for token in (
        "install-supervised-proof-user-service.py", "systemctl --user start",
        "control-supervised-long-proof.py", "materialize-usdom-release-validation-report.py",
    )) and all(token in phase_generator for token in (
        "execute:release-validation-jobs -- pre-ceremony",
        "execute:release-validation-jobs -- post-ceremony",
    )),
    "release-validation inherits release": release_validation.get("inherits") == "release",
    "release-validation retains line locations": release_validation.get("debug") == 1,
    "short guard is selected exactly in CI": all(token in ci for token in (
        "cargo test --locked --offline -j1",
        "-p dom-usdom-checkpoint-program --features host-reference",
        "reference::tests::short_390_v6_target_binding_rejects_span_total_and_closure_drift -- --exact",
    )),
    "pilot gate crash/replay mutation guard is mandatory": PILOT_GATE_STATE_MACHINE.is_file()
        and all(token in PILOT_GATE_STATE_MACHINE.read_text() for token in (
            "for(let round=0;round<128;round++)", ".pilot-funds-rotation.json",
            "clearExpiredPilotDepositAuthorization(bytes32,uint64)",
            "pilot-deposit-gate-clear-finalized.json",
        )),
    "pilot gate emergency cancellation guard is mandatory": PILOT_GATE_EMERGENCY_CANCEL.is_file()
        and all(token in PILOT_GATE_EMERGENCY_CANCEL.read_text() for token in (
            "cancelPilotDepositAuthorization", "AUTORIZO CANCELAR GATE PILOTO OWNER",
            "PilotDepositAuthorizationCancelled", "never rearms",
        )),
    "complete placeholder-free operator command flow is mandatory": OPERATOR_COMMAND_FLOW.is_file()
        and all(token in OPERATOR_COMMAND_FLOW.read_text() for token in (
            "plan.phaseOrder.length,23", "unresolved USDOM variable",
            "fund-moving commands exist only", "generated by pinned tools or hardware",
        )),
    "final ABI selector, event, error, storage and consumer guard is mandatory": FINAL_ABI_COLLISION.is_file()
        and all(token in FINAL_ABI_COLLISION.read_text() for token in (
            "function/error selector", "event topic", "storage overlap",
            "stale pilot ABI consumer", "pilotAuthorizationGeneration",
        )),
    "final Solidity build semantic reproducibility guard is mandatory": FINAL_SOLIDITY_REPRODUCIBILITY.is_file()
        and all(token in FINAL_SOLIDITY_REPRODUCIBILITY.read_text() for token in (
            "initcode, runtime, ABI, storage layout and every source hash",
            "comparison rejects any semantic drift", "deployment rejects stale",
        )),
    "reserve constructor cross-encoder equivalence guard is mandatory": RESERVE_CONSTRUCTOR_EQUIVALENCE.is_file()
        and all(token in RESERVE_CONSTRUCTOR_EQUIVALENCE.read_text() for token in (
            "ethers, cast and solc constructor ABI", "pilotRestricted", "oldEncoding",
            "deriveReserveArtifactBinding", "every constructor component changes initcode",
        )),
    "current operational claims guard is mandatory": CURRENT_OPERATIONAL_CLAIMS.is_file()
        and all(token in CURRENT_OPERATIONAL_CLAIMS.read_text() for token in (
            "23-phase plan", "distinguishes both fund authorizations",
            "only final measured values", "explicitly denies action authorization",
        )),
}
failures.extend(message for message, condition in required.items() if not condition)

if failures:
    print("USDOM required-test policy: FAIL", file=sys.stderr)
    for failure in failures:
        print(f"- {failure}", file=sys.stderr)
    raise SystemExit(1)
print("USDOM required-test policy: PASS (three mandatory release vectors, one active short CI guard, no silent Node/Foundry skips)")
