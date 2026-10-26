#!/usr/bin/env python3
"""Pin proof-program sources and reject production panic primitives."""
import ast, hashlib, re, sys
from pathlib import Path

REPO=Path(__file__).resolve().parents[3]
MANIFEST=REPO/'labs/usdom-reserve/PROOF-PROGRAM-MANIFEST.sha256'
SOURCES={
 'crates/dom-node/src/bin/dom-usdom-build-finalized-deposit-witness.rs',
 'crates/dom-node/src/bin/dom-usdom-build-private-burn.rs',
 'crates/dom-node/src/bin/dom-usdom-bootstrap-tpm-wallet-authority.rs',
 'crates/dom-node/src/bin/dom-usdom-register-finalized-deposit.rs',
 'crates/dom-node/src/bin/dom-usdom-recover-wallet-at-checkpoint.rs',
 'crates/dom-node/src/bin/dom-usdom-submit-private-burn.rs',
 'crates/dom-node/src/bin/dom-usdom-wallet-tpm-keystore.rs',
 'crates/dom-node/src/bin/dom-usdom-observe-finalized-deposit.rs',
 'crates/dom-node/src/bin/dom-usdom-export-checkpoint-source.rs',
 'crates/dom-node/src/bin/dom-usdom-export-checkpoint-source-set.rs',
 'crates/dom-node/src/bin/dom-usdom-export-finalized-burn-source.rs',
 'crates/dom-node/src/bin/dom-usdom-export-preactivation-anchor.rs',
 'crates/dom-node/src/bin/dom-usdom-export-randomx-statement-set.rs',
 'crates/dom-node/src/native_usdom_config.rs',
 'crates/dom-node/src/private_staging_directory.rs',
 'crates/dom-risc0-program-packager/src/main.rs',
 'crates/dom-usdom-randomx-proof-host/src/bin/plan.rs',
 'crates/dom-usdom-randomx-proof-host/src/bin/plan-aggregate.rs',
 'crates/dom-usdom-randomx-proof-host/src/bin/prove.rs',
 'crates/dom-usdom-randomx-proof-host/src/bin/prove-aggregate.rs',
 'crates/dom-usdom-randomx-proof-host/src/aggregate.rs',
 'crates/dom-usdom-randomx-proof-host/src/lib.rs',
 'crates/dom-usdom-finalized-burn-program/src/lib.rs',
 'crates/dom-usdom-finalized-burn-program/src/main.rs',
 'crates/dom-usdom-finalized-burn-proof-host/src/bin/plan.rs',
 'crates/dom-usdom-finalized-burn-proof-host/src/bin/package-evm.rs',
 'crates/dom-usdom-finalized-burn-proof-host/src/bin/prove.rs',
 'crates/dom-usdom-finalized-burn-proof-host/src/lib.rs',
 'crates/dom-usdom-checkpoint-program/src/bin/dom-usdom-export-randomx-statement.rs',
 'crates/dom-usdom-checkpoint-program/src/economic_chunks.rs',
 'crates/dom-usdom-checkpoint-program/src/lib.rs',
 'crates/dom-usdom-checkpoint-program/src/outer.rs',
 'crates/dom-usdom-checkpoint-program/src/portable.rs',
 'crates/dom-usdom-checkpoint-program/src/reference.rs',
 'crates/dom-usdom-checkpoint-program/src/source.rs',
 'crates/dom-usdom-checkpoint-statement/src/lib.rs',
 'crates/dom-usdom-checkpoint-statement/src/main.rs',
 'crates/dom-usdom-economic-block-program/src/lib.rs',
 'crates/dom-usdom-economic-proof-host/src/bin/plan.rs',
 'crates/dom-usdom-economic-proof-host/src/bin/prove.rs',
 'crates/dom-usdom-economic-proof-host/src/lib.rs',
 'crates/dom-usdom-checkpoint-proof-host/src/bin/plan.rs',
 'crates/dom-usdom-checkpoint-proof-host/src/bin/plan-outer.rs',
 'crates/dom-usdom-checkpoint-proof-host/src/bin/prove-outer.rs',
 'crates/dom-usdom-checkpoint-proof-host/src/bin/package-outer-evm.rs',
 'crates/dom-usdom-checkpoint-proof-host/src/bin/prove.rs',
 'crates/dom-usdom-checkpoint-proof-host/src/lib.rs',
 'crates/dom-usdom-prover/src/lib.rs',
 'crates/dom-wallet-crypto/src/lib.rs',
}
ARTIFACTS={
 'Cargo.lock',
 'Cargo.toml',
 'crates/dom-risc0-program-packager/Cargo.toml',
 'crates/dom-usdom-checkpoint-outer-risc0-guest/src/main.rs',
 'crates/dom-usdom-checkpoint-outer-risc0-guest/Cargo.lock',
 'crates/dom-usdom-checkpoint-outer-risc0-guest/Cargo.toml',
 'crates/dom-usdom-checkpoint-outer-risc0-guest/elfs/usdom-checkpoint-outer.bin',
 'crates/dom-usdom-checkpoint-outer-risc0-guest/elfs/usdom-checkpoint-outer.elf',
 'crates/dom-usdom-checkpoint-outer-risc0-guest/elfs/usdom-checkpoint-outer.iid',
 'crates/dom-usdom-checkpoint-segment-risc0-guest/Cargo.lock',
 'crates/dom-usdom-checkpoint-segment-risc0-guest/Cargo.toml',
 'crates/dom-usdom-checkpoint-segment-risc0-guest/elfs/usdom-checkpoint-segment.bin',
 'crates/dom-usdom-checkpoint-segment-risc0-guest/elfs/usdom-checkpoint-segment.elf',
 'crates/dom-usdom-checkpoint-segment-risc0-guest/elfs/usdom-checkpoint-segment.iid',
 'crates/dom-usdom-checkpoint-segment-risc0-guest/src/main.rs',
 'crates/dom-usdom-economic-block-risc0-guest/Cargo.lock',
 'crates/dom-usdom-economic-block-risc0-guest/Cargo.toml',
 'crates/dom-usdom-economic-block-risc0-guest/elfs/usdom-economic-block.bin',
 'crates/dom-usdom-economic-block-risc0-guest/elfs/usdom-economic-block.elf',
 'crates/dom-usdom-economic-block-risc0-guest/elfs/usdom-economic-block.iid',
 'crates/dom-usdom-economic-block-risc0-guest/src/main.rs',
 'crates/dom-usdom-economic-chunk-risc0-guest/Cargo.lock',
 'crates/dom-usdom-economic-chunk-risc0-guest/Cargo.toml',
 'crates/dom-usdom-economic-chunk-risc0-guest/elfs/usdom-economic-chunk.bin',
 'crates/dom-usdom-economic-chunk-risc0-guest/elfs/usdom-economic-chunk.elf',
 'crates/dom-usdom-economic-chunk-risc0-guest/elfs/usdom-economic-chunk.iid',
 'crates/dom-usdom-economic-chunk-risc0-guest/src/main.rs',
 'crates/dom-usdom-finalized-burn-risc0-guest/Cargo.lock',
 'crates/dom-usdom-finalized-burn-risc0-guest/Cargo.toml',
 'crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.elf',
 'crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.iid',
 'crates/dom-usdom-finalized-burn-risc0-guest/src/main.rs',
 'crates/dom-usdom-randomx-aggregate-risc0-guest/Cargo.lock',
 'crates/dom-usdom-randomx-aggregate-risc0-guest/Cargo.toml',
 'crates/dom-usdom-randomx-aggregate-risc0-guest/elfs/usdom-randomx-aggregate.bin',
 'crates/dom-usdom-randomx-aggregate-risc0-guest/elfs/usdom-randomx-aggregate.iid',
 'crates/dom-usdom-randomx-aggregate-risc0-guest/src/main.rs',
 'crates/dom-usdom-randomx-risc0-guest/Cargo.lock',
 'crates/dom-usdom-randomx-risc0-guest/Cargo.toml',
 'crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.bin',
 'crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.elf',
 'crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.iid',
 'crates/dom-usdom-randomx-risc0-guest/src/main.rs',
 'labs/usdom-reserve/scripts/build-checkpoint-outer-risc0-guest.sh',
 'labs/usdom-reserve/scripts/build-checkpoint-segment-risc0-guest.sh',
 'labs/usdom-reserve/scripts/build-complete-randomx-risc0-guest.sh',
 'labs/usdom-reserve/scripts/build-economic-block-risc0-guest.sh',
 'labs/usdom-reserve/scripts/build-economic-chunk-risc0-guest.sh',
 'labs/usdom-reserve/scripts/build-finalized-burn-risc0-guest.sh',
 'labs/usdom-reserve/scripts/build-randomx-aggregate-risc0-guest.sh',
}
REMOTE_PROVER_VARIABLES={
 'BONSAI_API_URL','BONSAI_API_KEY','BONSAI_POLL_INTERVAL_MS',
 'RISC0_SERVER_PATH','RISC0_SERVER_ADDR','RISC0_EXECUTOR','RISC0_PPROF_OUT',
 'RISC0_PPROF_ENABLE_INLINE_FUNCTIONS','RISC0_KECCAK_PO2',
 'RISC0_DEFAULT_PROVER_NUM_GPUS','RISC0_INFO','RISC0_REDIS_CHANNEL_SIZE',
}
LOCAL_PROVER_HELPERS={
 'crates/dom-usdom-finalized-burn-proof-host/src/lib.rs':(
  'finalized-burn proving','finalized-burn Groth16 compression',
 ),
 'crates/dom-usdom-randomx-proof-host/src/lib.rs':('RandomX proving',),
 'crates/dom-usdom-economic-proof-host/src/lib.rs':('economic proving',),
 'crates/dom-usdom-checkpoint-proof-host/src/lib.rs':(
  'checkpoint segment proving','checkpoint outer proving',
  'checkpoint outer Groth16 compression',
 ),
}
LOCAL_PROVER_CALLS={
 'crates/dom-usdom-randomx-proof-host/src/aggregate.rs':('RandomX aggregate proving',),
}
LOCAL_PROVER_LAUNCHERS={
 'labs/usdom-reserve/scripts/prove-authenticated-finalized-burn.sh',
 'labs/usdom-reserve/scripts/package-authenticated-finalized-burn-evm-proof.sh',
 'labs/usdom-reserve/scripts/prove-authenticated-randomx-receipt-set.sh',
 'labs/usdom-reserve/scripts/prove-authenticated-randomx-aggregate-set.sh',
 'labs/usdom-reserve/scripts/prove-authenticated-economic-receipt-set.sh',
 'labs/usdom-reserve/scripts/prove-authenticated-checkpoint-segment-set.sh',
 'labs/usdom-reserve/scripts/prove-authenticated-checkpoint-outer.sh',
 'labs/usdom-reserve/scripts/package-authenticated-checkpoint-outer-evm-proof.sh',
}
ADAPTIVE_LOCAL_PROVER_LAUNCHERS={
 'labs/usdom-reserve/scripts/check-finalized-burn-prover-e2e.sh',
}
LOCAL_PROVER_JS_LAUNCHERS={
 'labs/usdom-reserve/scripts/run-finalized-burn-capacity-e2e.mjs',
 'labs/usdom-reserve/scripts/run-checkpoint-capacity-e2e.mjs',
}
FIXED_PROOF_ENTRYPOINTS={
 'crates/dom-usdom-finalized-burn-proof-host/src/bin/plan.rs',
 'crates/dom-usdom-finalized-burn-proof-host/src/bin/prove.rs',
 'crates/dom-usdom-finalized-burn-proof-host/src/bin/package-evm.rs',
 'crates/dom-usdom-randomx-proof-host/src/bin/plan.rs',
 'crates/dom-usdom-randomx-proof-host/src/bin/prove.rs',
 'crates/dom-usdom-randomx-proof-host/src/bin/plan-aggregate.rs',
 'crates/dom-usdom-randomx-proof-host/src/bin/prove-aggregate.rs',
 'crates/dom-usdom-economic-proof-host/src/bin/plan.rs',
 'crates/dom-usdom-economic-proof-host/src/bin/prove.rs',
 'crates/dom-usdom-checkpoint-proof-host/src/bin/plan.rs',
 'crates/dom-usdom-checkpoint-proof-host/src/bin/prove.rs',
 'crates/dom-usdom-checkpoint-proof-host/src/bin/plan-outer.rs',
 'crates/dom-usdom-checkpoint-proof-host/src/bin/prove-outer.rs',
 'crates/dom-usdom-checkpoint-proof-host/src/bin/package-outer-evm.rs',
}
PRIVATE_OUTPUT_HOSTS={
 'crates/dom-usdom-finalized-burn-proof-host/src/lib.rs',
 'crates/dom-usdom-randomx-proof-host/src/lib.rs',
 'crates/dom-usdom-economic-proof-host/src/lib.rs',
 'crates/dom-usdom-checkpoint-proof-host/src/lib.rs',
}
PRIVATE_PROOF_SCRIPTS={
 'labs/usdom-reserve/scripts/export-canonical-checkpoint-source.sh',
 'labs/usdom-reserve/scripts/export-canonical-checkpoint-source-set.sh',
 'labs/usdom-reserve/scripts/export-canonical-finalized-burn-source.sh',
 'labs/usdom-reserve/scripts/export-authenticated-randomx-statement.sh',
 'labs/usdom-reserve/scripts/export-authenticated-randomx-statement-set.sh',
 'labs/usdom-reserve/scripts/plan-authenticated-randomx-receipt-set.sh',
 'labs/usdom-reserve/scripts/plan-authenticated-randomx-aggregate-set.sh',
 'labs/usdom-reserve/scripts/plan-authenticated-economic-receipt-set.sh',
 'labs/usdom-reserve/scripts/plan-authenticated-checkpoint-segment-set.sh',
 'labs/usdom-reserve/scripts/plan-authenticated-checkpoint-outer.sh',
 'labs/usdom-reserve/scripts/plan-authenticated-finalized-burn.sh',
 'labs/usdom-reserve/scripts/prove-authenticated-randomx-receipt-set.sh',
 'labs/usdom-reserve/scripts/prove-authenticated-randomx-aggregate-set.sh',
 'labs/usdom-reserve/scripts/prove-authenticated-economic-receipt-set.sh',
 'labs/usdom-reserve/scripts/prove-authenticated-checkpoint-segment-set.sh',
 'labs/usdom-reserve/scripts/prove-authenticated-checkpoint-outer.sh',
 'labs/usdom-reserve/scripts/package-authenticated-checkpoint-outer-evm-proof.sh',
 'labs/usdom-reserve/scripts/prove-authenticated-finalized-burn.sh',
 'labs/usdom-reserve/scripts/package-authenticated-finalized-burn-evm-proof.sh',
 'labs/usdom-reserve/scripts/check-finalized-burn-prover-e2e.sh',
}
GUEST_BUILD_SCRIPTS={
 'labs/usdom-reserve/scripts/build-checkpoint-outer-risc0-guest.sh',
 'labs/usdom-reserve/scripts/build-checkpoint-segment-risc0-guest.sh',
 'labs/usdom-reserve/scripts/build-complete-randomx-risc0-guest.sh',
 'labs/usdom-reserve/scripts/build-economic-block-risc0-guest.sh',
 'labs/usdom-reserve/scripts/build-economic-chunk-risc0-guest.sh',
 'labs/usdom-reserve/scripts/build-finalized-burn-risc0-guest.sh',
 'labs/usdom-reserve/scripts/build-randomx-aggregate-risc0-guest.sh',
}
GUEST_ARTIFACT_RELATIONS={
 'checkpoint-outer':('checkpoint-outer','usdom-checkpoint-outer',True,True,False),
 'checkpoint-segment':('checkpoint-segment','usdom-checkpoint-segment',True,True,False),
 'economic-block':('economic-block','usdom-economic-block',True,True,False),
 'economic-chunk':('economic-chunk','usdom-economic-chunk',True,True,False),
 'finalized-burn':('finalized-burn','usdom-finalized-burn',True,False,True),
 'randomx':('complete-randomx','usdom-randomx',True,True,False),
 'randomx-aggregate':('randomx-aggregate','usdom-randomx-aggregate',False,True,False),
}
PANIC=re.compile(r'\.(?:unwrap|expect)\s*\(|\b(?:panic|unreachable|todo|unimplemented)!\s*\(')
LINE=re.compile(r'^([0-9a-f]{64})  (.+)$')

def fail(message): raise SystemExit(f'FAIL: {message}')
def production(source):
 return '\n'.join(x for x in source.split('#[cfg(test)]',1)[0].splitlines()
                  if not x.lstrip().startswith('//'))
def check_text(source,label):
 checked=production(source); match=PANIC.search(checked)
 if match: fail(f'{label}: panic primitive {match.group(0)!r}')

def check_local_helper(source,label,contexts):
 for variable in REMOTE_PROVER_VARIABLES:
  if f'"{variable}"' not in source: fail(f'{label}: missing rejection for {variable}')
 if 'std::env::var_os(variable).is_some()' not in source:
  fail(f'{label}: remote prover variables are not rejected by presence')
 for context in contexts:
  if f'require_local_prover_environment("{context}")?' not in source:
   fail(f'{label}: missing local prover guard for {context}')

def check_local_call(source,label,contexts):
 for context in contexts:
  if f'require_local_prover_environment("{context}")?' not in source:
   fail(f'{label}: missing local prover guard for {context}')

def check_local_endpoint_boundary(source,label):
 for variable in REMOTE_PROVER_VARIABLES:
  if f'-u {variable}' not in source: fail(f'{label}: does not clear {variable}')
 for assignment in ('RISC0_PROVER=local','RISC0_DEV_MODE=0'):
  if assignment not in source: fail(f'{label}: missing {assignment}')

def check_local_launcher(source,label):
 check_local_endpoint_boundary(source,label)
 if 'RAYON_NUM_THREADS=1' not in source: fail(f'{label}: missing RAYON_NUM_THREADS=1')

def check_local_js_launcher(source,label):
 for variable in REMOTE_PROVER_VARIABLES:
  if f"'{variable}'" not in source: fail(f'{label}: does not clear {variable}')
 if 'delete environment[name]' not in source: fail(f'{label}: does not delete remote variables')
 for assignment in ("RAYON_NUM_THREADS:'1'","RISC0_PROVER:'local'","RISC0_DEV_MODE:'0'"):
  if assignment not in source: fail(f'{label}: missing {assignment}')

def check_fixed_entrypoint(source,label):
 if '#![deny(unsafe_code)]' not in source: fail(f'{label}: unsafe code is not denied')
 if 'env::args_os().len() != 1' not in source:
  fail(f'{label}: direct arguments or overrides are not rejected')

def check_private_output_host(source,label):
 if '.mode(0o644)' in source: fail(f'{label}: proof output is group/world readable')
 if '.mode(0o600)' not in source and 'save_private_bytes(' not in source:
  fail(f'{label}: owner-only proof output boundary is absent')

def check_private_script(source,label):
 if not re.search(r'^umask 077$',source,re.MULTILINE):
  fail(f'{label}: restrictive umask is absent')

def check_guest_build_script(source,label):
 common=(
  'set -euo pipefail', 'build_root="$(mktemp -d', 'trap \'rm -rf "$build_root"\' EXIT',
  'expected_workspace_lock_sha=', 'expected_guest_lock_sha=', 'expected_id=', 'CARGO_TARGET_DIR=',
  'sha256sum "$repo/Cargo.lock"', 'sha256sum "$expected_lock"',
  'test "$actual_id" = "$expected_id"',
 )
 for token in common:
  if token not in source: fail(f'{label}: missing reproducibility relation {token!r}')
 if 'finalized-burn' in label:
  required=('RISC0_BUILD_LOCKED=1', 'RISC0_DOCKER_CONTAINER_TAG=', 'command in cargo docker r0vm',
            'xxd -p -c 256 "$expected_iid"', 'cmp --silent "$user_elf" "$expected_elf"',
            'actual_id="$(r0vm --id --elf "$user_elf")"')
 else:
  required=('--locked', '-p dom-risc0-program-packager', 'expected_program_sha=',
            'cmp --silent "$program" "$expected_program"', 'expected_rustc_commit=',
            'expected_llvm_version=', 'expected_rustup_sha=',
            'cargo_path="$(realpath "$(command -v cargo)")"',
            'rustup_path="$(realpath "$(command -v rustup)")"',
            '"$rustup_path" run risc0 rustc --version --verbose',
            'commit-hash: $expected_rustc_commit', 'LLVM version: $expected_llvm_version',
            'RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS',
            'test -z "${!variable-}"')
  if 'randomx-aggregate' not in label:
   required += ('expected_elf_sha=', 'cmp --silent "$user_elf" "$expected_elf"')
  else:
   required += ('expected_user_sha=', 'sha256sum "$user_elf"')
 for token in required:
  if token not in source: fail(f'{label}: missing artifact relation {token!r}')

def shell_assignment(source,name,label):
 match=re.search(rf'^{re.escape(name)}="([0-9a-f]+)"$',source,re.MULTILINE)
 if not match: fail(f'{label}: missing canonical {name} assignment')
 return match.group(1)

def file_sha256(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def check_guest_artifact_constants():
 workspace_lock=file_sha256(REPO/'Cargo.lock')
 for guest,(script_name,stem,has_elf,has_program,raw_iid) in GUEST_ARTIFACT_RELATIONS.items():
  label=f'labs/usdom-reserve/scripts/build-{script_name}-risc0-guest.sh'
  source=(REPO/label).read_text()
  directory=REPO/f'crates/dom-usdom-{guest}-risc0-guest'
  if shell_assignment(source,'expected_workspace_lock_sha',label) != workspace_lock:
   fail(f'{label}: expected workspace lock hash differs from workspace lock')
  guest_lock=file_sha256(directory/'Cargo.lock')
  if shell_assignment(source,'expected_guest_lock_sha',label) != guest_lock:
   fail(f'{label}: expected guest provenance lock hash differs from its snapshot')
  iid=(directory/f'elfs/{stem}.iid').read_bytes()
  encoded_iid=iid.hex() if raw_iid else iid.decode('ascii').strip()
  if not re.fullmatch(r'[0-9a-f]{64}',encoded_iid): fail(f'{label}: malformed committed ImageID')
  if shell_assignment(source,'expected_id',label) != encoded_iid:
   fail(f'{label}: expected ImageID differs from committed ImageID')
  if has_elf and shell_assignment(source,'expected_elf_sha',label) != file_sha256(directory/f'elfs/{stem}.elf'):
   fail(f'{label}: expected ELF hash differs from committed ELF')
  if has_program and shell_assignment(source,'expected_program_sha',label) != file_sha256(directory/f'elfs/{stem}.bin'):
   fail(f'{label}: expected ProgramBinary hash differs from committed binary')

def check_subprocess_timeouts(source,label):
 tree=ast.parse(source,filename=label)
 calls=[]
 for node in ast.walk(tree):
  function=node.func if isinstance(node,ast.Call) else None
  if (isinstance(function,ast.Attribute) and function.attr=='run'
      and isinstance(function.value,ast.Name) and function.value.id=='subprocess'):
   calls.append(node)
   timeout=next((keyword.value for keyword in node.keywords if keyword.arg=='timeout'),None)
   if not isinstance(timeout,ast.Constant) or not isinstance(timeout.value,int) or not 1 <= timeout.value <= 300:
    fail(f'{label}:{node.lineno}: subprocess.run lacks a bounded literal timeout')
 if calls:
  handled=any(
   isinstance(node,ast.ExceptHandler) and isinstance(node.type,ast.Attribute)
   and isinstance(node.type.value,ast.Name) and node.type.value.id=='subprocess'
   and node.type.attr=='TimeoutExpired' for node in ast.walk(tree)
  )
  if not handled: fail(f'{label}: subprocess.TimeoutExpired is not handled')

def check_boundary_command_timeouts():
 for path in sorted((REPO/'labs/usdom-reserve/scripts').glob('check-*.py')):
  check_subprocess_timeouts(path.read_text(),path.relative_to(REPO).as_posix())

def check_economic_receipt_schema(producer,consumer):
 producer_tokens=(
  '"block_height": job.block_height',
  '"chunk_proving_wall_milliseconds": chunk_proving_wall_milliseconds',
  '"chunk_peak_resident_kib": chunk_peak_resident_kib',
  '"block_proving_wall_milliseconds": block_proving_wall_milliseconds',
  '"block_peak_resident_kib": block_peak_resident_kib',
 )
 consumer_tokens=(
  'block_height: u64',
  'chunk_proving_wall_milliseconds: u64',
  'chunk_peak_resident_kib: u64',
  'block_proving_wall_milliseconds: u64',
  'block_peak_resident_kib: u64',
 )
 for token in producer_tokens:
  if token not in producer: fail(f'economic receipt producer omits {token}')
 for token in consumer_tokens:
  if token not in consumer: fail(f'economic receipt consumer omits {token}')

def check():
 if SOURCES & ARTIFACTS: fail('proof source and artifact inventories overlap')
 for name in sorted(SOURCES): check_text((REPO/name).read_text(),name)
 for name,contexts in LOCAL_PROVER_HELPERS.items():
  check_local_helper(production((REPO/name).read_text()),name,contexts)
 for name,contexts in LOCAL_PROVER_CALLS.items():
  check_local_call(production((REPO/name).read_text()),name,contexts)
 for name in LOCAL_PROVER_LAUNCHERS:
  check_local_launcher((REPO/name).read_text(),name)
 for name in ADAPTIVE_LOCAL_PROVER_LAUNCHERS:
  check_local_endpoint_boundary((REPO/name).read_text(),name)
 for name in LOCAL_PROVER_JS_LAUNCHERS:
  check_local_js_launcher((REPO/name).read_text(),name)
 for name in FIXED_PROOF_ENTRYPOINTS:
  check_fixed_entrypoint((REPO/name).read_text(),name)
 for name in PRIVATE_OUTPUT_HOSTS:
  check_private_output_host(production((REPO/name).read_text()),name)
 for name in PRIVATE_PROOF_SCRIPTS:
  check_private_script((REPO/name).read_text(),name)
 for name in GUEST_BUILD_SCRIPTS:
  check_guest_build_script((REPO/name).read_text(),name)
 check_guest_artifact_constants()
 check_boundary_command_timeouts()
 check_economic_receipt_schema(
  (REPO/'crates/dom-usdom-economic-proof-host/src/lib.rs').read_text(),
  (REPO/'crates/dom-usdom-checkpoint-proof-host/src/lib.rs').read_text(),
 )
 listed={}
 for number,line in enumerate(MANIFEST.read_text().splitlines(),1):
  match=LINE.fullmatch(line)
  if not match or match.group(2) in listed: fail(f'malformed or duplicate manifest line {number}')
  name=match.group(2); candidate=REPO/name; resolved=candidate.resolve()
  if candidate.is_symlink() or not resolved.is_relative_to(REPO.resolve()) or not resolved.is_file():
   fail(f'invalid manifest path: {name}')
  digest=hashlib.sha256(resolved.read_bytes()).hexdigest()
  if digest != match.group(1): fail(f'manifest digest mismatch: {name}')
  listed[name]=digest
 if set(listed)!=(SOURCES | ARTIFACTS): fail('proof-program manifest inventory mismatch')
 finalized=(REPO/'crates/dom-usdom-finalized-burn-program/src/main.rs').read_text()
 statement=(REPO/'crates/dom-usdom-checkpoint-statement/src/main.rs').read_text()
 if finalized.find('.take(maximum_read as u64)') > finalized.find('.read_to_end(') or 'checked_add(1)' not in finalized:
  fail('finalized-burn host input is not bounded before read_to_end')
 if statement.find('.take((CHECKPOINT_STATEMENT_V4_BYTES + 1) as u64)') > statement.find('.read_to_end('):
  fail('checkpoint-statement host input is not bounded before read_to_end')

def self_test():
 for primitive in ['x.unwrap()','x.expect("x")','panic!("x")','unreachable!()','todo!()','unimplemented!()']:
  try: check_text(f'fn f(){{{primitive};}}','mutation')
  except SystemExit: pass
  else: raise AssertionError(primitive)
 launcher=' '.join(f'-u {name}' for name in REMOTE_PROVER_VARIABLES)
 launcher+=' RAYON_NUM_THREADS=1 RISC0_PROVER=local RISC0_DEV_MODE=0'
 check_local_launcher(launcher,'mutation')
 for variable in REMOTE_PROVER_VARIABLES:
  try: check_local_launcher(launcher.replace(f'-u {variable}',''),'mutation')
  except SystemExit: pass
  else: raise AssertionError(variable)
 entrypoint='#![deny(unsafe_code)]\nfn f(){if env::args_os().len() != 1{}}'
 check_fixed_entrypoint(entrypoint,'mutation')
 for token in ('#![deny(unsafe_code)]','env::args_os().len() != 1'):
  try: check_fixed_entrypoint(entrypoint.replace(token,''),'mutation')
  except SystemExit: pass
  else: raise AssertionError(token)
 check_private_output_host('.mode(0o600)','mutation')
 try: check_private_output_host('.mode(0o644)','mutation')
 except SystemExit: pass
 else: raise AssertionError('world-readable proof output')
 check_private_script('umask 077\n','mutation')
 try: check_private_script('umask 022\n','mutation')
 except SystemExit: pass
 else: raise AssertionError('permissive umask')
 normal_build=(REPO/'labs/usdom-reserve/scripts/build-economic-chunk-risc0-guest.sh').read_text()
 finalized_build=(REPO/'labs/usdom-reserve/scripts/build-finalized-burn-risc0-guest.sh').read_text()
 for source,label,token in (
  (normal_build,'economic-build-mutation','cmp --silent "$program" "$expected_program"'),
  (normal_build,'lock-build-mutation','sha256sum "$expected_lock"'),
  (normal_build,'toolchain-build-mutation','expected_rustc_commit='),
  (normal_build,'llvm-build-mutation','expected_llvm_version='),
  (normal_build,'ambient-wrapper-mutation','RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS'),
  (normal_build,'rustup-launcher-mutation','expected_rustup_sha='),
  (finalized_build,'docker-build-mutation','RISC0_DOCKER_CONTAINER_TAG='),
  (finalized_build,'image-id-build-mutation','actual_id="$(r0vm --id --elf "$user_elf")"'),
 ):
  try: check_guest_build_script(source.replace(token,'',1),label)
  except SystemExit: pass
  else: raise AssertionError(token)
 producer=' '.join((
  '"block_height": job.block_height',
  '"chunk_proving_wall_milliseconds": chunk_proving_wall_milliseconds',
  '"chunk_peak_resident_kib": chunk_peak_resident_kib',
  '"block_proving_wall_milliseconds": block_proving_wall_milliseconds',
  '"block_peak_resident_kib": block_peak_resident_kib',
 ))
 consumer=' '.join((
  'block_height: u64','chunk_proving_wall_milliseconds: u64',
  'chunk_peak_resident_kib: u64','block_proving_wall_milliseconds: u64',
  'block_peak_resident_kib: u64',
 ))
 check_economic_receipt_schema(producer,consumer)
 safe='import subprocess\ntry:\n subprocess.run(["cargo"],timeout=120)\nexcept subprocess.TimeoutExpired:\n pass\n'
 check_subprocess_timeouts(safe,'safe-timeout')
 for mutation in (safe.replace(',timeout=120',''),safe.replace('except subprocess.TimeoutExpired','except RuntimeError')):
  try: check_subprocess_timeouts(mutation,'timeout-mutation')
  except SystemExit: pass
  else: raise AssertionError('unbounded subprocess mutation')
 # Exact targeted mutation: the historically missing chunk block height must fail.
 try: check_economic_receipt_schema(producer.replace('"block_height": job.block_height',''),consumer)
 except SystemExit: pass
 else: raise AssertionError('economic block-height schema mismatch')
 print('PASS: proof-program checker rejects panic primitives and remote prover inheritance')

if sys.argv[1:]==['--self-test']: self_test()
elif not sys.argv[1:]:
 check(); print(f'PASS: {len(SOURCES)} proof-program sources are panic-primitive free; {len(SOURCES | ARTIFACTS)} critical sources/artifacts, prover-local boundaries and host reads are verified')
else: fail('usage: check-proof-program-panic-boundary.py [--self-test]')
