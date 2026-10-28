#!/usr/bin/env python3
"""Pin proof-program sources and reject production panic primitives."""
import ast, hashlib, json, os, re, shutil, signal, struct, subprocess, sys, tempfile, time, tomllib
from pathlib import Path
from specialized_manifest import direct, manifest, rust_closure, snapshot

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
 'crates/dom-usdom-checkpoint-program/src/sync_attestation.rs',
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
 'labs/usdom-reserve/scripts/pinned-risc0-guest-toolchain.sh',
 'labs/usdom-reserve/scripts/risc0-guest-build-launcher.c',
 'labs/usdom-reserve/scripts/risc0-guest-build-launcher',
 'labs/usdom-reserve/config/risc0-guest-build-launcher-provenance.json',
}
CRATE_MANIFESTS={"/".join(name.split("/")[:2])+"/Cargo.toml" for name in SOURCES if name.startswith("crates/")}
ARTIFACTS.update(CRATE_MANIFESTS)
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

def derive_cargo_path_closure():
 workspace=tomllib.loads(direct(REPO,'Cargo.toml').decode()).get('workspace',{}).get('dependencies',{})
 pending=list(CRATE_MANIFESTS);seen=set()
 closure=set()
 while pending:
  cargo=pending.pop()
  if cargo in seen:continue
  seen.add(cargo);raw=direct(REPO,cargo);closure.add(cargo)
  document=tomllib.loads(raw.decode());base=Path(cargo).parent
  tables=[document.get(x,{}) for x in ('dependencies','dev-dependencies','build-dependencies')]
  for key,value in document.items():
   if key=='target' and isinstance(value,dict):
    for target in value.values():
     if isinstance(target,dict):tables.extend(target.get(x,{}) for x in ('dependencies','dev-dependencies','build-dependencies'))
  for table in tables:
   if not isinstance(table,dict):continue
   for dependency_name,spec in table.items():
    from_workspace=isinstance(spec,dict) and spec.get('workspace') is True
    if from_workspace:spec=workspace.get(dependency_name,{})
    if isinstance(spec,dict) and isinstance(spec.get('path'),str):
     dependency=((REPO if from_workspace else REPO/base)/spec['path']/'Cargo.toml').resolve()
     try:relative=dependency.relative_to(REPO).as_posix()
     except ValueError:fail(f'path dependency escapes repository: {cargo}')
     pending.append(relative)
  package=document.get('package',{});targets=[]
  if (REPO/base/'src/lib.rs').is_file():targets.append((base/'src/lib.rs').as_posix())
  if (REPO/base/'src/main.rs').is_file():targets.append((base/'src/main.rs').as_posix())
  for table in ('bin','example'):
   for item in document.get(table,[]):
    if isinstance(item,dict) and isinstance(item.get('path'),str):targets.append((base/item['path']).as_posix())
  build=package.get('build') if isinstance(package,dict) else None
  if isinstance(build,str):targets.append((base/build).as_posix())
  elif build is not False and (REPO/base/'build.rs').is_file():targets.append((base/'build.rs').as_posix())
  for candidate in (REPO/base/'src').rglob('*.rs') if (REPO/base/'src').is_dir() else ():
   relative=candidate.relative_to(REPO).as_posix();direct(REPO,relative);closure.add(relative)
  for target in targets:direct(REPO,target);closure.add(target)
 # Bind every compile-time file input. Dynamic concat/env/path construction is
 # deliberately unsupported because it cannot be audited as a closed set.
 literal=re.compile(r'include(?:_str|_bytes)?!\s*\(\s*"([^"]+)"\s*\)')
 any_include=re.compile(r'include(?:_str|_bytes)?!\s*\(')
 for source in sorted(name for name in closure if name.endswith('.rs')):
  text=direct(REPO,source).decode();matches=literal.findall(text)
  if len(matches)!=len(any_include.findall(text)):fail(f'dynamic Rust include is forbidden: {source}')
  for included in matches:
   asset=(REPO/Path(source).parent/included).resolve()
   try:relative=asset.relative_to(REPO).as_posix()
   except ValueError:fail(f'Rust include escapes repository: {source}')
   direct(REPO,relative);closure.add(relative)
 return closure

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
  '#!/usr/bin/env -S -i USDOM_PINNED_BUILD_ENV=1',
  'set -euo pipefail', 'umask 077', 'build_root="$("$USDOM_MKTEMP" -d', 'trap \'rm -rf "$build_root"\' EXIT',
  'expected_workspace_lock_sha=', 'expected_guest_lock_sha=', 'expected_id=', 'CARGO_TARGET_DIR=',
  'usdom_sha256 "$repo/Cargo.lock"', 'usdom_sha256 "$expected_lock"',
  'reject_ambient_build_environment', 'pin_build_utilities ', 'prepare_isolated_cargo_home "$build_root"',
  'source_authority=/proc/self/fd/10',
  'export USDOM_RELEASE_BUILD=1', 'export DOM_BUILD_COMMIT="sha256:',
  'test "$actual_id" = "$expected_id"', 'USDOM_BUILD_CAP_FD:-} != 8',
  'USD0M-RISC0-BUILD-CAP-v2:$expected_builder:$USDOM_BUILD_SCRIPT_SHA256:$USDOM_BUILD_NONCE',
  'authenticate_risc0_build_launcher_parent', 'source /proc/self/fd/11',
  'source_authority=/proc/self/fd/10', '--authority-self-test',
 )
 for token in common:
  if token not in source: fail(f'{label}: missing reproducibility relation {token!r}')
 if 'finalized-burn' in label:
  required=('RISC0_BUILD_LOCKED=1', 'RISC0_DOCKER_CONTAINER_TAG=', '"$FROZEN_CARGO_RISZERO" risczero build',
            '"$FROZEN_R0VM" --id --elf', '"$USDOM_DOCKER" "$USDOM_DOCKER_SHA256"',
            '"$USDOM_XXD" -p -c 256 "$expected_iid"', '"$USDOM_CMP" --silent "$user_elf" "$expected_elf"',
            'actual_id="$("$FROZEN_R0VM" --id --elf "$user_elf")"')
 else:
  required=('--locked', '-p dom-risc0-program-packager', 'expected_program_sha=',
            '"$USDOM_CMP" --silent "$program" "$expected_program"', 'expected_rustc_commit=',
            'expected_llvm_version=', 'expected_rustup_sha=',
            'rustup_path=/home/leonardov/.cargo/bin/rustup',
            'source /proc/self/fd/11',
            'pin_risc0_guest_toolchain "$rustup_path" "$expected_rustup_sha"',
            'pin_host_rust_toolchain "$rustup_path" "$expected_rustup_sha"',
            'RUSTC="$RISC0_GUEST_RUSTC" "$RISC0_GUEST_CARGO" build',
            'linker='"'"'"$RISC0_GUEST_RUST_LLD"',
            'RUSTC="$HOST_RUSTC" "$HOST_CARGO" run',
            'assert_risc0_guest_toolchain_unchanged',
            'assert_host_rust_toolchain_unchanged',
            'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$USDOM_HOST_LINKER"',
            '"$RISC0_GUEST_RUSTC" --version --verbose',
            'commit-hash: $expected_rustc_commit', 'LLVM version: $expected_llvm_version',
            'RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS',
            'test -z "${!variable-}"')
  if 'randomx-aggregate' not in label:
   required += ('expected_elf_sha=', '"$USDOM_CMP" --silent "$user_elf" "$expected_elf"')
  else:
   required += ('expected_user_sha=', 'usdom_sha256 "$user_elf"')
 for token in required:
  if token not in source: fail(f'{label}: missing artifact relation {token!r}')

def check_package_guest_route(package):
 expected='./scripts/mainnet-tool-dispatcher repo-exec scripts/risc0-guest-build-launcher'
 if package.get('scripts',{}).get('build:risc0-guest')!=expected:
  fail('package route does not invoke the static guest-build launcher through the authenticated dispatcher')

def check_guest_build_launcher(payloads):
 provenance=json.loads(payloads['labs/usdom-reserve/config/risc0-guest-build-launcher-provenance.json'])
 source_name='labs/usdom-reserve/scripts/risc0-guest-build-launcher.c'
 artifact_name='labs/usdom-reserve/scripts/risc0-guest-build-launcher'
 source=payloads[source_name];artifact=payloads[artifact_name]
 expected={
  'schema':'dom-usdom-risc0-guest-build-launcher-v2',
  'compiler':'/usr/bin/x86_64-linux-gnu-gcc-13',
  'compilerSha256':'1b99826121ae6682a634e5efe09bd3e3df58ce58e0b28f849114ab5b89139c26',
  'source':source_name,'sourceSha256':hashlib.sha256(source).hexdigest(),
  'artifact':artifact_name,'artifactSha256':hashlib.sha256(artifact).hexdigest(),
 }
 for key,value in expected.items():
  if provenance.get(key)!=value:fail(f'guest-build launcher provenance mismatch: {key}')
 arguments=['-static','-std=c11','-O2','-Wall','-Wextra','-Werror','-fno-ident',
            '-fno-asynchronous-unwind-tables','-Wl,--build-id=none','-s']
 if provenance.get('compileArguments')!=arguments:fail('guest-build launcher compile arguments drifted')
 if not artifact.startswith(b'\x7fELF') or len(artifact)<64:fail('guest-build launcher is not ELF')
 elf_class,endian=artifact[4],artifact[5]
 if (elf_class,endian)!=(2,1):fail('guest-build launcher must be little-endian ELF64')
 phoff=struct.unpack_from('<Q',artifact,32)[0];phentsize=struct.unpack_from('<H',artifact,54)[0]
 phnum=struct.unpack_from('<H',artifact,56)[0]
 if phentsize<56 or phoff+phentsize*phnum>len(artifact):fail('invalid launcher ELF headers')
 if any(struct.unpack_from('<I',artifact,phoff+i*phentsize)[0]==3 for i in range(phnum)):
  fail('guest-build launcher has PT_INTERP and is not static')
 launcher_source=source.decode()
 for token in ('F_DUPFD_CLOEXEC','SYS_close_range','getrandom(','setrlimit(RLIMIT_CORE','setrlimit(RLIMIT_NOFILE','sigprocmask(SIG_SETMASK','sigaction(SIGTERM','kill(-(pid_t)child_pid','LAUNCHER_SUFFIX','require_manifest_line','sha_self_test','--preflight','getpgid(child)'):
  if token not in launcher_source:fail(f'guest-build launcher omits native authority boundary {token}')
 if 'AF_ALG' in launcher_source or 'REPO_ROOT' in launcher_source:
  fail('guest-build launcher retains host-kernel hash or absolute repository dependency')
 launcher=REPO/artifact_name
 preflight=subprocess.run([launcher,'--preflight'],capture_output=True,timeout=30)
 if preflight.returncode or preflight.stdout!=b'PASS: RISC Zero guest launcher preflight\n':
  fail('guest-build launcher preflight is not executable')
 for sig in (signal.SIGTERM,signal.SIGHUP):
  process=subprocess.Popen([launcher,'--signal-self-test'],stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
  child=None
  try:
   deadline=time.monotonic()+5
   children=Path(f'/proc/{process.pid}/task/{process.pid}/children')
   while time.monotonic()<deadline:
    values=children.read_text().split() if children.exists() else []
    if values: child=int(values[0]);break
    time.sleep(.01)
   if child is None:fail('launcher signal regression did not create supervised child')
   os.kill(process.pid,sig)
   if process.wait(timeout=5)!=-sig:fail('launcher did not preserve forwarded signal status')
   if Path(f'/proc/{child}').exists():fail('launcher signal forwarding left an orphan')
  finally:
   if process.poll() is None:
    process.kill();process.wait(timeout=5)
 file_by_key={'checkpoint-outer':'build-checkpoint-outer-risc0-guest.sh',
  'checkpoint-segment':'build-checkpoint-segment-risc0-guest.sh',
  'complete-randomx':'build-complete-randomx-risc0-guest.sh',
  'economic-block':'build-economic-block-risc0-guest.sh',
  'economic-chunk':'build-economic-chunk-risc0-guest.sh',
  'finalized-burn':'build-finalized-burn-risc0-guest.sh',
  'randomx-aggregate':'build-randomx-aggregate-risc0-guest.sh'}
 with tempfile.TemporaryDirectory() as directory:
  relocated=Path(directory);scripts=relocated/'labs/usdom-reserve/scripts'
  scripts.mkdir(parents=True)
  shutil.copy2(launcher,scripts/launcher.name)
  shutil.copy2(REPO/'labs/usdom-reserve/scripts/pinned-risc0-guest-toolchain.sh',scripts)
  for filename in file_by_key.values():shutil.copy2(REPO/'labs/usdom-reserve/scripts'/filename,scripts)
  shutil.copy2(MANIFEST,relocated/'labs/usdom-reserve/PROOF-PROGRAM-MANIFEST.sha256')
  moved=subprocess.run([scripts/launcher.name,'--preflight'],capture_output=True,timeout=30)
  if moved.returncode:fail('guest-build launcher is not safely relocatable')
 for key,filename in file_by_key.items():
  if f'"{key}"' not in launcher_source or f'"{filename}"' not in launcher_source:fail(f'guest-build launcher omits {key}')
 package=json.loads(direct(REPO,'labs/usdom-reserve/package.json'))
 # npm must enter through the authenticated dispatcher. `repo-exec` accepts
 # only this static launcher and executes the descriptor it authenticated;
 # permitting the old direct pathname here would bypass the toolchain lock
 # that the rest of the release commands now enforce.
 check_package_guest_route(package)
 runbook=direct(REPO,'labs/usdom-reserve/docs/CLOSED-MAINNET-LINUX-RUNBOOK.md').decode()
 if './scripts/risc0-guest-build-launcher checkpoint-outer' not in runbook:
  fail('runbook omits authenticated guest-build launcher route')
 basenames=set(file_by_key.values())
 for candidate in (REPO/'labs/usdom-reserve/scripts').iterdir():
  if not candidate.is_file() or candidate.suffix not in {'.sh','.mjs','.js','.py'}:continue
  if candidate.name in basenames or candidate.name=='check-proof-program-panic-boundary.py':continue
  candidate_text=candidate.read_text(errors='replace')
  for basename in basenames:
   if basename in candidate_text:fail(f'unauthorized guest-builder callsite: {candidate.relative_to(REPO)}')
 for candidate_text,label in ((direct(REPO,'labs/usdom-reserve/package.json').decode(),'package.json'),(runbook,'runbook')):
  for basename in basenames:
   if basename in candidate_text:fail(f'{label} invokes internal guest builder directly')

def check_cargo_invocation(source,cargo_bytes,label):
 document=tomllib.loads(cargo_bytes.decode());features=set(document.get('features',{}))
 for raw in re.findall(r'--features(?:=|\s+)([^\s"\']+)',source):
  for feature in raw.split(','):
   if feature not in features:fail(f'{label}: command enables undeclared feature {feature}')
 bins={item.get('name') for item in document.get('bin',[]) if isinstance(item,dict)}
 for target in re.findall(r'--bin(?:=|\s+)([^\s"\']+)',source):
  if target not in bins:fail(f'{label}: command selects omitted bin target {target}')

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
 cargo_closure=derive_cargo_path_closure();expected=SOURCES|ARTIFACTS|cargo_closure
 payloads=manifest(REPO,'labs/usdom-reserve/PROOF-PROGRAM-MANIFEST.sha256',expected)
 rust_closure(REPO,SOURCES,expected)
 rpc_build=payloads['crates/dom-rpc/build.rs'].decode()
 for token in ('USDOM_RELEASE_BUILD','is_canonical_source_authority','release build requires DOM_BUILD_COMMIT'):
  if token not in rpc_build:fail(f'dom-rpc release identity fallback is not closed: missing {token}')
 boundaries=LOCAL_PROVER_LAUNCHERS|ADAPTIVE_LOCAL_PROVER_LAUNCHERS|LOCAL_PROVER_JS_LAUNCHERS|PRIVATE_PROOF_SCRIPTS
 boundary_payloads=snapshot(REPO,boundaries)
 text=lambda name:(payloads[name] if name in payloads else boundary_payloads[name]).decode()
 for name in sorted(SOURCES): check_text(payloads[name].decode(),name)
 for name,contexts in LOCAL_PROVER_HELPERS.items():
  check_local_helper(production(text(name)),name,contexts)
 for name,contexts in LOCAL_PROVER_CALLS.items():
  check_local_call(production(text(name)),name,contexts)
 for name in LOCAL_PROVER_LAUNCHERS:
  check_local_launcher(text(name),name)
 for name in ADAPTIVE_LOCAL_PROVER_LAUNCHERS:
  check_local_endpoint_boundary(text(name),name)
 for name in LOCAL_PROVER_JS_LAUNCHERS:
  check_local_js_launcher(text(name),name)
 for name in FIXED_PROOF_ENTRYPOINTS:
  check_fixed_entrypoint(text(name),name)
 for name in PRIVATE_OUTPUT_HOSTS:
  check_private_output_host(production(text(name)),name)
 for name in PRIVATE_PROOF_SCRIPTS:
  check_private_script(text(name),name)
 for name in GUEST_BUILD_SCRIPTS:
  check_guest_build_script(text(name),name)
 check_guest_build_launcher(payloads)
 for guest,(script_name,_,_,_,_) in GUEST_ARTIFACT_RELATIONS.items():
  label=f'labs/usdom-reserve/scripts/build-{script_name}-risc0-guest.sh'
  check_cargo_invocation(text(label),payloads[f'crates/dom-usdom-{guest}-risc0-guest/Cargo.toml'],label)
 check_guest_artifact_constants()
 check_boundary_command_timeouts()
 check_economic_receipt_schema(
  text('crates/dom-usdom-economic-proof-host/src/lib.rs'),
  text('crates/dom-usdom-checkpoint-proof-host/src/lib.rs'),
 )
 finalized=text('crates/dom-usdom-finalized-burn-program/src/main.rs')
 statement=text('crates/dom-usdom-checkpoint-statement/src/main.rs')
 if finalized.find('.take(maximum_read as u64)') > finalized.find('.read_to_end(') or 'checked_add(1)' not in finalized:
  fail('finalized-burn host input is not bounded before read_to_end')
 if statement.find('.take((CHECKPOINT_STATEMENT_V4_BYTES + 1) as u64)') > statement.find('.read_to_end('):
  fail('checkpoint-statement host input is not bounded before read_to_end')

def bounded_launcher_run(arguments,**kwargs):
 try:
  return subprocess.run(arguments,timeout=30,**kwargs)
 except subprocess.TimeoutExpired as error:
  fail(f'guest-build launcher regression timed out: {error}')

def self_test_guest_build_launcher():
 expected='./scripts/mainnet-tool-dispatcher repo-exec scripts/risc0-guest-build-launcher'
 check_package_guest_route({'scripts':{'build:risc0-guest':expected}})
 for hostile in ('./scripts/risc0-guest-build-launcher',
                 './scripts/mainnet-tool-dispatcher repo-exec scripts/build-finalized-burn-risc0-guest.sh',
                 expected+' --unexpected'):
  try:check_package_guest_route({'scripts':{'build:risc0-guest':hostile}})
  except SystemExit:pass
  else:raise AssertionError('unauthorized package guest-build route was accepted')
 launcher=REPO/'labs/usdom-reserve/scripts/risc0-guest-build-launcher'
 builder=REPO/'labs/usdom-reserve/scripts/build-economic-chunk-risc0-guest.sh'
 source=REPO/'labs/usdom-reserve/scripts/risc0-guest-build-launcher.c'
 compiler='/usr/bin/x86_64-linux-gnu-gcc-13'
 arguments=['-static','-std=c11','-O2','-Wall','-Wextra','-Werror','-fno-ident',
            '-fno-asynchronous-unwind-tables','-Wl,--build-id=none','-s']
 with tempfile.TemporaryDirectory(prefix='usdom-launcher-repro-') as temporary:
  first=Path(temporary)/'one';second=Path(temporary)/'two'
  clean={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','TZ':'UTC'}
  bounded_launcher_run([compiler,*arguments,'-o',first,source],env=clean,check=True)
  bounded_launcher_run([compiler,*arguments,'-o',second,source],env=clean,check=True)
  if first.read_bytes()!=second.read_bytes() or first.read_bytes()!=launcher.read_bytes():
   raise AssertionError('static launcher is not reproducible')
 with tempfile.NamedTemporaryFile('w',prefix='usdom-bash-env-',delete=False) as handle:
  handle.write('export USDOM_BUILD_CAP_FD=8 USDOM_BUILD_BUILDER=economic-chunk\\n')
  bash_env=handle.name
 try:
  hostile={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','TZ':'UTC',
           'BASH_ENV':bash_env,'LD_PRELOAD':'/definitely/not/a/library.so'}
  result=bounded_launcher_run([launcher,'economic-chunk','--authority-self-test'],env=hostile,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  if result.returncode or 'PASS: authenticated launcher for economic-chunk' not in result.stdout:
   raise AssertionError('static launcher did not clean hostile loader/shell environment')
  fd_command='for fd in $(seq 3 32); do eval "exec ${fd}</dev/null"; done; exec "$@"'
  result=bounded_launcher_run(['/usr/bin/bash','--noprofile','--norc','-c',fd_command,'fd-regression',launcher,'economic-chunk','--authority-self-test'],env=hostile,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  if result.returncode or 'PASS: authenticated launcher for economic-chunk' not in result.stdout:
   raise AssertionError('inherited descriptors confused launcher authority FDs')
  with tempfile.TemporaryDirectory(prefix='usdom-launcher-copy-') as copied_root:
   copied=Path(copied_root)/'labs/usdom-reserve/scripts/risc0-guest-build-launcher'
   copied.parent.mkdir(parents=True);copied.write_bytes(launcher.read_bytes());copied.chmod(0o700)
   result=bounded_launcher_run([copied,'economic-chunk','--authority-self-test'],env=hostile,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   if result.returncode==0:raise AssertionError('launcher accepted a copied repository root')
  read_fd,write_fd=os.pipe();os.write(write_fd,b'USD0M-RISC0-BUILD-CAP-v1:economic-chunk\\n');os.close(write_fd)
  saved_fd=None
  try:
   try:saved_fd=os.dup(8)
   except OSError:pass
   os.dup2(read_fd,8);os.close(read_fd)
   direct_env=dict(hostile,USDOM_BUILD_CAP_FD='8',USDOM_BUILD_BUILDER='economic-chunk',USDOM_BUILD_REPO=str(REPO))
   result=bounded_launcher_run(['/usr/bin/bash','--noprofile','--norc',builder,'--authority-self-test'],
                               env=direct_env,pass_fds=(8,),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   if result.returncode==0:raise AssertionError('bash builder bypassed launcher parent authority')
  finally:
   try:os.close(8)
   except OSError:pass
   if saved_fd is not None:os.dup2(saved_fd,8);os.close(saved_fd)
 finally:
  os.unlink(bash_env)

def self_test():
 self_test_guest_build_launcher()
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
 check_cargo_invocation('cargo build --features safe --bin worker',b'[features]\nsafe=[]\n[[bin]]\nname="worker"\npath="src/main.rs"\n','cargo-command')
 for mutation in ('cargo build --features omitted','cargo build --bin omitted'):
  try:check_cargo_invocation(mutation,b'[features]\nsafe=[]\n[[bin]]\nname="worker"\npath="src/main.rs"\n','cargo-command')
  except SystemExit:pass
  else:raise AssertionError('feature/target omission accepted')
 normal_build=(REPO/'labs/usdom-reserve/scripts/build-economic-chunk-risc0-guest.sh').read_text()
 finalized_build=(REPO/'labs/usdom-reserve/scripts/build-finalized-burn-risc0-guest.sh').read_text()
 for source,label,token in (
  (normal_build,'economic-build-mutation','"$USDOM_CMP" --silent "$program" "$expected_program"'),
  (normal_build,'lock-build-mutation','usdom_sha256 "$expected_lock"'),
  (normal_build,'utility-pin-mutation','pin_build_utilities '),
  (normal_build,'ambient-env-mutation','reject_ambient_build_environment'),
  (normal_build,'cargo-home-mutation','prepare_isolated_cargo_home "$build_root"'),
  (normal_build,'toolchain-build-mutation','expected_rustc_commit='),
  (normal_build,'llvm-build-mutation','expected_llvm_version='),
  (normal_build,'ambient-wrapper-mutation','RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS'),
  (normal_build,'rustup-launcher-mutation','expected_rustup_sha='),
  (normal_build,'pinned-guest-mutation','pin_risc0_guest_toolchain "$rustup_path" "$expected_rustup_sha"'),
  (normal_build,'pinned-host-mutation','pin_host_rust_toolchain "$rustup_path" "$expected_rustup_sha"'),
  (normal_build,'host-recheck-mutation','assert_host_rust_toolchain_unchanged'),
  (finalized_build,'docker-build-mutation','RISC0_DOCKER_CONTAINER_TAG='),
  (finalized_build,'image-id-build-mutation','actual_id="$("$FROZEN_R0VM" --id --elf "$user_elf")"'),
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
