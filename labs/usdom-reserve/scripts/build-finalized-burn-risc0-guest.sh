#!/usr/bin/env -S -i USDOM_PINNED_BUILD_ENV=1 PATH=/usr/bin:/bin LC_ALL=C LANG=C TZ=UTC /usr/bin/bash --noprofile --norc
set -euo pipefail

readonly expected_builder='finalized-burn'
if (( $# > 1 )) || (( $# == 1 )) && [[ $1 != --authority-self-test ]]; then
  printf '%s\n' 'builder must be invoked by risc0-guest-build-launcher' >&2
  exit 64
fi
if [[ ${USDOM_BUILD_CAP_FD:-} != 8 || ${USDOM_BUILD_AUTHORITY_FD:-} != 10 || ${USDOM_BUILD_HELPER_FD:-} != 11 || ${USDOM_BUILD_BUILDER:-} != "$expected_builder" || ${USDOM_BUILD_REPO:-} != /* || ! ${USDOM_BUILD_NONCE:-} =~ ^[0-9a-f]{64}$ || ! ${USDOM_BUILD_SCRIPT_SHA256:-} =~ ^[0-9a-f]{64}$ ]]; then
  printf '%s\n' 'missing authenticated guest-build launcher capability' >&2
  exit 77
fi
capability=''
if ! IFS= builtin read -r -u 8 capability || [[ $capability != "USD0M-RISC0-BUILD-CAP-v2:$expected_builder:$USDOM_BUILD_SCRIPT_SHA256:$USDOM_BUILD_NONCE" ]]; then
  printf '%s\n' 'invalid guest-build launcher capability' >&2
  exit 77
fi
exec 8<&-
umask 077
repo=$USDOM_BUILD_REPO
source /proc/self/fd/11
reject_ambient_build_environment
pin_build_utilities "$USDOM_CMP" "$USDOM_CMP_SHA256" "$USDOM_GREP" "$USDOM_GREP_SHA256" "$USDOM_MKTEMP" "$USDOM_MKTEMP_SHA256" "$USDOM_STAT" "$USDOM_STAT_SHA256" "$USDOM_REALPATH" "$USDOM_REALPATH_SHA256" "$USDOM_ID" "$USDOM_ID_SHA256" "$USDOM_XXD" "$USDOM_XXD_SHA256"
authenticate_risc0_build_launcher_parent
if [[ ${1:-} == --authority-self-test ]]; then
  printf 'PASS: authenticated launcher for %s\n' "$expected_builder"
  exit 0
fi
pin_build_utilities "$USDOM_DOCKER" "$USDOM_DOCKER_SHA256" "$USDOM_R0VM" "$USDOM_R0VM_SHA256" "$USDOM_CARGO_RISZERO" "$USDOM_CARGO_RISZERO_SHA256"
freeze_authenticated_tool FROZEN_R0VM "$USDOM_R0VM" "$USDOM_R0VM_SHA256"
freeze_authenticated_tool FROZEN_CARGO_RISZERO "$USDOM_CARGO_RISZERO" "$USDOM_CARGO_RISZERO_SHA256"
source_authority=/proc/self/fd/10
test -f "$source_authority"
export USDOM_RELEASE_BUILD=1
export DOM_BUILD_COMMIT="sha256:$(usdom_sha256 "$source_authority")"
manifest="$repo/crates/dom-usdom-finalized-burn-risc0-guest/Cargo.toml"
expected_elf="$repo/crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.elf"
expected_iid="$repo/crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.iid"
expected_lock="$repo/crates/dom-usdom-finalized-burn-risc0-guest/Cargo.lock"
builder="r0.1.97.0@sha256:7ae0a27fa72b10fb5c1066005bd949ae43dc4ead8a284f2d6572b99c82ab4468"
expected_workspace_lock_sha="66bce82983b22b50203ae6b8a49054121fe9f15312173695b9b84f65d316e120"
expected_guest_lock_sha="4b121d8cd50110e8235933ac405b7dfac3bb92d43f959082af638a24ea539765"
expected_elf_sha="bf3202187d7c0643204bcb936b34a53b41b871cc4d633781dc96956c7de9d511"
expected_id="f0d9c98287719bf6fca6626ab96f0b14e305662873a9e3b5d4894a50f206a1ae"
build_root="$("$USDOM_MKTEMP" -d "${TMPDIR:-/tmp}/usdom-finalized-burn.XXXXXX")"
trap 'rm -rf "$build_root"' EXIT
prepare_isolated_cargo_home "$build_root"

PATH=/usr/bin:/bin "$FROZEN_CARGO_RISZERO" risczero --version >/dev/null
test "$(usdom_sha256 "$repo/Cargo.lock")" = "$expected_workspace_lock_sha"
test "$(usdom_sha256 "$expected_lock")" = "$expected_guest_lock_sha"
test "$("$USDOM_XXD" -p -c 256 "$expected_iid")" = "$expected_id"

export CARGO_TARGET_DIR="$build_root/target"
export RISC0_BUILD_LOCKED=1
export RISC0_DOCKER_CONTAINER_TAG="$builder"
PATH=/usr/bin:/bin "$FROZEN_CARGO_RISZERO" risczero build --manifest-path "$manifest"
user_elf="$CARGO_TARGET_DIR/riscv32im-risc0-zkvm-elf/docker/usdom-finalized-burn.bin"

test "$(usdom_sha256 "$user_elf")" = "$expected_elf_sha"
"$USDOM_CMP" --silent "$user_elf" "$expected_elf"
actual_id="$("$FROZEN_R0VM" --id --elf "$user_elf")"
test "$actual_id" = "$expected_id"

printf 'PASS: reproducible finalized-burn RISC Zero guest %s ImageID %s\n' \
    "$expected_elf_sha" "$actual_id"
