#!/usr/bin/env -S -i USDOM_PINNED_BUILD_ENV=1 PATH=/usr/bin:/bin LC_ALL=C LANG=C TZ=UTC /usr/bin/bash --noprofile --norc
set -euo pipefail

readonly expected_builder='economic-block'
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
source_authority=/proc/self/fd/10
test -f "$source_authority"
export USDOM_RELEASE_BUILD=1
export DOM_BUILD_COMMIT="sha256:$(usdom_sha256 "$source_authority")"
manifest="$repo/crates/dom-usdom-economic-block-risc0-guest/Cargo.toml"
expected_elf="$repo/crates/dom-usdom-economic-block-risc0-guest/elfs/usdom-economic-block.elf"
expected_program="$repo/crates/dom-usdom-economic-block-risc0-guest/elfs/usdom-economic-block.bin"
expected_iid="$repo/crates/dom-usdom-economic-block-risc0-guest/elfs/usdom-economic-block.iid"
expected_lock="$repo/crates/dom-usdom-economic-block-risc0-guest/Cargo.lock"
expected_workspace_lock_sha="66bce82983b22b50203ae6b8a49054121fe9f15312173695b9b84f65d316e120"
expected_guest_lock_sha="e9e3696164e4cef4d20194457333c48fea709ab2960ba387e60720831e5ee745"
expected_elf_sha="e863f8ddc042a0692f8ceebc8d0c074e6812087bc9c06a5cd1710ac0c7bfda2f"
expected_program_sha="e16e6aea7d470baad85bec45578e0960c02c2d47bce267e26141a2f3fa4a6c1f"
expected_id="03dc111fee3c42a772f142c80d4a921a19bde10f932f86c888606503a28c22a7"
expected_rustc_commit="e638c6cfea1eff5fbbb24a27e60538e3760d21b8"
expected_llvm_version="22.1.6"
expected_rustup_sha="4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10"
for variable in RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS; do
  test -z "${!variable-}"
done
build_root="$("$USDOM_MKTEMP" -d "${TMPDIR:-/tmp}/usdom-economic-block.XXXXXX")"
trap 'rm -rf "$build_root"' EXIT
prepare_isolated_cargo_home "$build_root"

for command in sha256sum cmp mktemp; do command -v "$command" >/dev/null; done
rustup_path=/home/leonardov/.cargo/bin/rustup
test "$(usdom_sha256 "$rustup_path")" = "$expected_rustup_sha"
pin_risc0_guest_toolchain "$rustup_path" "$expected_rustup_sha"
pin_host_rust_toolchain "$rustup_path" "$expected_rustup_sha"
rustc_identity="$("$RISC0_GUEST_RUSTC" --version --verbose)"
"$USDOM_GREP" -Fx "commit-hash: $expected_rustc_commit" <<<"$rustc_identity" >/dev/null
"$USDOM_GREP" -Fx "LLVM version: $expected_llvm_version" <<<"$rustc_identity" >/dev/null
test "$(usdom_sha256 "$repo/Cargo.lock")" = "$expected_workspace_lock_sha"
test "$(usdom_sha256 "$expected_lock")" = "$expected_guest_lock_sha"
test "$(<"$expected_iid")" = "$expected_id"

export CARGO_TARGET_DIR="$build_root/guest-target"
export CARGO_ENCODED_RUSTFLAGS=$'-C\x1fpasses=lower-atomic\x1f-C\x1flink-arg=-Ttext=0x00200800\x1f-C\x1flink-arg=--fatal-warnings\x1f-C\x1fpanic=abort\x1f--cfg\x1fgetrandom_backend="custom"'$'\x1f-C\x1flinker='"$RISC0_GUEST_RUST_LLD"
export RISC0_FEATURE_bigint2=''
RUSTC="$RISC0_GUEST_RUSTC" "$RISC0_GUEST_CARGO" build --release --locked --target riscv32im-risc0-zkvm-elf --manifest-path "$manifest"
assert_risc0_guest_toolchain_unchanged
user_elf="$CARGO_TARGET_DIR/riscv32im-risc0-zkvm-elf/release/usdom-economic-block"
test "$(usdom_sha256 "$user_elf")" = "$expected_elf_sha"
"$USDOM_CMP" --silent "$user_elf" "$expected_elf"

unset CARGO_ENCODED_RUSTFLAGS RISC0_FEATURE_bigint2
export CARGO_TARGET_DIR="$build_root/host-target"
program="$build_root/usdom-economic-block.bin"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$USDOM_HOST_LINKER"
actual_id="$(RUSTC="$HOST_RUSTC" "$HOST_CARGO" run --quiet --locked --manifest-path "$repo/Cargo.toml" -p dom-risc0-program-packager -- "$user_elf" "$program")"
assert_risc0_guest_toolchain_unchanged
assert_host_rust_toolchain_unchanged
test "$actual_id" = "$expected_id"
test "$(usdom_sha256 "$program")" = "$expected_program_sha"
"$USDOM_CMP" --silent "$program" "$expected_program"
printf 'PASS: reproducible economic-block guest %s ImageID %s\n' "$expected_program_sha" "$actual_id"
