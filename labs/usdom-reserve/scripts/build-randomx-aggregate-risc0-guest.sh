#!/usr/bin/env -S -i USDOM_PINNED_BUILD_ENV=1 PATH=/usr/bin:/bin LC_ALL=C LANG=C TZ=UTC /usr/bin/bash --noprofile --norc
set -euo pipefail

readonly expected_builder='randomx-aggregate'
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
manifest="$repo/crates/dom-usdom-randomx-aggregate-risc0-guest/Cargo.toml"
expected_program="$repo/crates/dom-usdom-randomx-aggregate-risc0-guest/elfs/usdom-randomx-aggregate.bin"
expected_iid="$repo/crates/dom-usdom-randomx-aggregate-risc0-guest/elfs/usdom-randomx-aggregate.iid"
expected_lock="$repo/crates/dom-usdom-randomx-aggregate-risc0-guest/Cargo.lock"
expected_user_sha="192c97830e7e1c390c025c137480268e0f75dfc96184738fb6a14c8e13e81c6b"
expected_program_sha="3dad95bf467a807c7ef033f88595ea44f14578dca4c7558ad95b7ad76c0d198f"
expected_id="08abf768e699ecb9d5cd2abc7603368103bcd3ee61afe9066d8a77272ac02ebf"
expected_workspace_lock_sha="66bce82983b22b50203ae6b8a49054121fe9f15312173695b9b84f65d316e120"
expected_guest_lock_sha="745b3c37903c47e71d55b640909e745922e97f5c05afab6970cb8f0aec7edf84"
expected_rustc_commit="e638c6cfea1eff5fbbb24a27e60538e3760d21b8"
expected_llvm_version="22.1.6"
expected_rustup_sha="4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10"
for variable in RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS; do
  test -z "${!variable-}"
done
build_root="$("$USDOM_MKTEMP" -d "${TMPDIR:-/tmp}/usdom-randomx-aggregate.XXXXXX")"
trap 'rm -rf "$build_root"' EXIT
prepare_isolated_cargo_home "$build_root"

for command in sha256sum cmp mktemp grep; do command -v "$command" >/dev/null; done
rustup_path=/home/leonardov/.cargo/bin/rustup
test "$(usdom_sha256 "$rustup_path")" = "$expected_rustup_sha"
pin_risc0_guest_toolchain "$rustup_path" "$expected_rustup_sha"
pin_host_rust_toolchain "$rustup_path" "$expected_rustup_sha"
rustc_identity="$("$RISC0_GUEST_RUSTC" --version --verbose)"
"$USDOM_GREP" -Fx "commit-hash: $expected_rustc_commit" <<<"$rustc_identity" >/dev/null
"$USDOM_GREP" -Fx "LLVM version: $expected_llvm_version" <<<"$rustc_identity" >/dev/null
command -v rustc >/dev/null
test "$(usdom_sha256 "$repo/Cargo.lock")" = "$expected_workspace_lock_sha"
test "$(usdom_sha256 "$expected_lock")" = "$expected_guest_lock_sha"
test "$(<"$expected_iid")" = "$expected_id"

export CARGO_TARGET_DIR="$build_root/guest-target"
export CARGO_ENCODED_RUSTFLAGS=$'-C\x1fpasses=lower-atomic\x1f-C\x1flink-arg=-Ttext=0x00200800\x1f-C\x1flink-arg=--fatal-warnings\x1f-C\x1fpanic=abort\x1f--cfg\x1fgetrandom_backend="custom"'$'\x1f-C\x1flinker='"$RISC0_GUEST_RUST_LLD"
export RISC0_FEATURE_bigint2=''
RUSTC="$RISC0_GUEST_RUSTC" "$RISC0_GUEST_CARGO" build --release --locked --target riscv32im-risc0-zkvm-elf \
    --manifest-path "$manifest"

assert_risc0_guest_toolchain_unchanged
user_elf="$CARGO_TARGET_DIR/riscv32im-risc0-zkvm-elf/release/usdom-randomx-aggregate"
actual_user_sha="$(usdom_sha256 "$user_elf")"
test "$actual_user_sha" = "$expected_user_sha"

unset CARGO_ENCODED_RUSTFLAGS RISC0_FEATURE_bigint2
export CARGO_TARGET_DIR="$build_root/host-target"
program="$build_root/usdom-randomx-aggregate.bin"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$USDOM_HOST_LINKER"
actual_id="$(
    RUSTC="$HOST_RUSTC" "$HOST_CARGO" run --quiet --locked --manifest-path "$repo/Cargo.toml" -p dom-risc0-program-packager -- \
        "$user_elf" "$program"
)"
assert_risc0_guest_toolchain_unchanged
assert_host_rust_toolchain_unchanged
test "$actual_id" = "$expected_id"
actual_program_sha="$(usdom_sha256 "$program")"
test "$actual_program_sha" = "$expected_program_sha"
"$USDOM_CMP" --silent "$program" "$expected_program"

printf 'PASS: reproducible candidate RandomX aggregate RISC Zero program %s ImageID %s\n' \
    "$actual_program_sha" "$actual_id"
