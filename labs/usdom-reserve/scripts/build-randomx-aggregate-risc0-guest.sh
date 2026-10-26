#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
manifest="$repo/crates/dom-usdom-randomx-aggregate-risc0-guest/Cargo.toml"
expected_program="$repo/crates/dom-usdom-randomx-aggregate-risc0-guest/elfs/usdom-randomx-aggregate.bin"
expected_iid="$repo/crates/dom-usdom-randomx-aggregate-risc0-guest/elfs/usdom-randomx-aggregate.iid"
expected_lock="$repo/crates/dom-usdom-randomx-aggregate-risc0-guest/Cargo.lock"
expected_user_sha="192c97830e7e1c390c025c137480268e0f75dfc96184738fb6a14c8e13e81c6b"
expected_program_sha="3dad95bf467a807c7ef033f88595ea44f14578dca4c7558ad95b7ad76c0d198f"
expected_id="08abf768e699ecb9d5cd2abc7603368103bcd3ee61afe9066d8a77272ac02ebf"
expected_workspace_lock_sha="fb095d8cd7943e0481666164dffad9555ac11e82aa92e2445e556843331165c1"
expected_guest_lock_sha="745b3c37903c47e71d55b640909e745922e97f5c05afab6970cb8f0aec7edf84"
expected_rustc_commit="e638c6cfea1eff5fbbb24a27e60538e3760d21b8"
expected_llvm_version="22.1.6"
expected_rustup_sha="4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10"
for variable in RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS; do
  test -z "${!variable-}"
done
build_root="$(mktemp -d "${TMPDIR:-/tmp}/usdom-randomx-aggregate.XXXXXX")"
trap 'rm -rf "$build_root"' EXIT

for command in cargo rustup sha256sum cmp mktemp grep; do command -v "$command" >/dev/null; done
cargo_path="$(realpath "$(command -v cargo)")"; rustup_path="$(realpath "$(command -v rustup)")"
test "$cargo_path" = "$rustup_path"; test "$(sha256sum "$rustup_path" | awk '{print $1}')" = "$expected_rustup_sha"
rustc_identity="$("$rustup_path" run risc0 rustc --version --verbose)"
grep -Fx "commit-hash: $expected_rustc_commit" <<<"$rustc_identity" >/dev/null
grep -Fx "LLVM version: $expected_llvm_version" <<<"$rustc_identity" >/dev/null
command -v rustc >/dev/null
test "$(sha256sum "$repo/Cargo.lock" | awk '{print $1}')" = "$expected_workspace_lock_sha"
test "$(sha256sum "$expected_lock" | awk '{print $1}')" = "$expected_guest_lock_sha"
test "$(tr -d '\n' < "$expected_iid")" = "$expected_id"

export CARGO_TARGET_DIR="$build_root/guest-target"
export CARGO_ENCODED_RUSTFLAGS=$'-C\x1fpasses=lower-atomic\x1f-C\x1flink-arg=-Ttext=0x00200800\x1f-C\x1flink-arg=--fatal-warnings\x1f-C\x1fpanic=abort\x1f--cfg\x1fgetrandom_backend="custom"'
export RISC0_FEATURE_bigint2=''
"$cargo_path" +risc0 build --release --locked --target riscv32im-risc0-zkvm-elf \
    --manifest-path "$manifest"

user_elf="$CARGO_TARGET_DIR/riscv32im-risc0-zkvm-elf/release/usdom-randomx-aggregate"
actual_user_sha="$(sha256sum "$user_elf" | awk '{print $1}')"
test "$actual_user_sha" = "$expected_user_sha"

unset CARGO_ENCODED_RUSTFLAGS RISC0_FEATURE_bigint2
export CARGO_TARGET_DIR="$build_root/host-target"
program="$build_root/usdom-randomx-aggregate.bin"
actual_id="$(
    "$cargo_path" run --quiet --locked --manifest-path "$repo/Cargo.toml" -p dom-risc0-program-packager -- \
        "$user_elf" "$program"
)"
test "$actual_id" = "$expected_id"
actual_program_sha="$(sha256sum "$program" | awk '{print $1}')"
test "$actual_program_sha" = "$expected_program_sha"
cmp --silent "$program" "$expected_program"

printf 'PASS: reproducible candidate RandomX aggregate RISC Zero program %s ImageID %s\n' \
    "$actual_program_sha" "$actual_id"
