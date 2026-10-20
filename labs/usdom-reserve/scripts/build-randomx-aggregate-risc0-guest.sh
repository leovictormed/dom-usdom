#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
manifest="$repo/crates/dom-usdom-randomx-aggregate-risc0-guest/Cargo.toml"
expected="$repo/crates/dom-usdom-randomx-aggregate-risc0-guest/elfs/usdom-randomx-aggregate.bin"
build_lock="$repo/crates/dom-usdom-randomx-aggregate-risc0-guest/Cargo.lock"
expected_user_sha="192c97830e7e1c390c025c137480268e0f75dfc96184738fb6a14c8e13e81c6b"
expected_program_sha="3dad95bf467a807c7ef033f88595ea44f14578dca4c7558ad95b7ad76c0d198f"
expected_id="08abf768e699ecb9d5cd2abc7603368103bcd3ee61afe9066d8a77272ac02ebf"
expected_lock_sha="745b3c37903c47e71d55b640909e745922e97f5c05afab6970cb8f0aec7edf84"
build_root="$(mktemp -d "${TMPDIR:-/tmp}/usdom-randomx-aggregate.XXXXXX")"
trap 'rm -rf "$build_root"' EXIT

command -v cargo >/dev/null
command -v rustc >/dev/null
test "$(sha256sum "$repo/Cargo.lock" | awk '{print $1}')" = "$expected_lock_sha"
test "$(sha256sum "$build_lock" | awk '{print $1}')" = "$expected_lock_sha"

export CARGO_TARGET_DIR="$build_root/guest-target"
export CARGO_ENCODED_RUSTFLAGS=$'-C\x1fpasses=lower-atomic\x1f-C\x1flink-arg=-Ttext=0x00200800\x1f-C\x1flink-arg=--fatal-warnings\x1f-C\x1fpanic=abort\x1f--cfg\x1fgetrandom_backend="custom"'
export RISC0_FEATURE_bigint2=''
cargo +risc0 build --release --locked --target riscv32im-risc0-zkvm-elf \
    --manifest-path "$manifest"

user_elf="$CARGO_TARGET_DIR/riscv32im-risc0-zkvm-elf/release/usdom-randomx-aggregate"
actual_user_sha="$(sha256sum "$user_elf" | awk '{print $1}')"
test "$actual_user_sha" = "$expected_user_sha"

unset CARGO_ENCODED_RUSTFLAGS RISC0_FEATURE_bigint2
export CARGO_TARGET_DIR="$build_root/host-target"
program="$build_root/usdom-randomx-aggregate.bin"
actual_id="$(
    cargo run --quiet --locked --manifest-path "$manifest" --example package_program -- \
        "$user_elf" "$program"
)"
test "$actual_id" = "$expected_id"
actual_program_sha="$(sha256sum "$program" | awk '{print $1}')"
test "$actual_program_sha" = "$expected_program_sha"
cmp --silent "$program" "$expected"

printf 'PASS: reproducible candidate RandomX aggregate RISC Zero program %s ImageID %s\n' \
    "$actual_program_sha" "$actual_id"
