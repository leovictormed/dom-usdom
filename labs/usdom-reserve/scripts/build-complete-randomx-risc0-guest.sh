#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
manifest="$repo/crates/dom-usdom-randomx-risc0-guest/Cargo.toml"
expected_elf="$repo/crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.elf"
expected_program="$repo/crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.bin"
expected_lock="$repo/crates/dom-usdom-randomx-risc0-guest/Cargo.lock"
expected_lock_sha="745b3c37903c47e71d55b640909e745922e97f5c05afab6970cb8f0aec7edf84"
expected_elf_sha="1a8e491304763477094da84ff0701ea18d935600a3b3a79eb1c1250facd6903f"
expected_program_sha="0601bf022575b060edaeb0b32414b2f53e72f39d2284028069099414653591dd"
expected_id="8efa49d4fe0f616840013adb1d3029ef71642099cb336c577a2691f7eea1dc24"
build_root="$(mktemp -d "${TMPDIR:-/tmp}/usdom-randomx-complete.XXXXXX")"
trap 'rm -rf "$build_root"' EXIT

test "$(sha256sum "$repo/Cargo.lock" | awk '{print $1}')" = "$expected_lock_sha"
test "$(sha256sum "$expected_lock" | awk '{print $1}')" = "$expected_lock_sha"
export CARGO_TARGET_DIR="$build_root/guest-target"
export CARGO_ENCODED_RUSTFLAGS=$'-C\x1fpasses=lower-atomic\x1f-C\x1flink-arg=-Ttext=0x00200800\x1f-C\x1flink-arg=--fatal-warnings\x1f-C\x1fpanic=abort\x1f--cfg\x1fgetrandom_backend="custom"'
export RISC0_FEATURE_bigint2=''
cargo +risc0 build --release --locked --target riscv32im-risc0-zkvm-elf --manifest-path "$manifest"
user_elf="$CARGO_TARGET_DIR/riscv32im-risc0-zkvm-elf/release/usdom-randomx"
test "$(sha256sum "$user_elf" | awk '{print $1}')" = "$expected_elf_sha"
cmp --silent "$user_elf" "$expected_elf"

unset CARGO_ENCODED_RUSTFLAGS RISC0_FEATURE_bigint2
export CARGO_TARGET_DIR="$build_root/host-target"
program="$build_root/usdom-randomx.bin"
actual_id="$(cargo run --quiet --locked --manifest-path "$manifest" --example package_program -- "$user_elf" "$program")"
test "$actual_id" = "$expected_id"
test "$(sha256sum "$program" | awk '{print $1}')" = "$expected_program_sha"
cmp --silent "$program" "$expected_program"
printf 'PASS: reproducible complete RandomX guest %s ImageID %s\n' "$expected_program_sha" "$expected_id"
