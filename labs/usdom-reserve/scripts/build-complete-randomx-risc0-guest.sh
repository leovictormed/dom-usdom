#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
manifest="$repo/crates/dom-usdom-randomx-risc0-guest/Cargo.toml"
expected_elf="$repo/crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.elf"
expected_program="$repo/crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.bin"
expected_iid="$repo/crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.iid"
expected_lock="$repo/crates/dom-usdom-randomx-risc0-guest/Cargo.lock"
expected_workspace_lock_sha="fb095d8cd7943e0481666164dffad9555ac11e82aa92e2445e556843331165c1"
expected_guest_lock_sha="745b3c37903c47e71d55b640909e745922e97f5c05afab6970cb8f0aec7edf84"
expected_elf_sha="1a8e491304763477094da84ff0701ea18d935600a3b3a79eb1c1250facd6903f"
expected_program_sha="0601bf022575b060edaeb0b32414b2f53e72f39d2284028069099414653591dd"
expected_id="8efa49d4fe0f616840013adb1d3029ef71642099cb336c577a2691f7eea1dc24"
expected_rustc_commit="e638c6cfea1eff5fbbb24a27e60538e3760d21b8"
expected_llvm_version="22.1.6"
expected_rustup_sha="4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10"
for variable in RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS; do
  test -z "${!variable-}"
done
build_root="$(mktemp -d "${TMPDIR:-/tmp}/usdom-randomx-complete.XXXXXX")"
trap 'rm -rf "$build_root"' EXIT

for command in cargo rustup sha256sum cmp mktemp grep; do command -v "$command" >/dev/null; done
cargo_path="$(realpath "$(command -v cargo)")"; rustup_path="$(realpath "$(command -v rustup)")"
test "$cargo_path" = "$rustup_path"; test "$(sha256sum "$rustup_path" | awk '{print $1}')" = "$expected_rustup_sha"
rustc_identity="$("$rustup_path" run risc0 rustc --version --verbose)"
grep -Fx "commit-hash: $expected_rustc_commit" <<<"$rustc_identity" >/dev/null
grep -Fx "LLVM version: $expected_llvm_version" <<<"$rustc_identity" >/dev/null
test "$(sha256sum "$repo/Cargo.lock" | awk '{print $1}')" = "$expected_workspace_lock_sha"
test "$(sha256sum "$expected_lock" | awk '{print $1}')" = "$expected_guest_lock_sha"
test "$(tr -d '\n' < "$expected_iid")" = "$expected_id"
export CARGO_TARGET_DIR="$build_root/guest-target"
export CARGO_ENCODED_RUSTFLAGS=$'-C\x1fpasses=lower-atomic\x1f-C\x1flink-arg=-Ttext=0x00200800\x1f-C\x1flink-arg=--fatal-warnings\x1f-C\x1fpanic=abort\x1f--cfg\x1fgetrandom_backend="custom"'
export RISC0_FEATURE_bigint2=''
"$cargo_path" +risc0 build --release --locked --target riscv32im-risc0-zkvm-elf --manifest-path "$manifest"
user_elf="$CARGO_TARGET_DIR/riscv32im-risc0-zkvm-elf/release/usdom-randomx"
test "$(sha256sum "$user_elf" | awk '{print $1}')" = "$expected_elf_sha"
cmp --silent "$user_elf" "$expected_elf"

unset CARGO_ENCODED_RUSTFLAGS RISC0_FEATURE_bigint2
export CARGO_TARGET_DIR="$build_root/host-target"
program="$build_root/usdom-randomx.bin"
actual_id="$("$cargo_path" run --quiet --locked --manifest-path "$repo/Cargo.toml" -p dom-risc0-program-packager -- "$user_elf" "$program")"
test "$actual_id" = "$expected_id"
test "$(sha256sum "$program" | awk '{print $1}')" = "$expected_program_sha"
cmp --silent "$program" "$expected_program"
printf 'PASS: reproducible complete RandomX guest %s ImageID %s\n' "$expected_program_sha" "$expected_id"
