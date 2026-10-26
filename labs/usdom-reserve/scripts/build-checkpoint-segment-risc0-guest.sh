#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
manifest="$repo/crates/dom-usdom-checkpoint-segment-risc0-guest/Cargo.toml"
expected_elf="$repo/crates/dom-usdom-checkpoint-segment-risc0-guest/elfs/usdom-checkpoint-segment.elf"
expected_program="$repo/crates/dom-usdom-checkpoint-segment-risc0-guest/elfs/usdom-checkpoint-segment.bin"
expected_iid="$repo/crates/dom-usdom-checkpoint-segment-risc0-guest/elfs/usdom-checkpoint-segment.iid"
expected_lock="$repo/crates/dom-usdom-checkpoint-segment-risc0-guest/Cargo.lock"
expected_workspace_lock_sha="fb095d8cd7943e0481666164dffad9555ac11e82aa92e2445e556843331165c1"
expected_guest_lock_sha="e9e3696164e4cef4d20194457333c48fea709ab2960ba387e60720831e5ee745"
expected_elf_sha="5c1a4d730459d44e995a8842d1ce89136af546616464362a8136988ab7751272"
expected_program_sha="c4cc41b0b53d787c46b9293d1515c2d0c4ded982c3ae7b98d33877dd142d2b38"
expected_id="4e711490f3ab7dde97636687972456da58da4287ce5017e38d4acaa7263a02d6"
expected_rustc_commit="e638c6cfea1eff5fbbb24a27e60538e3760d21b8"
expected_llvm_version="22.1.6"
expected_rustup_sha="4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10"
for variable in RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS; do
  test -z "${!variable-}"
done
build_root="$(mktemp -d "${TMPDIR:-/tmp}/usdom-checkpoint-segment.XXXXXX")"
trap 'rm -rf "$build_root"' EXIT

for command in cargo rustup sha256sum cmp mktemp; do command -v "$command" >/dev/null; done
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
user_elf="$CARGO_TARGET_DIR/riscv32im-risc0-zkvm-elf/release/usdom-checkpoint-segment"
test "$(sha256sum "$user_elf" | awk '{print $1}')" = "$expected_elf_sha"
cmp --silent "$user_elf" "$expected_elf"

unset CARGO_ENCODED_RUSTFLAGS RISC0_FEATURE_bigint2
export CARGO_TARGET_DIR="$build_root/host-target"
program="$build_root/usdom-checkpoint-segment.bin"
actual_id="$("$cargo_path" run --quiet --locked --manifest-path "$repo/Cargo.toml" -p dom-risc0-program-packager -- "$user_elf" "$program")"
test "$actual_id" = "$expected_id"
test "$(sha256sum "$program" | awk '{print $1}')" = "$expected_program_sha"
cmp --silent "$program" "$expected_program"
printf 'PASS: reproducible checkpoint-segment guest %s ImageID %s\n' "$expected_program_sha" "$actual_id"
