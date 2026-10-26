#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
manifest="$repo/crates/dom-usdom-finalized-burn-risc0-guest/Cargo.toml"
expected_elf="$repo/crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.elf"
expected_iid="$repo/crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.iid"
expected_lock="$repo/crates/dom-usdom-finalized-burn-risc0-guest/Cargo.lock"
builder="r0.1.97.0@sha256:7ae0a27fa72b10fb5c1066005bd949ae43dc4ead8a284f2d6572b99c82ab4468"
expected_workspace_lock_sha="571022e832a552ef7710cdd2dc8643e974436fae44c7c2f003acd05ee0106c34"
expected_guest_lock_sha="4b121d8cd50110e8235933ac405b7dfac3bb92d43f959082af638a24ea539765"
expected_elf_sha="883ec39b03e3a0703e592026fc7d92a15ce7d949cb937551c5dd8360184cde21"
expected_id="2e26f74497b54b680dfff4c116d56280d016f01d0125329f49bf6d744b1c18ea"
build_root="$(mktemp -d "${TMPDIR:-/tmp}/usdom-finalized-burn.XXXXXX")"
trap 'rm -rf "$build_root"' EXIT

for command in cargo docker r0vm sha256sum cmp xxd mktemp; do command -v "$command" >/dev/null; done
cargo risczero --version >/dev/null
test "$(sha256sum "$repo/Cargo.lock" | awk '{print $1}')" = "$expected_workspace_lock_sha"
test "$(sha256sum "$expected_lock" | awk '{print $1}')" = "$expected_guest_lock_sha"
test "$(xxd -p -c 256 "$expected_iid")" = "$expected_id"

export CARGO_TARGET_DIR="$build_root/target"
export RISC0_BUILD_LOCKED=1
export RISC0_DOCKER_CONTAINER_TAG="$builder"
cargo risczero build --manifest-path "$manifest"
user_elf="$CARGO_TARGET_DIR/riscv32im-risc0-zkvm-elf/docker/usdom-finalized-burn.bin"

test "$(sha256sum "$user_elf" | awk '{print $1}')" = "$expected_elf_sha"
cmp --silent "$user_elf" "$expected_elf"
actual_id="$(r0vm --id --elf "$user_elf")"
test "$actual_id" = "$expected_id"

printf 'PASS: reproducible finalized-burn RISC Zero guest %s ImageID %s\n' \
    "$expected_elf_sha" "$actual_id"
