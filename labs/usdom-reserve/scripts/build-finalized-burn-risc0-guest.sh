#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
manifest="$repo/crates/dom-usdom-finalized-burn-risc0-guest/Cargo.toml"
expected="$repo/crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.elf"
output="$repo/target/riscv32im-risc0-zkvm-elf/docker/usdom-finalized-burn.bin"
builder="r0.1.97.0@sha256:7ae0a27fa72b10fb5c1066005bd949ae43dc4ead8a284f2d6572b99c82ab4468"
expected_sha="438adf4a9a50832da0dfbb77c0b8588d9ba1fbb41d216875e874dfa1db5dfcb0"
expected_id="3975a5f01dc85b6e89925913c5555ade4aefb951c65261142384fd829a70f88a"

command -v cargo >/dev/null
command -v docker >/dev/null
cargo risczero --version >/dev/null

export RISC0_BUILD_LOCKED=1
export RISC0_DOCKER_CONTAINER_TAG="$builder"
cargo risczero build --manifest-path "$manifest"

actual_sha="$(sha256sum "$output" | awk '{print $1}')"
test "$actual_sha" = "$expected_sha"
cmp --silent "$output" "$expected"

if command -v r0vm >/dev/null; then
    actual_id="$(r0vm --id --elf "$output")"
    test "$actual_id" = "$expected_id"
fi

printf 'PASS: reproducible finalized-burn RISC Zero program %s ImageID %s\n' \
    "$actual_sha" "$expected_id"
