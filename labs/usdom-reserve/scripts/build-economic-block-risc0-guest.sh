#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
manifest="$repo/crates/dom-usdom-economic-block-risc0-guest/Cargo.toml"
target_dir="${CARGO_TARGET_DIR:-$repo/target}"
user_elf="$target_dir/riscv32im-risc0-zkvm-elf/release/usdom-economic-block"
output="$target_dir/riscv32im-risc0-zkvm-elf/release/usdom-economic-block.bin"

command -v cargo >/dev/null
cargo +risc0 --version >/dev/null
cd "$repo"

export CARGO_ENCODED_RUSTFLAGS=$'-C\x1fpasses=lower-atomic\x1f-C\x1flink-arg=-Ttext=0x00200800\x1f-C\x1flink-arg=--fatal-warnings\x1f-C\x1fpanic=abort\x1f--cfg\x1fgetrandom_backend="custom"'
cargo +risc0 build --release --locked --target riscv32im-risc0-zkvm-elf \
  --manifest-path "$manifest"
unset CARGO_ENCODED_RUSTFLAGS

cargo run --locked -p dom-risc0-program-packager -- "$user_elf" "$output"
sha256sum "$user_elf" "$output"
stat -c '%n bytes=%s' "$user_elf" "$output"
