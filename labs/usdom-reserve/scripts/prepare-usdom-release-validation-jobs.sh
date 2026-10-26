#!/bin/bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
preparer="$repo/labs/usdom-reserve/scripts/prepare-supervised-proof-job.py"
toolchain_lock="$repo/labs/usdom-reserve/config/mainnet-toolchain-lock.json"
mapfile -t rust_tools < <(/usr/bin/python3 -c 'import json,sys
d=json.load(open(sys.argv[1])); items={x["name"]:x for x in d["executables"]}
for name in ("cargo","rustc"):
 x=items[name]; print(x["realpath"]); print(x["sha256"])' "$toolchain_lock")
test "${#rust_tools[@]}" -eq 4
cargo_bin="${rust_tools[0]}"; cargo_sha="${rust_tools[1]}"
rustc_bin="${rust_tools[2]}"; rustc_sha="${rust_tools[3]}"
test -x "$cargo_bin" -a -f "$cargo_bin" -a ! -L "$cargo_bin"
test -x "$rustc_bin" -a -f "$rustc_bin" -a ! -L "$rustc_bin"
test "$(/usr/bin/sha256sum "$cargo_bin" | /usr/bin/cut -d' ' -f1)" = "$cargo_sha"
test "$(/usr/bin/sha256sum "$rustc_bin" | /usr/bin/cut -d' ' -f1)" = "$rustc_sha"
target="${HOME}/.local/state/usdom-proof/target-release-validation"
jobs="${HOME}/.config/usdom-proof/jobs"
common=(
  --jobs-directory "$jobs" --cwd "$repo"
  --env "CARGO_HOME=${HOME}/.cargo" --env "RUSTUP_HOME=${HOME}/.rustup"
  --env "RUSTC=${rustc_bin}" --env "CARGO_TARGET_DIR=${target}"
  --env CARGO_INCREMENTAL=0 --max-log-bytes 67108864 --min-free-bytes 21474836480
  --bind-input Cargo.toml --bind-input Cargo.lock --bind-input rust-toolchain.toml
  --bind-input labs/usdom-reserve/config/mainnet-toolchain-lock.json
)

checkpoint_id="$(/usr/bin/python3 "$preparer" "${common[@]}" \
  --max-runtime-seconds 43200 \
  --bind-input crates/dom-usdom-checkpoint-program/src/reference.rs \
  --bind-input crates/dom-usdom-checkpoint-program/Cargo.toml \
  --bind-input crates/dom-usdom-checkpoint-program/tests/v2_checkpoint_extension.rs \
  --bind-input crates/dom-usdom-checkpoint-statement/Cargo.toml \
  --bind-input crates/dom-usdom-checkpoint-statement/src/lib.rs \
  --bind-input crates/dom-usdom-state/Cargo.toml \
  --bind-input crates/dom-usdom-state/src/lib.rs \
  --require-output 'test full_360_plus_30_v2_checkpoint_extension_is_recomputed ... ok' \
  --require-output 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;' -- \
  "$cargo_bin" test --profile release-validation --locked --offline -j1 \
  -p dom-usdom-checkpoint-program --features host-reference --test v2_checkpoint_extension \
  full_360_plus_30_v2_checkpoint_extension_is_recomputed -- \
  --exact --ignored --nocapture --test-threads=1)"

randomx_id="$(/usr/bin/python3 "$preparer" "${common[@]}" \
  --max-runtime-seconds 14400 \
  --bind-input crates/dom-usdom-randomx-portable/Cargo.toml \
  --bind-input crates/dom-usdom-randomx-portable/src/lib.rs \
  --bind-input crates/dom-usdom-randomx-portable/src/dataset.rs \
  --bind-input crates/dom-usdom-randomx-portable/src/superscalar.rs \
  --require-output 'test dataset::tests::upstream_randomx_argon2d_cache_vector_matches ... ok' \
  --require-output 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;' -- \
  "$cargo_bin" test --profile release-validation --locked --offline -j1 \
  -p dom-usdom-randomx-portable \
  dataset::tests::upstream_randomx_argon2d_cache_vector_matches -- \
  --exact --ignored --nocapture --test-threads=1)"

printf 'checkpointRunId=%s\nrandomxRunId=%s\n' "$checkpoint_id" "$randomx_id"
