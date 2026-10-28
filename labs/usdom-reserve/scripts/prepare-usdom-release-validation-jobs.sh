#!/bin/bash
set -euo pipefail

if [[ "$#" -ne 3 || ! "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ \
      || ! "$2" =~ ^[0-9a-f]{40}$ \
      || ! "$3" =~ ^usdom-v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]; then
  echo 'usage: prepare-usdom-release-validation-jobs.sh RELEASE_ID SOURCE_COMMIT SOURCE_TAG' >&2
  exit 64
fi
release_id="$1"; source_commit="$2"; source_tag="$3"

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
  --env "USDOM_RELEASE_ID=${release_id}" --env "USDOM_SOURCE_COMMIT=${source_commit}"
  --env "USDOM_SOURCE_TAG=${source_tag}"
  --env CARGO_INCREMENTAL=0 --max-log-bytes 67108864 --min-free-bytes 21474836480
  --bind-input Cargo.toml --bind-input Cargo.lock --bind-input rust-toolchain.toml
  --bind-input labs/usdom-reserve/config/mainnet-toolchain-lock.json
  --bind-source-inventory labs/usdom-reserve/config/rebuild-v3-critical-source-inventory.json
)

checkpoint_id="$(/usr/bin/python3 "$preparer" "${common[@]}" \
  --max-runtime-seconds 43200 \
  --bind-input crates/dom-usdom-checkpoint-program/src/reference.rs \
  --bind-input crates/dom-usdom-checkpoint-program/src/lib.rs \
  --bind-input crates/dom-usdom-checkpoint-program/src/economic_chunks.rs \
  --bind-input crates/dom-usdom-checkpoint-program/src/outer.rs \
  --bind-input crates/dom-usdom-checkpoint-program/src/portable.rs \
  --bind-input crates/dom-usdom-checkpoint-program/src/source.rs \
  --bind-input crates/dom-usdom-checkpoint-program/src/sync_attestation.rs \
  --bind-input crates/dom-usdom-checkpoint-program/Cargo.toml \
  --bind-input crates/dom-usdom-checkpoint-program/tests/v2_checkpoint_extension.rs \
  --bind-input crates/dom-usdom-checkpoint-statement/Cargo.toml \
  --bind-input crates/dom-usdom-checkpoint-statement/src/lib.rs \
  --bind-input crates/dom-usdom-state/Cargo.toml \
  --bind-input crates/dom-usdom-state/src/lib.rs \
  --bind-input crates/dom-usdom-state/src/sparse.rs \
  --require-output 'test full_360_plus_30_v2_checkpoint_extension_is_recomputed ... ok' \
  --require-output 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;' -- \
  "$cargo_bin" test --profile release-validation --locked --offline -j1 \
  -p dom-usdom-checkpoint-program --features host-reference --test v2_checkpoint_extension \
  full_360_plus_30_v2_checkpoint_extension_is_recomputed -- \
  --exact --ignored --nocapture --test-threads=1)"

randomx_id="$(/usr/bin/python3 "$preparer" "${common[@]}" \
  --max-runtime-seconds 14400 \
  --bind-input crates/dom-usdom-randomx-portable/Cargo.toml \
  --bind-input crates/dom-usdom-randomx-portable/src/bytecode.rs \
  --bind-input crates/dom-usdom-randomx-portable/src/lib.rs \
  --bind-input crates/dom-usdom-randomx-portable/src/dataset.rs \
  --bind-input crates/dom-usdom-randomx-portable/src/superscalar.rs \
  --require-output 'test dataset::tests::upstream_randomx_argon2d_cache_vector_matches ... ok' \
  --require-output 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;' -- \
  "$cargo_bin" test --profile release-validation --locked --offline -j1 \
  -p dom-usdom-randomx-portable \
  dataset::tests::upstream_randomx_argon2d_cache_vector_matches -- \
  --exact --ignored --nocapture --test-threads=1)"

native_privacy_id="$(/usr/bin/python3 "$preparer" "${common[@]}" \
  --max-runtime-seconds 43200 \
  --bind-input crates/dom-usdom-privacy/Cargo.toml \
  --bind-input crates/dom-usdom-privacy/MANIFEST.sha256 \
  --bind-input crates/dom-usdom-privacy/src/lib.rs \
  --bind-input crates/dom-usdom-privacy/src/circuit.rs \
  --bind-input crates/dom-usdom-privacy/src/ceremony.rs \
  --bind-input crates/dom-usdom-privacy/src/phase1.rs \
  --bind-input crates/dom-usdom-privacy/src/verifier.rs \
  --require-output 'test phase1::tests::production_specialization_matches_real_prover_and_all_public_inputs ... ok' \
  --require-output 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;' -- \
  "$cargo_bin" test --profile release-validation --locked --offline -j1 \
  -p dom-usdom-privacy \
  phase1::tests::production_specialization_matches_real_prover_and_all_public_inputs -- \
  --exact --ignored --nocapture --test-threads=1)"

printf 'checkpointRunId=%s\nrandomxRunId=%s\nnativePrivacyRunId=%s\n' \
  "$checkpoint_id" "$randomx_id" "$native_privacy_id"
