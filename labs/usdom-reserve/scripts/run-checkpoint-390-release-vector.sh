#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
if [[ "${USDOM_RUN_LONG_RELEASE_TEST-}" != "YES" ]]; then
  echo 'refusing: set USDOM_RUN_LONG_RELEASE_TEST=YES for the mandatory 390-block release vector' >&2
  exit 64
fi
if [[ -n "${RUSTC_WRAPPER-}" || -n "${RUSTFLAGS-}" || -n "${CARGO_ENCODED_RUSTFLAGS-}" ]]; then
  echo 'refusing inherited Rust compiler overrides' >&2
  exit 64
fi

cd "$repo"
export DOM_REGTEST_FAST_MINING=1
export CARGO_INCREMENTAL=0
exec cargo test --profile release-validation --locked --offline -j1 \
  -p dom-usdom-checkpoint-program --features host-reference \
  --test v2_checkpoint_extension \
  full_360_plus_30_v2_checkpoint_extension_is_recomputed -- \
  --exact --ignored --nocapture --test-threads=1
