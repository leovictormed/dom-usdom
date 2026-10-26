#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
if [[ "${USDOM_RUN_LONG_RELEASE_TEST-}" != "YES" ]]; then
  echo 'refusing: set USDOM_RUN_LONG_RELEASE_TEST=YES for the mandatory RandomX cache release vector' >&2
  exit 64
fi
if [[ -n "${RUSTC_WRAPPER-}" || -n "${RUSTFLAGS-}" || -n "${CARGO_ENCODED_RUSTFLAGS-}" ]]; then
  echo 'refusing inherited Rust compiler overrides' >&2
  exit 64
fi

cd "$repo"
export CARGO_INCREMENTAL=0
exec cargo test --profile release-validation --locked --offline -j1 \
  -p dom-usdom-randomx-portable \
  dataset::tests::upstream_randomx_argon2d_cache_vector_matches -- \
  --exact --ignored --nocapture --test-threads=1
