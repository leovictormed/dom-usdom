#!/usr/bin/env bash
set -euo pipefail
for name in CARGO_HOME CARGO_TARGET_DIR CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER \
  CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_TARGET CARGO_ENCODED_RUSTFLAGS \
  CARGO_NET_GIT_FETCH_WITH_CLI RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER \
  RUSTFLAGS RUSTDOC RUSTDOCFLAGS LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT; do
  if [[ -v "$name" ]]; then
    printf 'unsafe environment survived: %s\n' "$name" >&2
    exit 91
  fi
done
printf 'dispatcher-clean-env-ok\n'
