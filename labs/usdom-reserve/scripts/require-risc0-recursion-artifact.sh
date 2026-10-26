#!/usr/bin/env bash
# Source this file before invoking a RISC Zero prover.  The upstream build
# script otherwise downloads this input late in a release build, after a large
# amount of CPU time has already been spent.

USDOM_RISC0_RECURSION_SHA256=744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849
USDOM_RISC0_RECURSION_BYTES=59768781

require_risc0_recursion_artifact() {
  local default_path actual bytes
  default_path="${XDG_DATA_HOME:-$HOME/.local/share}/dom-usdom/toolchain/risc0-4.0.5/recursion_zkr.zip"
  RECURSION_SRC_PATH="${RECURSION_SRC_PATH:-$default_path}"

  if [[ "$RECURSION_SRC_PATH" != /* || ! -f "$RECURSION_SRC_PATH" || -L "$RECURSION_SRC_PATH" ]]; then
    printf 'Missing direct regular RISC Zero recursion artifact: %s\n' "$RECURSION_SRC_PATH" >&2
    return 1
  fi
  bytes=$(wc -c <"$RECURSION_SRC_PATH")
  if [[ "$bytes" != "$USDOM_RISC0_RECURSION_BYTES" ]]; then
    printf 'RISC Zero recursion artifact has %s bytes; expected %s: %s\n' \
      "$bytes" "$USDOM_RISC0_RECURSION_BYTES" "$RECURSION_SRC_PATH" >&2
    return 1
  fi
  actual=$(sha256sum "$RECURSION_SRC_PATH" | cut -d ' ' -f 1)
  if [[ "$actual" != "$USDOM_RISC0_RECURSION_SHA256" ]]; then
    printf 'RISC Zero recursion artifact SHA-256 mismatch: %s\n' "$RECURSION_SRC_PATH" >&2
    return 1
  fi
  export RECURSION_SRC_PATH
}
