#!/usr/bin/env bash
set -euo pipefail
set +x
unset BASH_XTRACEFD 2>/dev/null || true
if ! ulimit -c 0; then
  printf '%s\n' 'Cannot disable core dumps for private witness construction.' >&2
  exit 1
fi
# This noninteractive evidence builder must not inherit caller-owned input,
# evidence, lock or logging descriptors.
exec </dev/null
for fd_path in /proc/$$/fd/*; do
  inherited_fd=${fd_path##*/}
  [[ "$inherited_fd" =~ ^[0-9]+$ ]] || exit 1
  ((inherited_fd > 2)) || continue
  [[ "$inherited_fd" == 255 ]] && continue
  exec {inherited_fd}>&-
done
# Prevent ambient loader/toolchain/proxy/debug settings from changing children
# that receive wallet, TPM, bearer or witness inputs.
unset LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
  NODE_OPTIONS NODE_PATH NODE_DEBUG NODE_DEBUG_NATIVE SSLKEYLOGFILE \
  RUST_LOG RUSTFLAGS RUSTC_WRAPPER CARGO_BUILD_RUSTC_WRAPPER \
  CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR CARGO_BUILD_TARGET \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
for inherited_name in ${!FOUNDRY_@} ${!CAST_@}; do unset "$inherited_name"; done

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent build:finalized-deposit-witness' >&2
  exit 2
fi

LAB_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
REPOSITORY_ROOT=$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)
for tool_boundary_command in stat realpath id dirname sha256sum cut timeout; do command -v "$tool_boundary_command" >/dev/null; done
source "$LAB_ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool timeout
run_pinned_timeout() { assert_runtime_tool timeout; "$timeout_bin" "$@"; }
pin_runtime_tool cargo
cargo() { assert_runtime_tool cargo; "$cargo_bin" "$@"; }
RUNTIME_ROOT="$LAB_ROOT/evidence/native-runtime"
MANIFEST="$RUNTIME_ROOT/native-usdom-v2.json"
MANIFEST_PIN="$RUNTIME_ROOT/native-usdom-v2.manifest.sha256"
SOURCE="$LAB_ROOT/evidence/finalized-deposit-source/finalized-deposit-source.json"
OUTPUT_DIR="$LAB_ROOT/evidence/finalized-deposit-witness"

for command in node realpath stat dirname sha256sum cut id timeout; do command -v "$command" >/dev/null; done
NODE_BIN=$(realpath "$(command -v node)")
test -x "$NODE_BIN"; test -f "$NODE_BIN"; test ! -L "$NODE_BIN"
node_owner=$(stat -Lc '%u' "$NODE_BIN"); test "$node_owner" = 0 || test "$node_owner" = "$(id -u)"
test "$(stat -Lc '%h' "$NODE_BIN")" = 1
node_size=$(stat -Lc '%s' "$NODE_BIN"); (( node_size > 0 && node_size <= 512 * 1024 * 1024 ))
node_mode=$(stat -Lc '%a' "$NODE_BIN"); (( (8#$node_mode & 8#022) == 0 ))
node_directory=$(dirname "$NODE_BIN")
test "$(realpath "$node_directory")" = "$node_directory"
node_directory_owner=$(stat -Lc '%u' "$node_directory"); test "$node_directory_owner" = 0 || test "$node_directory_owner" = "$(id -u)"
node_directory_mode=$(stat -Lc '%a' "$node_directory"); (( (8#$node_directory_mode & 8#022) == 0 ))
node_directory_identity=$(stat -Lc '%d:%i:%u:%a' "$node_directory")
node_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$NODE_BIN")
node_sha256=$(sha256sum "$NODE_BIN" | cut -d ' ' -f 1)
test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$NODE_BIN")" = "$node_identity"
test "$(stat -Lc '%d:%i:%u:%a' "$node_directory")" = "$node_directory_identity"
assert_node_unchanged() {
  test "$(realpath "$(command -v node)")" = "$NODE_BIN"
  test "$(realpath "$node_directory")" = "$node_directory"
  test "$(stat -Lc '%d:%i:%u:%a' "$node_directory")" = "$node_directory_identity"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$NODE_BIN")" = "$node_identity"
  test "$(sha256sum "$NODE_BIN" | cut -d ' ' -f 1)" = "$node_sha256"
  test "$(stat -Lc '%d:%i:%s:%Y:%Z' "$NODE_BIN")" = "$node_identity"
  test "$(stat -Lc '%d:%i:%u:%a' "$node_directory")" = "$node_directory_identity"
}

for required in "$MANIFEST" "$MANIFEST_PIN" "$SOURCE"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    printf 'Missing direct regular file: %s\n' "$required" >&2
    exit 1
  fi
done
SNAPSHOT_DIRECTORY=$(mktemp -d -p /dev/shm usdom-deposit-witness.XXXXXXXX)
chmod 0700 -- "$SNAPSHOT_DIRECTORY"
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  if [[ "$SNAPSHOT_DIRECTORY" == /dev/shm/usdom-deposit-witness.* \
    && -d "$SNAPSHOT_DIRECTORY" && ! -L "$SNAPSHOT_DIRECTORY" ]]; then
    if assert_node_unchanged &&
      run_pinned_timeout --foreground --signal=TERM --kill-after=5s 30s \
        "$NODE_BIN" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' \
        "$SNAPSHOT_DIRECTORY" > /dev/null 2> /dev/null &&
      assert_node_unchanged && assert_runtime_tool timeout && test ! -e "$SNAPSHOT_DIRECTORY"; then
      :
    else
      status=1
    fi
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
assert_node_unchanged
"$NODE_BIN" "$LAB_ROOT/scripts/read-release-config-file-stdout.mjs" "$MANIFEST" \
  > "$SNAPSHOT_DIRECTORY/native-usdom-v2.json"
assert_node_unchanged
"$NODE_BIN" "$LAB_ROOT/scripts/read-release-config-file-stdout.mjs" "$MANIFEST_PIN" \
  > "$SNAPSHOT_DIRECTORY/native-usdom-v2.manifest.sha256"
assert_node_unchanged
"$NODE_BIN" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$SOURCE" \
  > "$SNAPSHOT_DIRECTORY/finalized-deposit-source.json"
chmod 0600 -- "$SNAPSHOT_DIRECTORY"/*
MANIFEST="$SNAPSHOT_DIRECTORY/native-usdom-v2.json"
MANIFEST_PIN="$SNAPSHOT_DIRECTORY/native-usdom-v2.manifest.sha256"
SOURCE="$SNAPSHOT_DIRECTORY/finalized-deposit-source.json"
mkdir -p -- "$OUTPUT_DIR"
if [[ ! -d "$OUTPUT_DIR" || -L "$OUTPUT_DIR" ]]; then
  printf '%s\n' 'Witness output must be a direct directory.' >&2
  exit 1
fi
IFS= read -r manifest_sha256 < "$MANIFEST_PIN"
if [[ ! "$manifest_sha256" =~ ^[0-9a-f]{64}$ ]] \
  || [[ $(wc -l < "$MANIFEST_PIN") -ne 1 ]] \
  || [[ $(sha256sum -- "$MANIFEST" | cut -d ' ' -f 1) != "$manifest_sha256" ]]; then
  printf '%s\n' 'Native runtime manifest does not match its exact SHA-256 pin.' >&2
  exit 1
fi

cd "$REPOSITORY_ROOT"
timeout --signal=TERM --kill-after=30s 3600s cargo run --quiet --release --locked -p dom-node \
  --features native-usdom-v4-poc \
  --bin dom-usdom-build-finalized-deposit-witness -- \
  --manifest-file "$MANIFEST" \
  --manifest-sha256 "$manifest_sha256" \
  --source-file "$SOURCE" \
  --output-dir "$OUTPUT_DIR" \
  --network mainnet
