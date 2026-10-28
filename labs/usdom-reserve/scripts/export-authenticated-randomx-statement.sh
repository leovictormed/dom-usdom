#!/usr/bin/env bash
set -euo pipefail
umask 077

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
for tool_boundary_command in stat realpath id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$LAB_ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node
node() { assert_runtime_tool node; "$node_bin" "$@"; }
pin_runtime_tool cargo
cargo() { assert_runtime_tool cargo; "$cargo_bin" "$@"; }
pin_runtime_tool timeout
timeout() { assert_runtime_tool timeout; "$timeout_bin" "$@"; }
SOURCE_DIR="$LAB_ROOT/evidence/randomx-source"
OUTPUT="$LAB_ROOT/evidence/randomx-canonical-statement.bin"
REPORT="$LAB_ROOT/evidence/randomx-canonical-statement-export.json"
SNAPSHOT_ROOT="$(mktemp -d "/dev/shm/usdom-randomx-statement.XXXXXX")"
chmod 0700 "$SNAPSHOT_ROOT"
SNAPSHOT_ROOT_IDENTITY=$(/usr/bin/stat -c '%u:%d:%i:%a' "$SNAPSHOT_ROOT")
cleanup_snapshot() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  if [[ $(/usr/bin/stat -c '%u:%d:%i:%a' "$SNAPSHOT_ROOT" 2>/dev/null) == "$SNAPSHOT_ROOT_IDENTITY" ]]; then
    /usr/bin/rm -rf -- "$SNAPSHOT_ROOT" || status=1
  else
    status=1
  fi
  exit "$status"
}
trap 'cleanup_snapshot $?' EXIT
trap 'cleanup_snapshot 129' HUP
trap 'cleanup_snapshot 130' INT
trap 'cleanup_snapshot 143' TERM

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent export:authenticated-randomx-statement' >&2
  exit 2
fi

mkdir -p -- "$SNAPSHOT_ROOT/evidence/randomx-source"
chmod 0700 "$SNAPSHOT_ROOT" "$SNAPSHOT_ROOT/evidence" "$SNAPSHOT_ROOT/evidence/randomx-source"
for name in \
  checkpoint-segment-transition.bin \
  checkpoint-segment-private-input.bin \
  checkpoint-segment-policy-input.bin \
  checkpoint-segment-native-state-opening.bin; do
  timeout --signal=TERM --kill-after=2s 120s node "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$SOURCE_DIR/$name" \
    > "$SNAPSHOT_ROOT/evidence/randomx-source/$name"
  chmod 0600 "$SNAPSHOT_ROOT/evidence/randomx-source/$name"
done

cd "$SNAPSHOT_ROOT"
timeout --signal=TERM --kill-after=30s 3600s \
  cargo run --quiet --locked \
  --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-usdom-checkpoint-program \
  --features host-reference \
  --bin dom-usdom-export-randomx-statement

# The JSON report is the completion marker for the statement. Preserve the old
# generation during export, then durably invalidate it before replacing bytes.
timeout --signal=TERM --kill-after=2s 120s node \
  "$LAB_ROOT/scripts/remove-private-file-durable.mjs" "$REPORT"
timeout --signal=TERM --kill-after=2s 120s node "$LAB_ROOT/scripts/read-private-file-stdout.mjs" \
  "$SNAPSHOT_ROOT/evidence/randomx-canonical-statement.bin" \
  | timeout --signal=TERM --kill-after=2s 120s node "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$OUTPUT"
timeout --signal=TERM --kill-after=2s 120s node "$LAB_ROOT/scripts/read-private-file-stdout.mjs" \
  "$SNAPSHOT_ROOT/evidence/randomx-canonical-statement-export.json" \
  | timeout --signal=TERM --kill-after=2s 120s node "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$REPORT"
