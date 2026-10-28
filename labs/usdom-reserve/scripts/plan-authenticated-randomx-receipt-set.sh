#!/usr/bin/env bash
set -euo pipefail
umask 077

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
STATEMENT_DIR="$LAB_ROOT/evidence/randomx-statement-set"
STATEMENT_INDEX="$STATEMENT_DIR/randomx-statement-set-index.json"
OUTPUT_DIR="$LAB_ROOT/evidence/randomx-proof-jobs"
SNAPSHOT_ROOT="$(mktemp -d "/dev/shm/usdom-randomx-plan.XXXXXX")"
chmod 0700 "$SNAPSHOT_ROOT"
SNAPSHOT_ROOT_IDENTITY=$(/usr/bin/stat -c '%u:%d:%i:%a' "$SNAPSHOT_ROOT")
SNAPSHOT_LAB="$SNAPSHOT_ROOT/repository/labs/usdom-reserve"
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
  printf '%s\n' 'Usage: npm run --silent plan:authenticated-randomx-receipt-set' >&2
  exit 2
fi
for command in cargo cp jq mktemp node; do command -v "$command" >/dev/null; done
for tool_boundary_command in timeout stat realpath id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$LAB_ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node; pin_runtime_tool timeout; pin_runtime_tool cargo; pin_runtime_tool jq
cargo() { assert_runtime_tool cargo; "$cargo_bin" "$@"; }
jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }
run_pinned_node_timed() { assert_runtime_tool node; assert_runtime_tool timeout; "$timeout_bin" --signal=TERM --kill-after=2s 120s "$node_bin" "$@"; }
run_pinned_timeout() { assert_runtime_tool timeout; "$timeout_bin" "$@"; }
if [[ ! -d "$STATEMENT_DIR" || -L "$STATEMENT_DIR" ]]; then
  printf 'Missing non-symlink RandomX statement-set directory: %s\n' "$STATEMENT_DIR" >&2
  exit 1
fi
if [[ ! -f "$STATEMENT_INDEX" || -L "$STATEMENT_INDEX" ]]; then
  printf 'Missing non-symlink RandomX statement-set index: %s\n' "$STATEMENT_INDEX" >&2
  exit 1
fi
mkdir -p -- "$OUTPUT_DIR"
if [[ -L "$OUTPUT_DIR" ]]; then
  printf '%s\n' 'RandomX proof-job output directory cannot be a symlink' >&2
  exit 1
fi

snapshot_statements="$SNAPSHOT_LAB/evidence/randomx-statement-set"
snapshot_jobs="$SNAPSHOT_LAB/evidence/randomx-proof-jobs"
snapshot_artifacts="$SNAPSHOT_ROOT/repository/crates/dom-usdom-randomx-risc0-guest/elfs"
mkdir -p -- "$snapshot_statements" "$snapshot_jobs" "$snapshot_artifacts"
chmod -R go-rwx -- "$SNAPSHOT_ROOT"
snapshot_index="$snapshot_statements/randomx-statement-set-index.json"
run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$STATEMENT_INDEX" > "$snapshot_index"
chmod 0600 "$snapshot_index"
mapfile -t statement_files < <(jq -er '
  select(.schema == "usdom-authenticated-randomx-statement-set-v1")
  | select(.statement_count == (.statements | length) and .statement_count > 0 and .statement_count <= 720)
  | [.statements[].statement_file]
  | select(length == (unique | length))
  | .[] | select(test("^randomx-statement-[0-9]{4}\\.bin$"))
' "$snapshot_index")
if ((${#statement_files[@]} == 0)); then
  printf '%s\n' 'RandomX statement-set index has no canonical statements' >&2
  exit 1
fi
for name in "${statement_files[@]}"; do
  run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$STATEMENT_DIR/$name" \
    > "$snapshot_statements/$name"
  chmod 0600 "$snapshot_statements/$name"
done
artifact_source="$REPOSITORY_ROOT/crates/dom-usdom-randomx-risc0-guest/elfs"
for name in usdom-randomx.elf usdom-randomx.bin usdom-randomx.iid; do
  [[ -f "$artifact_source/$name" && ! -L "$artifact_source/$name" ]]
  cp --reflink=never --no-preserve=mode,ownership,timestamps -- \
    "$artifact_source/$name" "$snapshot_artifacts/$name"
  chmod 0600 "$snapshot_artifacts/$name"
done

cd "$SNAPSHOT_LAB"
run_pinned_timeout --signal=TERM --kill-after=30s 3600s \
  cargo run --quiet --locked \
  --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-usdom-randomx-proof-host \
  --bin dom-usdom-plan-randomx-receipt-set

run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" \
  "$snapshot_jobs/randomx-proof-job-index.json" \
  | run_pinned_node_timed "$LAB_ROOT/scripts/install-private-file-stdin.mjs" \
    "$OUTPUT_DIR/randomx-proof-job-index.json"
