#!/usr/bin/env bash
set -euo pipefail
umask 077

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
SOURCE_DIR="$LAB_ROOT/evidence/checkpoint-source-set"
RANDOMX_JOB_DIR="$LAB_ROOT/evidence/randomx-proof-jobs"
RANDOMX_RECEIPT_DIR="$LAB_ROOT/evidence/randomx-receipt-set"
ECONOMIC_JOB_DIR="$LAB_ROOT/evidence/economic-proof-jobs"
ECONOMIC_RECEIPT_DIR="$LAB_ROOT/evidence/economic-receipt-set"
OUTPUT_DIR="$LAB_ROOT/evidence/checkpoint-segment-proof-jobs"
SNAPSHOT_ROOT="$(mktemp -d "/dev/shm/usdom-segment-plan.XXXXXX")"
chmod 0700 "$SNAPSHOT_ROOT"
SNAPSHOT_LAB="$SNAPSHOT_ROOT/repository/labs/usdom-reserve"
trap 'rm -rf -- "$SNAPSHOT_ROOT"' EXIT HUP INT TERM

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent plan:authenticated-checkpoint-segment-set' >&2
  exit 2
fi
for command in cargo cp jq mktemp node; do command -v "$command" >/dev/null; done
for tool_boundary_command in timeout stat realpath id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$LAB_ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node; pin_runtime_tool timeout
run_pinned_node_timed() { assert_runtime_tool node; assert_runtime_tool timeout; "$timeout_bin" --signal=TERM --kill-after=2s 120s "$node_bin" "$@"; }
run_pinned_timeout() { assert_runtime_tool timeout; "$timeout_bin" "$@"; }
for directory in \
  "$SOURCE_DIR" "$RANDOMX_JOB_DIR" "$RANDOMX_RECEIPT_DIR" \
  "$ECONOMIC_JOB_DIR" "$ECONOMIC_RECEIPT_DIR"; do
  if [[ ! -d "$directory" || -L "$directory" ]]; then
    printf 'Missing non-symlink segment-plan input directory: %s\n' "$directory" >&2
    exit 1
  fi
done
for index in \
  "$SOURCE_DIR/checkpoint-source-set-index.json" \
  "$RANDOMX_JOB_DIR/randomx-proof-job-index.json" \
  "$RANDOMX_RECEIPT_DIR/randomx-receipt-set-index.json" \
  "$ECONOMIC_JOB_DIR/economic-proof-job-index.json" \
  "$ECONOMIC_RECEIPT_DIR/economic-receipt-set-index.json"; do
  if [[ ! -f "$index" || -L "$index" ]]; then
    printf 'Missing non-symlink segment-plan input index: %s\n' "$index" >&2
    exit 1
  fi
done
mkdir -p -- "$OUTPUT_DIR"
if [[ -L "$OUTPUT_DIR" ]]; then
  printf '%s\n' 'Checkpoint segment-job output directory cannot be a symlink' >&2
  exit 1
fi

snapshot_source="$SNAPSHOT_LAB/evidence/checkpoint-source-set"
snapshot_randomx_jobs="$SNAPSHOT_LAB/evidence/randomx-proof-jobs"
snapshot_randomx_receipts="$SNAPSHOT_LAB/evidence/randomx-receipt-set"
snapshot_economic_jobs="$SNAPSHOT_LAB/evidence/economic-proof-jobs"
snapshot_economic_receipts="$SNAPSHOT_LAB/evidence/economic-receipt-set"
snapshot_output="$SNAPSHOT_LAB/evidence/checkpoint-segment-proof-jobs"
snapshot_artifacts="$SNAPSHOT_ROOT/repository/crates/dom-usdom-checkpoint-segment-risc0-guest/elfs"
mkdir -p -- "$snapshot_source" "$snapshot_randomx_jobs" "$snapshot_randomx_receipts" \
  "$snapshot_economic_jobs" "$snapshot_economic_receipts" "$snapshot_output" "$snapshot_artifacts"
chmod -R go-rwx -- "$SNAPSHOT_ROOT"
run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$SOURCE_DIR/checkpoint-source-set-index.json" > "$snapshot_source/checkpoint-source-set-index.json"
run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$RANDOMX_JOB_DIR/randomx-proof-job-index.json" > "$snapshot_randomx_jobs/randomx-proof-job-index.json"
run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$RANDOMX_RECEIPT_DIR/randomx-receipt-set-index.json" > "$snapshot_randomx_receipts/randomx-receipt-set-index.json"
run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$ECONOMIC_JOB_DIR/economic-proof-job-index.json" > "$snapshot_economic_jobs/economic-proof-job-index.json"
run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$ECONOMIC_RECEIPT_DIR/economic-receipt-set-index.json" > "$snapshot_economic_receipts/economic-receipt-set-index.json"
chmod 0600 "$snapshot_source/checkpoint-source-set-index.json" \
  "$snapshot_randomx_jobs/randomx-proof-job-index.json" \
  "$snapshot_randomx_receipts/randomx-receipt-set-index.json" \
  "$snapshot_economic_jobs/economic-proof-job-index.json" \
  "$snapshot_economic_receipts/economic-receipt-set-index.json"
mapfile -t source_files < <(jq -r '
  [.segments[] | .transition_file, .private_input_file, .policy_input_file, .native_state_opening_file]
  | unique | .[] | select(test("^checkpoint-segment-[0-9]{4}-(transition|private-input|policy-input|native-state-opening)\\.bin$"))
' "$snapshot_source/checkpoint-source-set-index.json")
mapfile -t randomx_receipts < <(jq -r '
  [.receipts[].receipt_file] | select(length > 0 and length == (unique | length))
  | .[] | select(test("^randomx-receipt-[0-9]{4}\\.bin$"))
' "$snapshot_randomx_receipts/randomx-receipt-set-index.json")
mapfile -t economic_receipts < <(jq -r '
  [.block_receipts[].receipt_file] | select(length > 0 and length == (unique | length))
  | .[] | select(test("^economic-block-receipt-[0-9]{4}\\.bin$"))
' "$snapshot_economic_receipts/economic-receipt-set-index.json")
if ((${#source_files[@]} == 0 || ${#randomx_receipts[@]} == 0 || ${#economic_receipts[@]} == 0)); then
  printf '%s\n' 'Checkpoint segment plan has an empty or noncanonical input catalog' >&2
  exit 1
fi
for name in "${source_files[@]}"; do
  run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$SOURCE_DIR/$name" > "$snapshot_source/$name"
  chmod 0600 "$snapshot_source/$name"
done
for name in "${randomx_receipts[@]}"; do
  run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$RANDOMX_RECEIPT_DIR/$name" > "$snapshot_randomx_receipts/$name"
  chmod 0600 "$snapshot_randomx_receipts/$name"
done
for name in "${economic_receipts[@]}"; do
  run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$ECONOMIC_RECEIPT_DIR/$name" > "$snapshot_economic_receipts/$name"
  chmod 0600 "$snapshot_economic_receipts/$name"
done
artifact_source="$REPOSITORY_ROOT/crates/dom-usdom-checkpoint-segment-risc0-guest/elfs"
for extension in elf bin iid; do
  name="usdom-checkpoint-segment.${extension}"
  [[ -f "$artifact_source/$name" && ! -L "$artifact_source/$name" ]]
  cp --reflink=never --no-preserve=mode,ownership,timestamps -- "$artifact_source/$name" "$snapshot_artifacts/$name"
  chmod 0600 "$snapshot_artifacts/$name"
done

cd "$SNAPSHOT_LAB"
run_pinned_timeout --signal=TERM --kill-after=30s 3600s \
  cargo run --quiet --release --locked \
  --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-usdom-checkpoint-proof-host \
  --features verify \
  --bin dom-usdom-plan-checkpoint-segment-set

run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" \
  "$snapshot_output/checkpoint-segment-proof-job-index.json" \
  | run_pinned_node_timed "$LAB_ROOT/scripts/install-private-file-stdin.mjs" \
    "$OUTPUT_DIR/checkpoint-segment-proof-job-index.json"
