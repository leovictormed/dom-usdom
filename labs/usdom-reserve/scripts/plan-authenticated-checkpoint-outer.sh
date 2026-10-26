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
SEGMENT_JOB_DIR="$LAB_ROOT/evidence/checkpoint-segment-proof-jobs"
SEGMENT_RECEIPT_DIR="$LAB_ROOT/evidence/checkpoint-segment-receipt-set"
OUTPUT_DIR="$LAB_ROOT/evidence/checkpoint-outer-proof-job"
SNAPSHOT_ROOT="$(mktemp -d "/dev/shm/usdom-outer-plan.XXXXXX")"
chmod 0700 "$SNAPSHOT_ROOT"
SNAPSHOT_LAB="$SNAPSHOT_ROOT/repository/labs/usdom-reserve"
trap 'rm -rf -- "$SNAPSHOT_ROOT"' EXIT HUP INT TERM
if (($# != 0)); then printf '%s\n' 'Usage: npm run --silent plan:authenticated-checkpoint-outer' >&2; exit 2; fi
for command in cargo cp jq mktemp node; do command -v "$command" >/dev/null; done
for tool_boundary_command in timeout stat realpath id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$LAB_ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node; pin_runtime_tool timeout
run_pinned_node_timed() { assert_runtime_tool node; assert_runtime_tool timeout; "$timeout_bin" --signal=TERM --kill-after=2s 120s "$node_bin" "$@"; }
run_pinned_timeout() { assert_runtime_tool timeout; "$timeout_bin" "$@"; }
for directory in "$SOURCE_DIR" "$RANDOMX_JOB_DIR" "$RANDOMX_RECEIPT_DIR" "$ECONOMIC_JOB_DIR" "$ECONOMIC_RECEIPT_DIR" "$SEGMENT_JOB_DIR" "$SEGMENT_RECEIPT_DIR"; do
  [[ -d "$directory" && ! -L "$directory" ]] || { printf 'Missing non-symlink outer-plan input directory: %s\n' "$directory" >&2; exit 1; }
done
for index in "$SOURCE_DIR/checkpoint-source-set-index.json" "$RANDOMX_JOB_DIR/randomx-proof-job-index.json" "$RANDOMX_RECEIPT_DIR/randomx-receipt-set-index.json" "$ECONOMIC_JOB_DIR/economic-proof-job-index.json" "$ECONOMIC_RECEIPT_DIR/economic-receipt-set-index.json" "$SEGMENT_JOB_DIR/checkpoint-segment-proof-job-index.json" "$SEGMENT_RECEIPT_DIR/checkpoint-segment-receipt-set-index.json"; do
  [[ -f "$index" && ! -L "$index" ]] || { printf 'Missing non-symlink outer-plan input index: %s\n' "$index" >&2; exit 1; }
done
mkdir -p -- "$OUTPUT_DIR"
[[ ! -L "$OUTPUT_DIR" ]] || { printf '%s\n' 'Checkpoint outer-job output directory cannot be a symlink' >&2; exit 1; }
snapshot_source="$SNAPSHOT_LAB/evidence/checkpoint-source-set"
snapshot_randomx_jobs="$SNAPSHOT_LAB/evidence/randomx-proof-jobs"
snapshot_randomx_receipts="$SNAPSHOT_LAB/evidence/randomx-receipt-set"
snapshot_economic_jobs="$SNAPSHOT_LAB/evidence/economic-proof-jobs"
snapshot_economic_receipts="$SNAPSHOT_LAB/evidence/economic-receipt-set"
snapshot_segment_jobs="$SNAPSHOT_LAB/evidence/checkpoint-segment-proof-jobs"
snapshot_segment_receipts="$SNAPSHOT_LAB/evidence/checkpoint-segment-receipt-set"
snapshot_output="$SNAPSHOT_LAB/evidence/checkpoint-outer-proof-job"
snapshot_segment_artifacts="$SNAPSHOT_ROOT/repository/crates/dom-usdom-checkpoint-segment-risc0-guest/elfs"
snapshot_outer_artifacts="$SNAPSHOT_ROOT/repository/crates/dom-usdom-checkpoint-outer-risc0-guest/elfs"
mkdir -p -- "$snapshot_source" "$snapshot_randomx_jobs" "$snapshot_randomx_receipts" "$snapshot_economic_jobs" "$snapshot_economic_receipts" "$snapshot_segment_jobs" "$snapshot_segment_receipts" "$snapshot_output" "$snapshot_segment_artifacts" "$snapshot_outer_artifacts"
chmod -R go-rwx -- "$SNAPSHOT_ROOT"
capture_private() {
  run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "${1}" > "${2}"
  chmod 0600 "${2}"
}
capture_private "$SOURCE_DIR/checkpoint-source-set-index.json" "$snapshot_source/checkpoint-source-set-index.json"
capture_private "$RANDOMX_JOB_DIR/randomx-proof-job-index.json" "$snapshot_randomx_jobs/randomx-proof-job-index.json"
capture_private "$RANDOMX_RECEIPT_DIR/randomx-receipt-set-index.json" "$snapshot_randomx_receipts/randomx-receipt-set-index.json"
capture_private "$ECONOMIC_JOB_DIR/economic-proof-job-index.json" "$snapshot_economic_jobs/economic-proof-job-index.json"
capture_private "$ECONOMIC_RECEIPT_DIR/economic-receipt-set-index.json" "$snapshot_economic_receipts/economic-receipt-set-index.json"
capture_private "$SEGMENT_JOB_DIR/checkpoint-segment-proof-job-index.json" "$snapshot_segment_jobs/checkpoint-segment-proof-job-index.json"
capture_private "$SEGMENT_RECEIPT_DIR/checkpoint-segment-receipt-set-index.json" "$snapshot_segment_receipts/checkpoint-segment-receipt-set-index.json"
mapfile -t source_files < <(jq -r '[.segments[] | .transition_file, .private_input_file, .policy_input_file, .native_state_opening_file] | unique | .[] | select(test("^checkpoint-segment-[0-9]{4}-(transition|private-input|policy-input|native-state-opening)\\.bin$"))' "$snapshot_source/checkpoint-source-set-index.json")
mapfile -t randomx_receipts < <(jq -r '[.receipts[].receipt_file] | select(length > 0 and length == (unique | length)) | .[] | select(test("^randomx-receipt-[0-9]{4}\\.bin$"))' "$snapshot_randomx_receipts/randomx-receipt-set-index.json")
mapfile -t economic_receipts < <(jq -r '[.block_receipts[].receipt_file] | select(length > 0 and length == (unique | length)) | .[] | select(test("^economic-block-receipt-[0-9]{4}\\.bin$"))' "$snapshot_economic_receipts/economic-receipt-set-index.json")
mapfile -t segment_receipts < <(jq -r '[.receipts[].receipt_file] | select(length > 0 and length == (unique | length) and all(.[]; type == "string" and test("^checkpoint-segment-receipt-[0-9]{4}\\.bin$"))) | .[]' "$snapshot_segment_receipts/checkpoint-segment-receipt-set-index.json")
if ((${#source_files[@]} == 0 || ${#randomx_receipts[@]} == 0 || ${#economic_receipts[@]} == 0 || ${#segment_receipts[@]} == 0)); then
  printf '%s\n' 'Checkpoint outer plan has an empty, duplicate or noncanonical input catalog' >&2; exit 1
fi
for name in "${source_files[@]}"; do capture_private "$SOURCE_DIR/$name" "$snapshot_source/$name"; done
for name in "${randomx_receipts[@]}"; do capture_private "$RANDOMX_RECEIPT_DIR/$name" "$snapshot_randomx_receipts/$name"; done
for name in "${economic_receipts[@]}"; do capture_private "$ECONOMIC_RECEIPT_DIR/$name" "$snapshot_economic_receipts/$name"; done
for name in "${segment_receipts[@]}"; do capture_private "$SEGMENT_RECEIPT_DIR/$name" "$snapshot_segment_receipts/$name"; done
for guest in checkpoint-segment checkpoint-outer; do
  artifact_source="$REPOSITORY_ROOT/crates/dom-usdom-${guest}-risc0-guest/elfs"
  if [[ $guest == checkpoint-segment ]]; then artifact_target="$snapshot_segment_artifacts"; artifact_name=usdom-checkpoint-segment; else artifact_target="$snapshot_outer_artifacts"; artifact_name=usdom-checkpoint-outer; fi
  for extension in elf bin iid; do
    name="${artifact_name}.${extension}"
    [[ -f "$artifact_source/$name" && ! -L "$artifact_source/$name" ]]
    cp --reflink=never --no-preserve=mode,ownership,timestamps -- "$artifact_source/$name" "$artifact_target/$name"
    chmod 0600 "$artifact_target/$name"
  done
done
cd "$SNAPSHOT_LAB"
run_pinned_timeout --signal=TERM --kill-after=30s 3600s \
  cargo run --quiet --release --locked --manifest-path "$REPOSITORY_ROOT/Cargo.toml" -p dom-usdom-checkpoint-proof-host --features verify --bin dom-usdom-plan-checkpoint-outer
# The job index is the completion marker for the statement and chain. Keep the
# prior generation live during planning, then invalidate it before publishing
# either new supporting artifact and reinstall it last.
run_pinned_node_timed \
  "$LAB_ROOT/scripts/remove-private-file-durable.mjs" \
  "$OUTPUT_DIR/checkpoint-outer-proof-job-index.json"
for name in checkpoint-statement-v6.bin checkpoint-outer-chain.bin checkpoint-outer-proof-job-index.json; do
  run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$snapshot_output/$name" | run_pinned_node_timed "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$OUTPUT_DIR/$name"
done
