#!/usr/bin/env bash
set -euo pipefail

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
WORK_ROOT="$(mktemp -d /dev/shm/usdom-finalized-burn-handoff.XXXXXXXX)"
chmod 0700 -- "$WORK_ROOT"

cleanup() {
  if [[ -d "$WORK_ROOT" && "$WORK_ROOT" == /dev/shm/usdom-finalized-burn-handoff.* ]]; then
    chmod -R u+w -- "$WORK_ROOT" 2>/dev/null || true
    find "$WORK_ROOT" -depth -delete
  fi
}
trap cleanup EXIT HUP INT TERM

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent check:finalized-burn-planner-handoff' >&2
  exit 2
fi

TEMP_LAB="$WORK_ROOT/labs/usdom-reserve"
SOURCE_DIR="$TEMP_LAB/evidence/finalized-burn-source"
JOB_DIR="$TEMP_LAB/evidence/finalized-burn-proof-job"
TEMP_GUEST_DIR="$TEMP_LAB/evidence/finalized-burn-guest"
SOURCE_FILE="$SOURCE_DIR/finalized-burn-input.bin"
INDEX_FILE="$JOB_DIR/finalized-burn-proof-job-index.json"
COPIED_INPUT="$JOB_DIR/finalized-burn-input.bin"
PLANNER_LOG="$WORK_ROOT/planner.log"
VECTOR_LOG="$WORK_ROOT/vector.log"

mkdir -p -- "$SOURCE_DIR" "$JOB_DIR" "$TEMP_GUEST_DIR"
cp -- "$REPOSITORY_ROOT/crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.elf" \
  "$TEMP_GUEST_DIR/usdom-finalized-burn.elf"
cp -- "$REPOSITORY_ROOT/crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.iid" \
  "$TEMP_GUEST_DIR/usdom-finalized-burn.iid"

cd "$REPOSITORY_ROOT"
if ! USDOM_RAW_CHECKPOINT_VECTOR_OUT="$SOURCE_FILE" cargo test --quiet --locked \
  -p dom-usdom-finalized-burn-program \
  --test raw_checkpoint_positive \
  raw_ethereum_checkpoint_executes_udfinl04_end_to_end -- --exact >"$VECTOR_LOG" 2>&1; then
  cat -- "$VECTOR_LOG" >&2
  exit 1
fi

test "$(wc -c < "$SOURCE_FILE")" -eq 64782
test "$(sha256sum -- "$SOURCE_FILE" | cut -d ' ' -f 1)" = \
  'bdcd115207f47fd31e6e7b211ad2e2812ea7c5fa22fa4310ffae9b4cce949f5e'

cd "$TEMP_LAB"
if ! cargo run --quiet --release --locked --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-usdom-finalized-burn-proof-host \
  --bin dom-usdom-plan-finalized-burn-proof >"$PLANNER_LOG" 2>&1; then
  cat -- "$PLANNER_LOG" >&2
  exit 1
fi

cmp -s -- "$SOURCE_FILE" "$COPIED_INPUT"
test ! -e "$JOB_DIR/finalized-burn-receipt.bin"
test "$(sed -n 's/^statement_hash: //p' "$PLANNER_LOG")" = \
  'c0461e1c2bcff62d1dfd8e8fed0b094b5d19c2744cf9bad34c8ae3722e7eaef4'
test "$(sed -n 's/^input_sha256: //p' "$PLANNER_LOG")" = \
  'bdcd115207f47fd31e6e7b211ad2e2812ea7c5fa22fa4310ffae9b4cce949f5e'
test "$(sed -n 's/^job_index_sha256: //p' "$PLANNER_LOG")" = \
  "$(sha256sum -- "$INDEX_FILE" | cut -d ' ' -f 1)"

jq -e '
  .schema == "usdom-finalized-burn-proof-job-v1"
  and .source_input_path == "evidence/finalized-burn-source/finalized-burn-input.bin"
  and .source_input_sha256 == "bdcd115207f47fd31e6e7b211ad2e2812ea7c5fa22fa4310ffae9b4cce949f5e"
  and .input_file == "finalized-burn-input.bin"
  and .input_sha256 == .source_input_sha256
  and .input_bytes == 64782
  and .statement_hash == "c0461e1c2bcff62d1dfd8e8fed0b094b5d19c2744cf9bad34c8ae3722e7eaef4"
  and .program_sha256 == "883ec39b03e3a0703e592026fc7d92a15ce7d949cb937551c5dd8360184cde21"
  and .image_id_file_sha256 == "5c07a37b10235eb0b42c667408ff4f890cb9273d8e68d0f70a04e8e697677103"
  and .image_id == "2e26f74497b54b680dfff4c116d56280d016f01d0125329f49bf6d744b1c18ea"
  and .risc0_zkvm_version == "3.0.6"
  and .receipt_kind == "succinct"
  and .relation_executed == true
  and .generates_proofs == false
  and .mines == false
  and .receipt_file == "finalized-burn-receipt.bin"
' "$INDEX_FILE" >/dev/null

printf '%s\n' \
  'PASS: canonical UDFINL04 source-to-planner handoff is hash-bound, non-proving and temporary'
