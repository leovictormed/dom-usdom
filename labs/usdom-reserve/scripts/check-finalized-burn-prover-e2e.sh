#!/usr/bin/env bash
set -euo pipefail
umask 077

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
source "$LAB_ROOT/scripts/require-risc0-recursion-artifact.sh"

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent check:finalized-burn-prover-e2e' >&2
  exit 2
fi
if [[ -z "${HOME:-}" ]]; then
  printf '%s\n' 'HOME is required for durable prover diagnostics.' >&2
  exit 1
fi
if [[ "$HOME" != /* || ! -d "$HOME" || -L "$HOME" \
  || $(stat -c '%u' "$HOME") != "$(id -u)" ]]; then
  printf '%s\n' 'HOME must be a current-user direct directory.' >&2
  exit 1
fi

ensure_owned_directory() {
  local path="$1"
  local create_mode="$2"
  local require_private="$3"
  if [[ -e "$path" || -L "$path" ]]; then
    if [[ ! -d "$path" || -L "$path" || $(stat -c '%u' "$path") != "$(id -u)" ]]; then
      printf 'Unsafe durable prover directory: %s\n' "$path" >&2
      exit 1
    fi
  else
    mkdir -m "$create_mode" -- "$path"
  fi
  if [[ "$require_private" == true ]]; then
    local path_mode
    path_mode="$(stat -c '%a' "$path")"
    if ((8#$path_mode & 077)); then
      printf 'Durable prover directory must deny group/other access: %s\n' "$path" >&2
      exit 1
    fi
  fi
}

ensure_owned_directory "$HOME/.local" 700 false
ensure_owned_directory "$HOME/.local/share" 700 false
ensure_owned_directory "$HOME/.local/share/dom-usdom" 700 true
ensure_owned_directory "$HOME/.local/share/dom-usdom/prover-capacity" 700 true
ARTIFACT_ROOT="$HOME/.local/share/dom-usdom/prover-capacity/finalized-burn"
RUNS_ROOT="$ARTIFACT_ROOT/runs"
CACHE_ROOT="$ARTIFACT_ROOT/cache"
ensure_owned_directory "$ARTIFACT_ROOT" 700 true
ensure_owned_directory "$RUNS_ROOT" 700 true
ensure_owned_directory "$CACHE_ROOT" 700 true

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
RUN_ROOT="$RUNS_ROOT/$RUN_ID"
mkdir -m 700 -- "$RUN_ROOT"
WORK_ROOT="$(mktemp -d /dev/shm/usdom-finalized-burn-proof.XXXXXXXX)"
chmod 0700 -- "$WORK_ROOT"
RUN_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ONE_WORKER_MIN_AVAILABLE_KIB=$((3 * 1024 * 1024))
TWO_WORKER_MIN_AVAILABLE_KIB=$((4 * 1024 * 1024))
RAYON_WORKERS=0
CACHE_LOADED=false

select_rayon_workers() {
  local available_kib online_cpus
  available_kib="$(awk '$1 == "MemAvailable:" { print $2 }' /proc/meminfo)"
  online_cpus="$(getconf _NPROCESSORS_ONLN)"
  if [[ ! "$available_kib" =~ ^[0-9]+$ || ! "$online_cpus" =~ ^[0-9]+$ \
    || "$online_cpus" -lt 1 || "$available_kib" -lt "$ONE_WORKER_MIN_AVAILABLE_KIB" ]]; then
    printf '%s\n' 'At least one CPU and 3 GiB of available RAM are required for the local prover.' >&2
    return 1
  fi
  if ((online_cpus >= 2 && available_kib >= TWO_WORKER_MIN_AVAILABLE_KIB)); then
    printf '%s\n' 2
  else
    printf '%s\n' 1
  fi
}

write_run_status() {
  local status="$1"
  local exit_status="$2"
  local temporary="$RUN_ROOT/.run-status.json.tmp"
  jq -n \
    --arg status "$status" \
    --arg run_id "$RUN_ID" \
    --arg started_at "$RUN_STARTED_AT" \
    --arg recorded_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson rayon_workers "$RAYON_WORKERS" \
    --argjson exit_status "$exit_status" \
    '{schema:"usdom-finalized-burn-prover-run-v1",status:$status,
      runId:$run_id,exitStatus:$exit_status,rayonWorkers:$rayon_workers,segmentLimitPo2:18,
      prover:"local",devMode:false,receiptKind:"succinct",
      startedAt:$started_at,recordedAt:$recorded_at}' \
    > "$temporary"
  chmod 600 -- "$temporary"
  # A rename is atomic but not power-loss durable. Persist the complete status
  # bytes before publishing the name, then persist the directory entry.
  sync -f "$temporary"
  mv -f -- "$temporary" "$RUN_ROOT/run-status.json"
  sync -f "$RUN_ROOT"
}

cleanup() {
  if [[ -d "$WORK_ROOT" && "$WORK_ROOT" == /dev/shm/usdom-finalized-burn-proof.* ]]; then
    chmod -R u+w -- "$WORK_ROOT" 2>/dev/null || true
    find "$WORK_ROOT" -depth -delete
  fi
}

atomic_copy_to() {
  local source="$1"
  local destination="$2"
  local temporary="$destination.tmp"
  cp -- "$source" "$temporary"
  chmod 600 -- "$temporary"
  sync -f "$temporary"
  mv -f -- "$temporary" "$destination"
  sync -f "$(dirname -- "$destination")"
}

copy_artifact() {
  local source="$1"
  atomic_copy_to "$source" "$RUN_ROOT/$(basename -- "$source")"
}

finalize_run() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  for log in vector.log planner.log prover.log time.log; do
    if [[ -f "$WORK_ROOT/$log" && ! -L "$WORK_ROOT/$log" ]]; then
      copy_artifact "$WORK_ROOT/$log"
    fi
  done
  local temporary_composite="$WORK_ROOT/labs/usdom-reserve/evidence/finalized-burn-receipt/finalized-burn-composite-receipt.bin"
  local cached_composite="$CACHE_ROOT/finalized-burn-composite-receipt.bin"
  if [[ -f "$temporary_composite" && ! -L "$temporary_composite" ]]; then
    atomic_copy_to "$temporary_composite" "$cached_composite"
    sync -f "$CACHE_ROOT" 2>/dev/null || true
  elif [[ "$CACHE_LOADED" == true && ( -e "$cached_composite" || -L "$cached_composite" ) ]]; then
    rm -f -- "$cached_composite"
    sync -f "$CACHE_ROOT" 2>/dev/null || true
  fi
  if ((status == 0)); then
    for artifact in \
      "$WORK_ROOT/labs/usdom-reserve/evidence/finalized-burn-receipt/finalized-burn-receipt.bin" \
      "$WORK_ROOT/labs/usdom-reserve/evidence/finalized-burn-receipt/finalized-burn-receipt-index.json"; do
      if [[ -f "$artifact" && ! -L "$artifact" ]]; then
        copy_artifact "$artifact"
      fi
    done
    write_run_status succeeded 0
  else
    write_run_status failed "$status"
  fi
  sync -f "$RUN_ROOT" 2>/dev/null || true
  cleanup
  exit "$status"
}

trap finalize_run EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if ! selected_workers="$(select_rayon_workers)"; then
  exit 1
fi
RAYON_WORKERS="$selected_workers"
write_run_status running 0

TEMP_LAB="$WORK_ROOT/labs/usdom-reserve"
SOURCE_DIR="$TEMP_LAB/evidence/finalized-burn-source"
JOB_DIR="$TEMP_LAB/evidence/finalized-burn-proof-job"
RECEIPT_DIR="$TEMP_LAB/evidence/finalized-burn-receipt"
CHECKPOINT_RECEIPT_DIR="$TEMP_LAB/evidence/checkpoint-outer-receipt-set"
TEMP_GUEST_DIR="$TEMP_LAB/evidence/finalized-burn-guest"
SOURCE_FILE="$SOURCE_DIR/finalized-burn-input.bin"
JOB_INDEX="$JOB_DIR/finalized-burn-proof-job-index.json"
RECEIPT_FILE="$RECEIPT_DIR/finalized-burn-receipt.bin"
RECEIPT_INDEX="$RECEIPT_DIR/finalized-burn-receipt-index.json"
VECTOR_LOG="$WORK_ROOT/vector.log"
PLANNER_LOG="$WORK_ROOT/planner.log"
PROVER_LOG="$WORK_ROOT/prover.log"
TIME_LOG="$WORK_ROOT/time.log"
CACHED_COMPOSITE="$CACHE_ROOT/finalized-burn-composite-receipt.bin"
TEMP_COMPOSITE="$RECEIPT_DIR/finalized-burn-composite-receipt.bin"

mkdir -p -- "$SOURCE_DIR" "$JOB_DIR" "$RECEIPT_DIR" "$CHECKPOINT_RECEIPT_DIR" "$TEMP_GUEST_DIR"
if [[ -e "$CACHED_COMPOSITE" || -L "$CACHED_COMPOSITE" ]]; then
  if [[ ! -f "$CACHED_COMPOSITE" || -L "$CACHED_COMPOSITE" \
    || $(stat -c '%u' "$CACHED_COMPOSITE") != "$(id -u)" \
    || $(stat -c '%a' "$CACHED_COMPOSITE") != 600 \
    || $(stat -c '%s' "$CACHED_COMPOSITE") -le 0 \
    || $(stat -c '%s' "$CACHED_COMPOSITE") -gt $((512 * 1024 * 1024)) ]]; then
    printf '%s\n' 'Cached composite receipt is not a direct owner-only bounded file.' >&2
    exit 1
  fi
  cp -- "$CACHED_COMPOSITE" "$TEMP_COMPOSITE"
  chmod 600 -- "$TEMP_COMPOSITE"
  CACHE_LOADED=true
fi
cp -- "$REPOSITORY_ROOT/crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.elf" \
  "$TEMP_GUEST_DIR/usdom-finalized-burn.elf"
cp -- "$REPOSITORY_ROOT/crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.iid" \
  "$TEMP_GUEST_DIR/usdom-finalized-burn.iid"

cd "$REPOSITORY_ROOT"
if ! CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true \
  USDOM_RAW_CHECKPOINT_VECTOR_OUT="$SOURCE_FILE" cargo test --quiet --release --locked \
  -p dom-usdom-finalized-burn-program \
  --test raw_checkpoint_positive \
  raw_ethereum_checkpoint_executes_udfinl04_end_to_end -- --exact >"$VECTOR_LOG" 2>&1; then
  cat -- "$VECTOR_LOG" >&2
  exit 1
fi

CHECKPOINT_RECEIPT_SOURCE="$LAB_ROOT/evidence/checkpoint-outer-receipt-set/checkpoint-outer-receipt.bin"
if [[ ! -f "$CHECKPOINT_RECEIPT_SOURCE" || -L "$CHECKPOINT_RECEIPT_SOURCE" ]]; then
  printf '%s\n' 'A direct checkpoint-outer receipt is required for recursive UDFINL04 proving.' >&2
  exit 1
fi
cp -- "$CHECKPOINT_RECEIPT_SOURCE" "$CHECKPOINT_RECEIPT_DIR/checkpoint-outer-receipt.bin"
chmod 600 -- "$CHECKPOINT_RECEIPT_DIR/checkpoint-outer-receipt.bin"

test "$(wc -c < "$SOURCE_FILE")" -eq 64782
test "$(sha256sum -- "$SOURCE_FILE" | cut -d ' ' -f 1)" = \
  'bdcd115207f47fd31e6e7b211ad2e2812ea7c5fa22fa4310ffae9b4cce949f5e'

require_risc0_recursion_artifact
cd "$TEMP_LAB"
if ! cargo run --quiet --release --locked --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-usdom-finalized-burn-proof-host \
  --bin dom-usdom-plan-finalized-burn-proof >"$PLANNER_LOG" 2>&1; then
  cat -- "$PLANNER_LOG" >&2
  exit 1
fi

# Recheck immediately before the expensive phase. Memory pressure may have
# changed during vector generation and compilation. Downgrading concurrency
# changes only scheduling and resource use, never the guest, ImageID, journal
# or receipt validity.
current_workers="$(select_rayon_workers)"
if ((current_workers < RAYON_WORKERS)); then
  RAYON_WORKERS="$current_workers"
  write_run_status running 0
fi

set +e
env \
  -u BONSAI_API_URL \
  -u BONSAI_API_KEY \
  -u RISC0_SERVER_PATH \
  -u RISC0_SERVER_ADDR \
  -u RISC0_EXECUTOR \
  -u RISC0_PPROF_OUT \
  -u RISC0_PPROF_ENABLE_INLINE_FUNCTIONS \
  -u RISC0_KECCAK_PO2 \
  -u RISC0_DEFAULT_PROVER_NUM_GPUS \
  -u RISC0_INFO \
  -u RISC0_REDIS_CHANNEL_SIZE \
  -u BONSAI_POLL_INTERVAL_MS \
  RAYON_NUM_THREADS="$RAYON_WORKERS" \
  MALLOC_ARENA_MAX=2 \
  RISC0_PROVER=local \
  RISC0_DEV_MODE=0 \
  /usr/bin/time -v -o "$TIME_LOG" \
  cargo run --quiet --release --locked --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-usdom-finalized-burn-proof-host \
  --features prove \
  --bin dom-usdom-prove-finalized-burn >"$PROVER_LOG" 2>&1
prover_status=$?
set -e
if ((prover_status != 0)); then
  cat -- "$PROVER_LOG" >&2
  cat -- "$TIME_LOG" >&2
  exit "$prover_status"
fi

test -s "$RECEIPT_FILE"
test -s "$RECEIPT_INDEX"
test "$(sed -n 's/^status: //p' "$PROVER_LOG")" = 'proved-and-verified'
test "$(sed -n 's/^statement_hash: //p' "$PROVER_LOG")" = \
  'c0461e1c2bcff62d1dfd8e8fed0b094b5d19c2744cf9bad34c8ae3722e7eaef4'
test "$(sed -n 's/^reused_receipt: //p' "$PROVER_LOG")" = 'false'
test "$(sed -n 's/^reused_composite_receipt: //p' "$PROVER_LOG")" = 'false' \
  || test "$(sed -n 's/^reused_composite_receipt: //p' "$PROVER_LOG")" = 'true'

jq -e --arg receipt_sha "$(sha256sum -- "$RECEIPT_FILE" | cut -d ' ' -f 1)" \
  --argjson receipt_bytes "$(wc -c < "$RECEIPT_FILE")" \
  --arg job_sha "$(sha256sum -- "$JOB_INDEX" | cut -d ' ' -f 1)" '
  .schema == "usdom-finalized-burn-receipt-v1"
  and .proof_job_index_sha256 == $job_sha
  and .input_sha256 == "bdcd115207f47fd31e6e7b211ad2e2812ea7c5fa22fa4310ffae9b4cce949f5e"
  and .statement_hash == "c0461e1c2bcff62d1dfd8e8fed0b094b5d19c2744cf9bad34c8ae3722e7eaef4"
  and .program_sha256 == "883ec39b03e3a0703e592026fc7d92a15ce7d949cb937551c5dd8360184cde21"
  and .image_id == "2e26f74497b54b680dfff4c116d56280d016f01d0125329f49bf6d744b1c18ea"
  and .risc0_zkvm_version == "3.0.6"
  and .receipt_kind == "succinct"
  and .segment_limit_po2 == 18
  and .receipt_sha256 == $receipt_sha
  and .receipt_bytes == $receipt_bytes
  and .relation_executed == true
  and .receipt_verified == true
  and .dev_mode == false
  and .generates_proofs == true
  and .mines == false
' "$RECEIPT_INDEX" >/dev/null

cat -- "$PROVER_LOG"
cat -- "$TIME_LOG"
printf 'receipt_bytes: %s\n' "$(wc -c < "$RECEIPT_FILE")"
printf 'receipt_sha256: %s\n' "$(sha256sum -- "$RECEIPT_FILE" | cut -d ' ' -f 1)"
printf 'durable_artifact_directory: %s\n' "$RUN_ROOT"
printf '%s\n' 'PASS: authenticated recursive UDFINL04 job produced and verified one local succinct receipt'
