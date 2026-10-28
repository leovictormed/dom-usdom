#!/usr/bin/env bash
set -euo pipefail
umask 077
LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
source "$LAB_ROOT/scripts/require-risc0-recursion-artifact.sh"
SOURCE_DIR="$LAB_ROOT/evidence/checkpoint-source-set"
RANDOMX_JOB_DIR="$LAB_ROOT/evidence/randomx-proof-jobs"
RANDOMX_RECEIPT_DIR="$LAB_ROOT/evidence/randomx-receipt-set"
ECONOMIC_JOB_DIR="$LAB_ROOT/evidence/economic-proof-jobs"
ECONOMIC_RECEIPT_DIR="$LAB_ROOT/evidence/economic-receipt-set"
SEGMENT_JOB_DIR="$LAB_ROOT/evidence/checkpoint-segment-proof-jobs"
SEGMENT_RECEIPT_DIR="$LAB_ROOT/evidence/checkpoint-segment-receipt-set"
JOB_DIR="$LAB_ROOT/evidence/checkpoint-outer-proof-job"
OUTPUT_DIR="$LAB_ROOT/evidence/checkpoint-outer-receipt-set"
SNAPSHOT_ROOT="$(mktemp -d "/dev/shm/usdom-outer-prove.XXXXXX")"
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
if (($# != 0)); then printf '%s\n' 'Usage: npm run --silent prove:authenticated-checkpoint-outer' >&2; exit 2; fi
for command in cargo cp jq mktemp node sync env realpath stat sha256sum id dirname cmp; do command -v "$command" >/dev/null; done
pin_tool() {
 local name=${1} directory_identity_name="${1}_directory_identity" identity_name="${1}_identity" path owner mode size directory directory_owner directory_mode
 path=$(realpath "$(command -v "$name")"); [[ -x $path && -f $path && ! -L $path ]]
 owner=$(stat -Lc '%u' "$path"); [[ $owner == 0 || $owner == "$(id -u)" ]]
 [[ $(stat -Lc '%h' "$path") == 1 ]]; mode=$(stat -Lc '%a' "$path"); (( (8#$mode & 8#022) == 0 ))
 size=$(stat -Lc '%s' "$path"); (( size > 0 && size <= 512 * 1024 * 1024 ))
 directory=$(dirname "$path"); directory_owner=$(stat -Lc '%u' "$directory"); [[ $directory_owner == 0 || $directory_owner == "$(id -u)" ]]
 directory_mode=$(stat -Lc '%a' "$directory"); (( (8#$directory_mode & 8#022) == 0 ))
 [[ $(realpath "$directory") == "$directory" ]]
 printf -v "${name}_directory_identity" '%s' "$(stat -Lc '%d:%i:%u:%a' "$directory")"
 printf -v "${name}_bin" '%s' "$path"; printf -v "${name}_identity" '%s' "$(stat -Lc '%d:%i:%s:%Y:%Z' "$path")"
 local executable_sha ignored
 read -r executable_sha ignored < <(sha256sum "$path")
 printf -v "${name}_sha256" '%s' "$executable_sha"
 [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" ]]
 [[ $(stat -Lc '%d:%i:%u:%a' "$directory") == "${!directory_identity_name}" ]]
}
assert_tool_unchanged() {
  local name=${1} bin_name="${1}_bin" identity_name="${1}_identity" sha_name="${1}_sha256" directory_identity_name="${1}_directory_identity"
  local path=${!bin_name} identity=${!identity_name} sha=${!sha_name} directory
  directory=$(dirname "$path")
  [[ $(realpath "$directory") == "$directory" ]] || return 1
  [[ $(stat -Lc '%d:%i:%u:%a' "$directory") == "${!directory_identity_name}" ]] || return 1
  [[ $(realpath "$(command -v "$name")") == "$path" ]] || return 1
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "$identity" ]] || return 1
  local observed_sha ignored
  read -r observed_sha ignored < <("$sha256sum_bin" "$path") || return 1
  [[ $observed_sha == "$sha" ]] || return 1
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "$identity" ]] || return 1
  [[ $(stat -Lc '%d:%i:%u:%a' "$directory") == "${!directory_identity_name}" ]] || return 1
}
sha256_file() {
  local output ignored
  read -r output ignored < <("$sha256sum_bin" -- "${1}")
  printf '%s\n' "$output"
}
for command in cargo cp jq node env sha256sum stat; do pin_tool "$command"; done
for directory in "$SOURCE_DIR" "$RANDOMX_JOB_DIR" "$RANDOMX_RECEIPT_DIR" "$ECONOMIC_JOB_DIR" "$ECONOMIC_RECEIPT_DIR" "$SEGMENT_JOB_DIR" "$SEGMENT_RECEIPT_DIR" "$JOB_DIR"; do
  [[ -d "$directory" && ! -L "$directory" ]] || { printf 'Missing non-symlink outer-prove input directory: %s\n' "$directory" >&2; exit 1; }
done
for input in "$SOURCE_DIR/checkpoint-source-set-index.json" "$RANDOMX_JOB_DIR/randomx-proof-job-index.json" "$RANDOMX_RECEIPT_DIR/randomx-receipt-set-index.json" "$ECONOMIC_JOB_DIR/economic-proof-job-index.json" "$ECONOMIC_RECEIPT_DIR/economic-receipt-set-index.json" "$SEGMENT_JOB_DIR/checkpoint-segment-proof-job-index.json" "$SEGMENT_RECEIPT_DIR/checkpoint-segment-receipt-set-index.json" "$JOB_DIR/checkpoint-outer-proof-job-index.json" "$JOB_DIR/checkpoint-statement-v6.bin" "$JOB_DIR/checkpoint-outer-chain.bin"; do
  [[ -f "$input" && ! -L "$input" ]] || { printf 'Missing non-symlink outer proof input: %s\n' "$input" >&2; exit 1; }
done
mkdir -p -- "$OUTPUT_DIR"
[[ ! -L "$OUTPUT_DIR" ]] || { printf '%s\n' 'Checkpoint outer-receipt output directory cannot be a symlink' >&2; exit 1; }
snapshot_source="$SNAPSHOT_LAB/evidence/checkpoint-source-set"
snapshot_randomx_jobs="$SNAPSHOT_LAB/evidence/randomx-proof-jobs"
snapshot_randomx_receipts="$SNAPSHOT_LAB/evidence/randomx-receipt-set"
snapshot_economic_jobs="$SNAPSHOT_LAB/evidence/economic-proof-jobs"
snapshot_economic_receipts="$SNAPSHOT_LAB/evidence/economic-receipt-set"
snapshot_segment_jobs="$SNAPSHOT_LAB/evidence/checkpoint-segment-proof-jobs"
snapshot_segment_receipts="$SNAPSHOT_LAB/evidence/checkpoint-segment-receipt-set"
snapshot_jobs="$SNAPSHOT_LAB/evidence/checkpoint-outer-proof-job"
snapshot_output="$SNAPSHOT_LAB/evidence/checkpoint-outer-receipt-set"
snapshot_segment_artifacts="$SNAPSHOT_ROOT/repository/crates/dom-usdom-checkpoint-segment-risc0-guest/elfs"
snapshot_outer_artifacts="$SNAPSHOT_ROOT/repository/crates/dom-usdom-checkpoint-outer-risc0-guest/elfs"
mkdir -p -- "$snapshot_source" "$snapshot_randomx_jobs" "$snapshot_randomx_receipts" "$snapshot_economic_jobs" "$snapshot_economic_receipts" "$snapshot_segment_jobs" "$snapshot_segment_receipts" "$snapshot_jobs" "$snapshot_output" "$snapshot_segment_artifacts" "$snapshot_outer_artifacts"
chmod -R go-rwx -- "$SNAPSHOT_ROOT"
capture_private() {
  local capture_source capture_target
  capture_source=${@::1}
  capture_target=${@:2:1}
  "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$capture_source" > "$capture_target"
  chmod 0600 "$capture_target"
}
capture_private "$SOURCE_DIR/checkpoint-source-set-index.json" "$snapshot_source/checkpoint-source-set-index.json"
capture_private "$RANDOMX_JOB_DIR/randomx-proof-job-index.json" "$snapshot_randomx_jobs/randomx-proof-job-index.json"
capture_private "$RANDOMX_RECEIPT_DIR/randomx-receipt-set-index.json" "$snapshot_randomx_receipts/randomx-receipt-set-index.json"
capture_private "$ECONOMIC_JOB_DIR/economic-proof-job-index.json" "$snapshot_economic_jobs/economic-proof-job-index.json"
capture_private "$ECONOMIC_RECEIPT_DIR/economic-receipt-set-index.json" "$snapshot_economic_receipts/economic-receipt-set-index.json"
capture_private "$SEGMENT_JOB_DIR/checkpoint-segment-proof-job-index.json" "$snapshot_segment_jobs/checkpoint-segment-proof-job-index.json"
capture_private "$SEGMENT_RECEIPT_DIR/checkpoint-segment-receipt-set-index.json" "$snapshot_segment_receipts/checkpoint-segment-receipt-set-index.json"
capture_private "$JOB_DIR/checkpoint-outer-proof-job-index.json" "$snapshot_jobs/checkpoint-outer-proof-job-index.json"
capture_private "$JOB_DIR/checkpoint-statement-v6.bin" "$snapshot_jobs/checkpoint-statement-v6.bin"
capture_private "$JOB_DIR/checkpoint-outer-chain.bin" "$snapshot_jobs/checkpoint-outer-chain.bin"

# Validate whole bounded catalogs before deriving names. Filtering bad entries
# could otherwise prove a strict subset of the authenticated plan.
"$jq_bin" -e '(.segments|type=="array" and length>0 and length<=720) and ([.segments[]|.transition_file]|length==(unique|length)) and ([.segments[]|.private_input_file]|length==(unique|length)) and ([.segments[]|.policy_input_file]|length==(unique|length)) and ([.segments[]|.native_state_opening_file]|length==(unique|length)) and all(.segments[]; (.transition_file|test("^checkpoint-segment-[0-9]{4}-transition\\.bin$")) and (.private_input_file|test("^checkpoint-segment-[0-9]{4}-private-input\\.bin$")) and (.policy_input_file|test("^checkpoint-segment-[0-9]{4}-policy-input\\.bin$")) and (.native_state_opening_file|test("^checkpoint-segment-[0-9]{4}-native-state-opening\\.bin$")))' "$snapshot_source/checkpoint-source-set-index.json" >/dev/null || { printf '%s\n' 'Checkpoint outer prover has an invalid source catalog' >&2; exit 1; }
"$jq_bin" -e '(.receipts|type=="array" and length>0 and length<=720) and ([.receipts[].receipt_file]|length==(unique|length)) and all(.receipts[];.receipt_file|type=="string" and test("^randomx-receipt-[0-9]{4}\\.bin$"))' "$snapshot_randomx_receipts/randomx-receipt-set-index.json" >/dev/null || { printf '%s\n' 'Checkpoint outer prover has an invalid RandomX receipt catalog' >&2; exit 1; }
"$jq_bin" -e '(.block_receipts|type=="array" and length>0 and length<=720) and ([.block_receipts[].receipt_file]|length==(unique|length)) and all(.block_receipts[];.receipt_file|type=="string" and test("^economic-block-receipt-[0-9]{4}\\.bin$"))' "$snapshot_economic_receipts/economic-receipt-set-index.json" >/dev/null || { printf '%s\n' 'Checkpoint outer prover has an invalid economic receipt catalog' >&2; exit 1; }
"$jq_bin" -e '(.receipts|type=="array" and length>0 and length<=720) and ([.receipts[].receipt_file]|length==(unique|length)) and all(.receipts[];.receipt_file|type=="string" and test("^checkpoint-segment-receipt-[0-9]{4}\\.bin$"))' "$snapshot_segment_receipts/checkpoint-segment-receipt-set-index.json" >/dev/null || { printf '%s\n' 'Checkpoint outer prover has an invalid segment receipt catalog' >&2; exit 1; }
mapfile -t source_files < <("$jq_bin" -r '[.segments[]|.transition_file,.private_input_file,.policy_input_file,.native_state_opening_file]|unique|.[]' "$snapshot_source/checkpoint-source-set-index.json")
mapfile -t randomx_receipts < <("$jq_bin" -r '[.receipts[].receipt_file]|unique|.[]' "$snapshot_randomx_receipts/randomx-receipt-set-index.json")
mapfile -t economic_receipts < <("$jq_bin" -r '[.block_receipts[].receipt_file]|unique|.[]' "$snapshot_economic_receipts/economic-receipt-set-index.json")
mapfile -t segment_receipts < <("$jq_bin" -r '[.receipts[].receipt_file]|unique|.[]' "$snapshot_segment_receipts/checkpoint-segment-receipt-set-index.json")
for name in "${source_files[@]}"; do capture_private "$SOURCE_DIR/$name" "$snapshot_source/$name"; done
for name in "${randomx_receipts[@]}"; do capture_private "$RANDOMX_RECEIPT_DIR/$name" "$snapshot_randomx_receipts/$name"; done
for name in "${economic_receipts[@]}"; do capture_private "$ECONOMIC_RECEIPT_DIR/$name" "$snapshot_economic_receipts/$name"; done
for name in "${segment_receipts[@]}"; do capture_private "$SEGMENT_RECEIPT_DIR/$name" "$snapshot_segment_receipts/$name"; done
for guest in checkpoint-segment checkpoint-outer; do
  artifact_source="$REPOSITORY_ROOT/crates/dom-usdom-${guest}-risc0-guest/elfs"
  if [[ $guest == checkpoint-segment ]]; then artifact_target="$snapshot_segment_artifacts"; artifact_name=usdom-checkpoint-segment; else artifact_target="$snapshot_outer_artifacts"; artifact_name=usdom-checkpoint-outer; fi
  for extension in elf bin iid; do name="${artifact_name}.${extension}"; [[ -f "$artifact_source/$name" && ! -L "$artifact_source/$name" ]]; "$cp_bin" --reflink=never --no-preserve=mode,ownership,timestamps -- "$artifact_source/$name" "$artifact_target/$name"; chmod 0600 "$artifact_target/$name"; done
done
receipt_name=$("$jq_bin" -er '.receipt_file | select(type=="string" and test("^checkpoint-outer-receipt\\.bin$"))' "$snapshot_jobs/checkpoint-outer-proof-job-index.json")
if [[ -e "$OUTPUT_DIR/$receipt_name" || -L "$OUTPUT_DIR/$receipt_name" ]]; then capture_private "$OUTPUT_DIR/$receipt_name" "$snapshot_output/$receipt_name"; fi
assert_tool_unchanged cargo
source "$LAB_ROOT/scripts/require-risc0-program-binary.sh"
verify_risc0_program_binary "$cargo_bin" "$REPOSITORY_ROOT" \
  "$snapshot_segment_artifacts/usdom-checkpoint-segment.bin" \
  371e408b360a0e4a0aae2cb994bddb2d66afcc5891a7ed574fa83119734bfbf7
verify_risc0_program_binary "$cargo_bin" "$REPOSITORY_ROOT" \
  "$snapshot_outer_artifacts/usdom-checkpoint-outer.bin" \
  311d58dadcb97cac783e3ec0efe3c4570f42b944cbda1e48aeb56b055682257b
require_risc0_recursion_artifact
cd "$SNAPSHOT_LAB"
reviewed_job_index="$SNAPSHOT_ROOT/reviewed-checkpoint-outer-job-index.json"
"$cp_bin" --reflink=never --no-preserve=mode,ownership,timestamps -- "$snapshot_jobs/checkpoint-outer-proof-job-index.json" "$reviewed_job_index"
rm -- "$snapshot_jobs/checkpoint-outer-proof-job-index.json" "$snapshot_jobs/checkpoint-statement-v6.bin" "$snapshot_jobs/checkpoint-outer-chain.bin"
assert_tool_unchanged cargo; assert_tool_unchanged cp; assert_tool_unchanged node
"$cargo_bin" run --quiet --release --locked --manifest-path "$REPOSITORY_ROOT/Cargo.toml" -p dom-usdom-checkpoint-proof-host --features verify --bin dom-usdom-plan-checkpoint-outer
cmp -s "$reviewed_job_index" "$snapshot_jobs/checkpoint-outer-proof-job-index.json" || { printf '%s\n' 'Checkpoint outer job index is not reproducible from snapshotted inputs' >&2; exit 1; }
critical="$SNAPSHOT_ROOT/checkpoint-outer-critical-inputs.sha256"
{
 "$sha256sum_bin" "$snapshot_source/checkpoint-source-set-index.json" "$snapshot_randomx_jobs/randomx-proof-job-index.json" "$snapshot_randomx_receipts/randomx-receipt-set-index.json" "$snapshot_economic_jobs/economic-proof-job-index.json" "$snapshot_economic_receipts/economic-receipt-set-index.json" "$snapshot_segment_jobs/checkpoint-segment-proof-job-index.json" "$snapshot_segment_receipts/checkpoint-segment-receipt-set-index.json" "$snapshot_jobs/checkpoint-outer-proof-job-index.json" "$snapshot_jobs/checkpoint-statement-v6.bin" "$snapshot_jobs/checkpoint-outer-chain.bin"
 for name in "${source_files[@]}"; do "$sha256sum_bin" "$snapshot_source/$name"; done
 for name in "${randomx_receipts[@]}"; do "$sha256sum_bin" "$snapshot_randomx_receipts/$name"; done
 for name in "${economic_receipts[@]}"; do "$sha256sum_bin" "$snapshot_economic_receipts/$name"; done
 for name in "${segment_receipts[@]}"; do "$sha256sum_bin" "$snapshot_segment_receipts/$name"; done
 "$sha256sum_bin" "$snapshot_segment_artifacts"/* "$snapshot_outer_artifacts"/*
 [[ ! -e $snapshot_output/$receipt_name ]] || "$sha256sum_bin" "$snapshot_output/$receipt_name"
} > "$critical"
assert_tool_unchanged cargo; assert_tool_unchanged cp; assert_tool_unchanged jq; assert_tool_unchanged node; assert_tool_unchanged env; assert_tool_unchanged sha256sum; assert_tool_unchanged stat
"$sha256sum_bin" -c "$critical" >/dev/null
"$env_bin" -u BONSAI_API_URL -u BONSAI_API_KEY -u RISC0_SERVER_PATH -u RISC0_SERVER_ADDR -u RISC0_EXECUTOR -u RISC0_PPROF_OUT -u RISC0_PPROF_ENABLE_INLINE_FUNCTIONS -u RISC0_KECCAK_PO2 -u RISC0_DEFAULT_PROVER_NUM_GPUS -u RISC0_INFO -u RISC0_REDIS_CHANNEL_SIZE -u BONSAI_POLL_INTERVAL_MS RAYON_NUM_THREADS=1 RISC0_PROVER=local RISC0_DEV_MODE=0 "$cargo_bin" run --quiet --release --locked --manifest-path "$REPOSITORY_ROOT/Cargo.toml" -p dom-usdom-checkpoint-proof-host --features prove --bin dom-usdom-prove-checkpoint-outer
completion_index="$snapshot_output/checkpoint-outer-receipt-set-index.json"
completion_record=$("$jq_bin" -er --arg receipt "$receipt_name" '
  select(.schema == "usdom-checkpoint-outer-receipt-set-v1") |
  select(.receipt_file == $receipt) |
  select(.receipt_sha256|type == "string" and test("^[0-9a-f]{64}$")) |
  select(.receipt_bytes|type == "number" and floor == . and . > 0 and . <= 268435456) |
  [.receipt_file,.receipt_sha256,(.receipt_bytes|tostring)] | @tsv
' "$completion_index")
IFS=$'\t' read -r completion_receipt completion_sha completion_bytes <<< "$completion_record"
[[ $completion_receipt == "$receipt_name" && $("$stat_bin" -Lc '%s' "$snapshot_output/$completion_receipt") == "$completion_bytes" && $(sha256_file "$snapshot_output/$completion_receipt") == "$completion_sha" ]] || { printf '%s\n' 'Checkpoint outer prover receipt does not match its completion index' >&2; exit 1; }
final_index="$OUTPUT_DIR/checkpoint-outer-receipt-set-index.json"
if [[ -e "$final_index" || -L "$final_index" ]]; then
 [[ -f "$final_index" && ! -L "$final_index" ]] || { printf '%s\n' 'Checkpoint outer receipt-set index is not a direct regular file' >&2; exit 1; }
 rm -- "$final_index"; sync -d "$OUTPUT_DIR"
fi
# Receipt first; the verified index is the durable completion marker and is last.
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$snapshot_output/$completion_receipt" | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$OUTPUT_DIR/$completion_receipt"
[[ $("$stat_bin" -Lc '%s' "$OUTPUT_DIR/$completion_receipt") == "$completion_bytes" && $(sha256_file "$OUTPUT_DIR/$completion_receipt") == "$completion_sha" ]] || { printf '%s\n' 'Published checkpoint outer receipt failed integrity verification' >&2; exit 1; }
completion_index_sha=$(sha256_file "$completion_index")
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$completion_index" | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$final_index"
[[ $(sha256_file "$final_index") == "$completion_index_sha" ]] || { printf '%s\n' 'Published checkpoint outer completion index changed during installation' >&2; exit 1; }
[[ $("$stat_bin" -Lc '%s' "$OUTPUT_DIR/$completion_receipt") == "$completion_bytes" && $(sha256_file "$OUTPUT_DIR/$completion_receipt") == "$completion_sha" ]] || { printf '%s\n' 'Checkpoint outer receipt changed before completion publication' >&2; exit 1; }
