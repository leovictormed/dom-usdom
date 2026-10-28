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
JOB_DIR="$LAB_ROOT/evidence/checkpoint-segment-proof-jobs"
JOB_INDEX="$JOB_DIR/checkpoint-segment-proof-job-index.json"
OUTPUT_DIR="$LAB_ROOT/evidence/checkpoint-segment-receipt-set"
SNAPSHOT_ROOT="$(mktemp -d "/dev/shm/usdom-segment-prove.XXXXXX")"
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
if (($# != 0)); then printf '%s\n' 'Usage: npm run --silent prove:authenticated-checkpoint-segment-set' >&2; exit 2; fi
for command in cargo cp jq mktemp node env realpath stat sha256sum id dirname cmp; do command -v "$command" >/dev/null; done
pin_tool() {
 local name=${1} directory_identity_name="${1}_directory_identity" identity_name="${1}_identity" path owner mode size directory directory_owner directory_mode
 path=$(realpath "$(command -v "$name")"); [[ -x $path && -f $path && ! -L $path ]]
 owner=$(stat -Lc '%u' "$path"); [[ $owner == 0 || $owner == "$(id -u)" ]]
 [[ $(stat -Lc '%h' "$path") == 1 ]]; mode=$(stat -Lc '%a' "$path"); (( (8#$mode & 8#022) == 0 ))
 size=$(stat -Lc '%s' "$path"); (( size > 0 && size <= 512 * 1024 * 1024 ))
 directory=$(dirname "$path"); directory_owner=$(stat -Lc '%u' "$directory")
 [[ $directory_owner == 0 || $directory_owner == "$(id -u)" ]]
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
for directory in "$SOURCE_DIR" "$RANDOMX_JOB_DIR" "$RANDOMX_RECEIPT_DIR" "$ECONOMIC_JOB_DIR" "$ECONOMIC_RECEIPT_DIR" "$JOB_DIR"; do
  [[ -d "$directory" && ! -L "$directory" ]] || { printf 'Missing non-symlink segment-prove input directory: %s\n' "$directory" >&2; exit 1; }
done
for index in "$SOURCE_DIR/checkpoint-source-set-index.json" "$RANDOMX_JOB_DIR/randomx-proof-job-index.json" "$RANDOMX_RECEIPT_DIR/randomx-receipt-set-index.json" "$ECONOMIC_JOB_DIR/economic-proof-job-index.json" "$ECONOMIC_RECEIPT_DIR/economic-receipt-set-index.json" "$JOB_INDEX"; do
  [[ -f "$index" && ! -L "$index" ]] || { printf 'Missing non-symlink segment-prove input index: %s\n' "$index" >&2; exit 1; }
done
mkdir -p -- "$OUTPUT_DIR"
[[ ! -L "$OUTPUT_DIR" ]] || { printf '%s\n' 'Checkpoint segment receipt output directory cannot be a symlink' >&2; exit 1; }
snapshot_source="$SNAPSHOT_LAB/evidence/checkpoint-source-set"
snapshot_randomx_jobs="$SNAPSHOT_LAB/evidence/randomx-proof-jobs"
snapshot_randomx_receipts="$SNAPSHOT_LAB/evidence/randomx-receipt-set"
snapshot_economic_jobs="$SNAPSHOT_LAB/evidence/economic-proof-jobs"
snapshot_economic_receipts="$SNAPSHOT_LAB/evidence/economic-receipt-set"
snapshot_jobs="$SNAPSHOT_LAB/evidence/checkpoint-segment-proof-jobs"
snapshot_output="$SNAPSHOT_LAB/evidence/checkpoint-segment-receipt-set"
snapshot_artifacts="$SNAPSHOT_ROOT/repository/crates/dom-usdom-checkpoint-segment-risc0-guest/elfs"
mkdir -p -- "$snapshot_source" "$snapshot_randomx_jobs" "$snapshot_randomx_receipts" "$snapshot_economic_jobs" "$snapshot_economic_receipts" "$snapshot_jobs" "$snapshot_output" "$snapshot_artifacts"
chmod -R go-rwx -- "$SNAPSHOT_ROOT"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$SOURCE_DIR/checkpoint-source-set-index.json" > "$snapshot_source/checkpoint-source-set-index.json"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$RANDOMX_JOB_DIR/randomx-proof-job-index.json" > "$snapshot_randomx_jobs/randomx-proof-job-index.json"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$RANDOMX_RECEIPT_DIR/randomx-receipt-set-index.json" > "$snapshot_randomx_receipts/randomx-receipt-set-index.json"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$ECONOMIC_JOB_DIR/economic-proof-job-index.json" > "$snapshot_economic_jobs/economic-proof-job-index.json"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$ECONOMIC_RECEIPT_DIR/economic-receipt-set-index.json" > "$snapshot_economic_receipts/economic-receipt-set-index.json"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$JOB_INDEX" > "$snapshot_jobs/checkpoint-segment-proof-job-index.json"
chmod 0600 "$snapshot_source/checkpoint-source-set-index.json" "$snapshot_randomx_jobs/randomx-proof-job-index.json" "$snapshot_randomx_receipts/randomx-receipt-set-index.json" "$snapshot_economic_jobs/economic-proof-job-index.json" "$snapshot_economic_receipts/economic-receipt-set-index.json" "$snapshot_jobs/checkpoint-segment-proof-job-index.json"
# Validate complete catalogs before selecting names; filtering invalid entries would fail open.
"$jq_bin" -e '
 (.jobs|type=="array" and length>0 and length<=720) and
 ([.jobs[]|.transition_file]|length==(unique|length)) and
 ([.jobs[]|.private_input_file]|length==(unique|length)) and
 ([.jobs[]|.policy_input_file]|length==(unique|length)) and
 ([.jobs[]|.native_state_opening_file]|length==(unique|length)) and
 ([.jobs[]|.receipt_file]|length==(unique|length)) and
 (all(.jobs[];
   (.transition_file|test("^evidence/checkpoint-source-set/checkpoint-segment-[0-9]{4}-transition\\.bin$")) and
   (.private_input_file|test("^evidence/checkpoint-source-set/checkpoint-segment-[0-9]{4}-private-input\\.bin$")) and
   (.policy_input_file|test("^evidence/checkpoint-source-set/checkpoint-segment-[0-9]{4}-policy-input\\.bin$")) and
   (.native_state_opening_file|test("^evidence/checkpoint-source-set/checkpoint-segment-[0-9]{4}-native-state-opening\\.bin$")) and
   (.receipt_file|test("^checkpoint-segment-receipt-[0-9]{4}\\.bin$")) and
   (.randomx_receipts|type=="array" and length<=720) and
   (.economic_block_receipts|type=="array" and length<=720) and
   (all(.randomx_receipts[];.receipt_file|test("^randomx-receipt-[0-9]{4}\\.bin$"))) and
   (all(.economic_block_receipts[];.receipt_file|test("^economic-block-receipt-[0-9]{4}\\.bin$"))))) and
 ([.jobs[].randomx_receipts[].receipt_file]|length>0 and length<=720 and length==(unique|length)) and
 ([.jobs[].economic_block_receipts[].receipt_file]|length>0 and length<=720 and length==(unique|length))
' "$snapshot_jobs/checkpoint-segment-proof-job-index.json" >/dev/null || { printf '%s\n' 'Checkpoint segment prover has an empty, duplicate, excessive or noncanonical job catalog' >&2; exit 1; }
mapfile -t source_files < <("$jq_bin" -r '[.jobs[]|.transition_file,.private_input_file,.policy_input_file,.native_state_opening_file]|unique|.[]' "$snapshot_jobs/checkpoint-segment-proof-job-index.json")
mapfile -t randomx_receipts < <("$jq_bin" -r '[.jobs[].randomx_receipts[].receipt_file]|unique|.[]' "$snapshot_jobs/checkpoint-segment-proof-job-index.json")
mapfile -t economic_receipts < <("$jq_bin" -r '[.jobs[].economic_block_receipts[].receipt_file]|unique|.[]' "$snapshot_jobs/checkpoint-segment-proof-job-index.json")
mapfile -t receipt_files < <("$jq_bin" -r '[.jobs[].receipt_file]|unique|.[]' "$snapshot_jobs/checkpoint-segment-proof-job-index.json")
for logical_path in "${source_files[@]}"; do name=${logical_path##*/}; "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$SOURCE_DIR/$name" > "$snapshot_source/$name"; chmod 0600 "$snapshot_source/$name"; done
for name in "${randomx_receipts[@]}"; do "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$RANDOMX_RECEIPT_DIR/$name" > "$snapshot_randomx_receipts/$name"; chmod 0600 "$snapshot_randomx_receipts/$name"; done
for name in "${economic_receipts[@]}"; do "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$ECONOMIC_RECEIPT_DIR/$name" > "$snapshot_economic_receipts/$name"; chmod 0600 "$snapshot_economic_receipts/$name"; done
for name in "${receipt_files[@]}"; do
  if [[ -e "$OUTPUT_DIR/$name" || -L "$OUTPUT_DIR/$name" ]]; then "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$OUTPUT_DIR/$name" > "$snapshot_output/$name"; chmod 0600 "$snapshot_output/$name"; fi
done
artifact_source="$REPOSITORY_ROOT/crates/dom-usdom-checkpoint-segment-risc0-guest/elfs"
for extension in elf bin iid; do
 name="usdom-checkpoint-segment.${extension}"; [[ -f "$artifact_source/$name" && ! -L "$artifact_source/$name" ]]
 "$cp_bin" --reflink=never --no-preserve=mode,ownership,timestamps -- "$artifact_source/$name" "$snapshot_artifacts/$name"; chmod 0600 "$snapshot_artifacts/$name"
done
assert_tool_unchanged cargo
source "$LAB_ROOT/scripts/require-risc0-program-binary.sh"
verify_risc0_program_binary "$cargo_bin" "$REPOSITORY_ROOT" \
  "$snapshot_artifacts/usdom-checkpoint-segment.bin" \
  371e408b360a0e4a0aae2cb994bddb2d66afcc5891a7ed574fa83119734bfbf7
require_risc0_recursion_artifact
cd "$SNAPSHOT_LAB"
reviewed_job_index="$SNAPSHOT_ROOT/reviewed-segment-job-index.json"
"$cp_bin" --reflink=never --no-preserve=mode,ownership,timestamps -- "$snapshot_jobs/checkpoint-segment-proof-job-index.json" "$reviewed_job_index"
rm -- "$snapshot_jobs/checkpoint-segment-proof-job-index.json"
assert_tool_unchanged cargo; assert_tool_unchanged cp; assert_tool_unchanged node
"$cargo_bin" run --quiet --release --locked --manifest-path "$REPOSITORY_ROOT/Cargo.toml" -p dom-usdom-checkpoint-proof-host --features verify --bin dom-usdom-plan-checkpoint-segment-set
cmp -s "$reviewed_job_index" "$snapshot_jobs/checkpoint-segment-proof-job-index.json" || { printf '%s\n' 'Checkpoint segment job index is not reproducible from snapshotted inputs' >&2; exit 1; }
critical="$SNAPSHOT_ROOT/checkpoint-segment-critical-inputs.sha256"
{
 "$sha256sum_bin" "$snapshot_source/checkpoint-source-set-index.json" "$snapshot_randomx_jobs/randomx-proof-job-index.json" "$snapshot_randomx_receipts/randomx-receipt-set-index.json" "$snapshot_economic_jobs/economic-proof-job-index.json" "$snapshot_economic_receipts/economic-receipt-set-index.json" "$snapshot_jobs/checkpoint-segment-proof-job-index.json"
 for logical_path in "${source_files[@]}"; do "$sha256sum_bin" "$SNAPSHOT_LAB/$logical_path"; done
 for name in "${randomx_receipts[@]}"; do "$sha256sum_bin" "$snapshot_randomx_receipts/$name"; done
 for name in "${economic_receipts[@]}"; do "$sha256sum_bin" "$snapshot_economic_receipts/$name"; done
 "$sha256sum_bin" "$snapshot_artifacts"/*
 for name in "${receipt_files[@]}"; do [[ ! -e $snapshot_output/$name ]] || "$sha256sum_bin" "$snapshot_output/$name"; done
} > "$critical"
assert_tool_unchanged cargo; assert_tool_unchanged cp; assert_tool_unchanged jq; assert_tool_unchanged node; assert_tool_unchanged env; assert_tool_unchanged sha256sum; assert_tool_unchanged stat
"$sha256sum_bin" -c "$critical" >/dev/null
"$env_bin" -u BONSAI_API_URL -u BONSAI_API_KEY -u RISC0_SERVER_PATH -u RISC0_SERVER_ADDR -u RISC0_EXECUTOR -u RISC0_PPROF_OUT -u RISC0_PPROF_ENABLE_INLINE_FUNCTIONS -u RISC0_KECCAK_PO2 -u RISC0_DEFAULT_PROVER_NUM_GPUS -u RISC0_INFO -u RISC0_REDIS_CHANNEL_SIZE -u BONSAI_POLL_INTERVAL_MS RAYON_NUM_THREADS=1 RISC0_PROVER=local RISC0_DEV_MODE=0 "$cargo_bin" run --quiet --release --locked --manifest-path "$REPOSITORY_ROOT/Cargo.toml" -p dom-usdom-checkpoint-proof-host --features prove --bin dom-usdom-prove-checkpoint-segment-set
completion_index="$snapshot_output/checkpoint-segment-receipt-set-index.json"
completion_catalog="$SNAPSHOT_ROOT/checkpoint-segment-completion-catalog.tsv"
"$jq_bin" -er '
  select(.schema == "usdom-checkpoint-segment-receipt-set-v1") |
  select(.receipt_count == (.receipts|length)) |
  select((.receipts|length) > 0 and (.receipts|length) <= 720) |
  select([.receipts[].receipt_file]|length == (unique|length)) |
  .receipts[] |
  select(.receipt_file|type == "string" and test("^checkpoint-segment-receipt-[0-9]{4}\\.bin$")) |
  select(.receipt_sha256|type == "string" and test("^[0-9a-f]{64}$")) |
  select(.receipt_bytes|type == "number" and floor == . and . > 0 and . <= 268435456) |
  [.receipt_file,.receipt_sha256,(.receipt_bytes|tostring)] | @tsv
' "$completion_index" > "$completion_catalog"
mapfile -t completion_records < "$completion_catalog"
(( ${#completion_records[@]} == ${#receipt_files[@]} )) || { printf '%s\n' 'Checkpoint segment completion index has an incomplete receipt catalog' >&2; exit 1; }
for i in "${!completion_records[@]}"; do
  IFS=$'\t' read -r name receipt_sha receipt_bytes <<< "${completion_records[$i]}"
  [[ $name == "${receipt_files[$i]}" ]] || { printf '%s\n' 'Checkpoint segment completion index does not match reviewed receipt order' >&2; exit 1; }
  [[ $("$stat_bin" -Lc '%s' "$snapshot_output/$name") == "$receipt_bytes" && $(sha256_file "$snapshot_output/$name") == "$receipt_sha" ]] || { printf '%s\n' 'Checkpoint segment prover receipt does not match its completion index' >&2; exit 1; }
done
# Preserve the prior valid completion marker throughout proving. Invalidate it only
# after a new complete snapshot exists and immediately before publishing receipts.
final_index="$OUTPUT_DIR/checkpoint-segment-receipt-set-index.json"
if [[ -e "$final_index" || -L "$final_index" ]]; then
 [[ -f "$final_index" && ! -L "$final_index" ]] || { printf '%s\n' 'Checkpoint segment receipt-set index is not a direct regular file' >&2; exit 1; }
 rm -- "$final_index"; sync -d "$OUTPUT_DIR"
fi
# Receipts become durable first. The verified index is the completion marker.
for record in "${completion_records[@]}"; do
 IFS=$'\t' read -r name receipt_sha receipt_bytes <<< "$record"
 "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$snapshot_output/$name" | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$OUTPUT_DIR/$name"
 [[ $("$stat_bin" -Lc '%s' "$OUTPUT_DIR/$name") == "$receipt_bytes" && $(sha256_file "$OUTPUT_DIR/$name") == "$receipt_sha" ]] || { printf '%s\n' 'Published checkpoint segment receipt failed integrity verification' >&2; exit 1; }
done
completion_sha=$(sha256_file "$completion_index")
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$completion_index" | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$final_index"
[[ $(sha256_file "$final_index") == "$completion_sha" ]] || { printf '%s\n' 'Published checkpoint segment completion index changed during installation' >&2; exit 1; }
for record in "${completion_records[@]}"; do
 IFS=$'\t' read -r name receipt_sha receipt_bytes <<< "$record"
 [[ $("$stat_bin" -Lc '%s' "$OUTPUT_DIR/$name") == "$receipt_bytes" && $(sha256_file "$OUTPUT_DIR/$name") == "$receipt_sha" ]] || { printf '%s\n' 'Checkpoint segment receipt changed before completion publication' >&2; exit 1; }
done
