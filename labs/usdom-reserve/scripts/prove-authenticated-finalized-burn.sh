#!/usr/bin/env bash
set -euo pipefail
umask 077

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
source "$LAB_ROOT/scripts/require-risc0-recursion-artifact.sh"
SOURCE_INPUT="$LAB_ROOT/evidence/finalized-burn-source/finalized-burn-input.bin"
JOB_DIR="$LAB_ROOT/evidence/finalized-burn-proof-job"
JOB_INPUT="$JOB_DIR/finalized-burn-input.bin"
JOB_INDEX="$JOB_DIR/finalized-burn-proof-job-index.json"
CHECKPOINT_STATEMENT="$LAB_ROOT/evidence/checkpoint-outer-proof-job/checkpoint-statement-v6.bin"
CHECKPOINT_OUTER_RECEIPT="$LAB_ROOT/evidence/checkpoint-outer-receipt-set/checkpoint-outer-receipt.bin"
ARTIFACT_DIR="$LAB_ROOT/evidence/finalized-burn-guest"
OUTPUT_DIR="$LAB_ROOT/evidence/finalized-burn-receipt"
SNAPSHOT_ROOT="$(mktemp -d "/dev/shm/usdom-finalized-burn-prove.XXXXXX")"
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
  printf '%s\n' 'Usage: npm run --silent prove:authenticated-finalized-burn' >&2
  exit 2
fi
for command in cargo cmp cut jq mktemp node sha256sum sync wc env realpath stat id dirname cp; do command -v "$command" >/dev/null; done
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
for command in cargo cmp jq node env cp sha256sum stat; do pin_tool "$command"; done
for directory in "$JOB_DIR" "$ARTIFACT_DIR"; do
  [[ -d "$directory" && ! -L "$directory" ]] || {
    printf 'Missing non-symlink finalized-burn proof input directory: %s\n' "$directory" >&2; exit 1; }
done
for input in "$SOURCE_INPUT" "$JOB_INPUT" "$JOB_INDEX" "$CHECKPOINT_STATEMENT" \
  "$CHECKPOINT_OUTER_RECEIPT" "$ARTIFACT_DIR/usdom-finalized-burn.elf" \
  "$ARTIFACT_DIR/usdom-finalized-burn.iid"; do
  [[ -f "$input" && ! -L "$input" ]] || {
    printf 'Missing non-symlink finalized-burn proof input: %s\n' "$input" >&2; exit 1; }
done
mkdir -p -- "$OUTPUT_DIR"
[[ ! -L "$OUTPUT_DIR" ]] || { printf '%s\n' 'Finalized-burn receipt output directory cannot be a symlink' >&2; exit 1; }

snapshot_source="$SNAPSHOT_LAB/evidence/finalized-burn-source"
snapshot_jobs="$SNAPSHOT_LAB/evidence/finalized-burn-proof-job"
snapshot_statement="$SNAPSHOT_LAB/evidence/checkpoint-outer-proof-job"
snapshot_checkpoint_receipts="$SNAPSHOT_LAB/evidence/checkpoint-outer-receipt-set"
snapshot_artifacts="$SNAPSHOT_LAB/evidence/finalized-burn-guest"
snapshot_output="$SNAPSHOT_LAB/evidence/finalized-burn-receipt"
mkdir -p -- "$snapshot_source" "$snapshot_jobs" "$snapshot_statement" \
  "$snapshot_checkpoint_receipts" "$snapshot_artifacts" "$snapshot_output"
chmod -R go-rwx -- "$SNAPSHOT_ROOT"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$SOURCE_INPUT" > "$snapshot_source/finalized-burn-input.bin"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$JOB_INPUT" > "$snapshot_jobs/finalized-burn-input.bin"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$JOB_INDEX" > "$snapshot_jobs/finalized-burn-proof-job-index.json"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$CHECKPOINT_STATEMENT" > "$snapshot_statement/checkpoint-statement-v6.bin"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$CHECKPOINT_OUTER_RECEIPT" > "$snapshot_checkpoint_receipts/checkpoint-outer-receipt.bin"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$ARTIFACT_DIR/usdom-finalized-burn.elf" > "$snapshot_artifacts/usdom-finalized-burn.elf"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$ARTIFACT_DIR/usdom-finalized-burn.iid" > "$snapshot_artifacts/usdom-finalized-burn.iid"
chmod 0600 "$snapshot_source/finalized-burn-input.bin" "$snapshot_jobs/finalized-burn-input.bin" \
  "$snapshot_jobs/finalized-burn-proof-job-index.json" "$snapshot_statement/checkpoint-statement-v6.bin" \
  "$snapshot_checkpoint_receipts/checkpoint-outer-receipt.bin" \
  "$snapshot_artifacts/usdom-finalized-burn.elf" "$snapshot_artifacts/usdom-finalized-burn.iid"

for name in finalized-burn-receipt.bin finalized-burn-composite-receipt.bin; do
  if [[ -e "$OUTPUT_DIR/$name" || -L "$OUTPUT_DIR/$name" ]]; then
    "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$OUTPUT_DIR/$name" > "$snapshot_output/$name"
    chmod 0600 "$snapshot_output/$name"
  fi
done
input_sha=$(sha256_file "$snapshot_jobs/finalized-burn-input.bin")
program_sha=$(sha256_file "$snapshot_artifacts/usdom-finalized-burn.elf")
if ! "$cmp_bin" -s "$snapshot_source/finalized-burn-input.bin" "$snapshot_jobs/finalized-burn-input.bin"; then
  printf '%s\n' 'Finalized-burn source differs from the exact planned proof input' >&2
  exit 1
fi
"$jq_bin" -e --arg input_sha "$input_sha" --arg program_sha "$program_sha" '
  .schema == "usdom-finalized-burn-proof-job-v1" and
  .source_input_path == "evidence/finalized-burn-source/finalized-burn-input.bin" and
  .input_file == "finalized-burn-input.bin" and
  .program_path == "evidence/finalized-burn-guest/usdom-finalized-burn.elf" and
  .image_id_path == "evidence/finalized-burn-guest/usdom-finalized-burn.iid" and
  .receipt_file == "finalized-burn-receipt.bin" and
  .source_input_sha256 == $input_sha and .input_sha256 == $input_sha and
  .program_sha256 == $program_sha and
  (.input_bytes | type == "number" and . > 0 and . <= 67108864) and
  .relation_executed == true and .generates_proofs == false and .mines == false
' "$snapshot_jobs/finalized-burn-proof-job-index.json" >/dev/null || {
  printf '%s\n' 'Finalized-burn proof-job index has a noncanonical path, hash or bound' >&2; exit 1; }
if (($(wc -c < "$snapshot_jobs/finalized-burn-input.bin") > 67108864 \
  || $(wc -c < "$snapshot_jobs/finalized-burn-proof-job-index.json") > 16384 \
  || $(wc -c < "$snapshot_statement/checkpoint-statement-v6.bin") > 65536 \
  || $(wc -c < "$snapshot_checkpoint_receipts/checkpoint-outer-receipt.bin") > 268435456 \
  || $(wc -c < "$snapshot_artifacts/usdom-finalized-burn.elf") > 4194304 \
  || $(wc -c < "$snapshot_artifacts/usdom-finalized-burn.iid") != 32)); then
  printf '%s\n' 'Finalized-burn proof input exceeds its fixed byte catalog' >&2
  exit 1
fi

assert_tool_unchanged cargo
source "$LAB_ROOT/scripts/require-risc0-program-binary.sh"
verify_risc0_program_binary "$cargo_bin" "$REPOSITORY_ROOT" \
  "$snapshot_artifacts/usdom-finalized-burn.elf" \
  f0d9c98287719bf6fca6626ab96f0b14e305662873a9e3b5d4894a50f206a1ae
require_risc0_recursion_artifact
cd "$SNAPSHOT_LAB"
reviewed_job_index="$SNAPSHOT_ROOT/reviewed-finalized-burn-job-index.json"
"$cp_bin" --reflink=never --no-preserve=mode,ownership,timestamps -- "$snapshot_jobs/finalized-burn-proof-job-index.json" "$reviewed_job_index"
rm -- "$snapshot_jobs/finalized-burn-proof-job-index.json" "$snapshot_jobs/finalized-burn-input.bin"
assert_tool_unchanged cargo; assert_tool_unchanged cp; assert_tool_unchanged node
"$cargo_bin" run --quiet --release --locked --manifest-path "$REPOSITORY_ROOT/Cargo.toml" -p dom-usdom-finalized-burn-proof-host --bin dom-usdom-plan-finalized-burn-proof
"$cmp_bin" -s "$reviewed_job_index" "$snapshot_jobs/finalized-burn-proof-job-index.json" || { printf '%s\n' 'Finalized-burn job index is not reproducible from snapshotted inputs' >&2; exit 1; }
"$cmp_bin" -s "$snapshot_source/finalized-burn-input.bin" "$snapshot_jobs/finalized-burn-input.bin" || { printf '%s\n' 'Rebuilt finalized-burn witness differs from private source' >&2; exit 1; }
critical="$SNAPSHOT_ROOT/finalized-burn-critical-inputs.sha256"
{
 "$sha256sum_bin" "$snapshot_source/finalized-burn-input.bin" "$snapshot_jobs/finalized-burn-input.bin" "$snapshot_jobs/finalized-burn-proof-job-index.json" "$snapshot_statement/checkpoint-statement-v6.bin" "$snapshot_checkpoint_receipts/checkpoint-outer-receipt.bin" "$snapshot_artifacts/usdom-finalized-burn.elf" "$snapshot_artifacts/usdom-finalized-burn.iid"
 for name in finalized-burn-receipt.bin finalized-burn-composite-receipt.bin; do [[ ! -e $snapshot_output/$name ]] || "$sha256sum_bin" "$snapshot_output/$name"; done
} > "$critical"
assert_tool_unchanged cargo; assert_tool_unchanged cmp; assert_tool_unchanged jq; assert_tool_unchanged node; assert_tool_unchanged env; assert_tool_unchanged sha256sum; assert_tool_unchanged stat
"$sha256sum_bin" -c "$critical" >/dev/null
"$env_bin" -u BONSAI_API_URL -u BONSAI_API_KEY -u RISC0_SERVER_PATH -u RISC0_SERVER_ADDR \
  -u RISC0_EXECUTOR -u RISC0_PPROF_OUT -u RISC0_PPROF_ENABLE_INLINE_FUNCTIONS \
  -u RISC0_KECCAK_PO2 -u RISC0_DEFAULT_PROVER_NUM_GPUS -u RISC0_INFO \
  -u RISC0_REDIS_CHANNEL_SIZE -u BONSAI_POLL_INTERVAL_MS \
  RAYON_NUM_THREADS=1 RISC0_PROVER=local RISC0_DEV_MODE=0 \
  "$cargo_bin" run --quiet --release --locked --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-usdom-finalized-burn-proof-host --features prove \
  --bin dom-usdom-prove-finalized-burn

completion_index="$snapshot_output/finalized-burn-receipt-index.json"
completion_record=$("$jq_bin" -er '
  select(.schema == "usdom-finalized-burn-receipt-v1") |
  select(.receipt_file == "finalized-burn-receipt.bin") |
  select(.receipt_sha256|type == "string" and test("^[0-9a-f]{64}$")) |
  select(.receipt_bytes|type == "number" and floor == . and . > 0 and . <= 268435456) |
  [.receipt_file,.receipt_sha256,(.receipt_bytes|tostring)] | @tsv
' "$completion_index")
IFS=$'\t' read -r completion_receipt completion_sha completion_bytes <<< "$completion_record"
[[ $completion_receipt == finalized-burn-receipt.bin && $("$stat_bin" -Lc '%s' "$snapshot_output/$completion_receipt") == "$completion_bytes" && $(sha256_file "$snapshot_output/$completion_receipt") == "$completion_sha" ]] || { printf '%s\n' 'Finalized-burn prover receipt does not match its completion index' >&2; exit 1; }

final_index="$OUTPUT_DIR/finalized-burn-receipt-index.json"
if [[ -e "$final_index" || -L "$final_index" ]]; then
 [[ -f "$final_index" && ! -L "$final_index" ]] || { printf '%s\n' 'Finalized-burn receipt index is not a direct regular file' >&2; exit 1; }
 rm -- "$final_index"; sync -d "$OUTPUT_DIR"
fi
installed_receipt="$OUTPUT_DIR/finalized-burn-receipt.bin"
if [[ -e "$installed_receipt" || -L "$installed_receipt" ]]; then
  [[ -f "$installed_receipt" && ! -L "$installed_receipt" ]] || {
    printf '%s\n' 'Finalized-burn receipt is not a direct regular file' >&2; exit 1; }
  rm -- "$installed_receipt"
  sync -d "$OUTPUT_DIR"
fi
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$snapshot_output/$completion_receipt" \
  | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$OUTPUT_DIR/$completion_receipt"
[[ $("$stat_bin" -Lc '%s' "$OUTPUT_DIR/$completion_receipt") == "$completion_bytes" && $(sha256_file "$OUTPUT_DIR/$completion_receipt") == "$completion_sha" ]] || { printf '%s\n' 'Published finalized-burn receipt failed integrity verification' >&2; exit 1; }
completion_index_sha=$(sha256_file "$completion_index")
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$completion_index" \
  | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$final_index"
[[ $(sha256_file "$final_index") == "$completion_index_sha" ]] || { printf '%s\n' 'Published finalized-burn completion index changed during installation' >&2; exit 1; }
[[ $("$stat_bin" -Lc '%s' "$OUTPUT_DIR/$completion_receipt") == "$completion_bytes" && $(sha256_file "$OUTPUT_DIR/$completion_receipt") == "$completion_sha" ]] || { printf '%s\n' 'Finalized-burn receipt changed before completion publication' >&2; exit 1; }
