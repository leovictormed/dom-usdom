#!/usr/bin/env bash
set -euo pipefail
umask 077

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
source "$LAB_ROOT/scripts/require-risc0-recursion-artifact.sh"
JOB_DIR="$LAB_ROOT/evidence/finalized-burn-proof-job"
RECEIPT_DIR="$LAB_ROOT/evidence/finalized-burn-receipt"
ARTIFACT_DIR="$LAB_ROOT/evidence/finalized-burn-guest"
OUTPUT_DIR="$LAB_ROOT/evidence/finalized-burn-evm-proof"
SNAPSHOT_ROOT=''
SNAPSHOT_LAB=''
cleanup_snapshot() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  if [[ -n $SNAPSHOT_ROOT ]]; then
    [[ $SNAPSHOT_ROOT =~ ^/dev/shm/usdom-finalized-burn-evm\.[A-Za-z0-9]{6}$ && -d $SNAPSHOT_ROOT && ! -L $SNAPSHOT_ROOT ]] || exit 1
    assert_tool_unchanged rm; assert_tool_unchanged timeout
    "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$rm_bin" -rf -- "$SNAPSHOT_ROOT" || status=1
    [[ ! -e $SNAPSHOT_ROOT && ! -L $SNAPSHOT_ROOT ]] || status=1
  fi
  exit "$status"
}
trap 'cleanup_snapshot $?' EXIT; trap 'cleanup_snapshot 129' HUP; trap 'cleanup_snapshot 130' INT; trap 'cleanup_snapshot 143' TERM

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent package:authenticated-finalized-burn-evm-proof' >&2
  exit 2
fi
for command in cargo cut jq mkdir mktemp node sha256sum sync wc env realpath stat id dirname cmp rm timeout; do command -v "$command" >/dev/null; done
pin_tool() {
  local name=${1} identity_name="${1}_identity" directory_identity_name="${1}_directory_identity"
  local path owner mode size directory directory_owner directory_mode
  path=$(realpath "$(command -v "$name")"); [[ -x $path && -f $path && ! -L $path ]]
  owner=$(stat -Lc '%u' "$path"); [[ $owner == 0 || $owner == "$(id -u)" ]]
  [[ $(stat -Lc '%h' "$path") == 1 ]]
  size=$(stat -Lc '%s' "$path"); (( size > 0 && size <= 512 * 1024 * 1024 ))
  mode=$(stat -Lc '%a' "$path"); (( (8#$mode & 8#022) == 0 ))
  directory=$(dirname "$path"); [[ $(realpath "$directory") == "$directory" ]]
  directory_owner=$(stat -Lc '%u' "$directory"); [[ $directory_owner == 0 || $directory_owner == "$(id -u)" ]]
  directory_mode=$(stat -Lc '%a' "$directory"); (( (8#$directory_mode & 8#022) == 0 ))
  printf -v "${name}_directory_identity" '%s' "$(stat -Lc '%d:%i:%u:%a' "$directory")"
  printf -v "${name}_bin" '%s' "$path"
  printf -v "${name}_identity" '%s' "$(stat -Lc '%d:%i:%s:%Y:%Z' "$path")"
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
for command in cargo jq node env mktemp stat id sha256sum mkdir rm timeout sync; do pin_tool "$command"; done
SNAPSHOT_ROOT="$("$mktemp_bin" -d "/dev/shm/usdom-finalized-burn-evm.XXXXXX")"
[[ $SNAPSHOT_ROOT == /dev/shm/usdom-finalized-burn-evm.* && -d $SNAPSHOT_ROOT && ! -L $SNAPSHOT_ROOT ]]
[[ $("$stat_bin" -Lc '%F:%u:%a:%h' "$SNAPSHOT_ROOT") == "directory:$("$id_bin" -u):700:2" ]]
SNAPSHOT_LAB="$SNAPSHOT_ROOT/repository/labs/usdom-reserve"
assert_private_file() {
  local file=${1-}
  [[ -f $file && ! -L $file ]]
  [[ $("$stat_bin" -Lc '%F:%u:%a:%h' "$file") == "regular file:$("$id_bin" -u):600:1" ]]
}
remove_output_file() {
  local file=${1-}
  case $file in
    "$OUTPUT_DIR/finalized-burn-evm-proof-index.json"|"$OUTPUT_DIR/finalized-burn-groth16-receipt.bin"|"$OUTPUT_DIR/finalized-burn-evm-seal.bin") ;;
    *) return 1 ;;
  esac
  [[ -f $file && ! -L $file ]]
  assert_tool_unchanged rm; assert_tool_unchanged timeout
  "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$rm_bin" -- "$file"
  [[ ! -e $file && ! -L $file ]]
}
sync_output_directory() {
  local before after
  [[ -d $OUTPUT_DIR && ! -L $OUTPUT_DIR ]]
  before=$("$stat_bin" -Lc '%d:%i:%u:%a:%h' -- "$OUTPUT_DIR")
  assert_tool_unchanged sync; assert_tool_unchanged timeout
  "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$sync_bin" -d "$OUTPUT_DIR"
  assert_tool_unchanged sync
  after=$("$stat_bin" -Lc '%d:%i:%u:%a:%h' -- "$OUTPUT_DIR")
  test "$before" = "$after"
}
snapshot_file_size() {
  local file=${1-} before size after
  [[ $file == "$SNAPSHOT_ROOT/"* ]]
  assert_private_file "$file"
  assert_tool_unchanged stat; assert_tool_unchanged timeout
  before=$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$stat_bin" -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h' -- "$file")
  size=$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$stat_bin" -Lc '%s' -- "$file")
  after=$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$stat_bin" -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h' -- "$file")
  test "$before" = "$after"
  [[ $size =~ ^(0|[1-9][0-9]{0,19})$ ]]
  printf '%s' "$size"
}
snapshot_sha256() {
  local file=${1-} maximum=${2-} size before digest after
  [[ $file == "$SNAPSHOT_ROOT/"* && $maximum =~ ^[1-9][0-9]{0,9}$ ]]
  assert_private_file "$file"
  size=$(snapshot_file_size "$file"); (( size <= maximum ))
  assert_tool_unchanged node; assert_tool_unchanged timeout
  before=$("$stat_bin" -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h' -- "$file")
  digest=$("$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$node_bin" -e \
    'const fs=require("fs"),c=require("crypto"),p=process.argv[1],m=Number(process.argv[2]),b=fs.readFileSync(p);if(!Number.isSafeInteger(m)||b.length>m)process.exit(1);process.stdout.write(c.createHash("sha256").update(b).digest("hex"))' \
    "$file" "$maximum")
  after=$("$stat_bin" -Lc '%d:%i:%s:%Y:%Z:%u:%a:%h' -- "$file")
  test "$before" = "$after"
  [[ $digest =~ ^[0-9a-f]{64}$ ]]
  printf '%s' "$digest"
}
for directory in "$JOB_DIR" "$RECEIPT_DIR" "$ARTIFACT_DIR"; do
  [[ -d "$directory" && ! -L "$directory" ]] || {
    printf 'Missing direct finalized-burn EVM-package input directory: %s\n' "$directory" >&2; exit 1; }
done
for input in "$JOB_DIR/finalized-burn-input.bin" \
  "$JOB_DIR/finalized-burn-proof-job-index.json" \
  "$RECEIPT_DIR/finalized-burn-receipt-index.json" \
  "$RECEIPT_DIR/finalized-burn-receipt.bin" \
  "$ARTIFACT_DIR/usdom-finalized-burn.elf" \
  "$ARTIFACT_DIR/usdom-finalized-burn.iid"; do
  [[ -f "$input" && ! -L "$input" ]] || {
    printf 'Missing direct finalized-burn EVM-package input: %s\n' "$input" >&2; exit 1; }
done
snapshot_jobs="$SNAPSHOT_LAB/evidence/finalized-burn-proof-job"
snapshot_receipts="$SNAPSHOT_LAB/evidence/finalized-burn-receipt"
snapshot_artifacts="$SNAPSHOT_LAB/evidence/finalized-burn-guest"
snapshot_output="$SNAPSHOT_LAB/evidence/finalized-burn-evm-proof"
assert_tool_unchanged mkdir; assert_tool_unchanged timeout
"$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$mkdir_bin" -p -- \
  "$OUTPUT_DIR" "$snapshot_jobs" "$snapshot_receipts" "$snapshot_artifacts" "$snapshot_output"
assert_tool_unchanged mkdir
[[ $("$stat_bin" -Lc '%F:%u:%a' -- "$OUTPUT_DIR") == "directory:$("$id_bin" -u):700" ]]
for private_directory in "$snapshot_jobs" "$snapshot_receipts" "$snapshot_artifacts" "$snapshot_output"; do
  [[ $("$stat_bin" -Lc '%F:%u:%a' -- "$private_directory") == "directory:$("$id_bin" -u):700" ]]
done
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$JOB_DIR/finalized-burn-input.bin" > "$snapshot_jobs/finalized-burn-input.bin"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$JOB_DIR/finalized-burn-proof-job-index.json" > "$snapshot_jobs/finalized-burn-proof-job-index.json"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$RECEIPT_DIR/finalized-burn-receipt.bin" > "$snapshot_receipts/finalized-burn-receipt.bin"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$RECEIPT_DIR/finalized-burn-receipt-index.json" > "$snapshot_receipts/finalized-burn-receipt-index.json"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$ARTIFACT_DIR/usdom-finalized-burn.elf" > "$snapshot_artifacts/usdom-finalized-burn.elf"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$ARTIFACT_DIR/usdom-finalized-burn.iid" > "$snapshot_artifacts/usdom-finalized-burn.iid"
for private_input in "$snapshot_jobs"/* "$snapshot_receipts"/* "$snapshot_artifacts"/*; do
  assert_private_file "$private_input"
done
if [[ -e "$OUTPUT_DIR/finalized-burn-groth16-receipt.bin" || -L "$OUTPUT_DIR/finalized-burn-groth16-receipt.bin" ]]; then
  "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" \
    "$OUTPUT_DIR/finalized-burn-groth16-receipt.bin" \
    > "$snapshot_output/finalized-burn-groth16-receipt.bin"
  assert_private_file "$snapshot_output/finalized-burn-groth16-receipt.bin"
fi

job_sha=$(snapshot_sha256 "$snapshot_jobs/finalized-burn-proof-job-index.json" 16384)
input_sha=$(snapshot_sha256 "$snapshot_jobs/finalized-burn-input.bin" 67108864)
receipt_sha=$(snapshot_sha256 "$snapshot_receipts/finalized-burn-receipt.bin" 268435456)
receipt_index_sha=$(snapshot_sha256 "$snapshot_receipts/finalized-burn-receipt-index.json" 16384)
program_sha=$(snapshot_sha256 "$snapshot_artifacts/usdom-finalized-burn.elf" 4194304)
"$jq_bin" -e --arg job_sha "$job_sha" --arg input_sha "$input_sha" \
  --arg receipt_sha "$receipt_sha" --arg program_sha "$program_sha" '
  .schema == "usdom-finalized-burn-receipt-v1" and
  .proof_job_index_path == "evidence/finalized-burn-proof-job/finalized-burn-proof-job-index.json" and
  .proof_job_index_sha256 == $job_sha and
  .input_path == "evidence/finalized-burn-proof-job/finalized-burn-input.bin" and
  .input_sha256 == $input_sha and
  .program_path == "evidence/finalized-burn-guest/usdom-finalized-burn.elf" and
  .program_sha256 == $program_sha and
  .receipt_file == "finalized-burn-receipt.bin" and
  .receipt_sha256 == $receipt_sha and
  (.receipt_bytes | type == "number" and . > 0 and . <= 268435456) and
  .receipt_verified == true and .dev_mode == false and .generates_proofs == true and .mines == false
' "$snapshot_receipts/finalized-burn-receipt-index.json" >/dev/null || {
  printf '%s\n' 'Finalized-burn receipt catalog has a noncanonical path, hash or bound' >&2; exit 1; }
if (($(snapshot_file_size "$snapshot_jobs/finalized-burn-input.bin") > 67108864 \
  || $(snapshot_file_size "$snapshot_jobs/finalized-burn-proof-job-index.json") > 16384 \
  || $(snapshot_file_size "$snapshot_receipts/finalized-burn-receipt.bin") > 268435456 \
  || $(snapshot_file_size "$snapshot_receipts/finalized-burn-receipt-index.json") > 16384 \
  || $(snapshot_file_size "$snapshot_artifacts/usdom-finalized-burn.elf") > 4194304 \
  || $(snapshot_file_size "$snapshot_artifacts/usdom-finalized-burn.iid") != 32)); then
  printf '%s\n' 'Finalized-burn EVM-package input exceeds its fixed byte catalog' >&2
  exit 1
fi

require_risc0_recursion_artifact
cd "$SNAPSHOT_LAB"
critical="$SNAPSHOT_ROOT/finalized-burn-evm-critical-inputs.sha256"
assert_tool_unchanged sha256sum; assert_tool_unchanged timeout
{
 "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$sha256sum_bin" \
   "$snapshot_jobs/finalized-burn-input.bin" "$snapshot_jobs/finalized-burn-proof-job-index.json" \
   "$snapshot_receipts/finalized-burn-receipt.bin" "$snapshot_receipts/finalized-burn-receipt-index.json" \
   "$snapshot_artifacts/usdom-finalized-burn.elf" "$snapshot_artifacts/usdom-finalized-burn.iid"
 [[ ! -e $snapshot_output/finalized-burn-groth16-receipt.bin ]] || \
   "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$sha256sum_bin" \
     "$snapshot_output/finalized-burn-groth16-receipt.bin"
} > "$critical"
assert_tool_unchanged cargo; assert_tool_unchanged jq; assert_tool_unchanged node; assert_tool_unchanged env
assert_tool_unchanged sha256sum; assert_tool_unchanged timeout
"$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$sha256sum_bin" -c "$critical" >/dev/null
assert_tool_unchanged sha256sum
"$env_bin" -u BONSAI_API_URL -u BONSAI_API_KEY -u RISC0_SERVER_PATH -u RISC0_SERVER_ADDR \
  -u RISC0_EXECUTOR -u RISC0_PPROF_OUT -u RISC0_PPROF_ENABLE_INLINE_FUNCTIONS \
  -u RISC0_KECCAK_PO2 -u RISC0_DEFAULT_PROVER_NUM_GPUS -u RISC0_INFO \
  -u RISC0_REDIS_CHANNEL_SIZE -u BONSAI_POLL_INTERVAL_MS \
  RAYON_NUM_THREADS=1 RISC0_PROVER=local RISC0_DEV_MODE=0 \
  "$cargo_bin" run --quiet --release --locked --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-usdom-finalized-burn-proof-host --features prove \
  --bin dom-usdom-package-finalized-burn-evm-proof

completion_index="$snapshot_output/finalized-burn-evm-proof-index.json"
completion_record=$("$jq_bin" -er --arg receipt_index_sha "$receipt_index_sha" '
  select(.schema == "usdom-finalized-burn-evm-proof-v1") |
  select(.receipt_index_path == "evidence/finalized-burn-receipt/finalized-burn-receipt-index.json") |
  select(.receipt_index_sha256 == $receipt_index_sha) |
  select(.groth16_receipt_file == "finalized-burn-groth16-receipt.bin") |
  select(.evm_seal_file == "finalized-burn-evm-seal.bin") |
  select(.groth16_receipt_sha256|type == "string" and test("^[0-9a-f]{64}$")) |
  select(.evm_seal_sha256|type == "string" and test("^[0-9a-f]{64}$")) |
  select(.groth16_receipt_bytes|type == "number" and floor == . and . > 0 and . <= 268435456) |
  select(.evm_seal_bytes|type == "number" and floor == . and . > 0 and . <= 268435456) |
  select(.receipt_verified == true and .dev_mode == false and .generates_proofs == true and .mines == false) |
  [.groth16_receipt_file,.groth16_receipt_sha256,(.groth16_receipt_bytes|tostring),.evm_seal_file,.evm_seal_sha256,(.evm_seal_bytes|tostring)] | @tsv
' "$completion_index")
IFS=$'\t' read -r groth_name groth_sha groth_bytes seal_name seal_sha seal_bytes <<< "$completion_record"
[[ $(snapshot_file_size "$snapshot_output/$groth_name") == "$groth_bytes" && $(snapshot_sha256 "$snapshot_output/$groth_name" 268435456) == "$groth_sha" ]] || { printf '%s\n' 'Finalized-burn Groth16 receipt does not match its completion index' >&2; exit 1; }
[[ $(snapshot_file_size "$snapshot_output/$seal_name") == "$seal_bytes" && $(snapshot_sha256 "$snapshot_output/$seal_name" 268435456) == "$seal_sha" ]] || { printf '%s\n' 'Finalized-burn EVM seal does not match its completion index' >&2; exit 1; }

final_index="$OUTPUT_DIR/finalized-burn-evm-proof-index.json"
if [[ -e "$final_index" || -L "$final_index" ]]; then
 [[ -f "$final_index" && ! -L "$final_index" ]] || { printf '%s\n' 'Finalized-burn EVM-proof index is not a direct regular file' >&2; exit 1; }
 remove_output_file "$final_index"; sync_output_directory
fi
for record in "$groth_name"$'\t'"$groth_sha"$'\t'"$groth_bytes" "$seal_name"$'\t'"$seal_sha"$'\t'"$seal_bytes"; do
  IFS=$'\t' read -r name artifact_sha artifact_bytes <<< "$record"
  destination="$OUTPUT_DIR/$name"
  if [[ -e "$destination" || -L "$destination" ]]; then
    [[ -f "$destination" && ! -L "$destination" ]] || {
      printf 'Finalized-burn EVM-proof output is not a direct regular file: %s\n' "$destination" >&2; exit 1; }
    remove_output_file "$destination"
  fi
  "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$snapshot_output/$name" \
    | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$destination"
  [[ $("$stat_bin" -Lc '%s' "$destination") == "$artifact_bytes" && $(sha256_file "$destination") == "$artifact_sha" ]] || { printf '%s\n' 'Published finalized-burn EVM artifact failed integrity verification' >&2; exit 1; }
done
sync_output_directory
completion_index_sha=$(sha256_file "$completion_index")
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" \
  "$completion_index" \
  | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" \
    "$final_index"
[[ $(sha256_file "$final_index") == "$completion_index_sha" ]] || { printf '%s\n' 'Published finalized-burn EVM completion index changed during installation' >&2; exit 1; }
for record in "$groth_name"$'\t'"$groth_sha"$'\t'"$groth_bytes" "$seal_name"$'\t'"$seal_sha"$'\t'"$seal_bytes"; do
  IFS=$'\t' read -r name artifact_sha artifact_bytes <<< "$record"
  destination="$OUTPUT_DIR/$name"
  [[ $("$stat_bin" -Lc '%s' "$destination") == "$artifact_bytes" && $(sha256_file "$destination") == "$artifact_sha" ]] || { printf '%s\n' 'Finalized-burn EVM artifact changed before completion publication' >&2; exit 1; }
done
