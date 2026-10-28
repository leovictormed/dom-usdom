#!/usr/bin/env bash
set -euo pipefail
umask 077

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
source "$LAB_ROOT/scripts/require-risc0-recursion-artifact.sh"
JOB_DIR="$LAB_ROOT/evidence/randomx-aggregate-jobs"
JOB_INDEX="$JOB_DIR/randomx-aggregate-job-index.json"
RECEIPT_DIR="$LAB_ROOT/evidence/randomx-receipt-set"
RECEIPT_INDEX="$RECEIPT_DIR/randomx-receipt-set-index.json"
SOURCE_DIR="$LAB_ROOT/evidence/checkpoint-source-set"
SOURCE_INDEX="$SOURCE_DIR/checkpoint-source-set-index.json"
OUTPUT_DIR="$LAB_ROOT/evidence/randomx-aggregate-receipt-set"
SNAPSHOT_ROOT="$(mktemp -d "/dev/shm/usdom-randomx-aggregate-prove.XXXXXX")"
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
SNAPSHOT_LAB="$SNAPSHOT_ROOT/repository/labs/usdom-reserve"

if (($# != 0)); then printf '%s\n' 'Usage: npm run --silent prove:authenticated-randomx-aggregate-set' >&2; exit 2; fi
for command in cargo cp jq node env realpath stat sha256sum id dirname find cmp; do command -v "$command" >/dev/null; done
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
  read -r output ignored < <("$sha256sum_bin" -- "$1")
  printf '%s\n' "$output"
}
for command in cargo cp jq node env find sha256sum stat; do pin_tool "$command"; done
for directory in "$JOB_DIR" "$RECEIPT_DIR" "$SOURCE_DIR"; do
  [[ -d $directory && ! -L $directory ]]
  [[ -z $("$find_bin" "$directory" -xdev -type l -print -quit) ]]
done
for index in "$JOB_INDEX" "$RECEIPT_INDEX" "$SOURCE_INDEX"; do [[ -f $index && ! -L $index ]]; done
mkdir -p -- "$OUTPUT_DIR" "$SNAPSHOT_LAB/evidence" \
  "$SNAPSHOT_ROOT/repository/crates/dom-usdom-randomx-aggregate-risc0-guest/elfs"
[[ ! -L $OUTPUT_DIR ]]
[[ -z $("$find_bin" "$OUTPUT_DIR" -xdev -type l -print -quit) ]]
for name in randomx-aggregate-jobs randomx-receipt-set checkpoint-source-set; do
  "$cp_bin" -R --reflink=never --no-preserve=mode,ownership,timestamps -- \
    "$LAB_ROOT/evidence/$name" "$SNAPSHOT_LAB/evidence/$name"
done
"$cp_bin" -R --reflink=never --no-preserve=mode,ownership,timestamps -- \
  "$OUTPUT_DIR" "$SNAPSHOT_LAB/evidence/randomx-aggregate-receipt-set"
artifact_source="$REPOSITORY_ROOT/crates/dom-usdom-randomx-aggregate-risc0-guest/elfs"
snapshot_artifacts="$SNAPSHOT_ROOT/repository/crates/dom-usdom-randomx-aggregate-risc0-guest/elfs"
for name in usdom-randomx-aggregate.elf usdom-randomx-aggregate.bin usdom-randomx-aggregate.iid; do
  [[ -f $artifact_source/$name && ! -L $artifact_source/$name ]]
  "$cp_bin" --reflink=never --no-preserve=mode,ownership,timestamps -- "$artifact_source/$name" "$snapshot_artifacts/$name"
done
chmod -R go-rwx -- "$SNAPSHOT_ROOT"
assert_tool_unchanged cargo
source "$LAB_ROOT/scripts/require-risc0-program-binary.sh"
verify_risc0_program_binary "$cargo_bin" "$REPOSITORY_ROOT" \
  "$snapshot_artifacts/usdom-randomx-aggregate.bin" \
  08abf768e699ecb9d5cd2abc7603368103bcd3ee61afe9066d8a77272ac02ebf
require_risc0_recursion_artifact
cd "$SNAPSHOT_LAB"
reviewed="$SNAPSHOT_ROOT/reviewed-randomx-aggregate-job-index.json"
"$cp_bin" --reflink=never --no-preserve=mode,ownership,timestamps -- \
  evidence/randomx-aggregate-jobs/randomx-aggregate-job-index.json "$reviewed"
rm -- evidence/randomx-aggregate-jobs/randomx-aggregate-job-index.json
assert_tool_unchanged cargo; assert_tool_unchanged node; assert_tool_unchanged cp
"$cargo_bin" run --quiet --locked --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-usdom-randomx-proof-host --features verify --bin dom-usdom-plan-randomx-aggregate-set
cmp -s "$reviewed" evidence/randomx-aggregate-jobs/randomx-aggregate-job-index.json || {
  printf '%s\n' 'RandomX aggregate job index is not reproducible from snapshotted inputs' >&2; exit 1; }
critical="$SNAPSHOT_ROOT/randomx-aggregate-critical-inputs.sha256"
while IFS= read -r -d '' file; do "$sha256sum_bin" "$file"; done \
  < <("$find_bin" evidence/randomx-aggregate-jobs evidence/randomx-receipt-set \
    evidence/checkpoint-source-set -xdev -type f -print0) > "$critical"
"$sha256sum_bin" "$snapshot_artifacts"/* >> "$critical"
assert_tool_unchanged cargo; assert_tool_unchanged cp; assert_tool_unchanged node
assert_tool_unchanged env; assert_tool_unchanged find
"$sha256sum_bin" -c "$critical" >/dev/null
"$env_bin" -u BONSAI_API_URL -u BONSAI_API_KEY -u RISC0_SERVER_PATH -u RISC0_SERVER_ADDR \
  -u RISC0_EXECUTOR -u RISC0_PPROF_OUT -u RISC0_PPROF_ENABLE_INLINE_FUNCTIONS \
  -u RISC0_KECCAK_PO2 -u RISC0_DEFAULT_PROVER_NUM_GPUS -u RISC0_INFO \
  -u RISC0_REDIS_CHANNEL_SIZE -u BONSAI_POLL_INTERVAL_MS RAYON_NUM_THREADS=1 \
  RISC0_PROVER=local RISC0_DEV_MODE=0 "$cargo_bin" run --quiet --release --locked \
  --manifest-path "$REPOSITORY_ROOT/Cargo.toml" -p dom-usdom-randomx-proof-host \
  --features prove --bin dom-usdom-prove-randomx-aggregate-set
snapshot_output="$SNAPSHOT_LAB/evidence/randomx-aggregate-receipt-set"
snapshot_index="$snapshot_output/randomx-aggregate-receipt-set-index.json"
final_index="$OUTPUT_DIR/randomx-aggregate-receipt-set-index.json"
[[ -f "$snapshot_index" && ! -L "$snapshot_index" ]]
mapfile -t publication_records < <("$jq_bin" -er '
  select(.schema == "usdom-randomx-aggregate-receipt-set-v1")
  | select(.receipt_count == (.receipts | length) and .receipt_count > 0 and .receipt_count <= 720)
  | [.receipts[].receipt_file] as $names
  | select(($names | length) == ($names | unique | length))
  | .receipts[]
  | select((.receipt_file | test("^randomx-aggregate-receipt-[0-9]{4}\\.bin$"))
      and (.receipt_sha256 | test("^[0-9a-f]{64}$"))
      and (.receipt_bytes | type == "number" and . >= 1 and . <= 268435456))
  | [.receipt_file,.receipt_sha256,(.receipt_bytes|tostring)] | @tsv
' "$snapshot_index")
if ((${#publication_records[@]} == 0)); then
  printf '%s\n' 'RandomX aggregate receipt index has a noncanonical publication catalog' >&2
  exit 1
fi
if [[ -e "$final_index" || -L "$final_index" ]]; then
  [[ -f "$final_index" && ! -L "$final_index" ]]
  rm -- "$final_index"; sync -d "$OUTPUT_DIR"
fi
for record in "${publication_records[@]}"; do
  IFS=$'\t' read -r name expected_sha expected_bytes <<< "$record"
  "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$snapshot_output/$name" | \
    "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$OUTPUT_DIR/$name"
  [[ $("$stat_bin" -Lc '%s' "$OUTPUT_DIR/$name") == "$expected_bytes" ]]
  [[ $(sha256_file "$OUTPUT_DIR/$name") == "$expected_sha" ]]
done
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$snapshot_index" | \
  "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$final_index"
[[ $(sha256_file "$final_index") == "$(sha256_file "$snapshot_index")" ]]
for record in "${publication_records[@]}"; do
  IFS=$'\t' read -r name expected_sha expected_bytes <<< "$record"
  [[ $("$stat_bin" -Lc '%s' "$OUTPUT_DIR/$name") == "$expected_bytes" ]]
  [[ $(sha256_file "$OUTPUT_DIR/$name") == "$expected_sha" ]]
done
assert_tool_unchanged node; assert_tool_unchanged jq
assert_tool_unchanged sha256sum; assert_tool_unchanged stat
