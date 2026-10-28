#!/usr/bin/env bash
set -euo pipefail
umask 077

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
source "$LAB_ROOT/scripts/require-risc0-recursion-artifact.sh"
JOB_DIR="$LAB_ROOT/evidence/randomx-proof-jobs"
JOB_INDEX="$JOB_DIR/randomx-proof-job-index.json"
OUTPUT_DIR="$LAB_ROOT/evidence/randomx-receipt-set"
STATEMENT_DIR="$LAB_ROOT/evidence/randomx-statement-set"
STATEMENT_INDEX="$STATEMENT_DIR/randomx-statement-set-index.json"
SNAPSHOT_ROOT="$(mktemp -d "/dev/shm/usdom-randomx-prove.XXXXXX")"
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
  printf '%s\n' 'Usage: npm run --silent prove:authenticated-randomx-receipt-set' >&2
  exit 2
fi
for command in cargo cp jq mktemp node realpath stat sha256sum id dirname env; do
  command -v "$command" >/dev/null
done
pin_tool() {
  local name=${1} directory_identity_name="${1}_directory_identity" identity_name="${1}_identity" path owner mode size directory directory_owner directory_mode
  path=$(realpath "$(command -v "$name")")
  [[ -x $path && -f $path && ! -L $path ]]
  owner=$(stat -Lc '%u' "$path"); [[ $owner == 0 || $owner == "$(id -u)" ]]
  [[ $(stat -Lc '%h' "$path") == 1 ]]
  size=$(stat -Lc '%s' "$path"); (( size > 0 && size <= 512 * 1024 * 1024 ))
  mode=$(stat -Lc '%a' "$path"); (( (8#$mode & 8#022) == 0 ))
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
for command in cargo cp jq node env sha256sum stat; do pin_tool "$command"; done
if [[ ! -d "$JOB_DIR" || -L "$JOB_DIR" ]]; then
  printf 'Missing non-symlink RandomX proof-job directory: %s\n' "$JOB_DIR" >&2
  exit 1
fi
if [[ ! -f "$JOB_INDEX" || -L "$JOB_INDEX" ]]; then
  printf 'Missing non-symlink RandomX proof-job index: %s\n' "$JOB_INDEX" >&2
  exit 1
fi
if [[ ! -f "$STATEMENT_INDEX" || -L "$STATEMENT_INDEX" ]]; then
  printf 'Missing non-symlink RandomX statement-set index: %s\n' "$STATEMENT_INDEX" >&2
  exit 1
fi
mkdir -p -- "$OUTPUT_DIR"
if [[ -L "$OUTPUT_DIR" ]]; then
  printf '%s\n' 'RandomX receipt output directory cannot be a symlink' >&2
  exit 1
fi

snapshot_statements="$SNAPSHOT_LAB/evidence/randomx-statement-set"
snapshot_jobs="$SNAPSHOT_LAB/evidence/randomx-proof-jobs"
snapshot_receipts="$SNAPSHOT_LAB/evidence/randomx-receipt-set"
snapshot_artifacts="$SNAPSHOT_ROOT/repository/crates/dom-usdom-randomx-risc0-guest/elfs"
mkdir -p -- "$snapshot_statements" "$snapshot_jobs" "$snapshot_receipts" "$snapshot_artifacts"
chmod -R go-rwx -- "$SNAPSHOT_ROOT"
snapshot_job_index="$snapshot_jobs/randomx-proof-job-index.json"
snapshot_statement_index="$snapshot_statements/randomx-statement-set-index.json"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$JOB_INDEX" > "$snapshot_job_index"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$STATEMENT_INDEX" > "$snapshot_statement_index"
chmod 0600 "$snapshot_job_index" "$snapshot_statement_index"
mapfile -t statement_files < <("$jq_bin" -er '
  select(.schema == "usdom-randomx-proof-job-set-v1")
  | select(.job_count == (.jobs | length) and .job_count > 0 and .job_count <= 720)
  | [.jobs[].statement_file]
  | select(length == (unique | length))
  | .[] | select(test("^evidence/randomx-statement-set/randomx-statement-[0-9]{4}\\.bin$"))
' "$snapshot_job_index")
mapfile -t receipt_files < <("$jq_bin" -er '
  [.jobs[].receipt_file]
  | select(length > 0 and length <= 720 and length == (unique | length))
  | .[] | select(test("^randomx-receipt-[0-9]{4}\\.bin$"))
' "$snapshot_job_index")
if ((${#statement_files[@]} == 0 || ${#statement_files[@]} != ${#receipt_files[@]})); then
  printf '%s\n' 'RandomX proof-job index has a noncanonical job catalog' >&2
  exit 1
fi
for logical in "${statement_files[@]}"; do
  name=${logical##*/}
  "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$STATEMENT_DIR/$name" \
    > "$snapshot_statements/$name"
  chmod 0600 "$snapshot_statements/$name"
done
for name in "${receipt_files[@]}"; do
  if [[ -e "$OUTPUT_DIR/$name" || -L "$OUTPUT_DIR/$name" ]]; then
    "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$OUTPUT_DIR/$name" \
      > "$snapshot_receipts/$name"
    chmod 0600 "$snapshot_receipts/$name"
  fi
done
artifact_source="$REPOSITORY_ROOT/crates/dom-usdom-randomx-risc0-guest/elfs"
for name in usdom-randomx.elf usdom-randomx.bin usdom-randomx.iid; do
  [[ -f "$artifact_source/$name" && ! -L "$artifact_source/$name" ]]
  "$cp_bin" --reflink=never --no-preserve=mode,ownership,timestamps -- \
    "$artifact_source/$name" "$snapshot_artifacts/$name"
  chmod 0600 "$snapshot_artifacts/$name"
done

assert_tool_unchanged cargo
source "$LAB_ROOT/scripts/require-risc0-program-binary.sh"
verify_risc0_program_binary "$cargo_bin" "$REPOSITORY_ROOT" \
  "$snapshot_artifacts/usdom-randomx.bin" \
  8efa49d4fe0f616840013adb1d3029ef71642099cb336c577a2691f7eea1dc24
require_risc0_recursion_artifact
cd "$SNAPSHOT_LAB"
# Rebuild the deterministic job catalog from the snapshotted statement index.
# The prover never trusts a job index that cannot be reproduced from the same
# statement/ELF/IID/program inputs it is about to consume.
reviewed_job_index="$SNAPSHOT_ROOT/reviewed-randomx-proof-job-index.json"
"$cp_bin" --reflink=never --no-preserve=mode,ownership,timestamps -- \
  "$snapshot_job_index" "$reviewed_job_index"
rm -- "$snapshot_job_index"
assert_tool_unchanged cargo; assert_tool_unchanged node; assert_tool_unchanged jq
"$cargo_bin" run --quiet --locked \
  --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-usdom-randomx-proof-host \
  --bin dom-usdom-plan-randomx-receipt-set
cmp -s "$reviewed_job_index" "$snapshot_job_index" || {
  printf '%s\n' 'RandomX proof-job index is not reproducible from the snapshotted inputs' >&2
  exit 1
}

critical_snapshot="$SNAPSHOT_ROOT/randomx-critical-inputs.sha256"
{
  "$sha256sum_bin" "$snapshot_job_index" "$snapshot_statement_index"
  for logical in "${statement_files[@]}"; do "$sha256sum_bin" "$SNAPSHOT_LAB/$logical"; done
  "$sha256sum_bin" "$snapshot_artifacts/usdom-randomx.elf" \
    "$snapshot_artifacts/usdom-randomx.bin" "$snapshot_artifacts/usdom-randomx.iid"
} > "$critical_snapshot"
chmod 0600 "$critical_snapshot"
assert_tool_unchanged cargo; assert_tool_unchanged cp; assert_tool_unchanged jq
assert_tool_unchanged node; assert_tool_unchanged env
"$sha256sum_bin" -c "$critical_snapshot" >/dev/null
"$env_bin" \
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
  RAYON_NUM_THREADS=1 \
  RISC0_PROVER=local \
  RISC0_DEV_MODE=0 \
  "$cargo_bin" run --quiet --release --locked \
  --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-usdom-randomx-proof-host \
  --features prove \
  --bin dom-usdom-prove-randomx-receipt-set

snapshot_receipt_index="$snapshot_receipts/randomx-receipt-set-index.json"
final_index="$OUTPUT_DIR/randomx-receipt-set-index.json"
mapfile -t publication_records < <("$jq_bin" -er '
  select(.schema == "usdom-randomx-receipt-set-v1")
  | select(.receipt_count == (.receipts | length) and .receipt_count > 0 and .receipt_count <= 720)
  | [.receipts[].receipt_file] as $names
  | select(($names | length) == ($names | unique | length))
  | .receipts[]
  | select((.receipt_file | test("^randomx-receipt-[0-9]{4}\\.bin$"))
      and (.receipt_sha256 | test("^[0-9a-f]{64}$"))
      and (.receipt_bytes | type == "number" and . >= 1 and . <= 268435456))
  | [.receipt_file,.receipt_sha256,(.receipt_bytes|tostring)] | @tsv
' "$snapshot_receipt_index")
if ((${#publication_records[@]} != ${#receipt_files[@]})); then
  printf '%s\n' 'RandomX receipt index has a noncanonical publication catalog' >&2
  exit 1
fi
for ((record_index=0; record_index<${#publication_records[@]}; ++record_index)); do
  IFS=$'\t' read -r name _ _ <<< "${publication_records[$record_index]}"
  if [[ $name != "${receipt_files[$record_index]}" ]]; then
    printf '%s\n' 'RandomX receipt publication order differs from the reviewed proof jobs' >&2
    exit 1
  fi
done
if [[ -e "$final_index" || -L "$final_index" ]]; then
  [[ -f "$final_index" && ! -L "$final_index" ]]
  rm -- "$final_index"; sync -d "$OUTPUT_DIR"
fi
for record in "${publication_records[@]}"; do
  IFS=$'\t' read -r name expected_sha expected_bytes <<< "$record"
  "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$snapshot_receipts/$name" \
    | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$OUTPUT_DIR/$name"
  [[ $("$stat_bin" -Lc '%s' "$OUTPUT_DIR/$name") == "$expected_bytes" ]]
  [[ $(sha256_file "$OUTPUT_DIR/$name") == "$expected_sha" ]]
done
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$snapshot_receipt_index" \
  | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" \
    "$final_index"
[[ $(sha256_file "$final_index") == "$(sha256_file "$snapshot_receipt_index")" ]]
for record in "${publication_records[@]}"; do
  IFS=$'\t' read -r name expected_sha expected_bytes <<< "$record"
  [[ $("$stat_bin" -Lc '%s' "$OUTPUT_DIR/$name") == "$expected_bytes" ]]
  [[ $(sha256_file "$OUTPUT_DIR/$name") == "$expected_sha" ]]
done
assert_tool_unchanged node; assert_tool_unchanged jq
assert_tool_unchanged sha256sum; assert_tool_unchanged stat
