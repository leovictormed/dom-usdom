#!/usr/bin/env bash
set -euo pipefail
umask 077

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
source "$LAB_ROOT/scripts/require-risc0-recursion-artifact.sh"
JOB_DIR="$LAB_ROOT/evidence/economic-proof-jobs"
JOB_INDEX="$JOB_DIR/economic-proof-job-index.json"
OUTPUT_DIR="$LAB_ROOT/evidence/economic-receipt-set"
SOURCE_DIR="$LAB_ROOT/evidence/checkpoint-source-set"
SOURCE_INDEX="$SOURCE_DIR/checkpoint-source-set-index.json"
ECONOMIC_INDEX="$SOURCE_DIR/checkpoint-economic-source-set-index.json"
SNAPSHOT_ROOT="$(mktemp -d "/dev/shm/usdom-economic-prove.XXXXXX")"
chmod 0700 "$SNAPSHOT_ROOT"
SNAPSHOT_LAB="$SNAPSHOT_ROOT/repository/labs/usdom-reserve"
trap 'rm -rf -- "$SNAPSHOT_ROOT"' EXIT HUP INT TERM

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent prove:authenticated-economic-receipt-set' >&2
  exit 2
fi
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
  printf -v "${name}_bin" '%s' "$path"
  printf -v "${name}_identity" '%s' "$(stat -Lc '%d:%i:%s:%Y:%Z' "$path")"
  printf -v "${name}_sha256" '%s' "$(sha256sum "$path" | awk '{print $NF}')"
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" ]]
  [[ $(stat -Lc '%d:%i:%u:%a' "$directory") == "${!directory_identity_name}" ]]
}
assert_tool_unchanged() {
  local name=${1} bin_name="${1}_bin" identity_name="${1}_identity" sha_name="${1}_sha256" directory_identity_name="${1}_directory_identity"
  local path=${!bin_name} identity=${!identity_name} sha=${!sha_name} directory
  directory=$(dirname "$path")
  [[ $(realpath "$directory") == "$directory" ]]
  [[ $(stat -Lc '%d:%i:%u:%a' "$directory") == "${!directory_identity_name}" ]]
  [[ $(realpath "$(command -v "$name")") == "$path" ]]
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "$identity" ]]
  [[ $(sha256sum "$path" | awk '{print $NF}') == "$sha" ]]
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "$identity" ]]
  [[ $(stat -Lc '%d:%i:%u:%a' "$directory") == "${!directory_identity_name}" ]]
}
for command in cargo cp jq node env; do pin_tool "$command"; done
if [[ ! -d "$JOB_DIR" || -L "$JOB_DIR" ]]; then
  printf 'Missing non-symlink economic proof-job directory: %s\n' "$JOB_DIR" >&2
  exit 1
fi
for index in "$SOURCE_INDEX" "$ECONOMIC_INDEX"; do
  [[ -f "$index" && ! -L "$index" ]] || { printf 'Missing economic source index: %s\n' "$index" >&2; exit 1; }
done
if [[ ! -f "$JOB_INDEX" || -L "$JOB_INDEX" ]]; then
  printf 'Missing non-symlink economic proof-job index: %s\n' "$JOB_INDEX" >&2
  exit 1
fi
mkdir -p -- "$OUTPUT_DIR"
if [[ -L "$OUTPUT_DIR" ]]; then
  printf '%s\n' 'Economic receipt output directory cannot be a symlink' >&2
  exit 1
fi

snapshot_source="$SNAPSHOT_LAB/evidence/checkpoint-source-set"
snapshot_jobs="$SNAPSHOT_LAB/evidence/economic-proof-jobs"
snapshot_receipts="$SNAPSHOT_LAB/evidence/economic-receipt-set"
chunk_artifacts="$SNAPSHOT_ROOT/repository/crates/dom-usdom-economic-chunk-risc0-guest/elfs"
block_artifacts="$SNAPSHOT_ROOT/repository/crates/dom-usdom-economic-block-risc0-guest/elfs"
mkdir -p -- "$snapshot_source" "$snapshot_jobs" "$snapshot_receipts" \
  "$chunk_artifacts" "$block_artifacts"
chmod -R go-rwx -- "$SNAPSHOT_ROOT"
snapshot_job_index="$snapshot_jobs/economic-proof-job-index.json"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$JOB_INDEX" > "$snapshot_job_index"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$SOURCE_INDEX" \
  > "$snapshot_source/checkpoint-source-set-index.json"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$ECONOMIC_INDEX" \
  > "$snapshot_source/checkpoint-economic-source-set-index.json"
chmod 0600 "$snapshot_job_index" "$snapshot_source"/*.json
mapfile -t source_files < <("$jq_bin" -r '
  [.chunk_jobs[].package_source_file, .chunk_jobs[].transition_file,
   .chunk_jobs[].witness_file, .block_jobs[].transition_file]
  | unique | .[]
  | select(test("^evidence/checkpoint-source-set/checkpoint-segment-[0-9]{4}-(private-input|economic-block-[0-9]{4}-(transition|chunk-[0-9]{4}-(transition|witness)))\\.bin$"))
' "$snapshot_job_index")
mapfile -t receipt_files < <("$jq_bin" -r '
  [.chunk_jobs[].receipt_file, .block_jobs[].receipt_file]
  | select(length > 0 and length == (unique | length)) | .[]
  | select(test("^economic-(chunk|block)-receipt-[0-9]{4}\\.bin$"))
' "$snapshot_job_index")
if ((${#source_files[@]} == 0 || ${#receipt_files[@]} == 0)); then
  printf '%s\n' 'Economic job index has a noncanonical source or receipt catalog' >&2
  exit 1
fi
for logical in "${source_files[@]}"; do
  name=${logical##*/}
  "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$SOURCE_DIR/$name" > "$snapshot_source/$name"
  chmod 0600 "$snapshot_source/$name"
done
for name in "${receipt_files[@]}"; do
  if [[ -e "$OUTPUT_DIR/$name" || -L "$OUTPUT_DIR/$name" ]]; then
    "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$OUTPUT_DIR/$name" > "$snapshot_receipts/$name"
    chmod 0600 "$snapshot_receipts/$name"
  fi
done
for guest in chunk block; do
  source_artifacts="$REPOSITORY_ROOT/crates/dom-usdom-economic-${guest}-risc0-guest/elfs"
  destination="$SNAPSHOT_ROOT/repository/crates/dom-usdom-economic-${guest}-risc0-guest/elfs"
  for extension in elf bin iid; do
    name="usdom-economic-${guest}.${extension}"
    [[ -f "$source_artifacts/$name" && ! -L "$source_artifacts/$name" ]]
    "$cp_bin" --reflink=never --no-preserve=mode,ownership,timestamps -- "$source_artifacts/$name" "$destination/$name"
    chmod 0600 "$destination/$name"
  done
done

assert_tool_unchanged cargo
source "$LAB_ROOT/scripts/require-risc0-program-binary.sh"
verify_risc0_program_binary "$cargo_bin" "$REPOSITORY_ROOT" \
  "$chunk_artifacts/usdom-economic-chunk.bin" \
  67d286e04444b52305ec409de3c0d22b2131a42f2aa6706f087ace253048e350
verify_risc0_program_binary "$cargo_bin" "$REPOSITORY_ROOT" \
  "$block_artifacts/usdom-economic-block.bin" \
  03dc111fee3c42a772f142c80d4a921a19bde10f932f86c888606503a28c22a7
require_risc0_recursion_artifact
cd "$SNAPSHOT_LAB"
reviewed_job_index="$SNAPSHOT_ROOT/reviewed-economic-proof-job-index.json"
"$cp_bin" --reflink=never --no-preserve=mode,ownership,timestamps -- \
  "$snapshot_job_index" "$reviewed_job_index"
rm -- "$snapshot_job_index"
assert_tool_unchanged cargo; assert_tool_unchanged cp; assert_tool_unchanged node
"$cargo_bin" run --quiet --locked --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-usdom-economic-proof-host --bin dom-usdom-plan-economic-receipt-set
cmp -s "$reviewed_job_index" "$snapshot_job_index" || {
  printf '%s\n' 'Economic proof-job index is not reproducible from snapshotted inputs' >&2; exit 1; }
critical_snapshot="$SNAPSHOT_ROOT/economic-critical-inputs.sha256"
{
  sha256sum "$snapshot_job_index" "$snapshot_source"/*.json
  for logical in "${source_files[@]}"; do sha256sum "$SNAPSHOT_LAB/$logical"; done
  sha256sum "$chunk_artifacts"/* "$block_artifacts"/*
  for name in "${receipt_files[@]}"; do [[ ! -e $snapshot_receipts/$name ]] || sha256sum "$snapshot_receipts/$name"; done
} > "$critical_snapshot"
assert_tool_unchanged cargo; assert_tool_unchanged cp; assert_tool_unchanged jq
assert_tool_unchanged node; assert_tool_unchanged env
sha256sum -c "$critical_snapshot" >/dev/null
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
  -p dom-usdom-economic-proof-host \
  --features prove \
  --bin dom-usdom-prove-economic-receipt-set

final_index="$OUTPUT_DIR/economic-receipt-set-index.json"
if [[ -e "$final_index" || -L "$final_index" ]]; then
  [[ -f "$final_index" && ! -L "$final_index" ]]
  rm -- "$final_index"; sync -d "$OUTPUT_DIR"
fi
for name in "${receipt_files[@]}"; do
  "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$snapshot_receipts/$name" \
    | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$OUTPUT_DIR/$name"
done
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" \
  "$snapshot_receipts/economic-receipt-set-index.json" \
  | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" \
    "$final_index"
