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
SNAPSHOT_ROOT="$(mktemp -d "/dev/shm/usdom-finalized-burn-evm.XXXXXX")"
chmod 0700 "$SNAPSHOT_ROOT"
SNAPSHOT_LAB="$SNAPSHOT_ROOT/repository/labs/usdom-reserve"
trap 'rm -rf -- "$SNAPSHOT_ROOT"' EXIT HUP INT TERM

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent package:authenticated-finalized-burn-evm-proof' >&2
  exit 2
fi
for command in cargo cut jq mktemp node sha256sum sync wc env realpath stat id dirname cmp; do command -v "$command" >/dev/null; done
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
for command in cargo jq node env; do pin_tool "$command"; done
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
mkdir -p -- "$OUTPUT_DIR"
[[ ! -L "$OUTPUT_DIR" ]] || { printf '%s\n' 'Finalized-burn EVM-proof output directory cannot be a symlink' >&2; exit 1; }

snapshot_jobs="$SNAPSHOT_LAB/evidence/finalized-burn-proof-job"
snapshot_receipts="$SNAPSHOT_LAB/evidence/finalized-burn-receipt"
snapshot_artifacts="$SNAPSHOT_LAB/evidence/finalized-burn-guest"
snapshot_output="$SNAPSHOT_LAB/evidence/finalized-burn-evm-proof"
mkdir -p -- "$snapshot_jobs" "$snapshot_receipts" "$snapshot_artifacts" "$snapshot_output"
chmod -R go-rwx -- "$SNAPSHOT_ROOT"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$JOB_DIR/finalized-burn-input.bin" > "$snapshot_jobs/finalized-burn-input.bin"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$JOB_DIR/finalized-burn-proof-job-index.json" > "$snapshot_jobs/finalized-burn-proof-job-index.json"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$RECEIPT_DIR/finalized-burn-receipt.bin" > "$snapshot_receipts/finalized-burn-receipt.bin"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$RECEIPT_DIR/finalized-burn-receipt-index.json" > "$snapshot_receipts/finalized-burn-receipt-index.json"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$ARTIFACT_DIR/usdom-finalized-burn.elf" > "$snapshot_artifacts/usdom-finalized-burn.elf"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$ARTIFACT_DIR/usdom-finalized-burn.iid" > "$snapshot_artifacts/usdom-finalized-burn.iid"
chmod 0600 "$snapshot_jobs"/* "$snapshot_receipts"/* "$snapshot_artifacts"/*
if [[ -e "$OUTPUT_DIR/finalized-burn-groth16-receipt.bin" || -L "$OUTPUT_DIR/finalized-burn-groth16-receipt.bin" ]]; then
  "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" \
    "$OUTPUT_DIR/finalized-burn-groth16-receipt.bin" \
    > "$snapshot_output/finalized-burn-groth16-receipt.bin"
  chmod 0600 "$snapshot_output/finalized-burn-groth16-receipt.bin"
fi

job_sha=$(sha256sum "$snapshot_jobs/finalized-burn-proof-job-index.json" | cut -d ' ' -f 1)
input_sha=$(sha256sum "$snapshot_jobs/finalized-burn-input.bin" | cut -d ' ' -f 1)
receipt_sha=$(sha256sum "$snapshot_receipts/finalized-burn-receipt.bin" | cut -d ' ' -f 1)
program_sha=$(sha256sum "$snapshot_artifacts/usdom-finalized-burn.elf" | cut -d ' ' -f 1)
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
if (($(wc -c < "$snapshot_jobs/finalized-burn-input.bin") > 67108864 \
  || $(wc -c < "$snapshot_jobs/finalized-burn-proof-job-index.json") > 16384 \
  || $(wc -c < "$snapshot_receipts/finalized-burn-receipt.bin") > 268435456 \
  || $(wc -c < "$snapshot_receipts/finalized-burn-receipt-index.json") > 16384 \
  || $(wc -c < "$snapshot_artifacts/usdom-finalized-burn.elf") > 4194304 \
  || $(wc -c < "$snapshot_artifacts/usdom-finalized-burn.iid") != 32)); then
  printf '%s\n' 'Finalized-burn EVM-package input exceeds its fixed byte catalog' >&2
  exit 1
fi

require_risc0_recursion_artifact
cd "$SNAPSHOT_LAB"
critical="$SNAPSHOT_ROOT/finalized-burn-evm-critical-inputs.sha256"
{
 sha256sum "$snapshot_jobs/finalized-burn-input.bin" "$snapshot_jobs/finalized-burn-proof-job-index.json" "$snapshot_receipts/finalized-burn-receipt.bin" "$snapshot_receipts/finalized-burn-receipt-index.json" "$snapshot_artifacts/usdom-finalized-burn.elf" "$snapshot_artifacts/usdom-finalized-burn.iid"
 [[ ! -e $snapshot_output/finalized-burn-groth16-receipt.bin ]] || sha256sum "$snapshot_output/finalized-burn-groth16-receipt.bin"
} > "$critical"
assert_tool_unchanged cargo; assert_tool_unchanged jq; assert_tool_unchanged node; assert_tool_unchanged env
sha256sum -c "$critical" >/dev/null
"$env_bin" -u BONSAI_API_URL -u BONSAI_API_KEY -u RISC0_SERVER_PATH -u RISC0_SERVER_ADDR \
  -u RISC0_EXECUTOR -u RISC0_PPROF_OUT -u RISC0_PPROF_ENABLE_INLINE_FUNCTIONS \
  -u RISC0_KECCAK_PO2 -u RISC0_DEFAULT_PROVER_NUM_GPUS -u RISC0_INFO \
  -u RISC0_REDIS_CHANNEL_SIZE -u BONSAI_POLL_INTERVAL_MS \
  RAYON_NUM_THREADS=1 RISC0_PROVER=local RISC0_DEV_MODE=0 \
  "$cargo_bin" run --quiet --release --locked --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-usdom-finalized-burn-proof-host --features prove \
  --bin dom-usdom-package-finalized-burn-evm-proof

final_index="$OUTPUT_DIR/finalized-burn-evm-proof-index.json"
if [[ -e "$final_index" || -L "$final_index" ]]; then
 [[ -f "$final_index" && ! -L "$final_index" ]] || { printf '%s\n' 'Finalized-burn EVM-proof index is not a direct regular file' >&2; exit 1; }
 rm -- "$final_index"; sync -d "$OUTPUT_DIR"
fi
for name in finalized-burn-groth16-receipt.bin finalized-burn-evm-seal.bin; do
  destination="$OUTPUT_DIR/$name"
  if [[ -e "$destination" || -L "$destination" ]]; then
    [[ -f "$destination" && ! -L "$destination" ]] || {
      printf 'Finalized-burn EVM-proof output is not a direct regular file: %s\n' "$destination" >&2; exit 1; }
    rm -- "$destination"
  fi
  "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$snapshot_output/$name" \
    | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$destination"
done
sync -d "$OUTPUT_DIR"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" \
  "$snapshot_output/finalized-burn-evm-proof-index.json" \
  | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" \
    "$OUTPUT_DIR/finalized-burn-evm-proof-index.json"
