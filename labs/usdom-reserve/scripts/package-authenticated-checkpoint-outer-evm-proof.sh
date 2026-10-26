#!/usr/bin/env bash
set -euo pipefail
umask 077
LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
source "$LAB_ROOT/scripts/require-risc0-recursion-artifact.sh"
JOB_DIR="$LAB_ROOT/evidence/checkpoint-outer-proof-job"
RECEIPT_DIR="$LAB_ROOT/evidence/checkpoint-outer-receipt-set"
OUTPUT_DIR="$LAB_ROOT/evidence/checkpoint-outer-evm-proof"
ARTIFACT_DIR="$REPOSITORY_ROOT/crates/dom-usdom-checkpoint-outer-risc0-guest/elfs"
SNAPSHOT_ROOT="$(mktemp -d /dev/shm/usdom-outer-evm.XXXXXX)"; chmod 0700 "$SNAPSHOT_ROOT"
SNAPSHOT_LAB="$SNAPSHOT_ROOT/repository/labs/usdom-reserve"
trap 'rm -rf -- "$SNAPSHOT_ROOT"' EXIT HUP INT TERM
if (($# != 0)); then printf '%s\n' 'Usage: npm run --silent package:authenticated-checkpoint-outer-evm-proof' >&2; exit 2; fi
for command in cargo cp node env realpath stat sha256sum id dirname sync; do command -v "$command" >/dev/null; done
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
for command in cargo cp node env; do pin_tool "$command"; done
for directory in "$JOB_DIR" "$RECEIPT_DIR" "$ARTIFACT_DIR"; do [[ -d $directory && ! -L $directory ]]; done
for input in "$JOB_DIR/checkpoint-outer-proof-job-index.json" "$JOB_DIR/checkpoint-statement-v6.bin" "$JOB_DIR/checkpoint-outer-chain.bin" "$RECEIPT_DIR/checkpoint-outer-receipt-set-index.json" "$RECEIPT_DIR/checkpoint-outer-receipt.bin" "$ARTIFACT_DIR/usdom-checkpoint-outer.elf" "$ARTIFACT_DIR/usdom-checkpoint-outer.bin" "$ARTIFACT_DIR/usdom-checkpoint-outer.iid"; do [[ -f $input && ! -L $input ]]; done
mkdir -p -- "$OUTPUT_DIR" "$SNAPSHOT_LAB/evidence/checkpoint-outer-proof-job" "$SNAPSHOT_LAB/evidence/checkpoint-outer-receipt-set" "$SNAPSHOT_LAB/evidence/checkpoint-outer-evm-proof" "$SNAPSHOT_ROOT/repository/crates/dom-usdom-checkpoint-outer-risc0-guest/elfs"
[[ ! -L $OUTPUT_DIR ]]
capture() { "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "${1}" > "${2}"; chmod 0600 "$2"; }
for name in checkpoint-outer-proof-job-index.json checkpoint-statement-v6.bin checkpoint-outer-chain.bin; do capture "$JOB_DIR/$name" "$SNAPSHOT_LAB/evidence/checkpoint-outer-proof-job/$name"; done
for name in checkpoint-outer-receipt-set-index.json checkpoint-outer-receipt.bin; do capture "$RECEIPT_DIR/$name" "$SNAPSHOT_LAB/evidence/checkpoint-outer-receipt-set/$name"; done
for name in usdom-checkpoint-outer.elf usdom-checkpoint-outer.bin usdom-checkpoint-outer.iid; do "$cp_bin" --reflink=never --no-preserve=mode,ownership,timestamps -- "$ARTIFACT_DIR/$name" "$SNAPSHOT_ROOT/repository/crates/dom-usdom-checkpoint-outer-risc0-guest/elfs/$name"; done
snapshot_output="$SNAPSHOT_LAB/evidence/checkpoint-outer-evm-proof"
for name in checkpoint-outer-groth16-receipt.bin checkpoint-outer-evm-seal.bin; do [[ ! -e $OUTPUT_DIR/$name && ! -L $OUTPUT_DIR/$name ]] || capture "$OUTPUT_DIR/$name" "$snapshot_output/$name"; done
chmod -R go-rwx -- "$SNAPSHOT_ROOT"
require_risc0_recursion_artifact
cd "$SNAPSHOT_LAB"
critical="$SNAPSHOT_ROOT/checkpoint-outer-evm-critical-inputs.sha256"
sha256sum evidence/checkpoint-outer-proof-job/* evidence/checkpoint-outer-receipt-set/* ../../crates/dom-usdom-checkpoint-outer-risc0-guest/elfs/* > "$critical"
for name in checkpoint-outer-groth16-receipt.bin checkpoint-outer-evm-seal.bin; do [[ ! -e $snapshot_output/$name ]] || sha256sum "$snapshot_output/$name" >> "$critical"; done
assert_tool_unchanged cargo; assert_tool_unchanged cp; assert_tool_unchanged node; assert_tool_unchanged env
sha256sum -c "$critical" >/dev/null
"$env_bin" -u BONSAI_API_URL -u BONSAI_API_KEY -u RISC0_SERVER_PATH -u RISC0_SERVER_ADDR -u RISC0_EXECUTOR -u RISC0_PPROF_OUT -u RISC0_PPROF_ENABLE_INLINE_FUNCTIONS -u RISC0_KECCAK_PO2 -u RISC0_DEFAULT_PROVER_NUM_GPUS -u RISC0_INFO -u RISC0_REDIS_CHANNEL_SIZE -u BONSAI_POLL_INTERVAL_MS RAYON_NUM_THREADS=1 RISC0_PROVER=local RISC0_DEV_MODE=0 "$cargo_bin" run --quiet --release --locked --manifest-path "$REPOSITORY_ROOT/Cargo.toml" -p dom-usdom-checkpoint-proof-host --features prove --bin dom-usdom-package-checkpoint-outer-evm-proof
final_index="$OUTPUT_DIR/checkpoint-outer-evm-proof-index.json"
if [[ -e $final_index || -L $final_index ]]; then [[ -f $final_index && ! -L $final_index ]]; rm -- "$final_index"; sync -d "$OUTPUT_DIR"; fi
for name in checkpoint-outer-groth16-receipt.bin checkpoint-outer-evm-seal.bin; do
 destination="$OUTPUT_DIR/$name"; if [[ -e $destination || -L $destination ]]; then [[ -f $destination && ! -L $destination ]]; rm -- "$destination"; fi
 "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$snapshot_output/$name" | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$destination"
done
sync -d "$OUTPUT_DIR"
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$snapshot_output/checkpoint-outer-evm-proof-index.json" | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$final_index"
