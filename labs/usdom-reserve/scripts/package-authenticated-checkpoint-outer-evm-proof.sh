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
SNAPSHOT_ROOT=''
SNAPSHOT_LAB=''
cleanup_snapshot() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  if [[ -n $SNAPSHOT_ROOT ]]; then
    [[ $SNAPSHOT_ROOT =~ ^/dev/shm/usdom-outer-evm\.[A-Za-z0-9]{6}$ && -d $SNAPSHOT_ROOT && ! -L $SNAPSHOT_ROOT ]] || exit 1
    assert_tool_unchanged rm; assert_tool_unchanged timeout
    "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$rm_bin" -rf -- "$SNAPSHOT_ROOT" || status=1
    [[ ! -e $SNAPSHOT_ROOT && ! -L $SNAPSHOT_ROOT ]] || status=1
  fi
  exit "$status"
}
trap 'cleanup_snapshot $?' EXIT; trap 'cleanup_snapshot 129' HUP; trap 'cleanup_snapshot 130' INT; trap 'cleanup_snapshot 143' TERM
if (($# != 0)); then printf '%s\n' 'Usage: npm run --silent package:authenticated-checkpoint-outer-evm-proof' >&2; exit 2; fi
for command in cargo cp node env realpath stat sha256sum id dirname sync mkdir mktemp rm timeout; do command -v "$command" >/dev/null; done
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
  [[ $(realpath "$directory") == "$directory" ]] || return 1
  [[ $(stat -Lc '%d:%i:%u:%a' "$directory") == "${!directory_identity_name}" ]] || return 1
  [[ $(realpath "$(command -v "$name")") == "$path" ]] || return 1
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "$identity" ]] || return 1
  [[ $(sha256sum "$path" | awk '{print $NF}') == "$sha" ]] || return 1
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "$identity" ]] || return 1
  [[ $(stat -Lc '%d:%i:%u:%a' "$directory") == "${!directory_identity_name}" ]] || return 1
}
for command in cargo cp node env mktemp stat id sha256sum mkdir rm timeout sync; do pin_tool "$command"; done
SNAPSHOT_ROOT="$("$mktemp_bin" -d /dev/shm/usdom-outer-evm.XXXXXX)"
[[ $SNAPSHOT_ROOT == /dev/shm/usdom-outer-evm.* && -d $SNAPSHOT_ROOT && ! -L $SNAPSHOT_ROOT ]]
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
    "$OUTPUT_DIR/checkpoint-outer-evm-proof-index.json"|"$OUTPUT_DIR/checkpoint-outer-groth16-receipt.bin"|"$OUTPUT_DIR/checkpoint-outer-evm-seal.bin") ;;
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
for directory in "$JOB_DIR" "$RECEIPT_DIR" "$ARTIFACT_DIR"; do [[ -d $directory && ! -L $directory ]]; done
for input in "$JOB_DIR/checkpoint-outer-proof-job-index.json" "$JOB_DIR/checkpoint-statement-v6.bin" "$JOB_DIR/checkpoint-outer-chain.bin" "$RECEIPT_DIR/checkpoint-outer-receipt-set-index.json" "$RECEIPT_DIR/checkpoint-outer-receipt.bin" "$ARTIFACT_DIR/usdom-checkpoint-outer.elf" "$ARTIFACT_DIR/usdom-checkpoint-outer.bin" "$ARTIFACT_DIR/usdom-checkpoint-outer.iid"; do [[ -f $input && ! -L $input ]]; done
assert_tool_unchanged mkdir; assert_tool_unchanged timeout
"$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$mkdir_bin" -p -- \
  "$OUTPUT_DIR" "$SNAPSHOT_LAB/evidence/checkpoint-outer-proof-job" \
  "$SNAPSHOT_LAB/evidence/checkpoint-outer-receipt-set" \
  "$SNAPSHOT_LAB/evidence/checkpoint-outer-evm-proof" \
  "$SNAPSHOT_ROOT/repository/crates/dom-usdom-checkpoint-outer-risc0-guest/elfs"
assert_tool_unchanged mkdir
[[ $("$stat_bin" -Lc '%F:%u:%a' -- "$OUTPUT_DIR") == "directory:$("$id_bin" -u):700" ]]
for private_directory in \
  "$SNAPSHOT_LAB/evidence/checkpoint-outer-proof-job" \
  "$SNAPSHOT_LAB/evidence/checkpoint-outer-receipt-set" \
  "$SNAPSHOT_LAB/evidence/checkpoint-outer-evm-proof" \
  "$SNAPSHOT_ROOT/repository/crates/dom-usdom-checkpoint-outer-risc0-guest/elfs"; do
  [[ $("$stat_bin" -Lc '%F:%u:%a' -- "$private_directory") == "directory:$("$id_bin" -u):700" ]]
done
capture() {
  assert_tool_unchanged node; assert_tool_unchanged timeout
  "$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$node_bin" \
    "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "${1}" > "${2}"
  assert_tool_unchanged node
  assert_private_file "$2"
}
for name in checkpoint-outer-proof-job-index.json checkpoint-statement-v6.bin checkpoint-outer-chain.bin; do capture "$JOB_DIR/$name" "$SNAPSHOT_LAB/evidence/checkpoint-outer-proof-job/$name"; done
for name in checkpoint-outer-receipt-set-index.json checkpoint-outer-receipt.bin; do capture "$RECEIPT_DIR/$name" "$SNAPSHOT_LAB/evidence/checkpoint-outer-receipt-set/$name"; done
for name in usdom-checkpoint-outer.elf usdom-checkpoint-outer.bin usdom-checkpoint-outer.iid; do
  destination="$SNAPSHOT_ROOT/repository/crates/dom-usdom-checkpoint-outer-risc0-guest/elfs/$name"
  "$cp_bin" --reflink=never --no-preserve=mode,ownership,timestamps -- "$ARTIFACT_DIR/$name" "$destination"
  assert_private_file "$destination"
done
snapshot_output="$SNAPSHOT_LAB/evidence/checkpoint-outer-evm-proof"
for name in checkpoint-outer-groth16-receipt.bin checkpoint-outer-evm-seal.bin; do [[ ! -e $OUTPUT_DIR/$name && ! -L $OUTPUT_DIR/$name ]] || capture "$OUTPUT_DIR/$name" "$snapshot_output/$name"; done
require_risc0_recursion_artifact
cd "$SNAPSHOT_LAB"
critical="$SNAPSHOT_ROOT/checkpoint-outer-evm-critical-inputs.sha256"
assert_tool_unchanged sha256sum; assert_tool_unchanged timeout
"$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$sha256sum_bin" \
  evidence/checkpoint-outer-proof-job/* evidence/checkpoint-outer-receipt-set/* \
  ../../crates/dom-usdom-checkpoint-outer-risc0-guest/elfs/* > "$critical"
for name in checkpoint-outer-groth16-receipt.bin checkpoint-outer-evm-seal.bin; do
  [[ ! -e $snapshot_output/$name ]] || "$timeout_bin" --foreground --signal=TERM \
    --kill-after=5s 120s "$sha256sum_bin" "$snapshot_output/$name" >> "$critical"
done
assert_tool_unchanged cargo; assert_tool_unchanged cp; assert_tool_unchanged node; assert_tool_unchanged env
assert_tool_unchanged sha256sum; assert_tool_unchanged timeout
"$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "$sha256sum_bin" -c "$critical" >/dev/null
assert_tool_unchanged sha256sum
"$env_bin" -u BONSAI_API_URL -u BONSAI_API_KEY -u RISC0_SERVER_PATH -u RISC0_SERVER_ADDR -u RISC0_EXECUTOR -u RISC0_PPROF_OUT -u RISC0_PPROF_ENABLE_INLINE_FUNCTIONS -u RISC0_KECCAK_PO2 -u RISC0_DEFAULT_PROVER_NUM_GPUS -u RISC0_INFO -u RISC0_REDIS_CHANNEL_SIZE -u BONSAI_POLL_INTERVAL_MS RAYON_NUM_THREADS=1 RISC0_PROVER=local RISC0_DEV_MODE=0 "$cargo_bin" run --quiet --release --locked --manifest-path "$REPOSITORY_ROOT/Cargo.toml" -p dom-usdom-checkpoint-proof-host --features prove --bin dom-usdom-package-checkpoint-outer-evm-proof
final_index="$OUTPUT_DIR/checkpoint-outer-evm-proof-index.json"
if [[ -e $final_index || -L $final_index ]]; then remove_output_file "$final_index"; sync_output_directory; fi
for name in checkpoint-outer-groth16-receipt.bin checkpoint-outer-evm-seal.bin; do
 destination="$OUTPUT_DIR/$name"; if [[ -e $destination || -L $destination ]]; then remove_output_file "$destination"; fi
 "$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$snapshot_output/$name" | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$destination"
done
sync_output_directory
"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$snapshot_output/checkpoint-outer-evm-proof-index.json" | "$node_bin" "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$final_index"
