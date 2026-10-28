#!/usr/bin/env bash
set -euo pipefail
umask 077

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
SOURCE_DIR="$LAB_ROOT/evidence/checkpoint-source-set"
SOURCE_INDEX="$SOURCE_DIR/checkpoint-source-set-index.json"
ECONOMIC_INDEX="$SOURCE_DIR/checkpoint-economic-source-set-index.json"
OUTPUT_DIR="$LAB_ROOT/evidence/economic-proof-jobs"
SNAPSHOT_ROOT="$(mktemp -d "/dev/shm/usdom-economic-plan.XXXXXX")"
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
  printf '%s\n' 'Usage: npm run --silent plan:authenticated-economic-receipt-set' >&2
  exit 2
fi
for command in cargo cp jq mktemp node; do command -v "$command" >/dev/null; done
for tool_boundary_command in timeout stat realpath id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$LAB_ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node; pin_runtime_tool timeout; pin_runtime_tool cargo; pin_runtime_tool jq
cargo() { assert_runtime_tool cargo; "$cargo_bin" "$@"; }
jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }
run_pinned_node_timed() { assert_runtime_tool node; assert_runtime_tool timeout; "$timeout_bin" --signal=TERM --kill-after=2s 120s "$node_bin" "$@"; }
run_pinned_timeout() { assert_runtime_tool timeout; "$timeout_bin" "$@"; }
if [[ ! -d "$SOURCE_DIR" || -L "$SOURCE_DIR" ]]; then
  printf 'Missing non-symlink checkpoint source-set directory: %s\n' "$SOURCE_DIR" >&2
  exit 1
fi
for index in "$SOURCE_INDEX" "$ECONOMIC_INDEX"; do
  if [[ ! -f "$index" || -L "$index" ]]; then
    printf 'Missing non-symlink economic source index: %s\n' "$index" >&2
    exit 1
  fi
done
mkdir -p -- "$OUTPUT_DIR"
if [[ -L "$OUTPUT_DIR" ]]; then
  printf '%s\n' 'Economic proof-job output directory cannot be a symlink' >&2
  exit 1
fi

snapshot_source="$SNAPSHOT_LAB/evidence/checkpoint-source-set"
snapshot_jobs="$SNAPSHOT_LAB/evidence/economic-proof-jobs"
chunk_artifacts="$SNAPSHOT_ROOT/repository/crates/dom-usdom-economic-chunk-risc0-guest/elfs"
block_artifacts="$SNAPSHOT_ROOT/repository/crates/dom-usdom-economic-block-risc0-guest/elfs"
mkdir -p -- "$snapshot_source" "$snapshot_jobs" "$chunk_artifacts" "$block_artifacts"
chmod -R go-rwx -- "$SNAPSHOT_ROOT"
snapshot_source_index="$snapshot_source/checkpoint-source-set-index.json"
snapshot_economic_index="$snapshot_source/checkpoint-economic-source-set-index.json"
run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$SOURCE_INDEX" > "$snapshot_source_index"
run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$ECONOMIC_INDEX" > "$snapshot_economic_index"
chmod 0600 "$snapshot_source_index" "$snapshot_economic_index"
mapfile -t source_files < <(jq -nr \
  --slurpfile checkpoint "$snapshot_source_index" \
  --slurpfile economic "$snapshot_economic_index" '
  [$checkpoint[0].segments[].private_input_file,
   $economic[0].blocks[].block_transition_file,
   $economic[0].blocks[].chunks[].transition_file,
   $economic[0].blocks[].chunks[].witness_file]
  | unique | .[]
  | select(test("^checkpoint-segment-[0-9]{4}-(private-input|economic-block-[0-9]{4}-(transition|chunk-[0-9]{4}-(transition|witness)))\\.bin$"))
')
if ((${#source_files[@]} == 0)); then
  printf '%s\n' 'Economic source indexes have no canonical source catalog' >&2
  exit 1
fi
for name in "${source_files[@]}"; do
  run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$SOURCE_DIR/$name" \
    > "$snapshot_source/$name"
  chmod 0600 "$snapshot_source/$name"
done
for guest in chunk block; do
  source_artifacts="$REPOSITORY_ROOT/crates/dom-usdom-economic-${guest}-risc0-guest/elfs"
  destination="$SNAPSHOT_ROOT/repository/crates/dom-usdom-economic-${guest}-risc0-guest/elfs"
  for extension in elf bin iid; do
    name="usdom-economic-${guest}.${extension}"
    [[ -f "$source_artifacts/$name" && ! -L "$source_artifacts/$name" ]]
    cp --reflink=never --no-preserve=mode,ownership,timestamps -- \
      "$source_artifacts/$name" "$destination/$name"
    chmod 0600 "$destination/$name"
  done
done

cd "$SNAPSHOT_LAB"
run_pinned_timeout --signal=TERM --kill-after=30s 3600s \
  cargo run --quiet --locked \
  --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-usdom-economic-proof-host \
  --bin dom-usdom-plan-economic-receipt-set

run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" \
  "$snapshot_jobs/economic-proof-job-index.json" \
  | run_pinned_node_timed "$LAB_ROOT/scripts/install-private-file-stdin.mjs" \
    "$OUTPUT_DIR/economic-proof-job-index.json"
