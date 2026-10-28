#!/usr/bin/env bash
set -euo pipefail
umask 077

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
SOURCE_DIR="$LAB_ROOT/evidence/finalized-burn-source"
SOURCE_FILE="$SOURCE_DIR/finalized-burn-input.bin"
ARTIFACT_DIR="$LAB_ROOT/evidence/finalized-burn-guest"
OUTPUT_DIR="$LAB_ROOT/evidence/finalized-burn-proof-job"
SNAPSHOT_ROOT="$(mktemp -d "/dev/shm/usdom-finalized-burn-plan.XXXXXX")"
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
  printf '%s\n' 'Usage: npm run --silent plan:authenticated-finalized-burn' >&2
  exit 2
fi
for command in cargo cp mktemp node sync wc; do command -v "$command" >/dev/null; done
for tool_boundary_command in timeout stat realpath id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$LAB_ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node; pin_runtime_tool timeout; pin_runtime_tool cargo
cargo() { assert_runtime_tool cargo; "$cargo_bin" "$@"; }
run_pinned_node_timed() { assert_runtime_tool node; assert_runtime_tool timeout; "$timeout_bin" --signal=TERM --kill-after=2s 120s "$node_bin" "$@"; }
run_pinned_timeout() { assert_runtime_tool timeout; "$timeout_bin" "$@"; }
for directory in "$SOURCE_DIR" "$ARTIFACT_DIR"; do
  if [[ ! -d "$directory" || -L "$directory" ]]; then
    printf 'Missing non-symlink finalized-burn planner input directory: %s\n' "$directory" >&2
    exit 1
  fi
done
for input in "$SOURCE_FILE" "$ARTIFACT_DIR/usdom-finalized-burn.elf" "$ARTIFACT_DIR/usdom-finalized-burn.iid"; do
  if [[ ! -f "$input" || -L "$input" ]]; then
    printf 'Missing non-symlink finalized-burn planner input: %s\n' "$input" >&2
    exit 1
  fi
done
mkdir -p -- "$OUTPUT_DIR"
if [[ -L "$OUTPUT_DIR" ]]; then
  printf '%s\n' 'Finalized-burn proof-job output directory cannot be a symlink' >&2
  exit 1
fi

snapshot_source="$SNAPSHOT_LAB/evidence/finalized-burn-source"
snapshot_artifacts="$SNAPSHOT_LAB/evidence/finalized-burn-guest"
snapshot_output="$SNAPSHOT_LAB/evidence/finalized-burn-proof-job"
mkdir -p -- "$snapshot_source" "$snapshot_artifacts" "$snapshot_output"
chmod -R go-rwx -- "$SNAPSHOT_ROOT"
run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$SOURCE_FILE" \
  > "$snapshot_source/finalized-burn-input.bin"
run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" \
  "$ARTIFACT_DIR/usdom-finalized-burn.elf" \
  > "$snapshot_artifacts/usdom-finalized-burn.elf"
run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" \
  "$ARTIFACT_DIR/usdom-finalized-burn.iid" \
  > "$snapshot_artifacts/usdom-finalized-burn.iid"
chmod 0600 "$snapshot_source/finalized-burn-input.bin" \
  "$snapshot_artifacts/usdom-finalized-burn.elf" \
  "$snapshot_artifacts/usdom-finalized-burn.iid"

input_bytes=$(wc -c < "$snapshot_source/finalized-burn-input.bin")
program_bytes=$(wc -c < "$snapshot_artifacts/usdom-finalized-burn.elf")
image_id_bytes=$(wc -c < "$snapshot_artifacts/usdom-finalized-burn.iid")
if ((input_bytes == 0 || input_bytes > 67108864)); then
  printf '%s\n' 'Canonical UDFINL04 input is empty or exceeds the 64 MiB planner bound' >&2
  exit 1
fi
if ((program_bytes == 0 || program_bytes > 4194304 || image_id_bytes != 32)); then
  printf '%s\n' 'Finalized-burn guest artifact catalog violates its fixed size bounds' >&2
  exit 1
fi

cd "$SNAPSHOT_LAB"
run_pinned_timeout --signal=TERM --kill-after=30s 3600s \
  cargo run --quiet --release --locked \
  --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-usdom-finalized-burn-proof-host \
  --bin dom-usdom-plan-finalized-burn-proof

# Replace the old pair only after the replica has produced and verified both outputs.
for name in finalized-burn-proof-job-index.json finalized-burn-input.bin; do
  destination="$OUTPUT_DIR/$name"
  if [[ -e "$destination" || -L "$destination" ]]; then
    if [[ ! -f "$destination" || -L "$destination" ]]; then
      printf 'Finalized-burn planner output is not a direct regular file: %s\n' "$destination" >&2
      exit 1
    fi
    rm -- "$destination"
  fi
done
sync -d "$OUTPUT_DIR"
run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" \
  "$snapshot_output/finalized-burn-input.bin" \
  | run_pinned_node_timed "$LAB_ROOT/scripts/install-private-file-stdin.mjs" \
    "$OUTPUT_DIR/finalized-burn-input.bin"
run_pinned_node_timed "$LAB_ROOT/scripts/read-private-file-stdout.mjs" \
  "$snapshot_output/finalized-burn-proof-job-index.json" \
  | run_pinned_node_timed "$LAB_ROOT/scripts/install-private-file-stdin.mjs" \
    "$OUTPUT_DIR/finalized-burn-proof-job-index.json"
