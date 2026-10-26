#!/usr/bin/env bash
set -euo pipefail
umask 077

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
SOURCE_DIR="$LAB_ROOT/evidence/checkpoint-source-set"
SOURCE_INDEX="$SOURCE_DIR/checkpoint-source-set-index.json"
OUTPUT_DIR="$LAB_ROOT/evidence/randomx-statement-set"
SNAPSHOT_ROOT="$(mktemp -d "/dev/shm/usdom-randomx-statement-set.XXXXXX")"
chmod 0700 "$SNAPSHOT_ROOT"
trap 'rm -rf -- "$SNAPSHOT_ROOT"' EXIT HUP INT TERM

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent export:authenticated-randomx-statement-set' >&2
  exit 2
fi
for command in cargo jq node mktemp; do command -v "$command" >/dev/null; done

if [[ ! -d "$SOURCE_DIR" || -L "$SOURCE_DIR" ]]; then
  printf 'Missing non-symlink checkpoint source-set directory: %s\n' "$SOURCE_DIR" >&2
  exit 1
fi
if [[ ! -f "$SOURCE_INDEX" || -L "$SOURCE_INDEX" ]]; then
  printf 'Missing non-symlink checkpoint source-set index: %s\n' "$SOURCE_INDEX" >&2
  exit 1
fi
mkdir -p -- "$OUTPUT_DIR"
if [[ -L "$OUTPUT_DIR" ]]; then
  printf '%s\n' 'RandomX statement-set output directory cannot be a symlink' >&2
  exit 1
fi

mkdir -p -- "$SNAPSHOT_ROOT/evidence/checkpoint-source-set" \
  "$SNAPSHOT_ROOT/evidence/randomx-statement-set"
chmod 0700 "$SNAPSHOT_ROOT" "$SNAPSHOT_ROOT/evidence" \
  "$SNAPSHOT_ROOT/evidence/checkpoint-source-set" \
  "$SNAPSHOT_ROOT/evidence/randomx-statement-set"
snapshot_index="$SNAPSHOT_ROOT/evidence/checkpoint-source-set/checkpoint-source-set-index.json"
timeout --signal=TERM --kill-after=2s 120s node "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$SOURCE_INDEX" > "$snapshot_index"
chmod 0600 "$snapshot_index"
mapfile -t source_files < <(jq -er '
  select(.schema == "usdom-canonical-checkpoint-source-set-v1")
  | select(.segment_count == (.segments | length) and .segment_count > 0 and .segment_count <= 32)
  | [.segments[] | .transition_file, .private_input_file, .policy_input_file, .native_state_opening_file]
  | select(length == (unique | length))
  | .[] | select(test("^checkpoint-segment-[0-9]{4}-(transition|private-input|policy-input|native-state-opening)\\.bin$"))
' "$snapshot_index")
if ((${#source_files[@]} == 0)); then
  printf '%s\n' 'Checkpoint source-set index has no canonical component files' >&2
  exit 1
fi
for name in "${source_files[@]}"; do
  timeout --signal=TERM --kill-after=2s 120s node "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$SOURCE_DIR/$name" \
    > "$SNAPSHOT_ROOT/evidence/checkpoint-source-set/$name"
  chmod 0600 "$SNAPSHOT_ROOT/evidence/checkpoint-source-set/$name"
done

cd "$SNAPSHOT_ROOT"
timeout --signal=TERM --kill-after=30s 3600s \
  cargo run --quiet --locked \
  --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-node \
  --features native-usdom-v4-poc \
  --bin dom-usdom-export-randomx-statement-set -- \
  --evidence-dir "$SNAPSHOT_ROOT/evidence"

snapshot_output="$SNAPSHOT_ROOT/evidence/randomx-statement-set"
output_index="$snapshot_output/randomx-statement-set-index.json"
mapfile -t statement_files < <(jq -er '
  select(.schema == "usdom-authenticated-randomx-statement-set-v1")
  | select(.statement_count == (.statements | length) and .statement_count > 0 and .statement_count <= 720)
  | [.statements[].statement_file]
  | select(length == (unique | length))
  | .[] | select(test("^randomx-statement-[0-9]{4}\\.bin$"))
' "$output_index")
if ((${#statement_files[@]} == 0)); then
  printf '%s\n' 'RandomX statement-set output has no canonical statement files' >&2
  exit 1
fi
# Install the index last. Any interruption while replacing statement files makes
# the previous index fail its hashes rather than presenting a mixed set as valid.
for name in "${statement_files[@]}"; do
  timeout --signal=TERM --kill-after=2s 120s node "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$snapshot_output/$name" \
    | timeout --signal=TERM --kill-after=2s 120s node "$LAB_ROOT/scripts/install-private-file-stdin.mjs" "$OUTPUT_DIR/$name"
done
timeout --signal=TERM --kill-after=2s 120s node "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$output_index" \
  | timeout --signal=TERM --kill-after=2s 120s node "$LAB_ROOT/scripts/install-private-file-stdin.mjs" \
    "$OUTPUT_DIR/randomx-statement-set-index.json"
