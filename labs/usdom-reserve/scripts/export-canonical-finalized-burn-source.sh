#!/usr/bin/env bash
set -euo pipefail
umask 077

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
RUNTIME_ROOT="$LAB_ROOT/evidence/native-runtime"
MANIFEST="$RUNTIME_ROOT/native-usdom-v2.json"
MANIFEST_PIN="$RUNTIME_ROOT/native-usdom-v2.manifest.sha256"
DATA_DIR="$LAB_ROOT/evidence/native-mainnet-node"
OUTPUT_DIR="$LAB_ROOT/evidence/finalized-burn-source"
CHECKPOINT_WITNESS="$OUTPUT_DIR/checkpoint-witness.bin"
CHECKPOINT_STATEMENT="$LAB_ROOT/evidence/checkpoint-outer-proof-job/checkpoint-statement-v6.bin"
BURN_ID="$OUTPUT_DIR/burn-id.hex"

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent export:canonical-finalized-burn-source' >&2
  exit 2
fi

for required in "$MANIFEST" "$MANIFEST_PIN" "$CHECKPOINT_WITNESS" "$CHECKPOINT_STATEMENT" "$BURN_ID"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    printf 'Missing non-symlink regular file: %s\n' "$required" >&2
    exit 1
  fi
done
SNAPSHOT_DIRECTORY=$(mktemp -d -p /dev/shm usdom-finalized-burn-source.XXXXXXXX)
chmod 0700 -- "$SNAPSHOT_DIRECTORY"
trap 'rm -rf -- "$SNAPSHOT_DIRECTORY"' EXIT HUP INT TERM
timeout --signal=TERM --kill-after=2s 120s node "$LAB_ROOT/scripts/read-release-config-file-stdout.mjs" "$MANIFEST" \
  > "$SNAPSHOT_DIRECTORY/native-usdom-v2.json"
timeout --signal=TERM --kill-after=2s 120s node "$LAB_ROOT/scripts/read-release-config-file-stdout.mjs" "$MANIFEST_PIN" \
  > "$SNAPSHOT_DIRECTORY/native-usdom-v2.manifest.sha256"
timeout --signal=TERM --kill-after=2s 120s node "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$CHECKPOINT_WITNESS" \
  > "$SNAPSHOT_DIRECTORY/checkpoint-witness.bin"
timeout --signal=TERM --kill-after=2s 120s node "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$CHECKPOINT_STATEMENT" \
  > "$SNAPSHOT_DIRECTORY/checkpoint-statement-v6.bin"
timeout --signal=TERM --kill-after=2s 120s node "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$BURN_ID" \
  > "$SNAPSHOT_DIRECTORY/burn-id.hex"
chmod 0600 -- "$SNAPSHOT_DIRECTORY"/*
MANIFEST="$SNAPSHOT_DIRECTORY/native-usdom-v2.json"
MANIFEST_PIN="$SNAPSHOT_DIRECTORY/native-usdom-v2.manifest.sha256"
CHECKPOINT_WITNESS="$SNAPSHOT_DIRECTORY/checkpoint-witness.bin"
CHECKPOINT_STATEMENT="$SNAPSHOT_DIRECTORY/checkpoint-statement-v6.bin"
BURN_ID="$SNAPSHOT_DIRECTORY/burn-id.hex"
if [[ ! -d "$DATA_DIR" || -L "$DATA_DIR" ]]; then
  printf 'Missing non-symlink DOM mainnet data directory: %s\n' "$DATA_DIR" >&2
  exit 1
fi
if [[ ! -d "$OUTPUT_DIR" || -L "$OUTPUT_DIR" ]]; then
  printf 'Missing non-symlink finalized-burn source directory: %s\n' "$OUTPUT_DIR" >&2
  exit 1
fi

IFS= read -r manifest_sha256 < "$MANIFEST_PIN"
if [[ ! "$manifest_sha256" =~ ^[0-9a-f]{64}$ ]] \
  || [[ "$(wc -l < "$MANIFEST_PIN")" -ne 1 ]]; then
  printf '%s\n' 'Native manifest pin must contain exactly one lowercase SHA-256 line' >&2
  exit 1
fi
observed_sha256="$(sha256sum -- "$MANIFEST" | cut -d ' ' -f 1)"
if [[ "$observed_sha256" != "$manifest_sha256" ]]; then
  printf '%s\n' 'Native runtime manifest does not match its exact SHA-256 pin' >&2
  exit 1
fi

cd "$REPOSITORY_ROOT"
timeout --signal=TERM --kill-after=30s 3600s \
  cargo run --quiet --locked \
  -p dom-node \
  --features native-usdom-v4-poc \
  --bin dom-usdom-export-finalized-burn-source \
  -- \
  --manifest-file "$MANIFEST" \
  --manifest-sha256 "$manifest_sha256" \
  --data-dir "$DATA_DIR" \
  --checkpoint-statement-file "$CHECKPOINT_STATEMENT" \
  --checkpoint-witness-file "$CHECKPOINT_WITNESS" \
  --burn-id-file "$BURN_ID" \
  --output-dir "$OUTPUT_DIR" \
  --network mainnet
