#!/usr/bin/env bash
set -euo pipefail
umask 077

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
RUNTIME_ROOT="$LAB_ROOT/evidence/native-runtime"
MANIFEST="$RUNTIME_ROOT/native-usdom-v2.json"
MANIFEST_PIN="$RUNTIME_ROOT/native-usdom-v2.manifest.sha256"
DATA_DIR="$LAB_ROOT/evidence/native-mainnet-node"
OUTPUT_DIR="$LAB_ROOT/evidence/checkpoint-source-set"

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent export:canonical-checkpoint-source-set' >&2
  exit 2
fi

for required in "$MANIFEST" "$MANIFEST_PIN"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    printf 'Missing non-symlink regular file: %s\n' "$required" >&2
    exit 1
  fi
done
SNAPSHOT_DIRECTORY=$(mktemp -d -p /dev/shm usdom-checkpoint-source-set.XXXXXXXX)
chmod 0700 -- "$SNAPSHOT_DIRECTORY"
trap 'rm -rf -- "$SNAPSHOT_DIRECTORY"' EXIT HUP INT TERM
node "$LAB_ROOT/scripts/read-release-config-file-stdout.mjs" "$MANIFEST" \
  > "$SNAPSHOT_DIRECTORY/native-usdom-v2.json"
node "$LAB_ROOT/scripts/read-release-config-file-stdout.mjs" "$MANIFEST_PIN" \
  > "$SNAPSHOT_DIRECTORY/native-usdom-v2.manifest.sha256"
chmod 0600 -- "$SNAPSHOT_DIRECTORY"/*
MANIFEST="$SNAPSHOT_DIRECTORY/native-usdom-v2.json"
MANIFEST_PIN="$SNAPSHOT_DIRECTORY/native-usdom-v2.manifest.sha256"
if [[ ! -d "$DATA_DIR" || -L "$DATA_DIR" ]]; then
  printf 'Missing non-symlink DOM mainnet data directory: %s\n' "$DATA_DIR" >&2
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

mkdir -p -- "$OUTPUT_DIR"
if [[ -L "$OUTPUT_DIR" ]]; then
  printf '%s\n' 'Checkpoint source output directory cannot be a symlink' >&2
  exit 1
fi

cd "$REPOSITORY_ROOT"
cargo run --quiet --locked \
  -p dom-node \
  --features native-usdom-v4-poc \
  --bin dom-usdom-export-checkpoint-source-set \
  -- \
  --manifest-file "$MANIFEST" \
  --manifest-sha256 "$manifest_sha256" \
  --data-dir "$DATA_DIR" \
  --output-dir "$OUTPUT_DIR" \
  --network mainnet
