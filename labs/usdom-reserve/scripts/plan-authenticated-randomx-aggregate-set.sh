#!/usr/bin/env bash
set -euo pipefail
umask 077

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
SOURCE_DIR="$LAB_ROOT/evidence/checkpoint-source-set"
SOURCE_INDEX="$SOURCE_DIR/checkpoint-source-set-index.json"
RECEIPT_DIR="$LAB_ROOT/evidence/randomx-receipt-set"
RECEIPT_INDEX="$RECEIPT_DIR/randomx-receipt-set-index.json"
OUTPUT_DIR="$LAB_ROOT/evidence/randomx-aggregate-jobs"

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent plan:authenticated-randomx-aggregate-set' >&2
  exit 2
fi
for command in cargo realpath stat sha256sum awk dirname id; do command -v "$command" >/dev/null; done
pin_cargo() {
  cargo_bin=$(realpath "$(command -v cargo)")
  [[ -x $cargo_bin && -f $cargo_bin && ! -L $cargo_bin ]]
  [[ $(stat -Lc '%h' "$cargo_bin") == 1 ]]
  cargo_size=$(stat -Lc '%s' "$cargo_bin"); (( cargo_size > 0 && cargo_size <= 512 * 1024 * 1024 ))
  cargo_owner=$(stat -Lc '%u' "$cargo_bin"); [[ $cargo_owner == 0 || $cargo_owner == "$(id -u)" ]]
  cargo_mode=$(stat -Lc '%a' "$cargo_bin"); (( (8#$cargo_mode & 8#022) == 0 ))
  cargo_directory=$(dirname "$cargo_bin"); [[ $(realpath "$cargo_directory") == "$cargo_directory" ]]
  cargo_directory_owner=$(stat -Lc '%u' "$cargo_directory"); [[ $cargo_directory_owner == 0 || $cargo_directory_owner == "$(id -u)" ]]
  cargo_directory_mode=$(stat -Lc '%a' "$cargo_directory"); (( (8#$cargo_directory_mode & 8#022) == 0 ))
  cargo_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$cargo_bin")
  cargo_directory_identity=$(stat -Lc '%d:%i:%u:%a' "$cargo_directory")
  cargo_sha256=$(sha256sum "$cargo_bin" | awk '{print $1}')
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$cargo_bin") == "$cargo_identity" ]]
  [[ $(stat -Lc '%d:%i:%u:%a' "$cargo_directory") == "$cargo_directory_identity" ]]
}
assert_cargo_unchanged() {
  [[ $(realpath "$(command -v cargo)") == "$cargo_bin" ]]
  [[ $(realpath "$cargo_directory") == "$cargo_directory" ]]
  [[ $(stat -Lc '%d:%i:%u:%a' "$cargo_directory") == "$cargo_directory_identity" ]]
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$cargo_bin") == "$cargo_identity" ]]
  [[ $(sha256sum "$cargo_bin" | awk '{print $1}') == "$cargo_sha256" ]]
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$cargo_bin") == "$cargo_identity" ]]
  [[ $(stat -Lc '%d:%i:%u:%a' "$cargo_directory") == "$cargo_directory_identity" ]]
}
pin_cargo
for directory in "$SOURCE_DIR" "$RECEIPT_DIR"; do
  if [[ ! -d "$directory" || -L "$directory" ]]; then
    printf 'Missing non-symlink aggregate input directory: %s\n' "$directory" >&2
    exit 1
  fi
done
for index in "$SOURCE_INDEX" "$RECEIPT_INDEX"; do
  if [[ ! -f "$index" || -L "$index" ]]; then
    printf 'Missing non-symlink aggregate input index: %s\n' "$index" >&2
    exit 1
  fi
done
mkdir -p -- "$OUTPUT_DIR"
if [[ -L "$OUTPUT_DIR" ]]; then
  printf '%s\n' 'RandomX aggregate-job output directory cannot be a symlink' >&2
  exit 1
fi

cd "$LAB_ROOT"
assert_cargo_unchanged
exec "$cargo_bin" run --quiet --locked \
  --manifest-path "$REPOSITORY_ROOT/Cargo.toml" \
  -p dom-usdom-randomx-proof-host \
  --features verify \
  --bin dom-usdom-plan-randomx-aggregate-set
