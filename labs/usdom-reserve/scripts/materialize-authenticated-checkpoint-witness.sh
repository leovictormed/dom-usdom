#!/usr/bin/env bash
set -euo pipefail
umask 077

LAB_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$LAB_ROOT/../.." && pwd -P)"
for tool_boundary_command in stat realpath id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$LAB_ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node
node() { assert_runtime_tool node; "$node_bin" "$@"; }
pin_runtime_tool jq
jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }
pin_runtime_tool cargo
cargo() { assert_runtime_tool cargo; "$cargo_bin" "$@"; }
SOURCE="$LAB_ROOT/evidence/checkpoint-witness-source/checkpoint-witness-source.json"
SOURCE_COMPLETION="$LAB_ROOT/evidence/checkpoint-witness-source/checkpoint-witness-source.complete.json"
STATEMENT="$LAB_ROOT/evidence/checkpoint-outer-proof-job/checkpoint-statement-v6.bin"
OUTPUT_DIRECTORY="$LAB_ROOT/evidence/finalized-burn-source"
OUTPUT="$OUTPUT_DIRECTORY/checkpoint-witness.bin"

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent materialize:authenticated-checkpoint-witness' >&2
  exit 2
fi
for input in "$SOURCE" "$SOURCE_COMPLETION" "$STATEMENT"; do
  [[ -f $input && ! -L $input ]] || { printf 'Missing regular non-symlink input: %s\n' "$input" >&2; exit 1; }
done
[[ -d $OUTPUT_DIRECTORY && ! -L $OUTPUT_DIRECTORY ]] || { printf '%s\n' 'Unsafe witness output directory' >&2; exit 1; }
[[ ! -e $OUTPUT && ! -L $OUTPUT ]] || { printf '%s\n' 'Checkpoint witness already exists' >&2; exit 1; }

snapshot="$(mktemp -d -p /dev/shm usdom-checkpoint-witness.XXXXXXXX)"
chmod 0700 -- "$snapshot"
snapshot_identity="$(stat -c '%u:%d:%i:%a' "$snapshot")"
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  if [[ $(stat -c '%u:%d:%i:%a' "$snapshot" 2>/dev/null) == "$snapshot_identity" ]]; then
    rm -rf -- "$snapshot" || status=1
  else
    # Do not let cleanup follow a pathname that another process replaced.
    status=1
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
for name in checkpoint-witness-source.json checkpoint-witness-source.complete.json checkpoint-statement-v6.bin; do
  case "$name" in
    checkpoint-witness-source.json) origin=$SOURCE ;;
    checkpoint-witness-source.complete.json) origin=$SOURCE_COMPLETION ;;
    *) origin=$STATEMENT ;;
  esac
  node "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$origin" > "$snapshot/$name"
  chmod 0600 -- "$snapshot/$name"
done
source_sha="$(sha256sum -- "$snapshot/checkpoint-witness-source.json" | cut -d ' ' -f 1)"
jq -e --arg sha "$source_sha" '
  keys==["schema","sourceSha256","status"] and
  .schema=="usdom-checkpoint-witness-source-completion/v1" and .status=="complete" and
  .sourceSha256==$sha
' "$snapshot/checkpoint-witness-source.complete.json" >/dev/null || {
  printf '%s\n' 'Checkpoint witness source completion is invalid' >&2; exit 1;
}

cd "$REPOSITORY_ROOT"
cargo run --quiet --locked -p usdom-ethereum-finality-experiment \
  --bin usdom-build-checkpoint-witness -- \
  "$snapshot/checkpoint-witness-source.json" "$snapshot/checkpoint-statement-v6.bin" "$OUTPUT"

for pair in "$SOURCE:$snapshot/checkpoint-witness-source.json" \
  "$SOURCE_COMPLETION:$snapshot/checkpoint-witness-source.complete.json" \
  "$STATEMENT:$snapshot/checkpoint-statement-v6.bin"; do
  origin=${pair%%:*}; frozen=${pair#*:}
  cmp -s -- "$origin" "$frozen" || { rm -f -- "$OUTPUT"; printf '%s\n' 'Witness input changed during materialization' >&2; exit 1; }
done
printf '%s  %s\n' "$(sha256sum -- "$OUTPUT" | cut -d ' ' -f 1)" checkpoint-witness.bin
