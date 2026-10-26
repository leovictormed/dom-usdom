#!/usr/bin/env bash
set -euo pipefail
umask 077
if (($# != 0)); then printf '%s\n' 'Usage: bash scripts/write-checkpoint-finalized-transaction-reference.sh' >&2; exit 64; fi
for command in node realpath install stat id mktemp chmod sha256sum sync cmp awk; do command -v "$command" >/dev/null; done
ROOT=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$ROOT"
for tool_boundary_command in stat id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node
node() { assert_runtime_tool node; "$node_bin" "$@"; }
BASE="$ROOT/evidence/checkpoint-finalized-event"
install -d -m 0700 "$BASE"
[[ -d "$BASE" && ! -L "$BASE" && "$(stat -c '%u:%a' "$BASE")" == "$(id -u):700" ]] || exit 1
REFERENCE="$BASE/transaction-reference.json"
REFERENCE_SHA="$BASE/transaction-reference.sha256"
[[ ! -e "$REFERENCE" && ! -L "$REFERENCE" ]] || exit 1
if [[ -e "$REFERENCE_SHA" || -L "$REFERENCE_SHA" ]]; then
  [[ -f "$REFERENCE_SHA" && ! -L "$REFERENCE_SHA" && "$(stat -c '%u:%a' "$REFERENCE_SHA")" == "$(id -u):600" ]] || exit 1
fi
TEMPORARY=$(mktemp -d -p /dev/shm usdom-checkpoint-finalized-reference.XXXXXXXX)
chmod 0700 "$TEMPORARY"; trap 'rm -rf -- "$TEMPORARY"' EXIT HUP INT TERM
node "$ROOT/scripts/prepare-checkpoint-finalized-transaction-reference.mjs" > "$TEMPORARY/reference.json"
chmod 0600 "$TEMPORARY/reference.json"
sha256sum "$TEMPORARY/reference.json" | awk '{print $1}' > "$TEMPORARY/reference.sha256"
chmod 0600 "$TEMPORARY/reference.sha256"
if [[ -e "$REFERENCE_SHA" ]]; then
  cmp -s "$TEMPORARY/reference.sha256" "$REFERENCE_SHA" || {
    printf '%s\n' 'Existing checkpoint transaction-reference hash differs from rebuilt output.' >&2
    exit 1
  }
else
  node "$ROOT/scripts/install-private-file-immutable-stdin.mjs" "$REFERENCE_SHA" < "$TEMPORARY/reference.sha256"
fi
cmp -s "$TEMPORARY/reference.sha256" "$REFERENCE_SHA" || exit 1
node "$ROOT/scripts/install-private-file-immutable-stdin.mjs" "$REFERENCE" < "$TEMPORARY/reference.json"
[[ -f "$REFERENCE" && ! -L "$REFERENCE" && "$(stat -c '%u:%a' "$REFERENCE")" == "$(id -u):600" ]] || exit 1
cmp -s "$TEMPORARY/reference.json" "$REFERENCE" || exit 1
sync -f "$REFERENCE"; sync -f "$REFERENCE_SHA"; sync -f "$BASE"
