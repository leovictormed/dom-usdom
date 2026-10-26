#!/usr/bin/env bash
set -euo pipefail
umask 077
if (($# != 0)); then printf '%s\n' 'Usage: bash scripts/write-checkpoint-bootstrap-ratification-observation.sh' >&2; exit 64; fi
for command in node realpath install stat id mktemp chmod sync; do command -v "$command" >/dev/null; done
ROOT=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$ROOT"
for tool_boundary_command in stat id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node
node() { assert_runtime_tool node; "$node_bin" "$@"; }
BASE="$ROOT/evidence/checkpoint-bootstrap"
install -d -m 0700 "$BASE" "$BASE/raw"
[[ -d "$BASE" && ! -L "$BASE" && -d "$BASE/raw" && ! -L "$BASE/raw"
  && "$(stat -c '%u:%a' "$BASE/raw")" == "$(id -u):700" ]] || exit 1
TARGET="$BASE/raw/ratification-observation.json"
# Request, signatures and transaction references remain immutable; only this
# finalized observation is retryable and must be absent before collector RPC.
node "$ROOT/scripts/remove-private-file-durable.mjs" "$TARGET"
TEMPORARY=$(mktemp -p "$BASE/raw" .ratification-observation.XXXXXXXX)
trap 'rm -f -- "$TEMPORARY"' EXIT HUP INT TERM
node "$ROOT/scripts/collect-checkpoint-bootstrap-ratification-observation.mjs" >"$TEMPORARY"
chmod 0600 "$TEMPORARY"; sync -f "$TEMPORARY"
node "$ROOT/scripts/install-private-file-immutable-stdin.mjs" "$TARGET" <"$TEMPORARY"
[[ -f "$TARGET" && ! -L "$TARGET" && "$(stat -c '%u:%a' "$TARGET")" == "$(id -u):600" ]] || exit 1
sync -f "$TARGET"; sync -f "$BASE/raw"
