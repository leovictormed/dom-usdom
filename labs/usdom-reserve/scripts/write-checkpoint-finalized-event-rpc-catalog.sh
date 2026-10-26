#!/usr/bin/env bash
set -euo pipefail
umask 022
if (($# != 0)); then printf '%s\n' 'Usage: bash scripts/write-checkpoint-finalized-event-rpc-catalog.sh' >&2; exit 64; fi
for command in node realpath mktemp chmod sync; do command -v "$command" >/dev/null; done
ROOT=$(realpath "$(dirname "$0")/.."); test "$PWD" = "$ROOT"
for tool_boundary_command in stat id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node
node() { assert_runtime_tool node; "$node_bin" "$@"; }
TARGET="$ROOT/config/checkpoint-finalized-event-rpc-catalog.json"
[[ ! -e "$TARGET" && ! -L "$TARGET" ]] || { printf '%s\n' 'RPC catalog already exists' >&2; exit 1; }
TEMPORARY=$(mktemp -p "$ROOT/config" .checkpoint-finalized-rpc-catalog.XXXXXXXX)
trap 'rm -f -- "$TEMPORARY"' EXIT HUP INT TERM
node "$ROOT/scripts/prepare-checkpoint-finalized-event-rpc-catalog.mjs" >"$TEMPORARY"
chmod 0644 "$TEMPORARY"; sync -f "$TEMPORARY"
node "$ROOT/scripts/install-public-file-create-once-stdin.mjs" "$TARGET" <"$TEMPORARY"
[[ -f "$TARGET" && ! -L "$TARGET" ]] || exit 1
sync -f "$TARGET"; sync -f "$ROOT/config"
