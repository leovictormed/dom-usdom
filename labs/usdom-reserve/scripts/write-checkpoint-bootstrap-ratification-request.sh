#!/usr/bin/env bash
set -euo pipefail
umask 077
if (($# != 0)); then printf '%s\n' 'Usage: bash scripts/write-checkpoint-bootstrap-ratification-request.sh' >&2; exit 64; fi
for command in node realpath install stat id mktemp chmod sync sha256sum cmp awk; do command -v "$command" >/dev/null; done
ROOT=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$ROOT"
for tool_boundary_command in stat id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node
node() { assert_runtime_tool node; "$node_bin" "$@"; }
BASE="$ROOT/evidence/checkpoint-bootstrap"
install -d -m 0700 "$BASE"
[[ -d "$BASE" && ! -L "$BASE" && "$(stat -c '%u:%a' "$BASE")" == "$(id -u):700" ]] || exit 1
REQUEST="$BASE/ratification-signing-request.json"
SHA="$BASE/ratification-signing-request.sha256"
[[ ! -e "$REQUEST" && ! -L "$REQUEST" ]] || exit 1
if [[ -e "$SHA" || -L "$SHA" ]]; then
  [[ -f "$SHA" && ! -L "$SHA" && "$(stat -c '%u:%a' "$SHA")" == "$(id -u):600" ]] || exit 1
fi
TEMPORARY=$(mktemp -d -p /dev/shm usdom-checkpoint-ratification-request.XXXXXXXX)
chmod 0700 "$TEMPORARY"
TEMPORARY_IDENTITY=$(/usr/bin/stat -c '%u:%d:%i:%a' -- "$TEMPORARY")
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  if [[ $(/usr/bin/stat -c '%u:%d:%i:%a' -- "$TEMPORARY" 2>/dev/null) == "$TEMPORARY_IDENTITY" ]]; then
    /usr/bin/rm -rf -- "$TEMPORARY" || { (( status != 0 )) || status=1; }
  else
    (( status != 0 )) || status=1
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
node "$ROOT/scripts/prepare-checkpoint-bootstrap-ratification-request.mjs" > "$TEMPORARY/request.json"
chmod 0600 "$TEMPORARY/request.json"
sha256sum "$TEMPORARY/request.json" | awk '{print $1}' > "$TEMPORARY/request.sha256"
chmod 0600 "$TEMPORARY/request.sha256"
if [[ -e "$SHA" ]]; then
  cmp -s "$TEMPORARY/request.sha256" "$SHA" || {
    printf '%s\n' 'Existing ratification-request hash differs from rebuilt output.' >&2
    exit 1
  }
else
  node "$ROOT/scripts/install-private-file-immutable-stdin.mjs" "$SHA" < "$TEMPORARY/request.sha256"
fi
cmp -s "$TEMPORARY/request.sha256" "$SHA" || exit 1
node "$ROOT/scripts/install-private-file-immutable-stdin.mjs" --json "$REQUEST" < "$TEMPORARY/request.json"
[[ -f "$REQUEST" && ! -L "$REQUEST" && "$(stat -c '%u:%a' "$REQUEST")" == "$(id -u):600" ]] || exit 1
cmp -s "$TEMPORARY/request.json" "$REQUEST" || exit 1
sync -f "$REQUEST"; sync -f "$SHA"; sync -f "$BASE"
