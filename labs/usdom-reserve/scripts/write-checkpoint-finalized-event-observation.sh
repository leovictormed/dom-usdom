#!/usr/bin/env bash
set -euo pipefail
umask 077
if (($# != 0)); then printf '%s\n' 'Usage: bash scripts/write-checkpoint-finalized-event-observation.sh' >&2; exit 64; fi
for command in node realpath install stat id mktemp chmod sync timeout sha256sum cut dirname; do command -v "$command" >/dev/null; done
pin_tool() {
  local name=$1 path owner mode size parent parent_owner parent_mode identity_name parent_identity_name
  path=$(realpath "$(command -v "$name")"); [[ -x $path && -f $path && ! -L $path ]]
  owner=$(stat -Lc '%u' "$path"); [[ $owner == 0 || $owner == "$(id -u)" ]]; [[ $(stat -Lc '%h' "$path") == 1 ]]
  size=$(stat -Lc '%s' "$path"); (( size > 0 && size <= 512 * 1024 * 1024 ))
  mode=$(stat -Lc '%a' "$path"); (( (8#$mode & 8#022) == 0 ))
  parent=$(dirname "$path"); [[ $(realpath "$parent") == "$parent" ]]
  parent_owner=$(stat -Lc '%u' "$parent"); [[ $parent_owner == 0 || $parent_owner == "$(id -u)" ]]
  parent_mode=$(stat -Lc '%a' "$parent"); (( (8#$parent_mode & 8#022) == 0 ))
  printf -v "${name}_bin" '%s' "$path"; printf -v "${name}_identity" '%s' "$(stat -Lc '%d:%i:%s:%Y:%Z' "$path")"
  printf -v "${name}_parent_identity" '%s' "$(stat -Lc '%d:%i:%u:%a' "$parent")"; printf -v "${name}_sha256" '%s' "$(sha256sum "$path" | cut -d ' ' -f 1)"
  identity_name="${name}_identity"; parent_identity_name="${name}_parent_identity"
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" && $(stat -Lc '%d:%i:%u:%a' "$parent") == "${!parent_identity_name}" ]]
}
assert_tool_unchanged() {
  local name=$1 bin_name="${1}_bin" identity_name="${1}_identity" parent_identity_name="${1}_parent_identity" sha_name="${1}_sha256" path parent
  path=${!bin_name}; parent=$(dirname "$path"); [[ $(realpath "$(command -v "$name")") == "$path" && $(realpath "$parent") == "$parent" ]]
  [[ $(stat -Lc '%d:%i:%u:%a' "$parent") == "${!parent_identity_name}" && $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" ]] || return 1
  [[ $(sha256sum "$path" | cut -d ' ' -f 1) == "${!sha_name}" && $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" ]] || return 1
}
pin_tool node; pin_tool timeout
ROOT=$(realpath "$(dirname "$0")/.."); test "$PWD" = "$ROOT"
BASE="$ROOT/evidence/checkpoint-finalized-event"
install -d -m 0700 "$BASE" "$BASE/raw"
[[ -d "$BASE" && ! -L "$BASE" && -d "$BASE/raw" && ! -L "$BASE/raw"
  && "$(stat -c '%u:%a' "$BASE/raw")" == "$(id -u):700" ]] || exit 1
TARGET="$BASE/raw/checkpoint-finalized-event-observation.json"
# Submission and transaction references remain immutable; only the finalized
# event observation is retryable and is invalidated before collector RPC.
assert_tool_unchanged node; assert_tool_unchanged timeout
"$timeout_bin" --signal=TERM --kill-after=2s 30s \
  "$node_bin" "$ROOT/scripts/remove-private-file-durable.mjs" "$TARGET"
TEMPORARY=$(mktemp -p "$BASE/raw" .checkpoint-finalized-event.XXXXXXXX)
TEMPORARY_IDENTITY=$(/usr/bin/stat -c '%u:%d:%i:%a' -- "$TEMPORARY")
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  if [[ $(/usr/bin/stat -c '%u:%d:%i:%a' -- "$TEMPORARY" 2>/dev/null) == "$TEMPORARY_IDENTITY" ]]; then
    /usr/bin/rm -f -- "$TEMPORARY" || { (( status != 0 )) || status=1; }
  else
    (( status != 0 )) || status=1
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT; trap 'cleanup 129' HUP; trap 'cleanup 130' INT; trap 'cleanup 143' TERM
assert_tool_unchanged node; assert_tool_unchanged timeout
"$timeout_bin" --signal=TERM --kill-after=5s 300s \
  "$node_bin" "$ROOT/scripts/collect-checkpoint-finalized-event-observation.mjs" >"$TEMPORARY"
chmod 0600 "$TEMPORARY"; sync -f "$TEMPORARY"
assert_tool_unchanged node; assert_tool_unchanged timeout
"$timeout_bin" --signal=TERM --kill-after=2s 30s \
  "$node_bin" "$ROOT/scripts/install-private-file-immutable-stdin.mjs" "$TARGET" <"$TEMPORARY"
[[ -f "$TARGET" && ! -L "$TARGET" && "$(stat -c '%u:%a' "$TARGET")" == "$(id -u):600" ]] || exit 1
sync -f "$TARGET"; sync -f "$BASE/raw"
