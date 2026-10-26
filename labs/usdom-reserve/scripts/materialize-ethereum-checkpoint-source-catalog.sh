#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
TARGET="$ROOT/config/ethereum-checkpoint-source-catalog.unconfigured.json"
for command in node jq mktemp flock sync cmp stat id; do command -v "$command" >/dev/null; done
pin_tool() {
 local name=$1 path parent owner mode size parent_owner parent_mode identity_name parent_identity_name
 path=$(realpath "$(command -v "$name")"); [[ -x $path && -f $path && ! -L $path ]]
 owner=$(stat -Lc '%u' "$path"); [[ $owner == 0 || $owner == "$(id -u)" ]]; [[ $(stat -Lc '%h' "$path") == 1 ]]
 size=$(stat -Lc '%s' "$path"); (( size > 0 && size <= 512 * 1024 * 1024 )); mode=$(stat -Lc '%a' "$path"); (( (8#$mode & 8#022) == 0 ))
 parent=$(dirname "$path"); [[ $(realpath "$parent") == "$parent" ]]; parent_owner=$(stat -Lc '%u' "$parent"); [[ $parent_owner == 0 || $parent_owner == "$(id -u)" ]]
 parent_mode=$(stat -Lc '%a' "$parent"); (( (8#$parent_mode & 8#022) == 0 ))
 printf -v "${name}_bin" '%s' "$path"; printf -v "${name}_identity" '%s' "$(stat -Lc '%d:%i:%s:%Y:%Z' "$path")"; printf -v "${name}_parent_identity" '%s' "$(stat -Lc '%d:%i:%u:%a' "$parent")"; printf -v "${name}_sha256" '%s' "$(sha256sum "$path" | cut -d ' ' -f 1)"
 identity_name="${name}_identity"; parent_identity_name="${name}_parent_identity"; [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" && $(stat -Lc '%d:%i:%u:%a' "$parent") == "${!parent_identity_name}" ]]
}
assert_tool_unchanged() {
 local name=$1 bin_name="${1}_bin" identity_name="${1}_identity" parent_identity_name="${1}_parent_identity" sha_name="${1}_sha256" path parent; path=${!bin_name}; parent=$(dirname "$path")
 [[ $(realpath "$(command -v "$name")") == "$path" && $(realpath "$parent") == "$parent" && $(stat -Lc '%d:%i:%u:%a' "$parent") == "${!parent_identity_name}" ]]
 [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" && $(sha256sum "$path" | cut -d ' ' -f 1) == "${!sha_name}" && $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" ]]
}
pin_tool node; pin_tool jq
[[ -f "$TARGET" && ! -L "$TARGET" && "$(stat -c '%u:%a' "$TARGET")" == "$(id -u):644" ]] || {
  printf '%s\n' 'Source catalog target must be a direct caller-owned mode-0644 file' >&2
  exit 1
}
exec 9<"$ROOT/config"
flock -n 9 || { printf '%s\n' 'Another release materializer holds the config lock' >&2; exit 75; }
TMP=$(mktemp -p "$ROOT/config" .ethereum-checkpoint-source-catalog.XXXXXXXX)
cleanup() { local status=${1:-$?}; trap - EXIT HUP INT TERM; assert_tool_unchanged node && "$node_bin" -e 'require("fs").rmSync(process.argv[1],{force:true})' "$TMP" || status=1; exit "$status"; }
trap 'cleanup $?' EXIT; trap 'cleanup 129' HUP; trap 'cleanup 130' INT; trap 'cleanup 143' TERM
assert_tool_unchanged node
"$node_bin" "$ROOT/scripts/prepare-ethereum-checkpoint-source-catalog.mjs" >"$TMP"
assert_tool_unchanged jq
"$jq_bin" -e '.schema == "usdom-ethereum-checkpoint-source-catalog-v1"
  and (.sources|length) == 3
  and all(.sources[]; (.operatorId|type)=="string"
    and (.originKeccak256|test("^0x[0-9a-f]{64}$")))' "$TMP" >/dev/null
if jq -e 'any(.sources[]; .operatorId != null or .originKeccak256 != null)' "$TARGET" >/dev/null; then
  cmp -s "$TMP" "$TARGET" || {
    printf '%s\n' 'Existing source catalog differs; refusing to rotate trust implicitly' >&2
    exit 1
  }
else
  chmod 0600 "$TMP"; sync -f "$TMP"
  assert_tool_unchanged node
  "$node_bin" "$ROOT/scripts/install-release-config-stdin.mjs" "$TARGET" <"$TMP"
  sync -f "$TARGET"; sync -f "$ROOT/config"
fi
assert_tool_unchanged jq
"$jq_bin" . "$TARGET"
