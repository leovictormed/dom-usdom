#!/usr/bin/env bash
set -euo pipefail
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent materialize:native-preactivation-facts' >&2
  exit 64
fi
for command in node jq stat realpath mktemp flock sync cmp; do command -v "$command" >/dev/null; done
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
project=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$project"
policy="$project/config/native-preactivation-policy.unconfigured.json"
target="$project/config/native-preactivation-facts.unconfigured.json"
evidence_directory="$project/evidence/native-preactivation"
anchor="$evidence_directory/dom-anchor.json"
for required in "$policy" "$target" "$anchor"; do
  [[ -f "$required" && ! -L "$required" ]] || {
    printf 'Missing direct regular configuration file: %s\n' "$required" >&2
    exit 1
  }
done
exec 9<"$project/config"
flock -n 9 || { printf '%s\n' 'Another release materializer holds the config lock' >&2; exit 75; }
temporary_facts=$(mktemp -p "$project/config" .native-preactivation-facts.XXXXXXXX)
cleanup() { local status=${1:-$?}; trap - EXIT; assert_tool_unchanged node && "$node_bin" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' "$temporary_facts" || status=1; exit "$status"; }
trap 'cleanup $?' EXIT
assert_tool_unchanged node
"$node_bin" scripts/prepare-native-preactivation-facts.mjs < "$anchor" > "$temporary_facts"
assert_tool_unchanged jq
"$jq_bin" -e '.schema == "usdom-native-preactivation-facts-v1"
  and .checkpointFirstV4Height == ((.checkpointInitialHeight|tonumber)+1|tostring)
  and .checkpointInitialBlock != null and .checkpointInitialContextHash != null
  and .checkpointInitialTotalDifficulty != "0"' "$temporary_facts" >/dev/null
chmod 0600 "$temporary_facts"
sync -f "$temporary_facts"
if ! cmp -s "$temporary_facts" "$target"; then
  assert_tool_unchanged node
  "$node_bin" scripts/install-release-config-stdin.mjs "$target" < "$temporary_facts"
fi
sync -f "$target"; sync -f "$project/config"
assert_tool_unchanged jq
"$jq_bin" . "$target"
