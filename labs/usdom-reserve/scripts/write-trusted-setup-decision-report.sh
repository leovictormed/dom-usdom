#!/usr/bin/env bash
set -euo pipefail
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: bash scripts/write-trusted-setup-decision-report.sh' >&2
  exit 64
fi
for command in node jq sha256sum stat realpath mktemp flock sync mv cmp id chmod awk timeout python3; do
  command -v "$command" >/dev/null
done
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
 [[ $(realpath "$(command -v "$name")") == "$path" && $(realpath "$parent") == "$parent" && $(stat -Lc '%d:%i:%u:%a' "$parent") == "${!parent_identity_name}" ]] || return 1
 [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" && $(sha256sum "$path" | cut -d ' ' -f 1) == "${!sha_name}" && $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" ]] || return 1
}
pin_tool node; pin_tool jq; pin_tool timeout; pin_tool python3
project=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$project"
config_directory="$project/config"
metadata="$config_directory/mainnet-release-evidence.unconfigured.json"
evidence_root="$project/evidence"
output="$evidence_root/trusted-setup"
if [[ ! -e "$evidence_root" ]]; then mkdir -m 0700 "$evidence_root"; fi
test -d "$evidence_root"; test ! -L "$evidence_root"
test "$(stat -c '%u' "$evidence_root")" = "$(id -u)"
test "$(stat -c '%a' "$evidence_root")" = 700
if [[ ! -e "$output" ]]; then mkdir -m 0700 "$output"; fi
test -d "$output"; test ! -L "$output"
test "$(stat -c '%u' "$output")" = "$(id -u)"
test "$(stat -c '%a' "$output")" = 700
exec 8<"$config_directory"
flock -n 8 || { printf '%s\n' 'Another release materializer holds the config lock' >&2; exit 75; }
exec 9<"$output"
flock -n 9 || { printf '%s\n' 'Another trusted-setup writer holds the output lock' >&2; exit 75; }
metadata_sha256=$(sha256sum "$metadata" | awk '{print $1}')
parent_device=$(stat -Lc '%d' "$config_directory")
parent_inode=$(stat -Lc '%i' "$config_directory")

invalidation=$(mktemp -p "$output" .invalidate.XXXXXXXX)
cleanup_invalidation() {
  local status=${1:-$?}; trap - EXIT
  if assert_tool_unchanged node && assert_tool_unchanged timeout &&
    "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
      "$node_bin" -e 'require("fs").rmSync(process.argv[1],{force:true})' "$invalidation" \
      > /dev/null 2> /dev/null &&
    assert_tool_unchanged node && assert_tool_unchanged timeout && test ! -e "$invalidation"; then :; else status=1; fi
  exit "$status"
}
trap 'cleanup_invalidation $?' EXIT
assert_tool_unchanged node
"$node_bin" "$project/scripts/read-release-config-file-stdout.mjs" "$metadata" \
  | (assert_tool_unchanged jq; "$jq_bin" '.trustedSetup.decisionReport=null | .checkpointTrustedSetup.decisionReport=null') > "$invalidation"
chmod 0600 "$invalidation"; sync -f "$invalidation"
assert_tool_unchanged node
assert_tool_unchanged python3
candidate_sha256=$(sha256sum "$invalidation" | awk '{print $1}')
"$node_bin" "$project/scripts/replace-locked-source-stdin.mjs" "$metadata" \
  "$candidate_sha256" "$metadata_sha256" "$parent_device" "$parent_inode" \
  "$python3_bin" "$python3_sha256" < "$invalidation"
metadata_sha256=$candidate_sha256
assert_tool_unchanged node
"$node_bin" "$project/scripts/remove-private-file-durable.mjs" "$output/trusted-setup-decision-report.json"
sync -f "$metadata"; sync -f "$output"; sync -f "$config_directory"

temporary=$(mktemp -d -p "$output" .build.XXXXXXXX)
cleanup() {
  local status=${1:-$?}; trap - EXIT
  if assert_tool_unchanged node && assert_tool_unchanged timeout &&
    "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
      "$node_bin" -e 'const fs=require("fs");for(const p of process.argv.slice(1))fs.rmSync(p,{recursive:true,force:true})' \
      "$invalidation" "$temporary" > /dev/null 2> /dev/null &&
    assert_tool_unchanged node && assert_tool_unchanged timeout &&
    test ! -e "$invalidation" && test ! -e "$temporary"; then :; else status=1; fi
  exit "$status"
}
trap 'cleanup $?' EXIT
report="$temporary/trusted-setup-decision-report.json"
next_metadata="$temporary/mainnet-release-evidence.json"
metadata_snapshot="$temporary/mainnet-release-evidence.input.json"
metadata_current="$temporary/mainnet-release-evidence.current.json"
metadata_installed="$temporary/mainnet-release-evidence.installed.json"
assert_tool_unchanged node
"$node_bin" "$project/scripts/read-release-config-file-stdout.mjs" "$metadata" > "$metadata_snapshot"
assert_tool_unchanged node
"$node_bin" scripts/prepare-trusted-setup-decision-report.mjs > "$report"
chmod 0600 "$report"
assert_tool_unchanged node
"$node_bin" "$project/scripts/read-release-config-file-stdout.mjs" "$metadata" > "$metadata_current"
cmp -s "$metadata_snapshot" "$metadata_current"
report_sha=$(sha256sum "$report" | awk '{print $1}')
report_path=evidence/trusted-setup/trusted-setup-decision-report.json
assert_tool_unchanged jq
"$jq_bin" --arg path "$report_path" --arg sha "$report_sha" '
  ({path:$path,sha256:$sha}) as $document |
  if (.trustedSetup.decisionReport == null or .trustedSetup.decisionReport == $document)
     and (.checkpointTrustedSetup.decisionReport == null or .checkpointTrustedSetup.decisionReport == $document)
  then .trustedSetup.decisionReport=$document | .checkpointTrustedSetup.decisionReport=$document
  else error("trusted-setup report slot already contains a different document") end
' "$metadata_snapshot" > "$next_metadata"
chmod 0600 "$next_metadata"
target="$output/trusted-setup-decision-report.json"
sync -f "$report"; sync -f "$next_metadata"
assert_tool_unchanged node
"$node_bin" "$project/scripts/install-private-file-immutable-stdin.mjs" "$target" < "$report"
sync -f "$target"
assert_tool_unchanged node
"$node_bin" "$project/scripts/read-release-config-file-stdout.mjs" "$metadata" > "$metadata_current"
cmp -s "$metadata_snapshot" "$metadata_current"
if ! cmp -s "$next_metadata" "$metadata_snapshot"; then
  assert_tool_unchanged node
  assert_tool_unchanged python3
  candidate_sha256=$(sha256sum "$next_metadata" | awk '{print $1}')
  "$node_bin" "$project/scripts/replace-locked-source-stdin.mjs" "$metadata" \
    "$candidate_sha256" "$metadata_sha256" "$parent_device" "$parent_inode" \
    "$python3_bin" "$python3_sha256" < "$next_metadata"
fi
assert_tool_unchanged node
"$node_bin" "$project/scripts/read-release-config-file-stdout.mjs" "$metadata" > "$metadata_installed"
cmp -s "$next_metadata" "$metadata_installed"
sync -f "$metadata"; sync -f "$output"; sync -f "$config_directory"
assert_tool_unchanged jq
"$jq_bin" '{trustedSetup,checkpointTrustedSetup}' "$next_metadata"
