#!/usr/bin/env bash
set -euo pipefail
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent materialize:production-preactivation-core' >&2
  exit 64
fi
for command in node jq stat realpath mktemp flock sync cmp sha256sum awk; do command -v "$command" >/dev/null; done
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
target="$config_directory/proof-reserve.unconfigured.json"
test -f "$target"; test ! -L "$target"
test "$(stat -c '%u' "$target")" = "$(id -u)"
test "$(stat -c '%a' "$target")" = '644'
target_sha256=$(sha256sum "$target" | awk '{print $1}')
exec 9<"$config_directory"
flock -n 9 || { printf '%s\n' 'Another release materializer holds the config lock' >&2; exit 75; }
temporary=$(mktemp -p "$config_directory" .production-preactivation-core.XXXXXXXX)
cleanup() {
  local status=${1:-$?}
  trap - EXIT
  if assert_tool_unchanged node && assert_tool_unchanged timeout &&
    "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
      "$node_bin" -e 'const fs=require("fs");fs.rmSync(process.argv[1],{recursive:true,force:true});fs.rmSync(process.argv[2],{recursive:true,force:true})' \
      "$temporary" "$temporary.rechecked" > /dev/null 2> /dev/null &&
    assert_tool_unchanged node && assert_tool_unchanged timeout && test ! -e "$temporary" &&
      test ! -e "$temporary.rechecked"; then
    :
  else
    status=1
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
assert_tool_unchanged node
"$node_bin" scripts/prepare-production-preactivation-core-materialization.mjs > "$temporary"
assert_tool_unchanged jq
"$jq_bin" -e '.productionReady == false and .realFundsAuthorized == false
  and .activationScheduleCommitment == null and .checkpointActivationEmptyStateRoot == null
  and .checkpointInitialStateRoot == null and .reserveConfigHash == null
  and .checkpointRegistryConfigHash != null and .verifierCodeHash != null
  and .verifierInitcodeHash != null and .checkpointVerifierCodeHash != null
  and .checkpointVerifierInitcodeHash != null' "$temporary" >/dev/null
chmod 0600 "$temporary"
sync -f "$temporary"
test "$(sha256sum "$target" | awk '{print $1}')" = "$target_sha256" || {
  printf '%s\n' 'Release template changed during preactivation materialization' >&2
  exit 75
}
if ! cmp -s "$temporary" "$target"; then
  assert_tool_unchanged node
  assert_tool_unchanged python3
  candidate_sha256=$(sha256sum "$temporary" | awk '{print $1}')
  parent_device=$(stat -Lc '%d' "$config_directory")
  parent_inode=$(stat -Lc '%i' "$config_directory")
  "$node_bin" scripts/replace-locked-source-stdin.mjs "$target" "$candidate_sha256" \
    "$target_sha256" "$parent_device" "$parent_inode" "$python3_bin" "$python3_sha256" \
    < "$temporary"
fi
test -f "$target"; test ! -L "$target"
test "$(stat -Lc '%u:%a:%h' "$target")" = "$(id -u):644:1"
cmp -s "$temporary" "$target"
sync -f "$target"; sync -f "$config_directory"
cmp -s "$temporary" "$target"
# Re-derive from all installed inputs after the durable directory boundary.
# This makes a late, non-cooperating source/artifact replacement observable
# before the materializer reports success.
assert_tool_unchanged node
"$node_bin" scripts/prepare-production-preactivation-core-materialization.mjs > "$temporary.rechecked"
cmp -s "$temporary" "$temporary.rechecked"
cmp -s "$temporary" "$target"
"$node_bin" scripts/prepare-production-preactivation-core-materialization.mjs > "$temporary.rechecked"
cmp -s "$temporary" "$temporary.rechecked"
cmp -s "$temporary" "$target"
"$node_bin" scripts/prepare-production-preactivation-core-materialization.mjs > "$temporary.rechecked"
cmp -s "$temporary" "$temporary.rechecked"
assert_tool_unchanged jq
assert_tool_unchanged python3
"$jq_bin" '{productionReady,realFundsAuthorized,domDomain,activationScheduleCommitment,
  verifierCodeHash,verifierInitcodeHash,verifierConfigHash,reserveConfigHash,checkpointVerifierCodeHash,
  checkpointVerifierInitcodeHash,checkpointVerifierConfigHash,checkpointRegistryConfigHash,
  checkpointActivationEmptyStateRoot}' "$target"
