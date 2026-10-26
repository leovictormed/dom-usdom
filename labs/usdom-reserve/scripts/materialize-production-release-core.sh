#!/usr/bin/env bash
set -euo pipefail
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent materialize:production-release-core' >&2
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
 [[ $(realpath "$(command -v "$name")") == "$path" && $(realpath "$parent") == "$parent" && $(stat -Lc '%d:%i:%u:%a' "$parent") == "${!parent_identity_name}" ]]
 [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" && $(sha256sum "$path" | cut -d ' ' -f 1) == "${!sha_name}" && $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" ]]
}
pin_tool node; pin_tool jq
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
temporary=$(mktemp -p "$config_directory" .production-release-core.XXXXXXXX)
cleanup() { local status=${1:-$?}; trap - EXIT; assert_tool_unchanged node && "$node_bin" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' "$temporary" || status=1; exit "$status"; }
trap 'cleanup $?' EXIT
assert_tool_unchanged node
"$node_bin" scripts/prepare-production-release-core-materialization.mjs > "$temporary"
assert_tool_unchanged jq
"$jq_bin" -e '.productionReady == false and .realFundsAuthorized == false
  and .reserveConfigHash != null and .checkpointRegistryConfigHash != null
  and .reserveRuntimeCodeHash != null and .reserveInitcodeHash != null
  and .checkpointRegistryRuntimeCodeHash != null and .checkpointRegistryInitcodeHash != null
  and .verifierCodeHash != null and .verifierInitcodeHash != null
  and .checkpointVerifierCodeHash != null and .checkpointVerifierInitcodeHash != null' "$temporary" >/dev/null
chmod 0600 "$temporary"
sync -f "$temporary"
# The preparer rechecked every source before emitting output. Recheck the
# mutable template as well so it cannot be replaced between that snapshot and
# the durable transition below.
test "$(sha256sum "$target" | awk '{print $1}')" = "$target_sha256" || {
  printf '%s\n' 'Release template changed during materialization' >&2
  exit 75
}
if ! cmp -s "$temporary" "$target"; then
  assert_tool_unchanged node
  "$node_bin" scripts/install-release-config-stdin.mjs "$target" < "$temporary"
fi
sync -f "$target"
sync -f "$config_directory"
assert_tool_unchanged jq
"$jq_bin" '{productionReady,realFundsAuthorized,domDomain,activationScheduleCommitment,
  reserveRuntimeCodeHash,reserveInitcodeHash,
  verifierCodeHash,verifierInitcodeHash,verifierConfigHash,reserveConfigHash,checkpointVerifierCodeHash,
  checkpointVerifierInitcodeHash,checkpointVerifierConfigHash,checkpointRegistryConfigHash,checkpointInitialHeight,
  checkpointInitialBlock,checkpointInitialStateRoot,checkpointInitialContextHash,
  checkpointInitialTotalDifficulty}' "$target"
