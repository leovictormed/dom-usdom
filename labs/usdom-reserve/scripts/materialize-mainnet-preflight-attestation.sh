#!/usr/bin/env bash
set -euo pipefail
umask 077
if (($# != 1)) || [[ $1 != predeployment && $1 != postdeployment ]]; then
  printf '%s\n' 'usage: internal fixed wrapper <predeployment|postdeployment>' >&2
  exit 64
fi
for command in node flock realpath timeout stat sha256sum cut dirname id; do command -v "$command" >/dev/null; done
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
  [[ $(stat -Lc '%d:%i:%u:%a' "$parent") == "${!parent_identity_name}" && $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" ]]
  [[ $(sha256sum "$path" | cut -d ' ' -f 1) == "${!sha_name}" && $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" ]]
}
pin_tool node; pin_tool timeout
project=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$project"
exec 9<"$project/config"
flock -n 9 || { printf '%s\n' 'Another release materializer holds the config-directory lock' >&2; exit 75; }
assert_tool_unchanged node; assert_tool_unchanged timeout
exec "$timeout_bin" --signal=TERM --kill-after=5s 300s \
  "$node_bin" scripts/materialize-mainnet-preflight-attestation.mjs "$1"
