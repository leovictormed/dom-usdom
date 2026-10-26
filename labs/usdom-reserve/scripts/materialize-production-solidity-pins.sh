#!/usr/bin/env bash
set -euo pipefail
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent materialize:production-solidity-pins' >&2
  exit 64
fi
for command in node jq stat realpath mktemp flock sync cmp install mv sha256sum awk; do command -v "$command" >/dev/null; done
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
config="$project/config/proof-reserve.unconfigured.json"
reserve="$project/contracts/USDOMProofReserve.sol"
registry="$project/contracts/DOMCheckpointRegistry.sol"
for target in "$config" "$reserve" "$registry"; do
  test -f "$target"; test ! -L "$target"
  test "$(stat -c '%u' "$target")" = "$(id -u)"
  test "$(stat -c '%h' "$target")" = '1'
done
exec 9<"$project/config"
flock -n 9 || { printf '%s\n' 'Another release materializer holds the config lock' >&2; exit 75; }
exec 8<"$project/contracts"
flock -n 8 || { printf '%s\n' 'Another source materializer holds the contracts lock' >&2; exit 75; }
temporary=$(mktemp -d -p "$project" .production-solidity-pins.XXXXXXXX)
cleanup() { local status=${1:-$?}; trap - EXIT; assert_tool_unchanged node && "$node_bin" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' "$temporary" || status=1; exit "$status"; }
trap 'cleanup $?' EXIT
assert_tool_unchanged node
"$node_bin" scripts/prepare-production-solidity-pins.mjs > "$temporary/envelope.json"
assert_tool_unchanged jq
"$jq_bin" -er '.reserveSource' "$temporary/envelope.json" > "$temporary/reserve.sol"
assert_tool_unchanged jq
"$jq_bin" -er '.checkpointRegistrySource' "$temporary/envelope.json" > "$temporary/registry.sol"
expected_config=$(assert_tool_unchanged jq; "$jq_bin" -er '.inputSha256.releaseConfig' "$temporary/envelope.json")
expected_reserve=$(assert_tool_unchanged jq; "$jq_bin" -er '.inputSha256.reserveSource' "$temporary/envelope.json")
expected_registry=$(assert_tool_unchanged jq; "$jq_bin" -er '.inputSha256.checkpointRegistrySource' "$temporary/envelope.json")
test "$(sha256sum "$config" | awk '{print $1}')" = "$expected_config"
test "$(sha256sum "$reserve" | awk '{print $1}')" = "$expected_reserve"
test "$(sha256sum "$registry" | awk '{print $1}')" = "$expected_registry"
for pair in "$reserve:$temporary/reserve.sol" "$registry:$temporary/registry.sol"; do
  target=${pair%%:*}; candidate=${pair#*:}
  test -s "$candidate"
  chmod 0644 "$candidate"
  sync -f "$candidate"
  if ! cmp -s "$candidate" "$target"; then
    test "$(sha256sum "$config" | awk '{print $1}')" = "$expected_config"
    install -m 0644 -T "$candidate" "$target.new"
    sync -f "$target.new"
    mv -T "$target.new" "$target"
    sync -f "$target"
  fi
done
cmp -s "$temporary/reserve.sol" "$reserve"
cmp -s "$temporary/registry.sol" "$registry"
test "$(sha256sum "$config" | awk '{print $1}')" = "$expected_config"
sync -f "$project/contracts"
assert_tool_unchanged jq
"$jq_bin" -n '{ok:true,productionReady:false,realFundsAuthorized:false,
  sources:["contracts/USDOMProofReserve.sol","contracts/DOMCheckpointRegistry.sol"]}'
