#!/usr/bin/env bash
set -euo pipefail
umask 077

if (($# < 1)) || [[ $1 != reserve && $1 != checkpointRegistry ]] ||
  [[ $1 == reserve && $# != 2 ]] || [[ $1 == checkpointRegistry && $# != 1 ]]; then
  printf '%s\n' 'Usage: npm run --silent materialize:production-solidity-pins -- checkpointRegistry | reserve RATIFICATION_PROPOSAL' >&2
  exit 64
fi
component=$1
ratification_proposal=${2:-}
for command in node jq python3 stat realpath mktemp flock sync cmp mv sha256sum awk; do command -v "$command" >/dev/null; done
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
pin_tool node; pin_tool jq; pin_tool python3; pin_tool timeout
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
config_directory_identity=$(stat -Lc '%d:%i:%u:%a' /proc/self/fd/9)
contracts_directory_identity=$(stat -Lc '%d:%i:%u:%a' /proc/self/fd/8)
contracts_directory_device=$(stat -Lc '%d' /proc/self/fd/8)
contracts_directory_inode=$(stat -Lc '%i' /proc/self/fd/8)
assert_project_directories() {
  test "$(realpath /proc/self/fd/9)" = "$project/config"
  test "$(realpath /proc/self/fd/8)" = "$project/contracts"
  test "$(stat -Lc '%d:%i:%u:%a' "$project/config")" = "$config_directory_identity"
  test "$(stat -Lc '%d:%i:%u:%a' "$project/contracts")" = "$contracts_directory_identity"
}
assert_project_directories
# Every mutable input/output below resolves through the locked directory inode.
config=/proc/self/fd/9/proof-reserve.unconfigured.json
reserve=/proc/self/fd/8/USDOMProofReserve.sol
registry=/proc/self/fd/8/DOMCheckpointRegistry.sol
temporary=$(mktemp -d -p "$project" .production-solidity-pins.XXXXXXXX)
cleanup() {
  local status=${1:-$?}
  trap - EXIT
  if assert_tool_unchanged node && assert_tool_unchanged timeout &&
    "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
      "$node_bin" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' \
      "$temporary" > /dev/null 2> /dev/null &&
    assert_tool_unchanged node && assert_tool_unchanged timeout && test ! -e "$temporary"; then
    :
  else
    # Cleanup must fail an otherwise successful run, but it must not erase a
    # more informative operation status (especially 80: rename was applied
    # and requires revalidation).
    (( status != 0 )) || status=1
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
verify_reserve_ratification() {
  [[ $component != reserve ]] || {
    assert_tool_unchanged node
    "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
      "$node_bin" scripts/check-reserve-pin-ratification.mjs "$ratification_proposal" \
      config/proof-reserve.unconfigured.json config/finalized-burn-verifier.unconfigured.json \
      > /dev/null
    assert_tool_unchanged node
  }
}
assert_tool_unchanged node
verify_reserve_ratification
"$node_bin" scripts/prepare-production-solidity-pins.mjs "$component" > "$temporary/envelope.json"
expected_config=$(assert_tool_unchanged jq; "$jq_bin" -er '.inputSha256.releaseConfig' "$temporary/envelope.json")
expected_reserve=$(assert_tool_unchanged jq; "$jq_bin" -er '.inputSha256.reserveSource' "$temporary/envelope.json")
expected_registry=$(assert_tool_unchanged jq; "$jq_bin" -er '.inputSha256.checkpointRegistrySource' "$temporary/envelope.json")
test "$(sha256sum "$config" | awk '{print $1}')" = "$expected_config"
test "$(sha256sum "$reserve" | awk '{print $1}')" = "$expected_reserve"
test "$(sha256sum "$registry" | awk '{print $1}')" = "$expected_registry"
assert_inputs_unchanged() {
  assert_project_directories
  test "$(sha256sum "$config" | awk '{print $1}')" = "$expected_config"
  test "$(sha256sum "$reserve" | awk '{print $1}')" = "$expected_reserve"
  test "$(sha256sum "$registry" | awk '{print $1}')" = "$expected_registry"
  assert_tool_unchanged node
  "$node_bin" scripts/prepare-production-solidity-pins.mjs "$component" > "$temporary/rechecked-envelope.json"
  cmp -s "$temporary/rechecked-envelope.json" "$temporary/envelope.json"
  verify_reserve_ratification
  assert_project_directories
}
assert_installed_stable() {
  local post_envelope="$temporary/installed-envelope.json"
  local post_candidate="$temporary/installed-candidate"
  assert_project_directories || return 1
  test "$(sha256sum "$config" | awk '{print $1}')" = "$expected_config" || return 1
  if [[ $component == reserve ]]; then
    test "$(sha256sum "$registry" | awk '{print $1}')" = "$expected_registry" || return 1
  else
    test "$(sha256sum "$reserve" | awk '{print $1}')" = "$expected_reserve" || return 1
  fi
  assert_tool_unchanged node || return 1
  "$node_bin" scripts/prepare-production-solidity-pins.mjs "$component" > "$post_envelope" || return 1
  assert_tool_unchanged jq || return 1
  if [[ $component == reserve ]]; then
    "$jq_bin" -er '.reserveSource' "$post_envelope" > "$post_candidate" || return 1
  else
    "$jq_bin" -er '.checkpointRegistrySource' "$post_envelope" > "$post_candidate" || return 1
  fi
  cmp -s "$post_candidate" "$target" || return 1
  test "$(sha256sum "$target" | awk '{print $1}')" = "$candidate_sha256" || return 1
  assert_project_directories || return 1
}
if [[ $component == reserve ]]; then
  assert_tool_unchanged jq
  "$jq_bin" -er '.reserveSource' "$temporary/envelope.json" > "$temporary/reserve.sol"
  target=$reserve
  install_target="$project/contracts/USDOMProofReserve.sol"
  previous_sha256=$expected_reserve
  candidate=$temporary/reserve.sol
else
  assert_tool_unchanged jq
  "$jq_bin" -er '.checkpointRegistrySource' "$temporary/envelope.json" > "$temporary/registry.sol"
  target=$registry
  install_target="$project/contracts/DOMCheckpointRegistry.sol"
  previous_sha256=$expected_registry
  candidate=$temporary/registry.sol
fi
test -s "$candidate"
chmod 0644 "$candidate"
sync -f "$candidate"
candidate_sha256=$(sha256sum "$candidate" | awk '{print $1}')
if ! cmp -s "$candidate" "$target"; then
  assert_inputs_unchanged
  sync -f "$candidate"
  assert_inputs_unchanged
  assert_project_directories
  replacement_status=0
  "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
    "$node_bin" scripts/replace-locked-source-stdin.mjs "$install_target" "$candidate_sha256" \
    "$previous_sha256" "$contracts_directory_device" "$contracts_directory_inode" \
    "$python3_bin" "$python3_sha256" <"$candidate" || replacement_status=$?
  if (( replacement_status == 80 )); then
    # The rename committed, but the helper could not prove its terminal
    # postcondition. Accept only a complete fresh derivation over the installed
    # candidate; otherwise preserve the distinct recovery-required status.
    if assert_installed_stable; then
      replacement_status=0
    else
      exit 80
    fi
  elif (( replacement_status != 0 )); then
    exit "$replacement_status"
  fi
  assert_tool_unchanged node
fi
test "$(sha256sum "$target" | awk '{print $1}')" = "$candidate_sha256"
# The selected source is expected to differ after a successful replacement;
# keep binding the release config and the other source to the prepared envelope.
test "$(sha256sum "$config" | awk '{print $1}')" = "$expected_config"
if [[ $component == reserve ]]; then
  test "$(sha256sum "$registry" | awk '{print $1}')" = "$expected_registry"
else
  test "$(sha256sum "$reserve" | awk '{print $1}')" = "$expected_reserve"
fi
sync -f /proc/self/fd/8
assert_project_directories
assert_installed_stable
# Alternate output and input checks so neither side is trusted only before the
# last observation of the other side.
test "$(sha256sum "$target" | awk '{print $1}')" = "$candidate_sha256"
assert_installed_stable
assert_tool_unchanged jq
"$jq_bin" -n --arg component "$component" '{ok:true,productionReady:false,realFundsAuthorized:false,
  component:$component}'
