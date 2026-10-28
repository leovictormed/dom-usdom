#!/usr/bin/env bash
set -euo pipefail
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent materialize:safe-control-release-metadata' >&2
  exit 64
fi
for command in node jq stat realpath mktemp flock sync mv cmp git sha256sum awk python3; do command -v "$command" >/dev/null; done
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
repository=$(git -C "$project" rev-parse --show-toplevel)
project_relative=$(realpath --relative-to="$repository" "$project")
git -C "$repository" diff --quiet HEAD -- \
  "$project_relative/config/proof-reserve.unconfigured.json"
while IFS= read -r status_line; do
  changed_path=${status_line:3}
  case "$changed_path" in
    "$project_relative/config/mainnet-release-evidence.unconfigured.json"|\
    "$project_relative/config/operator-intent.json"|\
    "$project_relative/evidence/"*) ;;
    *)
      printf 'Source tree contains a non-evidence change: %s\n' "$changed_path" >&2
      exit 1
      ;;
  esac
done < <(git -C "$repository" status --porcelain=v1 --untracked-files=all)
config_directory="$project/config"
target="$config_directory/mainnet-release-evidence.unconfigured.json"
test -f "$target"; test ! -L "$target"
test "$(stat -c '%u' "$target")" = "$(id -u)"
exec 9<"$config_directory"
if ! flock -n 9; then
  printf '%s\n' 'Another release materializer holds the config-directory lock' >&2
  exit 75
fi
target_sha256=$(sha256sum "$target" | awk '{print $1}')
temporary=$(mktemp -d -p "$config_directory" .safe-release-metadata.XXXXXXXX)
chmod 0700 "$temporary"
prepared="$temporary/prepared.json"
rechecked="$temporary/rechecked.json"
installed="$temporary/installed.json"
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
    status=1
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
assert_tool_unchanged node
"$node_bin" scripts/prepare-safe-control-release-metadata-materialization.mjs > "$prepared"
assert_tool_unchanged jq
"$jq_bin" -e '.schema == 1 and .controlPlaneEvidenceBundle != null
  and .controlPlane.governance != null and .controlPlane.guardian != null
  and .controlPlane.checkpointGuardian != null
  and .controlPlane.usdtCustody != null
  and .controlPlaneSeparationReport != null
  and .controlPlaneRecoveryDrillReport != null' "$prepared" >/dev/null
chmod 0600 "$prepared"
sync -f "$prepared"
assert_tool_unchanged node
"$node_bin" scripts/prepare-safe-control-release-metadata-materialization.mjs > "$rechecked"
chmod 0600 "$rechecked"
assert_tool_unchanged jq
"$jq_bin" -e '.schema == 1 and .controlPlaneEvidenceBundle != null
  and .controlPlane.governance != null and .controlPlane.guardian != null
  and .controlPlane.checkpointGuardian != null
  and .controlPlane.usdtCustody != null
  and .controlPlaneSeparationReport != null
  and .controlPlaneRecoveryDrillReport != null' "$rechecked" >/dev/null
cmp -s "$prepared" "$rechecked"
if ! cmp -s "$prepared" "$target" || [[ $(stat -c '%a' "$target") != 644 ]]; then
  assert_tool_unchanged node
  assert_tool_unchanged python3
  candidate_sha256=$(sha256sum "$prepared" | awk '{print $1}')
  parent_device=$(stat -Lc '%d' "$config_directory")
  parent_inode=$(stat -Lc '%i' "$config_directory")
  "$node_bin" "$project/scripts/replace-locked-source-stdin.mjs" "$target" \
    "$candidate_sha256" "$target_sha256" "$parent_device" "$parent_inode" \
    "$python3_bin" "$python3_sha256" < "$prepared"
fi
sync -f "$target"
assert_tool_unchanged node
"$node_bin" scripts/read-release-config-file-stdout.mjs "$target" > "$installed"
cmp -s "$prepared" "$installed"
sync -f "$config_directory"
assert_tool_unchanged node
"$node_bin" scripts/read-release-config-file-stdout.mjs "$target" \
  > "$temporary/installed.durable.json"
cmp -s "$prepared" "$temporary/installed.durable.json"
assert_tool_unchanged jq
assert_tool_unchanged python3
"$jq_bin" '{schema,controlPlaneEvidenceBundle,controlPlane,
  controlPlaneSeparationReport,controlPlaneRecoveryDrillReport}' "$target"
