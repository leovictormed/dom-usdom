#!/usr/bin/env bash
set -euo pipefail
umask 077

if (($# != 0)); then
  printf '%s\n' 'Usage: npm run --silent materialize:preactivation-policy' >&2
  exit 64
fi
for command in node jq stat realpath mktemp flock sync cmp; do command -v "$command" >/dev/null; done
project=$(realpath "$(dirname "$0")/..")
test "$PWD" = "$project"
for tool_boundary_command in stat realpath id dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$project/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool jq
jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }
pin_runtime_tool node
node() { assert_runtime_tool node; "$node_bin" "$@"; }
pin_runtime_tool timeout
pin_runtime_tool python3
python3() { assert_runtime_tool python3; "$python3_bin" "$@"; }
target="$project/config/native-preactivation-policy.unconfigured.json"
test -f "$target"; test ! -L "$target"
test "$(stat -c '%u:%a' "$target")" = "$(id -u):644"
exec 9<"$project/config"
flock -n 9 || { printf '%s\n' 'Another release materializer holds the config lock' >&2; exit 75; }
target_sha256=$(sha256sum "$target" | awk '{print $1}')
parent_device=$(stat -Lc '%d' "$project/config")
parent_inode=$(stat -Lc '%i' "$project/config")
temporary=$(mktemp -p "$project/config" .preactivation-policy.XXXXXXXX)
cleanup() {
  local status=${1:-$?}; trap - EXIT HUP INT TERM
  if assert_runtime_tool node && assert_runtime_tool timeout &&
    "$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \
      "$node_bin" -e 'require("fs").rmSync(process.argv[1],{force:true})' "$temporary" \
      > /dev/null 2> /dev/null &&
    assert_runtime_tool node && assert_runtime_tool timeout && test ! -e "$temporary"; then :; else status=1; fi
  exit "$status"
}
trap 'cleanup $?' EXIT; trap 'cleanup 129' HUP; trap 'cleanup 130' INT; trap 'cleanup 143' TERM
node scripts/prepare-preactivation-policy-materialization.mjs > "$temporary"
jq -e '.schema == "usdom-preactivation-policy-v1"
  and .nativeEthereumTrustedCheckpoint != null and .domDomain != null
  and .checkpointIntervalBlocks == "360"
  and .checkpointConfirmationDepthBlocks == "30"
  and .checkpointChallengePeriodSeconds == "172800"' "$temporary" >/dev/null
chmod 0600 "$temporary"; sync -f "$temporary"
if ! cmp -s "$temporary" "$target"; then
  candidate_sha256=$(sha256sum "$temporary" | awk '{print $1}')
  node scripts/replace-locked-source-stdin.mjs "$target" \
    "$candidate_sha256" "$target_sha256" "$parent_device" "$parent_inode" \
    "$python3_bin" "$python3_sha256" < "$temporary"
fi
test "$(stat -Lc '%u:%a:%h' "$target")" = "$(id -u):644:1"
cmp -s "$temporary" "$target"
sync -f "$target"; sync -f "$project/config"
cmp -s "$temporary" "$target"
jq . "$target"
