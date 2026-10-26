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
target="$project/config/native-preactivation-policy.unconfigured.json"
test -f "$target"; test ! -L "$target"
test "$(stat -c '%u:%a' "$target")" = "$(id -u):644"
exec 9<"$project/config"
flock -n 9 || { printf '%s\n' 'Another release materializer holds the config lock' >&2; exit 75; }
temporary=$(mktemp -p "$project/config" .preactivation-policy.XXXXXXXX)
trap 'rm -f -- "$temporary"' EXIT
node scripts/prepare-preactivation-policy-materialization.mjs > "$temporary"
jq -e '.schema == "usdom-preactivation-policy-v1"
  and .nativeEthereumTrustedCheckpoint != null and .domDomain != null
  and .checkpointIntervalBlocks == "360"
  and .checkpointConfirmationDepthBlocks == "30"
  and .checkpointChallengePeriodSeconds == "172800"' "$temporary" >/dev/null
chmod 0600 "$temporary"; sync -f "$temporary"
if ! cmp -s "$temporary" "$target"; then
  node scripts/install-release-config-stdin.mjs "$target" < "$temporary"
fi
sync -f "$target"; sync -f "$project/config"
jq . "$target"
