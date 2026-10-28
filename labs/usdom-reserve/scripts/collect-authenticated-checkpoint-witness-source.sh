#!/usr/bin/env bash
set -euo pipefail
set +x
unset BASH_XTRACEFD 2>/dev/null || true
umask 077
ulimit -c 0
if (($#)); then printf '%s\n' 'This command accepts no arguments.' >&2; exit 64; fi
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$ROOT"
test -t 0; test -t 2
for tool in node jq mktemp stat id; do command -v "$tool" >/dev/null; done
for tool_boundary_command in realpath dirname sha256sum cut; do command -v "$tool_boundary_command" >/dev/null; done
source "$ROOT/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node
node() { assert_runtime_tool node; "$node_bin" "$@"; }
pin_runtime_tool jq
jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }
execution_catalog=config/checkpoint-finalized-event-rpc-catalog.json
beacon_catalog=config/ethereum-checkpoint-source-catalog.json
test -f "$execution_catalog"; test ! -L "$execution_catalog"
test -f "$beacon_catalog"; test ! -L "$beacon_catalog"
mapfile -t execution_ids < <(jq -er '.sources[].operatorId' "$execution_catalog")
mapfile -t beacon_ids < <(jq -er '.sources[].operatorId' "$beacon_catalog")
((${#execution_ids[@]} >= 2 && ${#execution_ids[@]} <= 5))
test "${#execution_ids[@]}" -eq "${#beacon_ids[@]}"
temporary=$(mktemp -p /dev/shm usdom-checkpoint-witness-rpcs.XXXXXXXX)
temporary_identity=$(stat -c '%u:%d:%i:%a' "$temporary")
cleanup(){ local status=${1:-$?}; trap - EXIT HUP INT TERM; unset USDOM_CHECKPOINT_WITNESS_RPC_SOURCES_FILE; if test "$(stat -c '%u:%d:%i:%a' "$temporary" 2>/dev/null)" = "$temporary_identity"; then rm -f -- "$temporary" || status=1; fi; exit "$status"; }
trap 'cleanup $?' EXIT; trap 'cleanup 129' HUP; trap 'cleanup 130' INT; trap 'cleanup 143' TERM
sources='[]'
for ((i=0;i<${#execution_ids[@]};i++)); do
  printf 'Execution RPC URL for %s (hidden): ' "${execution_ids[i]}" >&2
  IFS= read -r -s execution_url; printf '\n' >&2
  printf 'Beacon RPC URL for %s (hidden): ' "${beacon_ids[i]}" >&2
  IFS= read -r -s beacon_url; printf '\n' >&2
  ((${#execution_url} >= 10 && ${#execution_url} <= 2048
    && ${#beacon_url} >= 10 && ${#beacon_url} <= 2048)) || {
    unset execution_url beacon_url
    printf '%s\n' 'RPC URLs must contain 10..2048 characters.' >&2
    exit 1
  }
  sources=$(jq -cn --argjson current "$sources" --arg operatorId "${execution_ids[i]}" \
    --arg beaconOperatorId "${beacon_ids[i]}" --arg executionUrl "$execution_url" \
    --arg beaconUrl "$beacon_url" '$current+[{operatorId:$operatorId,beaconOperatorId:$beaconOperatorId,executionUrl:$executionUrl,beaconUrl:$beaconUrl}]')
  unset execution_url beacon_url
done
printf '%s\n' "$sources" >"$temporary"
chmod 0600 "$temporary"
test "$(stat -c '%u:%a:%h' "$temporary")" = "$(id -u):600:1"
export USDOM_CHECKPOINT_WITNESS_RPC_SOURCES_FILE=$temporary
node scripts/collect-authenticated-checkpoint-witness-source.mjs
