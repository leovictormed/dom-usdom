#!/usr/bin/env bash
set -euo pipefail
# This entrypoint receives provider URLs that may embed API credentials.  Keep
# them out of xtrace, process environments, crash dumps and argv.
set +x
unset BASH_XTRACEFD 2>/dev/null || true
export RUST_BACKTRACE=0
export RUST_LIB_BACKTRACE=0
if ! ulimit -c 0; then
  printf '%s\n' 'Cannot disable core dumps for a credential-bearing operation.' >&2
  exit 1
fi
umask 077

if (($# != 0)); then
  printf '%s\n' 'This command accepts no arguments.' >&2
  exit 2
fi

SCRIPT_DIRECTORY=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
RESERVE_DIRECTORY=$(CDPATH='' cd -- "$SCRIPT_DIRECTORY/.." && pwd -P)
for tool_boundary_command in stat realpath id dirname sha256sum cut timeout jq; do command -v "$tool_boundary_command" >/dev/null; done
source "$RESERVE_DIRECTORY/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool timeout
pin_runtime_tool jq
pin_runtime_tool node
run_pinned_timeout() { assert_runtime_tool timeout; "$timeout_bin" "$@"; }
run_pinned_jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }
node() { assert_runtime_tool node; "$node_bin" "$@"; }
command -v timeout >/dev/null
for required in \
  "$RESERVE_DIRECTORY/evidence/native-runtime/native-usdom-v2.json" \
  "$RESERVE_DIRECTORY/evidence/native-runtime/native-usdom-v2.manifest.sha256" \
  "$RESERVE_DIRECTORY/evidence/finalized-deposit-source/deposit-transaction-hash.hex"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    printf 'Missing direct regular file: %s\n' "$required" >&2
    exit 1
  fi
done
if [[ ! -t 0 || ! -t 2 ]]; then
  printf '%s\n' 'RPC endpoints require an interactive terminal.' >&2
  exit 2
fi
catalog="$RESERVE_DIRECTORY/config/finalized-deposit-source-catalog.json"
[[ -f "$catalog" && ! -L "$catalog" ]] || { printf '%s\n' 'Missing finalized-deposit source catalog.' >&2; exit 1; }
USDOM_FINALIZED_DEPOSIT_SOURCES='[]'
while IFS= read -r operator_id; do
  IFS= read -r -s -p "Secret execution RPC URL for $operator_id: " execution_url
  printf '\n' >&2
  IFS= read -r -s -p "Secret Beacon RPC URL for $operator_id: " beacon_url
  printf '\n' >&2
  USDOM_FINALIZED_DEPOSIT_SOURCES=$(printf '%s' "$USDOM_FINALIZED_DEPOSIT_SOURCES" | run_pinned_jq -c \
    --arg operatorId "$operator_id" --arg executionUrl "$execution_url" --arg beaconUrl "$beacon_url" \
    '.+[{operatorId:$operatorId,executionUrl:$executionUrl,beaconUrl:$beaconUrl}]')
  unset execution_url beacon_url
done < <(run_pinned_jq -er '.sources[].operatorId' "$catalog")
cd "$RESERVE_DIRECTORY"
if printf '%s' "$USDOM_FINALIZED_DEPOSIT_SOURCES" \
  | run_pinned_timeout --signal=TERM --kill-after=5s 300s \
    node scripts/collect-finalized-deposit-source.mjs; then
  status=0
else
  status=$?
fi
unset USDOM_FINALIZED_DEPOSIT_SOURCES
exit "$status"
