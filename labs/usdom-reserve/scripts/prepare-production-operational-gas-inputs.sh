#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077
if (($#)); then printf '%s\n' 'This command accepts no arguments.' >&2; exit 64; fi
: "${USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:?required}"
: "${USDOM_OPERATIONAL_GAS_RUN_CONFIG:?required}"
: "${USDOM_OPERATIONAL_GAS_RPC_SOURCES:?required}"
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P); cd "$ROOT"
test -t 0; test -t 2
release=config/proof-reserve.unconfigured.json
local_evidence=docs/LOCAL-OPERATIONAL-GAS-MEASUREMENT-2026-10-26.json
reserve=$(jq -er '.reserve|select(test("^0x[0-9a-f]{40}$"))' "$release")
reserve_hash=$(jq -er '.reserveRuntimeCodeHash|select(test("^0x[0-9a-f]{64}$"))' "$release")
safe=$(jq -er '.governance|select(test("^0x[0-9a-f]{40}$"))' "$release")
safe_hash=$(jq -er '.governanceCodeHash|select(test("^0x[0-9a-f]{64}$"))' "$release")
mapfile -t maxima < <(jq -er '.scenarios|[.queueWithdrawal.gasUsed,.pruneExpired256.gasUsed,.pruneDiscardable256.gasUsed,.safeAdminOverhead.gasUsed][]|tostring' "$local_evidence")
ids=(queueWithdrawal-worst-case pruneExpired-256 pruneDiscardable-256 safe-admin-swapOwner-3-owner-2-threshold)
scenarios='[]'
for ((i=0;i<4;i++)); do
  runs='[]'
  for ordinal in 1 2; do
    printf 'Transaction hash for %s run %s: ' "${ids[i]}" "$ordinal" >&2
    IFS= read -r transaction_hash
    printf 'SHA-256 of exact calldata bytes for %s run %s: ' "${ids[i]}" "$ordinal" >&2
    IFS= read -r calldata_sha
    ((${#transaction_hash} == 66 && ${#calldata_sha} == 66)) || {
      unset transaction_hash calldata_sha
      printf '%s\n' 'Identifiers must contain exactly 66 characters.' >&2
      exit 1
    }
    [[ $transaction_hash =~ ^0x[0-9a-f]{64}$ && $calldata_sha =~ ^0x[0-9a-f]{64}$ ]] || { printf '%s\n' 'Expected canonical lowercase 0x-prefixed bytes32.' >&2; exit 1; }
    runs=$(jq -cn --argjson current "$runs" --argjson ordinal "$ordinal" --arg transactionHash "$transaction_hash" --arg calldataSha256 "$calldata_sha" '$current+[{ordinal:$ordinal,transactionHash:$transactionHash,calldataSha256:$calldataSha256}]')
  done
  target=$reserve; target_hash=$reserve_hash
  if ((i==3)); then target=$safe; target_hash=$safe_hash; fi
  scenarios=$(jq -cn --argjson current "$scenarios" --arg id "${ids[i]}" --arg target "$target" --arg targetRuntimeCodeHash "$target_hash" --arg maximumGasUsed "${maxima[i]}" --argjson runs "$runs" '$current+[{id:$id,target:$target,targetRuntimeCodeHash:$targetRuntimeCodeHash,maximumGasUsed:$maximumGasUsed,runs:$runs}]')
done
candidate=$(mktemp -p /dev/shm usdom-operational-gas-config.XXXXXXXX)
installed=$(mktemp -p /dev/shm usdom-operational-gas-installed.XXXXXXXX)
trap 'rm -f -- "$candidate" "$installed"' EXIT HUP INT TERM
jq -n --argjson scenarios "$scenarios" '{schema:"usdom-production-operational-gas-run-config/v1",scenarios:$scenarios}' >"$candidate"
chmod 0600 "$candidate"
node scripts/install-private-file-immutable-stdin.mjs --json "$USDOM_OPERATIONAL_GAS_RUN_CONFIG" <"$candidate"
node scripts/read-private-file-stdout.mjs "$USDOM_OPERATIONAL_GAS_RUN_CONFIG" >"$installed"
cmp -s "$candidate" "$installed"
# RPC evidence reuses the already authenticated two-source operator file and
# only projects the schema needed by the gas collector; URLs never reach stdout.
jq -c '{schema:"usdom-production-operational-gas-rpc-sources/v1",sources:[.[]|{sourceId:.operatorId,providerId,infrastructureId,url}]}' "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" >"$candidate"
node scripts/install-private-file-immutable-stdin.mjs --json "$USDOM_OPERATIONAL_GAS_RPC_SOURCES" <"$candidate"
node scripts/read-private-file-stdout.mjs "$USDOM_OPERATIONAL_GAS_RPC_SOURCES" >"$installed"
cmp -s "$candidate" "$installed"
