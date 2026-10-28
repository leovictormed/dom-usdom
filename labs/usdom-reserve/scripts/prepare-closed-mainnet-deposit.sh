#!/usr/bin/env bash
exec bash "$(dirname "$0")/reject-legacy-eoa-mainnet-deposit.sh"
set -euo pipefail
set +x
umask 077
unset BASH_XTRACEFD 2>/dev/null || true
unset LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
  NODE_OPTIONS NODE_PATH NODE_DEBUG NODE_DEBUG_NATIVE SSLKEYLOGFILE \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
for inherited_name in ${!FOUNDRY_@} ${!CAST_@}; do unset "$inherited_name"; done
export PATH=/usr/lib/chatgpt/resources/cua_node/bin:/home/leonardov/.foundry/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ulimit -c 0

if (($# != 0)); then
  printf '%s\n' 'This command accepts no arguments or secret overrides.' >&2
  exit 2
fi
if [[ -t 1 ]]; then
  printf '%s\n' 'Refusing to print the private deposit package to a terminal; redirect it to the owner-only installer.' >&2
  exit 2
fi
for fd_path in /proc/"$$"/fd/*; do
  inherited_fd=${fd_path##*/}
  [[ $inherited_fd =~ ^[0-9]+$ ]] || exit 1
  (( inherited_fd<=2 )) && continue
  [[ $inherited_fd == 255 ]] && continue
  exec {inherited_fd}>&-
done

SCRIPT_DIRECTORY=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
RESERVE_DIRECTORY=$(CDPATH='' cd -- "$SCRIPT_DIRECTORY/.." && pwd -P)

command -v cast >/dev/null
command -v node >/dev/null
command -v timeout >/dev/null
: "${USDOM_SAFE_USDT_CUSTODY_AUTHORITY:?USDOM_SAFE_USDT_CUSTODY_AUTHORITY is required}"
cd "$RESERVE_DIRECTORY"

FIRST_ADDRESS=$(timeout --signal=TERM --kill-after=5s 30s node scripts/read-safe-usdt-custody-address.mjs "$USDOM_SAFE_USDT_CUSTODY_AUTHORITY")
SECOND_ADDRESS=$(timeout --signal=TERM --kill-after=5s 30s node scripts/read-safe-usdt-custody-address.mjs "$USDOM_SAFE_USDT_CUSTODY_AUTHORITY")
if [[ ! "$FIRST_ADDRESS" =~ ^0x[0-9a-fA-F]{40}$ || "$FIRST_ADDRESS" != "$SECOND_ADDRESS" ]]; then
  printf '%s\n' 'Safe custody authority returned a missing, malformed or unstable funder address.' >&2
  exit 1
fi

export USDOM_DEPOSIT_FUNDER=$FIRST_ADDRESS
exec timeout --signal=TERM --kill-after=2s 120s \
  node scripts/prepare-closed-mainnet-deposit.mjs
