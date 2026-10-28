#!/usr/bin/env bash
set -euo pipefail;set +x;umask 077
(($#==1))||exit 64;case $1 in approve|deposit)kind=$1;;*)exit 64;;esac
test -t 0&&test -t 2||exit 2
project=$(CDPATH='' cd -- "$(dirname "$0")/.."&&pwd -P);test "$PWD" = "$project";: "${USDOM_CONTROL_EVIDENCE_DIRECTORY:?required}" "${USDOM_SAFE_DEPOSIT_RELAYER_AUTHORITY:?required}" "${USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:?required}"
evidence=$(realpath -ms "$USDOM_CONTROL_EVIDENCE_DIRECTORY");exec 9<"$evidence";flock -n 9||exit 75
source scripts/pinned-shell-tool-functions.sh;pin_runtime_tool node;pin_runtime_tool jq;pin_runtime_tool cast
envelope="$evidence/safe-deposit-$kind-safe-envelope.json";raw="$evidence/safe-deposit-$kind-relayer-raw.txt";validation="$evidence/safe-deposit-$kind-relayer-validation.json";journal="$evidence/safe-deposit-$kind-broadcast-journal.json";completion="$evidence/safe-deposit-$kind-finalized.json"
for f in "$envelope" "$raw" "$validation" "$journal" "$USDOM_SAFE_DEPOSIT_RELAYER_AUTHORITY" "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE";do test -f "$f"&&test ! -L "$f"&&test "$(stat -c '%u:%a:%h' "$f")" = "$(id -u):600:1";done
$jq_bin -e --arg kind "$kind" --slurpfile validation "$validation" '.schema=="usdom-safe-deposit-broadcast-journal/v1" and .kind==$kind and .state=="signed-unresolved" and .validation==$validation[0]' "$journal">/dev/null
rpc_catalog=config/mainnet-preflight-rpc-catalog.json;test -f "$rpc_catalog"&&test ! -L "$rpc_catalog"
rpc_config=$(mktemp -p /dev/shm usdom-safe-deposit-rpc.XXXXXXXX);tmp='';state=signed-unresolved
cleanup(){ s=${1:-$?};trap - EXIT HUP INT TERM;rm -f -- "$rpc_config";[[ -z $tmp ]]||rm -f -- "$tmp" "$tmp.rpc";[[ $state == clean || $s == 0 ]]||s=80;exit "$s";};trap 'cleanup $?' EXIT;trap 'cleanup 129' HUP;trap 'cleanup 130' INT;trap 'cleanup 143' TERM
$node_bin scripts/materialize-private-foundry-rpc-aliases.mjs "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "$rpc_catalog">"$rpc_config";chmod 0600 "$rpc_config";export FOUNDRY_CONFIG="$rpc_config";rpc1=usdom_rpc_a;rpc2=usdom_rpc_b
relayer=$($jq_bin -er .outerTransaction.from "$envelope");safe=$($jq_bin -er .outerTransaction.to "$envelope");outer_nonce=$($jq_bin -er .outerTransaction.nonce "$envelope");safe_nonce=$($jq_bin -er .typedData.message.nonce "$envelope");txhash=$($jq_bin -er .transactionHash "$validation")
observe(){ rpc=$1;test "$($cast_bin chain-id --rpc-url "$rpc")" = 1;test "$($cast_bin nonce "$relayer" --block pending --rpc-url "$rpc")" = "$outer_nonce";observed=$($cast_bin call "$safe" 'nonce()(uint256)' --block pending --rpc-url "$rpc");test "${observed%% *}" = "$safe_nonce";}
if test -e "$completion";then
 $jq_bin -e --arg kind "$kind" --arg tx "$txhash" '.schema=="usdom-safe-deposit-finalized/v1" and .kind==$kind and .state=="finalized-awaiting-accounting-collector" and .finalizedRpcCount==2 and (.transactionHash|ascii_downcase)==($tx|ascii_downcase)' "$completion">/dev/null
 block=$($jq_bin -er .blockNumber "$completion");hash=$($jq_bin -er '.blockHash|ascii_downcase' "$completion")
 for rpc in "$rpc1" "$rpc2";do
  test "$($cast_bin chain-id --rpc-url "$rpc")" = 1
  test "$($cast_bin block "$block" --field hash --rpc-url "$rpc"|tr '[:upper:]' '[:lower:]')" = "$hash"
  finalized=$($cast_bin block finalized --field number --rpc-url "$rpc");$node_bin -e 'if(BigInt(process.argv[1])>BigInt(process.argv[2]))process.exit(1)' "$block" "$finalized"
  tmp=$(mktemp -p /dev/shm usdom-safe-deposit-restart.XXXXXXXX);$cast_bin receipt "$txhash" --json --rpc-url "$rpc">"$tmp"
  $jq_bin -e --arg tx "$txhash" --arg block "$block" --arg hash "$hash" '.status=="0x1" and (.transactionHash|ascii_downcase)==($tx|ascii_downcase) and .blockNumber==$block and (.blockHash|ascii_downcase)==$hash' "$tmp">/dev/null;rm -f -- "$tmp";tmp=
 done
 state=clean;exit 0
fi
observe "$rpc1";observe "$rpc2"
echo "AUTHORIZE SAFE DEPOSIT BROADCAST kind=$kind txHash=$txhash relayer=$relayer safe=$safe outerNonce=$outer_nonce safeNonce=$safe_nonce" >&2
read -r -p "Digite AUTORIZO TRANSMITIR SAFE DEPOSITO $kind TX $txhash: " answer </dev/tty;test "$answer" = "AUTORIZO TRANSMITIR SAFE DEPOSITO $kind TX $txhash"
observe "$rpc1";observe "$rpc2"
state=publishing;out=$($node_bin scripts/publish-private-raw-transaction.mjs "$raw" "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "$rpc_catalog" 0);test "${out,,}" = "${txhash,,}"
receipt="$evidence/safe-deposit-$kind-receipt.json";tmp=$(mktemp -p /dev/shm usdom-safe-deposit-receipt.XXXXXXXX)
$cast_bin receipt "$txhash" --confirmations 2 --json --rpc-url "$rpc1">"$tmp";$jq_bin -e --arg tx "$txhash" '.status=="0x1" and (.transactionHash|ascii_downcase)==($tx|ascii_downcase)' "$tmp">/dev/null
block=$($jq_bin -er .blockNumber "$tmp");hash=$($jq_bin -er '.blockHash|ascii_downcase' "$tmp")
for rpc in "$rpc1" "$rpc2";do r="$tmp.rpc";$cast_bin receipt "$txhash" --json --rpc-url "$rpc">"$r";$jq_bin -e --arg tx "$txhash" --arg block "$block" --arg hash "$hash" '.status=="0x1" and (.transactionHash|ascii_downcase)==($tx|ascii_downcase) and .blockNumber==$block and (.blockHash|ascii_downcase)==$hash' "$r">/dev/null;fin=$($cast_bin block finalized --field number --rpc-url "$rpc");$node_bin -e 'if(BigInt(process.argv[1])>BigInt(process.argv[2]))process.exit(1)' "$block" "$fin";rm -f "$r";done
$node_bin scripts/install-private-file-new-stdin.mjs --json "$receipt"<"$tmp"
$jq_bin -n --arg kind "$kind" --arg tx "$txhash" --arg block "$block" --arg hash "$hash" '{schema:"usdom-safe-deposit-finalized/v1",kind:$kind,transactionHash:$tx,blockNumber:$block,blockHash:$hash,finalizedRpcCount:2,state:"finalized-awaiting-accounting-collector"}'|$node_bin scripts/install-private-file-new-stdin.mjs --json "$completion"
rm -f "$tmp";state=clean
