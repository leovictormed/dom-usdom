#!/usr/bin/env bash
set -euo pipefail
set +x;umask 077
project=$(CDPATH='' cd -- "$(dirname -- "$0")/.."&&pwd -P);cd "$project"
: "${USDOM_CONTROL_EVIDENCE_DIRECTORY:?required}" "${USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:?required}" "${USDOM_SAFE_RECOVERY_ROSTER_PLAN:?required}"
node_bin=/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node;root=$(realpath -ms "$USDOM_CONTROL_EVIDENCE_DIRECTORY")
set +e;"$node_bin" scripts/run-operational-status78-cycle.mjs recovery-v3;status=$?;set -e;((status==0||status==80))||exit "$status"
completion_args=();for n in $(seq 0 11);do f="$root/recovery-v3-step-$n-completion.json";[[ -e $f ]]||break;completion_args+=("$f");done
prefix="/dev/shm/usdom-recovery-v3-prefix.$$.json";left="$prefix.left";right="$prefix.right";candidate="$prefix.completion";final_tmp="$prefix.final";cleanup(){ s=${1:-$?};trap - EXIT HUP INT TERM;rm -f -- "$prefix" "$left" "$right" "$candidate" "$final_tmp";exit "$s";};trap 'cleanup $?' EXIT;trap 'cleanup 129' HUP;trap 'cleanup 130' INT;trap 'cleanup 143' TERM;"$node_bin" scripts/materialize-safe-recovery-v3-prefix.mjs "$USDOM_SAFE_RECOVERY_ROSTER_PLAN" "${completion_args[@]}" "$prefix";ordinal=$("$node_bin" scripts/materialize-safe-recovery-roster-drill.mjs next "$USDOM_SAFE_RECOVERY_ROSTER_PLAN" "$prefix");[[ $ordinal == complete ]]&&{ echo complete;exit 0;}
assembled="$root/step-$ordinal-assembled.json";journal="$root/recovery-v3-step-$ordinal-journal.json";raw="$root/recovery-v3-step-$ordinal-relayer-raw.txt";completion="$root/recovery-v3-step-$ordinal-completion.json";observations="$root/recovery-v3-step-$ordinal-finalized-observations.json"
[[ -f $journal && -f $raw ]]
set +e;"$node_bin" scripts/collect-safe-recovery-v3-finalized.mjs "$assembled" "$journal" config/mainnet-preflight-rpc-catalog.json >"$final_tmp";final_status=$?;set -e
if ((final_status!=0));then presence=$("$node_bin" scripts/check-safe-recovery-v3-transaction-presence.mjs "$journal" config/mainnet-preflight-rpc-catalog.json);if [[ $presence == absent ]];then tx=$("$node_bin" -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).transactionHash)' "$journal");envhash=$(sha256sum "$root/recovery-v3-step-$ordinal-relayer-envelope.json"|cut -d' ' -f1);read -r -p "Digite AUTORIZO TRANSMITIR RECOVERY V3 STEP $ordinal TX $tx ENVELOPE $envhash: " approval </dev/tty;[[ $approval == "AUTORIZO TRANSMITIR RECOVERY V3 STEP $ordinal TX $tx ENVELOPE $envhash" ]];set +e;"$node_bin" scripts/publish-private-raw-transaction.mjs "$raw" "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" config/mainnet-preflight-rpc-catalog.json 0 >/dev/null;publish_status=$?;set -e;if ((publish_status!=0));then [[ $("$node_bin" scripts/check-safe-recovery-v3-transaction-presence.mjs "$journal" config/mainnet-preflight-rpc-catalog.json) == observed ]]||exit 80;fi;fi
 deadline=$((SECONDS+1800));while ! "$node_bin" scripts/collect-safe-recovery-v3-finalized.mjs "$assembled" "$journal" config/mainnet-preflight-rpc-catalog.json >"$final_tmp";do ((SECONDS<deadline))||exit 80;sleep 15;done
fi
"$node_bin" scripts/install-private-file-new-stdin.mjs --json "$observations" <"$final_tmp" 2>/dev/null||cmp -s "$final_tmp" "$observations"
"$node_bin" -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1]));fs.writeFileSync(process.argv[2],JSON.stringify(v[0]));fs.writeFileSync(process.argv[3],JSON.stringify(v[1]))' "$observations" "$left" "$right";chmod 600 "$left" "$right"
"$node_bin" scripts/check-safe-recovery-roster-v3-finalized.mjs "$USDOM_SAFE_RECOVERY_ROSTER_PLAN" "$assembled" "$journal" "$left" "$right" >"$candidate";chmod 600 "$candidate"
if [[ ! -e $completion ]];then "$node_bin" scripts/install-private-file-new-stdin.mjs --json "$completion" <"$candidate";else cmp -s "$candidate" "$completion";fi
echo "finalized-recovery-v3-step-$ordinal"
