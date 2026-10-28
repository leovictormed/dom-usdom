#!/usr/bin/env bash
set -euo pipefail
set +x;umask 077
project=$(CDPATH='' cd -- "$(dirname -- "$0")/.."&&pwd -P);cd "$project"
: "${USDOM_CONTROL_EVIDENCE_DIRECTORY:?required}" "${USDOM_SAFE_RECOVERY_V3_STATE_DIRECTORY:?required}" "${USDOM_SAFE_RECOVERY_RELAYER_POLICY:?required}"
[[ $(realpath -ms "$USDOM_CONTROL_EVIDENCE_DIRECTORY") == $(realpath -ms "$USDOM_SAFE_RECOVERY_V3_STATE_DIRECTORY") ]]||exit 64
bash scripts/prepare-safe-recovery-roster-v3-step.sh
node_bin=/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node;root=$(realpath -ms "$USDOM_CONTROL_EVIDENCE_DIRECTORY");state="/dev/shm/usdom-recovery-v3-prefix.$$.json";completion_args=();for n in $(seq 0 11);do f="$root/recovery-v3-step-$n-completion.json";[[ -e $f ]]||break;completion_args+=("$f");done;"$node_bin" scripts/materialize-safe-recovery-v3-prefix.mjs "$USDOM_SAFE_RECOVERY_ROSTER_PLAN" "${completion_args[@]}" "$state"
ordinal=$("$node_bin" scripts/materialize-safe-recovery-roster-drill.mjs next "$USDOM_SAFE_RECOVERY_ROSTER_PLAN" "$state");rm -f "$state";[[ $ordinal == complete ]]&&{ echo complete;exit 0;}
assembled="$root/step-$ordinal-assembled.json";observed="$root/recovery-v3-step-$ordinal-prebroadcast-observations.json";envelope="$root/recovery-v3-step-$ordinal-relayer-envelope.json";input="$root/recovery-v3-step-$ordinal-relayer-input.json";raw="$root/recovery-v3-step-$ordinal-relayer-raw.txt";journal="$root/recovery-v3-step-$ordinal-journal.json"
if [[ ! -e $observed ]];then "$node_bin" scripts/collect-safe-recovery-v3-prebroadcast.mjs "$assembled" "$USDOM_SAFE_RECOVERY_RELAYER_POLICY" config/mainnet-preflight-rpc-catalog.json|"$node_bin" scripts/install-private-file-new-stdin.mjs --json "$observed";fi
[[ -e $envelope ]]||"$node_bin" scripts/materialize-safe-recovery-v3-relayer-envelope.mjs "$USDOM_SAFE_RECOVERY_ROSTER_PLAN" "$ordinal" "$assembled" "$USDOM_SAFE_RECOVERY_RELAYER_POLICY" "$observed" "$envelope"
if [[ ! -e $input ]];then "$node_bin" -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1]));process.stdout.write(JSON.stringify({to:v.safe,data:v.execTransactionData,value:"0"}))' "$assembled"|"$node_bin" scripts/install-private-file-new-stdin.mjs --json "$input";fi
if [[ ! -e $raw ]];then echo "RELAYER_SIGNATURE_REQUIRED: recovery-v3:$ordinal" >&2;exit 78;fi
validation=$(/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node scripts/validate-safe-recovery-v3-relayer-raw.mjs "$envelope" "$input" "$raw")
tx=$(printf '%s' "$validation"|"$node_bin" -e 'let s="";process.stdin.on("data",x=>s+=x).on("end",()=>process.stdout.write(JSON.parse(s).transactionHash))')
if [[ ! -e $journal ]];then printf '{"schema":"usdom-safe-recovery-roster-broadcast-journal/v3","planHash":"%s","ordinal":%s,"safeTxHash":"%s","status":"signed-unresolved","transactionHash":"%s"}\n' "$("$node_bin" -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).planHash)' "$assembled")" "$ordinal" "$("$node_bin" -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).safeTxHash)' "$assembled")" "$tx"|"$node_bin" scripts/install-private-file-new-stdin.mjs --json "$journal";fi
"$node_bin" -e 'const fs=require("fs"),j=JSON.parse(fs.readFileSync(process.argv[1])),v=JSON.parse(process.argv[2]);if(j.transactionHash!==v.transactionHash||j.status!=="signed-unresolved")process.exit(1)' "$journal" "$validation"
echo "signed-unresolved-recovery-v3-step-$ordinal";exit 80
