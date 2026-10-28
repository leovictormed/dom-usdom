#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077
project=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P);cd "$project"
node_bin=/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node
[[ -x $node_bin ]]||exit 69
: "${USDOM_SAFE_RECOVERY_ROSTER_PLAN:?required}" "${USDOM_SAFE_RECOVERY_ROSTER_PROOFS:?required}" "${USDOM_SAFE_RECOVERY_V3_STATE_DIRECTORY:?required}"
: "${USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG:?required}" "${USDOM_ONEKEY_IOS_ONBOARDING_EVIDENCE_DIRECTORY:?required}"
: "${USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:?required}"
root=$(realpath -ms "$USDOM_SAFE_RECOVERY_V3_STATE_DIRECTORY");evidence=$(realpath -ms "$USDOM_ONEKEY_IOS_ONBOARDING_EVIDENCE_DIRECTORY")
[[ $root == /* && $evidence == /* && ! -L $root && ! -L $evidence ]]
install -d -m 700 "$root";[[ $(stat -c '%u:%a:%h' "$root") == "$UID:700:2" ]]
exec 9>"$root/.prepare.lock";flock -n 9||exit 75
for file in "$USDOM_SAFE_RECOVERY_ROSTER_PLAN" "$USDOM_SAFE_RECOVERY_ROSTER_PROOFS" "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE";do [[ -f $file && ! -L $file && $(stat -c '%u:%a:%h' "$file") == "$UID:600:1" ]];done
"$node_bin" scripts/materialize-safe-recovery-roster-drill.mjs validate-proofs "$USDOM_SAFE_RECOVERY_ROSTER_PLAN" "$USDOM_SAFE_RECOVERY_ROSTER_PROOFS"
# The catalog is derived only from the authenticated private source list. It is
# required now so the later relayer phase cannot substitute RPC origins.
USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE=$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE npm run --silent materialize:mainnet-preflight-rpc-catalog >/dev/null
[[ -f config/mainnet-preflight-rpc-catalog.json && ! -L config/mainnet-preflight-rpc-catalog.json ]]
state="/dev/shm/usdom-recovery-v3-prefix.$$.json";completion_args=();for n in $(seq 0 11);do f="$root/recovery-v3-step-$n-completion.json";[[ -e $f ]]||break;completion_args+=("$f");done
"$node_bin" scripts/materialize-safe-recovery-v3-prefix.mjs "$USDOM_SAFE_RECOVERY_ROSTER_PLAN" "${completion_args[@]}" "$state"
next=$("$node_bin" scripts/materialize-safe-recovery-roster-drill.mjs next "$USDOM_SAFE_RECOVERY_ROSTER_PLAN" "$state")
rm -f -- "$state"
[[ $next == complete ]]&&{ printf '%s\n' complete;exit 0; }
[[ $next =~ ^([0-9]|1[01])$ ]]||exit 1
ordinal=$next;step="$root/step-$ordinal-envelope.json";assembled="$root/step-$ordinal-assembled.json"
[[ -e $step ]]||"$node_bin" scripts/materialize-safe-recovery-roster-drill.mjs step-envelope "$USDOM_SAFE_RECOVERY_ROSTER_PLAN" "$ordinal" "$step"
current="/dev/shm/usdom-recovery-v3-step.$$.$ordinal.json";cleanup(){ s=${1:-$?};trap - EXIT HUP INT TERM;rm -f -- "$current";exit "$s";};trap 'cleanup $?' EXIT;trap 'cleanup 129' HUP;trap 'cleanup 130' INT;trap 'cleanup 143' TERM
"$node_bin" scripts/materialize-safe-recovery-roster-drill.mjs step-envelope "$USDOM_SAFE_RECOVERY_ROSTER_PLAN" "$ordinal" "$current";cmp -s "$current" "$step";rm -f "$current"
mapfile -t owners < <("$node_bin" -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1]));for(const x of v.quorumBefore)console.log(x)' "$step")
[[ ${#owners[@]} == 2 && ${owners[0],,} != ${owners[1],,} ]]
for slot in 0 1;do
 owner=${owners[$slot]};physical=''
 for candidate in "$evidence"/*.json;do [[ -f $candidate && ! -L $candidate ]]||continue;observed=$("$node_bin" -e 'const fs=require("fs"),{getAddress}=require("ethers"),v=JSON.parse(fs.readFileSync(process.argv[1]));process.stdout.write(getAddress(v.address))' "$candidate" 2>/dev/null||true);[[ ${observed,,} == ${owner,,} ]]&&physical=$candidate;done
 [[ -n $physical ]]||{ echo "ONBOARDING_EVIDENCE_REQUIRED: $owner" >&2;exit 78;}
 request="$root/step-$ordinal-owner-$slot-request.json";response="$root/step-$ordinal-owner-$slot-response.json";signature="$root/step-$ordinal-owner-$slot-signature.json"
 [[ -e $request ]]||"$node_bin" scripts/prepare-onekey-ios-walletconnect-request.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$step" "$physical" "$owner" "$request"
 "$node_bin" scripts/check-onekey-ios-walletconnect-request.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$step" "$physical" "$owner" "$request"
 [[ -e $response ]]||"$node_bin" scripts/sign-onekey-ios-walletconnect-typed-data.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$request" "$physical" "$response"||{ code=$?;((code==80))&&exit 80;exit "$code";}
 "$node_bin" scripts/check-onekey-ios-walletconnect-request.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$step" "$physical" "$owner" "$request"
 if [[ ! -e $signature ]];then sig=$("$node_bin" scripts/extract-onekey-ios-walletconnect-signature.mjs "$request" "$response");printf '{"signer":"%s","signature":"%s"}\n' "$owner" "$sig"|"$node_bin" scripts/install-private-file-new-stdin.mjs --json "$signature";fi
done
[[ -e $assembled ]]||"$node_bin" scripts/materialize-safe-recovery-roster-drill.mjs step-assemble "$USDOM_SAFE_RECOVERY_ROSTER_PLAN" "$ordinal" "$root/step-$ordinal-owner-0-signature.json" "$root/step-$ordinal-owner-1-signature.json" "$assembled"
"$node_bin" scripts/materialize-safe-recovery-roster-drill.mjs step-assemble "$USDOM_SAFE_RECOVERY_ROSTER_PLAN" "$ordinal" "$root/step-$ordinal-owner-0-signature.json" "$root/step-$ordinal-owner-1-signature.json" "$current";cmp -s "$current" "$assembled";rm -f "$current"
printf 'prepared-recovery-v3-step-%s\n' "$ordinal"
