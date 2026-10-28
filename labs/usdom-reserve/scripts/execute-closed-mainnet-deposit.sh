#!/usr/bin/env bash
set -euo pipefail; set +x; umask 077; ulimit -c 0
unset BASH_XTRACEFD NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH
(($#==0))||exit 64; test -t 0 && test -t 2||exit 2
project=$(CDPATH='' cd -- "$(dirname -- "$0")/.."&&pwd -P); test "$PWD" = "$project"
: "${USDOM_CONTROL_EVIDENCE_DIRECTORY:?required}" "${USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG:?required}" "${USDOM_ONEKEY_IOS_PHYSICAL_EVIDENCE_DIRECTORY:?required}" "${USDOM_SAFE_DEPOSIT_AUTHORITY:?required}" "${USDOM_SAFE_DEPOSIT_RELAYER_AUTHORITY:?required}" "${USDOM_SAFE_DEPOSIT_RELAYER_POLICY:?required}"
evidence=$(realpath -ms "$USDOM_CONTROL_EVIDENCE_DIRECTORY"); test -d "$evidence" && test ! -L "$evidence" && test "$(stat -c '%u:%a' "$evidence")" = "$(id -u):700"
exec 9<"$evidence"; flock -n 9||exit 75
source scripts/pinned-shell-tool-functions.sh; pin_runtime_tool node; pin_runtime_tool jq
for f in "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$USDOM_SAFE_DEPOSIT_AUTHORITY" "$USDOM_SAFE_DEPOSIT_RELAYER_AUTHORITY" "$USDOM_SAFE_DEPOSIT_RELAYER_POLICY";do test -f "$f"&&test ! -L "$f"&&test "$(stat -c '%u:%a:%h' "$f")" = "$(id -u):600:1";done
plan="$evidence/closed-mainnet-safe-deposit-plan.json"; pre="$evidence/closed-mainnet-safe-deposit-pre-state.json"
test -f "$pre"&&test ! -L "$pre"&&test "$(stat -c '%u:%a:%h' "$pre")" = "$(id -u):600:1"
if test ! -e "$plan";then "$node_bin" scripts/plan-onekey-ios-safe-usdt-deposit.mjs "$USDOM_SAFE_DEPOSIT_AUTHORITY" "$pre" "$plan";fi
tmp=$(mktemp -d -p /dev/shm usdom-safe-deposit.XXXXXXXX);tid=$(stat -c '%u:%d:%i:%a' "$tmp");state=clean
cleanup(){ s=${1:-$?};trap - EXIT HUP INT TERM;[[ $(stat -c '%u:%d:%i:%a' "$tmp") == "$tid" ]]&&rm -rf -- "$tmp"||s=1;[[ $state == clean || $s == 0 ]]||s=80;exit "$s";};trap 'cleanup $?' EXIT;trap 'cleanup 129' HUP;trap 'cleanup 130' INT;trap 'cleanup 143' TERM
"$node_bin" scripts/plan-onekey-ios-safe-usdt-deposit.mjs "$USDOM_SAFE_DEPOSIT_AUTHORITY" "$pre" "$tmp/plan.json";cmp -s "$plan" "$tmp/plan.json"
test "$($jq_bin -er .threshold "$USDOM_SAFE_DEPOSIT_AUTHORITY")" = 2
for op in 0 1;do
 kind=$($jq_bin -er ".operations[$op].kind" "$plan");envelope="$tmp/$kind-eip712.json"
 $jq_bin -c --argjson op "$op" '{schema:"usdom-onekey-eip712-signing/v1",digest:.operations[$op].digest,typedData:.operations[$op].typedData}' "$plan">"$envelope"
 for owner in 0 1;do
  n=$((owner+1));expected=$($jq_bin -er ".owners[$owner]" "$USDOM_SAFE_DEPOSIT_AUTHORITY");physical="$USDOM_ONEKEY_IOS_PHYSICAL_EVIDENCE_DIRECTORY/owner-$n.json";request="$evidence/safe-deposit-$kind-owner-$n-wc-request.json";response="$evidence/safe-deposit-$kind-owner-$n-wc-response.json";signature="$evidence/safe-deposit-$kind-owner-$n-signature.json"
  test -e "$request"||"$node_bin" scripts/prepare-onekey-ios-walletconnect-request.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$envelope" "$physical" "$expected" "$request"
  "$node_bin" scripts/check-onekey-ios-walletconnect-request.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$envelope" "$physical" "$expected" "$request"
  test -e "$response"||"$node_bin" scripts/sign-onekey-ios-walletconnect-typed-data.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$request" "$physical" "$response"||{ state=signed-unresolved;exit 80;}
  if test ! -e "$signature";then sig=$($node_bin scripts/extract-onekey-ios-walletconnect-signature.mjs "$request" "$response");$jq_bin -n --arg signer "$expected" --arg signature "$sig" '{signer:$signer,signature:$signature}'|"$node_bin" scripts/install-private-file-new-stdin.mjs --json "$signature";fi
 done
 snapshot="$evidence/safe-deposit-$kind-relayer-snapshot.json";fees="$evidence/safe-deposit-$kind-relayer-fees.json";test -f "$snapshot"&&test -f "$fees";bundle="$tmp/$kind-bundle.json"
 "$node_bin" scripts/materialize-safe-deposit-relayer.mjs envelope "$plan" "$op" "$USDOM_SAFE_DEPOSIT_RELAYER_AUTHORITY" "$snapshot" "$evidence/safe-deposit-$kind-owner-1-signature.json" "$evidence/safe-deposit-$kind-owner-2-signature.json" "$fees">"$bundle"
 for spec in "signerEnvelope:relayer-envelope" "input:relayer-input" "envelope:safe-envelope";do field=${spec%%:*};suffix=${spec#*:};dest="$evidence/safe-deposit-$kind-$suffix.json";current="$tmp/$kind-$suffix.current.json";$jq_bin -c ".$field" "$bundle">"$current";if test -e "$dest";then cmp -s "$current" "$dest"||{ echo "persisted Safe deposit artifact drifted: $dest" >&2;exit 80;};else "$node_bin" scripts/install-private-file-new-stdin.mjs --json "$dest"<"$current";fi;done
 raw="$evidence/safe-deposit-$kind-relayer-raw.txt";test -e "$raw"||{ echo "RELAYER_SIGNATURE_REQUIRED: sign-operational-gas-relayer.sh safe-deposit:$kind" >&2;exit 78;}
 validation="$evidence/safe-deposit-$kind-relayer-validation.json";test -e "$validation"||"$node_bin" scripts/materialize-safe-deposit-relayer.mjs raw "$evidence/safe-deposit-$kind-safe-envelope.json" "$evidence/safe-deposit-$kind-relayer-input.json" "$USDOM_SAFE_DEPOSIT_RELAYER_POLICY" "$raw"|"$node_bin" scripts/install-private-file-new-stdin.mjs --json "$validation"
 journal="$evidence/safe-deposit-$kind-broadcast-journal.json";test -e "$journal"||$jq_bin -n --slurpfile v "$validation" --arg kind "$kind" '{schema:"usdom-safe-deposit-broadcast-journal/v1",kind:$kind,state:"signed-unresolved",validation:$v[0]}'|"$node_bin" scripts/install-private-file-new-stdin.mjs --json "$journal"
 completion="$evidence/safe-deposit-$kind-finalized.json"
 if test -e "$completion";then $jq_bin -e --arg kind "$kind" 'keys==["blockHash","blockNumber","finalizedRpcCount","kind","schema","state","transactionHash"] and .schema=="usdom-safe-deposit-finalized/v1" and .kind==$kind and .finalizedRpcCount==2' "$completion">/dev/null;state=clean;continue;fi
 state=signed-unresolved;echo "BROADCAST_REVALIDATION_REQUIRED: run publish-safe-deposit-relayer.sh $kind" >&2;exit 80
done
observer_a="$evidence/safe-deposit-observer-a.json";observer_b="$evidence/safe-deposit-observer-b.json"
if test ! -e "$observer_a" || test ! -e "$observer_b";then
 mapfile -t observer_ids < <("$jq_bin" -er '.rpcOrigins|if length==2 then .[].id else error("exactly two origins required") end' "$USDOM_SAFE_DEPOSIT_AUTHORITY");test "${#observer_ids[@]}" = 2
 for index in 0 1;do
  target=$([[ $index == 0 ]]&&printf '%s' "$observer_a"||printf '%s' "$observer_b")
  test -e "$target"&&continue
  read -r -s -p "RPC HTTPS privado para observer ${observer_ids[$index]}: " rpc_url </dev/tty;printf '\n' >&2
  printf '%s\n' "$rpc_url"|"$node_bin" scripts/collect-safe-deposit-accounting-observer.mjs "$USDOM_SAFE_DEPOSIT_AUTHORITY" "$plan" "$evidence/safe-deposit-approve-safe-envelope.json" "$evidence/safe-deposit-deposit-safe-envelope.json" "$evidence/safe-deposit-approve-finalized.json" "$evidence/safe-deposit-deposit-finalized.json" "${observer_ids[$index]}" "$target"
  unset rpc_url
 done
fi
for observer in "$observer_a" "$observer_b";do test -f "$observer"&&test ! -L "$observer"&&test "$(stat -c '%u:%a:%h' "$observer")" = "$(id -u):600:1"||{ echo "FINAL_ACCOUNTING_OBSERVATION_REQUIRED: $observer" >&2;exit 78;};done
collected="$evidence/safe-deposit-collected-evidence.json";observation="$evidence/safe-deposit-custody-observation.json";approval="$evidence/safe-deposit-ratification-approval.json";ratification="$evidence/safe-deposit-final-ratification.json"
current_collected="$tmp/collected.current.json";"$node_bin" scripts/collect-onekey-ios-safe-usdt-deposit.mjs "$USDOM_SAFE_DEPOSIT_AUTHORITY" "$plan" "$observer_a" "$observer_b" "$current_collected"||exit 80;if test -e "$collected";then cmp -s "$current_collected" "$collected"||exit 80;else "$node_bin" scripts/install-private-file-new-stdin.mjs --json "$collected"<"$current_collected";fi
current_observation="$tmp/observation.current.json";"$node_bin" scripts/materialize-onekey-ios-safe-usdt-custody.mjs "$USDOM_SAFE_DEPOSIT_AUTHORITY" "$collected" "$current_observation"||exit 80;if test -e "$observation";then cmp -s "$current_observation" "$observation"||exit 80;else "$node_bin" scripts/install-private-file-new-stdin.mjs --json "$observation"<"$current_observation";fi
if test ! -e "$approval";then
 approval_candidate="$tmp/ratification-approval.json";"$node_bin" scripts/prepare-safe-deposit-ratification-approval.mjs "$plan" "$observation">"$approval_candidate";approval_hash=$(sha256sum "$approval_candidate"|cut -d ' ' -f1)
 echo "FINAL SAFE DEPOSIT ACCOUNTING REVIEW plan=$plan observation=$observation approvalSha256=$approval_hash" >&2;read -r -p "Digite AUTORIZO RATIFICAR DEPOSITO SAFE AUTH $approval_hash: " answer </dev/tty;test "$answer" = "AUTORIZO RATIFICAR DEPOSITO SAFE AUTH $approval_hash"
 "$node_bin" scripts/install-private-file-new-stdin.mjs --json "$approval"<"$approval_candidate"
fi
current_ratification="$tmp/ratification.current.json";"$node_bin" scripts/ratify-onekey-ios-safe-usdt-deposit.mjs "$USDOM_SAFE_DEPOSIT_AUTHORITY" "$plan" "$collected" "$observation" "$approval" "$current_ratification"||exit 80;if test -e "$ratification";then cmp -s "$current_ratification" "$ratification"||exit 80;else "$node_bin" scripts/install-private-file-new-stdin.mjs --json "$ratification"<"$current_ratification";fi
$jq_bin -e '.schema=="usdom-onekey-ios-safe-usdt-deposit-ratification-v1" and .status=="ratified-specific-observed-deposit" and ([.gates[]]|all(.==true))' "$ratification">/dev/null
state=clean
printf '%s\n' 'Safe deposit complete: dual-RPC finality, Deposited event and accounting ratification agree.'
