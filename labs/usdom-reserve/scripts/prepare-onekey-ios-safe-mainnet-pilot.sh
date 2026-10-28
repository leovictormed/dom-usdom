#!/usr/bin/env bash
set -euo pipefail
set +x
project=/home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve
cd "$project"
root=${USDOM_PILOT_STATE_DIR:-/home/leonardov/.local/state/usdom-onekey-ios-pilot}
mode=${1:---status}; [[ $mode == --status || $mode == --next-command || $mode == --advance || $mode == --status-onboarding || $mode == --advance-onboarding || $mode == --status-custody || $mode == --advance-custody ]] || exit 64
[[ ! -L $root ]] || exit 73
if [[ -e $root ]];then [[ $(stat -c '%u:%a' "$root") == "$UID:700" && $(stat -c '%h' "$root") -ge 2 ]] || exit 73;fi
install -d -m 700 "$root"
[[ $(stat -c '%u:%a' "$root") == "$UID:700" ]] || exit 73
[[ $(stat -c '%h' "$root") -ge 2 ]] || exit 73
trap 'rm -f "$root/reown-project-request.json.tmp" "$root/install-system-dependencies-as-root.sh.tmp"' EXIT
exec 9>"$root/.lock"; flock -n 9 || exit 75
request=$root/reown-project-request.json; response=$root/reown-project-response.json; owner=$root/owner-1-evidence.json
rpc_sources=$root/mainnet-preflight-rpc-sources.json
walletconnect_config=${USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG:-$root/onekey-ios-walletconnect-client.json}
relayer_root=${USDOM_RELAYER_STATE_DIR:-/home/leonardov/.local/share/dom-usdom/mainnet-relayers}
relayer_roles=(deployment safe-deployment recovery reserve-resume pilot-gate)
node_bin=/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node
system_dependencies_ready(){ bash scripts/bootstrap-ubuntu-24.04-dependencies.sh --verify-only >/dev/null 2>&1; }
toolchain_ready(){ "$node_bin" scripts/check-mainnet-toolchain.mjs >/dev/null 2>&1; }
exists(){ [[ -e $1 || -L $1 ]]; }
private_file(){ [[ -f $1 && ! -L $1 && $(stat -c '%u:%a:%h' "$1") == "$UID:600:1" ]]; }
status(){
 system_dependencies_ready || { echo system-dependencies-pending;return; }
 toolchain_ready || { echo toolchain-pending;return; }
 exists "$rpc_sources" || { echo rpc-sources-pending;return; };private_file "$rpc_sources" || { echo rpc-sources-invalid;return; }
 exists "$request" || { echo reown-project-request-pending;return; };private_file "$request" || { echo reown-project-request-invalid;return; }
 exists "$response" || { echo reown-project-id-pending;return; };private_file "$response" || { echo reown-project-id-invalid;return; }
 for n in 1 2 3;do file=$root/owner-$n-evidence.json;exists "$file" || { echo owner-$n-pending;return; };private_file "$file" || { echo owner-$n-invalid;return; };done
 for role in "${relayer_roles[@]}";do file=$relayer_root/$role/relayer-public-identity.json;exists "$file" || { echo relayer-$role-pending;return; };private_file "$file" || { echo relayer-$role-invalid;return; };done
 exists "$root/safe-owner-identities-v2.json" || { echo owner-identities-pending;return; };private_file "$root/safe-owner-identities-v2.json" || { echo owner-identities-invalid;return; }
 [[ -n ${USDOM_SAFE_PACKAGE:-} ]] && exists "$USDOM_SAFE_PACKAGE" || { echo safe-package-pending;return; };private_file "$USDOM_SAFE_PACKAGE" || { echo safe-package-invalid;return; }
 exists "$walletconnect_config" || { echo walletconnect-config-pending;return; };private_file "$walletconnect_config" || { echo walletconnect-config-invalid;return; }
 for i in $(seq 0 11);do file=$root/custody-signature-$i.json;exists "$file" || { echo custody-signature-$i-pending;return; };private_file "$file" || { echo custody-signature-$i-invalid;return; };done
 exists "$root/safe-owner-hardware-custody-proofs-v1.json" || { echo custody-proof-bundle-pending;return; };private_file "$root/safe-owner-hardware-custody-proofs-v1.json" || { echo custody-proof-bundle-invalid;return; }
 exists "$root/preparation/plan-ready.json" || { echo offline-plan-pending;return; }
 "$node_bin" scripts/materialize-onekey-ios-pilot-preparation-plan.mjs "$root" "$relayer_root" "$USDOM_SAFE_PACKAGE" "$walletconnect_config" "$root/preparation" --verify-only >/dev/null 2>&1 || { echo offline-plan-invalid;return; }
 echo plan-ready
}
onboarding_status(){ for n in 1 2 3;do [[ -f $root/owner-$n-evidence.json ]] || { echo owner-$n-pending;return;};done;for role in "${relayer_roles[@]}";do [[ -f $relayer_root/$role/relayer-public-identity.json ]] || { echo relayer-$role-pending;return;};done;[[ -f $root/safe-owner-identities-v2.json ]] || { echo owner-identities-pending;return;};echo onboarding-complete; }
custody_status(){ onboarding_status | grep -Fx onboarding-complete >/dev/null || { onboarding_status;return;};[[ -n ${USDOM_SAFE_PACKAGE:-} && -f ${USDOM_SAFE_PACKAGE:-/nonexistent} ]] || { echo safe-package-pending;return;};for i in $(seq 0 11);do [[ -f $root/custody-signature-$i.json ]] || { echo custody-signature-$i-pending;return;};done;[[ -f $root/safe-owner-hardware-custody-proofs-v1.json ]] || { echo custody-proof-bundle-pending;return;};echo custody-proof-bundle-complete; }
[[ $mode != --status ]] || { status;exit 0; }
if [[ $mode == --next-command ]];then
 next=$(status)
 command_mode=--advance
 [[ $next != plan-ready ]] || command_mode=--status
 command=(/usr/bin/env "USDOM_PILOT_STATE_DIR=$root" "USDOM_RELAYER_STATE_DIR=$relayer_root")
 [[ -z ${USDOM_SAFE_PACKAGE:-} ]] || command+=("USDOM_SAFE_PACKAGE=$USDOM_SAFE_PACKAGE")
 command+=("USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG=$walletconnect_config")
 command+=("$project/scripts/prepare-onekey-ios-safe-mainnet-pilot.sh" "$command_mode")
 printf '%q ' "${command[@]}";printf '\n'
 exit 0
fi
[[ $mode != --status-onboarding ]] || { onboarding_status;exit 0; }
[[ $mode != --status-custody ]] || { custody_status;exit 0; }
[[ -x $node_bin ]] || { echo 'BLOCKED: pinned Node toolchain missing' >&2; exit 69; }
for protected in "$rpc_sources" "$request" "$response" "$walletconnect_config" "$root/safe-owner-identities-v2.json" "$root/safe-owner-hardware-custody-proofs-v1.json" "$root"/owner-*-evidence.json "$root"/custody-signature-*.json "$relayer_root"/*/relayer-public-identity.json;do [[ ! -L $protected ]] || exit 73;done
if ! system_dependencies_ready;then
 helper=$root/install-system-dependencies-as-root.sh
 candidate=$root/install-system-dependencies-as-root.sh.tmp
 cat >"$candidate" <<'SYSTEM_DEPS'
#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" -eq 0
exec /home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve/scripts/bootstrap-ubuntu-24.04-dependencies.sh --install
SYSTEM_DEPS
 chmod 0700 "$candidate"
 if [[ -e $helper ]];then [[ -f $helper && ! -L $helper && $(stat -c '%u:%a:%h' "$helper") == "$UID:700:1" ]] || { rm -f "$candidate";exit 73;};cmp -s "$candidate" "$helper" || { rm -f "$candidate";exit 73;};rm -f "$candidate";else mv -n "$candidate" "$helper" || exit 73;fi
 echo "SYSTEM_DEPENDENCIES_PENDING: run explicitly as root: $helper" >&2
 exit 78
fi
solc=/home/leonardov/.svm/0.8.37/solc-0.8.37
if [[ ! -e $solc ]];then bash scripts/bootstrap-solc-0.8.37.sh;fi
if ! toolchain_ready;then echo 'TOOLCHAIN_PENDING: pinned toolchain verification failed' >&2;exit 78;fi
"$node_bin" scripts/check-onekey-production-boundary.mjs >/dev/null
"$node_bin" scripts/check-onekey-production-readiness-dag.mjs >/dev/null
"$node_bin" scripts/check-walletconnect-sign-client-dependency.mjs >/dev/null
if [[ ! -e $rpc_sources ]];then
 [[ -r /dev/tty && -w /dev/tty ]] || { echo 'RPC_SOURCES_REQUIRE_PRIVATE_TTY' >&2;exit 2; }
 read -r -s -p 'Ethereum mainnet RPC HTTPS origin 1: ' rpc_a </dev/tty; printf '\n' >/dev/tty
 read -r -s -p 'Ethereum mainnet RPC HTTPS origin 2: ' rpc_b </dev/tty; printf '\n' >/dev/tty
 [[ -n $rpc_a && -n $rpc_b ]] || { unset rpc_a rpc_b;echo 'RPC sources cannot be empty' >&2;exit 78; }
 if printf '%s\n%s\n' "$rpc_a" "$rpc_b" | "$node_bin" scripts/install-onekey-pilot-rpc-sources.mjs "$rpc_sources";then :;else status=$?;unset rpc_a rpc_b;exit "$status";fi
 unset rpc_a rpc_b
fi
[[ -f $rpc_sources && ! -L $rpc_sources && $(stat -c '%u:%a:%h' "$rpc_sources") == "$UID:600:1" ]] || exit 73
rpc_catalog=$project/config/mainnet-preflight-rpc-catalog.json
rpc_catalog_candidate=$root/mainnet-preflight-rpc-catalog.candidate.json
trap 'rm -f "$root/reown-project-request.json.tmp" "$root/install-system-dependencies-as-root.sh.tmp" "${rpc_catalog_candidate:-}"' EXIT
USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE="$rpc_sources" "$node_bin" scripts/prepare-mainnet-preflight-rpc-catalog.mjs >"$rpc_catalog_candidate"
chmod 600 "$rpc_catalog_candidate"
if [[ -e $rpc_catalog ]];then
 cmp -s "$rpc_catalog_candidate" "$rpc_catalog" || { echo 'RPC catalog differs from the installed source pins' >&2;exit 78; }
else
 PATH="${node_bin%/*}:$PATH" USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE="$rpc_sources" bash scripts/write-mainnet-preflight-rpc-catalog.sh
fi
rm -f "$rpc_catalog_candidate"
if [[ ! -e $request ]];then umask 077; "$node_bin" scripts/request-reown-project-id.mjs >"$request.tmp"; chmod 600 "$request.tmp"; mv -n "$request.tmp" "$request" || exit 73;fi
if [[ ! -e $response ]];then echo "AWAITING_PUBLIC_PROJECT_ID: save only the validated public response at $response" >&2; exit 78;fi
private_file "$request" && private_file "$response" || exit 73
for n in 1 2 3;do
 owner="$root/owner-$n-evidence.json"
 if [[ -e $owner ]];then private_file "$owner" || exit 73;continue;fi
 echo "ACTION_REQUIRED: select a distinct Ethereum account in OneKey App for owner-$n" >&2
 "$node_bin" scripts/onboard-onekey-ios-owner.mjs "$response" "owner-$n" "$owner"
 addresses=$(for f in "$root"/owner-*-evidence.json;do "$node_bin" -e "console.log(JSON.parse(require('fs').readFileSync(process.argv[1])).address)" "$f";done)
 [[ $(printf '%s\n' "$addresses"|sort -u|wc -l) == $(printf '%s\n' "$addresses"|wc -l) ]] || exit 78
 exit 0
done
for role in "${relayer_roles[@]}";do
 identity="$relayer_root/$role/relayer-public-identity.json"
 [[ -e $identity ]] && { "$node_bin" scripts/read-mainnet-gas-relayer-identity.mjs "$identity" "$role" >/dev/null; continue; }
 echo "ACTION_REQUIRED: create distinct encrypted gas-only relayer for $role" >&2
 PATH="${node_bin%/*}:/home/leonardov/.foundry/bin:/usr/bin:/bin" bash scripts/create-mainnet-gas-relayer.sh "$role"
 exit 0
done
identities="$root/safe-owner-identities-v2.json"
[[ -e $identities ]] || "$node_bin" scripts/materialize-onekey-ios-owner-identities-v2.mjs "$root/owner-1-evidence.json" "$root/owner-2-evidence.json" "$root/owner-3-evidence.json" "$identities"
[[ $mode != --advance-onboarding ]] || { onboarding_status;exit 0; }
if [[ -z ${USDOM_SAFE_PACKAGE:-} || ! -e $USDOM_SAFE_PACKAGE ]];then echo "SAFE_PACKAGE_PENDING: produce the finalized Safe package, then rerun --next-command in the same environment" >&2;exit 78;fi
private_file "$USDOM_SAFE_PACKAGE" || exit 73
if [[ ! -e $walletconnect_config ]];then
 approval_phrase=$("$node_bin" scripts/materialize-onekey-ios-walletconnect-client-config.mjs --approval-phrase "$response")
 echo "ACTION_REQUIRED: $approval_phrase" >&2
 printf 'Cole a linha completa acima, sem ACTION_REQUIRED:, e pressione Enter.\nSua resposta: ' >&2
 if ! read -r operator_approval </dev/tty;then
  echo 'Autorização não recebida; a configuração WalletConnect não foi salva.' >&2
  exit 78
 fi
 if [[ $operator_approval != "$approval_phrase" ]];then
  echo 'Resposta vazia ou diferente da frase solicitada; a configuração WalletConnect não foi salva.' >&2
  exit 78
 fi
 printf '%s\n' "$operator_approval"|"$node_bin" scripts/materialize-onekey-ios-walletconnect-client-config.mjs "$response" "$walletconnect_config" >/dev/null
 unset operator_approval approval_phrase
 echo 'Configuração WalletConnect salva. Esta etapa terminou; nenhuma assinatura ou transação foi solicitada.'
 exit 0
fi
private_file "$walletconnect_config" || exit 73
USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG=$walletconnect_config
for index in $(seq 0 11);do
 signature="$root/custody-signature-$index.json";if [[ -e $signature ]];then private_file "$signature" || exit 73;continue;fi
 envelope="$root/custody-envelope-$index.json";request="$root/custody-request-$index.json";response="$root/custody-response-$index.json"
 [[ -e $envelope ]]||"$node_bin" scripts/materialize-safe-custody-signatures.mjs envelope "$USDOM_SAFE_PACKAGE" "$index" "$envelope"
 current_envelope="$root/.custody-envelope-recheck.$$.$index.json";test ! -e "$current_envelope";test ! -L "$current_envelope";trap 'rm -f -- "${current_envelope:-}" "$root/reown-project-request.json.tmp"' EXIT;trap 'exit 129' HUP;trap 'exit 130' INT;trap 'exit 143' TERM
 "$node_bin" scripts/materialize-safe-custody-signatures.mjs envelope "$USDOM_SAFE_PACKAGE" "$index" "$current_envelope";cmp -s "$current_envelope" "$envelope";rm -f -- "$current_envelope"
 expected=$("$node_bin" -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1])),i=Number(process.argv[2]),roles=["governance","reserveGuardian","checkpointGuardian","usdtCustody"];process.stdout.write(v.ownersByRole[roles[Math.floor(i/3)]][i%3])' "$USDOM_SAFE_PACKAGE" "$index")
 physical='';for candidate in "$root"/owner-*-evidence.json;do observed=$("$node_bin" -e 'const fs=require("fs"),{getAddress}=require("ethers"),v=JSON.parse(fs.readFileSync(process.argv[1]));process.stdout.write(getAddress(v.address))' "$candidate");[[ ${observed,,} == ${expected,,} ]]&&physical=$candidate;done;[[ -n $physical ]]||{ echo "ONBOARDING_EVIDENCE_REQUIRED: $expected" >&2;exit 78;}
 [[ -e $request ]]||"$node_bin" scripts/prepare-onekey-ios-walletconnect-request.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$envelope" "$physical" "$expected" "$request"
 "$node_bin" scripts/check-onekey-ios-walletconnect-request.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$envelope" "$physical" "$expected" "$request"
 [[ -e $response ]]||"$node_bin" scripts/sign-onekey-ios-walletconnect-typed-data.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$request" "$physical" "$response"||exit 80
 "$node_bin" scripts/materialize-safe-custody-signatures.mjs envelope "$USDOM_SAFE_PACKAGE" "$index" "$current_envelope";cmp -s "$current_envelope" "$envelope";rm -f -- "$current_envelope"
 "$node_bin" scripts/check-onekey-ios-walletconnect-request.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$envelope" "$physical" "$expected" "$request"
 sig=$("$node_bin" scripts/extract-onekey-ios-walletconnect-signature.mjs "$request" "$response")
 printf '{"signer":"%s","signature":"%s"}\n' "$expected" "$sig"|"$node_bin" scripts/install-private-file-new-stdin.mjs --json "$signature"
 exit 0
done
bundle="$root/safe-owner-hardware-custody-proofs-v1.json"
if [[ ! -e $bundle ]];then args=();for i in $(seq 0 11);do args+=("$root/custody-signature-$i.json");done;"$node_bin" scripts/materialize-safe-custody-signatures.mjs bundle "$USDOM_SAFE_PACKAGE" "${args[@]}" "$bundle";fi
export USDOM_SAFE_HARDWARE_CUSTODY_PROOFS="$bundle";"$node_bin" scripts/check-safe-owner-hardware-custody-proofs.mjs >/dev/null
[[ $mode != --advance-custody ]] || { custody_status;exit 0; }
if [[ $mode == --advance ]];then
 "$node_bin" scripts/materialize-onekey-ios-pilot-preparation-plan.mjs "$root" "$relayer_root" "$USDOM_SAFE_PACKAGE" "$walletconnect_config" "$root/preparation" >/dev/null
 status
 exit 0
fi
custody_authority="$root/onekey-ios-safe-usdt-custody-authority.json"
custody_authority_public="$root/onekey-ios-safe-usdt-custody-authority.public.json"
if [[ ! -e $custody_authority || ! -e $custody_authority_public ]];then
 : "${USDOM_SAFE_FINALIZED_BASELINE:?required}" "${USDOM_RELEASE_CONFIG_PRIVATE:?required}" "${USDOM_PILOT_FUNDS_SNAPSHOT:?required}" "${USDOM_PRIVATE_RPC_CATALOG:?required}"
 relayer_args=();for role in "${relayer_roles[@]}";do relayer_args+=("$relayer_root/$role/relayer-public-identity.json");done
 "$node_bin" scripts/materialize-onekey-ios-safe-usdt-custody-authority.mjs "$USDOM_SAFE_FINALIZED_BASELINE" "$bundle" "$root/safe-owner-identities-v2.json" "$USDOM_RELEASE_CONFIG_PRIVATE" "$USDOM_PILOT_FUNDS_SNAPSHOT" "$USDOM_PRIVATE_RPC_CATALOG" "${relayer_args[@]}" "$custody_authority" "$custody_authority_public"
fi
for n in 1 2 3;do
 replacement="$root/replacement-owner-$n-evidence.json";[[ -e $replacement ]]&&continue
 echo "ACTION_REQUIRED: onboard a new distinct OneKey replacement-owner-$n account" >&2
 "$node_bin" scripts/onboard-onekey-ios-owner.mjs "$response" "replacement-owner-$n" "$replacement";exit 0
done
forbidden="$root/recovery-forbidden-addresses.json"
if [[ ! -e $forbidden ]];then { for role in "${relayer_roles[@]}";do "$node_bin" scripts/read-mainnet-gas-relayer-identity.mjs "$relayer_root/$role/relayer-public-identity.json" "$role";done;}|"$node_bin" -e 'let s="";process.stdin.on("data",x=>s+=x).on("end",()=>process.stdout.write(JSON.stringify({addresses:s.trim().split(/\s+/)})))'|"$node_bin" scripts/install-private-file-new-stdin.mjs --json "$forbidden";fi
: "${USDOM_SAFE_FINALIZED_BASELINE:?required}"
drill="$root/safe-recovery-roster-drill-v3.json"
if [[ ! -e $drill ]];then "$node_bin" scripts/materialize-safe-recovery-roster-drill.mjs plan "$USDOM_SAFE_PACKAGE" "$USDOM_SAFE_FINALIZED_BASELINE" "$root/replacement-owner-1-evidence.json" "$root/replacement-owner-2-evidence.json" "$root/replacement-owner-3-evidence.json" "$forbidden" "$drill";fi
for index in 0 1 2;do
 signature="$root/recovery-roster-proof-signature-$index.json";[[ -e $signature ]]&&continue
 envelope="$root/recovery-roster-proof-envelope-$index.json";request="$root/recovery-roster-proof-request-$index.json";response_file="$root/recovery-roster-proof-response-$index.json";expected=$("$node_bin" -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1]));process.stdout.write(v.replacementOwners[Number(process.argv[2])])' "$drill" "$index")
 physical='';for candidate in "$root"/replacement-owner-*-evidence.json;do observed=$("$node_bin" -e 'const fs=require("fs"),{getAddress}=require("ethers"),v=JSON.parse(fs.readFileSync(process.argv[1]));process.stdout.write(getAddress(v.address))' "$candidate");[[ ${observed,,} == ${expected,,} ]]&&physical=$candidate;done;[[ -n $physical ]]||{ echo "REPLACEMENT_ONBOARDING_EVIDENCE_REQUIRED: $expected" >&2;exit 78;}
 [[ -e $envelope ]]||"$node_bin" scripts/materialize-safe-recovery-roster-drill.mjs envelope "$drill" "$index" "$envelope"
 current_plan="$root/.recovery-plan-recheck.$$.$index.json";current_envelope="$root/.recovery-envelope-recheck.$$.$index.json"
 test ! -e "$current_plan";test ! -L "$current_plan";test ! -e "$current_envelope";test ! -L "$current_envelope"
 trap 'rm -f -- "${current_plan:-}" "${current_envelope:-}" "$root/reown-project-request.json.tmp"' EXIT
 "$node_bin" scripts/materialize-safe-recovery-roster-drill.mjs plan "$USDOM_SAFE_PACKAGE" "$USDOM_SAFE_FINALIZED_BASELINE" "$root/replacement-owner-1-evidence.json" "$root/replacement-owner-2-evidence.json" "$root/replacement-owner-3-evidence.json" "$forbidden" "$current_plan"
 cmp -s "$current_plan" "$drill";rm -f -- "$current_plan"
 "$node_bin" scripts/materialize-safe-recovery-roster-drill.mjs envelope "$drill" "$index" "$current_envelope";cmp -s "$current_envelope" "$envelope";rm -f -- "$current_envelope"
 [[ -e $request ]]||"$node_bin" scripts/prepare-onekey-ios-walletconnect-request.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$envelope" "$physical" "$expected" "$request"
 "$node_bin" scripts/check-onekey-ios-walletconnect-request.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$envelope" "$physical" "$expected" "$request"
 [[ -e $response_file ]]||"$node_bin" scripts/sign-onekey-ios-walletconnect-typed-data.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$request" "$physical" "$response_file"||exit 80
 "$node_bin" scripts/materialize-safe-recovery-roster-drill.mjs plan "$USDOM_SAFE_PACKAGE" "$USDOM_SAFE_FINALIZED_BASELINE" "$root/replacement-owner-1-evidence.json" "$root/replacement-owner-2-evidence.json" "$root/replacement-owner-3-evidence.json" "$forbidden" "$current_plan"
 cmp -s "$current_plan" "$drill";rm -f -- "$current_plan"
 "$node_bin" scripts/materialize-safe-recovery-roster-drill.mjs envelope "$drill" "$index" "$current_envelope";cmp -s "$current_envelope" "$envelope";rm -f -- "$current_envelope"
 "$node_bin" scripts/check-onekey-ios-walletconnect-request.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$envelope" "$physical" "$expected" "$request"
 sig=$("$node_bin" scripts/extract-onekey-ios-walletconnect-signature.mjs "$request" "$response_file");printf '{"signer":"%s","signature":"%s"}\n' "$expected" "$sig"|"$node_bin" scripts/install-private-file-new-stdin.mjs --json "$signature";exit 0
done
recovery_proofs="$root/safe-recovery-roster-proofs-v3.json"
[[ -e $recovery_proofs ]]||"$node_bin" scripts/materialize-safe-recovery-roster-drill.mjs bundle "$drill" "$root/recovery-roster-proof-signature-0.json" "$root/recovery-roster-proof-signature-1.json" "$root/recovery-roster-proof-signature-2.json" "$recovery_proofs"
status
