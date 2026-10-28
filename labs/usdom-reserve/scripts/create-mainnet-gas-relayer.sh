#!/usr/bin/env bash
set -euo pipefail
set +x
unset BASH_XTRACEFD 2>/dev/null || true
umask 077
ulimit -c 0
export LANG=C LC_ALL=C TZ=UTC
unset NODE_OPTIONS NODE_PATH NODE_DEBUG NODE_DEBUG_NATIVE SSLKEYLOGFILE LD_PRELOAD LD_LIBRARY_PATH \
 HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy \
 CAST_PASSWORD ETH_PASSWORD
test "$#" -eq 1 || { printf '%s\n' 'usage: create-mainnet-gas-relayer.sh ROLE' >&2; exit 64; }
role=$1
case "$role" in deployment|safe-deployment|recovery|reserve-resume|pilot-gate);; *) echo 'unsupported relayer role' >&2; exit 64;; esac
test -t 0 && test -t 2 || { printf '%s\n' 'Relayer creation requires an interactive terminal.' >&2; exit 2; }
project=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P); test "$PWD" = "$project"
source "$project/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node; pin_runtime_tool cast
node(){ assert_runtime_tool node; "$node_bin" "$@"; }
account_home=$(node -e 'const os=require("os");process.stdout.write(os.userInfo().homedir)')
relayer_base=${USDOM_RELAYER_STATE_DIR:-$account_home/.local/share/dom-usdom/mainnet-relayers}
root="$relayer_base/$role"
keystore="$root/relayer-keystore"
identity="$root/relayer-public-identity.json"
mkdir -p -m 0700 "$relayer_base"; test -d "$relayer_base" && test ! -L "$relayer_base" && test "$(stat -c '%u:%a' "$relayer_base")" = "$(id -u):700"
test ! -e "$root" && test ! -L "$root"
mkdir -m 0700 -p "$root"
root_identity=$(stat -Lc '%d:%i:%u:%a' "$root"); completed=false
cleanup(){ status=${1:-$?};trap - EXIT HUP INT TERM;if [[ $completed == false && -d $root && ! -L $root && $(stat -Lc '%d:%i:%u:%a' "$root") == "$root_identity" ]];then rm -rf -- "$root";fi;exit "$status";}
trap 'cleanup $?' EXIT;trap 'cleanup 129' HUP;trap 'cleanup 130' INT;trap 'cleanup 143' TERM
"$cast_bin" wallet new "$root" relayer-keystore </dev/tty >/dev/null
test -f "$keystore" && test ! -L "$keystore"; chmod 0600 "$keystore"
test ! -e "$identity" && test ! -L "$identity"
address=$("$cast_bin" wallet address --keystore "$keystore" </dev/tty)
separation_inputs=()
for sibling in "$relayer_base"/*/relayer-public-identity.json; do [[ -e $sibling && $sibling != "$identity" ]] && separation_inputs+=("$sibling"); done
pilot_root=${USDOM_PILOT_STATE_DIR:-$account_home/.local/state/usdom-onekey-ios-pilot}
for owner in "$pilot_root"/owner-*-evidence.json; do [[ -e $owner ]] && separation_inputs+=("$owner"); done
[[ -e $project/config/proof-reserve.unconfigured.json ]] && separation_inputs+=("$project/config/proof-reserve.unconfigured.json")
if ((${#separation_inputs[@]})); then node scripts/check-gas-relayer-role-separation.mjs "$address" "${separation_inputs[@]}" || { rm -rf -- "$root"; exit 1; }; fi
keystore_sha=$(sha256sum "$keystore" | cut -d ' ' -f 1)
node -e 'const {getAddress}=require("ethers"),fs=require("fs"),[target,address,hash,role]=process.argv.slice(1);const value={schema:"usdom-mainnet-gas-relayer-public-identity/v2",chainId:"1",address:getAddress(address),role:`${role}-gas-only`,encryptedKeystoreSha256:hash,custodyAuthority:false,tokenCustody:false};fs.writeFileSync(target,JSON.stringify(value)+"\n",{flag:"wx",mode:0o600})' "$identity" "$address" "$keystore_sha" "$role"
test "$(node scripts/read-mainnet-gas-relayer-identity.mjs "$identity" "$role")" = "$address"
completed=true
printf 'Relayer gas-only criado: %s\nIdentidade pública: %s\n' "$address" "$identity"
printf '%s\n' 'A chave privada ficou somente no keystore cifrado; guarde a senha fora deste computador.'
