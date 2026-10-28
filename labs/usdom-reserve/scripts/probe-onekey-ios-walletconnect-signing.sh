#!/usr/bin/env bash
set -euo pipefail
set +x
unset BASH_XTRACEFD 2>/dev/null || true
umask 077
ulimit -c 0
export LANG=C LC_ALL=C TZ=UTC
unset NODE_OPTIONS NODE_PATH NODE_DEBUG NODE_DEBUG_NATIVE SSLKEYLOGFILE \
  LD_PRELOAD LD_LIBRARY_PATH HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
  http_proxy https_proxy all_proxy no_proxy

test "$#" -eq 0 || { printf '%s\n' 'usage: npm run --silent probe:onekey-ios-walletconnect-signing' >&2; exit 64; }
test -t 0 && test -t 2 || { printf '%s\n' 'OneKey iPhone signing probe requires an interactive terminal.' >&2; exit 2; }
project=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
test "$PWD" = "$project"
source "$project/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node
node(){ assert_runtime_tool node; "$node_bin" "$@"; }
account_home=$(node -e 'const os=require("os");process.stdout.write(os.userInfo().homedir)')
root="$account_home/.local/share/dom-usdom/mainnet-wallet"
config="$root/onekey-ios-walletconnect-client.json"
physical="$root/onekey-ios-redemption-account-evidence.json"
output="$root/onekey-ios-walletconnect-capability-response.json"
request="$root/onekey-ios-walletconnect-capability-request.json"
test -d "$root" && test ! -L "$root" && test "$(stat -c '%u:%a' "$root")" = "$(id -u):700"
for input in "$config" "$physical"; do
 test -f "$input" && test ! -L "$input" && test "$(stat -c '%u:%a:%h' "$input")" = "$(id -u):600:1"
done
test ! -e "$request" && test ! -L "$request"
test ! -e "$output" && test ! -L "$output"
node scripts/prepare-onekey-ios-capability-probe.mjs "$config" "$physical" "$request"
node scripts/sign-onekey-ios-walletconnect-typed-data.mjs "$config" "$request" "$physical" "$output"
node -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));if(v.schema!=="usdom-onekey-ios-walletconnect-typed-data/v1"||!/^0x[0-9a-fA-F]{130}$/.test(v.signature))process.exit(1)' "$output"
printf '%s\n' 'Assinatura EIP-712 móvel confirmada; nenhuma transação foi criada ou transmitida.'
