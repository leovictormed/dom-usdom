#!/usr/bin/env bash
set -euo pipefail
set +x
unset BASH_XTRACEFD 2>/dev/null || true
umask 077
ulimit -c 0
export LANG=C LC_ALL=C TZ=UTC
unset NODE_OPTIONS NODE_PATH NODE_DEBUG NODE_DEBUG_NATIVE SSLKEYLOGFILE \
 LD_PRELOAD LD_LIBRARY_PATH HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
 http_proxy https_proxy all_proxy no_proxy CAST_PASSWORD ETH_PASSWORD

if (($#!=1)) || [[ ! $1 =~ ^[0-3]$ ]]; then
 printf '%s\n' 'usage: sign-mainnet-deployment-gas-relayer.sh INDEX_0_TO_3' >&2; exit 64
fi
test -t 0 && test -t 2 || { printf '%s\n' 'Gas-relayer signing requires an interactive terminal.' >&2; exit 2; }
: "${USDOM_CONTROL_EVIDENCE_DIRECTORY:?USDOM_CONTROL_EVIDENCE_DIRECTORY is required}"
project=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P); test "$PWD" = "$project"
source "$project/scripts/pinned-shell-tool-functions.sh"
pin_runtime_tool node; pin_runtime_tool cast
node(){ assert_runtime_tool node; "$node_bin" "$@"; }
account_home=$(node -e 'const os=require("os");process.stdout.write(os.userInfo().homedir)')
relayer_root="$account_home/.local/share/dom-usdom/mainnet-relayers/deployment"
keystore="$relayer_root/relayer-keystore"
identity="$relayer_root/relayer-public-identity.json"
evidence=$(realpath -ms "$USDOM_CONTROL_EVIDENCE_DIRECTORY")
test -d "$evidence" && test ! -L "$evidence" && test "$(stat -c '%u:%a' "$evidence")" = "$(id -u):700"
test -d "$relayer_root" && test ! -L "$relayer_root" && test "$(stat -c '%u:%a' "$relayer_root")" = "$(id -u):700"
for file in "$keystore" "$identity"; do test -f "$file" && test ! -L "$file" && test "$(stat -c '%u:%a:%h' "$file")" = "$(id -u):600:1"; done
expected_keystore_sha=$(node -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(v.encryptedKeystoreSha256??"")' "$identity")
test "$expected_keystore_sha" = "$(sha256sum "$keystore" | cut -d ' ' -f 1)"
expected=$(node scripts/read-mainnet-gas-relayer-identity.mjs "$identity" deployment)
index=$1
prepared="$evidence/contract-deployment-$index-relayer-envelope.json"
output="$evidence/contract-deployment-$index-relayer-external-raw.txt"
test -f "$prepared" && test ! -L "$prepared" && test "$(stat -c '%u:%a:%h' "$prepared")" = "$(id -u):600:1"
test ! -e "$output" && test ! -L "$output"
observed=$(node -e 'const fs=require("fs"),{getAddress}=require("ethers"),v=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(getAddress(v.from))' "$prepared")
test "$observed" = "$expected"
unsigned_hash=$(node -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));if(!/^0x[0-9a-f]{64}$/.test(v.unsignedHash??""))process.exit(1);process.stdout.write(v.unsignedHash)' "$prepared")
printf 'Revise o deploy índice %s pelo relayer %s, hash %s.\n' "$index" "$expected" "$unsigned_hash" >&2
read -r -p "Digite AUTORIZO ASSINAR RELAYER DEPLOY $index HASH $unsigned_hash: " approval </dev/tty
test "$approval" = "AUTORIZO ASSINAR RELAYER DEPLOY $index HASH $unsigned_hash"
signature=$("$cast_bin" wallet sign --no-hash "$unsigned_hash" --keystore "$keystore" </dev/tty)
temporary=$(mktemp -p /dev/shm usdom-relayer-raw.XXXXXXXX)
cleanup(){ local status=${1:-$?}; trap - EXIT HUP INT TERM; rm -f -- "$temporary"; exit "$status"; }
trap 'cleanup $?' EXIT; trap 'cleanup 129' HUP; trap 'cleanup 130' INT; trap 'cleanup 143' TERM
printf '%s\n' "$signature" | node scripts/assemble-gas-relayer-eip1559.mjs "$prepared" >"$temporary"
chmod 0600 "$temporary"
node -e 'const fs=require("fs"),{Transaction,getAddress}=require("ethers"),raw=fs.readFileSync(process.argv[1],"ascii").trim(),tx=Transaction.from(raw);if(tx.serialized!==raw||getAddress(tx.from)!==getAddress(process.argv[2])||tx.chainId!==1n||tx.type!==2||tx.value!==0n)process.exit(1)' "$temporary" "$expected"
node scripts/install-private-file-new-stdin.mjs "$output" <"$temporary"
printf 'Raw do relayer instalada para o índice %s; nenhuma transmissão foi realizada.\n' "$index"
