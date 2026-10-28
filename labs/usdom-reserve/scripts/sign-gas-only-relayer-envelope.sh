#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077
ulimit -c 0
export LANG=C LC_ALL=C TZ=UTC
unset BASH_XTRACEFD NODE_OPTIONS NODE_PATH NODE_DEBUG LD_PRELOAD LD_LIBRARY_PATH CAST_PASSWORD ETH_PASSWORD
if (($#!=6)); then echo 'usage: FLOW ENVELOPE INPUT POLICY KEYSTORE OUTPUT' >&2; exit 64; fi
test -t 0 && test -t 2 || { echo 'assinatura do relayer exige terminal interativo' >&2; exit 2; }
flow=$1 envelope=$2 input=$3 policy=$4 keystore=$5 output=$6
project=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P); test "$PWD" = "$project"
source "$project/scripts/pinned-shell-tool-functions.sh"; pin_runtime_tool node; pin_runtime_tool cast
for file in "$envelope" "$input" "$policy" "$keystore"; do test -f "$file" && test ! -L "$file" && test "$(stat -c '%u:%a:%h' "$file")" = "$(id -u):600:1"; done
test ! -e "$output" && test ! -L "$output"
tmp=$(mktemp -d -p /dev/shm usdom-gas-relayer.XXXXXXXX); cleanup(){ s=${1:-$?};trap - EXIT HUP INT TERM;rm -rf -- "$tmp";exit "$s";};trap 'cleanup $?' EXIT;trap 'cleanup 129' HUP;trap 'cleanup 130' INT;trap 'cleanup 143' TERM
"$node_bin" scripts/prepare-gas-only-relayer-signing.mjs "$envelope" "$input" "$policy" "$keystore" >"$tmp/request.json"; chmod 0600 "$tmp/request.json"
hash=$("$node_bin" -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1]));if(!/^0x[0-9a-f]{64}$/.test(v.unsignedHash))process.exit(1);process.stdout.write(v.unsignedHash)' "$tmp/request.json")
printf 'Revise o fluxo %s e o hash %s. A raw sera somente gravada, nunca transmitida.\n' "$flow" "$hash" >&2
read -r -p "Digite AUTORIZO ASSINAR RELAYER $flow HASH $hash: " approval </dev/tty
test "$approval" = "AUTORIZO ASSINAR RELAYER $flow HASH $hash"
signature=$("$cast_bin" wallet sign --no-hash "$hash" --keystore "$keystore" </dev/tty)
printf '%s\n' "$signature" | "$node_bin" scripts/assemble-gas-only-relayer-signing.mjs "$tmp/request.json" >"$tmp/raw.txt"; chmod 0600 "$tmp/raw.txt"
"$node_bin" scripts/install-private-file-new-stdin.mjs "$output" <"$tmp/raw.txt"
printf 'Raw privada create-once instalada em %s; nenhuma transmissao foi realizada.\n' "$output"
