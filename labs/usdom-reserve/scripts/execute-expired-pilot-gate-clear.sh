#!/usr/bin/env bash
set -euo pipefail
set +x; umask 077
unset BASH_XTRACEFD 2>/dev/null || true
unset NODE_OPTIONS NODE_PATH NODE_DEBUG NODE_DEBUG_NATIVE NODE_EXTRA_CA_CERTS NODE_TLS_REJECT_UNAUTHORIZED \
  SSL_CERT_FILE SSL_CERT_DIR OPENSSL_CONF OPENSSL_ENGINES SSLKEYLOGFILE RES_OPTIONS LOCALDOMAIN HOSTALIASES \
  LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
for inherited_name in ${!FOUNDRY_@} ${!CAST_@}; do unset "$inherited_name"; done
export RUST_BACKTRACE=0 RUST_LIB_BACKTRACE=0
ulimit -c 0 || { echo 'cannot disable core dumps' >&2; exit 1; }
export PATH=/home/leonardov/.foundry/bin:/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin:/usr/bin:/bin
test $# -eq 0 && test -t 0 && test -t 1 || { echo 'expired pilot gate clear requires an interactive terminal and no arguments' >&2; exit 64; }
: "${USDOM_CONTROL_EVIDENCE_DIRECTORY:?required}" "${USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:?required}"
readonly project=/home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve
test -d "$USDOM_CONTROL_EVIDENCE_DIRECTORY" && test ! -L "$USDOM_CONTROL_EVIDENCE_DIRECTORY"
test "$(stat -c '%u:%a' -- "$USDOM_CONTROL_EVIDENCE_DIRECTORY")" = "$UID:700"
test "$(realpath -e "$USDOM_CONTROL_EVIDENCE_DIRECTORY")" = "$USDOM_CONTROL_EVIDENCE_DIRECTORY"
for fd_path in /proc/"$$"/fd/*; do inherited_fd=${fd_path##*/}; [[ $inherited_fd =~ ^[0-9]+$ ]] || exit 1; (( inherited_fd<=2 )) && continue; [[ $inherited_fd == 255 ]] && continue; exec {inherited_fd}>&-; done
cd "$project"; exec 9<"$USDOM_CONTROL_EVIDENCE_DIRECTORY"; flock -n 9 || exit 75
test "$(realpath -e /proc/$$/fd/9)" = "$USDOM_CONTROL_EVIDENCE_DIRECTORY"
readonly evidence_parent_identity=$(stat -Lc '%d:%i:%u:%a' -- /proc/$$/fd/9)
test "$evidence_parent_identity" = "$(stat -c '%d:%i:%u:%a' -- "$USDOM_CONTROL_EVIDENCE_DIRECTORY")"
[[ $evidence_parent_identity == *":$UID:700" ]]
assert_evidence_parent() {
 test -d "$USDOM_CONTROL_EVIDENCE_DIRECTORY" && test ! -L "$USDOM_CONTROL_EVIDENCE_DIRECTORY"
 test "$(realpath -e "$USDOM_CONTROL_EVIDENCE_DIRECTORY")" = "$USDOM_CONTROL_EVIDENCE_DIRECTORY"
 test "$(stat -c '%d:%i:%u:%a' -- "$USDOM_CONTROL_EVIDENCE_DIRECTORY")" = "$evidence_parent_identity"
 test "$(stat -Lc '%d:%i:%u:%a' -- /proc/$$/fd/9)" = "$evidence_parent_identity"
}
readonly release_source="$project/config/proof-reserve.unconfigured.json" plan_source="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-plan.json"
readonly gate_completion_source="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-finalized.json" relayer_policy="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-gate-relayer-policy.json" relayer_package="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-clear-transaction.json" relayer_envelope="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-clear-relayer-envelope.json" raw="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-clear-raw.txt"
readonly receipt="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-clear-receipt.json" completion="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-clear-finalized.json"
tmp=$(mktemp -d -p /dev/shm usdom-pilot-clear.XXXXXXXX)
tmp_identity=$(/usr/bin/stat -c '%u:%d:%i:%a' "$tmp")
pilot_clear_broadcast_state=clean
cleanup() {
 local status=${1:-$?}
 trap - EXIT HUP INT TERM
 if [[ $pilot_clear_broadcast_state != clean ]] && (( status != 0 )); then status=80; fi
 if [[ $(/usr/bin/stat -c '%u:%d:%i:%a' "$tmp" 2>/dev/null) == "$tmp_identity" ]]; then
  /usr/bin/rm -rf -- "$tmp" || { (( status != 0 )) || status=1; }
 else
  (( status != 0 )) || status=1
 fi
 exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
snapshot_authority(){ local source=$1 destination=$2; node scripts/check-direct-strict-json-file.mjs --stdout "$source" >"$destination"; chmod 0600 "$destination"; node scripts/check-direct-strict-json-file.mjs "$destination"; }
snapshot_authority "$plan_source" "$tmp/gate-plan.json"
snapshot_authority "$gate_completion_source" "$tmp/gate-completion.json"
snapshot_authority "$release_source" "$tmp/release.json"
snapshot_authority "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "$tmp/rpc-sources.json"
snapshot_authority "$project/config/mainnet-preflight-rpc-catalog.json" "$tmp/rpc-catalog.json"
readonly plan="$tmp/gate-plan.json" gate_completion="$tmp/gate-completion.json" release="$tmp/release.json" rpc_catalog="$tmp/rpc-catalog.json"
USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE="$tmp/rpc-sources.json"
for file in "$plan" "$gate_completion"; do test -f "$file" && test ! -L "$file" && test "$(stat -c '%u:%a:%h' "$file")" = "$UID:600:1"; done
for file in "$relayer_package" "$relayer_envelope" "$raw" "$receipt" "$completion"; do if test -e "$file" || test -L "$file"; then test -f "$file" && test ! -L "$file" && test "$(stat -c '%u:%a:%h' "$file")" = "$UID:600:1"; fi; done
for authority in "$plan" "$gate_completion"; do node scripts/check-private-strict-json-file.mjs "$authority"; done
for authority in "$receipt" "$completion"; do if test -e "$authority"; then node scripts/check-private-strict-json-file.mjs "$authority"; fi; done
test "$(jq -er 'length' "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE")" -ge 2;
reserve=$(jq -er .reserve "$release"); snapshot=$(jq -er .snapshotCommitment "$plan"); expected=$(jq -er .expectedAuthorization "$plan"); valid_until=$(jq -er .validUntil "$plan"); generation=$(jq -er .generation "$plan")
data=$(cast calldata 'clearExpiredPilotDepositAuthorization(bytes32,uint64)' "$snapshot" "$generation")
printf '{"to":"%s","data":"%s"}\n' "$reserve" "$data" >"$tmp/private-transaction-input.json"
chmod 0600 "$tmp/private-transaction-input.json"
node -e 'const fs=require("fs"),{keccak256}=require("ethers"),v=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(JSON.stringify({schema:"usdom-pilot-gate-clear-relayer-package/v1",to:v.to,data:v.data,dataHash:keccak256(v.data)})+"\n")' "$tmp/private-transaction-input.json" >"$tmp/relayer-package.json"; chmod 0600 "$tmp/relayer-package.json"
if test -e "$relayer_package"; then cmp -s "$tmp/relayer-package.json" "$relayer_package"; else assert_evidence_parent; node scripts/install-private-file-new-stdin.mjs --json "$relayer_package" <"$tmp/relayer-package.json"; fi
node scripts/materialize-private-foundry-rpc-aliases.mjs "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "$rpc_catalog" >"$tmp/foundry-rpc.toml"
chmod 0600 "$tmp/foundry-rpc.toml"; export FOUNDRY_CONFIG="$tmp/foundry-rpc.toml"
rpcs=(usdom_rpc_a usdom_rpc_b)
rpc1=${rpcs[0]}; rpc2=${rpcs[1]}
observe() {
 local rpc=$1 out=$2 number hash timestamp
 test "$(cast chain-id --rpc-url "$rpc")" = 1; number=$(cast block finalized --field number --rpc-url "$rpc"); hash=$(cast block "$number" --field hash --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]'); timestamp=$(cast block "$number" --field timestamp --rpc-url "$rpc")
 jq -cn --arg number "$number" --arg hash "$hash" --arg timestamp "$timestamp" \
  --arg authorization "$(cast call "$reserve" 'authorizedPilotDeposit()(bytes32)' --block "$number" --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" \
  --arg snapshot "$(cast call "$reserve" 'authorizedPilotSnapshot()(bytes32)' --block "$number" --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" \
  --arg validUntil "$(cast call "$reserve" 'authorizedPilotValidUntil()(uint64)' --block "$number" --rpc-url "$rpc")" \
  --arg generation "$(cast call "$reserve" 'pilotAuthorizationGeneration()(uint64)' --block "$number" --rpc-url "$rpc")" \
  '{number:$number,hash:$hash,timestamp:$timestamp,authorization:$authorization,snapshot:$snapshot,validUntil:$validUntil,generation:$generation}' >"$out"; chmod 0600 "$out"
}
observe "$rpc1" "$tmp/a.json"; observe "$rpc2" "$tmp/b.json"; cmp -s "$tmp/a.json" "$tmp/b.json"
current=$(jq -er .authorization "$tmp/a.json"); current_generation=$(jq -er .generation "$tmp/a.json")
if test "$current" != 0x$(printf '0%.0s' {1..64}); then
 test "$current" = "$expected"; test "$(jq -er .snapshot "$tmp/a.json")" = "$snapshot"; test "$(jq -er .validUntil "$tmp/a.json")" = "$valid_until"; test "$current_generation" = "$generation"; test "$(node scripts/canonical-uint256.mjs ge "$(jq -er .timestamp "$tmp/a.json")" "$(node scripts/canonical-uint256.mjs add1 "$valid_until")")" = true
fi
if test ! -e "$relayer_envelope"; then
 test "$current" = "$expected" || { echo 'gate already clear but no authenticated clear evidence exists' >&2; exit 1; }
 test -f "$relayer_policy" && test ! -L "$relayer_policy" && test "$(stat -c '%u:%a:%h' "$relayer_policy")" = "$UID:600:1"; node scripts/check-private-strict-json-file.mjs "$relayer_policy"; relayer=$(jq -er .relayer "$relayer_policy")
 for forbidden in "$(jq -er .token "$release")" "$(jq -er .reserve "$release")" "$(jq -er .governance "$release")" "$(jq -er .guardian "$release")"; do test "${relayer,,}" != "${forbidden,,}"; done; for owner in $(jq -er '.governanceOwners[],.guardianOwners[],.checkpointGuardianOwners[]' "$release"); do test "${relayer,,}" != "${owner,,}"; done
 nonce1=$(cast nonce "$relayer" --block pending --rpc-url "$rpc1"); test "$nonce1" = "$(cast nonce "$relayer" --block pending --rpc-url "$rpc2")"; test "$(cast code "$relayer" --block finalized --rpc-url "$rpc1")" = 0x; test "$(cast code "$relayer" --block finalized --rpc-url "$rpc2")" = 0x
 private_estimate=$(node scripts/prepare-private-eth-estimate-gas.mjs "$tmp/private-transaction-input.json" "$relayer"); gas1=$(printf '%s\n' "$private_estimate" | cast rpc eth_estimateGas --raw --rpc-url "$rpc1" | jq -er . | xargs cast to-dec); test "$gas1" = "$(printf '%s\n' "$private_estimate" | cast rpc eth_estimateGas --raw --rpc-url "$rpc2" | jq -er . | xargs cast to-dec)"; base=$(cast block finalized --field baseFeePerGas --rpc-url "$rpc1"); test "$base" = "$(cast block finalized --field baseFeePerGas --rpc-url "$rpc2")"; fee_plan=$(node scripts/calculate-pilot-transaction-fees.mjs "$gas1" "$base" 250000 25000000000000000); gas=$(jq -er .gas <<<"$fee_plan"); fee=$(jq -er .maxFee <<<"$fee_plan")
 node scripts/prepare-pilot-gate-relayer-envelope.mjs "$tmp/private-transaction-input.json" "$relayer_package" "$relayer_policy" "$nonce1" "$gas" "$fee" 2000000000 >"$tmp/relayer-envelope.json"; chmod 0600 "$tmp/relayer-envelope.json"; assert_evidence_parent; node scripts/install-private-file-new-stdin.mjs --json "$relayer_envelope" <"$tmp/relayer-envelope.json"; echo "Envelope do relayer criado em $relayer_envelope. Instale a raw privada em $raw e execute novamente." >&2; exit 78
fi
if test ! -e "$raw"; then echo "raw privada do relayer ausente: $raw" >&2; exit 78; fi
node scripts/check-pilot-gate-relayer-raw.mjs "$raw" "$relayer_package" "$relayer_envelope" "$release" "$relayer_policy" >"$tmp/raw.json"; txhash=$(jq -er .transactionHash "$tmp/raw.json")
assert_relayer_live(){ local relayer nonce; relayer=$(jq -er .relayer "$relayer_envelope"); nonce=$(jq -er .nonce "$relayer_envelope"); test "$(cast nonce "$relayer" --block pending --rpc-url "$rpc1")" = "$nonce"; test "$(cast nonce "$relayer" --block pending --rpc-url "$rpc2")" = "$nonce"; test "$(cast code "$relayer" --block finalized --rpc-url "$rpc1")" = 0x; test "$(cast code "$relayer" --block finalized --rpc-url "$rpc2")" = 0x; node scripts/check-pilot-gate-relayer-raw.mjs "$raw" "$relayer_package" "$relayer_envelope" "$release" "$relayer_policy" | cmp -s - "$tmp/raw.json"; }
pilot_clear_broadcast_state=signed-unresolved
if test ! -e "$receipt"; then
 if ! cast receipt "$txhash" --json --rpc-url "$rpc1" >"$tmp/r1.json" 2>/dev/null || ! cast receipt "$txhash" --json --rpc-url "$rpc2" >"$tmp/r2.json" 2>/dev/null; then
  assert_relayer_live
  read -r -p "Digite AUTORIZO TRANSMITIR LIMPEZA EXPIRADA TX $txhash: " approval </dev/tty; test "$approval" = "AUTORIZO TRANSMITIR LIMPEZA EXPIRADA TX $txhash"
  assert_relayer_live
  observe "$rpc1" "$tmp/pre-send-a.json"; observe "$rpc2" "$tmp/pre-send-b.json"; cmp -s "$tmp/pre-send-a.json" "$tmp/pre-send-b.json"
  test "$(jq -er .authorization "$tmp/pre-send-a.json")" = "$expected"; test "$(jq -er .snapshot "$tmp/pre-send-a.json")" = "$snapshot"; test "$(jq -er .generation "$tmp/pre-send-a.json")" = "$generation"; test "$(node scripts/canonical-uint256.mjs ge "$(jq -er .timestamp "$tmp/pre-send-a.json")" "$(node scripts/canonical-uint256.mjs add1 "$valid_until")")" = true
  assert_evidence_parent
  pilot_clear_broadcast_state=publishing
  published=$(node scripts/publish-private-raw-transaction.mjs "$raw" "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "$rpc_catalog" 0 | tr '[:upper:]' '[:lower:]'); test "$published" = "$txhash"
 fi
 receipt_deadline=$((SECONDS+1800)); until cast receipt "$txhash" --json --rpc-url "$rpc1" >"$tmp/r1.json" 2>/dev/null && cast receipt "$txhash" --json --rpc-url "$rpc2" >"$tmp/r2.json" 2>/dev/null; do test "$SECONDS" -lt "$receipt_deadline" || { echo 'receipt observation timed out; restart to recover without rebroadcast' >&2; exit 75; }; sleep 12; done
 assert_evidence_parent
 node scripts/install-private-file-new-stdin.mjs --json "$receipt" <"$tmp/r1.json"
fi
for pair in "a:$rpc1" "b:$rpc2"; do label=${pair%%:*}; rpc=${pair#*:}; cast receipt "$txhash" --json --rpc-url "$rpc" >"$tmp/receipt-$label.json"; cast tx "$txhash" --json --rpc-url "$rpc" >"$tmp/tx-$label.json"; done
test "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs}' "$tmp/receipt-a.json")" = "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs}' "$tmp/receipt-b.json")"; cmp -s <(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs}' "$receipt") <(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs}' "$tmp/receipt-a.json")
test "$(jq -cS '{hash,from,to,nonce,input,value,blockNumber,blockHash}' "$tmp/tx-a.json")" = "$(jq -cS '{hash,from,to,nonce,input,value,blockNumber,blockHash}' "$tmp/tx-b.json")"
jq -e --arg tx "$txhash" --arg from "$(jq -er '.from|ascii_downcase' "$tmp/raw.json")" --arg to "${reserve,,}" --slurpfile private "$tmp/private-transaction-input.json" '(.hash|ascii_downcase)==$tx and (.from|ascii_downcase)==$from and (.to|ascii_downcase)==$to and (.input|ascii_downcase)==($private[0].data|ascii_downcase) and .value=="0x0"' "$tmp/tx-a.json" >/dev/null
test "$(node scripts/canonical-uint256.mjs normalize "$(jq -er .nonce "$tmp/tx-a.json")")" = "$(node scripts/canonical-uint256.mjs normalize "$(jq -er .nonce "$tmp/raw.json")")"
jq -e --arg tx "$txhash" '.status=="0x1" and (.transactionHash|ascii_downcase)==$tx' "$receipt" >/dev/null
cancel_topic=$(cast keccak 'PilotDepositAuthorizationCancelled(bytes32,bytes32,uint64,uint64,address)' | tr '[:upper:]' '[:lower:]')
cancel_data=$(cast abi-encode 'f(uint64,uint64)' "$valid_until" "$generation" | tr '[:upper:]' '[:lower:]'); authority=0x000000000000000000000000$(jq -er '.from|ascii_downcase|ltrimstr("0x")' "$tmp/raw.json")
jq -e --arg reserve "${reserve,,}" --arg topic "$cancel_topic" --arg snapshot "$snapshot" --arg expected "$expected" --arg authority "$authority" --arg data "$cancel_data" '([.logs[]|select((.address|ascii_downcase)==$reserve and (.topics[0]|ascii_downcase)==$topic and (.topics[1]|ascii_downcase)==$snapshot and (.topics[2]|ascii_downcase)==$expected and (.topics[3]|ascii_downcase)==$authority and (.data|ascii_downcase)==$data)]|length)==1' "$receipt" >/dev/null
block=$(node scripts/canonical-uint256.mjs normalize "$(jq -er .blockNumber "$receipt")"); block_hash=$(jq -er '.blockHash|ascii_downcase' "$receipt"); transaction_index=$(node scripts/canonical-uint256.mjs normalize "$(jq -er .transactionIndex "$receipt")")
for rpc in "$rpc1" "$rpc2"; do test "$(cast block "$block" --field hash --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" = "$block_hash"; done
finality_deadline=$((SECONDS+14400)); while :; do f1=$(cast block finalized --field number --rpc-url "$rpc1"); f2=$(cast block finalized --field number --rpc-url "$rpc2"); if test "$f1" = "$f2" && test "$(node scripts/canonical-uint256.mjs ge "$f1" "$block")" = true; then fh1=$(cast block "$f1" --field hash --rpc-url "$rpc1" | tr '[:upper:]' '[:lower:]'); test "$fh1" = "$(cast block "$f2" --field hash --rpc-url "$rpc2" | tr '[:upper:]' '[:lower:]')" && break; fi; test "$SECONDS" -lt "$finality_deadline" || { echo 'finality observation timed out; restart to recover without rebroadcast' >&2; exit 75; }; sleep 12; done
for pair in "a:$rpc1" "b:$rpc2"; do
 label=${pair%%:*}; rpc=${pair#*:}
 cast receipt "$txhash" --json --rpc-url "$rpc" >"$tmp/post-finality-receipt-$label.json"
 cast tx "$txhash" --json --rpc-url "$rpc" >"$tmp/post-finality-tx-$label.json"
 test "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs}' "$tmp/post-finality-receipt-$label.json")" = "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs}' "$receipt")"
 test "$(jq -cS '{hash,from,to,nonce,input,value,blockNumber,blockHash}' "$tmp/post-finality-tx-$label.json")" = "$(jq -cS '{hash,from,to,nonce,input,value,blockNumber,blockHash}' "$tmp/tx-a.json")"
 test "$(cast block "$block" --field hash --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" = "$block_hash"
done
observe "$rpc1" "$tmp/final-a.json"; observe "$rpc2" "$tmp/final-b.json"; cmp -s "$tmp/final-a.json" "$tmp/final-b.json"
test "$(jq -er .authorization "$tmp/final-a.json")" = 0x$(printf '0%.0s' {1..64}); test "$(jq -er .snapshot "$tmp/final-a.json")" = 0x$(printf '0%.0s' {1..64}); test "$(jq -er .validUntil "$tmp/final-a.json")" = 0; test "$(jq -er .generation "$tmp/final-a.json")" = "$(node scripts/canonical-uint256.mjs add1 "$generation")"
if test -e "$completion"; then
 jq -e --arg tx "$txhash" --arg block "$block" --arg blockHash "$block_hash" --arg transactionIndex "$transaction_index" --arg snapshot "$snapshot" --arg generation "$generation" 'keys==["blockHash","blockNumber","finalizedBlockHash","finalizedBlockNumber","generation","schema","snapshotCommitment","transactionHash","transactionIndex"] and .schema=="usdom-pilot-deposit-gate-clear-finalized/v2" and (.transactionHash|ascii_downcase)==$tx and .blockNumber==$block and (.blockHash|ascii_downcase)==$blockHash and .transactionIndex==$transactionIndex and (.snapshotCommitment|ascii_downcase)==$snapshot and .generation==$generation' "$completion" >/dev/null
 stored_finalized=$(jq -er .finalizedBlockNumber "$completion"); stored_hash=$(jq -er '.finalizedBlockHash|ascii_downcase' "$completion")
 for rpc in "$rpc1" "$rpc2"; do test "$(cast block "$stored_finalized" --field hash --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" = "$stored_hash"; test "$(node scripts/canonical-uint256.mjs ge "$(cast block finalized --field number --rpc-url "$rpc")" "$stored_finalized")" = true; done
 pilot_clear_broadcast_state=clean; exit 0
fi
jq -n --arg tx "$txhash" --arg blockNumber "$block" --arg blockHash "$block_hash" --arg transactionIndex "$transaction_index" --arg finalizedBlockNumber "$f1" --arg finalizedBlockHash "$fh1" --arg snapshotCommitment "$snapshot" --arg generation "$generation" '{schema:"usdom-pilot-deposit-gate-clear-finalized/v2",transactionHash:$tx,blockNumber:$blockNumber,blockHash:$blockHash,transactionIndex:$transactionIndex,finalizedBlockNumber:$finalizedBlockNumber,finalizedBlockHash:$finalizedBlockHash,snapshotCommitment:$snapshotCommitment,generation:$generation}' >"$tmp/completion.json"
assert_evidence_parent
node scripts/install-private-file-new-stdin.mjs --json "$completion" <"$tmp/completion.json"
pilot_clear_broadcast_state=clean
