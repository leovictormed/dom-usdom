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
test $# -eq 0 && test -t 0 && test -t 1 || { echo 'pilot gate requires an interactive terminal and no arguments' >&2; exit 64; }
: "${USDOM_CONTROL_EVIDENCE_DIRECTORY:?required}" "${USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:?required}" "${USDOM_SAFE_PACKAGE:?required}" "${USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG:?required}"
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
readonly snapshot="$project/evidence/authorization/pilot-funds-snapshot.json" state="$project/evidence/authorization/pilot-funds-authorization-state.json"
readonly release="$project/config/proof-reserve.unconfigured.json" plan="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-plan.json"
readonly sig1="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-signature-1.json" sig2="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-signature-2.json"
readonly sighex1="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-onekey-signature-1.hex" sighex2="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-onekey-signature-2.hex"
readonly relayer_policy="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-gate-relayer-policy.json" relayer_envelope="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-relayer-envelope.json"
readonly package="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-transaction.json" raw="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-raw.txt"
readonly receipt="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-receipt.json" completion="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-finalized.json"
for authority in "$snapshot" "$state" "$release" "$USDOM_SAFE_PACKAGE" "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE"; do node scripts/check-direct-strict-json-file.mjs "$authority"; done
test "$(jq -er 'length' "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE")" -ge 2
reserve=$(jq -er .reserve "$release"); safe=$(jq -er .governance "$release")
observe() {
 local rpc=$1 out=$2 number hash
 test "$(cast chain-id --rpc-url "$rpc")" = 1
 number=$(cast block finalized --field number --rpc-url "$rpc"); hash=$(cast block "$number" --field hash --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')
 jq -cn --arg chainId 1 --arg finalizedBlockNumber "$number" --arg finalizedBlockHash "$hash" \
  --arg safeNonce "$(cast call "$safe" 'nonce()(uint256)' --block "$number" --rpc-url "$rpc")" \
  --arg safeThreshold "$(cast call "$safe" 'getThreshold()(uint256)' --block "$number" --rpc-url "$rpc")" \
  --argjson safeOwners "$(cast call "$safe" 'getOwners()(address[])' --block "$number" --rpc-url "$rpc" | sed -E 's/^\[//;s/\]$//;s/, /","/g;s/^/["/;s/$/"]/')" \
  --argjson pilotRestrictedDeployment "$(cast call "$reserve" 'pilotRestrictedDeployment()(bool)' --block "$number" --rpc-url "$rpc")" \
  --argjson permissionlessDeposits "$(cast call "$reserve" 'permissionlessDeposits()(bool)' --block "$number" --rpc-url "$rpc")" \
  --argjson pilotDepositConsumed "$(cast call "$reserve" 'pilotDepositConsumed()(bool)' --block "$number" --rpc-url "$rpc")" \
  --arg authorizedPilotDeposit "$(cast call "$reserve" 'authorizedPilotDeposit()(bytes32)' --block "$number" --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" \
  --arg authorizedPilotSnapshot "$(cast call "$reserve" 'authorizedPilotSnapshot()(bytes32)' --block "$number" --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" \
  --arg authorizedPilotValidUntil "$(cast call "$reserve" 'authorizedPilotValidUntil()(uint64)' --block "$number" --rpc-url "$rpc")" \
  --arg pilotAuthorizationGeneration "$(cast call "$reserve" 'pilotAuthorizationGeneration()(uint64)' --block "$number" --rpc-url "$rpc")" \
  --arg totalDeposited "$(cast call "$reserve" 'totalDeposited()(uint256)' --block "$number" --rpc-url "$rpc")" \
  --arg derivedAuthorization "$(cast call "$reserve" 'pilotDepositAuthorization(address,uint64,bytes32,bytes32,uint64,uint64)(bytes32)' "$(jq -er .funder "$snapshot")" "$(jq -er .pilotDepositBaseUnits "$snapshot")" "$(jq -er .salt "$snapshot")" "$(jq -er .receivingCommitment "$snapshot")" "$(jq -er .authorization.validUntil "$state")" "$(cast call "$reserve" 'pilotAuthorizationGeneration()(uint64)' --block "$number" --rpc-url "$rpc")" --block "$number" --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" \
  '{chainId:$chainId,finalizedBlockNumber:$finalizedBlockNumber,finalizedBlockHash:$finalizedBlockHash,safeNonce:$safeNonce,safeThreshold:$safeThreshold,safeOwners:$safeOwners,pilotRestrictedDeployment:$pilotRestrictedDeployment,permissionlessDeposits:$permissionlessDeposits,pilotDepositConsumed:$pilotDepositConsumed,authorizedPilotDeposit:$authorizedPilotDeposit,authorizedPilotSnapshot:$authorizedPilotSnapshot,authorizedPilotValidUntil:$authorizedPilotValidUntil,pilotAuthorizationGeneration:$pilotAuthorizationGeneration,totalDeposited:$totalDeposited,derivedAuthorization:$derivedAuthorization}' >"$out"
 chmod 0600 "$out"
}
assert_plan_prestate() {
 local observed=$1 zero=0x0000000000000000000000000000000000000000000000000000000000000000
 test "$(jq -er .safeNonce "$observed")" = "$(jq -er .safeTransaction.nonce "$plan")"
 test "$(jq -er .pilotAuthorizationGeneration "$observed")" = "$(jq -er .generation "$plan")"
 test "$(jq -er .pilotDepositConsumed "$observed")" = false
 test "$(jq -er .authorizedPilotDeposit "$observed")" = "$zero"
 test "$(jq -er .authorizedPilotSnapshot "$observed")" = "$zero"
 test "$(jq -er .authorizedPilotValidUntil "$observed")" = 0
 test "$(jq -er .derivedAuthorization "$observed")" = "$(jq -er .expectedAuthorization "$plan")"
}
tmp=$(mktemp -d -p /dev/shm usdom-pilot-gate.XXXXXXXX)
tmp_identity=$(/usr/bin/stat -c '%u:%d:%i:%a' "$tmp")
pilot_broadcast_state=clean
cleanup() {
 local status=${1:-$?}
 trap - EXIT HUP INT TERM
 if [[ $pilot_broadcast_state != clean ]] && (( status != 0 )); then status=80; fi
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
node scripts/materialize-private-foundry-rpc-aliases.mjs "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" \
  config/mainnet-preflight-rpc-catalog.json >"$tmp/foundry-rpc.toml"
chmod 0600 "$tmp/foundry-rpc.toml"; export FOUNDRY_CONFIG="$tmp/foundry-rpc.toml"
rpcs=(usdom_rpc_a usdom_rpc_b)
rpc1=${rpcs[0]}; rpc2=${rpcs[1]}
cp -- "$release" "$tmp/release.json"; chmod 0600 "$tmp/release.json"
for durable in "$plan" "$sig1" "$sig2" "$sighex1" "$sighex2" "$package" "$relayer_envelope" "$raw" "$receipt" "$completion"; do if test -e "$durable" || test -L "$durable"; then test -f "$durable" && test ! -L "$durable" && test "$(stat -c '%u:%a:%h' "$durable")" = "$UID:600:1"; fi; done
for authority in "$plan" "$sig1" "$sig2" "$package" "$receipt" "$completion"; do if test -e "$authority"; then node scripts/check-private-strict-json-file.mjs "$authority"; fi; done
if test -e "$completion"; then
 for durable in "$plan" "$sig1" "$sig2" "$package" "$relayer_envelope" "$raw" "$receipt" "$completion"; do test -f "$durable" && test ! -L "$durable" && test "$(stat -c '%u:%a:%h' "$durable")" = "$UID:600:1"; done
 node scripts/assemble-pilot-deposit-gate-transaction.mjs "$plan" "$snapshot" "$state" "$tmp/release.json" "$USDOM_SAFE_PACKAGE" "$sig1" "$sig2" >"$tmp/package-rebuilt.json"; cmp -s "$tmp/package-rebuilt.json" "$package"
 node scripts/check-pilot-gate-relayer-raw.mjs "$raw" "$package" "$relayer_envelope" "$tmp/release.json" "$relayer_policy" >"$tmp/raw-validation.json"
 txhash=$(jq -er .transactionHash "$tmp/raw-validation.json"); payer=$(jq -er .from "$tmp/raw-validation.json"); payer_nonce=$(jq -er .nonce "$tmp/raw-validation.json")
 safe_hash=$(jq -er .safeTxHash "$plan"); expected=$(jq -er .expectedAuthorization "$plan"); commitment=$(jq -er .snapshotCommitment "$plan")
 jq -e --arg tx "$txhash" --arg safeHash "$safe_hash" --arg expected "$expected" --arg commitment "$commitment" --arg generation "$(jq -er .generation "$plan")" 'keys==["blockHash","blockNumber","expectedAuthorization","finalizedBlockHash","finalizedBlockNumber","generation","safeTxHash","schema","snapshotCommitment","transactionHash","transactionIndex"] and .schema=="usdom-pilot-deposit-gate-finalized/v2" and (.transactionHash|ascii_downcase)==$tx and (.safeTxHash|ascii_downcase)==$safeHash and (.expectedAuthorization|ascii_downcase)==$expected and (.snapshotCommitment|ascii_downcase)==$commitment and .generation==$generation' "$completion" >/dev/null
 for pair in "a:$rpc1" "b:$rpc2"; do label=${pair%%:*}; rpc=${pair#*:}; cast receipt "$txhash" --json --rpc-url "$rpc" >"$tmp/restart-receipt-$label.json"; cast tx "$txhash" --json --rpc-url "$rpc" >"$tmp/restart-tx-$label.json"; done
 test "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs}' "$tmp/restart-receipt-a.json")" = "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs}' "$tmp/restart-receipt-b.json")"
 test "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs}' "$tmp/restart-receipt-a.json")" = "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs}' "$receipt")"
 test "$(jq -cS '{hash,from,to,nonce,input,value,blockNumber,blockHash}' "$tmp/restart-tx-a.json")" = "$(jq -cS '{hash,from,to,nonce,input,value,blockNumber,blockHash}' "$tmp/restart-tx-b.json")"
 jq -e --arg tx "$txhash" --arg payer "${payer,,}" --arg safe "${safe,,}" '.status=="0x1" and (.transactionHash|ascii_downcase)==$tx and (.from|ascii_downcase)==$payer and (.to|ascii_downcase)==$safe' "$receipt" >/dev/null
 jq -e --arg tx "$txhash" --arg payer "${payer,,}" --arg safe "${safe,,}" --slurpfile package "$package" '(.hash|ascii_downcase)==$tx and (.from|ascii_downcase)==$payer and (.to|ascii_downcase)==$safe and (.input|ascii_downcase)==($package[0].data|ascii_downcase) and .value=="0x0"' "$tmp/restart-tx-a.json" >/dev/null
 test "$(node scripts/canonical-uint256.mjs normalize "$(jq -er .nonce "$tmp/restart-tx-a.json")")" = "$(node scripts/canonical-uint256.mjs normalize "$payer_nonce")"
 execution_topic=$(cast keccak 'ExecutionSuccess(bytes32,uint256)' | tr '[:upper:]' '[:lower:]'); authorization_topic=$(cast keccak 'PilotDepositAuthorized(bytes32,bytes32,uint64,uint64)' | tr '[:upper:]' '[:lower:]'); authorization_data=$(cast abi-encode 'f(uint64,uint64)' "$(jq -er .validUntil "$plan")" "$(jq -er .generation "$plan")" | tr '[:upper:]' '[:lower:]')
 jq -e --arg safe "${safe,,}" --arg reserve "${reserve,,}" --arg execution "$execution_topic" --arg authorization "$authorization_topic" --arg authorizationData "$authorization_data" --arg safeHash "$safe_hash" --arg commitment "$commitment" --arg expected "$expected" '([.logs[]|select((.address|ascii_downcase)==$safe and (.topics[0]|ascii_downcase)==$execution and (.topics[1]|ascii_downcase)==$safeHash)]|length)==1 and ([.logs[]|select((.address|ascii_downcase)==$reserve and (.topics[0]|ascii_downcase)==$authorization and (.topics[1]|ascii_downcase)==$commitment and (.topics[2]|ascii_downcase)==$expected and (.data|ascii_downcase)==$authorizationData)]|length)==1' "$receipt" >/dev/null
 completed_block=$(node scripts/canonical-uint256.mjs normalize "$(jq -er .blockNumber "$completion")"); completed_hash=$(jq -er '.blockHash|ascii_downcase' "$completion"); completed_index=$(node scripts/canonical-uint256.mjs normalize "$(jq -er .transactionIndex "$completion")"); completed_finalized=$(node scripts/canonical-uint256.mjs normalize "$(jq -er .finalizedBlockNumber "$completion")"); completed_finalized_hash=$(jq -er .finalizedBlockHash "$completion")
 test "$(node scripts/canonical-uint256.mjs normalize "$(jq -er .blockNumber "$receipt")")" = "$completed_block"; test "$(jq -er '.blockHash|ascii_downcase' "$receipt")" = "$completed_hash"; test "$(node scripts/canonical-uint256.mjs normalize "$(jq -er .transactionIndex "$receipt")")" = "$completed_index"
 for rpc in "$rpc1" "$rpc2"; do test "$(cast chain-id --rpc-url "$rpc")" = 1; test "$(cast block "$completed_block" --field hash --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" = "$completed_hash"; test "$(cast block "$completed_finalized" --field hash --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" = "$completed_finalized_hash"; test "$(node scripts/canonical-uint256.mjs ge "$(cast block finalized --field number --rpc-url "$rpc")" "$completed_finalized")" = true; done
 # Before the deposit the exact gate must remain armed. After a successful
 # deposit, one-way consumption plus the exact deposit record is the only
 # accepted replacement state.
 deposit_id=$(jq -er .depositId "$snapshot")
 observe "$rpc1" "$tmp/completion-state-a.json"; observe "$rpc2" "$tmp/completion-state-b.json"; cmp -s "$tmp/completion-state-a.json" "$tmp/completion-state-b.json"
 state_block=$(jq -er .finalizedBlockNumber "$tmp/completion-state-a.json"); armed=$(jq -er .authorizedPilotDeposit "$tmp/completion-state-a.json"); armed_snapshot=$(jq -er .authorizedPilotSnapshot "$tmp/completion-state-a.json"); armed_until=$(jq -er .authorizedPilotValidUntil "$tmp/completion-state-a.json"); consumed=$(jq -er .pilotDepositConsumed "$tmp/completion-state-a.json"); current_generation=$(jq -er .pilotAuthorizationGeneration "$tmp/completion-state-a.json")
 if test "$consumed" = false; then
  test "$armed" = "$expected"; test "$armed_snapshot" = "$commitment"; test "$armed_until" = "$(jq -er .validUntil "$plan")"; test "$current_generation" = "$(jq -er .generation "$plan")"
 else
  test "$armed" = 0x0000000000000000000000000000000000000000000000000000000000000000; test "$armed_snapshot" = 0x0000000000000000000000000000000000000000000000000000000000000000; test "$armed_until" = 0; test "$current_generation" = "$(node scripts/canonical-uint256.mjs add1 "$(jq -er .generation "$plan")")"
  for rpc in "$rpc1" "$rpc2"; do mapfile -t deposit_fields < <(cast call "$reserve" 'deposits(bytes32)(address,uint64,bytes32)' "$deposit_id" --block "$state_block" --rpc-url "$rpc"); test "${#deposit_fields[@]}" = 3; test "${deposit_fields[0],,}" = "$(jq -er '.funder|ascii_downcase' "$snapshot")"; test "${deposit_fields[1]%% *}" = "$(jq -er .pilotDepositBaseUnits "$snapshot")"; test "${deposit_fields[2],,}" = "$(jq -er '.receivingCommitment|ascii_downcase' "$snapshot")"; done
 fi
 exit 0
fi
node scripts/check-pilot-funds-authorization-live.mjs >/dev/null
observe "$rpc1" "$tmp/a.json"; observe "$rpc2" "$tmp/b.json"
# Both providers must identify the same finalized snapshot, not merely similar state.
cmp -s "$tmp/a.json" "$tmp/b.json"
node scripts/prepare-pilot-deposit-gate-plan.mjs "$snapshot" "$state" "$tmp/release.json" "$USDOM_SAFE_PACKAGE" "$tmp/a.json" "$tmp/b.json" >"$tmp/plan.json"
if test -e "$plan"; then
 # A restart may observe a later finalized block. Preserve the create-once plan
 # while requiring every authorization field and the live Safe nonce to agree.
 test "$(jq -cS '{schema,chainId,snapshotCommitment,validUntil,generation,governanceSafe,reserve,authorizedOwners,safeTransaction,safeTxHash,expectedAuthorization}' "$tmp/plan.json")" = "$(jq -cS '{schema,chainId,snapshotCommitment,validUntil,generation,governanceSafe,reserve,authorizedOwners,safeTransaction,safeTxHash,expectedAuthorization}' "$plan")"
else node scripts/install-private-file-new-stdin.mjs --json "$plan" <"$tmp/plan.json"; fi
safe_hash=$(jq -er .safeTxHash "$plan")
safe_data=$(jq -er .safeTransaction.data "$plan"); safe_nonce=$(jq -er .safeTransaction.nonce "$plan")
snapshot_commitment=$(jq -er .snapshotCommitment "$plan"); funder=$(jq -er .funder "$snapshot"); amount=$(jq -er .pilotDepositBaseUnits "$snapshot"); salt=$(jq -er .salt "$snapshot"); receiving_commitment=$(jq -er .receivingCommitment "$snapshot")
safe_hash_call=$(node scripts/prepare-private-safe-hash-eth-call.mjs "$plan" "$(jq -er .finalizedBlockNumber "$plan")")
for rpc in "$rpc1" "$rpc2"; do
 observed_hash=$(printf '%s
' "$safe_hash_call" | cast rpc eth_call --raw --rpc-url "$rpc" | jq -er '.|ascii_downcase')
 test "$observed_hash" = "$safe_hash"
done
node scripts/prepare-pilot-gate-onekey-envelope.mjs "$plan" >"$tmp/safe-envelope.json"
chmod 0600 "$tmp/safe-envelope.json"
sign_owner() {
 local index=$1 destination=$2 signature_file=$3 identity approval expected_owner observed_owner physical request response status
 test ! -e "$destination" || return 0
 test ! -e "$signature_file" || pilot_broadcast_state=signed-unresolved
 identity="$USDOM_CONTROL_EVIDENCE_DIRECTORY/onekey-governance-owner-$index-identity.json"
 test -f "$identity" && test ! -L "$identity" && test "$(stat -c '%u:%a:%h' "$identity")" = "$UID:600:1"
 expected_owner=$(jq -er ".authorizedOwners[$((index-1))]" "$plan")
 observed_owner=$(jq -er '.expectedAddress' "$identity"); test "$observed_owner" = "$expected_owner"
 echo "AUTHORIZE REVIEW SAFE gate=authorizePilotDeposit chainId=1 safe=$safe safeNonce=$safe_nonce to=$reserve valueWei=0 snapshotCommitment=$snapshot_commitment funder=$funder amountBaseUnits=$amount salt=$salt receivingCommitment=$receiving_commitment validUntil=$(jq -er .validUntil "$plan") generation=$(jq -er .generation "$plan") calldataHash=$(printf '%s' "$safe_data" | cast keccak) safeTxHash=$safe_hash owner=$index/2" >&2
 echo "Conecte por Bluetooth a OneKey Classic 1S do owner $index de 2 ($expected_owner)." >&2
 read -r -p "Digite AUTORIZO GATE PILOTO OWNER $index HASH $safe_hash: " approval </dev/tty
 test "$approval" = "AUTORIZO GATE PILOTO OWNER $index HASH $safe_hash"
 node scripts/check-pilot-funds-authorization-live.mjs >/dev/null
 observe "$rpc1" "$tmp/owner-$index-pre-sign-a.json"; observe "$rpc2" "$tmp/owner-$index-pre-sign-b.json"
 cmp -s "$tmp/owner-$index-pre-sign-a.json" "$tmp/owner-$index-pre-sign-b.json"
 assert_plan_prestate "$tmp/owner-$index-pre-sign-a.json"
 if test ! -e "$signature_file"; then
  physical="$USDOM_CONTROL_EVIDENCE_DIRECTORY/onekey-governance-owner-$index-physical-account.json"
  request="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-owner-$index-walletconnect-request.json"
  response="$USDOM_CONTROL_EVIDENCE_DIRECTORY/pilot-deposit-gate-owner-$index-walletconnect-response.json"
  test -f "$physical" && test ! -L "$physical" && test "$(stat -c '%u:%a:%h' "$physical")" = "$UID:600:1"
  if test ! -e "$request"; then node scripts/prepare-onekey-ios-walletconnect-request.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$tmp/safe-envelope.json" "$physical" "$expected_owner" "$request"; fi
  node scripts/check-onekey-ios-walletconnect-request.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$tmp/safe-envelope.json" "$physical" "$expected_owner" "$request"
  if test ! -e "$response"; then if node scripts/sign-onekey-ios-walletconnect-typed-data.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$request" "$physical" "$response"; then :; else status=$?; pilot_broadcast_state=signed-unresolved; ((status==80)) && exit 80; exit "$status"; fi; fi
  pilot_broadcast_state=signed-unresolved
  node scripts/extract-onekey-ios-walletconnect-signature.mjs "$request" "$response" >"$tmp/owner-$index.hex"; chmod 0600 "$tmp/owner-$index.hex"
  node scripts/install-private-file-immutable-stdin.mjs "$signature_file" <"$tmp/owner-$index.hex"
 fi
 assert_evidence_parent
 if node scripts/materialize-pilot-gate-onekey-signature.mjs "$plan" "$identity" "$signature_file" "$index" "$destination"; then :; else
  materialize_status=$?; pilot_broadcast_state=signed-unresolved; exit "$materialize_status"
 fi
}
sign_owner 1 "$sig1" "$sighex1"; sign_owner 2 "$sig2" "$sighex2"; test "$(jq -r .signer "$sig1" | tr '[:upper:]' '[:lower:]')" != "$(jq -r .signer "$sig2" | tr '[:upper:]' '[:lower:]')"
node scripts/assemble-pilot-deposit-gate-transaction.mjs "$plan" "$snapshot" "$state" "$tmp/release.json" "$USDOM_SAFE_PACKAGE" "$sig1" "$sig2" >"$tmp/package.json"
assert_evidence_parent
if test -e "$package"; then cmp -s "$tmp/package.json" "$package"; else node scripts/install-private-file-new-stdin.mjs --json "$package" <"$tmp/package.json"; fi
to=$(jq -er .to "$package"); data=$(jq -er .data "$package")
if test ! -e "$relayer_envelope"; then
 test -f "$relayer_policy" && test ! -L "$relayer_policy" && test "$(stat -c '%u:%a:%h' "$relayer_policy")" = "$UID:600:1"
 node scripts/check-private-strict-json-file.mjs "$relayer_policy"
 relayer=$(jq -er .relayer "$relayer_policy")
 for forbidden in "$(jq -er .token "$tmp/release.json")" "$(jq -er .reserve "$tmp/release.json")" "$(jq -er .governance "$tmp/release.json")" "$(jq -er .guardian "$tmp/release.json")"; do test "${relayer,,}" != "${forbidden,,}"; done
 for owner in $(jq -er '.governanceOwners[],.guardianOwners[],.checkpointGuardianOwners[]' "$tmp/release.json"); do test "${relayer,,}" != "${owner,,}"; done
 nonce1=$(cast nonce "$relayer" --block pending --rpc-url "$rpc1"); nonce2=$(cast nonce "$relayer" --block pending --rpc-url "$rpc2"); test "$nonce1" = "$nonce2"
 test "$(cast code "$relayer" --block finalized --rpc-url "$rpc1")" = 0x; test "$(cast code "$relayer" --block finalized --rpc-url "$rpc2")" = 0x
 printf '{"to":"%s","data":"%s"}
' "$to" "$data" >"$tmp/private-transaction-input.json"; chmod 0600 "$tmp/private-transaction-input.json"
 private_estimate=$(node scripts/prepare-private-eth-estimate-gas.mjs "$tmp/private-transaction-input.json" "$relayer")
 gas1=$(printf '%s
' "$private_estimate" | cast rpc eth_estimateGas --raw --rpc-url "$rpc1" | jq -er . | xargs cast to-dec); gas2=$(printf '%s
' "$private_estimate" | cast rpc eth_estimateGas --raw --rpc-url "$rpc2" | jq -er . | xargs cast to-dec); test "$gas1" = "$gas2"
 base1=$(cast block finalized --field baseFeePerGas --rpc-url "$rpc1"); base2=$(cast block finalized --field baseFeePerGas --rpc-url "$rpc2"); test "$base1" = "$base2"; fee_plan=$(node scripts/calculate-pilot-transaction-fees.mjs "$gas1" "$base1" 500000 50000000000000000); gas=$(jq -er .gas <<<"$fee_plan"); max_fee=$(jq -er .maxFee <<<"$fee_plan")
 node scripts/prepare-pilot-gate-relayer-envelope.mjs "$tmp/private-transaction-input.json" "$package" "$relayer_policy" "$nonce1" "$gas" "$max_fee" 2000000000 >"$tmp/relayer-envelope.json"; chmod 0600 "$tmp/relayer-envelope.json"
 assert_evidence_parent; node scripts/install-private-file-new-stdin.mjs --json "$relayer_envelope" <"$tmp/relayer-envelope.json"
 echo "Envelope do relayer criado em $relayer_envelope. Assine-o pela fronteira separada do relayer e instale a raw privada em $raw; depois execute novamente." >&2
 exit 78
fi
if test ! -e "$raw"; then echo "raw privada do relayer ausente: $raw" >&2; exit 78; fi
node scripts/check-pilot-gate-relayer-raw.mjs "$raw" "$package" "$relayer_envelope" "$tmp/release.json" "$relayer_policy" >"$tmp/raw-validation.json"
txhash=$(jq -er .transactionHash "$tmp/raw-validation.json")
pilot_broadcast_state=signed-unresolved
if test ! -e "$receipt"; then
 if ! cast receipt "$txhash" --json --rpc-url "$rpc1" >"$tmp/r1.json" 2>/dev/null || ! cast receipt "$txhash" --json --rpc-url "$rpc2" >"$tmp/r2.json" 2>/dev/null; then
  echo "AUTHORIZE BROADCAST chainId=1 txHash=$txhash safeTxHash=$safe_hash to=$to dataHash=$(jq -er .dataHash "$package") snapshotCommitment=$snapshot_commitment" >&2
  read -r -p "Digite AUTORIZO TRANSMITIR GATE PILOTO TX $txhash: " approval </dev/tty; test "$approval" = "AUTORIZO TRANSMITIR GATE PILOTO TX $txhash"
  node scripts/check-pilot-funds-authorization-live.mjs >/dev/null; observe "$rpc1" "$tmp/pre-send-a.json"; observe "$rpc2" "$tmp/pre-send-b.json"; cmp -s "$tmp/pre-send-a.json" "$tmp/pre-send-b.json"; assert_plan_prestate "$tmp/pre-send-a.json"
  node scripts/check-pilot-gate-relayer-raw.mjs "$raw" "$package" "$relayer_envelope" "$tmp/release.json" "$relayer_policy" | cmp -s - "$tmp/raw-validation.json"
  assert_evidence_parent
  pilot_broadcast_state=publishing
  published=$(node scripts/publish-private-raw-transaction.mjs "$raw" "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" config/mainnet-preflight-rpc-catalog.json 0 | tr '[:upper:]' '[:lower:]'); test "$published" = "$txhash"
 fi
 receipt_deadline=$((SECONDS+1800)); until cast receipt "$txhash" --json --rpc-url "$rpc1" >"$tmp/r1.json" 2>/dev/null && cast receipt "$txhash" --json --rpc-url "$rpc2" >"$tmp/r2.json" 2>/dev/null; do test "$SECONDS" -lt "$receipt_deadline" || { echo 'receipt observation timed out; restart to recover without rebroadcast' >&2; exit 75; }; sleep 12; done
 jq -e '.status=="0x1"' "$tmp/r1.json" >/dev/null; test "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,to,logs}' "$tmp/r1.json")" = "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,to,logs}' "$tmp/r2.json")"
 execution_topic=$(cast keccak 'ExecutionSuccess(bytes32,uint256)' | tr '[:upper:]' '[:lower:]'); authorization_topic=$(cast keccak 'PilotDepositAuthorized(bytes32,bytes32,uint64,uint64)' | tr '[:upper:]' '[:lower:]'); authorization_data=$(cast abi-encode 'f(uint64,uint64)' "$(jq -er .validUntil "$plan")" "$(jq -er .generation "$plan")" | tr '[:upper:]' '[:lower:]')
 jq -e --arg safe "${safe,,}" --arg reserve "${reserve,,}" --arg execution "$execution_topic" --arg authorization "$authorization_topic" --arg authorizationData "$authorization_data" --arg safeHash "$safe_hash" --arg snapshotCommitment "$(jq -er .snapshotCommitment "$plan")" --arg expectedAuthorization "$(jq -er .expectedAuthorization "$plan")" '
  ([.logs[]|select((.address|ascii_downcase)==$safe and (.topics[0]|ascii_downcase)==$execution and (.topics[1]|ascii_downcase)==$safeHash)]|length)==1 and
  ([.logs[]|select((.address|ascii_downcase)==$reserve and (.topics[0]|ascii_downcase)==$authorization and (.topics[1]|ascii_downcase)==$snapshotCommitment and (.topics[2]|ascii_downcase)==$expectedAuthorization and (.data|ascii_downcase)==$authorizationData)]|length)==1' "$tmp/r1.json" >/dev/null
 assert_evidence_parent
 node scripts/install-private-file-new-stdin.mjs --json "$receipt" <"$tmp/r1.json"
fi
# Revalidate a persisted or newly created receipt and transaction identically.
for pair in "a:$rpc1" "b:$rpc2"; do label=${pair%%:*}; rpc=${pair#*:}; cast receipt "$txhash" --json --rpc-url "$rpc" >"$tmp/current-receipt-$label.json"; cast tx "$txhash" --json --rpc-url "$rpc" >"$tmp/current-tx-$label.json"; done
test "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs}' "$tmp/current-receipt-a.json")" = "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs}' "$tmp/current-receipt-b.json")"
test "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs}' "$tmp/current-receipt-a.json")" = "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs}' "$receipt")"
test "$(jq -cS '{hash,from,to,nonce,input,value,blockNumber,blockHash}' "$tmp/current-tx-a.json")" = "$(jq -cS '{hash,from,to,nonce,input,value,blockNumber,blockHash}' "$tmp/current-tx-b.json")"
jq -e --arg tx "$txhash" --arg payer "$(jq -er '.from|ascii_downcase' "$tmp/raw-validation.json")" --arg safe "${safe,,}" '.status=="0x1" and (.transactionHash|ascii_downcase)==$tx and (.from|ascii_downcase)==$payer and (.to|ascii_downcase)==$safe' "$receipt" >/dev/null
jq -e --arg tx "$txhash" --arg payer "$(jq -er '.from|ascii_downcase' "$tmp/raw-validation.json")" --arg safe "${safe,,}" --slurpfile package "$package" '(.hash|ascii_downcase)==$tx and (.from|ascii_downcase)==$payer and (.to|ascii_downcase)==$safe and (.input|ascii_downcase)==($package[0].data|ascii_downcase) and .value=="0x0"' "$tmp/current-tx-a.json" >/dev/null
test "$(node scripts/canonical-uint256.mjs normalize "$(jq -er .nonce "$tmp/current-tx-a.json")")" = "$(node scripts/canonical-uint256.mjs normalize "$(jq -er .nonce "$tmp/raw-validation.json")")"
execution_topic=$(cast keccak 'ExecutionSuccess(bytes32,uint256)' | tr '[:upper:]' '[:lower:]'); authorization_topic=$(cast keccak 'PilotDepositAuthorized(bytes32,bytes32,uint64,uint64)' | tr '[:upper:]' '[:lower:]'); authorization_data=$(cast abi-encode 'f(uint64,uint64)' "$(jq -er .validUntil "$plan")" "$(jq -er .generation "$plan")" | tr '[:upper:]' '[:lower:]')
jq -e --arg safe "${safe,,}" --arg reserve "${reserve,,}" --arg execution "$execution_topic" --arg authorization "$authorization_topic" --arg authorizationData "$authorization_data" --arg safeHash "$safe_hash" --arg commitment "$snapshot_commitment" --arg expected "$(jq -er .expectedAuthorization "$plan")" '([.logs[]|select((.address|ascii_downcase)==$safe and (.topics[0]|ascii_downcase)==$execution and (.topics[1]|ascii_downcase)==$safeHash)]|length)==1 and ([.logs[]|select((.address|ascii_downcase)==$reserve and (.topics[0]|ascii_downcase)==$authorization and (.topics[1]|ascii_downcase)==$commitment and (.topics[2]|ascii_downcase)==$expected and (.data|ascii_downcase)==$authorizationData)]|length)==1' "$receipt" >/dev/null
block=$(node scripts/canonical-uint256.mjs normalize "$(jq -er .blockNumber "$receipt")"); block_hash=$(jq -er '.blockHash|ascii_downcase' "$receipt")
transaction_index=$(node scripts/canonical-uint256.mjs normalize "$(jq -er .transactionIndex "$receipt")")
for rpc in "$rpc1" "$rpc2"; do test "$(cast block "$block" --field hash --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" = "$block_hash"; done
finality_deadline=$((SECONDS+14400)); while :; do
 f1=$(cast block finalized --field number --rpc-url "$rpc1"); f2=$(cast block finalized --field number --rpc-url "$rpc2")
 if test "$f1" = "$f2" && test "$(node scripts/canonical-uint256.mjs ge "$f1" "$block")" = true; then
  fh1=$(cast block "$f1" --field hash --rpc-url "$rpc1" | tr '[:upper:]' '[:lower:]'); fh2=$(cast block "$f2" --field hash --rpc-url "$rpc2" | tr '[:upper:]' '[:lower:]')
  test "$fh1" = "$fh2" && break
 fi
 test "$SECONDS" -lt "$finality_deadline" || { echo 'finality observation timed out; restart to recover without rebroadcast' >&2; exit 75; }; sleep 12
done
# The receipt may have been reorged while finality was advancing. Re-read the
# exact transaction and receipt from both sources at the final anchor before
# persisting completion evidence.
for pair in "a:$rpc1" "b:$rpc2"; do
 label=${pair%%:*}; rpc=${pair#*:}
 cast receipt "$txhash" --json --rpc-url "$rpc" >"$tmp/post-finality-receipt-$label.json"
 cast tx "$txhash" --json --rpc-url "$rpc" >"$tmp/post-finality-tx-$label.json"
 test "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs}' "$tmp/post-finality-receipt-$label.json")" = "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs}' "$receipt")"
 test "$(jq -cS '{hash,from,to,nonce,input,value,blockNumber,blockHash}' "$tmp/post-finality-tx-$label.json")" = "$(jq -cS '{hash,from,to,nonce,input,value,blockNumber,blockHash}' "$tmp/current-tx-a.json")"
 test "$(cast block "$block" --field hash --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" = "$block_hash"
done
expected=$(jq -er .expectedAuthorization "$plan"); commitment=$(jq -er .snapshotCommitment "$plan")
for rpc in "$rpc1" "$rpc2"; do test "$(cast call "$reserve" 'authorizedPilotDeposit()(bytes32)' --block "$f1" --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" = "$expected"; test "$(cast call "$reserve" 'authorizedPilotSnapshot()(bytes32)' --block "$f1" --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" = "$commitment"; test "$(cast call "$reserve" 'authorizedPilotValidUntil()(uint64)' --block "$f1" --rpc-url "$rpc")" = "$(jq -er .validUntil "$plan")"; test "$(cast call "$reserve" 'pilotAuthorizationGeneration()(uint64)' --block "$f1" --rpc-url "$rpc")" = "$(jq -er .generation "$plan")"; done
assert_evidence_parent
jq -n --arg tx "$txhash" --arg safeTxHash "$safe_hash" --arg blockNumber "$block" --arg blockHash "$block_hash" --arg transactionIndex "$transaction_index" --arg finalizedBlockNumber "$f1" --arg finalizedBlockHash "$fh1" --arg snapshotCommitment "$commitment" --arg expectedAuthorization "$expected" --arg generation "$(jq -er .generation "$plan")" '{schema:"usdom-pilot-deposit-gate-finalized/v2",transactionHash:$tx,safeTxHash:$safeTxHash,blockNumber:$blockNumber,blockHash:$blockHash,transactionIndex:$transactionIndex,finalizedBlockNumber:$finalizedBlockNumber,finalizedBlockHash:$finalizedBlockHash,snapshotCommitment:$snapshotCommitment,expectedAuthorization:$expectedAuthorization,generation:$generation}' | node scripts/install-private-file-new-stdin.mjs --json "$completion"
pilot_broadcast_state=clean
