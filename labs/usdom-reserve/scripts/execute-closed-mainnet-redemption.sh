#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077
if (($# != 0)) || [[ ! -t 0 || ! -t 1 ]]; then printf '%s\n' 'Interactive redemption executor accepts no arguments.' >&2; exit 64; fi
readonly project=/home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve
readonly evidence=/home/leonardov/usdom-mainnet-private/control-plane
readonly submission="$project/evidence/finalized-burn-submission/finalized-burn-submission.json"
readonly package="$evidence/closed-mainnet-redemption-package.json"
readonly payout_baseline="$evidence/closed-mainnet-redemption-payout-baseline.json"
: "${USDOM_SAFE_PACKAGE:?required}" "${USDOM_REDEMPTION_RELAYER_POLICY:?required}" "${USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG:?required}"
readonly mobile_root=${USDOM_PILOT_STATE_DIR:-/home/leonardov/.local/state/usdom-onekey-ios-pilot}
readonly rpc1=https://ethereum-rpc.publicnode.com
readonly rpc2=https://rpc.mevblocker.io
export PATH=/usr/lib/chatgpt/resources/cua_node/bin:/home/leonardov/.foundry/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stat_run() {
  local LC_ALL=C value
  value=$(timeout --foreground --signal=TERM --kill-after=5s 120s stat "$@" | head -c 257)
  (( ${#value} <= 256 ))
  printf '%s' "$value"
}
private_tmpdir() {
  local prefix=${1-} path
  [[ $prefix == usdom-closed-redemption ]]
  path=$(timeout --foreground --signal=TERM --kill-after=5s 120s \
    mktemp -d -p /dev/shm "$prefix.XXXXXXXX" | head -c 128)
  [[ $path =~ ^/dev/shm/usdom-closed-redemption\.[A-Za-z0-9]{8}$ ]]
  [[ -d $path && ! -L $path ]]
  test "$(stat_run -c '%u:%a' -- "$path")" = "$UID:700"
  printf '%s' "$path"
}
remove_private_tree() {
  local path=${1-} expected_identity=${2-}
  [[ $path =~ ^/dev/shm/usdom-closed-redemption\.[A-Za-z0-9]{8}$ ]]
  [[ -d $path && ! -L $path ]]
  [[ $expected_identity =~ ^[0-9]+:[0-9]+:[0-9]+:700$ ]]
  test "$(stat_run -c '%u:%d:%i:%a' -- "$path")" = "$expected_identity"
  timeout --foreground --signal=TERM --kill-after=5s 120s rm -rf -- "$path"
  [[ ! -e $path && ! -L $path ]]
}
remove_private_raw() {
  local path=${1-}
  [[ $path =~ ^/home/leonardov/usdom-mainnet-private/control-plane/closed-redemption-[0-1]-raw\.txt$ ]]
  if [[ ! -e $path && ! -L $path ]]; then return 0; fi
  [[ -f $path && ! -L $path ]]
  test "$(stat_run -c '%u:%a:%h' -- "$path")" = "$UID:600:1"
  timeout --foreground --signal=TERM --kill-after=5s 120s rm -f -- "$path"
  [[ ! -e $path && ! -L $path ]]
}
[[ -d $evidence && ! -L $evidence ]]
test "$(realpath -e "$evidence")" = "$evidence"
cd "$project"; exec 9<"$evidence"
test "$(realpath -e /proc/$$/fd/9)" = "$evidence"
test "$(stat_run -Lc '%u:%a' -- /proc/$$/fd/9)" = "$UID:700"
test "$(stat_run -c '%d:%i' -- "$evidence")" = "$(stat_run -Lc '%d:%i' -- /proc/$$/fd/9)"
flock -n 9 || exit 75
shopt -s nullglob
for abandoned in /dev/shm/usdom-closed-redemption.*; do
  [[ -d $abandoned && ! -L $abandoned && $(stat_run -c '%u:%a' "$abandoned") == "$UID:700" ]] || exit 1
  abandoned_identity=$(stat_run -c '%u:%d:%i:%a' -- "$abandoned")
  remove_private_tree "$abandoned" "$abandoned_identity"
done
shopt -u nullglob
is_canonical_rpc_uint() {
  (( ${#1} <= 78 )) && [[ ${1-} =~ ^(0|[1-9][0-9]*|0x0|0x[1-9a-f][0-9a-f]*)$ ]]
}
require_mainnet_chain_id() {
  local chain
  chain=$(timeout --foreground --signal=TERM --kill-after=5s 120s cast chain-id --rpc-url "$1" | head -c 80)
  is_canonical_rpc_uint "$chain" && test "$chain" = 1
}
read_nonce() {
  local value
  value=$(timeout --foreground --signal=TERM --kill-after=5s 120s \
    cast nonce "$1" --block "$2" --rpc-url "$3" | head -c 80)
  is_canonical_rpc_uint "$value"
  printf '%s' "$value"
}
rpc_uint_call() {
  local value
  value=$(timeout --foreground --signal=TERM --kill-after=5s 120s \
    cast call "$@" | head -c 80)
  is_canonical_rpc_uint "$value"
  printf '%s' "$value"
}
rpc_bool_call() {
  local value
  value=$(timeout --foreground --signal=TERM --kill-after=5s 120s \
    cast call "$@" | head -c 8)
  case $value in true|false) ;; *) return 1 ;; esac
  printf '%s' "$value"
}
rpc_address_call() {
  local value
  value=$(timeout --foreground --signal=TERM --kill-after=5s 120s \
    cast call "$@" | head -c 44)
  [[ $value =~ ^0x[0-9a-fA-F]{40}$ ]]
  printf '%s' "${value,,}"
}
rpc_bytes32_call() {
  local value
  value=$(timeout --foreground --signal=TERM --kill-after=5s 120s \
    cast call "$@" | head -c 68)
  [[ $value =~ ^0x[0-9a-fA-F]{64}$ ]]
  printf '%s' "${value,,}"
}
rpc_tuple_call() {
  local value
  value=$(timeout --foreground --signal=TERM --kill-after=5s 120s \
    cast call "$@" | head -c 1025)
  (( ${#value} <= 1024 ))
  printf '%s' "$value"
}
rpc_codehash() {
  local value
  value=$(timeout --foreground --signal=TERM --kill-after=5s 120s \
    cast codehash "$@" | head -c 68)
  [[ $value =~ ^0x[0-9a-fA-F]{64}$ ]]
  printf '%s' "${value,,}"
}
is_cast_uint_line() {
  [[ ${1-} =~ ^(0|[1-9][0-9]*)(\ \[[0-9.eE+-]+\])?$ ]]
}
sha256_file() {
  local path=$1 value before after
  [[ -f $path && ! -L $path ]]
  before=$(stat_run -c '%d:%i:%s:%Y:%Z:%u:%a:%h' -- "$path")
  value=$(timeout --foreground --signal=TERM --kill-after=5s 120s \
    sha256sum -- "$path" | head -c 66)
  after=$(stat_run -c '%d:%i:%s:%Y:%Z:%u:%a:%h' -- "$path")
  test "$before" = "$after"
  [[ $value =~ ^[0-9a-f]{64}\ \ $ ]]
  printf '%s' "${value:0:64}"
}
node_eval() {
  timeout --foreground --signal=TERM --kill-after=5s 120s \
    node -e "$@" | head -c 161
}
cmp_exact() {
  timeout --foreground --signal=TERM --kill-after=5s 120s cmp -s -- "$@"
}
jq_run() {
  local LC_ALL=C value
  value=$(timeout --foreground --signal=TERM --kill-after=5s 120s jq "$@" | head -c 1048577)
  (( ${#value} <= 1048576 ))
  printf '%s' "$value"
}
check_rpc_transaction_binding() {
  local rpc=$1 label=$2 validation_file=$3 receipt_file=$4 private_input=$5
  local tx_file="$temporary/transaction-$label.json" tx_nonce expected_nonce
  timeout --foreground --signal=TERM --kill-after=5s 120s \
    cast tx "$(jq_run -er '.transactionHash' "$validation_file")" --json --rpc-url "$rpc" | head -c 65537 >"$tx_file"
  test "$(stat_run -c '%s' "$tx_file")" -le 65536
  timeout --foreground --signal=TERM --kill-after=5s 120s node scripts/check-private-strict-json-file.mjs "$tx_file"
  jq_run -e --arg hash "$(jq_run -er '.transactionHash|ascii_downcase' "$validation_file")" \
    --arg from "$(jq_run -er '.from|ascii_downcase' "$validation_file")" \
    --arg to "$(jq_run -er '.to|ascii_downcase' "$validation_file")" --slurpfile input "$private_input" \
    --arg block "$(jq_run -er '.blockNumber' "$receipt_file")" \
    --arg blockHash "$(jq_run -er '.blockHash|ascii_downcase' "$receipt_file")" '
      (.hash|ascii_downcase)==$hash and (.from|ascii_downcase)==$from and (.to|ascii_downcase)==$to
      and (.input|ascii_downcase)==($input[0].data|ascii_downcase) and .value=="0x0"
      and .blockNumber==$block and (.blockHash|ascii_downcase)==$blockHash' "$tx_file" >/dev/null
  tx_nonce=$(jq_run -er '.nonce' "$tx_file"); expected_nonce=$(jq_run -er '.nonce' "$validation_file")
  node_eval 'if(BigInt(process.argv[1])!==BigInt(process.argv[2]))process.exit(1)' "$tx_nonce" "$expected_nonce" >/dev/null
}
check_pilot_budget() {
  local proposed=${1-} deposit_costs='' redemption_costs='' separator=''
  for budget_index in 0 1 2; do
    local budget_file="$evidence/closed-deposit-$budget_index-validation.json"
    if [[ -f $budget_file ]]; then deposit_costs+="$separator$(jq_run -er '.maximumCost' "$budget_file")"; separator=,; fi
  done
  separator=''
  for budget_index in 0 1; do
    local budget_file="$evidence/closed-redemption-$budget_index-validation.json"
    if [[ -f $budget_file ]]; then redemption_costs+="$separator$(jq_run -er '.maximumCost' "$budget_file")"; separator=,; fi
  done
  if [[ -n $proposed ]]; then redemption_costs+="$separator$proposed"; fi
  timeout --foreground --signal=TERM --kill-after=5s 120s \
    node scripts/check-closed-mainnet-pilot-budget.mjs "$deposit_costs" "$redemption_costs" >/dev/null
}
test -f "$submission" && test ! -L "$submission"
timeout --foreground --signal=TERM --kill-after=5s 120s \
  node scripts/check-mainnet-toolchain.mjs >/dev/null
temporary=$(private_tmpdir usdom-closed-redemption)
temporary_identity=$(stat_run -c '%u:%d:%i:%a' -- "$temporary")
pilot_broadcast_state=clean
cleanup() { local status=${1:-$?}; trap - EXIT HUP INT TERM; unset USDOM_CLOSED_MAINNET_REDEMPTION_RAW_FILE
  if [[ $pilot_broadcast_state != clean ]] && (( status != 0 )); then status=80; fi
  remove_private_tree "$temporary" "$temporary_identity" || { (( status != 0 )) || status=1; }
  exit "$status"
}
trap 'cleanup $?' EXIT; trap 'cleanup 129' HUP; trap 'cleanup 130' INT; trap 'cleanup 143' TERM
lookup_known_transaction() {
  local rpc=$1 expected=$2 label=$3 response="$temporary/known-transaction-$label.json"
  timeout --foreground --signal=TERM --kill-after=5s 120s \
    cast rpc eth_getTransactionByHash "$expected" --rpc-url "$rpc" | head -c 65537 >"$response"
  test "$(stat_run -c '%s' "$response")" -le 65536
  timeout --foreground --signal=TERM --kill-after=5s 120s node scripts/check-private-strict-json-file.mjs "$response"
  jq_run -er --arg expected "$expected" '
    if .==null then ""
    elif type=="object" and (.hash|type)=="string" and ((.hash|ascii_downcase)==($expected|ascii_downcase))
    then (.hash|ascii_downcase)
    else error("unexpected transaction lookup response") end
  ' "$response"
}
write_redemption_candidate() {
  local destination=$1
  shift
  timeout --foreground --signal=TERM --kill-after=5s 120s \
    node scripts/check-closed-mainnet-redemption.mjs "$@" | head -c 1048577 >"$destination"
  test "$(stat_run -c '%s' "$destination")" -le 1048576
  timeout --foreground --signal=TERM --kill-after=5s 120s node scripts/check-private-strict-json-file.mjs "$destination"
}
readiness="$temporary/readiness.json"; candidate="$temporary/candidate.json"
timeout --foreground --signal=TERM --kill-after=5s 300s \
  node scripts/check-mainnet-readiness.mjs real-funds | head -c 1048577 >"$readiness"
test "$(stat_run -c '%s' "$readiness")" -le 1048576
timeout --foreground --signal=TERM --kill-after=5s 120s node scripts/check-private-strict-json-file.mjs "$readiness"
jq_run -e '.ready==true and .blockerCount==0' "$readiness" >/dev/null
write_redemption_candidate "$candidate" "$submission"
if [[ -e $package ]]; then cmp_exact "$candidate" "$package"; else timeout --foreground --signal=TERM --kill-after=5s 120s node scripts/install-private-file-new-stdin.mjs --json "$package" <"$candidate"; fi
timeout --foreground --signal=TERM --kill-after=5s 120s \
  node scripts/check-closed-mainnet-redemption.mjs "$submission" "$package" >/dev/null
release_sha=$(sha256_file config/proof-reserve.unconfigured.json)
verifier_sha=$(sha256_file config/finalized-burn-verifier.unconfigured.json)
timeout --foreground --signal=TERM --kill-after=5s 120s \
  node scripts/check-closed-mainnet-redemption-release.mjs "$submission" "$package" config/proof-reserve.unconfigured.json "$release_sha" "$verifier_sha" >/dev/null
package_sha=$(sha256_file "$package"); reserve=$(jq_run -er '.reserve' "$package")
recipient=$(jq_run -er '.recipient' "$package"); burn_id=$(jq_run -er '.burnId' "$package")
request_id=$(jq_run -er '.requestId' "$package"); test "$(jq_run -er '.amountBaseUnits' "$package")" = 1000000
valid_until=$(jq_run -er '.burn.validUntil' "$submission")
zero32=0x$(printf '00%.0s' {1..32})
check_burn_unused() {
  local rpc=$1
  test "$(rpc_bool_call "$reserve" 'paidBurns(bytes32)(bool)' "$burn_id" --block "$consensus_block" --rpc-url "$rpc")" = false
  test "$(rpc_bool_call "$reserve" 'paidRequests(bytes32)(bool)' "$request_id" --block "$consensus_block" --rpc-url "$rpc")" = false
  test "$(rpc_bytes32_call "$reserve" 'provedBurnDebts(bytes32)(bytes32)' "$burn_id" --block "$consensus_block" --rpc-url "$rpc")" = "$zero32"
  test "$(rpc_bytes32_call "$reserve" 'provedRequestBurns(bytes32)(bytes32)' "$request_id" --block "$consensus_block" --rpc-url "$rpc")" = "$zero32"
}
check_permanent_burn_debt() {
  local rpc=$1 statement debt request_burn
  statement=$(rpc_bytes32_call "$reserve" 'provedBurnStatements(bytes32)(bytes32)' "$burn_id" --block "$consensus_block" --rpc-url "$rpc")
  debt=$(rpc_bytes32_call "$reserve" 'provedBurnDebts(bytes32)(bytes32)' "$burn_id" --block "$consensus_block" --rpc-url "$rpc")
  request_burn=$(rpc_bytes32_call "$reserve" 'provedRequestBurns(bytes32)(bytes32)' "$request_id" --block "$consensus_block" --rpc-url "$rpc")
  test "$statement" != "$zero32"; test "$debt" != "$zero32"; test "$request_burn" = "${burn_id,,}"
}
token=$(jq_run -er '.token' config/proof-reserve.unconfigured.json)
reserve_code_hash=$(jq_run -er '.reserveRuntimeCodeHash' config/proof-reserve.unconfigured.json)
token_code_hash=$(jq_run -er '.tokenCodeHash' config/proof-reserve.unconfigured.json)
reserve_config_hash=$(jq_run -er '.reserveConfigHash' config/proof-reserve.unconfigured.json)
readonly mainnet_genesis=0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3
consensus_block=''
consensus_hash=''
consensus_timestamp=''
consensus_base_fee=''
rpc_consensus_snapshot() {
  local chain1 chain2 genesis1 genesis2 number1 number2 hash1 hash2 time1 time2 base1 base2
  require_mainnet_chain_id "$rpc1"; require_mainnet_chain_id "$rpc2"
  genesis1=$(timeout --foreground --signal=TERM --kill-after=5s 120s cast block 0 --field hash --rpc-url "$rpc1" | tr '[:upper:]' '[:lower:]' | head -c 68)
  genesis2=$(timeout --foreground --signal=TERM --kill-after=5s 120s cast block 0 --field hash --rpc-url "$rpc2" | tr '[:upper:]' '[:lower:]' | head -c 68)
  [[ $genesis1 =~ ^0x[0-9a-f]{64}$ && $genesis2 =~ ^0x[0-9a-f]{64}$ ]] || return 1
  test "$genesis1" = "$mainnet_genesis"; test "$genesis2" = "$mainnet_genesis"
  number1=$(timeout --foreground --signal=TERM --kill-after=5s 120s cast block finalized --field number --rpc-url "$rpc1" | head -c 80)
  number2=$(timeout --foreground --signal=TERM --kill-after=5s 120s cast block finalized --field number --rpc-url "$rpc2" | head -c 80)
  is_canonical_rpc_uint "$number1"; is_canonical_rpc_uint "$number2"
  test "$number1" = "$number2"
  hash1=$(timeout --foreground --signal=TERM --kill-after=5s 120s cast block "$number1" --field hash --rpc-url "$rpc1" | tr '[:upper:]' '[:lower:]' | head -c 68)
  hash2=$(timeout --foreground --signal=TERM --kill-after=5s 120s cast block "$number2" --field hash --rpc-url "$rpc2" | tr '[:upper:]' '[:lower:]' | head -c 68)
  [[ $hash1 =~ ^0x[0-9a-f]{64}$ && $hash2 =~ ^0x[0-9a-f]{64}$ ]] || return 1
  test "$hash1" = "$hash2"
  time1=$(timeout --foreground --signal=TERM --kill-after=5s 120s cast block "$number1" --field timestamp --rpc-url "$rpc1" | head -c 80)
  time2=$(timeout --foreground --signal=TERM --kill-after=5s 120s cast block "$number2" --field timestamp --rpc-url "$rpc2" | head -c 80)
  base1=$(timeout --foreground --signal=TERM --kill-after=5s 120s cast block "$number1" --field baseFeePerGas --rpc-url "$rpc1" | head -c 80)
  base2=$(timeout --foreground --signal=TERM --kill-after=5s 120s cast block "$number2" --field baseFeePerGas --rpc-url "$rpc2" | head -c 80)
  is_canonical_rpc_uint "$time1"; is_canonical_rpc_uint "$time2"
  is_canonical_rpc_uint "$base1"; is_canonical_rpc_uint "$base2"
  test "$time1" = "$time2"; test "$base1" = "$base2"
  receipt_projection=''
  rpc_index=0
  for rpc in "$rpc1" "$rpc2"; do
    rpc_index=$((rpc_index+1))
    test "$(rpc_codehash "$reserve" --block "$number1" --rpc-url "$rpc")" = "${reserve_code_hash,,}"
    test "$(rpc_codehash "$token" --block "$number1" --rpc-url "$rpc")" = "${token_code_hash,,}"
    test "$(rpc_bytes32_call "$reserve" 'reserveConfigHash()(bytes32)' --block "$number1" --rpc-url "$rpc")" = "${reserve_config_hash,,}"
    # Refuse to sign a transaction that the pinned USDT policy would reject or
    # tax. The reserve enforces the same predicates on-chain; repeating them at
    # the finalized dual-RPC boundary avoids paying gas for a known failure and
    # closes policy drift between package preparation and each signature.
    test "$(rpc_bool_call "$token" 'paused()(bool)' --block "$number1" --rpc-url "$rpc")" = false
    test "$(rpc_bool_call "$token" 'deprecated()(bool)' --block "$number1" --rpc-url "$rpc")" = false
    test "$(rpc_address_call "$token" 'upgradedAddress()(address)' --block "$number1" --rpc-url "$rpc")" = 0x0000000000000000000000000000000000000000
    test "$(rpc_uint_call "$token" 'basisPointsRate()(uint256)' --block "$number1" --rpc-url "$rpc")" = 0
    test "$(rpc_uint_call "$token" 'maximumFee()(uint256)' --block "$number1" --rpc-url "$rpc")" = 0
    test "$(rpc_bool_call "$token" 'isBlackListed(address)(bool)' "$reserve" --block "$number1" --rpc-url "$rpc")" = false
    test "$(rpc_bool_call "$token" 'isBlackListed(address)(bool)' "$recipient" --block "$number1" --rpc-url "$rpc")" = false
  done
  # Re-read the exact numeric block after code/state queries to close the TOCTOU window.
  test "$(timeout --foreground --signal=TERM --kill-after=5s 120s cast block "$number1" --field hash --rpc-url "$rpc1" | tr '[:upper:]' '[:lower:]' | head -c 68)" = "$hash1"
  test "$(timeout --foreground --signal=TERM --kill-after=5s 120s cast block "$number1" --field hash --rpc-url "$rpc2" | tr '[:upper:]' '[:lower:]' | head -c 68)" = "$hash1"
  consensus_block=$number1; consensus_hash=$hash1; consensus_timestamp=$time1; consensus_base_fee=$base1
}
relayer_policy=$(realpath -e "$USDOM_REDEMPTION_RELAYER_POLICY")
signer=$(node scripts/check-redemption-relayer-policy.mjs "$relayer_policy" "$USDOM_SAFE_PACKAGE" config/proof-reserve.unconfigured.json "$recipient")
rpc_consensus_snapshot
base_nonce=''
for index in 0 1; do
  rpc_consensus_snapshot
  name=$(jq_run -er ".transactions[$index].name" "$package")
  private_input="$temporary/redemption-$index-private-transaction-input.json"
  timeout --foreground --signal=TERM --kill-after=5s 120s node scripts/prepare-closed-mainnet-private-transaction-input.mjs "$package" "$index" >"$private_input"
  inner_input="$temporary/redemption-$index-inner-transaction-input.json"; cp "$private_input" "$inner_input"; chmod 0600 "$inner_input"
  inner_selector=$(jq_run -er '.data[0:10]' "$inner_input")
  governance_safe=$(jq_run -er '.controls[]|select(.role=="governance")|.safe' "$USDOM_SAFE_PACKAGE")
  safe_nonce1=$(rpc_uint_call "$governance_safe" 'nonce()(uint256)' --block "$consensus_block" --rpc-url "$rpc1"); safe_nonce2=$(rpc_uint_call "$governance_safe" 'nonce()(uint256)' --block "$consensus_block" --rpc-url "$rpc2"); test "$safe_nonce1" = "$safe_nonce2"
  safe_plan="$evidence/closed-redemption-$index-safe-operation.json"
  if [[ ! -e $safe_plan ]]; then node scripts/prepare-safe-redemption-operation.mjs plan "$package" "$index" "$USDOM_SAFE_PACKAGE" "$safe_nonce1" | node scripts/install-private-file-new-stdin.mjs --json "$safe_plan"; fi
  test "$(jq_run -er '.typedData.message.nonce' "$safe_plan")" = "$safe_nonce1"
  typed_data="$temporary/redemption-$index-typed-data.json"; jq_run -c '.typedData' "$safe_plan" >"$typed_data"; chmod 0600 "$typed_data"
  for owner_index in 0 1; do
    owner=$(jq_run -er ".owners[$owner_index]" "$safe_plan"); signing_envelope="$evidence/closed-redemption-$index-owner-$owner_index-envelope.json"; request="$evidence/closed-redemption-$index-owner-$owner_index-request.json"; response="$evidence/closed-redemption-$index-owner-$owner_index-response.json"
    if [[ ! -e $signing_envelope ]]; then jq_run -n --slurpfile plan "$safe_plan" '{schema:"usdom-onekey-eip712-signing/v1",digest:$plan[0].digest,typedData:$plan[0].typedData}' | node scripts/install-private-file-new-stdin.mjs --json "$signing_envelope"; fi
    physical=''; for candidate_owner in "$mobile_root"/owner-*-evidence.json; do [[ -f $candidate_owner ]] && [[ $(jq_run -er '.address|ascii_downcase' "$candidate_owner") == ${owner,,} ]] && physical=$candidate_owner; done; [[ -n $physical ]]
    if [[ ! -e $request ]]; then node scripts/prepare-onekey-ios-walletconnect-request.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$signing_envelope" "$physical" "$owner" "$request"; fi
    if [[ ! -e $response ]]; then
      # Close the authorization-to-sign TOCTOU window: the Safe nonce and the
      # complete typed-data plan must still be identical at the finalized
      # dual-RPC boundary immediately before the mobile signing request.
      rpc_consensus_snapshot
      live_safe_nonce1=$(rpc_uint_call "$governance_safe" 'nonce()(uint256)' --block "$consensus_block" --rpc-url "$rpc1")
      live_safe_nonce2=$(rpc_uint_call "$governance_safe" 'nonce()(uint256)' --block "$consensus_block" --rpc-url "$rpc2")
      test "$live_safe_nonce1" = "$safe_nonce1"; test "$live_safe_nonce2" = "$safe_nonce1"
      live_safe_plan="$temporary/redemption-$index-owner-$owner_index-live-safe-operation.json"
      node scripts/prepare-safe-redemption-operation.mjs plan "$package" "$index" "$USDOM_SAFE_PACKAGE" "$safe_nonce1" >"$live_safe_plan"
      cmp_exact "$live_safe_plan" "$safe_plan"
      timeout --foreground --signal=TERM --kill-after=10s 330s node scripts/sign-onekey-ios-walletconnect-typed-data.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$request" "$physical" "$response" || { status=$?; ((status==80))&&exit 80; exit "$status"; }
    fi
    owner_signature=$(node scripts/read-onekey-ios-walletconnect-signature.mjs "$request" "$response" "$owner" "$typed_data")
    signature_file="$temporary/redemption-$index-owner-$owner_index-signature.json"; jq_run -n --arg signer "$owner" --arg signature "$owner_signature" '{signer:$signer,signature:$signature}' >"$signature_file"; chmod 0600 "$signature_file"
  done
  node scripts/prepare-safe-redemption-operation.mjs input "$safe_plan" "$temporary/redemption-$index-owner-0-signature.json" "$temporary/redemption-$index-owner-1-signature.json" >"$private_input"
  to=$(jq_run -er '.to' "$private_input"); raw_file="$evidence/closed-redemption-$index-raw.txt"
  validation="$evidence/closed-redemption-$index-validation.json"; receipt_record="$evidence/closed-redemption-$index-receipt.json"
  finality_record="$evidence/closed-redemption-$index-finality.json"
  if [[ -z $base_nonce ]]; then
    if [[ -f $validation ]]; then
      base_nonce=$(jq_run -er '.nonce' "$validation")
    else
      n1=$(read_nonce "$signer" pending "$rpc1")
      n2=$(read_nonce "$signer" pending "$rpc2")
      test "$n1" = "$n2"
      base_nonce=$n1
    fi
  fi
  nonce=$(node_eval 'process.stdout.write(String(BigInt(process.argv[1])+BigInt(process.argv[2])))' "$base_nonce" "$index")
  if [[ -e $raw_file && ! -e $validation ]]; then
    node scripts/check-safe-redemption-relayer-raw.mjs "$raw_file" "$evidence/closed-redemption-$index-relayer-input.json" "$evidence/closed-redemption-$index-relayer-envelope.json" "$relayer_policy" "$safe_plan" "$package" "$index" >"$candidate"
    timeout --foreground --signal=TERM --kill-after=5s 120s node scripts/install-private-file-new-stdin.mjs --json "$validation" <"$candidate"
  fi
  if [[ -f $receipt_record ]]; then
    test -f "$validation" && test ! -L "$validation" && test "$(stat_run -c '%a:%h' "$validation")" = '600:1'
    test "$(jq_run -er '.nonce' "$validation")" = "$nonce"
    if [[ -e $raw_file ]]; then
      node scripts/check-safe-redemption-relayer-raw.mjs "$raw_file" "$evidence/closed-redemption-$index-relayer-input.json" "$evidence/closed-redemption-$index-relayer-envelope.json" "$relayer_policy" "$safe_plan" "$package" "$index" | cmp_exact - "$validation"
    fi
  else
    if [[ ! -e $raw_file ]] && ((index==1)); then
      pending1=$(rpc_tuple_call "$reserve" 'pendingWithdrawals(bytes32)(bytes32,bytes32,uint64,uint64,uint64,uint64,bytes32,bytes32)' "$burn_id" --block "$consensus_block" --rpc-url "$rpc1")
      pending2=$(rpc_tuple_call "$reserve" 'pendingWithdrawals(bytes32)(bytes32,bytes32,uint64,uint64,uint64,uint64,bytes32,bytes32)' "$burn_id" --block "$consensus_block" --rpc-url "$rpc2")
      test "$pending1" = "$pending2"
      mapfile -t pending_fields <<<"$pending1"
      ((${#pending_fields[@]} == 8))
      for field_index in 0 1 6 7; do [[ ${pending_fields[field_index]} =~ ^0x[0-9a-fA-F]{64}$ ]]; done
      for field_index in 2 3 4 5; do is_cast_uint_line "${pending_fields[field_index]}"; done
      ready_at=${pending_fields[2]%% *}
      now1=$consensus_timestamp; now2=$consensus_timestamp
      node_eval 'if(BigInt(process.argv[1])<BigInt(process.argv[3])||BigInt(process.argv[2])<BigInt(process.argv[3]))process.exit(75)' "$now1" "$now2" "$ready_at"
    fi
    if ((index==1)); then
      for rpc in "$rpc1" "$rpc2"; do
        check_permanent_burn_debt "$rpc"
        test "$(rpc_bool_call "$reserve" 'paidBurns(bytes32)(bool)' "$burn_id" --block "$consensus_block" --rpc-url "$rpc")" = false
        test "$(rpc_bool_call "$reserve" 'paidRequests(bytes32)(bool)' "$request_id" --block "$consensus_block" --rpc-url "$rpc")" = false
      done
      token1=$(rpc_address_call "$reserve" 'token()(address)' --block "$consensus_block" --rpc-url "$rpc1"); token2=$(rpc_address_call "$reserve" 'token()(address)' --block "$consensus_block" --rpc-url "$rpc2")
      test "$token1" = "${token,,}"; test "$token2" = "${token,,}"
      if [[ -e $payout_baseline ]]; then
        test "$(stat_run -c '%a:%h' "$payout_baseline")" = '600:1'
        jq_run -e --arg packageSha256 "$package_sha" --arg token "$token" --arg reserve "$reserve" --arg recipient "$recipient" '.schema=="usdom-closed-mainnet-redemption-payout-baseline-v1" and .chainId=="1" and .packageSha256==$packageSha256 and (.token|ascii_downcase)==($token|ascii_downcase) and (.reserve|ascii_downcase)==($reserve|ascii_downcase) and (.recipient|ascii_downcase)==($recipient|ascii_downcase) and ([.recipientBalanceBaseUnits,.reserveBalanceBaseUnits,.totalReleasedBaseUnits,.outstandingBaseUnits,.totalProvedDebtBaseUnits,.snapshotBlockNumber]|all(test("^(0|[1-9][0-9]*)$"))) and .totalProvedDebtBaseUnits=="1000000" and (.snapshotBlockHash|test("^0x[0-9a-fA-F]{64}$"))' "$payout_baseline" >/dev/null
        baseline_block=$(jq_run -er '.snapshotBlockNumber' "$payout_baseline"); baseline_hash=$(jq_run -er '.snapshotBlockHash|ascii_downcase' "$payout_baseline")
        for rpc in "$rpc1" "$rpc2"; do
          test "$(timeout --foreground --signal=TERM --kill-after=5s 120s cast block "$baseline_block" --field hash --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]' | head -c 68)" = "$baseline_hash"
          test "$(rpc_uint_call "$token" 'balanceOf(address)(uint256)' "$recipient" --block "$baseline_block" --rpc-url "$rpc")" = "$(jq_run -er '.recipientBalanceBaseUnits' "$payout_baseline")"
          test "$(rpc_uint_call "$token" 'balanceOf(address)(uint256)' "$reserve" --block "$baseline_block" --rpc-url "$rpc")" = "$(jq_run -er '.reserveBalanceBaseUnits' "$payout_baseline")"
          test "$(rpc_uint_call "$reserve" 'totalReleased()(uint256)' --block "$baseline_block" --rpc-url "$rpc")" = "$(jq_run -er '.totalReleasedBaseUnits' "$payout_baseline")"
          test "$(rpc_uint_call "$reserve" 'outstanding()(uint256)' --block "$baseline_block" --rpc-url "$rpc")" = "$(jq_run -er '.outstandingBaseUnits' "$payout_baseline")"
          test "$(rpc_uint_call "$reserve" 'totalProvedDebtAmount()(uint256)' --block "$baseline_block" --rpc-url "$rpc")" = 1000000
        done
      else
        balance1=$(rpc_uint_call "$token" 'balanceOf(address)(uint256)' "$recipient" --block "$consensus_block" --rpc-url "$rpc1"); balance2=$(rpc_uint_call "$token" 'balanceOf(address)(uint256)' "$recipient" --block "$consensus_block" --rpc-url "$rpc2")
        reserve1=$(rpc_uint_call "$token" 'balanceOf(address)(uint256)' "$reserve" --block "$consensus_block" --rpc-url "$rpc1"); reserve2=$(rpc_uint_call "$token" 'balanceOf(address)(uint256)' "$reserve" --block "$consensus_block" --rpc-url "$rpc2")
        released1=$(rpc_uint_call "$reserve" 'totalReleased()(uint256)' --block "$consensus_block" --rpc-url "$rpc1"); released2=$(rpc_uint_call "$reserve" 'totalReleased()(uint256)' --block "$consensus_block" --rpc-url "$rpc2")
        outstanding1=$(rpc_uint_call "$reserve" 'outstanding()(uint256)' --block "$consensus_block" --rpc-url "$rpc1"); outstanding2=$(rpc_uint_call "$reserve" 'outstanding()(uint256)' --block "$consensus_block" --rpc-url "$rpc2")
        debt1=$(rpc_uint_call "$reserve" 'totalProvedDebtAmount()(uint256)' --block "$consensus_block" --rpc-url "$rpc1"); debt2=$(rpc_uint_call "$reserve" 'totalProvedDebtAmount()(uint256)' --block "$consensus_block" --rpc-url "$rpc2")
        test "$balance1" = "$balance2"; test "$reserve1" = "$reserve2"; test "$released1" = "$released2"; test "$outstanding1" = "$outstanding2"; test "$debt1" = "$debt2"; test "$debt1" = 1000000
        jq_run -n --arg packageSha256 "$package_sha" --arg token "$token" --arg reserve "$reserve" --arg recipient "$recipient" --arg balance "$balance1" --arg reserveBalance "$reserve1" --arg totalReleased "$released1" --arg outstanding "$outstanding1" --arg totalProvedDebt "$debt1" --arg snapshotBlockNumber "$consensus_block" --arg snapshotBlockHash "$consensus_hash" '{schema:"usdom-closed-mainnet-redemption-payout-baseline-v1",chainId:"1",packageSha256:$packageSha256,token:$token,reserve:$reserve,recipient:$recipient,recipientBalanceBaseUnits:$balance,reserveBalanceBaseUnits:$reserveBalance,totalReleasedBaseUnits:$totalReleased,outstandingBaseUnits:$outstanding,totalProvedDebtBaseUnits:$totalProvedDebt,observedAt:"finalized",rpcCount:2,snapshotBlockNumber:$snapshotBlockNumber,snapshotBlockHash:$snapshotBlockHash}' | timeout --foreground --signal=TERM --kill-after=5s 120s node scripts/install-private-file-new-stdin.mjs --json "$payout_baseline"
      fi
    fi
    if [[ ! -e $raw_file ]]; then
     for rpc in "$rpc1" "$rpc2"; do test "$(read_nonce "$signer" pending "$rpc")" = "$nonce"; done
    private_estimate=$(node scripts/prepare-private-eth-estimate-gas.mjs "$private_input" "$signer")
    estimate1=$(printf '%s\n' "$private_estimate" | cast rpc eth_estimateGas --raw --rpc-url "$rpc1" | jq_run -r . | xargs cast to-dec)
    estimate2=$(printf '%s\n' "$private_estimate" | cast rpc eth_estimateGas --raw --rpc-url "$rpc2" | jq_run -r . | xargs cast to-dec)
    is_canonical_rpc_uint "$estimate1"; is_canonical_rpc_uint "$estimate2"
    gas=$(node_eval 'let a=BigInt(process.argv[1]),b=BigInt(process.argv[2]),m=a>b?a:b,g=(m*125n+99n)/100n;if(g>2500000n)process.exit(1);process.stdout.write(String(g))' "$estimate1" "$estimate2")
    base1=$consensus_base_fee; base2=$consensus_base_fee
    test "$base1" = "$base2"
    fee=$(node_eval 'let a=BigInt(process.argv[1]),b=BigInt(process.argv[2]),g=BigInt(process.argv[3]),f=a>b?a:b;for(let i=0;i<12;i++)f=(f*9n+7n)/8n;f+=2000000000n;if(f>100000000000n||f*g>100000000000000000n)process.exit(1);process.stdout.write(String(f))' "$base1" "$base2" "$gas")
      proposed_cost=$(node_eval 'process.stdout.write(String(BigInt(process.argv[1])*BigInt(process.argv[2])))' "$gas" "$fee")
      check_pilot_budget "$proposed_cost"
      gas_balance1=$(timeout --foreground --signal=TERM --kill-after=5s 120s \
        cast balance "$signer" --block pending --rpc-url "$rpc1" | head -c 80)
      gas_balance2=$(timeout --foreground --signal=TERM --kill-after=5s 120s \
        cast balance "$signer" --block pending --rpc-url "$rpc2" | head -c 80)
      is_canonical_rpc_uint "$gas_balance1"; is_canonical_rpc_uint "$gas_balance2"
      timeout --foreground --signal=TERM --kill-after=5s 120s \
        node scripts/check-pilot-gas-funding.mjs "$gas_balance1" "$gas_balance2" "$(node_eval 'process.stdout.write(String(BigInt(process.argv[1])*BigInt(process.argv[2])))' "$gas" "$fee")" >/dev/null
      data_hash=$(jq_run -er ".transactions[$index].dataKeccak256" "$package")
      authorization_preimage="usdom-closed-redemption-sign-v2|action=$name|stage=$index|chainId=1|signer=$signer|target=$to|nonce=$nonce|tokenAmountBaseUnits=1000000|valueWei=0|dataHash=$data_hash|evidencePackageSha256=$package_sha|releaseConfigSha256=$release_sha|verifierManifestSha256=$verifier_sha|validUntil=$valid_until|gasLimit=$gas|maxFeePerGas=$fee|maxPriorityFeePerGas=2000000000|maximumGasCostWei=$proposed_cost"
      authorization_hash=$(timeout --foreground --signal=TERM --kill-after=5s 120s cast keccak "$authorization_preimage" | head -c 68)
      [[ $authorization_hash =~ ^0x[0-9a-f]{64}$ ]]
      printf 'AUTHORIZE REVIEW action=%s chainId=1 signer=%s target=%s nonce=%s selector=%s tokenAmountBaseUnits=1000000 valueWei=0 dataHash=%s evidencePackageSha256=%s releaseConfigSha256=%s verifierManifestSha256=%s gasLimit=%s maxFeePerGas=%s priorityFeePerGas=2000000000 maximumGasCostWei=%s validUntil=%s authorizationHash=%s\n' \
        "$name" "$signer" "$to" "$nonce" "$inner_selector" "$data_hash" "$package_sha" "$release_sha" "$verifier_sha" "$gas" "$fee" "$proposed_cost" "$valid_until" "$authorization_hash"
      read -r -p "Digite AUTORIZO ASSINAR RESGATE ETAPA $index AUTH $authorization_hash: " answer; test "$answer" = "AUTORIZO ASSINAR RESGATE ETAPA $index AUTH $authorization_hash"
      rpc_consensus_snapshot
      for rpc in "$rpc1" "$rpc2"; do
        require_mainnet_chain_id "$rpc"
        test "$(read_nonce "$signer" "$consensus_block" "$rpc")" = "$nonce"
        test "$(read_nonce "$signer" pending "$rpc")" = "$nonce"
      done
      live_base1=$consensus_base_fee
      live_time1=$consensus_timestamp; live_time2=$consensus_timestamp
      node_eval 'let f=BigInt(process.argv[1]);for(let i=0;i<12;i++)f=(f*9n+7n)/8n;f+=2000000000n;if(BigInt(process.argv[2])<f||BigInt(process.argv[3])+204n>BigInt(process.argv[5])||BigInt(process.argv[4])+204n>BigInt(process.argv[5]))process.exit(1)' "$live_base1" "$fee" "$live_time1" "$live_time2" "$valid_until"
      rpc_consensus_snapshot
      for rpc in "$rpc1" "$rpc2"; do
        test "$(read_nonce "$signer" "$consensus_block" "$rpc")" = "$nonce"
        test "$(read_nonce "$signer" pending "$rpc")" = "$nonce"
      done
      node_eval 'if(BigInt(process.argv[1])+204n>BigInt(process.argv[2]))process.exit(1)' "$consensus_timestamp" "$valid_until"
      relayer_input="$evidence/closed-redemption-$index-relayer-input.json"; relayer_envelope="$evidence/closed-redemption-$index-relayer-envelope.json"
      if [[ ! -e $relayer_input ]]; then node scripts/install-private-file-new-stdin.mjs --json "$relayer_input" <"$private_input"; fi
      if [[ ! -e $relayer_envelope ]]; then jq_run -cn --arg relayer "$signer" --arg to "$to" --arg dataHash "$(node_eval 'const fs=require("fs"),{keccak256}=require("ethers"),v=JSON.parse(fs.readFileSync(process.argv[1]));process.stdout.write(keccak256(v.data))' "$private_input")" --arg nonce "$nonce" --arg gasLimit "$gas" --arg maxFeePerGas "$fee" '{schema:"usdom-safe-redemption-gas-relayer-envelope/v1",chainId:"1",relayer:$relayer,to:$to,value:"0",dataHash:$dataHash,nonce:$nonce,gasLimit:$gasLimit,maxFeePerGas:$maxFeePerGas,maxPriorityFeePerGas:"2000000000"}' | node scripts/install-private-file-new-stdin.mjs --json "$relayer_envelope"; fi
      printf 'Autorizacao Safe EIP-712 concluida. Use sign-operational-gas-relayer.sh redemption:%s para instalar %s; nenhuma transmissao foi executada.\n' "$index" "$raw_file" >&2
      exit 78
    fi
    relayer_input="$evidence/closed-redemption-$index-relayer-input.json"; relayer_envelope="$evidence/closed-redemption-$index-relayer-envelope.json"
    node scripts/check-safe-redemption-relayer-raw.mjs "$raw_file" "$relayer_input" "$relayer_envelope" "$relayer_policy" "$safe_plan" "$package" "$index" >"$candidate"
    if [[ ! -e $validation ]]; then node scripts/install-private-file-new-stdin.mjs --json "$validation" <"$candidate"; else cmp_exact "$candidate" "$validation"; fi
    pilot_broadcast_state=signed-unresolved
    test -f "$validation" && test ! -L "$validation"
    test "$(stat_run -c '%u:%a:%h' -- "$validation")" = "$UID:600:1"
    node scripts/check-safe-redemption-relayer-raw.mjs "$raw_file" "$evidence/closed-redemption-$index-relayer-input.json" "$evidence/closed-redemption-$index-relayer-envelope.json" "$relayer_policy" "$safe_plan" "$package" "$index" | cmp_exact - "$validation"
    test "$(sha256_file "$package")" = "$package_sha"
    expected_hash=$(jq_run -er '.transactionHash|ascii_downcase' "$validation")
    pilot_broadcast_state=signed-unresolved
    finalized1=$(read_nonce "$signer" "$consensus_block" "$rpc1")
    finalized2=$(read_nonce "$signer" "$consensus_block" "$rpc2")
    current1=$(read_nonce "$signer" pending "$rpc1")
    current2=$(read_nonce "$signer" pending "$rpc2")
    known1=$(lookup_known_transaction "$rpc1" "$expected_hash" "$index-1")
    known2=$(lookup_known_transaction "$rpc2" "$expected_hash" "$index-2")
    nonce_action=$(timeout --foreground --signal=TERM --kill-after=5s 120s \
      node scripts/check-pilot-nonce-recovery.mjs "$nonce" "$finalized1" "$current1" "$finalized2" "$current2" "$expected_hash" "$known1" "$known2" | head -c 33)
    test "${#nonce_action}" -le 32
    case $nonce_action in publish|recover-receipt) ;; *) exit 1 ;; esac
    if test "$nonce_action" = publish; then
      if ((index==0)); then for rpc in "$rpc1" "$rpc2"; do check_burn_unused "$rpc"; done; fi
      maximum_cost=$(jq_run -er '.maximumCost' "$validation")
      gas_balance1=$(timeout --foreground --signal=TERM --kill-after=5s 120s \
        cast balance "$signer" --block pending --rpc-url "$rpc1" | head -c 80)
      gas_balance2=$(timeout --foreground --signal=TERM --kill-after=5s 120s \
        cast balance "$signer" --block pending --rpc-url "$rpc2" | head -c 80)
      is_canonical_rpc_uint "$gas_balance1"; is_canonical_rpc_uint "$gas_balance2"
      timeout --foreground --signal=TERM --kill-after=5s 120s \
        node scripts/check-pilot-gas-funding.mjs "$gas_balance1" "$gas_balance2" "$maximum_cost" >/dev/null
      check_pilot_budget
      rpc_consensus_snapshot
      for rpc in "$rpc1" "$rpc2"; do
        require_mainnet_chain_id "$rpc"
        test "$(read_nonce "$signer" "$consensus_block" "$rpc")" = "$nonce"
        test "$(read_nonce "$signer" pending "$rpc")" = "$nonce"
      done
      signed_fee=$(jq_run -er '.maxFeePerGas' "$validation")
      live_base1=$consensus_base_fee
      live_time1=$consensus_timestamp; live_time2=$consensus_timestamp
      node_eval 'let f=BigInt(process.argv[1]);for(let i=0;i<12;i++)f=(f*9n+7n)/8n;f+=2000000000n;if(BigInt(process.argv[2])<f||BigInt(process.argv[3])+204n>BigInt(process.argv[5])||BigInt(process.argv[4])+204n>BigInt(process.argv[5]))process.exit(1)' "$live_base1" "$signed_fee" "$live_time1" "$live_time2" "$valid_until"
      read -r -p "Digite AUTORIZO TRANSMITIR RESGATE ETAPA $index TX $expected_hash: " answer; test "$answer" = "AUTORIZO TRANSMITIR RESGATE ETAPA $index TX $expected_hash"
      rpc_consensus_snapshot
      for rpc in "$rpc1" "$rpc2"; do
        require_mainnet_chain_id "$rpc"
        test "$(read_nonce "$signer" "$consensus_block" "$rpc")" = "$nonce"
        test "$(read_nonce "$signer" pending "$rpc")" = "$nonce"
      done
      broadcast_journal="$evidence/closed-redemption-$index-broadcast-journal.json"
      if [[ ! -e $broadcast_journal ]]; then
        jq_run -cn --arg tx "$expected_hash" --arg safeTxHash "$(jq_run -er '.safeTxHash' "$validation")" --arg rawSha256 "$(sha256_file "$raw_file")" --arg packageSha256 "$package_sha" --arg nonce "$nonce" --arg relayer "$signer" --arg to "$to" '{schema:"usdom-closed-mainnet-redemption-broadcast-journal-v1",state:"signed-unresolved",chainId:"1",transactionHash:$tx,safeTxHash:$safeTxHash,rawSha256:$rawSha256,packageSha256:$packageSha256,nonce:$nonce,relayer:$relayer,to:$to}' | node scripts/install-private-file-new-stdin.mjs --json "$broadcast_journal"
      fi
      test -f "$broadcast_journal" && test ! -L "$broadcast_journal"
      test "$(stat_run -c '%u:%a:%h' -- "$broadcast_journal")" = "$UID:600:1"
      jq_run -e --arg tx "$expected_hash" --arg safeTxHash "$(jq_run -er '.safeTxHash' "$validation")" --arg rawSha256 "$(sha256_file "$raw_file")" --arg packageSha256 "$package_sha" --arg nonce "$nonce" --arg relayer "$signer" --arg to "$to" '.schema=="usdom-closed-mainnet-redemption-broadcast-journal-v1" and .state=="signed-unresolved" and .chainId=="1" and .transactionHash==$tx and .safeTxHash==$safeTxHash and .rawSha256==$rawSha256 and .packageSha256==$packageSha256 and .nonce==$nonce and (.relayer|ascii_downcase)==($relayer|ascii_downcase) and (.to|ascii_downcase)==($to|ascii_downcase)' "$broadcast_journal" >/dev/null
      publication_output="$temporary/publication-$index.txt"
      pilot_broadcast_state=publishing
      timeout --foreground --signal=TERM --kill-after=5s 45s \
        node scripts/publish-private-raw-transaction.mjs "$raw_file" "$rpc1" | head -c 68 >"$publication_output"
      test "$(stat_run -c '%s' "$publication_output")" -le 67
      timeout --foreground --signal=TERM --kill-after=5s 120s \
        node scripts/check-transaction-hash-output.mjs "$publication_output" "$expected_hash"
      tx_hash=$expected_hash
    elif test "$nonce_action" = recover-receipt; then
      pilot_broadcast_state=observed
      tx_hash=$expected_hash
    else
      exit 76
    fi
    timeout --foreground --signal=TERM --kill-after=5s 1800s \
      cast receipt "$tx_hash" --confirmations 2 --json --rpc-url "$rpc1" | head -c 65537 >"$candidate"
    test "$(stat_run -c '%s' "$candidate")" -le 65536
    timeout --foreground --signal=TERM --kill-after=5s 120s node scripts/check-private-strict-json-file.mjs "$candidate"
    jq_run -e --arg tx "$tx_hash" --arg from "$signer" --arg to "$to" '.status=="0x1" and (.transactionHash|ascii_downcase)==($tx|ascii_downcase) and (.from|ascii_downcase)==($from|ascii_downcase) and (.to|ascii_downcase)==($to|ascii_downcase)' "$candidate" >/dev/null
    timeout --foreground --signal=TERM --kill-after=5s 120s node scripts/install-private-file-new-stdin.mjs --json "$receipt_record" <"$candidate"
  fi
  tx_hash=$(jq_run -er '.transactionHash' "$validation"); block=$(jq_run -er '.blockNumber' "$receipt_record"); hash=$(jq_run -er '.blockHash|ascii_downcase' "$receipt_record"); transaction_index=$(jq_run -er '.transactionIndex' "$receipt_record")
  receipt_gas=$(jq_run -er '.gasUsed' "$receipt_record"); receipt_price=$(jq_run -er '.effectiveGasPrice' "$receipt_record")
  rpc_consensus_snapshot
  for rpc in "$rpc1" "$rpc2"; do
    timeout --foreground --signal=TERM --kill-after=5s 120s \
      cast receipt "$tx_hash" --json --rpc-url "$rpc" | head -c 65537 >"$candidate"
    test "$(stat_run -c '%s' "$candidate")" -le 65536
    timeout --foreground --signal=TERM --kill-after=5s 120s node scripts/check-private-strict-json-file.mjs "$candidate"
    jq_run -e --arg tx "$tx_hash" --arg from "$signer" --arg to "$to" --arg block "$block" --arg hash "$hash" --arg transactionIndex "$transaction_index" --arg gas "$receipt_gas" --arg price "$receipt_price" '.status=="0x1" and (.transactionHash|ascii_downcase)==($tx|ascii_downcase) and (.from|ascii_downcase)==($from|ascii_downcase) and (.to|ascii_downcase)==($to|ascii_downcase) and .blockNumber==$block and (.blockHash|ascii_downcase)==$hash and .transactionIndex==$transactionIndex and .gasUsed==$gas and .effectiveGasPrice==$price' "$candidate" >/dev/null
    check_rpc_transaction_binding "$rpc" "$index-$rpc_index" "$validation" "$candidate" "$private_input"
    current_projection=$(jq_run -cS '{transactionHash,status,from,to,blockNumber,blockHash,transactionIndex,logs}' "$candidate")
    if [[ -z $receipt_projection ]]; then receipt_projection=$current_projection; else test "$receipt_projection" = "$current_projection"; fi
    finalized=$consensus_block; node_eval 'if(BigInt(process.argv[1])>BigInt(process.argv[2]))process.exit(1)' "$block" "$finalized"
    test "$(timeout --foreground --signal=TERM --kill-after=5s 120s cast block "$block" --field hash --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]' | head -c 68)" = "$hash"
  done
  # Close the sequential-RPC window with a fresh common finalized snapshot and
  # exact receipt/canonical-block rechecks immediately before finality evidence.
  rpc_consensus_snapshot
  barrier_index=0
  for rpc in "$rpc1" "$rpc2"; do
    barrier_receipt="$temporary/redemption-receipt-barrier-$index-$barrier_index.json"
    timeout --foreground --signal=TERM --kill-after=5s 120s \
      cast receipt "$tx_hash" --json --rpc-url "$rpc" | head -c 65537 >"$barrier_receipt"
    test "$(stat_run -c '%s' "$barrier_receipt")" -le 65536
    timeout --foreground --signal=TERM --kill-after=5s 120s node scripts/check-private-strict-json-file.mjs "$barrier_receipt"
    test "$(jq_run -cS '{transactionHash,status,from,to,blockNumber,blockHash,transactionIndex,logs}' "$barrier_receipt")" = "$receipt_projection"
    check_rpc_transaction_binding "$rpc" "barrier-$index-$barrier_index" "$validation" "$barrier_receipt" "$private_input"
    node_eval 'if(BigInt(process.argv[1])>BigInt(process.argv[2]))process.exit(1)' "$block" "$consensus_block"
    test "$(timeout --foreground --signal=TERM --kill-after=5s 120s cast block "$block" --field hash --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]' | head -c 68)" = "$hash"
    barrier_index=$((barrier_index+1))
  done
  cost=$(timeout --foreground --signal=TERM --kill-after=5s 120s \
    node scripts/check-pilot-receipt-cost.mjs "$(jq_run -er '.gasUsed' "$receipt_record")" "$(jq_run -er '.effectiveGasPrice' "$receipt_record")" "$(jq_run -er '.maximumCost' "$validation")" | head -c 1025)
  test "${#cost}" -le 1024
  jq_run -e 'type=="object" and keys==["actualCost","effectiveGasPrice","gasUsed","maximumCost"] and all(.[];type=="string" and test("^(0|[1-9][0-9]*)$"))' <<<"$cost" >/dev/null
  if [[ ! -e $finality_record ]]; then
    jq_run -n --arg tx "$tx_hash" --arg block "$block" --arg hash "$hash" --arg transactionIndex "$transaction_index" --argjson cost "$cost" '{schema:"usdom-closed-mainnet-redemption-finality-v2",transactionHash:$tx,blockNumber:$block,blockHash:$hash,transactionIndex:$transactionIndex,finalizedRpcCount:2}+ $cost' | timeout --foreground --signal=TERM --kill-after=5s 120s node scripts/install-private-file-new-stdin.mjs --json "$finality_record"
  else
    test -f "$finality_record" && test ! -L "$finality_record" && test "$(stat_run -c '%a:%h' "$finality_record")" = '600:1'
    jq_run -e --arg tx "$tx_hash" --arg block "$block" --arg hash "$hash" --arg transactionIndex "$transaction_index" --argjson cost "$cost" '.schema=="usdom-closed-mainnet-redemption-finality-v2" and (.transactionHash|ascii_downcase)==($tx|ascii_downcase) and .blockNumber==$block and (.blockHash|ascii_downcase)==$hash and .transactionIndex==$transactionIndex and .finalizedRpcCount==2 and .gasUsed==$cost.gasUsed and .effectiveGasPrice==$cost.effectiveGasPrice and .actualCost==$cost.actualCost and .maximumCost==$cost.maximumCost' "$finality_record" >/dev/null
  fi
  remove_private_raw "$raw_file"
  pilot_broadcast_state=clean
done
rpc_consensus_snapshot
for rpc in "$rpc1" "$rpc2"; do
  test "$(rpc_bool_call "$reserve" 'paidBurns(bytes32)(bool)' "$burn_id" --block "$consensus_block" --rpc-url "$rpc")" = true
  test "$(rpc_bool_call "$reserve" 'paidRequests(bytes32)(bool)' "$request_id" --block "$consensus_block" --rpc-url "$rpc")" = true
  check_permanent_burn_debt "$rpc"
  before=$(jq_run -er '.recipientBalanceBaseUnits' "$payout_baseline")
  expected=$(node_eval 'process.stdout.write(String(BigInt(process.argv[1])+1000000n))' "$before")
  test "$(rpc_uint_call "$token" 'balanceOf(address)(uint256)' "$recipient" --block "$consensus_block" --rpc-url "$rpc")" = "$expected"
  reserve_before=$(jq_run -er '.reserveBalanceBaseUnits' "$payout_baseline"); released_before=$(jq_run -er '.totalReleasedBaseUnits' "$payout_baseline"); outstanding_before=$(jq_run -er '.outstandingBaseUnits' "$payout_baseline"); debt_before=$(jq_run -er '.totalProvedDebtBaseUnits' "$payout_baseline")
  reserve_after=$(node_eval 'let v=BigInt(process.argv[1]);if(v<1000000n)process.exit(1);process.stdout.write(String(v-1000000n))' "$reserve_before")
  released_after=$(node_eval 'process.stdout.write(String(BigInt(process.argv[1])+1000000n))' "$released_before")
  outstanding_after=$(node_eval 'let v=BigInt(process.argv[1]);if(v<1000000n)process.exit(1);process.stdout.write(String(v-1000000n))' "$outstanding_before")
  debt_after=$(node_eval 'let v=BigInt(process.argv[1]);if(v<1000000n)process.exit(1);process.stdout.write(String(v-1000000n))' "$debt_before")
  test "$(rpc_uint_call "$token" 'balanceOf(address)(uint256)' "$reserve" --block "$consensus_block" --rpc-url "$rpc")" = "$reserve_after"
  test "$(rpc_uint_call "$reserve" 'totalReleased()(uint256)' --block "$consensus_block" --rpc-url "$rpc")" = "$released_after"
  test "$(rpc_uint_call "$reserve" 'outstanding()(uint256)' --block "$consensus_block" --rpc-url "$rpc")" = "$outstanding_after"
  test "$(rpc_uint_call "$reserve" 'totalProvedDebtAmount()(uint256)' --block "$consensus_block" --rpc-url "$rpc")" = "$debt_after"
done
baseline_sha=$(sha256_file "$payout_baseline"); execute_finality_sha=$(sha256_file "$finality_record"); before=$(jq_run -er '.recipientBalanceBaseUnits' "$payout_baseline"); after=$(node_eval 'process.stdout.write(String(BigInt(process.argv[1])+1000000n))' "$before")
execution="$evidence/closed-mainnet-redemption-execution.json"; execution_candidate=$readiness
jq_run -n --arg packageSha256 "$package_sha" --arg burnId "$burn_id" --arg requestId "$request_id" --arg token "$token" --arg recipient "$recipient" --arg baselineSha256 "$baseline_sha" --arg executeFinalitySha256 "$execute_finality_sha" --arg before "$before" --arg after "$after" --arg reserveBefore "$reserve_before" --arg reserveAfter "$reserve_after" --arg releasedBefore "$released_before" --arg releasedAfter "$released_after" --arg outstandingBefore "$outstanding_before" --arg outstandingAfter "$outstanding_after" --arg debtBefore "$debt_before" --arg debtAfter "$debt_after" --arg snapshotBlockNumber "$consensus_block" --arg snapshotBlockHash "$consensus_hash" '{schema:"usdom-closed-mainnet-redemption-execution-v2",chainId:"1",packageSha256:$packageSha256,burnId:$burnId,requestId:$requestId,amountBaseUnits:"1000000",token:$token,recipient:$recipient,payoutBaselineSha256:$baselineSha256,executeFinalitySha256:$executeFinalitySha256,recipientBalanceBefore:$before,recipientBalanceAfter:$after,reserveBalanceBefore:$reserveBefore,reserveBalanceAfter:$reserveAfter,totalReleasedBefore:$releasedBefore,totalReleasedAfter:$releasedAfter,outstandingBefore:$outstandingBefore,outstandingAfter:$outstandingAfter,totalProvedDebtBefore:$debtBefore,totalProvedDebtAfter:$debtAfter,steps:2,finalizedAcrossRpcCount:2,outputLast:true,snapshotBlockNumber:$snapshotBlockNumber,snapshotBlockHash:$snapshotBlockHash}' >"$execution_candidate"
timeout --foreground --signal=TERM --kill-after=5s 120s node scripts/check-private-strict-json-file.mjs "$execution_candidate"
timeout --foreground --signal=TERM --kill-after=5s 120s \
  node scripts/check-closed-mainnet-payout-evidence.mjs "$payout_baseline" "$execution_candidate" "$package" "$finality_record" >/dev/null
if [[ -e $execution ]]; then cmp_exact "$execution_candidate" "$execution"; else timeout --foreground --signal=TERM --kill-after=5s 120s node scripts/install-private-file-new-stdin.mjs --json "$execution" <"$execution_candidate"; fi
