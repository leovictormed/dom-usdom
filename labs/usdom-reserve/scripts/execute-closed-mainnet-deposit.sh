#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077
unset BASH_XTRACEFD 2>/dev/null || true
unset LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
  NODE_OPTIONS NODE_PATH NODE_DEBUG NODE_DEBUG_NATIVE SSLKEYLOGFILE \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
for inherited_name in ${!FOUNDRY_@} ${!CAST_@}; do unset "$inherited_name"; done
ulimit -c 0
if (($# != 0)) || [[ ! -t 0 || ! -t 1 ]]; then
  printf '%s\n' 'Interactive closed-mainnet deposit executor accepts no arguments.' >&2; exit 64
fi
readonly project=/home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve
readonly evidence=/home/leonardov/usdom-mainnet-private/control-plane
readonly package="$evidence/closed-mainnet-deposit-package.json"
readonly deposit_baseline="$evidence/closed-mainnet-deposit-financial-baseline.json"
readonly rpc1=https://ethereum-rpc.publicnode.com
readonly rpc2=https://rpc.mevblocker.io
export PATH=/usr/lib/chatgpt/resources/cua_node/bin:/home/leonardov/.foundry/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
for fd_path in /proc/"$$"/fd/*; do
  inherited_fd=${fd_path##*/}
  [[ $inherited_fd =~ ^[0-9]+$ ]] || exit 1
  (( inherited_fd<=2 )) && continue
  [[ $inherited_fd == 255 ]] && continue
  exec {inherited_fd}>&-
done
cd "$project"
exec 9<"$evidence"; flock -n 9 || exit 75
shopt -s nullglob
for abandoned in /dev/shm/usdom-closed-deposit.*; do
  [[ -d $abandoned && ! -L $abandoned && $(stat -c '%u:%a' "$abandoned") == "$(id -u):700" ]] || exit 1
  rm -rf -- "$abandoned"
done
shopt -u nullglob
check_pilot_budget() {
  local proposed=${1-} deposit_costs='' separator=''
  for budget_index in 0 1 2; do
    local budget_file="$evidence/closed-deposit-$budget_index-validation.json"
    if [[ -f $budget_file ]]; then
      deposit_costs+="$separator$(jq -er '.maximumCost' "$budget_file")"; separator=,
    fi
  done
  if [[ -n $proposed ]]; then deposit_costs+="$separator$proposed"; fi
  node scripts/check-closed-mainnet-pilot-budget.mjs "$deposit_costs" '' >/dev/null
}
recheck_live_authorities() {
  local report="$temporary/live-authorities.json"
  local finalized_hash checkpoint_hash
  finalized_hash=$(tr -d '\n' < "$evidence/contract-deployment-0-submission-hash.txt")
  checkpoint_hash=$(tr -d '\n' < "$evidence/contract-deployment-1-submission-hash.txt")
  USDOM_MAINNET_DEPLOYMENT_EVIDENCE_DIRECTORY="$evidence" \
  USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE="$evidence/mainnet-preflight-rpc-sources.json" \
  USDOM_FINALIZED_BURN_VERIFIER_DEPLOYMENT_TX_HASH="$finalized_hash" \
  USDOM_CHECKPOINT_VERIFIER_DEPLOYMENT_TX_HASH="$checkpoint_hash" \
    node scripts/check-mainnet-preflight.mjs authority-recheck > "$report"
  jq -e '.phase=="authority-recheck" and .ready==true and .blockerCount==0' "$report" >/dev/null
}
refresh_consensus_block() {
  local finalized1 finalized2 hash1 hash2
  finalized1=$(cast block finalized --field number --rpc-url "$rpc1")
  finalized2=$(cast block finalized --field number --rpc-url "$rpc2")
  consensus_block=$(node -e 'let a=BigInt(process.argv[1]),b=BigInt(process.argv[2]);process.stdout.write(String(a<b?a:b))' "$finalized1" "$finalized2")
  hash1=$(cast block "$consensus_block" --field hash --rpc-url "$rpc1" | tr '[:upper:]' '[:lower:]')
  hash2=$(cast block "$consensus_block" --field hash --rpc-url "$rpc2" | tr '[:upper:]' '[:lower:]')
  test "$hash1" = "$hash2"; test "$hash1" != 0x0000000000000000000000000000000000000000000000000000000000000000
}
check_funder_not_blacklisted() {
  local blacklisted1 blacklisted2
  blacklisted1=$(cast call "$token" 'isBlackListed(address)(bool)' "$funder" --block "$consensus_block" --rpc-url "$rpc1")
  blacklisted2=$(cast call "$token" 'isBlackListed(address)(bool)' "$funder" --block "$consensus_block" --rpc-url "$rpc2")
  test "$blacklisted1" = false; test "$blacklisted2" = false
}
test -f "$package" && test ! -L "$package" && test "$(stat -c '%a:%h' "$package")" = '600:1'
node scripts/check-mainnet-toolchain.mjs >/dev/null
node scripts/check-closed-mainnet-deposit-package.mjs "$package" >/dev/null
temporary=$(mktemp -d -p /dev/shm usdom-closed-deposit.XXXXXXXX); chmod 0700 "$temporary"
cleanup() { local status=${1:-$?}; trap - EXIT HUP INT TERM; unset USDOM_CLOSED_MAINNET_DEPOSIT_RAW_FILE; rm -rf -- "$temporary"; exit "$status"; }
trap 'cleanup $?' EXIT; trap 'cleanup 129' HUP; trap 'cleanup 130' INT; trap 'cleanup 143' TERM
gate="$temporary/readiness.json"
node scripts/check-mainnet-readiness.mjs real-funds >"$gate"
jq -e '.ready==true and .blockerCount==0' "$gate" >/dev/null
package_sha=$(sha256sum "$package"|awk '{print $1}')
test "$(jq -er '.releaseConfigSha256' "$package")" = "$(sha256sum config/proof-reserve.unconfigured.json|awk '{print $1}')"
funder=$(jq -er '.funder' "$package"); token=$(jq -er '.token' "$package"); reserve=$(jq -er '.reserve' "$package")
amount=$(jq -er '.amountBaseUnits' "$package"); test "$amount" = 1000000
deposit_id=$(jq -er '.depositId' "$package"); commitment=$(jq -er '.receivingCommitment' "$package")
test "$(cast wallet address --ledger)" = "$funder"
for rpc in "$rpc1" "$rpc2"; do test "$(cast chain-id --rpc-url "$rpc")" = 1; done
consensus_block=''; refresh_consensus_block
check_funder_not_blacklisted
if [[ -e $deposit_baseline ]]; then
  test -f "$deposit_baseline" && test ! -L "$deposit_baseline" && test "$(stat -c '%a:%h' "$deposit_baseline")" = '600:1'
  jq -e --arg packageSha256 "$package_sha" --arg funder "$funder" --arg token "$token" --arg reserve "$reserve" '
    (keys|sort)==(["allowanceBaseUnits","chainId","funder","funderBalanceBaseUnits","observedAt","outstandingBaseUnits","packageSha256","reserve","reserveBalanceBaseUnits","rpcCount","schema","token","totalDepositedBaseUnits"]|sort)
    and .schema=="usdom-closed-mainnet-deposit-financial-baseline-v1" and .chainId=="1"
    and .packageSha256==$packageSha256 and (.funder|ascii_downcase)==($funder|ascii_downcase)
    and (.token|ascii_downcase)==($token|ascii_downcase) and (.reserve|ascii_downcase)==($reserve|ascii_downcase)
    and .allowanceBaseUnits=="0" and .observedAt=="finalized" and .rpcCount==2
    and ([.funderBalanceBaseUnits,.reserveBalanceBaseUnits,.totalDepositedBaseUnits,.outstandingBaseUnits]
      | all(type=="string" and test("^(0|[1-9][0-9]*)$")))' "$deposit_baseline" >/dev/null
else
  f1=$(cast call "$token" 'balanceOf(address)(uint256)' "$funder" --block "$consensus_block" --rpc-url "$rpc1"); f2=$(cast call "$token" 'balanceOf(address)(uint256)' "$funder" --block "$consensus_block" --rpc-url "$rpc2")
  r1=$(cast call "$token" 'balanceOf(address)(uint256)' "$reserve" --block "$consensus_block" --rpc-url "$rpc1"); r2=$(cast call "$token" 'balanceOf(address)(uint256)' "$reserve" --block "$consensus_block" --rpc-url "$rpc2")
  d1=$(cast call "$reserve" 'totalDeposited()(uint256)' --block "$consensus_block" --rpc-url "$rpc1"); d2=$(cast call "$reserve" 'totalDeposited()(uint256)' --block "$consensus_block" --rpc-url "$rpc2")
  o1=$(cast call "$reserve" 'outstanding()(uint256)' --block "$consensus_block" --rpc-url "$rpc1"); o2=$(cast call "$reserve" 'outstanding()(uint256)' --block "$consensus_block" --rpc-url "$rpc2")
  a1=$(cast call "$token" 'allowance(address,address)(uint256)' "$funder" "$reserve" --block "$consensus_block" --rpc-url "$rpc1"); a2=$(cast call "$token" 'allowance(address,address)(uint256)' "$funder" "$reserve" --block "$consensus_block" --rpc-url "$rpc2")
  test "$f1" = "$f2"; test "$r1" = "$r2"; test "$d1" = "$d2"; test "$o1" = "$o2"; test "$a1" = 0; test "$a2" = 0
  jq -n --arg packageSha256 "$package_sha" --arg funder "$funder" --arg token "$token" --arg reserve "$reserve" --arg funderBalance "$f1" --arg reserveBalance "$r1" --arg totalDeposited "$d1" --arg outstanding "$o1" '{schema:"usdom-closed-mainnet-deposit-financial-baseline-v1",chainId:"1",packageSha256:$packageSha256,funder:$funder,token:$token,reserve:$reserve,funderBalanceBaseUnits:$funderBalance,reserveBalanceBaseUnits:$reserveBalance,totalDepositedBaseUnits:$totalDeposited,outstandingBaseUnits:$outstanding,allowanceBaseUnits:"0",observedAt:"finalized",rpcCount:2}' | node scripts/install-private-file-new-stdin.mjs --json "$deposit_baseline"
fi
check_deposit_state() {
  local step=$1 rpc=$2 allowance_expected=0
  [[ $step == 1 ]] && allowance_expected=1000000
  local funder_expected reserve_expected deposited_expected outstanding_expected
  funder_expected=$(jq -er '.funderBalanceBaseUnits' "$deposit_baseline")
  reserve_expected=$(jq -er '.reserveBalanceBaseUnits' "$deposit_baseline")
  deposited_expected=$(jq -er '.totalDepositedBaseUnits' "$deposit_baseline")
  outstanding_expected=$(jq -er '.outstandingBaseUnits' "$deposit_baseline")
  if [[ $step == 2 ]]; then
    funder_expected=$(node -e 'let v=BigInt(process.argv[1]);if(v<1000000n)process.exit(1);process.stdout.write(String(v-1000000n))' "$funder_expected")
    reserve_expected=$(node -e 'process.stdout.write(String(BigInt(process.argv[1])+1000000n))' "$reserve_expected")
    deposited_expected=$(node -e 'process.stdout.write(String(BigInt(process.argv[1])+1000000n))' "$deposited_expected")
    outstanding_expected=$(node -e 'process.stdout.write(String(BigInt(process.argv[1])+1000000n))' "$outstanding_expected")
  fi
  test "$(cast call "$token" 'allowance(address,address)(uint256)' "$funder" "$reserve" --block "$consensus_block" --rpc-url "$rpc")" = "$allowance_expected"
  test "$(cast call "$token" 'balanceOf(address)(uint256)' "$funder" --block "$consensus_block" --rpc-url "$rpc")" = "$funder_expected"
  test "$(cast call "$token" 'balanceOf(address)(uint256)' "$reserve" --block "$consensus_block" --rpc-url "$rpc")" = "$reserve_expected"
  test "$(cast call "$reserve" 'totalDeposited()(uint256)' --block "$consensus_block" --rpc-url "$rpc")" = "$deposited_expected"
  test "$(cast call "$reserve" 'outstanding()(uint256)' --block "$consensus_block" --rpc-url "$rpc")" = "$outstanding_expected"
}
base_nonce=''
if test -f "$evidence/closed-deposit-0-validation.json"; then
  test ! -L "$evidence/closed-deposit-0-validation.json"
  test "$(stat -c '%a:%h' "$evidence/closed-deposit-0-validation.json")" = '600:1'
  base_nonce=$(jq -er '.nonce' "$evidence/closed-deposit-0-validation.json")
fi
for index in 0 1 2; do
  name=$(jq -er ".transactions[$index].name" "$package")
  to=$(jq -er ".transactions[$index].to" "$package")
  data=$(jq -er ".transactions[$index].data" "$package")
  if [[ -z $base_nonce ]]; then
    n1=$(cast nonce "$funder" --block pending --rpc-url "$rpc1")
    n2=$(cast nonce "$funder" --block pending --rpc-url "$rpc2")
    test "$n1" = "$n2"; base_nonce=$n1
  fi
  nonce=$(node -e 'process.stdout.write(String(BigInt(process.argv[1])+BigInt(process.argv[2])))' "$base_nonce" "$index")
  expected_next_nonce=$(node -e 'process.stdout.write(String(BigInt(process.argv[1])+1n))' "$nonce")
  raw_file="$evidence/closed-deposit-$index-raw.txt"; validation="$evidence/closed-deposit-$index-validation.json"
  receipt_record="$evidence/closed-deposit-$index-receipt.json"
  finality_record="$evidence/closed-deposit-$index-finality.json"
  if [[ -e $raw_file && ! -e $validation ]]; then
    export USDOM_CLOSED_MAINNET_DEPOSIT_RAW_FILE=$raw_file
    recovered_validation="$temporary/recovered-validation-$index.json"
    node scripts/check-closed-mainnet-deposit-raw.mjs "$package" "$index" "$nonce" >"$recovered_validation"
    node scripts/install-private-file-new-stdin.mjs --json "$validation" <"$recovered_validation"
    unset USDOM_CLOSED_MAINNET_DEPOSIT_RAW_FILE
  fi
  if test -f "$receipt_record"; then
    test ! -L "$receipt_record" && test "$(stat -c '%a:%h' "$receipt_record")" = '600:1'
    test -f "$validation" && test ! -L "$validation" && test "$(stat -c '%a:%h' "$validation")" = '600:1'
    test "$(jq -er '.nonce' "$validation")" = "$nonce"
    if [[ -e $raw_file ]]; then
      export USDOM_CLOSED_MAINNET_DEPOSIT_RAW_FILE=$raw_file
      node scripts/check-closed-mainnet-deposit-raw.mjs "$package" "$index" "$nonce" | cmp -s - "$validation"
      unset USDOM_CLOSED_MAINNET_DEPOSIT_RAW_FILE
    fi
    tx_hash=$(jq -er '.transactionHash' "$validation")
    receipt_block=$(jq -er '.blockNumber' "$receipt_record"); receipt_hash=$(jq -er '.blockHash|ascii_downcase' "$receipt_record")
    receipt_gas=$(jq -er '.gasUsed' "$receipt_record"); receipt_price=$(jq -er '.effectiveGasPrice' "$receipt_record")
    refresh_consensus_block
    for rpc in "$rpc1" "$rpc2"; do
      rpc_receipt="$temporary/receipt-existing-$index-${rpc//[^a-zA-Z0-9]/_}.json"; cast receipt "$tx_hash" --json --rpc-url "$rpc" >"$rpc_receipt"
      jq -e --arg tx "$tx_hash" --arg block "$receipt_block" --arg hash "$receipt_hash" --arg gas "$receipt_gas" --arg price "$receipt_price" \
        '(.transactionHash|ascii_downcase)==($tx|ascii_downcase) and .status=="0x1" and .blockNumber==$block and (.blockHash|ascii_downcase)==$hash and .gasUsed==$gas and .effectiveGasPrice==$price' "$rpc_receipt" >/dev/null
      finalized_number=$(cast block finalized --field number --rpc-url "$rpc")
      node -e 'if(BigInt(process.argv[1])>BigInt(process.argv[2]))process.exit(1)' "$receipt_block" "$finalized_number"
      # Earlier receipts authenticate history, but their transient allowance and
      # nonce states are no longer expected after a later finalized step.
      if (( index == 2 )) || { [[ ! -e $evidence/closed-deposit-$((index+1))-validation.json ]] && [[ ! -e $evidence/closed-deposit-$((index+1))-receipt.json ]]; }; then
        test "$(cast nonce "$funder" --block pending --rpc-url "$rpc")" = "$expected_next_nonce"
        check_deposit_state "$index" "$rpc"
      fi
    done
    cost=$(node scripts/check-pilot-receipt-cost.mjs "$(jq -er '.gasUsed' "$receipt_record")" "$(jq -er '.effectiveGasPrice' "$receipt_record")" "$(jq -er '.maximumCost' "$validation")")
    if [[ ! -e $finality_record ]]; then
      jq -n --arg tx "$tx_hash" --arg block "$receipt_block" --arg hash "$receipt_hash" --argjson cost "$cost" '{schema:"usdom-closed-mainnet-deposit-finality-v1",transactionHash:$tx,blockNumber:$block,blockHash:$hash,finalizedRpcCount:2}+$cost' | node scripts/install-private-file-new-stdin.mjs --json "$finality_record"
    else
      test -f "$finality_record" && test ! -L "$finality_record" && test "$(stat -c '%a:%h' "$finality_record")" = '600:1'
      jq -e --arg tx "$tx_hash" --arg block "$receipt_block" --arg hash "$receipt_hash" --argjson cost "$cost" '.schema=="usdom-closed-mainnet-deposit-finality-v1" and (.transactionHash|ascii_downcase)==($tx|ascii_downcase) and .blockNumber==$block and (.blockHash|ascii_downcase)==$hash and .finalizedRpcCount==2 and .gasUsed==$cost.gasUsed and .effectiveGasPrice==$cost.effectiveGasPrice and .actualCost==$cost.actualCost and .maximumCost==$cost.maximumCost' "$finality_record" >/dev/null
    fi
    rm -f -- "$raw_file"
    continue
  fi
  if [[ ! -e $raw_file ]]; then
   refresh_consensus_block
   for rpc in "$rpc1" "$rpc2"; do
    test "$(cast nonce "$funder" --block pending --rpc-url "$rpc")" = "$nonce"
    allowance=$(cast call "$token" 'allowance(address,address)(uint256)' "$funder" "$reserve" --rpc-url "$rpc" --block "$consensus_block")
    case $index in 0) : ;; 1) test "$allowance" = 0 ;; 2) test "$allowance" = 1000000 ;; esac
   done
   estimate1=$(cast estimate "$to" "$data" --from "$funder" --value 0 --rpc-url "$rpc1")
  estimate2=$(cast estimate "$to" "$data" --from "$funder" --value 0 --rpc-url "$rpc2")
  gas=$(node -e 'let a=BigInt(process.argv[1]),b=BigInt(process.argv[2]);let m=a>b?a:b,marg=(m*125n+99n)/100n;if(marg>500000n)process.exit(1);process.stdout.write(String(marg))' "$estimate1" "$estimate2")
  base1=$(cast block "$consensus_block" --field baseFeePerGas --rpc-url "$rpc1")
  base2=$(cast block "$consensus_block" --field baseFeePerGas --rpc-url "$rpc2")
  test "$base1" = "$base2"
  fee=$(node -e 'let a=BigInt(process.argv[1]),b=BigInt(process.argv[2]),f=a>b?a:b;for(let i=0;i<12;i++)f=(f*9n+7n)/8n;f+=2000000000n;if(f>100000000000n||f*BigInt(process.argv[3])>50000000000000000n)process.exit(1);process.stdout.write(String(f))' "$base1" "$base2" "$gas")
    proposed_cost=$(node -e 'process.stdout.write(String(BigInt(process.argv[1])*BigInt(process.argv[2])))' "$gas" "$fee")
    check_pilot_budget "$proposed_cost"
    gas_balance1=$(cast balance "$funder" --block pending --rpc-url "$rpc1"); gas_balance2=$(cast balance "$funder" --block pending --rpc-url "$rpc2")
    node scripts/check-pilot-gas-funding.mjs "$gas_balance1" "$gas_balance2" "$(node -e 'process.stdout.write(String(BigInt(process.argv[1])*BigInt(process.argv[2])))' "$gas" "$fee")" >/dev/null
    if [[ $index == 0 ]]; then recheck_live_authorities; fi
    read -r -p "Digite AUTORIZO ASSINAR DEPOSITO MAINNET ETAPA $index para assinar $name: " answer
    test "$answer" = "AUTORIZO ASSINAR DEPOSITO MAINNET ETAPA $index"
    recheck_live_authorities
    refresh_consensus_block
    check_funder_not_blacklisted
    for rpc in "$rpc1" "$rpc2"; do
      test "$(cast chain-id --rpc-url "$rpc")" = 1
      test "$(cast nonce "$funder" --block "$consensus_block" --rpc-url "$rpc")" = "$nonce"
      test "$(cast nonce "$funder" --block pending --rpc-url "$rpc")" = "$nonce"
    done
    live_base1=$(cast block "$consensus_block" --field baseFeePerGas --rpc-url "$rpc1"); live_base2=$(cast block "$consensus_block" --field baseFeePerGas --rpc-url "$rpc2")
    test "$live_base1" = "$live_base2"
    node -e 'let f=BigInt(process.argv[1]);for(let i=0;i<12;i++)f=(f*9n+7n)/8n;f+=2000000000n;if(BigInt(process.argv[2])<f)process.exit(1)' "$live_base1" "$fee"
    data_hash=$(jq -er ".transactions[$index].dataKeccak256" "$package")
    printf 'LEDGER CLEAR REVIEW action=%s chainId=1 signer=%s to=%s nonce=%s value=0 selector=%s dataHash=%s gas=%s maxFee=%s priorityFee=2000000000\n' \
      "$name" "$funder" "$to" "$nonce" "${data:0:10}" "$data_hash" "$gas" "$fee"
    read -r -p "Digite CONFIRMO CLEAR SIGNING DEPOSITO ETAPA $index somente se o Ledger exibir a mesma ação; blind signing é proibido: " clear_answer
    test "$clear_answer" = "CONFIRMO CLEAR SIGNING DEPOSITO ETAPA $index"
    raw_candidate="$temporary/raw-$index.txt"
    cast mktx "$to" --chain 1 --from "$funder" --nonce "$nonce" --value 0 --data "$data" \
      --gas-limit "$gas" --gas-price "$fee" --priority-gas-price 2000000000 --ledger --rpc-url "$rpc1" | tr '[:upper:]' '[:lower:]' >"$raw_candidate"
    chmod 0600 "$raw_candidate"
    export USDOM_CLOSED_MAINNET_DEPOSIT_RAW_FILE=$raw_candidate
    candidate="$temporary/validation-$index.json"
    node scripts/check-closed-mainnet-deposit-raw.mjs "$package" "$index" "$nonce" >"$candidate"
    test "$(jq -er '.from' "$candidate")" = "$funder"
    node scripts/install-private-file-new-stdin.mjs "$raw_file" <"$raw_candidate"
    node scripts/install-private-file-new-stdin.mjs --json "$validation" <"$candidate"
    unset USDOM_CLOSED_MAINNET_DEPOSIT_RAW_FILE
  fi
  export USDOM_CLOSED_MAINNET_DEPOSIT_RAW_FILE=$raw_file
  node scripts/check-closed-mainnet-deposit-raw.mjs "$package" "$index" "$nonce" | cmp -s - "$validation"
  unset USDOM_CLOSED_MAINNET_DEPOSIT_RAW_FILE
  test "$(sha256sum "$package"|awk '{print $1}')" = "$package_sha"
  expected_hash=$(jq -er '.transactionHash' "$validation")
  finalized1=$(cast nonce "$funder" --block "$consensus_block" --rpc-url "$rpc1"); finalized2=$(cast nonce "$funder" --block "$consensus_block" --rpc-url "$rpc2")
  current1=$(cast nonce "$funder" --block pending --rpc-url "$rpc1"); current2=$(cast nonce "$funder" --block pending --rpc-url "$rpc2")
  known1=$(cast tx "$expected_hash" --field hash --rpc-url "$rpc1" 2>/dev/null || true)
  known2=$(cast tx "$expected_hash" --field hash --rpc-url "$rpc2" 2>/dev/null || true)
  nonce_action=$(node scripts/check-pilot-nonce-recovery.mjs "$nonce" "$finalized1" "$current1" "$finalized2" "$current2" "$expected_hash" "$known1" "$known2")
  if test "$nonce_action" = publish; then
    maximum_cost=$(jq -er '.maximumCost' "$validation"); gas_balance1=$(cast balance "$funder" --block pending --rpc-url "$rpc1"); gas_balance2=$(cast balance "$funder" --block pending --rpc-url "$rpc2")
    node scripts/check-pilot-gas-funding.mjs "$gas_balance1" "$gas_balance2" "$maximum_cost" >/dev/null
    check_pilot_budget
    read -r -p "Digite AUTORIZO TRANSMITIR DEPOSITO MAINNET ETAPA $index para publicar: " answer
    test "$answer" = "AUTORIZO TRANSMITIR DEPOSITO MAINNET ETAPA $index"
    recheck_live_authorities
    refresh_consensus_block
    check_funder_not_blacklisted
    for rpc in "$rpc1" "$rpc2"; do
      test "$(cast chain-id --rpc-url "$rpc")" = 1
      test "$(cast nonce "$funder" --block "$consensus_block" --rpc-url "$rpc")" = "$nonce"
      test "$(cast nonce "$funder" --block pending --rpc-url "$rpc")" = "$nonce"
    done
    signed_fee=$(jq -er '.maxFeePerGas' "$validation")
    live_base1=$(cast block "$consensus_block" --field baseFeePerGas --rpc-url "$rpc1"); live_base2=$(cast block "$consensus_block" --field baseFeePerGas --rpc-url "$rpc2")
    test "$live_base1" = "$live_base2"
    node -e 'let f=BigInt(process.argv[1]);for(let i=0;i<12;i++)f=(f*9n+7n)/8n;f+=2000000000n;if(BigInt(process.argv[2])<f)process.exit(1)' "$live_base1" "$signed_fee"
    tx_hash=$(node scripts/publish-private-raw-transaction.mjs "$raw_file" "$rpc1")
    test "${tx_hash,,}" = "${expected_hash,,}"
  elif test "$nonce_action" = recover-receipt; then
    tx_hash=$expected_hash
  else
    exit 76
  fi
  receipt_candidate="$temporary/receipt-$index.json"
  cast receipt "$tx_hash" --confirmations 2 --json --rpc-url "$rpc1" >"$receipt_candidate"
  jq -e --arg tx "$tx_hash" --arg from "$funder" --arg to "$to" '.status=="0x1" and (.transactionHash|ascii_downcase)==($tx|ascii_downcase) and (.from|ascii_downcase)==($from|ascii_downcase) and (.to|ascii_downcase)==($to|ascii_downcase)' "$receipt_candidate" >/dev/null
  receipt_block=$(jq -er '.blockNumber' "$receipt_candidate")
  receipt_hash=$(jq -er '.blockHash|ascii_downcase' "$receipt_candidate")
  receipt_gas=$(jq -er '.gasUsed' "$receipt_candidate"); receipt_price=$(jq -er '.effectiveGasPrice' "$receipt_candidate")
  refresh_consensus_block
  for rpc in "$rpc1" "$rpc2"; do
    rpc_receipt="$temporary/receipt-$index-${rpc//[^a-zA-Z0-9]/_}.json"; cast receipt "$tx_hash" --json --rpc-url "$rpc" >"$rpc_receipt"
    jq -e --arg tx "$tx_hash" --arg from "$funder" --arg to "$to" --arg block "$receipt_block" --arg hash "$receipt_hash" --arg gas "$receipt_gas" --arg price "$receipt_price" \
      '.status=="0x1" and (.transactionHash|ascii_downcase)==($tx|ascii_downcase) and (.from|ascii_downcase)==($from|ascii_downcase) and (.to|ascii_downcase)==($to|ascii_downcase) and .blockNumber==$block and (.blockHash|ascii_downcase)==$hash and .gasUsed==$gas and .effectiveGasPrice==$price' "$rpc_receipt" >/dev/null
    finalized_number=$(cast block finalized --field number --rpc-url "$rpc")
    node -e 'if(BigInt(process.argv[1])>BigInt(process.argv[2]))process.exit(1)' "$receipt_block" "$finalized_number"
    test "$(cast block "$receipt_block" --field hash --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" = "$receipt_hash"
    test "$(cast nonce "$funder" --block pending --rpc-url "$rpc")" = "$expected_next_nonce"
    allowance=$(cast call "$token" 'allowance(address,address)(uint256)' "$funder" "$reserve" --rpc-url "$rpc" --block "$consensus_block")
    case $index in 0) test "$allowance" = 0 ;; 1) test "$allowance" = 1000000 ;; 2) test "$allowance" = 0 ;; esac
    check_deposit_state "$index" "$rpc"
  done
  node scripts/install-private-file-new-stdin.mjs --json "$evidence/closed-deposit-$index-receipt.json" <"$receipt_candidate"
  cost=$(node scripts/check-pilot-receipt-cost.mjs "$(jq -er '.gasUsed' "$receipt_record")" "$(jq -er '.effectiveGasPrice' "$receipt_record")" "$(jq -er '.maximumCost' "$validation")")
  if [[ ! -e $finality_record ]]; then
    jq -n --arg tx "$tx_hash" --arg block "$receipt_block" --arg hash "$receipt_hash" --argjson cost "$cost" '{schema:"usdom-closed-mainnet-deposit-finality-v1",transactionHash:$tx,blockNumber:$block,blockHash:$hash,finalizedRpcCount:2}+$cost' | node scripts/install-private-file-new-stdin.mjs --json "$finality_record"
  else
    test -f "$finality_record" && test ! -L "$finality_record" && test "$(stat -c '%a:%h' "$finality_record")" = '600:1'
    jq -e --arg tx "$tx_hash" --arg block "$receipt_block" --arg hash "$receipt_hash" --argjson cost "$cost" '.schema=="usdom-closed-mainnet-deposit-finality-v1" and (.transactionHash|ascii_downcase)==($tx|ascii_downcase) and .blockNumber==$block and (.blockHash|ascii_downcase)==$hash and .finalizedRpcCount==2 and .gasUsed==$cost.gasUsed and .effectiveGasPrice==$cost.effectiveGasPrice and .actualCost==$cost.actualCost and .maximumCost==$cost.maximumCost' "$finality_record" >/dev/null
  fi
  rm -f -- "$raw_file"
done
refresh_consensus_block
for rpc in "$rpc1" "$rpc2"; do
  test "$(cast call "$token" 'allowance(address,address)(uint256)' "$funder" "$reserve" --rpc-url "$rpc" --block "$consensus_block")" = 0
  before_funder=$(jq -er '.funderBalanceBaseUnits' "$deposit_baseline"); before_reserve=$(jq -er '.reserveBalanceBaseUnits' "$deposit_baseline"); before_deposited=$(jq -er '.totalDepositedBaseUnits' "$deposit_baseline"); before_outstanding=$(jq -er '.outstandingBaseUnits' "$deposit_baseline")
  expected_funder=$(node -e 'let v=BigInt(process.argv[1]);if(v<1000000n)process.exit(1);process.stdout.write(String(v-1000000n))' "$before_funder")
  expected_reserve=$(node -e 'process.stdout.write(String(BigInt(process.argv[1])+1000000n))' "$before_reserve")
  expected_deposited=$(node -e 'process.stdout.write(String(BigInt(process.argv[1])+1000000n))' "$before_deposited")
  expected_outstanding=$(node -e 'process.stdout.write(String(BigInt(process.argv[1])+1000000n))' "$before_outstanding")
  test "$(cast call "$token" 'balanceOf(address)(uint256)' "$funder" --block "$consensus_block" --rpc-url "$rpc")" = "$expected_funder"
  test "$(cast call "$token" 'balanceOf(address)(uint256)' "$reserve" --block "$consensus_block" --rpc-url "$rpc")" = "$expected_reserve"
  test "$(cast call "$reserve" 'totalDeposited()(uint256)' --block "$consensus_block" --rpc-url "$rpc")" = "$expected_deposited"
  test "$(cast call "$reserve" 'outstanding()(uint256)' --block "$consensus_block" --rpc-url "$rpc")" = "$expected_outstanding"
  record=$(cast call "$reserve" 'deposits(bytes32)(address,uint64,bytes32)' "$deposit_id" --block "$consensus_block" --rpc-url "$rpc")
  test "$(printf '%s\n' "$record"|sed -n '1p'|tr '[:upper:]' '[:lower:]')" = "${funder,,}"
  test "$(printf '%s\n' "$record"|sed -n '2{s/ .*//;p;}')" = 1000000
  test "$(printf '%s\n' "$record"|sed -n '3p'|tr '[:upper:]' '[:lower:]')" = "${commitment,,}"
done
baseline_sha=$(sha256sum "$deposit_baseline"|awk '{print $1}')
execution="$evidence/closed-mainnet-deposit-execution.json"; execution_candidate=$gate
jq -n --arg packageSha256 "$package_sha" --arg amount "$amount" --arg baselineSha256 "$baseline_sha" --arg funderBefore "$before_funder" --arg funderAfter "$expected_funder" --arg reserveBefore "$before_reserve" --arg reserveAfter "$expected_reserve" --arg totalDepositedBefore "$before_deposited" --arg totalDepositedAfter "$expected_deposited" --arg outstandingBefore "$before_outstanding" --arg outstandingAfter "$expected_outstanding" '{schema:"usdom-closed-mainnet-deposit-execution-v1",chainId:"1",packageSha256:$packageSha256,amountBaseUnits:$amount,financialBaselineSha256:$baselineSha256,funderBalanceBefore:$funderBefore,funderBalanceAfter:$funderAfter,reserveBalanceBefore:$reserveBefore,reserveBalanceAfter:$reserveAfter,totalDepositedBefore:$totalDepositedBefore,totalDepositedAfter:$totalDepositedAfter,outstandingBefore:$outstandingBefore,outstandingAfter:$outstandingAfter,steps:3,allowanceBefore:"0",allowanceAfter:"0",outputLast:true}' >"$execution_candidate"
if [[ -e $execution ]]; then
  test -f "$execution" && test ! -L "$execution" && test "$(stat -c '%a:%h' "$execution")" = '600:1'
  cmp -s "$execution_candidate" "$execution"
else
  node scripts/install-private-file-new-stdin.mjs --json "$execution" <"$execution_candidate"
fi
