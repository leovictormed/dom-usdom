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
readonly rpc1=https://ethereum-rpc.publicnode.com
readonly rpc2=https://rpc.mevblocker.io
export PATH=/usr/lib/chatgpt/resources/cua_node/bin:/home/leonardov/.foundry/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd "$project"; exec 9<"$evidence"; flock -n 9 || exit 75
shopt -s nullglob
for abandoned in /dev/shm/usdom-closed-redemption.*; do
  [[ -d $abandoned && ! -L $abandoned && $(stat -c '%u:%a' "$abandoned") == "$(id -u):700" ]] || exit 1
  rm -rf -- "$abandoned"
done
shopt -u nullglob
check_pilot_budget() {
  local proposed=${1-} deposit_costs='' redemption_costs='' separator=''
  for budget_index in 0 1 2; do
    local budget_file="$evidence/closed-deposit-$budget_index-validation.json"
    if [[ -f $budget_file ]]; then deposit_costs+="$separator$(jq -er '.maximumCost' "$budget_file")"; separator=,; fi
  done
  separator=''
  for budget_index in 0 1; do
    local budget_file="$evidence/closed-redemption-$budget_index-validation.json"
    if [[ -f $budget_file ]]; then redemption_costs+="$separator$(jq -er '.maximumCost' "$budget_file")"; separator=,; fi
  done
  if [[ -n $proposed ]]; then redemption_costs+="$separator$proposed"; fi
  node scripts/check-closed-mainnet-pilot-budget.mjs "$deposit_costs" "$redemption_costs" >/dev/null
}
test -f "$submission" && test ! -L "$submission"
node scripts/check-mainnet-toolchain.mjs >/dev/null
temporary=$(mktemp -d -p /dev/shm usdom-closed-redemption.XXXXXXXX); chmod 0700 "$temporary"
cleanup() { local status=${1:-$?}; trap - EXIT HUP INT TERM; unset USDOM_CLOSED_MAINNET_REDEMPTION_RAW_FILE; rm -rf -- "$temporary"; exit "$status"; }
trap 'cleanup $?' EXIT; trap 'cleanup 129' HUP; trap 'cleanup 130' INT; trap 'cleanup 143' TERM
readiness="$temporary/readiness.json"; candidate="$temporary/candidate.json"
node scripts/check-mainnet-readiness.mjs real-funds >"$readiness"
jq -e '.ready==true and .blockerCount==0' "$readiness" >/dev/null
node scripts/check-closed-mainnet-redemption.mjs "$submission" >"$candidate"
if [[ -e $package ]]; then cmp -s "$candidate" "$package"; else node scripts/install-private-file-new-stdin.mjs --json "$package" <"$candidate"; fi
node scripts/check-closed-mainnet-redemption.mjs "$submission" "$package" >/dev/null
release_sha=$(sha256sum config/proof-reserve.unconfigured.json|awk '{print $1}')
verifier_sha=$(sha256sum config/finalized-burn-verifier.unconfigured.json|awk '{print $1}')
node scripts/check-closed-mainnet-redemption-release.mjs "$submission" "$package" config/proof-reserve.unconfigured.json "$release_sha" "$verifier_sha" >/dev/null
package_sha=$(sha256sum "$package"|awk '{print $1}'); reserve=$(jq -er '.reserve' "$package")
recipient=$(jq -er '.recipient' "$package"); burn_id=$(jq -er '.burnId' "$package")
request_id=$(jq -er '.requestId' "$package"); test "$(jq -er '.amountBaseUnits' "$package")" = 1000000
valid_until=$(jq -er '.burn.validUntil' "$submission")
zero32=0x$(printf '00%.0s' {1..32})
check_burn_unused() {
  local rpc=$1
  test "$(cast call "$reserve" 'paidBurns(bytes32)(bool)' "$burn_id" --block "$consensus_block" --rpc-url "$rpc")" = false
  test "$(cast call "$reserve" 'paidRequests(bytes32)(bool)' "$request_id" --block "$consensus_block" --rpc-url "$rpc")" = false
  test "$(cast call "$reserve" 'provedBurnDebts(bytes32)(bytes32)' "$burn_id" --block "$consensus_block" --rpc-url "$rpc")" = "$zero32"
  test "$(cast call "$reserve" 'provedRequestBurns(bytes32)(bytes32)' "$request_id" --block "$consensus_block" --rpc-url "$rpc")" = "$zero32"
}
check_permanent_burn_debt() {
  local rpc=$1 statement debt request_burn
  statement=$(cast call "$reserve" 'provedBurnStatements(bytes32)(bytes32)' "$burn_id" --block "$consensus_block" --rpc-url "$rpc")
  debt=$(cast call "$reserve" 'provedBurnDebts(bytes32)(bytes32)' "$burn_id" --block "$consensus_block" --rpc-url "$rpc")
  request_burn=$(cast call "$reserve" 'provedRequestBurns(bytes32)(bytes32)' "$request_id" --block "$consensus_block" --rpc-url "$rpc")
  test "$statement" != "$zero32"; test "$debt" != "$zero32"; test "${request_burn,,}" = "${burn_id,,}"
}
token=$(jq -er '.token' config/proof-reserve.unconfigured.json)
reserve_code_hash=$(jq -er '.reserveRuntimeCodeHash' config/proof-reserve.unconfigured.json)
token_code_hash=$(jq -er '.tokenCodeHash' config/proof-reserve.unconfigured.json)
reserve_config_hash=$(jq -er '.reserveConfigHash' config/proof-reserve.unconfigured.json)
readonly mainnet_genesis=0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3
consensus_block=''
consensus_hash=''
consensus_timestamp=''
consensus_base_fee=''
rpc_consensus_snapshot() {
  local chain1 chain2 genesis1 genesis2 number1 number2 hash1 hash2 time1 time2 base1 base2
  chain1=$(cast chain-id --rpc-url "$rpc1"); chain2=$(cast chain-id --rpc-url "$rpc2")
  test "$chain1" = 1; test "$chain2" = 1
  genesis1=$(cast block 0 --field hash --rpc-url "$rpc1" | tr '[:upper:]' '[:lower:]')
  genesis2=$(cast block 0 --field hash --rpc-url "$rpc2" | tr '[:upper:]' '[:lower:]')
  test "$genesis1" = "$mainnet_genesis"; test "$genesis2" = "$mainnet_genesis"
  number1=$(cast block finalized --field number --rpc-url "$rpc1")
  number2=$(cast block finalized --field number --rpc-url "$rpc2")
  test "$number1" = "$number2"
  hash1=$(cast block "$number1" --field hash --rpc-url "$rpc1" | tr '[:upper:]' '[:lower:]')
  hash2=$(cast block "$number2" --field hash --rpc-url "$rpc2" | tr '[:upper:]' '[:lower:]')
  test "$hash1" = "$hash2"
  time1=$(cast block "$number1" --field timestamp --rpc-url "$rpc1")
  time2=$(cast block "$number2" --field timestamp --rpc-url "$rpc2")
  base1=$(cast block "$number1" --field baseFeePerGas --rpc-url "$rpc1")
  base2=$(cast block "$number2" --field baseFeePerGas --rpc-url "$rpc2")
  test "$time1" = "$time2"; test "$base1" = "$base2"
  for rpc in "$rpc1" "$rpc2"; do
    test "$(cast codehash "$reserve" --block "$number1" --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" = "${reserve_code_hash,,}"
    test "$(cast codehash "$token" --block "$number1" --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" = "${token_code_hash,,}"
    test "$(cast call "$reserve" 'reserveConfigHash()(bytes32)' --block "$number1" --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" = "${reserve_config_hash,,}"
  done
  # Re-read the exact numeric block after code/state queries to close the TOCTOU window.
  test "$(cast block "$number1" --field hash --rpc-url "$rpc1" | tr '[:upper:]' '[:lower:]')" = "$hash1"
  test "$(cast block "$number1" --field hash --rpc-url "$rpc2" | tr '[:upper:]' '[:lower:]')" = "$hash1"
  consensus_block=$number1; consensus_hash=$hash1; consensus_timestamp=$time1; consensus_base_fee=$base1
}
signer=$(cast wallet address --ledger); test "$signer" = "$recipient"
rpc_consensus_snapshot
base_nonce=''
for index in 0 1; do
  rpc_consensus_snapshot
  name=$(jq -er ".transactions[$index].name" "$package"); to=$(jq -er ".transactions[$index].to" "$package")
  data=$(jq -er ".transactions[$index].data" "$package"); raw_file="$evidence/closed-redemption-$index-raw.txt"
  validation="$evidence/closed-redemption-$index-validation.json"; receipt_record="$evidence/closed-redemption-$index-receipt.json"
  finality_record="$evidence/closed-redemption-$index-finality.json"
  if [[ -z $base_nonce ]]; then
    if [[ -f $validation ]]; then base_nonce=$(jq -er '.nonce' "$validation");
    else n1=$(cast nonce "$signer" --block pending --rpc-url "$rpc1"); n2=$(cast nonce "$signer" --block pending --rpc-url "$rpc2"); test "$n1" = "$n2"; base_nonce=$n1; fi
  fi
  nonce=$(node -e 'process.stdout.write(String(BigInt(process.argv[1])+BigInt(process.argv[2])))' "$base_nonce" "$index")
  if [[ -e $raw_file && ! -e $validation ]]; then
    export USDOM_CLOSED_MAINNET_REDEMPTION_RAW_FILE=$raw_file
    node scripts/check-closed-mainnet-redemption.mjs "$submission" "$package" "$index" "$nonce" >"$candidate"
    node scripts/install-private-file-new-stdin.mjs --json "$validation" <"$candidate"
    unset USDOM_CLOSED_MAINNET_REDEMPTION_RAW_FILE
  fi
  if [[ -f $receipt_record ]]; then
    test -f "$validation" && test ! -L "$validation" && test "$(stat -c '%a:%h' "$validation")" = '600:1'
    test "$(jq -er '.nonce' "$validation")" = "$nonce"
    if [[ -e $raw_file ]]; then
      export USDOM_CLOSED_MAINNET_REDEMPTION_RAW_FILE=$raw_file
      node scripts/check-closed-mainnet-redemption.mjs "$submission" "$package" "$index" "$nonce" | cmp -s - "$validation"
      unset USDOM_CLOSED_MAINNET_REDEMPTION_RAW_FILE
    fi
  else
    if [[ ! -e $raw_file ]] && ((index==1)); then
      pending1=$(cast call "$reserve" 'pendingWithdrawals(bytes32)(bytes32,bytes32,uint64,uint64,uint64,uint64,bytes32,bytes32)' "$burn_id" --block "$consensus_block" --rpc-url "$rpc1")
      pending2=$(cast call "$reserve" 'pendingWithdrawals(bytes32)(bytes32,bytes32,uint64,uint64,uint64,uint64,bytes32,bytes32)' "$burn_id" --block "$consensus_block" --rpc-url "$rpc2")
      test "$pending1" = "$pending2"; ready_at=$(printf '%s\n' "$pending1"|sed -n '3{s/ .*//;p;}')
      now1=$consensus_timestamp; now2=$consensus_timestamp
      node -e 'if(BigInt(process.argv[1])<BigInt(process.argv[3])||BigInt(process.argv[2])<BigInt(process.argv[3]))process.exit(75)' "$now1" "$now2" "$ready_at"
    fi
    if ((index==1)); then
      for rpc in "$rpc1" "$rpc2"; do
        check_permanent_burn_debt "$rpc"
        test "$(cast call "$reserve" 'paidBurns(bytes32)(bool)' "$burn_id" --block "$consensus_block" --rpc-url "$rpc")" = false
        test "$(cast call "$reserve" 'paidRequests(bytes32)(bool)' "$request_id" --block "$consensus_block" --rpc-url "$rpc")" = false
      done
      token1=$(cast call "$reserve" 'token()(address)' --block "$consensus_block" --rpc-url "$rpc1"); token2=$(cast call "$reserve" 'token()(address)' --block "$consensus_block" --rpc-url "$rpc2")
      test "${token1,,}" = "${token,,}"; test "${token2,,}" = "${token,,}"
      if [[ -e $payout_baseline ]]; then
        test "$(stat -c '%a:%h' "$payout_baseline")" = '600:1'
        jq -e --arg packageSha256 "$package_sha" --arg token "$token" --arg reserve "$reserve" --arg recipient "$recipient" '.schema=="usdom-closed-mainnet-redemption-payout-baseline-v1" and .chainId=="1" and .packageSha256==$packageSha256 and (.token|ascii_downcase)==($token|ascii_downcase) and (.reserve|ascii_downcase)==($reserve|ascii_downcase) and (.recipient|ascii_downcase)==($recipient|ascii_downcase) and ([.recipientBalanceBaseUnits,.reserveBalanceBaseUnits,.totalReleasedBaseUnits,.outstandingBaseUnits,.totalProvedDebtBaseUnits,.snapshotBlockNumber]|all(test("^(0|[1-9][0-9]*)$"))) and .totalProvedDebtBaseUnits=="1000000" and (.snapshotBlockHash|test("^0x[0-9a-fA-F]{64}$"))' "$payout_baseline" >/dev/null
        baseline_block=$(jq -er '.snapshotBlockNumber' "$payout_baseline"); baseline_hash=$(jq -er '.snapshotBlockHash|ascii_downcase' "$payout_baseline")
        for rpc in "$rpc1" "$rpc2"; do
          test "$(cast block "$baseline_block" --field hash --rpc-url "$rpc" | tr '[:upper:]' '[:lower:]')" = "$baseline_hash"
          test "$(cast call "$token" 'balanceOf(address)(uint256)' "$recipient" --block "$baseline_block" --rpc-url "$rpc")" = "$(jq -er '.recipientBalanceBaseUnits' "$payout_baseline")"
          test "$(cast call "$token" 'balanceOf(address)(uint256)' "$reserve" --block "$baseline_block" --rpc-url "$rpc")" = "$(jq -er '.reserveBalanceBaseUnits' "$payout_baseline")"
          test "$(cast call "$reserve" 'totalReleased()(uint256)' --block "$baseline_block" --rpc-url "$rpc")" = "$(jq -er '.totalReleasedBaseUnits' "$payout_baseline")"
          test "$(cast call "$reserve" 'outstanding()(uint256)' --block "$baseline_block" --rpc-url "$rpc")" = "$(jq -er '.outstandingBaseUnits' "$payout_baseline")"
          test "$(cast call "$reserve" 'totalProvedDebtAmount()(uint256)' --block "$baseline_block" --rpc-url "$rpc")" = 1000000
        done
      else
        balance1=$(cast call "$token" 'balanceOf(address)(uint256)' "$recipient" --block "$consensus_block" --rpc-url "$rpc1"); balance2=$(cast call "$token" 'balanceOf(address)(uint256)' "$recipient" --block "$consensus_block" --rpc-url "$rpc2")
        reserve1=$(cast call "$token" 'balanceOf(address)(uint256)' "$reserve" --block "$consensus_block" --rpc-url "$rpc1"); reserve2=$(cast call "$token" 'balanceOf(address)(uint256)' "$reserve" --block "$consensus_block" --rpc-url "$rpc2")
        released1=$(cast call "$reserve" 'totalReleased()(uint256)' --block "$consensus_block" --rpc-url "$rpc1"); released2=$(cast call "$reserve" 'totalReleased()(uint256)' --block "$consensus_block" --rpc-url "$rpc2")
        outstanding1=$(cast call "$reserve" 'outstanding()(uint256)' --block "$consensus_block" --rpc-url "$rpc1"); outstanding2=$(cast call "$reserve" 'outstanding()(uint256)' --block "$consensus_block" --rpc-url "$rpc2")
        debt1=$(cast call "$reserve" 'totalProvedDebtAmount()(uint256)' --block "$consensus_block" --rpc-url "$rpc1"); debt2=$(cast call "$reserve" 'totalProvedDebtAmount()(uint256)' --block "$consensus_block" --rpc-url "$rpc2")
        test "$balance1" = "$balance2"; test "$reserve1" = "$reserve2"; test "$released1" = "$released2"; test "$outstanding1" = "$outstanding2"; test "$debt1" = "$debt2"; test "$debt1" = 1000000
        jq -n --arg packageSha256 "$package_sha" --arg token "$token" --arg reserve "$reserve" --arg recipient "$recipient" --arg balance "$balance1" --arg reserveBalance "$reserve1" --arg totalReleased "$released1" --arg outstanding "$outstanding1" --arg totalProvedDebt "$debt1" --arg snapshotBlockNumber "$consensus_block" --arg snapshotBlockHash "$consensus_hash" '{schema:"usdom-closed-mainnet-redemption-payout-baseline-v1",chainId:"1",packageSha256:$packageSha256,token:$token,reserve:$reserve,recipient:$recipient,recipientBalanceBaseUnits:$balance,reserveBalanceBaseUnits:$reserveBalance,totalReleasedBaseUnits:$totalReleased,outstandingBaseUnits:$outstanding,totalProvedDebtBaseUnits:$totalProvedDebt,observedAt:"finalized",rpcCount:2,snapshotBlockNumber:$snapshotBlockNumber,snapshotBlockHash:$snapshotBlockHash}' | node scripts/install-private-file-new-stdin.mjs --json "$payout_baseline"
      fi
    fi
    if [[ ! -e $raw_file ]]; then
     for rpc in "$rpc1" "$rpc2"; do test "$(cast nonce "$signer" --block pending --rpc-url "$rpc")" = "$nonce"; done
     estimate1=$(cast estimate "$to" "$data" --from "$signer" --value 0 --rpc-url "$rpc1")
    estimate2=$(cast estimate "$to" "$data" --from "$signer" --value 0 --rpc-url "$rpc2")
    gas=$(node -e 'let a=BigInt(process.argv[1]),b=BigInt(process.argv[2]),m=a>b?a:b,g=(m*125n+99n)/100n;if(g>2500000n)process.exit(1);process.stdout.write(String(g))' "$estimate1" "$estimate2")
    base1=$consensus_base_fee; base2=$consensus_base_fee
    test "$base1" = "$base2"
    fee=$(node -e 'let a=BigInt(process.argv[1]),b=BigInt(process.argv[2]),g=BigInt(process.argv[3]),f=a>b?a:b;for(let i=0;i<12;i++)f=(f*9n+7n)/8n;f+=2000000000n;if(f>100000000000n||f*g>100000000000000000n)process.exit(1);process.stdout.write(String(f))' "$base1" "$base2" "$gas")
      proposed_cost=$(node -e 'process.stdout.write(String(BigInt(process.argv[1])*BigInt(process.argv[2])))' "$gas" "$fee")
      check_pilot_budget "$proposed_cost"
      gas_balance1=$(cast balance "$signer" --block pending --rpc-url "$rpc1"); gas_balance2=$(cast balance "$signer" --block pending --rpc-url "$rpc2")
      node scripts/check-pilot-gas-funding.mjs "$gas_balance1" "$gas_balance2" "$(node -e 'process.stdout.write(String(BigInt(process.argv[1])*BigInt(process.argv[2])))' "$gas" "$fee")" >/dev/null
      read -r -p "Digite AUTORIZO ASSINAR RESGATE MAINNET ETAPA $index para assinar $name: " answer; test "$answer" = "AUTORIZO ASSINAR RESGATE MAINNET ETAPA $index"
      rpc_consensus_snapshot
      for rpc in "$rpc1" "$rpc2"; do
        test "$(cast chain-id --rpc-url "$rpc")" = 1
        test "$(cast nonce "$signer" --block "$consensus_block" --rpc-url "$rpc")" = "$nonce"
        test "$(cast nonce "$signer" --block pending --rpc-url "$rpc")" = "$nonce"
      done
      live_base1=$consensus_base_fee
      live_time1=$consensus_timestamp; live_time2=$consensus_timestamp
      node -e 'let f=BigInt(process.argv[1]);for(let i=0;i<12;i++)f=(f*9n+7n)/8n;f+=2000000000n;if(BigInt(process.argv[2])<f||BigInt(process.argv[3])+204n>BigInt(process.argv[5])||BigInt(process.argv[4])+204n>BigInt(process.argv[5]))process.exit(1)' "$live_base1" "$fee" "$live_time1" "$live_time2" "$valid_until"
      data_hash=$(jq -er ".transactions[$index].dataKeccak256" "$package")
      printf 'LEDGER CLEAR REVIEW action=%s chainId=1 signer=%s to=%s nonce=%s value=0 selector=%s dataHash=%s gas=%s maxFee=%s priorityFee=2000000000 validUntil=%s\n' \
        "$name" "$signer" "$to" "$nonce" "${data:0:10}" "$data_hash" "$gas" "$fee" "$valid_until"
      read -r -p "Digite CONFIRMO CLEAR SIGNING RESGATE ETAPA $index somente se o Ledger exibir a mesma ação; blind signing é proibido: " clear_answer
      test "$clear_answer" = "CONFIRMO CLEAR SIGNING RESGATE ETAPA $index"
      raw_candidate="$temporary/raw-$index.txt"
      cast mktx "$to" --chain 1 --from "$signer" --nonce "$nonce" --value 0 --data "$data" --gas-limit "$gas" --gas-price "$fee" --priority-gas-price 2000000000 --ledger --rpc-url "$rpc1" | tr '[:upper:]' '[:lower:]' >"$raw_candidate"
      chmod 0600 "$raw_candidate"; export USDOM_CLOSED_MAINNET_REDEMPTION_RAW_FILE=$raw_candidate
      node scripts/check-closed-mainnet-redemption.mjs "$submission" "$package" "$index" "$nonce" >"$candidate"
      test "$(jq -er '.from' "$candidate")" = "$signer"
      node scripts/install-private-file-new-stdin.mjs "$raw_file" <"$raw_candidate"
      node scripts/install-private-file-new-stdin.mjs --json "$validation" <"$candidate"; unset USDOM_CLOSED_MAINNET_REDEMPTION_RAW_FILE
    fi
    test "$(sha256sum "$package"|awk '{print $1}')" = "$package_sha"
    expected_hash=$(jq -er '.transactionHash|ascii_downcase' "$validation")
    finalized1=$(cast nonce "$signer" --block "$consensus_block" --rpc-url "$rpc1"); finalized2=$(cast nonce "$signer" --block "$consensus_block" --rpc-url "$rpc2")
    current1=$(cast nonce "$signer" --block pending --rpc-url "$rpc1"); current2=$(cast nonce "$signer" --block pending --rpc-url "$rpc2")
    known1=$(cast tx "$expected_hash" --field hash --rpc-url "$rpc1" 2>/dev/null || true)
    known2=$(cast tx "$expected_hash" --field hash --rpc-url "$rpc2" 2>/dev/null || true)
    nonce_action=$(node scripts/check-pilot-nonce-recovery.mjs "$nonce" "$finalized1" "$current1" "$finalized2" "$current2" "$expected_hash" "$known1" "$known2")
    if test "$nonce_action" = publish; then
      if ((index==0)); then for rpc in "$rpc1" "$rpc2"; do check_burn_unused "$rpc"; done; fi
      maximum_cost=$(jq -er '.maximumCost' "$validation"); gas_balance1=$(cast balance "$signer" --block pending --rpc-url "$rpc1"); gas_balance2=$(cast balance "$signer" --block pending --rpc-url "$rpc2")
      node scripts/check-pilot-gas-funding.mjs "$gas_balance1" "$gas_balance2" "$maximum_cost" >/dev/null
      check_pilot_budget
      read -r -p "Digite AUTORIZO TRANSMITIR RESGATE MAINNET ETAPA $index para publicar: " answer; test "$answer" = "AUTORIZO TRANSMITIR RESGATE MAINNET ETAPA $index"
      rpc_consensus_snapshot
      for rpc in "$rpc1" "$rpc2"; do
        test "$(cast chain-id --rpc-url "$rpc")" = 1
        test "$(cast nonce "$signer" --block "$consensus_block" --rpc-url "$rpc")" = "$nonce"
        test "$(cast nonce "$signer" --block pending --rpc-url "$rpc")" = "$nonce"
      done
      signed_fee=$(jq -er '.maxFeePerGas' "$validation")
      live_base1=$consensus_base_fee
      live_time1=$consensus_timestamp; live_time2=$consensus_timestamp
      node -e 'let f=BigInt(process.argv[1]);for(let i=0;i<12;i++)f=(f*9n+7n)/8n;f+=2000000000n;if(BigInt(process.argv[2])<f||BigInt(process.argv[3])+204n>BigInt(process.argv[5])||BigInt(process.argv[4])+204n>BigInt(process.argv[5]))process.exit(1)' "$live_base1" "$signed_fee" "$live_time1" "$live_time2" "$valid_until"
      tx_hash=$(node scripts/publish-private-raw-transaction.mjs "$raw_file" "$rpc1"); test "${tx_hash,,}" = "$expected_hash"
    elif test "$nonce_action" = recover-receipt; then
      tx_hash=$expected_hash
    else
      exit 76
    fi
    cast receipt "$tx_hash" --confirmations 2 --json --rpc-url "$rpc1" >"$candidate"
    jq -e --arg tx "$tx_hash" --arg from "$signer" --arg to "$to" '.status=="0x1" and (.transactionHash|ascii_downcase)==($tx|ascii_downcase) and (.from|ascii_downcase)==($from|ascii_downcase) and (.to|ascii_downcase)==($to|ascii_downcase)' "$candidate" >/dev/null
    node scripts/install-private-file-new-stdin.mjs --json "$receipt_record" <"$candidate"
  fi
  tx_hash=$(jq -er '.transactionHash' "$validation"); block=$(jq -er '.blockNumber' "$receipt_record"); hash=$(jq -er '.blockHash|ascii_downcase' "$receipt_record")
  receipt_gas=$(jq -er '.gasUsed' "$receipt_record"); receipt_price=$(jq -er '.effectiveGasPrice' "$receipt_record")
  rpc_consensus_snapshot
  for rpc in "$rpc1" "$rpc2"; do
    cast receipt "$tx_hash" --json --rpc-url "$rpc" >"$candidate"
    jq -e --arg tx "$tx_hash" --arg from "$signer" --arg to "$to" --arg block "$block" --arg hash "$hash" --arg gas "$receipt_gas" --arg price "$receipt_price" '.status=="0x1" and (.transactionHash|ascii_downcase)==($tx|ascii_downcase) and (.from|ascii_downcase)==($from|ascii_downcase) and (.to|ascii_downcase)==($to|ascii_downcase) and .blockNumber==$block and (.blockHash|ascii_downcase)==$hash and .gasUsed==$gas and .effectiveGasPrice==$price' "$candidate" >/dev/null
    finalized=$consensus_block; node -e 'if(BigInt(process.argv[1])>BigInt(process.argv[2]))process.exit(1)' "$block" "$finalized"
    test "$(cast block "$block" --field hash --rpc-url "$rpc"|tr '[:upper:]' '[:lower:]')" = "$hash"
  done
  cost=$(node scripts/check-pilot-receipt-cost.mjs "$(jq -er '.gasUsed' "$receipt_record")" "$(jq -er '.effectiveGasPrice' "$receipt_record")" "$(jq -er '.maximumCost' "$validation")")
  if [[ ! -e $finality_record ]]; then
    jq -n --arg tx "$tx_hash" --arg block "$block" --arg hash "$hash" --argjson cost "$cost" '{schema:"usdom-closed-mainnet-redemption-finality-v1",transactionHash:$tx,blockNumber:$block,blockHash:$hash,finalizedRpcCount:2}+ $cost' | node scripts/install-private-file-new-stdin.mjs --json "$finality_record"
  else
    test -f "$finality_record" && test ! -L "$finality_record" && test "$(stat -c '%a:%h' "$finality_record")" = '600:1'
    jq -e --arg tx "$tx_hash" --arg block "$block" --arg hash "$hash" --argjson cost "$cost" '.schema=="usdom-closed-mainnet-redemption-finality-v1" and (.transactionHash|ascii_downcase)==($tx|ascii_downcase) and .blockNumber==$block and (.blockHash|ascii_downcase)==$hash and .finalizedRpcCount==2 and .gasUsed==$cost.gasUsed and .effectiveGasPrice==$cost.effectiveGasPrice and .actualCost==$cost.actualCost and .maximumCost==$cost.maximumCost' "$finality_record" >/dev/null
  fi
  rm -f -- "$raw_file"
done
rpc_consensus_snapshot
for rpc in "$rpc1" "$rpc2"; do
  test "$(cast call "$reserve" 'paidBurns(bytes32)(bool)' "$burn_id" --block "$consensus_block" --rpc-url "$rpc")" = true
  test "$(cast call "$reserve" 'paidRequests(bytes32)(bool)' "$request_id" --block "$consensus_block" --rpc-url "$rpc")" = true
  check_permanent_burn_debt "$rpc"
  before=$(jq -er '.recipientBalanceBaseUnits' "$payout_baseline")
  expected=$(node -e 'process.stdout.write(String(BigInt(process.argv[1])+1000000n))' "$before")
  test "$(cast call "$token" 'balanceOf(address)(uint256)' "$recipient" --block "$consensus_block" --rpc-url "$rpc")" = "$expected"
  reserve_before=$(jq -er '.reserveBalanceBaseUnits' "$payout_baseline"); released_before=$(jq -er '.totalReleasedBaseUnits' "$payout_baseline"); outstanding_before=$(jq -er '.outstandingBaseUnits' "$payout_baseline"); debt_before=$(jq -er '.totalProvedDebtBaseUnits' "$payout_baseline")
  reserve_after=$(node -e 'let v=BigInt(process.argv[1]);if(v<1000000n)process.exit(1);process.stdout.write(String(v-1000000n))' "$reserve_before")
  released_after=$(node -e 'process.stdout.write(String(BigInt(process.argv[1])+1000000n))' "$released_before")
  outstanding_after=$(node -e 'let v=BigInt(process.argv[1]);if(v<1000000n)process.exit(1);process.stdout.write(String(v-1000000n))' "$outstanding_before")
  debt_after=$(node -e 'let v=BigInt(process.argv[1]);if(v<1000000n)process.exit(1);process.stdout.write(String(v-1000000n))' "$debt_before")
  test "$(cast call "$token" 'balanceOf(address)(uint256)' "$reserve" --block "$consensus_block" --rpc-url "$rpc")" = "$reserve_after"
  test "$(cast call "$reserve" 'totalReleased()(uint256)' --block "$consensus_block" --rpc-url "$rpc")" = "$released_after"
  test "$(cast call "$reserve" 'outstanding()(uint256)' --block "$consensus_block" --rpc-url "$rpc")" = "$outstanding_after"
  test "$(cast call "$reserve" 'totalProvedDebtAmount()(uint256)' --block "$consensus_block" --rpc-url "$rpc")" = "$debt_after"
done
baseline_sha=$(sha256sum "$payout_baseline"|awk '{print $1}'); before=$(jq -er '.recipientBalanceBaseUnits' "$payout_baseline"); after=$(node -e 'process.stdout.write(String(BigInt(process.argv[1])+1000000n))' "$before")
execution="$evidence/closed-mainnet-redemption-execution.json"; execution_candidate=$readiness
jq -n --arg packageSha256 "$package_sha" --arg burnId "$burn_id" --arg requestId "$request_id" --arg token "$token" --arg recipient "$recipient" --arg baselineSha256 "$baseline_sha" --arg before "$before" --arg after "$after" --arg reserveBefore "$reserve_before" --arg reserveAfter "$reserve_after" --arg releasedBefore "$released_before" --arg releasedAfter "$released_after" --arg outstandingBefore "$outstanding_before" --arg outstandingAfter "$outstanding_after" --arg debtBefore "$debt_before" --arg debtAfter "$debt_after" --arg snapshotBlockNumber "$consensus_block" --arg snapshotBlockHash "$consensus_hash" '{schema:"usdom-closed-mainnet-redemption-execution-v1",chainId:"1",packageSha256:$packageSha256,burnId:$burnId,requestId:$requestId,amountBaseUnits:"1000000",token:$token,recipient:$recipient,payoutBaselineSha256:$baselineSha256,recipientBalanceBefore:$before,recipientBalanceAfter:$after,reserveBalanceBefore:$reserveBefore,reserveBalanceAfter:$reserveAfter,totalReleasedBefore:$releasedBefore,totalReleasedAfter:$releasedAfter,outstandingBefore:$outstandingBefore,outstandingAfter:$outstandingAfter,totalProvedDebtBefore:$debtBefore,totalProvedDebtAfter:$debtAfter,steps:2,finalizedAcrossRpcCount:2,outputLast:true,snapshotBlockNumber:$snapshotBlockNumber,snapshotBlockHash:$snapshotBlockHash}' >"$execution_candidate"
node scripts/check-closed-mainnet-payout-evidence.mjs "$payout_baseline" "$execution_candidate" "$package" >/dev/null
if [[ -e $execution ]]; then cmp -s "$execution_candidate" "$execution"; else node scripts/install-private-file-new-stdin.mjs --json "$execution" <"$execution_candidate"; fi
