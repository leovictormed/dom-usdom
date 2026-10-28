#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077
export LANG=C LC_ALL=C TZ=UTC RUST_BACKTRACE=0
unset NODE_OPTIONS NODE_PATH NODE_DEBUG SSLKEYLOGFILE LD_PRELOAD LD_LIBRARY_PATH \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
export PATH=/home/leonardov/.foundry/bin:/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin:/usr/bin:/bin

test "$#" -eq 0 || { echo 'usage: npm run --silent execute:reserve-resume' >&2; exit 64; }
test -t 0 && test -t 1 || { echo 'reserve resume requires an interactive hardware ceremony' >&2; exit 1; }
[[ -c /dev/tty ]] || { echo 'reserve resume terminal is unavailable' >&2; exit 1; }
exec </dev/null
: "${USDOM_MAINNET_DEPLOYMENT_PACKAGE:?required}"
: "${USDOM_CONTROL_EVIDENCE_DIRECTORY:?required}"
: "${USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:?required}"
: "${USDOM_SAFE_PACKAGE:?required}"
: "${USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG:?required}"
: "${USDOM_ONEKEY_IOS_PHYSICAL_EVIDENCE_DIRECTORY:?required}"
: "${USDOM_RESERVE_RESUME_RELAYER_POLICY:?required}"
for b in cast jq node timeout sleep sha256sum flock; do command -v "$b" >/dev/null; done
node scripts/check-mainnet-toolchain.mjs

for authority in "$USDOM_MAINNET_DEPLOYMENT_PACKAGE" "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "$USDOM_SAFE_PACKAGE" "$PWD/config/proof-reserve.unconfigured.json"; do
  node scripts/check-direct-strict-json-file.mjs "$authority"
done

test -d "$USDOM_CONTROL_EVIDENCE_DIRECTORY"
test ! -L "$USDOM_CONTROL_EVIDENCE_DIRECTORY"
test "$(stat -c '%u:%a' "$USDOM_CONTROL_EVIDENCE_DIRECTORY")" = "$(id -u):700"
exec 9<"$USDOM_CONTROL_EVIDENCE_DIRECTORY"
flock -n 9 || { printf '%s\n' 'Another reserve-resume ceremony holds the evidence-directory lock.' >&2; exit 75; }
resume_broadcast_state=clean
authority_snapshot_dir=''
authority_snapshot_identity=''
finish() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  for private_temporary in "${private_input:-}" "${prepared:-}" "${calldata_file:-}"; do
    if [[ -n $private_temporary && -f $private_temporary && ! -L $private_temporary ]]; then
      rm -f -- "$private_temporary"
    fi
  done
  if [[ -n $authority_snapshot_dir ]]; then
    if [[ $(stat -c '%u:%d:%i:%a' -- "$authority_snapshot_dir" 2>/dev/null) == "$authority_snapshot_identity" ]]; then
      rm -rf -- "$authority_snapshot_dir" || { (( status != 0 )) || status=1; }
    else
      (( status != 0 )) || status=1
    fi
  fi
  if [[ $resume_broadcast_state != clean ]] && (( status != 0 )); then
    printf '%s\n' 'Reserve resume transaction outcome is unresolved; revalidate the exact hash, receipt and payer nonce before any replacement.' >&2
    status=80
  fi
  exit "$status"
}
trap 'finish $?' EXIT; trap 'finish 129' HUP; trap 'finish 130' INT; trap 'finish 143' TERM

authority_snapshot_dir=$(mktemp -d -p "$USDOM_CONTROL_EVIDENCE_DIRECTORY" reserve-resume-authorities.XXXXXXXX)
chmod 0700 "$authority_snapshot_dir"
authority_snapshot_identity=$(stat -c '%u:%d:%i:%a' -- "$authority_snapshot_dir")
snapshot_authority() {
  local source=$1 destination=$2
  node scripts/check-direct-strict-json-file.mjs --stdout "$source" >"$destination"
  chmod 0600 "$destination"
  node scripts/check-direct-strict-json-file.mjs "$destination"
}
snapshot_authority "$USDOM_MAINNET_DEPLOYMENT_PACKAGE" "$authority_snapshot_dir/deployment.json"
snapshot_authority "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "$authority_snapshot_dir/rpc-sources.json"
snapshot_authority "$USDOM_SAFE_PACKAGE" "$authority_snapshot_dir/safe-package.json"
snapshot_authority "$PWD/config/proof-reserve.unconfigured.json" "$authority_snapshot_dir/reserve-config.json"
snapshot_authority "$PWD/config/mainnet-preflight-rpc-catalog.json" "$authority_snapshot_dir/rpc-catalog.json"
snapshot_authority "$USDOM_RESERVE_RESUME_RELAYER_POLICY" "$authority_snapshot_dir/relayer-policy.json"
USDOM_MAINNET_DEPLOYMENT_PACKAGE="$authority_snapshot_dir/deployment.json"
USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE="$authority_snapshot_dir/rpc-sources.json"
USDOM_SAFE_PACKAGE="$authority_snapshot_dir/safe-package.json"
reserve_config="$authority_snapshot_dir/reserve-config.json"
rpc_catalog="$authority_snapshot_dir/rpc-catalog.json"
relayer_policy="$authority_snapshot_dir/relayer-policy.json"

reserve=$(jq -er '.deployments[3].expectedAddress' "$USDOM_MAINNET_DEPLOYMENT_PACKAGE")
governance=$(jq -er '.governance' "$reserve_config")
delay=$(jq -er '.governanceDelaySeconds' "$reserve_config")
test "$delay" -ge 172800
export USDOM_GOVERNANCE_DELAY_SECONDS=$delay
mapfile -t rpcs < <(jq -er '.[].url' "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE")
test "${#rpcs[@]}" -ge 2
for rpc in "${rpcs[@]}"; do test "$(cast chain-id --rpc-url "$rpc")" = 1; done

state() {
  local rpc=$1
  jq -cn --argjson paused "$(cast call "$reserve" 'paused()(bool)' --rpc-url "$rpc")" \
    --arg ready "$(cast call "$reserve" 'resumeReadyAt()(uint64)' --rpc-url "$rpc")" \
    --arg epoch "$(cast call "$reserve" 'queueEpoch()(uint64)' --rpc-url "$rpc")" \
    --arg generation "$(cast call "$reserve" 'pilotAuthorizationGeneration()(uint64)' --rpc-url "$rpc")" \
    --arg pendingCount "$(cast call "$reserve" 'pendingCount()(uint256)' --rpc-url "$rpc")" \
    --arg totalPending "$(cast call "$reserve" 'totalPendingAmount()(uint256)' --rpc-url "$rpc")" \
    --arg provedDebt "$(cast call "$reserve" 'totalProvedDebtAmount()(uint256)' --rpc-url "$rpc")" \
    --argjson depositsClosed "$(cast call "$reserve" 'depositsClosed()(bool)' --rpc-url "$rpc")" \
    --argjson shutdown "$(cast call "$reserve" 'gracefullyShutdown()(bool)' --rpc-url "$rpc")" \
    --arg config "$(cast call "$reserve" 'reserveConfigHash()(bytes32)' --rpc-url "$rpc")" \
    --argjson healthy "$(cast call "$reserve" 'controlPlaneHealthy()(bool)' --rpc-url "$rpc")" \
    '{paused:$paused,resumeReadyAt:$ready,queueEpoch:$epoch,pilotAuthorizationGeneration:$generation,pendingCount:$pendingCount,totalPendingAmount:$totalPending,totalProvedDebtAmount:$provedDebt,depositsClosed:$depositsClosed,gracefullyShutdown:$shutdown,reserveConfigHash:($config|ascii_downcase),controlPlaneHealthy:$healthy}'
}

execute_step() {
  local step=$1 signature=$2 output=$3 before calldata nonce safe_hash safe_hash2 safe_hash_call calldata_hash signer1 signer2 observed sig1 sig2 signatures exec_data target gas_limit gas_price maximum_gas_cost raw journal txhash receipt receipt2 canonical1 canonical2 block transaction_index event_log_index finalized observation event_topic event_count payer_nonce n1 n2 f1 f2 exec_data_hash receipt_final1 receipt_final2 canonical_final1 canonical_final2 finalized_recheck1 finalized_recheck2 private_input='' prepared='' calldata_file='' private_estimate signing_hash payer_signature expected_txhash reserve_config_hash authorization_hash exec_selector private_temporary
  journal="$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-$step-raw-journal.json"
  receipt_persisted="$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-$step-receipt.json"
  if [[ -e $output ]]; then
    test -e "$journal"; test -e "$receipt_persisted"
    node scripts/check-reserve-resume-step.mjs "$step" "$output" "$receipt_persisted" "$journal"
    return 0
  fi
  if [[ -e $journal ]]; then
    printf '%s\n' 'Reserve resume has an unresolved durable raw journal; revalidate its exact receipt before any new signature.' >&2
    return 80
  fi
  before=$(state "${rpcs[0]}")
  calldata=$(cast calldata "$signature")
  [[ $calldata =~ ^0x([0-9a-fA-F]{2})+$ ]]
  calldata_file=$(mktemp -p "$USDOM_CONTROL_EVIDENCE_DIRECTORY" "resume-$step-calldata.XXXXXXXX")
  printf '%s\n' "${calldata,,}" >"$calldata_file"
  chmod 0600 "$calldata_file"
  calldata_hash=$(node scripts/prepare-reserve-resume-private-safe-input.mjs hash "$calldata_file")
  if [[ $step == schedule ]]; then
    nonce=$(cast call "$governance" 'nonce()(uint256)' --rpc-url "${rpcs[0]}")
    safe_hash_call=$(node scripts/prepare-reserve-resume-private-safe-input.mjs call "$calldata_file" "$governance" "$reserve" "$nonce")
    safe_hash=$(printf '%s\n' "$safe_hash_call" | cast rpc eth_call --raw --rpc-url "${rpcs[0]}" | jq -er '.|ascii_downcase')
    safe_hash2=$(printf '%s\n' "$safe_hash_call" | cast rpc eth_call --raw --rpc-url "${rpcs[1]}" | jq -er '.|ascii_downcase')
    test "$safe_hash" = "$safe_hash2"
    echo "AUTHORIZE REVIEW SAFE EIP712 step=schedule chainId=1 verifyingContract=$governance safeNonce=$nonce to=$reserve valueWei=0 gasLimit=0 maxFeePerGas=0 maximumGasCostWei=0 calldataHash=$calldata_hash safeTxHash=${safe_hash,,}" >&2
    mapfile -t governance_owners < <(jq -er '.ownersByRole.governance[]' "$USDOM_SAFE_PACKAGE")
    test "${#governance_owners[@]}" -ge 2
    typed_data="$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-schedule-typed-data.json"
    if [[ ! -e $typed_data ]]; then
      jq -n --arg safe "$governance" --arg nonce "$nonce" --arg to "$reserve" --arg data "${calldata,,}" '{types:{EIP712Domain:[{name:"chainId",type:"uint256"},{name:"verifyingContract",type:"address"}],SafeTx:[{name:"to",type:"address"},{name:"value",type:"uint256"},{name:"data",type:"bytes"},{name:"operation",type:"uint8"},{name:"safeTxGas",type:"uint256"},{name:"baseGas",type:"uint256"},{name:"gasPrice",type:"uint256"},{name:"gasToken",type:"address"},{name:"refundReceiver",type:"address"},{name:"nonce",type:"uint256"}]},primaryType:"SafeTx",domain:{chainId:1,verifyingContract:$safe},message:{to:$to,value:"0",data:$data,operation:0,safeTxGas:"0",baseGas:"0",gasPrice:"0",gasToken:"0x0000000000000000000000000000000000000000",refundReceiver:"0x0000000000000000000000000000000000000000",nonce:$nonce}}' | node scripts/install-private-file-new-stdin.mjs --json "$typed_data"
    fi
    typed_digest=$(node -e 'const fs=require("fs"),{TypedDataEncoder}=require("ethers"),v=JSON.parse(fs.readFileSync(process.argv[1],"utf8")),t={...v.types};delete t.EIP712Domain;process.stdout.write(TypedDataEncoder.hash(v.domain,t,v.message))' "$typed_data")
    test "${typed_digest,,}" = "${safe_hash,,}"
    typed_envelope="$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-schedule-onekey-envelope.json"
    if [[ ! -e $typed_envelope ]]; then jq -n --arg digest "$typed_digest" --slurpfile typed "$typed_data" '{schema:"usdom-onekey-eip712-signing/v1",digest:$digest,typedData:$typed[0]}' | node scripts/install-private-file-new-stdin.mjs --json "$typed_envelope"; fi
    for owner_index in 0 1; do
      expected_owner=${governance_owners[$owner_index]}; owner_lower=${expected_owner,,}
      request="$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-schedule-owner-$owner_index.request.json"
      response="$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-schedule-owner-$owner_index.response.json"
      evidence="$USDOM_ONEKEY_IOS_PHYSICAL_EVIDENCE_DIRECTORY/$owner_lower.json"
      if [[ ! -e $request ]]; then node scripts/prepare-onekey-ios-walletconnect-request.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$typed_envelope" "$evidence" "$expected_owner" "$request" >/dev/null; fi
      if [[ ! -e $response ]]; then
        test "$(cast call "$governance" 'nonce()(uint256)' --rpc-url "${rpcs[0]}")" = "$nonce"
        test "$(cast call "$governance" 'nonce()(uint256)' --rpc-url "${rpcs[1]}")" = "$nonce"
        test "$(state "${rpcs[0]}")" = "$before"; test "$(state "${rpcs[1]}")" = "$before"
        timeout --foreground --signal=TERM --kill-after=10s 330s node scripts/sign-onekey-ios-walletconnect-typed-data.mjs "$USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG" "$request" "$evidence" "$response" || { status=$?; ((status==80))&&return 80; return "$status"; }
      fi
      owner_signature=$(node scripts/read-onekey-ios-walletconnect-signature.mjs "$request" "$response" "$expected_owner" "$typed_data") || return 80
      resume_broadcast_state=signed-unresolved
      if ((owner_index==0)); then signer1=$expected_owner;sig1=$owner_signature;else signer2=$expected_owner;sig2=$owner_signature;fi
    done
    jq -cn --arg digest "$safe_hash" --arg signer "$signer2" --arg signature "$sig2" '{digest:$digest,signer:$signer,signature:$signature}' | node -e 'let s="";process.stdin.on("data",b=>s+=b).on("end",()=>{const {Signature,recoverAddress,getAddress}=require("ethers"),v=JSON.parse(s),p=Signature.from(v.signature);if(p.serialized.toLowerCase()!==v.signature.toLowerCase()||getAddress(recoverAddress(v.digest,p))!==getAddress(v.signer))process.exit(1)})'
    if [[ ${signer1,,} < ${signer2,,} ]]; then signatures="${sig1}${sig2#0x}"; else signatures="${sig2}${sig1#0x}"; fi
    exec_data=$(cast calldata 'execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)' "$reserve" 0 "$calldata" 0 0 0 0 0x0000000000000000000000000000000000000000 0x0000000000000000000000000000000000000000 "$signatures")
    target=$governance
  else
    test "$(jq -r '.after.resumeReadyAt' "$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-schedule-finalized.json")" = "$(jq -r '.resumeReadyAt' <<<"$before")"
    exec_data=$calldata; target=$reserve; safe_hash=$calldata_hash
  fi
  [[ $target =~ ^0x[0-9a-fA-F]{40}$ && $exec_data =~ ^0x([0-9a-fA-F]{2})+$ ]]
  private_input=$(mktemp -p "$USDOM_CONTROL_EVIDENCE_DIRECTORY" "resume-$step-private-input.XXXXXXXX")
  printf '{"to":"%s","data":"%s"}\n' "$target" "$exec_data" >"$private_input"
  chmod 0600 "$private_input"
  exec_selector=$(jq -er '.data[0:10]' "$private_input")
  unset exec_data
  signer2=$(node scripts/check-reserve-resume-relayer-policy.mjs "$relayer_policy" "$USDOM_SAFE_PACKAGE" "$reserve" "$governance")
  n1=$(cast nonce "$signer2" --block pending --rpc-url "${rpcs[0]}"); n2=$(cast nonce "$signer2" --block pending --rpc-url "${rpcs[1]}")
  f1=$(cast nonce "$signer2" --block finalized --rpc-url "${rpcs[0]}"); f2=$(cast nonce "$signer2" --block finalized --rpc-url "${rpcs[1]}")
  test "$n1" = "$n2"; test "$f1" = "$f2"; test "$n1" = "$f1"; payer_nonce=$n1
  private_estimate=$(node scripts/prepare-private-eth-estimate-gas.mjs "$private_input" "$signer2")
  gas_limit=$(printf '%s\n' "$private_estimate" | cast rpc eth_estimateGas --raw --rpc-url "${rpcs[0]}" | jq -r . | xargs cast to-dec)
  gas_price=$(cast gas-price --rpc-url "${rpcs[0]}")
  maximum_gas_cost=$(node -e 'const [g,f]=process.argv.slice(1).map(BigInt),c=g*f;if(g===0n||f===0n||c>100000000000000000n)process.exit(1);process.stdout.write(c.toString())' "$gas_limit" "$gas_price")
  exec_data_hash=$(node -e 'const fs=require("fs"),{keccak256}=require("ethers"),v=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(keccak256(v.data))' "$private_input")
  reserve_config_hash=$(jq -er '.reserveConfigHash' <<<"$before")
  authorization_hash=$(node -e 'const {keccak256,toUtf8Bytes}=require("ethers");const [step,signer,nonce,target,dataHash,reserve,configHash,governance,delay,gas,fee,cost]=process.argv.slice(1);process.stdout.write(keccak256(toUtf8Bytes(`usdom-reserve-resume-payer-sign-v1|step=${step}|chainId=1|signer=${signer.toLowerCase()}|nonce=${nonce}|target=${target.toLowerCase()}|valueWei=0|dataHash=${dataHash.toLowerCase()}|reserve=${reserve.toLowerCase()}|reserveConfigHash=${configHash.toLowerCase()}|governanceSafe=${governance.toLowerCase()}|governanceDelaySeconds=${delay}|gasLimit=${gas}|maxFeePerGas=${fee}|maximumGasCostWei=${cost}`)))' "$step" "$signer2" "$payer_nonce" "$target" "$exec_data_hash" "$reserve" "$reserve_config_hash" "$governance" "$delay" "$gas_limit" "$gas_price" "$maximum_gas_cost")
  echo "AUTHORIZE REVIEW action=$step chainId=1 signer=$signer2 nonce=$payer_nonce target=$target selector=$exec_selector calldataHash=$exec_data_hash reserve=$reserve reserveConfigHash=$reserve_config_hash governanceSafe=$governance governanceDelaySeconds=$delay valueWei=0 gasLimit=$gas_limit maxFeePerGas=$gas_price maximumGasCostWei=$maximum_gas_cost authorizationHash=$authorization_hash" >&2
  read -r -p "Digite AUTORIZO USAR RELAYER RETOMADA $step AUTH $authorization_hash: " approval </dev/tty
  test "$approval" = "AUTORIZO USAR RELAYER RETOMADA $step AUTH $authorization_hash"
  test "$(state "${rpcs[0]}")" = "$before"
  test "$(state "${rpcs[1]}")" = "$before"
  test "$(cast nonce "$signer2" --block pending --rpc-url "${rpcs[0]}")" = "$payer_nonce"
  test "$(cast nonce "$signer2" --block pending --rpc-url "${rpcs[1]}")" = "$payer_nonce"
  raw="$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-$step-relayer-raw.txt"
  relayer_input="$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-$step-relayer-input.json"
  relayer_envelope="$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-$step-relayer-envelope.json"
  if [[ ! -e $relayer_input ]]; then node scripts/install-private-file-new-stdin.mjs --json "$relayer_input" <"$private_input"; fi
  if [[ ! -e $relayer_envelope ]]; then jq -cn --arg schema 'usdom-reserve-resume-relayer-envelope/v1' --arg relayer "$signer2" --arg to "$target" --arg dataHash "$exec_data_hash" --arg nonce "$payer_nonce" --arg gasLimit "$gas_limit" --arg maxFeePerGas "$gas_price" --arg maxPriorityFeePerGas '2000000000' '{schema:$schema,chainId:"1",relayer:$relayer,to:$to,value:"0",dataHash:$dataHash,nonce:$nonce,gasLimit:$gasLimit,maxFeePerGas:$maxFeePerGas,maxPriorityFeePerGas:$maxPriorityFeePerGas}' | node scripts/install-private-file-new-stdin.mjs --json "$relayer_envelope"; fi
  if [[ ! -e $raw ]]; then echo "RAW externa do relayer ausente: instale $raw; nenhuma assinatura ou transmissao foi executada." >&2; return 78; fi
  test -f "$raw"; test ! -L "$raw"; test "$(stat -c '%u:%a:%h' "$raw")" = "$(id -u):600:1"
  node scripts/check-reserve-resume-relayer-raw.mjs "$raw" "$private_input" "$relayer_policy" "$payer_nonce" "$gas_limit" "$gas_price" 2000000000 >/dev/null
  resume_broadcast_state=signed-unresolved
  jq -n --arg step "$step" --rawfile raw "$raw" --arg safeTxHash "${safe_hash,,}" --rawfile calldata "$calldata_file" '{schema:"usdom-reserve-resume-raw-journal/v1",step:$step,raw:($raw|rtrimstr("\n")),safeTxHash:$safeTxHash,calldata:($calldata|rtrimstr("\n"))}' | node scripts/install-private-file-new-stdin.mjs --json "$journal"
  test "$(cast nonce "$signer2" --block pending --rpc-url "${rpcs[0]}")" = "$payer_nonce"
  test "$(cast nonce "$signer2" --block pending --rpc-url "${rpcs[1]}")" = "$payer_nonce"
  expected_txhash=$(node -e 'const fs=require("fs"),{Transaction}=require("ethers");const raw=fs.readFileSync(process.argv[1],"utf8").trim();process.stdout.write(Transaction.from(raw).hash)' "$raw"); [[ $expected_txhash =~ ^0x[0-9a-fA-F]{64}$ ]]
  read -r -p "Digite AUTORIZO TRANSMITIR RETOMADA $step TX ${expected_txhash,,}: " approval </dev/tty
  test "$approval" = "AUTORIZO TRANSMITIR RETOMADA $step TX ${expected_txhash,,}"
  resume_broadcast_state=publishing
  txhash=$(node scripts/publish-private-raw-transaction.mjs "$raw" "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "$rpc_catalog" 0); [[ $txhash =~ ^0x[0-9a-fA-F]{64}$ ]]
  test "${txhash,,}" = "${expected_txhash,,}"
  receipt=$(mktemp -p "$USDOM_CONTROL_EVIDENCE_DIRECTORY" "resume-$step-receipt.XXXXXXXX")
  receipt2=$(mktemp -p "$USDOM_CONTROL_EVIDENCE_DIRECTORY" "resume-$step-receipt2.XXXXXXXX")
  until cast receipt "$txhash" --json --rpc-url "${rpcs[0]}" >"$receipt" 2>/dev/null \
    && cast receipt "$txhash" --json --rpc-url "${rpcs[1]}" >"$receipt2" 2>/dev/null \
    && jq -e '.status=="0x1"' "$receipt" >/dev/null && jq -e '.status=="0x1"' "$receipt2" >/dev/null; do sleep 12; done
  test "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,to,logs}' "$receipt")" = "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,to,logs}' "$receipt2")"
  test "$(jq -r '.transactionHash|ascii_downcase' "$receipt")" = "${txhash,,}"
  if [[ $step == schedule ]]; then event_topic=$(cast keccak 'ResumeScheduled(uint64)'); else event_topic=$(cast keccak 'Resumed()'); fi
  event_count=$(jq -r --arg reserve "${reserve,,}" --arg topic "${event_topic,,}" '[.logs[]|select((.address|ascii_downcase)==$reserve and (.topics[0]|ascii_downcase)==$topic)]|length' "$receipt")
  test "$event_count" = 1
  block=$(node scripts/canonical-uint256.mjs normalize "$(jq -er .blockNumber "$receipt")")
  transaction_index=$(node scripts/canonical-uint256.mjs normalize "$(jq -er .transactionIndex "$receipt")")
  event_log_index=$(node scripts/canonical-uint256.mjs normalize "$(jq -er --arg reserve "${reserve,,}" --arg topic "${event_topic,,}" '.logs[]|select((.address|ascii_downcase)==$reserve and (.topics[0]|ascii_downcase)==$topic)|.logIndex' "$receipt")")
  canonical1=$(cast block "$block" --json --rpc-url "${rpcs[0]}")
  canonical2=$(cast block "$block" --json --rpc-url "${rpcs[1]}")
  test "$(jq -r '.hash|ascii_downcase' <<<"$canonical1")" = "$(jq -r '.blockHash|ascii_downcase' "$receipt")"
  test "$(jq -r '.hash|ascii_downcase' <<<"$canonical1")" = "$(jq -r '.hash|ascii_downcase' <<<"$canonical2")"
  while :; do
    finalized=$(cast block finalized --json --rpc-url "${rpcs[0]}"); f0=$(node scripts/canonical-uint256.mjs normalize "$(jq -er .number <<<"$finalized")")
    finalized2=$(cast block finalized --json --rpc-url "${rpcs[1]}"); f1=$(node scripts/canonical-uint256.mjs normalize "$(jq -er .number <<<"$finalized2")")
    test "$f0" = "$f1" && test "$(jq -r '.hash|ascii_downcase' <<<"$finalized")" = "$(jq -r '.hash|ascii_downcase' <<<"$finalized2")" && test "$(node scripts/canonical-uint256.mjs ge "$f0" "$block")" = true && break
    sleep 12
  done
  # Finality can advance on a different fork after the first receipt/canonical
  # observation. Re-fetch the exact receipt and its block on every source after
  # the wait, then re-check a common finalized head before persisting evidence.
  receipt_final1=$(cast receipt "$txhash" --json --rpc-url "${rpcs[0]}")
  receipt_final2=$(cast receipt "$txhash" --json --rpc-url "${rpcs[1]}")
  test "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,to,logs}' <<<"$receipt_final1")" = \
    "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,to,logs}' "$receipt")"
  test "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,to,logs}' <<<"$receipt_final2")" = \
    "$(jq -cS '{transactionHash,blockNumber,blockHash,transactionIndex,status,to,logs}' "$receipt")"
  canonical_final1=$(cast block "$block" --json --rpc-url "${rpcs[0]}")
  canonical_final2=$(cast block "$block" --json --rpc-url "${rpcs[1]}")
  test "$(jq -r '.hash|ascii_downcase' <<<"$canonical_final1")" = "$(jq -r '.blockHash|ascii_downcase' "$receipt")"
  test "$(jq -r '.hash|ascii_downcase' <<<"$canonical_final2")" = "$(jq -r '.blockHash|ascii_downcase' "$receipt")"
  finalized_recheck1=$(cast block finalized --json --rpc-url "${rpcs[0]}")
  finalized_recheck2=$(cast block finalized --json --rpc-url "${rpcs[1]}")
  test "$(jq -r '.number' <<<"$finalized_recheck1")" = "$(jq -r '.number' <<<"$finalized_recheck2")"
  test "$(jq -r '.hash|ascii_downcase' <<<"$finalized_recheck1")" = "$(jq -r '.hash|ascii_downcase' <<<"$finalized_recheck2")"
  test "$(node scripts/canonical-uint256.mjs ge "$(jq -er .number <<<"$finalized_recheck1")" "$block")" = true
  finalized=$finalized_recheck1; f0=$(node scripts/canonical-uint256.mjs normalize "$(jq -er .number <<<"$finalized")")
  observation=$(state "${rpcs[0]}"); test "$observation" = "$(state "${rpcs[1]}")"
  node scripts/install-private-file-new-stdin.mjs --json "$receipt_persisted" <"$receipt"
  jq -n --arg step "$step" --arg reserve "$reserve" --arg governance "$governance" --rawfile calldata "$calldata_file" --arg safeHash "${safe_hash,,}" --arg tx "${txhash,,}" --arg block "$block" --arg blockHash "$(jq -r '.blockHash|ascii_downcase' "$receipt")" --arg transactionIndex "$transaction_index" --arg eventLogIndex "$event_log_index" --arg timestamp "$(node scripts/canonical-uint256.mjs normalize "$(jq -er .timestamp <<<"$canonical1")")" --arg finalized "$f0" --arg finalizedHash "$(jq -r '.hash|ascii_downcase' <<<"$finalized")" --arg rawSha "$(sha256sum "$journal"|cut -d' ' -f1)" --arg receiptSha "$(sha256sum "$receipt_persisted"|cut -d' ' -f1)" --arg obsSha "$(printf '%s' "$observation"|sha256sum|cut -d' ' -f1)" --argjson before "$before" --argjson after "$observation" '{schema:"usdom-reserve-resume-step/v2",step:$step,chainId:"1",reserve:$reserve,governanceSafe:$governance,calldata:($calldata|rtrimstr("\n")),safeTransactionHash:$safeHash,ethereumTransactionHash:$tx,blockNumber:$block,blockHash:$blockHash,transactionIndex:$transactionIndex,eventLogIndex:$eventLogIndex,transactionTimestamp:$timestamp,finalizedBlockNumber:$finalized,finalizedBlockHash:$finalizedHash,rawJournalSha256:$rawSha,receiptSha256:$receiptSha,observationSha256:$obsSha,before:$before,after:$after}' | node scripts/install-private-file-new-stdin.mjs --json "$output"
  node scripts/check-reserve-resume-step.mjs "$step" "$output" "$receipt_persisted" "$journal"
  resume_broadcast_state=clean
  rm -f -- "$raw" "$receipt" "$receipt2" "$private_input" "$prepared" "$calldata_file"
  private_input=''; prepared=''; calldata_file=''
}

schedule="$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-schedule-finalized.json"
execute="$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-execute-finalized.json"
execute_step schedule 'scheduleResume()' "$schedule"
ready=$(node scripts/canonical-uint256.mjs normalize "$(jq -er '.after.resumeReadyAt' "$schedule")")
while test "$(node scripts/canonical-uint256.mjs ge "$(date +%s)" "$ready")" != true; do sleep 60; done
execute_step execute 'executeResume()' "$execute"
candidate=$(mktemp -p "$USDOM_CONTROL_EVIDENCE_DIRECTORY" reserve-resume-completion.XXXXXXXX)
node scripts/materialize-reserve-resume-completion.mjs >"$candidate"; chmod 0600 "$candidate"
node scripts/install-private-file-new-stdin.mjs --json "$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-finalized-completion.json" <"$candidate"
node scripts/materialize-reserve-resume-completion.mjs | cmp -s - "$USDOM_CONTROL_EVIDENCE_DIRECTORY/reserve-resume-finalized-completion.json"
rm -f -- "$candidate"
