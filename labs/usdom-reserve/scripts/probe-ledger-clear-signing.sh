#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077
readonly project=/home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve
readonly cast_bin=/home/leonardov/.foundry/bin/cast
readonly node_bin=/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node
if [[ ${1-} == --print-command && $# == 1 ]]; then
  printf '%s\n' 'cd /home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve && bash scripts/probe-ledger-clear-signing.sh --run'
  exit 0
fi
if [[ ${1-} != --run || $# != 1 || ! -t 0 || ! -t 1 || ! -t 2 ]]; then
  printf '%s\n' 'Execute primeiro: bash scripts/probe-ledger-clear-signing.sh --print-command' >&2
  exit 64
fi
cd "$project"
temporary=$(mktemp -d -p /dev/shm usdom-ledger-clear-signing.XXXXXXXX)
chmod 0700 "$temporary"
cleanup() { local status=${1:-$?}; trap - EXIT HUP INT TERM; rm -rf -- "$temporary"; exit "$status"; }
trap 'cleanup $?' EXIT; trap 'cleanup 129' HUP; trap 'cleanup 130' INT; trap 'cleanup 143' TERM
unset ETH_RPC_URL ETH_PRIVATE_KEY ETH_KEYSTORE ETH_PASSWORD ETH_PASSWORD_FILE
readonly sentinel=0x000000000000000000000000000000000000dEaD
cat >"$temporary/eip712.json" <<'EOF'
{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Capability":[{"name":"action","type":"bytes32"},{"name":"nonce","type":"uint256"},{"name":"deadline","type":"uint64"}]},"primaryType":"Capability","domain":{"name":"USDOM Ledger Capability Probe","version":"1","chainId":"31337","verifyingContract":"0x000000000000000000000000000000000000dEaD"},"message":{"action":"0x5553444f4d5f434c4541525f5349474e494e475f50524f424500000000000000","nonce":"0","deadline":"4102444800"}}
EOF
cat >"$temporary/safe.json" <<'EOF'
{"types":{"EIP712Domain":[{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"SafeTx":[{"name":"to","type":"address"},{"name":"value","type":"uint256"},{"name":"data","type":"bytes"},{"name":"operation","type":"uint8"},{"name":"safeTxGas","type":"uint256"},{"name":"baseGas","type":"uint256"},{"name":"gasPrice","type":"uint256"},{"name":"gasToken","type":"address"},{"name":"refundReceiver","type":"address"},{"name":"nonce","type":"uint256"}]},"primaryType":"SafeTx","domain":{"chainId":"31337","verifyingContract":"0x000000000000000000000000000000000000dEaD"},"message":{"to":"0x000000000000000000000000000000000000dEaD","value":"0","data":"0x","operation":"0","safeTxGas":"0","baseGas":"0","gasPrice":"0","gasToken":"0x0000000000000000000000000000000000000000","refundReceiver":"0x0000000000000000000000000000000000000000","nonce":"0"}}
EOF
address=$(timeout --foreground --signal=TERM --kill-after=5s 300s "$cast_bin" wallet address --ledger)
[[ $address =~ ^0x[0-9a-fA-F]{40}$ ]]
for kind in eip712 safe; do
  printf 'Confira no Ledger: chainId=31337, verifyingContract=%s, tipo=%s, nonce=0, value=0.\n' "$sentinel" "$kind"
  read -r -p "Digite CONFIRMO REVIEW EIP712 $kind somente se todos os campos forem exibidos; hash cego reprova: " answer
  test "$answer" = "CONFIRMO REVIEW EIP712 $kind"
  signature=$(timeout --foreground --signal=TERM --kill-after=5s 300s \
    "$cast_bin" wallet sign --data --from-file "$temporary/$kind.json" --ledger)
  "$cast_bin" wallet verify --address "$address" --data --from-file "$temporary/$kind.json" "$signature" >/dev/null
  unset signature
done
approve_data=$($cast_bin calldata 'approve(address,uint256)' "$sentinel" 1)
reserve_data=$($cast_bin calldata 'deposit(uint64,bytes32,bytes32)' 1 \
  0x1111111111111111111111111111111111111111111111111111111111111111 \
  0x2222222222222222222222222222222222222222222222222222222222222222)
index=0
for item in "erc20-approve:$approve_data" "usdom-deposit:$reserve_data"; do
  kind=${item%%:*}; data=${item#*:}
  printf 'Confira no Ledger: rede local 31337, action=%s, to=%s, value=0, nonce=%s, selector=%s.\n' \
    "$kind" "$sentinel" "$index" "${data:0:10}"
  read -r -p "Digite CONFIRMO CLEAR CALL $kind somente se a ação e os campos forem legíveis; blind signing reprova: " answer
  test "$answer" = "CONFIRMO CLEAR CALL $kind"
  raw="$temporary/$kind.raw"
  timeout --foreground --signal=TERM --kill-after=5s 300s "$cast_bin" mktx "$sentinel" \
    --chain 31337 --from "$address" --nonce "$index" --value 0 --data "$data" \
    --gas-limit 250000 --gas-price 2000000000 --priority-gas-price 1000000000 --ledger >"$raw"
  "$node_bin" scripts/check-ledger-clear-signing-capability.mjs "$raw" "$address" "$index" "$sentinel" "$data"
  index=$((index+1))
done
printf '%s\n' 'CAPABILITY PASS: EIP-712 genérico, SafeTx e chamadas reconhecidas foram exibidos e recuperaram o signer. Nenhuma transação foi transmitida; artefatos serão apagados.'
