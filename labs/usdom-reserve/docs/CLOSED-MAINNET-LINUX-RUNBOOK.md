# USDOM — roteiro Linux para o primeiro teste fechado em Ethereum mainnet

Este roteiro é fail-closed: qualquer comando que falhar interrompe a sequência.
Ele não autoriza implantação ou fundos. Cada seção de broadcast e a seção de
USDT somente devem ser executadas após autorização explícita. O gate
`closed-mainnet` deve estar verde antes de implantar o registry e a reserva; o
gate `real-funds` deve estar verde antes de mover USDT.

Nunca coloque seed, mnemonic ou chave privada em variável, arquivo do projeto,
argumento de processo ou histórico do shell. Use Ledger/Trezor, Safe interativa
ou um keystore protegido que solicite a senha interativamente.

## 1. Entrar no projeto e verificar ferramentas

```bash
set -euo pipefail
export USDOM_PROJECT=/home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve
cd "$USDOM_PROJECT"
export PATH=/usr/lib/chatgpt/resources/cua_node/bin:/home/leonardov/.foundry/bin:$PATH

node --version
npm --version
forge --version
cast --version
cargo --version
rustc --version
python3 --version
jq --version
git status --short
```

As versões atualmente validadas incluem Node 24.19.0, Foundry 1.8.5 e Solidity
0.8.37. Não prossiga se o checkout contém alterações que você não reconhece.

## 2. Executar a validação local completa

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
npm ci
npm test
forge test -vv
cargo test --locked -p dom-node --features native-usdom-v4-poc native_usdom_config --lib
cargo test --locked -p dom-node --features native-usdom-v4-poc --bin dom-usdom-manifest-check
npm run check:provenance
```

Esses comandos compilam e testam localmente. Eles não iniciam mineração nem
geram provas RISC Zero caras.

## 3. Preparar os três controles 1-de-1 sem transmitir transações

Use três Safe Smart Accounts distintos, todos com o mesmo proprietário apenas
durante este teste: governança, guardião da reserva e guardião de checkpoint.
A concentração do proprietário deve constar na aceitação de risco.

Use uma Ledger como único proprietário neste teste. O comando abaixo apenas lê
o endereço público; confira no próprio dispositivo. Para outro índice/caminho,
acrescente `--mnemonic-derivation-path` com o caminho que você documentou.

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
export ETHERS_VERSION=6.17.0
export ETHERS_INTEGRITY='sha512-BpyrpIPJ3ydEVow8zGaz1DuPS7YU8DcWxuBnY9a0UA/lvAPwrMr+EPXsfrul628SRaekPNeIM4UFh/91GWZang=='
test "$(node -p "require('./node_modules/ethers/package.json').version")" = \
  "$ETHERS_VERSION"
test "$(jq -r '.packages["node_modules/ethers"].integrity' package-lock.json)" = \
  "$ETHERS_INTEGRITY"
test "$(npm view "ethers@$ETHERS_VERSION" dist.integrity)" = \
  "$ETHERS_INTEGRITY"

export USDOM_SAFE_OWNER=$(cast wallet address --ledger)
owner_confirmation=$(cast wallet address --ledger)
test "$owner_confirmation" = "$USDOM_SAFE_OWNER"
printf 'Proprietário único confirmado no dispositivo: %s\n' "$USDOM_SAFE_OWNER"
```

Leia duas RPCs independentes sem gravá-las no histórico. O gerador usa o Safe
1.4.1 e nonces 1, 2 e 3, decodifica a inicialização, proíbe delegatecall e
pagamento, verifica os contratos Safe no bloco finalizado e recalcula cada
endereço CREATE2 diretamente a partir do ABI, do bytecode de criação e do salt.
Ele não depende do Protocol Kit e permanece reproduzível depois que uma ou duas
das Safes já tiverem sido implantadas. O comando apenas produz JSON; não assina
nem transmite.

```bash
read -rsp 'RPC Ethereum primária: ' ETHEREUM_RPC_URL; echo
read -rsp 'RPC Ethereum secundária: ' ETHEREUM_RPC_URL_2; echo
export ETHEREUM_RPC_URL ETHEREUM_RPC_URL_2
test "$(cast chain-id --rpc-url "$ETHEREUM_RPC_URL")" = "1"
test "$(cast chain-id --rpc-url "$ETHEREUM_RPC_URL_2")" = "1"

export USDOM_SAFE_PACKAGE=/tmp/usdom-safe-controls.json
export USDOM_SAFE_PACKAGE_SECONDARY=/tmp/usdom-safe-controls-secondary.json
node scripts/prepare-safe-controls.mjs > "$USDOM_SAFE_PACKAGE"
ETHEREUM_RPC_URL="$ETHEREUM_RPC_URL_2" node scripts/prepare-safe-controls.mjs \
  > "$USDOM_SAFE_PACKAGE_SECONDARY"
cmp -s "$USDOM_SAFE_PACKAGE" "$USDOM_SAFE_PACKAGE_SECONDARY"
export USDOM_SAFE_PACKAGE_SHA256=$(sha256sum "$USDOM_SAFE_PACKAGE" | awk '{print $1}')

jq '{schema,ethereumChainId,owner,threshold,safeVersion,factory,singleton,
  fallbackHandler,factoryCodeHash,singletonCodeHash,fallbackHandlerCodeHash,
  controls:[.controls[]|{role,saltNonce,safe,to,value,dataHash}]}' \
  "$USDOM_SAFE_PACKAGE"

test "$(jq -r '.owner' "$USDOM_SAFE_PACKAGE")" = "$USDOM_SAFE_OWNER"
test "$(jq -r '.threshold' "$USDOM_SAFE_PACKAGE")" = "1"
test "$(jq -r '[.controls[].safe|ascii_downcase]|unique|length' "$USDOM_SAFE_PACKAGE")" = "3"

export USDOM_GOVERNANCE_SAFE=$(jq -er '.controls[]|select(.role=="governance")|.safe' "$USDOM_SAFE_PACKAGE")
export USDOM_RESERVE_GUARDIAN_SAFE=$(jq -er '.controls[]|select(.role=="reserveGuardian")|.safe' "$USDOM_SAFE_PACKAGE")
export USDOM_CHECKPOINT_GUARDIAN_SAFE=$(jq -er '.controls[]|select(.role=="checkpointGuardian")|.safe' "$USDOM_SAFE_PACKAGE")
test "$USDOM_GOVERNANCE_SAFE" != "$USDOM_RESERVE_GUARDIAN_SAFE"
test "$USDOM_GOVERNANCE_SAFE" != "$USDOM_CHECKPOINT_GUARDIAN_SAFE"
test "$USDOM_RESERVE_GUARDIAN_SAFE" != "$USDOM_CHECKPOINT_GUARDIAN_SAFE"

for rpc_name in ETHEREUM_RPC_URL ETHEREUM_RPC_URL_2; do
  rpc=${!rpc_name}
  test "$(cast code "$USDOM_SAFE_OWNER" --rpc-url "$rpc" --block finalized)" = "0x"
  for safe in "$USDOM_GOVERNANCE_SAFE" "$USDOM_RESERVE_GUARDIAN_SAFE" "$USDOM_CHECKPOINT_GUARDIAN_SAFE"; do
    test "$(cast code "$safe" --rpc-url "$rpc" --block finalized)" = "0x"
  done
done
```

Revise o JSON e registre seu SHA-256 fora do repositório. Os endereços devem ser
três valores distintos. A concentração do mesmo proprietário nos três controles
é um risco residual aceito apenas para o teste fechado.

## 3.1 Implantar os três Safes — requer autorização explícita

Não execute este bloco até autorizar especificamente os três deploys e reservar
ETH apenas para o gás da EOA `USDOM_SAFE_OWNER`. Cada iteração recompõe o pacote
pelas duas RPCs, exige igualdade byte a byte e mostra endereço e hash do calldata
antes de pedir a assinatura física. O dispositivo pode não exibir todo o
calldata; confira esses valores no terminal e o destino Safe Proxy Factory.

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
test "${USDOM_SAFE_DEPLOY_AUTHORIZED:-}" = "SIM, TRES SAFES 1-DE-1"

for role in governance reserveGuardian checkpointGuardian; do
  rebuilt_primary=$(mktemp)
  rebuilt_secondary=$(mktemp)
  node scripts/prepare-safe-controls.mjs > "$rebuilt_primary"
  ETHEREUM_RPC_URL="$ETHEREUM_RPC_URL_2" node scripts/prepare-safe-controls.mjs \
    > "$rebuilt_secondary"
  cmp -s "$USDOM_SAFE_PACKAGE" "$rebuilt_primary"
  cmp -s "$rebuilt_primary" "$rebuilt_secondary"
  test "$(sha256sum "$USDOM_SAFE_PACKAGE" | awk '{print $1}')" = "$USDOM_SAFE_PACKAGE_SHA256"

  safe=$(jq -er --arg role "$role" '.controls[]|select(.role==$role)|.safe' "$USDOM_SAFE_PACKAGE")
  to=$(jq -er --arg role "$role" '.controls[]|select(.role==$role)|.to' "$USDOM_SAFE_PACKAGE")
  value=$(jq -er --arg role "$role" '.controls[]|select(.role==$role)|.value' "$USDOM_SAFE_PACKAGE")
  data=$(jq -er --arg role "$role" '.controls[]|select(.role==$role)|.data' "$USDOM_SAFE_PACKAGE")
  data_hash=$(jq -er --arg role "$role" '.controls[]|select(.role==$role)|.dataHash' "$USDOM_SAFE_PACKAGE")
  test "$(cast code "$safe" --rpc-url "$ETHEREUM_RPC_URL" --block finalized)" = "0x"
  printf 'Papel=%s Safe=%s Factory=%s Valor=%s CalldataHash=%s\n' \
    "$role" "$safe" "$to" "$value" "$data_hash"
  cast estimate "$to" "$data" --from "$USDOM_SAFE_OWNER" --value "$value" \
    --rpc-url "$ETHEREUM_RPC_URL"
  cast send "$to" --from "$USDOM_SAFE_OWNER" --data "$data" --value "$value" \
    --ledger --rpc-url "$ETHEREUM_RPC_URL" --confirmations 2 --json \
    > "/tmp/usdom-safe-$role-receipt.json"

  deadline=$((SECONDS + 1800))
  while test "$(cast code "$safe" --rpc-url "$ETHEREUM_RPC_URL" --block finalized)" = "0x"; do
    test "$SECONDS" -lt "$deadline"
    sleep 12
  done
done
```

O nome da variável de autorização é `USDOM_SAFE_DEPLOY_AUTHORIZED`; defina-a
somente após a decisão explícita, com o valor literal mostrado no bloco.

Depois de finalizados, verifique código, proprietário e threshold por duas RPCs
independentes. `ETHEREUM_RPC_URL` e `ETHEREUM_RPC_URL_2` são URLs privadas e não
devem ser gravadas no repositório.

```bash
for rpc_name in ETHEREUM_RPC_URL ETHEREUM_RPC_URL_2; do
  rpc=${!rpc_name}
  for safe in "$USDOM_GOVERNANCE_SAFE" "$USDOM_RESERVE_GUARDIAN_SAFE" "$USDOM_CHECKPOINT_GUARDIAN_SAFE"; do
    test "$(cast code "$safe" --rpc-url "$rpc" --block finalized)" != "0x"
    cast call "$safe" 'getOwners()(address[])' --rpc-url "$rpc" --block finalized
    test "$(cast call "$safe" 'getThreshold()(uint256)' --rpc-url "$rpc" --block finalized | tr -d '[:space:]')" = "1"
  done
done
```

## 4. Configurar a release sem inventar fatos

Preencha os arquivos de configuração somente com valores medidos ou aprovados:

```bash
cd "$USDOM_PROJECT"
jq -r 'paths(scalars) as $p | select(getpath($p) == null) | $p | map(tostring) | join(".")' \
  config/proof-reserve.unconfigured.json
jq -r 'paths(scalars) as $p | select(getpath($p) == null) | $p | map(tostring) | join(".")' \
  config/finalized-burn-verifier.unconfigured.json
jq -r 'paths(scalars) as $p | select(getpath($p) == null) | $p | map(tostring) | join(".")' \
  config/checkpoint-verifier.unconfigured.json
jq -r 'paths(scalars) as $p | select(getpath($p) == null) | $p | map(tostring) | join(".")' \
  config/mainnet-release-evidence.unconfigured.json
```

Se qualquer item ainda for desconhecido, deixe `null`; o gate deve impedir o
avanço. Não troque `productionReady` ou autorizações para `true` antes das
evidências correspondentes existirem.

## 5. Construir e verificar a release localmente

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
forge build contracts/USDOMProofReserve.sol contracts/DOMCheckpointRegistry.sol \
  contracts/DOMFinalizedBurnRiscZeroVerifier.sol contracts/DOMCheckpointRiscZeroVerifier.sol \
  --force --ignored-error-codes 6335 -D warnings
npm run check:provenance

read -rsp 'RPC Ethereum primária: ' ETHEREUM_RPC_URL; echo
export ETHEREUM_RPC_URL
export USDOM_RELEASE_SIGNING_KEY_FINGERPRINT='FINGERPRINT_FORA_DO_REPOSITORIO'
node scripts/check-mainnet-readiness.mjs closed-mainnet | tee /tmp/usdom-closed-mainnet.json
jq -r '.blockers[] | [.code,.detail] | @tsv' /tmp/usdom-closed-mainnet.json
```

Antes dos adaptadores existirem, o gate completo deve permanecer fechado porque
a evidência de predeployment ainda não pode ser produzida. Não transforme esse
estado esperado em `ready: true` manualmente. Corrija todos os demais blockers
e obtenha a autorização explícita para os dois primeiros broadcasts.

## 6. Gerar o pacote unsigned dos quatro CREATEs

Os quatro deployers e nonces já fazem parte da configuração exata da release.
O mesmo EOA de hardware pode ser usado com quatro nonces consecutivos. Não
envie nenhuma transação concorrente desse EOA entre a preparação e a
implantação.

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
node scripts/prepare-mainnet-deployment.mjs > /tmp/usdom-mainnet-deployment-package.json
jq -e '.schema == "usdom-mainnet-deployment-package-v1" and .chainId == "1" and (.transactions | length) == 4' \
  /tmp/usdom-mainnet-deployment-package.json
jq -r '.transactions[] | [.name,.from,.nonce,.expectedContract,.initcodeHash,.expectedRuntimeCodeHash] | @tsv' \
  /tmp/usdom-mainnet-deployment-package.json
export USDOM_PACKAGE_SHA256=$(sha256sum /tmp/usdom-mainnet-deployment-package.json | awk '{print $1}')
printf '%s  %s\n' "$USDOM_PACKAGE_SHA256" /tmp/usdom-mainnet-deployment-package.json
```

## 7. Conferir os quatro CREATEs antes de qualquer broadcast

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
jq -c '.transactions[]' /tmp/usdom-mainnet-deployment-package.json | while read -r tx; do
  from=$(jq -r '.from' <<<"$tx")
  nonce=$(jq -r '.nonce' <<<"$tx")
  test "$(cast nonce "$from" --block finalized --rpc-url "$ETHEREUM_RPC_URL")" = "$nonce"
  test "$(cast code "$(jq -r '.expectedContract' <<<"$tx")" --block finalized --rpc-url "$ETHEREUM_RPC_URL")" = "0x"
  cast estimate --create "$(jq -r '.data' <<<"$tx")" --from "$from" --block finalized \
    --rpc-url "$ETHEREUM_RPC_URL"
done
```

## 8. Implantar somente os dois adaptadores — exige autorização explícita

O bloco seguinte cria contratos e gasta ETH. Execute uma transação por vez e
confira no dispositivo `chainId`, deployer, nonce, ausência de destinatário,
valor zero e hash do initcode. Execute com `INDEX=0` e depois `INDEX=1`.

```bash
set -euo pipefail
PACKAGE=/tmp/usdom-mainnet-deployment-package.json
INDEX=0  # execute novamente com INDEX=1 para o adapter de checkpoint
REBUILT_PACKAGE=$(mktemp)
trap 'rm -f "$REBUILT_PACKAGE"' EXIT
node scripts/prepare-mainnet-deployment.mjs > "$REBUILT_PACKAGE"
cmp -s "$PACKAGE" "$REBUILT_PACKAGE"
test "$(sha256sum "$PACKAGE" | awk '{print $1}')" = "$USDOM_PACKAGE_SHA256"
rm -f "$REBUILT_PACKAGE"
trap - EXIT
FROM=$(jq -er ".transactions[$INDEX].from" "$PACKAGE")
NONCE=$(jq -er ".transactions[$INDEX].nonce" "$PACKAGE")
DATA=$(jq -er ".transactions[$INDEX].data" "$PACKAGE")
EXPECTED=$(jq -er ".transactions[$INDEX].expectedContract" "$PACKAGE")

test "$(cast nonce "$FROM" --block finalized --rpc-url "$ETHEREUM_RPC_URL")" = "$NONCE"
test "$(cast code "$EXPECTED" --block finalized --rpc-url "$ETHEREUM_RPC_URL")" = "0x"
cast send --create "$DATA" --chain 1 --rpc-url "$ETHEREUM_RPC_URL" --ledger \
  --from "$FROM" --nonce "$NONCE" --value 0 --confirmations 2 --json \
  | tee "/tmp/usdom-deploy-$INDEX.json"
jq -er '.transactionHash' "/tmp/usdom-deploy-$INDEX.json"
```

Registre os dois hashes, espere os contratos aparecerem no bloco `finalized` e
confira os endereços previstos:

```bash
export USDOM_FINALIZED_BURN_VERIFIER_DEPLOYMENT_TX_HASH=$(jq -er '.transactionHash' /tmp/usdom-deploy-0.json)
export USDOM_CHECKPOINT_VERIFIER_DEPLOYMENT_TX_HASH=$(jq -er '.transactionHash' /tmp/usdom-deploy-1.json)
for INDEX in 0 1; do
  EXPECTED=$(jq -er ".transactions[$INDEX].expectedContract" /tmp/usdom-mainnet-deployment-package.json)
  test "$(cast code "$EXPECTED" --block finalized --rpc-url "$ETHEREUM_RPC_URL")" != "0x"
done
```

Se o último comando falhar, aguarde a finalização e execute apenas esse bloco
de conferência novamente. Não retransmita uma transação já minerada.

## 9. Preflight intermediário e gate fechado

Agora os adaptadores devem estar ativos, enquanto os endereços do registry e da
reserva ainda estão vazios. Gere a evidência, atualize seu arquivo e hash de
evidência pelo processo de release e execute novamente o gate:

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
ETHEREUM_RPC_URL="$ETHEREUM_RPC_URL" \
USDOM_FINALIZED_BURN_VERIFIER_DEPLOYMENT_TX_HASH="$USDOM_FINALIZED_BURN_VERIFIER_DEPLOYMENT_TX_HASH" \
USDOM_CHECKPOINT_VERIFIER_DEPLOYMENT_TX_HASH="$USDOM_CHECKPOINT_VERIFIER_DEPLOYMENT_TX_HASH" \
node scripts/check-mainnet-preflight.mjs predeployment \
  | tee /tmp/usdom-predeployment.json
jq -e '.ready == true and .blockerCount == 0' /tmp/usdom-predeployment.json

node scripts/check-mainnet-readiness.mjs closed-mainnet | tee /tmp/usdom-closed-mainnet.json
jq -e '.ready == true and .blockerCount == 0' /tmp/usdom-closed-mainnet.json
```

O segundo comando só fica verde depois que a evidência hash-addressed e as
autorizações da release exata estiverem preenchidas e assinadas.

## 10. Implantar registry e reserva pausada — exige autorização explícita

Com o gate fechado verde, execute o mesmo bloco de broadcast da seção 8 com
`INDEX=2` e depois `INDEX=3`. Em seguida:

```bash
export USDOM_CHECKPOINT_REGISTRY_DEPLOYMENT_TX_HASH=$(jq -er '.transactionHash' /tmp/usdom-deploy-2.json)
export USDOM_DEPLOYMENT_TX_HASH=$(jq -er '.transactionHash' /tmp/usdom-deploy-3.json)
for INDEX in 2 3; do
  EXPECTED=$(jq -er ".transactions[$INDEX].expectedContract" /tmp/usdom-mainnet-deployment-package.json)
  test "$(cast code "$EXPECTED" --block finalized --rpc-url "$ETHEREUM_RPC_URL")" != "0x"
done
```

A reserva nasce pausada em Ethereum mainnet. Se a conferência falhar, aguarde a
finalização e repita somente a conferência.

## 11. Cold start finalizado dos quatro deployments

```bash
export USDOM_FINALIZED_BURN_VERIFIER_DEPLOYMENT_TX_HASH=0x_SUBSTITUA
export USDOM_CHECKPOINT_VERIFIER_DEPLOYMENT_TX_HASH=0x_SUBSTITUA
export USDOM_CHECKPOINT_REGISTRY_DEPLOYMENT_TX_HASH=0x_SUBSTITUA
export USDOM_DEPLOYMENT_TX_HASH=0x_SUBSTITUA

ETHEREUM_RPC_URL="$ETHEREUM_RPC_URL" \
USDOM_FINALIZED_BURN_VERIFIER_DEPLOYMENT_TX_HASH="$USDOM_FINALIZED_BURN_VERIFIER_DEPLOYMENT_TX_HASH" \
USDOM_CHECKPOINT_VERIFIER_DEPLOYMENT_TX_HASH="$USDOM_CHECKPOINT_VERIFIER_DEPLOYMENT_TX_HASH" \
USDOM_DEPLOYMENT_TX_HASH="$USDOM_DEPLOYMENT_TX_HASH" \
USDOM_CHECKPOINT_REGISTRY_DEPLOYMENT_TX_HASH="$USDOM_CHECKPOINT_REGISTRY_DEPLOYMENT_TX_HASH" \
node scripts/check-mainnet-preflight.mjs postdeployment | tee /tmp/usdom-cold-start.json
jq -e '.ready == true and .blockerCount == 0 and .observation.reserve.paused == true' \
  /tmp/usdom-cold-start.json
```

O preflight autentica as quatro transações, os quatro initcodes, os hashes de
código e a configuração viva. Não deposite USDT até o gate `real-funds`
continuar verde sobre a evidência finalizada, a retomada atrasada ser executada
pela governança e o limite monetário fechado ser explicitamente aprovado:

```bash
node scripts/check-mainnet-readiness.mjs real-funds | tee /tmp/usdom-real-funds.json
jq -e '.ready == true and .blockerCount == 0' /tmp/usdom-real-funds.json
```
