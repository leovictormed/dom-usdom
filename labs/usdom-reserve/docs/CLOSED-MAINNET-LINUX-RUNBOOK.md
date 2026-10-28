# USDOM — roteiro Linux para o primeiro teste fechado em Ethereum mainnet

> **Autoridade de hardware de produção:** somente **OneKey Classic 1S junto ao iPhone,
> pelo OneKey App e WalletConnect v2 EIP-712**.
> O endereço Ethereum deve usar caminho explícito e ser confirmado na tela do
> dispositivo. O transporte BLE oficial, SDK, firmware e transporte precisam estar fixados na política
> autenticada. EIP-1559, EIP-712, rejeição, cancelamento, desconexão e reconexão
> precisam de evidência antes de liberar o piloto. Pareamento, permissões Bluetooth,
> identidade do dispositivo e preservação dessa identidade após reconexão também
> exigem evidência. O antigo handoff BLE do desktop/Electron está preservado
> somente como laboratório e não integra gates nem comandos de produção.
> USB não é transporte produtivo nem fallback. Os fluxos e comandos Ledger
> existentes são legado de desenvolvimento e estão proibidos em produção; o
> readiness permanece fail-closed até sua substituição OneKey ser validada.

Este roteiro é fail-closed: qualquer comando que falhar interrompe a sequência.
Ele não autoriza implantação ou fundos. Cada seção de broadcast e a seção de
USDT somente devem ser executadas após autorização explícita. O gate
`closed-mainnet` deve estar verde antes de implantar o registry e a reserva; o
gate `real-funds` deve estar verde antes de mover USDT.

Nunca coloque seed, mnemonic ou chave privada em variável, arquivo do projeto,
argumento de processo ou histórico do shell. Use Ledger/Trezor, Safe interativa
ou um keystore protegido que solicite a senha interativamente.

Para não depender de variáveis mantidas entre terminais nem copiar campos,
publique primeiro o plano endereçado por conteúdo e materialize cada fase pelo
caminho oficial. Não execute a saída do gerador com substituição de processo:
o prólogo fecha descritores herdados, enquanto `bash <(...)` depende de um
descritor herdado para continuar lendo o próprio programa. As fases com sufixo
`-secret` somente leem a identidade pública do hardware; nunca imprimem seed,
chave ou senha.

```bash
set -euo pipefail
export USDOM_PROJECT=/home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve
cd "$USDOM_PROJECT"
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc scripts/prepare-closed-mainnet-pilot.sh --verify-only
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc scripts/prepare-closed-mainnet-pilot.sh --generate-plan
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc scripts/materialize-closed-mainnet-phase-script.sh prerequisites
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc -n /home/leonardov/usdom-mainnet-private/operator-phases/prerequisites.sh
cat /home/leonardov/usdom-mainnet-private/operator-phases/prerequisites.sh
```

Os nomes aceitos são exibidos quando o gerador é chamado sem argumentos. Ele
não inclui uma transmissão direta: as duas fases piloto apenas chamam os
executores retomáveis. Eles mantêm `broadcastAuthorized=false` nos pacotes e
exigem autorizações literais separadas para assinar e publicar cada transação,
com reconciliação e artefatos fixos descritos nas seções correspondentes.

Se as fontes ou o plano precisarem mudar depois que qualquer fase tiver sido
materializada, não apague nem sobrescreva os caminhos fixos. Primeiro execute,
sem nenhuma fase concorrente:

```bash
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc scripts/archive-closed-mainnet-phase-generation.sh
```

O comando autentica plano, tipos, owner, modos, realpaths e identidades
device:inode; copia e verifica todos os scripts e toda a control-plane em
`/home/leonardov/usdom-mainnet-private/phase-generation-archive/{plan-sha256}/`
antes de liberar os caminhos create-once. O `archive.json` preserva o inventário
canônico com tamanho e SHA-256 de cada arquivo; os inodes originais também são
movidos para o arquivo e nunca apagados pela rotação. Só então publique o novo plano e
materialize a nova geração. Nunca remova manualmente `.phase-generation.json`,
`.phase-completions` ou `operator-phases`.

### Ordem autoritativa das fases geradas

O plano contém 23 fases ordenadas e 33 rotas implementadas e classificadas. As 33 produzem e validam
evidência na fase correta. As duas rotas de privacidade permanecem falsas até
que três contribuições externas reais sejam importadas, a cerimônia multiparte
externa seja validada e ocorra a instalação create-once de sua chave
verificadora. Portanto,
cobertura 33/33 do plano não significa que o
piloto ou o uso de fundos estejam prontos.

Materialize o plano com a shell limpa mostrada no início deste roteiro e a opção
`--generate-plan`. Execute os scripts materializados somente nesta ordem, sem
copiar comandos entre fases:

<!-- BEGIN CLOSED MAINNET PHASE ORDER -->
1. `prerequisites`
2. `enroll-safe-owners-secret`
3. `migrate-safe-owners-hardware-secret`
4. `prepare-safe-controls`
5. `execute-safe-controls-deployment-secret`
6. `prepare-safe-recovery-secret`
7. `execute-safe-recovery-secret`
8. `materialize-safe-control-config`
9. `validate-local`
10. `verify-risc0-trusted-setup`
11. `derive-deployment-identity-secret`
12. `prepare-deployment`
13. `execute-mainnet-deployment-secret`
14. `execute-reserve-resume-secret`
15. `measure-release-capacity`
16. `prepare-native-wallet-secret`
17. `finalize-native-privacy-ceremony-secret`
18. `authorize-pilot-funds-secret`
19. `execute-pilot-deposit-secret`
20. `submit-pilot-burn-secret`
21. `produce-checkpoint-evidence-secret`
22. `execute-pilot-redemption-secret`
23. `readiness`
<!-- END CLOSED MAINNET PHASE ORDER -->

`authorize-pilot-funds-secret` somente termina após duas autorizações de owners
do Safe de governança, execução de `authorizePilotDeposit` e concordância de
dois RPCs sobre receipt, logs, bloco canônico, finalidade e estado armado. A
fase 19 reexecuta essa validação idempotente antes do depósito. Se a autorização
EIP-1271 expirar antes da conclusão, o fluxo arquiva automaticamente a geração
antiga pelo digest e só então permite uma nova request; artefato já minerado ou
finalizado exige primeiro cancelamento on-chain do snapshot exato.

Interrompa imediatamente se um comando retornar código diferente de zero, se o
hash ou o tamanho de uma fase divergir do plano, se um artefato create-once já
existente tiver bytes diferentes, se uma fonte RPC divergir ou perder
finalidade, se qualquer gate informar bloqueios, ou se faltar a evidência real
da cerimônia/instalação. Não pule, reordene nem repita uma transmissão. Uma fase
que pede autorização literal só pode prosseguir após revisão do artefato exato;
uma recusa ou ausência de autorização é critério de aborto, não motivo para
editar o script.

## 1. Entrar no projeto e verificar ferramentas

```bash
set -euo pipefail
export USDOM_PROJECT=/home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve
cd "$USDOM_PROJECT"
export PATH=/usr/lib/chatgpt/resources/cua_node/bin:/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin:/home/leonardov/.foundry/bin:/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export npm_config_offline=true npm_config_audit=false npm_config_ignore_scripts=true
export CARGO_NET_OFFLINE=true FOUNDRY_OFFLINE=true

node scripts/check-mainnet-toolchain.mjs
timeout --version | head -n 1
git status --short
```

O lock valida paths reais e SHA-256 de Node 24.19.0, npm 11.17.0, Foundry/cast
1.8.5, Rust 1.98.0, Python 3.12.3, jq 1.7, lockfiles e configuração.
O gate `prerequisites` aceita `solc` 0.8.37 somente no caminho, versão e SHA-256
fixados pelo lock. Se essa verificação falhar por ausência do binário, execute a
preparação abaixo fora de qualquer cerimônia e depois gere novamente a fase
`prerequisites`. O bootstrap pode acessar a rede; não edite o JSON por conta
própria.

```bash
set -euo pipefail
cd /home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve
bash scripts/bootstrap-solc-0.8.37.sh
```

O bootstrap baixa somente o asset oficial por HTTPS/TLS, compara o SHA-256
fixado em `config/solc-0.8.37-official-manifest.json`, confere a versão, instala
com link exclusivo em diretório 0700 e chama o materializador determinístico do
lock. Ele é idempotente: uma instalação existente só é aceita quando owner,
modo, link count, hash e versão são exatos.

Não prossiga se o checkout contém alterações que você não reconhece.

## 2. Executar a validação local completa

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
npm ci --offline --ignore-scripts --audit=false
npm test
forge test -vv
cargo test --locked -p dom-node --features native-usdom-v4-poc native_usdom_config --lib
cargo test --locked -p dom-node --features native-usdom-v4-poc --bin dom-usdom-manifest-check
npm run check:provenance
```

Esses comandos compilam e testam localmente. Eles não iniciam mineração nem
geram provas RISC Zero caras.

Os sete guests de release só podem ser reconstruídos pelo launcher estático
autenticado. Nunca execute os scripts internos com `bash`, `sh`, `source` ou
diretamente. Para selecionar exatamente um guest, use um dos seletores
`checkpoint-outer`, `checkpoint-segment`, `complete-randomx`, `economic-block`,
`economic-chunk`, `finalized-burn` ou `randomx-aggregate`:

```bash
./scripts/risc0-guest-build-launcher --preflight
./scripts/risc0-guest-build-launcher checkpoint-outer
```

O preflight autentica o launcher, os sete builders, o helper, o manifesto, a
fonte de aleatoriedade e os limites de recursos sem iniciar nenhum build.

O launcher começa antes de qualquer Bash ou loader dinâmico controlável pelo
ambiente, limpa integralmente o ambiente, congela o script aberto e mantém um
processo pai estático autenticado com uma capacidade por descritor. A execução
é um rebuild deliberadamente pesado; ela não faz parte da validação local
comum acima.

Essa autoridade pressupõe Linux com `procfs` disponível e sem um processo
hostil sob o mesmo UID capaz de usar `ptrace` contra a cerimônia. Execute o
rebuild em conta dedicada, com dumpability/ptrace restritos e sem processos não
confiáveis daquele UID. Ausência ou ocultação incompatível de `/proc` falha
fechado. O launcher deriva a raiz da própria localização e aceita realocação
do pacote íntegro; hashes de todos os builders/helper e as entradas do
manifesto recusam uma árvore substituída ou incompleta.

## 3. Preparar controles recuperáveis 2-de-3 para produção

O piloto usa três Safes separados. Cada Safe possui três owners exclusivos e
quórum 2-de-3; os nove endereços devem ser globalmente distintos. Nesta etapa
isolada, uma única pessoa pode operar nove keystores criptografados distintos.
Cada arquivo exige uma senha exclusiva digitada somente no prompt oculto. O
terceiro owner de cada Safe é a chave de recuperação daquele papel.

“Uma única pessoa opera” descreve a coordenação humana deste primeiro ensaio e
não muda a política criptográfica. A mesma pessoa controla nove chaves
Ethereum distintas: três para governança, três para o guardião da reserva e
três para o guardião de checkpoints. Cada ação de um papel exige duas
assinaturas produzidas por duas chaves diferentes daquele Safe 2-de-3. Uma
assinatura única nunca satisfaz o contrato. Os três Safes também continuam com
owners disjuntos; nenhuma chave pode ocupar dois papéis. O quórum protótipo de
atestadores 3-de-4 não é configurado por este piloto: o caminho de produção
usa as provas e checkpoints fixados no pacote de release.

A pessoa é o **operador/coordenador**, não uma identidade signer. Cada endereço
é uma identidade signer separada, com seed, senha, dispositivo e backup
próprios. Somente um dispositivo deve permanecer conectado por vez; ele deve ser
desconectado antes do próximo prompt. As três chaves `recovery` ficam em mídia
offline separada das chaves `primary` e `secondary`. Duas assinaturas do mesmo
endereço, duas derivações da mesma seed ou dois aliases do mesmo dispositivo não
formam quórum e devem abortar o ensaio.

O gerador abaixo produz o comando completo, cria cada keystore uma única vez
com o `cast` pinado, grava cópias criptografadas separadas em modo 0600 e
publica somente os nove endereços em um bundle JSON 0644 importável. Ele
rejeita schema v1, arquivos indiretos, hardlinks, cópias divergentes e qualquer
reutilização de owner entre os três papéis.

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc scripts/materialize-closed-mainnet-phase-script.sh enroll-safe-owners-secret
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc -n /home/leonardov/usdom-mainnet-private/operator-phases/enroll-safe-owners-secret.sh
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc /home/leonardov/usdom-mainnet-private/operator-phases/enroll-safe-owners-secret.sh
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc scripts/materialize-closed-mainnet-phase-script.sh migrate-safe-owners-hardware-secret
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc -n /home/leonardov/usdom-mainnet-private/operator-phases/migrate-safe-owners-hardware-secret.sh
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc /home/leonardov/usdom-mainnet-private/operator-phases/migrate-safe-owners-hardware-secret.sh
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc scripts/materialize-closed-mainnet-phase-script.sh prepare-safe-controls
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc -n /home/leonardov/usdom-mainnet-private/operator-phases/prepare-safe-controls.sh
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc /home/leonardov/usdom-mainnet-private/operator-phases/prepare-safe-controls.sh
```

O pacote resultante usa `usdom-safe-controls-recoverable/v2`, contém
`ownersByRole` e deriva três endereços CREATE2 distintos. Estes comandos não
transmitem transações. Copie o diretório
`/home/leonardov/usdom-mainnet-backup/safe-keystores` para mídia offline antes
de qualquer deploy; manter a cópia no mesmo disco não constitui recuperação
contra perda física. A ampliação de fundos exige migrar os owners para
dispositivos separados.

A fase de hardware cria nove provas EIP-712 offline. Cada prova vincula papel,
slot, owner, `packageHash`, chain ID 1 e o endereço CREATE2 do Safe daquele
papel. Se qualquer endereço ou assinatura falhar, o trap apaga os candidatos
em `/dev/shm`, nenhuma identidade hardware ativa é publicada e a configuração
de software continua incapaz de passar `prepare-safe-controls`. O suporte TPM
do wallet nativo não é tratado como signer Ethereum: até existir um signer TPM
secp256k1 auditado, os owners Safe desta fase usam hardware Ledger.

## 3.1 Implantar os controles recuperáveis — requer autorização explícita

Não execute este bloco sem autorização específica para os três deploys e ETH
na EOA primária apenas para gás. O executor deriva o dispositivo primário do
bundle autenticado, usa somente o proxy RPC local, grava o raw e sua validação
em um journal create-once antes de publicar e reclassifica a configuração
completa por quórum antes da assinatura, antes do envio e até a finalidade.

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc scripts/materialize-closed-mainnet-phase-script.sh execute-safe-controls-deployment-secret
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc -n /home/leonardov/usdom-mainnet-private/operator-phases/execute-safe-controls-deployment-secret.sh
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc /home/leonardov/usdom-mainnet-private/operator-phases/execute-safe-controls-deployment-secret.sh
```

## 3.2 Coletar o estado inicial finalizado dos três controles 2-de-3

Depois que os três deploys da seção 3.1 estiverem finalizados, execute este
bloco. Ele é somente leitura: não carrega chaves, não assina e não possui
capacidade de transmitir transações. Cada execução fixa um único bloco
`finalized`, recompõe o pacote a partir do bytecode Safe fixado e confere
storage, singleton, versão, owners, threshold, nonce, fallback, guard e módulos.
As duas RPCs podem estar em alturas finalizadas diferentes; por isso a
comparação remove apenas a identidade temporal do snapshot e exige igualdade
de todo o estado e de todos os hashes de configuração.

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
test -f "$USDOM_SAFE_PACKAGE"
test "$(sha256sum "$USDOM_SAFE_PACKAGE" | awk '{print $1}')" = "$USDOM_SAFE_PACKAGE_SHA256"

export USDOM_CONTROL_EVIDENCE_DIRECTORY=/home/leonardov/usdom-mainnet-private/control-plane
install -d -m 0700 "$USDOM_CONTROL_EVIDENCE_DIRECTORY"
export USDOM_SAFE_BASELINE="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-baseline-primary.json"
export USDOM_SAFE_BASELINE_SECONDARY="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-baseline-secondary.json"

timeout --signal=TERM 120s npm run --silent collect:recoverable-safe-controls \
  | node scripts/install-private-file-new-stdin.mjs "$USDOM_SAFE_BASELINE"
ETHEREUM_RPC_URL="$ETHEREUM_RPC_URL_2" timeout --signal=TERM 120s \
  npm run --silent collect:recoverable-safe-controls \
  | node scripts/install-private-file-new-stdin.mjs "$USDOM_SAFE_BASELINE_SECONDARY"

primary_normalized=$(mktemp)
secondary_normalized=$(mktemp)
trap 'rm -f -- "$primary_normalized" "$secondary_normalized"' EXIT
jq -S 'del(.finalizedBlockNumber,.finalizedBlockHash,.snapshotHash)' \
  "$USDOM_SAFE_BASELINE" > "$primary_normalized"
jq -S 'del(.finalizedBlockNumber,.finalizedBlockHash,.snapshotHash)' \
  "$USDOM_SAFE_BASELINE_SECONDARY" > "$secondary_normalized"
cmp -s "$primary_normalized" "$secondary_normalized"
rm -f -- "$primary_normalized" "$secondary_normalized"
trap - EXIT

for role in governance reserveGuardian checkpointGuardian; do
  jq -S --arg role "$role" '{
    schema,ethereumChainId,packageHash,finalizedBlockNumber,finalizedBlockHash,
    proxyRuntimeCodeHash,snapshotHash,
    role:(.roles[]|select(.role==$role))
  }' "$USDOM_SAFE_BASELINE" \
    | node scripts/install-private-file-new-stdin.mjs \
      "$USDOM_CONTROL_EVIDENCE_DIRECTORY/$role-configuration.json"
done

jq '{schema,packageHash,finalizedBlockNumber,finalizedBlockHash,
  proxyRuntimeCodeHash,snapshotHash,
  roles:[.roles[]|{role,address,configurationHash,owners,threshold,nonce,
    singleton,fallbackHandler,guard,modules}]}' "$USDOM_SAFE_BASELINE"
```

O ensaio de perda de chave usa outro coletor sobre três recibos finalizados. O
coletor já valida a transição e não envia nada, mas os comandos que constroem,
assinam em hardware e executam os três `swapOwner` serão fornecidos como um
bloco separado sujeito a autorização explícita. Até esse ensaio existir,
`production_control_plane_recovery_drill_passed` continua falso.

## 3.3 Preparar e assinar o ensaio de perda de uma chave por papel, sem transmitir

O ensaio v2 substitui uma chave diferente em cada Safe. O comando completo cria
as três transições a partir de dispositivos novos, prova a posse de cada
substituto por EIP-712, grava uma sessão durável antes dos arquivos derivados e
solicita os dois owners sobreviventes de cada papel. Ele produz somente o
calldata validado e não transmite.

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc scripts/materialize-closed-mainnet-phase-script.sh prepare-safe-recovery-secret
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc -n /home/leonardov/usdom-mainnet-private/operator-phases/prepare-safe-recovery-secret.sh
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc /home/leonardov/usdom-mainnet-private/operator-phases/prepare-safe-recovery-secret.sh
```

Se houver interrupção, gere e execute novamente o mesmo comando. A sessão
autenticada recupera arquivos ausentes e preserva assinaturas já duráveis. Pare
neste ponto até existir autorização específica para executar os três
`swapOwner`.

## 3.4 Executar o ensaio Safe — somente após autorização explícita

Este é o primeiro bloco desta seção que transmite operações de recuperação para
a Ethereum mainnet. Não o execute até autorizar especificamente os três
`swapOwner` e manter ETH suficiente para gás na chave secundária. O script é
retomável: ele deriva nonce, gás e taxas a partir de dois RPCs, grava cada raw
transaction antes de publicar e observa o evento finalizado antes de passar ao
próximo papel.

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc scripts/materialize-closed-mainnet-phase-script.sh execute-safe-recovery-secret
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc -n /home/leonardov/usdom-mainnet-private/operator-phases/execute-safe-recovery-secret.sh
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc /home/leonardov/usdom-mainnet-private/operator-phases/execute-safe-recovery-secret.sh
```

O script exige que os nonces `finalized` e `pending` coincidam nos dois RPCs,
estima o mesmo calldata nas duas visões, acrescenta 25% de margem e limita o
gás a 500.000. A gorjeta é fixa em 2 gwei, `maxFeePerGas` é duas vezes a maior
base fee observada mais a gorjeta e nunca pode exceder 500 gwei. Os dois RPCs
também precisam observar o relayer como EOA e saldo suficiente para o custo
máximo. Esse envelope é persistido e o raw EIP-1559 assinado precisa coincidir
exatamente com chain, relayer, nonce, gás, taxas, Safe, valor e calldata.

O script mostra papel, Safe, hash do calldata e hash do envelope antes do
primeiro envio e exige `AUTORIZO TRES SWAPOWNER SAFE MAINNET`. Se for
interrompido, execute exatamente o mesmo bloco: operações já finalizadas serão
apenas observadas, e uma raw transaction já assinada será reutilizada byte a
byte sem exigir o Ledger novamente. Não apague os arquivos
`*-recovery-envelope.json`, `*-recovery-raw-transaction.txt` nem
`*-recovery-submission-hash.txt` durante o ensaio.

## 3.5 Materializar a evidência Safe para a release

Execute este bloco somente depois de `safe-recovery-finalized-report.json` ter
sido produzido pela seção anterior. Ele não acessa RPC, hardware ou fundos e
não transmite transações. Os relatórios públicos são escritos em caminhos
fixos dentro de `evidence/control-plane/`; se um arquivo diferente já existir,
o comando falha em vez de sobrescrevê-lo.

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
export USDOM_CONTROL_EVIDENCE_DIRECTORY=/home/leonardov/usdom-mainnet-private/control-plane
export USDOM_SAFE_PACKAGE="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-package.json"
export USDOM_SAFE_BASELINE="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-baseline-primary.json"
export USDOM_SAFE_RECOVERY_REPORT="$USDOM_CONTROL_EVIDENCE_DIRECTORY/safe-recovery-finalized-report.json"
npm run --silent write:recoverable-safe-release-evidence
```

O JSON exibido é o fragmento canônico que o materializador da release deve
consumir. Não copie campos manualmente. O gate lê novamente o bundle, os três
relatórios de papel, o relatório de separação e o drill; todos precisam
concordar entre si e com os endereços, code hashes e configuration hashes da
release.

## 3.6 Fixar as identidades Safe na configuração fonte

Este comando consome novamente os arquivos canônicos da seção 3.5 e grava
somente os três endereços Safe e seus três runtime code hashes em
`config/proof-reserve.unconfigured.json`. Ele mantém `productionReady` e
`realFundsAuthorized` falsos, não acessa RPC, não assina e não cria commit. Um
valor preexistente diferente faz o comando falhar.

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
npm run --silent materialize:safe-control-release-config
```

Execute essa fase antes de criar o commit fonte imutável. Os metadados e hashes
dos relatórios não entram nesse arquivo e serão materializados somente depois
do commit fonte.

## 3.7 Fixar a política limitada do primeiro piloto

O primeiro teste fechado em Ethereum mainnet fica limitado a 1 USDT de
exposição total e 1 USDT de saída por dia. A espera de saque é 24 horas e o
atraso administrativo é 48 horas. As margens nativas são fixadas em 3.600,
1.800 e 7.200 segundos. O comando não aceita argumentos, preserva
`productionReady=false` e `realFundsAuthorized=false`, e falha se algum desses
campos já contiver uma política diferente.

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
npm run --silent materialize:limited-mainnet-policy
```

Esse limite comporta somente o depósito fechado de 1 USDT definido neste
runbook. Uma ampliação futura exige outra release e outra autorização exata.

## 3.8 Derivar deployer, nonces e quatro endereços CREATE

Conecte a Ledger que financiará somente os deployments. O comando lê o mesmo
endereço duas vezes, consulta duas RPCs HTTPS independentes e recusa uma conta
com código, nonce pendente, divergência de nonce ou qualquer endereço CREATE já
ocupado. Ele reserva quatro nonces consecutivos na ordem: adaptador de queima,
adaptador de checkpoint, registry e reserva. Nenhuma assinatura é solicitada.

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
export ETHEREUM_RPC_URL='https://ethereum-rpc.publicnode.com'
export ETHEREUM_RPC_URL_2='https://rpc.mevblocker.io'
export USDOM_CONTROL_EVIDENCE_DIRECTORY=/home/leonardov/usdom-mainnet-private/control-plane
npm run --silent materialize:mainnet-deployment-identity
```

O resultado público fica na configuração fonte. As duas observações
finalizadas, sem URLs, ficam em
`$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-deployment-identity-observation.json`.
Não envie outra transação pelo deployer entre esta etapa e os quatro CREATEs.

## 4. Configurar a release sem inventar fatos

Não edite os JSONs nem substitua campos manualmente. O diagnóstico abaixo
lista os fatos públicos que ainda precisam ser produzidos pelos materializadores
das etapas seguintes. Ele é apenas uma conferência; nenhum campo deve ser
copiado, preenchido ou devolvido manualmente.

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

Enquanto um item continuar desconhecido, o gate impede o avanço. Nunca altere
`productionReady` ou autorizações por edição direta.

Quando o exportador nativo tiver gravado o checkpoint inicial canônico em
`config/native-release-facts.unconfigured.json` e os dois manifestos de prova
estiverem completos, derive o núcleo em estágios, sem copiar hashes. A ordem é
obrigatória porque o runtime do registry entra na configuração da reserva:

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
npm run --silent materialize:production-release-core -- registry-pins
npm run --silent materialize:production-solidity-pins -- checkpointRegistry
forge build --offline contracts/DOMCheckpointRegistry.sol
npm run --silent materialize:production-release-core -- reserve-pins
npm run --silent materialize:production-solidity-pins -- reserve
forge build --offline contracts/USDOMProofReserve.sol
npm run --silent materialize:production-release-core -- final
node scripts/prepare-production-release-core-materialization.mjs final \
  | cmp -s - config/proof-reserve.unconfigured.json
```

Cada estágio valida integralmente os manifestos e snapshots de entrada. Primeiro
fixa e compila somente o registry; depois liga seu runtime à configuração da
reserva, fixa e compila somente a reserva; por fim deriva novamente ambos os
artefatos e exige igualdade byte a byte com a configuração instalada. Os
writers recusam pin preexistente divergente, mantêm `productionReady=false` e
`realFundsAuthorized=false`, e uma repetição aceita somente bytes idênticos.

## 5. Construir e verificar a release localmente

```bash
set -euo pipefail
umask 077
cd "$USDOM_PROJECT"
forge build contracts/USDOMProofReserve.sol contracts/DOMCheckpointRegistry.sol \
  contracts/DOMFinalizedBurnRiscZeroVerifier.sol contracts/DOMCheckpointRiscZeroVerifier.sol \
  --force --ignored-error-codes 6335 -D warnings
npm run check:provenance

export ETHEREUM_RPC_URL='https://ethereum-rpc.publicnode.com'
export ETHEREUM_RPC_URL_2='https://rpc.mevblocker.io'
test "$(cast chain-id --rpc-url "$ETHEREUM_RPC_URL")" = "1"
test "$(cast chain-id --rpc-url "$ETHEREUM_RPC_URL_2")" = "1"
export USDOM_CONTROL_EVIDENCE_DIRECTORY=/home/leonardov/usdom-mainnet-private/control-plane
export USDOM_RELEASE_SIGNING_PUBLIC_IDENTITY="$USDOM_CONTROL_EVIDENCE_DIRECTORY/release-signing-public-identity.json"
SIGNING_IDENTITY_CANDIDATE=$(mktemp)
trap 'rm -f "$SIGNING_IDENTITY_CANDIDATE"' EXIT
npm run --silent configure:release-signing-key > "$SIGNING_IDENTITY_CANDIDATE"
node scripts/install-private-file-immutable-stdin.mjs "$USDOM_RELEASE_SIGNING_PUBLIC_IDENTITY" \
  < "$SIGNING_IDENTITY_CANDIDATE"
rm -f "$SIGNING_IDENTITY_CANDIDATE"
trap - EXIT
export USDOM_RELEASE_SIGNING_KEY_FINGERPRINT="$(
  node scripts/read-private-file-stdout.mjs "$USDOM_RELEASE_SIGNING_PUBLIC_IDENTITY" | jq -er '.fingerprint'
)"
CLOSED_MAINNET_DIAGNOSTIC=$(mktemp)
trap 'rm -f "$CLOSED_MAINNET_DIAGNOSTIC"' EXIT
if node scripts/check-mainnet-readiness.mjs closed-mainnet > "$CLOSED_MAINNET_DIAGNOSTIC"; then
  diagnostic_status=0
else
  diagnostic_status=$?
fi
test "$diagnostic_status" -eq 1
jq -e '.ready == false and .blockerCount > 0' "$CLOSED_MAINNET_DIAGNOSTIC" >/dev/null
jq -r '.blockers[] | [.code,.detail] | @tsv' "$CLOSED_MAINNET_DIAGNOSTIC"
rm -f "$CLOSED_MAINNET_DIAGNOSTIC"
trap - EXIT
```

Antes dos adaptadores existirem, o gate completo deve permanecer fechado porque
a evidência de predeployment ainda não pode ser produzida. Não transforme esse
estado esperado em `ready: true` manualmente. Devolva o JSON de blockers; cada
fato local será implementado no código e cada ação externa receberá um novo
comando completo. Os dois primeiros broadcasts continuam sujeitos à
autorização explícita.

Não crie o commit fonte neste ponto. Deploys, benchmarks, ensaios e fatos
operacionais das seções seguintes ainda precisam completar o ledger fonte. A
cerimônia assinada começa somente na seção 23; criar o commit antes tornaria
esses fatos impossíveis de registrar sem violar a regra do filho exclusivamente
de evidência.

## 6. Gerar o pacote unsigned dos quatro CREATEs

Os quatro deployers e nonces já fazem parte da configuração exata da release.
O mesmo EOA de hardware pode ser usado com quatro nonces consecutivos. Não
envie nenhuma transação concorrente desse EOA entre a preparação e a
implantação.

Use uma EOA exclusiva e não deposite mais de 1 ETH nela. O executor recusa
saldo superior a 1 ETH, custo máximo superior a 0,6 ETH por CREATE, soma dos
quatro envelopes superior a 1 ETH ou `maxFeePerGas` superior a 100 gwei. Os
três endereços Safe previstos e os quatro contratos previstos devem ter saldo
zero antes da criação; não financie nenhum deles diretamente. Todos os CREATEs
têm `value=0` e a transação assinada é revalidada com aritmética `BigInt`.

Os tetos integrais por pagador são: Safe deployer 0,30 ETH (três deploys),
contract deployer 1 ETH (quatro CREATEs), deposit funder 0,15 ETH (três
transações), redemption relayer 0,20 ETH (duas transações) e recovery relayer
0,75 ETH (três papéis). Se o mesmo endereço assumir mais de uma dessas funções,
some os tetos antes de financiar. Cada executor consulta o endereço público do
Ledger e os saldos em dois RPCs; isso não exporta seed nem chave privada.

Não há substituição ou cancelamento automático: um raw já assinado pode apenas
ser republicado byte a byte ou recuperado pelo mesmo hash. Outro hash no mesmo
nonce aborta o fluxo. Sobra de ETH permanece no pagador e é reportada como
surplus; não existe sweep/refund automático. Qualquer retirada posterior é uma
operação fora do piloto e exige revisão e autorização próprias.

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc scripts/materialize-closed-mainnet-phase-script.sh prepare-deployment
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc -n /home/leonardov/usdom-mainnet-private/operator-phases/prepare-deployment.sh
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc /home/leonardov/usdom-mainnet-private/operator-phases/prepare-deployment.sh
```

O programa gerado calcula o compromisso da observação e relê o pacote somente
pelas fronteiras privadas autenticadas. Uma retomada aceita apenas os mesmos
bytes; qualquer pacote divergente falha sem substituir o inode existente.

## 7. Conferir os quatro CREATEs antes de qualquer broadcast

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
jq -c '.transactions[]' "$USDOM_MAINNET_DEPLOYMENT_PACKAGE" | while read -r tx; do
  from=$(jq -r '.from' <<<"$tx")
  nonce=$(jq -r '.nonce' <<<"$tx")
  test "$(cast nonce "$from" --block finalized --rpc-url "$ETHEREUM_RPC_URL")" = "$nonce"
  test "$(cast code "$(jq -r '.expectedContract' <<<"$tx")" --block finalized --rpc-url "$ETHEREUM_RPC_URL")" = "0x"
  cast estimate --create "$(jq -r '.data' <<<"$tx")" --from "$from" --block finalized \
    --rpc-url "$ETHEREUM_RPC_URL"
done
```

## 8. Implantar somente os dois adaptadores — exige autorização explícita

O bloco seguinte cria contratos e gasta ETH. Ele pede uma confirmação literal
antes de assinar cada índice e outra somente quando a transmissão é necessária,
grava o raw transaction e seu hash antes da transmissão,
executa os índices 0 e 1 em ordem, espera cada contrato chegar ao estado
`finalized` e só então passa ao próximo. Confira no dispositivo `chainId`,
deployer, nonce, ausência de destinatário, valor zero e hash do initcode.

```bash
set -euo pipefail
for INDEX in 0 1; do
  npm run --silent execute:mainnet-deployment -- "$INDEX"
done
```

Registre os dois hashes, espere os contratos aparecerem no bloco `finalized` e
confira os endereços previstos:

```bash
set -euo pipefail
umask 077
cd "$USDOM_PROJECT"
export USDOM_CONTROL_EVIDENCE_DIRECTORY=/home/leonardov/usdom-mainnet-private/control-plane
export USDOM_FINALIZED_BURN_VERIFIER_DEPLOYMENT_TX_HASH=$(node scripts/read-private-file-stdout.mjs \
  "$USDOM_CONTROL_EVIDENCE_DIRECTORY/contract-deployment-0-receipt.json" | jq -er '.transactionHash')
export USDOM_CHECKPOINT_VERIFIER_DEPLOYMENT_TX_HASH=$(node scripts/read-private-file-stdout.mjs \
  "$USDOM_CONTROL_EVIDENCE_DIRECTORY/contract-deployment-1-receipt.json" | jq -er '.transactionHash')
for INDEX in 0 1; do
  EXPECTED=$(jq -er ".transactions[$INDEX].expectedContract" "$USDOM_MAINNET_DEPLOYMENT_PACKAGE")
  test "$(cast code "$EXPECTED" --block finalized --rpc-url "$ETHEREUM_RPC_URL")" != "0x"
done
```

Se o último comando falhar, aguarde a finalização e execute apenas esse bloco
de conferência novamente. Não retransmita uma transação já minerada.

## 9. Preflight intermediário e gate fechado

Agora os adaptadores devem estar ativos, enquanto os endereços do registry e da
reserva ainda estão vazios. O bloco grava uma única observação privada,
recomputa integralmente o relatório e materializa seu hash e o requisito
correspondente sem edição manual da release.

```bash
set -euo pipefail
umask 077
cd "$USDOM_PROJECT"
export USDOM_CONTROL_EVIDENCE_DIRECTORY=/home/leonardov/usdom-mainnet-private/control-plane
export USDOM_PREDEPLOYMENT_ATTESTATION="$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-predeployment-attestation.json"
PREFLIGHT_CANDIDATE=$(mktemp)
trap 'rm -f "$PREFLIGHT_CANDIDATE"' EXIT
if ! USDOM_FINALIZED_BURN_VERIFIER_DEPLOYMENT_TX_HASH="$USDOM_FINALIZED_BURN_VERIFIER_DEPLOYMENT_TX_HASH" \
  USDOM_CHECKPOINT_VERIFIER_DEPLOYMENT_TX_HASH="$USDOM_CHECKPOINT_VERIFIER_DEPLOYMENT_TX_HASH" \
  node scripts/check-mainnet-preflight.mjs predeployment > "$PREFLIGHT_CANDIDATE"; then
  cat "$PREFLIGHT_CANDIDATE"
  exit 1
fi
node scripts/install-private-file-new-stdin.mjs "$USDOM_PREDEPLOYMENT_ATTESTATION" \
  < "$PREFLIGHT_CANDIDATE"
rm -f "$PREFLIGHT_CANDIDATE"
trap - EXIT
node scripts/read-private-file-stdout.mjs "$USDOM_PREDEPLOYMENT_ATTESTATION" \
  | jq -e '.ready == true and .blockerCount == 0'
npm run --silent materialize:mainnet-predeployment-attestation

```

Atualize e verifique o manifesto de integridade depois da materialização. O gate
fechado deve ficar verde antes de qualquer broadcast do registry ou da reserva.

## 10. Implantar registry e reserva pausada — exige autorização explícita

Com o gate fechado verde, execute o bloco completo abaixo. Ele pede sua
confirmação antes de assinar e antes de transmitir cada índice, rederiva o pacote antes de cada assinatura e executa os índices 2
e 3 em ordem, sem edição de variável.

```bash
set -euo pipefail
for INDEX in 2 3; do
  npm run --silent execute:mainnet-deployment -- "$INDEX"
done

export USDOM_CHECKPOINT_REGISTRY_DEPLOYMENT_TX_HASH=$(node scripts/read-private-file-stdout.mjs \
  "$USDOM_CONTROL_EVIDENCE_DIRECTORY/contract-deployment-2-receipt.json" | jq -er '.transactionHash')
export USDOM_DEPLOYMENT_TX_HASH=$(node scripts/read-private-file-stdout.mjs \
  "$USDOM_CONTROL_EVIDENCE_DIRECTORY/contract-deployment-3-receipt.json" | jq -er '.transactionHash')
for INDEX in 2 3; do
  EXPECTED=$(jq -er ".transactions[$INDEX].expectedContract" "$USDOM_MAINNET_DEPLOYMENT_PACKAGE")
  test "$(cast code "$EXPECTED" --block finalized --rpc-url "$ETHEREUM_RPC_URL")" != "0x"
done
```

A reserva nasce pausada em Ethereum mainnet. Se a conferência falhar, aguarde a
finalização e repita somente a conferência.

## 11. Cold start finalizado dos quatro deployments

```bash
set -euo pipefail
umask 077
cd "$USDOM_PROJECT"
export USDOM_CONTROL_EVIDENCE_DIRECTORY=/home/leonardov/usdom-mainnet-private/control-plane
export USDOM_FINALIZED_BURN_VERIFIER_DEPLOYMENT_TX_HASH=$(node scripts/read-private-file-stdout.mjs \
  "$USDOM_CONTROL_EVIDENCE_DIRECTORY/contract-deployment-0-receipt.json" | jq -er '.transactionHash')
export USDOM_CHECKPOINT_VERIFIER_DEPLOYMENT_TX_HASH=$(node scripts/read-private-file-stdout.mjs \
  "$USDOM_CONTROL_EVIDENCE_DIRECTORY/contract-deployment-1-receipt.json" | jq -er '.transactionHash')
export USDOM_CHECKPOINT_REGISTRY_DEPLOYMENT_TX_HASH=$(node scripts/read-private-file-stdout.mjs \
  "$USDOM_CONTROL_EVIDENCE_DIRECTORY/contract-deployment-2-receipt.json" | jq -er '.transactionHash')
export USDOM_DEPLOYMENT_TX_HASH=$(node scripts/read-private-file-stdout.mjs \
  "$USDOM_CONTROL_EVIDENCE_DIRECTORY/contract-deployment-3-receipt.json" | jq -er '.transactionHash')

export USDOM_COLD_START_ATTESTATION="$USDOM_CONTROL_EVIDENCE_DIRECTORY/mainnet-cold-start-attestation.json"
COLD_START_CANDIDATE=$(mktemp)
trap 'rm -f "$COLD_START_CANDIDATE"' EXIT
if ! USDOM_FINALIZED_BURN_VERIFIER_DEPLOYMENT_TX_HASH="$USDOM_FINALIZED_BURN_VERIFIER_DEPLOYMENT_TX_HASH" \
  USDOM_CHECKPOINT_VERIFIER_DEPLOYMENT_TX_HASH="$USDOM_CHECKPOINT_VERIFIER_DEPLOYMENT_TX_HASH" \
  USDOM_DEPLOYMENT_TX_HASH="$USDOM_DEPLOYMENT_TX_HASH" \
  USDOM_CHECKPOINT_REGISTRY_DEPLOYMENT_TX_HASH="$USDOM_CHECKPOINT_REGISTRY_DEPLOYMENT_TX_HASH" \
  node scripts/check-mainnet-preflight.mjs postdeployment > "$COLD_START_CANDIDATE"; then
  cat "$COLD_START_CANDIDATE"
  exit 1
fi
node scripts/install-private-file-new-stdin.mjs "$USDOM_COLD_START_ATTESTATION" \
  < "$COLD_START_CANDIDATE"
rm -f "$COLD_START_CANDIDATE"
trap - EXIT
node scripts/read-private-file-stdout.mjs "$USDOM_COLD_START_ATTESTATION" \
  | jq -e '.ready == true and .blockerCount == 0 and .observation.reserve.paused == true'
npm run --silent materialize:mainnet-cold-start-attestation
```

O preflight autentica as quatro transações, os quatro initcodes, os hashes de
código e a configuração viva. Não deposite USDT até o gate `real-funds`
continuar verde sobre a evidência finalizada, a retomada atrasada ser executada
pela governança e o limite monetário fechado ser explicitamente aprovado:

```bash
set -euo pipefail
umask 077
REAL_FUNDS_CANDIDATE=$(mktemp)
trap 'rm -f "$REAL_FUNDS_CANDIDATE"' EXIT
if ! node scripts/check-mainnet-readiness.mjs real-funds > "$REAL_FUNDS_CANDIDATE"; then
  cat "$REAL_FUNDS_CANDIDATE"
  exit 1
fi
jq -e '.ready == true and .blockerCount == 0' "$REAL_FUNDS_CANDIDATE"
rm -f "$REAL_FUNDS_CANDIDATE"
trap - EXIT
```

## 12. Criar e verificar a carteira nativa de recebimento

Execute somente depois que a configuração exata da release tiver sido
incorporada e o `domDomain` deixar de ser nulo. Este comando não transmite uma
transação. Ele solicita a senha sem eco, cria um backup criptografado fora do
repositório e verifica imediatamente a restauração. Em uma repetição, ele
revalida o mesmo backup e o mesmo endereço em vez de criar outra identidade.

```bash
set -euo pipefail
umask 077
cd "$USDOM_PROJECT"
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc scripts/materialize-closed-mainnet-phase-script.sh prepare-native-wallet-secret
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc -n /home/leonardov/usdom-mainnet-private/operator-phases/prepare-native-wallet-secret.sh
env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc /home/leonardov/usdom-mainnet-private/operator-phases/prepare-native-wallet-secret.sh
```

Devolva apenas o JSON público. Não envie a senha nem o arquivo
`recovery.usdom`. O `receivingCommitment` desse JSON será incorporado pelo
comando fechado de depósito quando a release, a finalização de Ethereum e o
ingresso nativo estiverem prontos.

## 13. Gerar o pacote unsigned do primeiro depósito fechado

Depois que a release exata estiver configurada, assinada e com o gate de fundos
reais verde, conecte e desbloqueie o Ledger. O comando deriva duas vezes o mesmo
endereço público, gera um salt aleatório e produz as três chamadas para
`approve(0)`, `approve(1 USDT)` e `deposit(1 USDT)`. Ele não acessa RPC, não
solicita assinatura e não transmite transações.

```bash
set -euo pipefail
umask 077
cd "$USDOM_PROJECT"
export USDOM_CONTROL_EVIDENCE_DIRECTORY=/home/leonardov/usdom-mainnet-private/control-plane
export USDOM_CLOSED_MAINNET_DEPOSIT_PACKAGE="$USDOM_CONTROL_EVIDENCE_DIRECTORY/closed-mainnet-deposit-package.json"
DEPOSIT_PACKAGE_CANDIDATE=$(mktemp)
trap 'rm -f "$DEPOSIT_PACKAGE_CANDIDATE"' EXIT
npm run --silent prepare:closed-mainnet-deposit > "$DEPOSIT_PACKAGE_CANDIDATE"
node scripts/install-private-file-new-stdin.mjs "$USDOM_CLOSED_MAINNET_DEPOSIT_PACKAGE" \
  < "$DEPOSIT_PACKAGE_CANDIDATE"
rm -f "$DEPOSIT_PACKAGE_CANDIDATE"
trap - EXIT
node scripts/read-private-file-stdout.mjs "$USDOM_CLOSED_MAINNET_DEPOSIT_PACKAGE" | jq -e '
  .schema == "usdom-closed-mainnet-deposit-v1"
  and .ethereumChainId == "1"
  and .amountBaseUnits == "1000000"
  and .broadcastAuthorized == false
  and (.transactions | length) == 3
'
sha256sum "$USDOM_CLOSED_MAINNET_DEPOSIT_PACKAGE"
```

Guarde esse JSON público para a conferência final. Não execute as calldatas por
conta própria. Depois da evidência finalizada da implantação, da abertura
atrasada da reserva, do gate `real-funds` verde e de autorização explícita para
movimentar exatamente 1 USDT, execute o comando completo abaixo:

```bash
set -euo pipefail
cd /home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve
bash scripts/execute-closed-mainnet-deposit.sh
```

O executor não confia em `broadcastAuthorized` para conceder autoridade: o
pacote continua obrigatoriamente falso. Para cada etapa ele prepara o envelope,
pede autorização de assinatura na Ledger, valida o raw EIP-1559 offline e só
então pede autorização distinta para publicar. Nonce, chain 1, destinatário,
value zero, calldata, taxas e gás são exatos. Dois RPCs precisam confirmar a
transação no mesmo bloco já finalizado e a allowance deve seguir `0 → 1 USDT →
0`. Recibos e validações são gravados antes do relatório final; uma repetição
revalida etapas já finalizadas e não as transmite novamente.

A configuração `pilotRestricted` também impõe essa propriedade dentro do
contrato. No início de `deposit`, a allowance do funder para a reserva deve ser
exatamente `1_000_000`; após `transferFrom`, deve ser zero. Autorizações maiores,
autorizações residuais e retornos `allowance()` malformados ou excessivos
revertem toda a operação, inclusive o consumo da autorização única do piloto.

## 14. Coletar a fonte pública do depósito depois da finalidade

O futuro comando autorizado de broadcast gravará automaticamente o hash da
transação no arquivo fixo esperado pelo coletor. Depois que o depósito estiver
finalizado, execute:

```bash
set -euo pipefail
umask 077
cd "$USDOM_PROJECT"
SOURCE_SUMMARY=$(mktemp)
trap 'rm -f "$SOURCE_SUMMARY"' EXIT
npm run --silent collect:finalized-deposit-source > "$SOURCE_SUMMARY"
jq -e '
  .status == "collected"
  and .amountBaseUnits == "1000000"
  and .broadcasts == false
  and .mines == false
' "$SOURCE_SUMMARY"
rm -f "$SOURCE_SUMMARY"
trap - EXIT
```

O comando pedirá, sem eco, uma URL HTTPS de RPC de execução e uma URL HTTPS da
API Beacon. As URLs não são gravadas. O JSON persistido contém somente dados
públicos não confiáveis; ele ainda precisa passar pelo construtor/verificador
Rust UDOMDPW1 antes de poder entrar em um bloco DOM.

## 15. Autenticar e construir a testemunha UDOMDPW1

Depois da coleta anterior, execute o construtor local. Ele não usa RPC e não
aceita campos manuais:

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
npm run --silent build:finalized-deposit-witness
test -s evidence/finalized-deposit-witness/finalized-deposit-witness.bin
jq -e '
  .schema == "usdom-finalized-deposit-witness-v1"
  and .amount_base_units == "1000000"
  and .relation_executed == true
  and .witness_verified == true
  and .mines == false
  and .broadcasts == false
' evidence/finalized-deposit-witness/finalized-deposit-witness-index.json
sha256sum -c <(jq -r '"\(.witness_sha256)  evidence/finalized-deposit-witness/\(.witness_file)"' \
  evidence/finalized-deposit-witness/finalized-deposit-witness-index.json)
```

O binário refaz BLS/SSZ, cabeçalhos e tries e depois reexecuta os bytes finais
pela mesma política de consenso. A emissão nativa ainda depende da inclusão
dessa testemunha em um bloco DOM válido após a ativação exata.

## 16. Iniciar o nó DOM mainnet fechado sem mineração

Em um terminal próprio, inicie o nó com a identidade mainnet e o manifesto
nativo fixado. O comando cria sozinho um bearer token de 256 bits em arquivo
0600. P2P fica preso ao loopback, descoberta DNS, conexões de entrada/saída e
mineração ficam desativadas:

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
npm run --silent run:closed-mainnet-node
```

Mantenha esse terminal aberto. O processo usa
`$HOME/.local/share/dom-usdom/mainnet-node/data` e expõe somente o RPC
autenticado em `127.0.0.1:33372`. O comando não gera endereço de mineração e
não produz blocos.

## 17. Inicializar o genesis DOM mainnet fixo

Em outro terminal, inicialize somente o bloco genesis canônico. A chamada é
autenticada, compara o estado vazio esperado e não inicia mineração contínua.
Se o genesis já existir, o comando apenas o revalida:

```bash
set -euo pipefail
umask 077
cd "$USDOM_PROJECT"
GENESIS_SUMMARY=$(mktemp)
trap 'rm -f "$GENESIS_SUMMARY"' EXIT
npm run --silent initialize:closed-mainnet-genesis > "$GENESIS_SUMMARY"
jq -e '
  .schema == "usdom-closed-mainnet-genesis-v1"
  and .network == "mainnet"
  and .tipHeight == "0"
  and .continuousMining == false
  and .peering == false
' "$GENESIS_SUMMARY"
rm -f "$GENESIS_SUMMARY"
trap - EXIT
```

## 18. Registrar o depósito na carteira nativa antes da submissão

Antes do primeiro registro, instale as ferramentas TPM e conceda ao login
acesso ao resource manager. Este comando não cria nem altera índices TPM:

```bash
set -euo pipefail
sudo apt-get update
sudo apt-get install -y --no-install-recommends tpm2-tools
sudo usermod -aG tss "$(id -un)"
printf '%s\n' 'Saia completamente da sessão Linux e entre novamente antes de continuar.'
```

Após o novo login, provisione uma única vez o segundo fator da carteira. O
comando pede a senha de recuperação e a autorização de owner do TPM em terminal
oculto; pressionar Enter corresponde a owner auth vazia:

```bash
set -euo pipefail
umask 077
cd "$USDOM_PROJECT"
TPM_SUMMARY=$(mktemp)
trap 'rm -f "$TPM_SUMMARY"' EXIT
npm run --silent provision:closed-mainnet-tpm-keystore > "$TPM_SUMMARY"
grep -Fx 'status: tpm-wallet-keystore-provisioned' "$TPM_SUMMARY"
grep -Fx 'operational_password_exported: false' "$TPM_SUMMARY"
grep -Fx 'submits: false' "$TPM_SUMMARY"
grep -Fx 'mines: false' "$TPM_SUMMARY"
grep -Fx 'ethereum_broadcasts: false' "$TPM_SUMMARY"
rm -f "$TPM_SUMMARY"
trap - EXIT
```

Não repita a provisão para tentar corrigir uma falha. Um índice existente que
não coincida deve ser tratado como incidente de recuperação e analisado antes
de qualquer mudança no TPM.

Com o nó DOM mainnet configurado em execução no loopback padrão, registre a
nota esperada no estado criptografado da mesma carteira usada no depósito. O
comando pede somente a senha de recuperação sem eco, exige o segundo fator TPM,
revalida integralmente o UDOMDPW1 e não submete nem minera:

```bash
set -euo pipefail
umask 077
cd "$USDOM_PROJECT"
REGISTRATION_SUMMARY=$(mktemp)
trap 'rm -f "$REGISTRATION_SUMMARY"' EXIT
npm run --silent register:finalized-deposit-wallet > "$REGISTRATION_SUMMARY"
grep -Eq '^status: (registered|already-registered)$' "$REGISTRATION_SUMMARY"
grep -Fx 'amount_base_units: 1000000' "$REGISTRATION_SUMMARY"
grep -Fx 'submits: false' "$REGISTRATION_SUMMARY"
grep -Fx 'mines: false' "$REGISTRATION_SUMMARY"
rm -f "$REGISTRATION_SUMMARY"
trap - EXIT
```

O estado é publicado em
`$HOME/.local/share/dom-usdom/mainnet-wallet/registered-state-v1` somente após
snapshot, selo e registro estarem duráveis. Uma repetição aceita apenas o mesmo
depósito e a mesma carteira.

## 19. Submeter a emissão verificada ao pool nativo

Esta ação altera somente o pool volátil do nó DOM local. Ela não produz bloco,
não minera DOM e não envia transação à Ethereum. Execute apenas quando a
submissão do testemunho tiver sido autorizada:

```bash
set -euo pipefail
umask 077
cd "$USDOM_PROJECT"
ISSUANCE_SUMMARY=$(mktemp)
trap 'rm -f "$ISSUANCE_SUMMARY"' EXIT
npm run --silent submit:finalized-deposit-issuance > "$ISSUANCE_SUMMARY"
jq -e '
  .schema == "usdom-finalized-deposit-issuance-submission-v1"
  and .amountBaseUnits == "1000000"
  and .state == "queued"
  and .mined == false
  and .broadcastsEthereum == false
' "$ISSUANCE_SUMMARY"
rm -f "$ISSUANCE_SUMMARY"
trap - EXIT
```

O nó reexecuta a verificação de finalidade e depósito antes de aceitar o
candidato. A produção do bloco DOM é uma etapa separada e permanece desativada
até autorização específica.

## 20. Produzir exatamente um bloco com a emissão

Esta é uma ação de mineração e exige autorização específica do operador. O
comando aceita somente o tip mainnet exato registrado na submissão, exige altura
zero e chama a capacidade isolada que produz no máximo um bloco. Ele não ativa
o minerador contínuo e não pode conectar peers:

```bash
set -euo pipefail
umask 077
cd "$USDOM_PROJECT"
MINING_SUMMARY=$(mktemp)
trap 'rm -f "$MINING_SUMMARY"' EXIT
npm run --silent mine:closed-mainnet-issuance-block > "$MINING_SUMMARY"
jq -e '
  .schema == "usdom-closed-mainnet-issuance-block-v1"
  and .parentHeight == "0"
  and .blockHeight == "1"
  and .exactlyOneBlock == true
  and .continuousMining == false
  and .issuanceObserved == false
' "$MINING_SUMMARY"
rm -f "$MINING_SUMMARY"
trap - EXIT
```

`issuanceObserved` permanece falso neste recibo por desenho: produzir um bloco
não substitui a varredura autenticada da carteira. O passo seguinte deve provar
que o compromisso esperado entrou no histórico canônico antes de declarar o
saldo utilizável.

## 21. Observar a emissão na carteira criptografada

Depois do bloco único, faça a carteira autenticar cabeçalho, compromisso do
lote, transição e raízes de estado. A senha fica somente em arquivo temporário
0600 em `/dev/shm`. O comando não submete, transmite ou minera:

```bash
set -euo pipefail
umask 077
cd "$USDOM_PROJECT"
OBSERVATION_SUMMARY=$(mktemp)
trap 'rm -f "$OBSERVATION_SUMMARY"' EXIT
npm run --silent observe:finalized-deposit-wallet > "$OBSERVATION_SUMMARY"
grep -Fx 'status: observed' "$OBSERVATION_SUMMARY"
grep -Fx 'available_balance_base_units: 1000000' "$OBSERVATION_SUMMARY"
grep -Fx 'block_height: 1' "$OBSERVATION_SUMMARY"
grep -Fx 'history_authenticated: true' "$OBSERVATION_SUMMARY"
grep -Fx 'broadcasts: false' "$OBSERVATION_SUMMARY"
grep -Fx 'mines: false' "$OBSERVATION_SUMMARY"
rm -f "$OBSERVATION_SUMMARY"
trap - EXIT
```

A nova geração é publicada em
`$HOME/.local/share/dom-usdom/mainnet-wallet/observed-state-v1`. O diretório
anterior permanece intacto; a publicação só ocorre depois de snapshot, selo e
recibo estarem sincronizados e de a nota exata aparecer canônica com saldo de
1.000.000 unidades base.

## 22. Ensaiar recuperação sem confiar no snapshot operacional

Quando `evidence/finalized-burn-source/checkpoint-witness.bin` contiver um
checkpoint Ethereum finalizado posterior à emissão, execute a recuperação em
um diretório novo. O comando ignora todos os snapshots operacionais existentes,
restaura a carteira pelo backup portátil, autentica novamente o depósito e o
checkpoint e reconstrói o histórico DOM completo pelo RPC local:

```bash
set -euo pipefail
umask 077
cd "$USDOM_PROJECT"
RECOVERY_SUMMARY=$(mktemp)
trap 'rm -f "$RECOVERY_SUMMARY"' EXIT
npm run --silent drill:closed-mainnet-wallet-recovery > "$RECOVERY_SUMMARY"
grep -Fx 'status: recovered-at-verified-checkpoint' "$RECOVERY_SUMMARY"
grep -Fx 'existing_operational_snapshot_read: false' "$RECOVERY_SUMMARY"
grep -Fx 'ethereum_broadcasts: false' "$RECOVERY_SUMMARY"
grep -Fx 'submits: false' "$RECOVERY_SUMMARY"
grep -Fx 'mines: false' "$RECOVERY_SUMMARY"
rm -f "$RECOVERY_SUMMARY"
trap - EXIT
```

A saída fixa é
`$HOME/.local/share/dom-usdom/mainnet-wallet/recovery-drill-v1`. Se a nota já
tiver sido queimada no checkpoint escolhido, o resultado correto registra
`note_spent_at_checkpoint: true` e saldo zero. O ensaio não deve reinterpretar
uma nota gasta como saldo disponível.

## 23. Criar o commit fonte assinado somente depois dos fatos técnicos

Execute esta seção apenas depois que todos os campos técnicos da configuração,
todos os requisitos fonte, benchmarks e ensaios objetivos estiverem concluídos.
O comando exige `productionReady`, `mainnet_ready` e as autorizações fonte para
fundos reais, mas exige que os metadados pós-commit e a aceitação do operador
continuem falsos/nulos. Ele repete a suíte completa e a proveniência, exclui
`evidence/` e o diário local do índice, rejeita caminhos sensíveis e cria um
único commit assinado. Em qualquer falha, restaura HEAD e índice sem apagar a
árvore de trabalho.

```bash
set -euo pipefail
umask 077
cd "$USDOM_PROJECT"
export USDOM_CONTROL_EVIDENCE_DIRECTORY=/home/leonardov/usdom-mainnet-private/control-plane
export USDOM_RELEASE_SOURCE_COMMIT_RESULT="$USDOM_CONTROL_EVIDENCE_DIRECTORY/release-source-commit-result.json"
SOURCE_COMMIT_CANDIDATE=$(mktemp)
trap 'rm -f "$SOURCE_COMMIT_CANDIDATE"' EXIT
npm run --silent commit:release-source > "$SOURCE_COMMIT_CANDIDATE"
node scripts/install-private-file-new-stdin.mjs "$USDOM_RELEASE_SOURCE_COMMIT_RESULT" \
  < "$SOURCE_COMMIT_CANDIDATE"
rm -f "$SOURCE_COMMIT_CANDIDATE"
trap - EXIT
node scripts/read-private-file-stdout.mjs "$USDOM_RELEASE_SOURCE_COMMIT_RESULT" | jq -e '
  .schema == "usdom-release-source-commit/v1"
  and (.sourceCommit | test("^[0-9a-f]{40}$"))
  and (.sourceTag | test("^usdom-v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$"))
  and (.signingFingerprint | test("^([0-9A-F]{40}([0-9A-F]{24})?|SHA256:[A-Za-z0-9+/]{43})$"))
'
```

O comando não possui operação remota. Não faça push. Guarde o JSON público; o
passo seguinte deriva novamente o mesmo hash diretamente do Git.

## 24. Materializar identidades e evidência ligadas ao commit fonte

O primeiro comando autentica autor, committer e assinatura do `HEAD` contra a
chave Ed25519 externa, deriva `releaseId` e `sourceTag` da versão fixa, grava o
hash completo e fixa o fingerprint. O segundo revalida todo o bundle Safe e
grava somente suas quatro referências de evidência. Nenhuma autorização é
alterada.

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
npm run --silent materialize:release-provenance
npm run --silent materialize:safe-control-release-metadata
```

Os dois comandos exigem índice vazio e permitem mudanças pendentes somente nos
dois JSONs de metadados ou em `evidence/`. Depois que os demais documentos
técnicos estiverem presentes, gere, assine e materialize as quatro atestações
nativas. O pedido deriva o compromisso do verificador do manifesto validado
pelo binário Rust e deriva uma única identidade da carteira a partir dos
artefatos de custódia TPM, identidade pública e recuperação. Nenhum campo é
digitado ou copiado manualmente.

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
export ETHEREUM_RPC_URL='https://ethereum-rpc.publicnode.com'
npm run --silent write:native-release-attestation-requests
npm run --silent sign:native-release-attestations
npm run --silent materialize:native-release-attestations
```

O assinador exige os dois primeiros proprietários ordenados do Safe 2-de-3,
confere cada endereço diretamente no Ledger, assina os quatro digests brutos,
verifica cada assinatura localmente e monta a codificação EIP-1271 na ordem
exigida pelo Safe. Ele não transmite transação.

Com as atestações já materializadas, gere o relatório residual determinístico.
Ele vincula o envelope completo de evidências, os limites, a finalidade e os
doze riscos documentados, sem ciclo de auto-hash. Em seguida gere e assine a
autorização da release. Essa aprovação vincula a permissão-base de produção,
implantação, fundos reais e aceitação residual ao `sourceCommit` e às duas
configurações imutáveis. Ela não autoriza sozinha o depósito piloto: a fase
`authorize-pilot-funds-secret` exige depois uma autorização Safe 2-de-3 separada,
ligada ao snapshot, à tupla exata, ao prazo e à geração on-chain do piloto.

```bash
set -euo pipefail
cd "$USDOM_PROJECT"
export ETHEREUM_RPC_URL='https://ethereum-rpc.publicnode.com'
npm run --silent write:residual-risk-report
npm run --silent write:release-authorization-request
npm run --silent sign:production-release-authorization
npm run --silent materialize:release-authorization
```

Os dois materializadores repetem `isValidSignature` no contrato de governança
em bloco Ethereum finalizado, conferem chain ID, código do Safe, digest,
timestamp e estabilidade do bloco, gravam arquivos imutáveis e somente então
atualizam os JSONs de metadados. Um arquivo ausente, divergente ou uma assinatura
rejeitada mantém todas as autorizações falsas.

## 25. Criar o filho de evidência e a tag assinada, sem publicar

Este comando exige aprovação explícita do operador, aceitação residual ligada
à release exata, os dois metadados modificados e somente arquivos regulares em
`evidence/`. Ele cria o filho assinado e a tag anotada assinada localmente,
verifica pai, autores, signatários e diff, e executa os gates closed-mainnet e
real-funds em árvore limpa. Se qualquer gate ainda tiver um bloqueio, remove
somente a tag e o commit recém-criados e conserva os arquivos sem stage para
correção.

```bash
set -euo pipefail
umask 077
cd "$USDOM_PROJECT"
export ETHEREUM_RPC_URL='https://ethereum-rpc.publicnode.com'
export USDOM_CONTROL_EVIDENCE_DIRECTORY=/home/leonardov/usdom-mainnet-private/control-plane
export USDOM_RELEASE_EVIDENCE_COMMIT_RESULT="$USDOM_CONTROL_EVIDENCE_DIRECTORY/release-evidence-commit-result.json"
EVIDENCE_COMMIT_CANDIDATE=$(mktemp)
trap 'rm -f "$EVIDENCE_COMMIT_CANDIDATE"' EXIT
npm run --silent commit:release-evidence > "$EVIDENCE_COMMIT_CANDIDATE"
node scripts/install-private-file-new-stdin.mjs "$USDOM_RELEASE_EVIDENCE_COMMIT_RESULT" \
  < "$EVIDENCE_COMMIT_CANDIDATE"
rm -f "$EVIDENCE_COMMIT_CANDIDATE"
trap - EXIT
node scripts/read-private-file-stdout.mjs "$USDOM_RELEASE_EVIDENCE_COMMIT_RESULT" | jq -e '
  .schema == "usdom-release-evidence-commit/v1"
  and (.sourceCommit | test("^[0-9a-f]{40}$"))
  and (.evidenceCommit | test("^[0-9a-f]{40}$"))
  and .closedMainnetReady == true
  and .realFundsReady == true
'
```

Um resultado persistente só existe se os dois gates retornarem zero bloqueios.
O comando não contém `push`, `fetch`, `pull` ou configuração de remoto. A tag e
os commits permanecem apenas locais até uma autorização separada e explícita
para push.

Emergency cancellation of an armed pilot gate uses
`npm run --silent execute:pilot-deposit-gate-cancel`. This separate guardian
2-of-3 Safe ceremony binds the current snapshot and generation, completes only
after dual-RPC finality, and never continues into rotation, authorization or
deposit. Resume the ordinary DAG only through a newly reviewed authorization
generation.
