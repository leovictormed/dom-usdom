# Auditoria estática do primeiro teste fechado em mainnet — ETAPA 2342

Escopo: `prepare-closed-mainnet-pilot.sh`, o gerador das 23 fases, materialização, deploy, Safes, recovery, depósito, burn, checkpoint e resgate. Esta revisão não executou rede, hardware, assinatura ou fundos.

## Dependências que não podem ser produzidas somente pelo repositório local

1. **Conta OneKey confirmada fisicamente e sessão WalletConnect.** Entrada: `onekey-ios-walletconnect-client.json` 0600 com projectId público configurado e arquivos 0600 em `onekey-ios-physical-evidence/`, cada um confirmando conta, device, firmware e release do app. Saída: responses EIP-712 create-once verificadas localmente. A conta física, o projectId emitido pelo serviço e a aprovação no iPhone não podem ser inventados localmente.
2. **Provas iniciais dos nove owners e provas dos três replacements.** `generate-closed-mainnet-phase-command.sh:278-301` apenas consome `safe-owner-identities.json` e `safe-owner-hardware-custody-proofs-v1.json`; `:412-439` exige `safe-recovery-transitions-v2.json` e `safe-recovery-replacement-proofs-v2.json`. Falta uma fase produtora completa dessas entradas usando o cliente WC atual. Contrato de saída: JSON 0600/create-once aceito por `check-safe-owner-hardware-custody-proofs.mjs` e `check-safe-recovery-replacement-proofs.mjs`.
3. **Cerimônia privada Groth16 multiparte.** `generate-closed-mainnet-phase-command.sh:907-950` exige contribuições e assinaturas de três participantes, R1CS, proving key e verifying key. A montagem/verificação é local; contribuições independentes e atestações de descarte não são geráveis unilateralmente.
4. **Ethereum mainnet e dois provedores independentes.** Nonces, codehashes, base fee, recibos e finalidade usados pelos executores dependem do estado real de mainnet. Os catálogos podem ser materializados localmente, mas as observações não.
5. **Keystores cifrados e senhas dos relayers gas-only.** O repositório fornece criadores/signers locais, porém a senha e a custódia do EOA devem permanecer externas. ETH para gas e USDT do Safe são fundos reais externos.
6. **Blocos e provas DOM reais.** Depósito finalizado, bloco minerado, checkpoint e burn finalizado exigem a rede DOM ativa e suas provas reais; os validadores locais não substituem esses fatos.

## Caminhos incompletos ou obsoletos

- **Bloqueador maior — depósito ainda tenta assinar raw EIP-1559 na OneKey.** `scripts/execute-closed-mainnet-deposit.sh:498-503` chama `prepare-onekey-eip1559-transaction.mjs` e `sign-onekey-mainnet-transaction.mjs`. O provider móvel aprovado oferece apenas `eth_signTypedData_v4`; não fornece raw transaction. Entrada necessária: plano Safe approve+deposit EIP-712 e evidência física dos owners. Saída requerida: assinaturas Safe canônicas + raw do relayer gas-only, sem custódia de USDT pelo relayer.
- **Bloqueador maior — resgate ainda tenta assinar raw EIP-1559 na OneKey.** `scripts/execute-closed-mainnet-redemption.sh:428-443` mantém a mesma fronteira obsoleta. Deve virar operação Safe EIP-712 ou outro fluxo explicitamente ratificado, com EOA gas-only apenas para a transação externa.
- **Bloqueador maior — autoridade de custódia continua não configurada.** `config/onekey-ios-safe-usdt-custody-authority.unconfigured.json` contém Safe, owners, threshold, reserve, amount, gas caps, salt e commitment nulos. A fase `authorize-pilot-funds-secret` falha fechado em `generate-closed-mainnet-phase-command.sh:702-711`. Esses valores devem ser derivados dos artefatos finalizados e ratificados, não digitados em comandos.
- **Lacuna de orquestração — status 78 tem signer, mas a fase não o chama.** Deploy (`sign-mainnet-deployment-gas-relayer.sh`) e Safe/recovery/resume/gates (`sign-operational-gas-relayer.sh`) têm instaladores create-once. As fases executam o executor uma vez e encerram em 78; faltam loops explícitos executor→signer→executor que preservem 80 e não façam retry cego.
- **Status 80 é intencional e possui retomada.** Ele marca assinatura ou publicação com resultado inconclusivo. Não foi encontrado status 80 sem artefato durable/checker; ele nunca deve ser convertido em retry automático.

## Placeholders e campos manuais

- Nenhum `YOUR_*`, `CHANGE_ME`, `PLACEHOLDER`, `TODO`, `TBD`, private key, mnemonic ou seed aparece nos programas gerados.
- Não existem campos para o operador completar dentro dos comandos. Os valores ainda ausentes estão em autoridades `unconfigured` e devem ser produzidos por materializadores ou cerimônias externas autenticadas.

## Correções pequenas aplicadas

- Os caminhos de recovery gerados foram alinhados entre preparação e execução para os mesmos artefatos `*-v2.json`.
- O comentário do executor de recovery foi corrigido: ele valida raws do relayer assinadas externamente; não assina envelopes.
