USDOM — PoC de checkpoints: autenticação Ethereum isolada
Portada para o repositório dom-protocol em 2026-10-17. A cópia limpa do Helios
fixada em 2af9b41887e069144ee56cd710f3ddca195473f8 foi vendorizada sob
vendor/helios para que o laboratório não dependa de um checkout irmão. Esta
mudança de localização não liga o verificador ao consenso DOM nem autoriza rede.
Estado atual (2026-10-17): 46 testes funcionais e 5 testes compile_fail
passam no workspace. O verificador compõe finalidade Fulu, ancestralidade,
recibo, evento de checkpoint, conta, código e storage em um tipo opaco aceito
pela barreira regtest da DOM. A etapa 23 acrescenta um envelope de testemunha
canônico e limitado a 4 MiB, replay completo e teto de slot vindo da política de
consenso. O recurso continua desabilitado por padrão e sem autoridade mainnet.
Ver ../usdom-reserve/docs/CONSENSUS-CHECKPOINT-WITNESS-2026-10-17.txt.
As seções seguintes preservam o histórico das etapas e suas contagens originais.

Etapa 2: autenticação Ethereum isolada
Pesquisa autorizada; sem push, deploy, ativação ou fundos reais.

Resultado

12 testes Rust passaram com verificação BLS/SSZ real do helios-consensus-core.
Os vetores históricos de mainnet fornecidos pelo próprio Helios são reprocessados
offline: bootstrap, seis atualizações (incluindo mudanças de comitê) e atualização
finalizada. Não há assinatura substituída por mock no caminho de sucesso.
Os dados de teste não foram consultados em RPC público nesta etapa.

Cabeçalho finalizado obtido:
  beacon slot: 7109344
  beacon root: 0xa9bb1965a6288f64374a9425f5ecb90dd81239cc2ae1a8ec8b673c13c9d2586a
  execution block: 17923026
  execution hash: 0xbc8499537876e5406c7a65e25f99063f1cd85a17014a3aa5ade38271b1fbf64f
  receipts root: 0xa71c4101ece61ca0fc624efdb54dc382be561a8c047a19cf5f10e530378e0b9c

A raiz exposta pertence ao bloco finalizado, não ao bloco atestado mais recente.
O primeiro teste positivo falhou porque a expectativa usava o hash atestado;
foi corrigida após conferir separadamente os dois cabeçalhos do fixture. O log
initial-wrong-expected-hash.log preserva essa falha de teste (11 passaram, 1 falhou).
tests.log contém o resultado final de 12 aprovados. A biblioteca de referência
emite um aviso de API deprecated; não foi alterada para silenciá-lo.

O que a camada experimental faz

- Verifica bootstrap contra raiz fornecida explicitamente como confiável.
- Mantém LightClientStore privado. Não importa estado desserializado de terceiros.
- Exige cabeçalho finalizado, prova de finalidade e pelo menos 342 dos 512
  participantes; em seguida verifica execução, finalidade, comitês, domínio,
  horário/ordem dos slots e assinatura BLS pela biblioteca fixada.
- Permite aprender o próximo comitê com uma atualização finalizada histórica,
  sem fazer o cabeçalho finalizado regredir. Isso é necessário para estes vetores.
- Aplica a atualização em cópia e só substitui o estado após as verificações.
- Expõe apenas slot/root beacon e número/hash/receiptsRoot/stateRoot de execução
  finalizados. Essas raízes NÃO autenticam automaticamente um bloco anterior.
- Rejeita atualizações otimistas e não possui operação force_update/timeout.
- Restringe este ensaio a cabeçalhos e assinaturas do intervalo histórico Capella.

Evidência adversarial

Raiz inicial errada/zero, prova do comitê inicial adulterada, domínio de gênese
ou fork errado, assinatura BLS de outra mensagem, prova de finalidade corrompida,
receiptsRoot alterada, prova do próximo comitê corrompida, assinatura futura,
período sem comitê conhecido, participação abaixo do limiar, finalidade ausente,
variante não suportada e tentativa de regressão são rejeitados. Uma atualização
correta ainda funciona depois de tentativas de envenenamento do estado.

O caso de participação reduzida altera os bits do fixture e também invalida sua
assinatura. Portanto testa especificamente a barreira anterior ao BLS, não um
certificado real assinado por um comitê de participação reduzida.

Uma comparação separada, usando a API upstream deliberadamente, verifica uma
atualização otimista válida e depois chama force_update após timeout. O campo
finalized_header avança de slot 7109344 para 7109431 sem uma nova prova de
finalidade. O cliente restrito recusa a mesma atualização e mantém 7109344.
Isso demonstra a diferença de semântica entre os caminhos, não uma vulnerabilidade
alegada no Helios: sua recuperação atende a outro objetivo de disponibilidade.

Recuperação neste ensaio significa construir estado novo a partir do MESMO
bootstrap confiável e repetir as provas. O teste obtém resultado idêntico.
Não há implementação de snapshot, banco persistente ou política antirollback.

Confiança e limites que permanecem

1. O checkpoint inicial foi retirado do teste upstream e é confiável APENAS como
   entrada deste experimento histórico. Não é um checkpoint recente aprovado para
   produção. A raiz, parâmetros da rede e cronograma de forks vêm do chamador.
2. O cliente leve depende das hipóteses dos sync committees Ethereum, do bootstrap,
   da validade criptográfica e da implementação. Não reexecuta todas as transições
   de consenso/execução Ethereum, nem verifica todos os votos dos validadores.
   Não elimina a necessidade de política de weak subjectivity e recuperação.
3. O relógio/slot é entrada determinística de teste. Não há regra nativa DOM de
   tempo, limite de idade do bootstrap, limite completo de recursos ou transporte.
4. Só Capella foi exercitado. Este código rejeita forks posteriores; não suporta
   a Ethereum atual e não pode ser ativado como cliente de produção.
5. Não autentica ainda um evento de checkpoint ou depósito; a conexão com o ensaio
   de recibos exige que a raiz seja exatamente a deste cabeçalho ou ancestralidade
   autenticada. Não há recibo de checkpoint implantado nesses vetores históricos.
6. Não fornece a prova oposta, DOM -> Ethereum: faltam validade de consenso DOM,
   estado privado USDOM, RandomX no provador, inclusão de queima e verificador EVM.
7. Não integra o estado deste cliente ao consenso/IBD/snapshot/reorg da DOM. A
   barreira nativa da etapa 1 continua usando install_from_test_oracle em regtest.
8. Não demonstra finalidade absoluta em caso de falha de segurança Ethereum.
   Conflitos finalizados, perda de dados e recuperação entre redes ainda exigem
   protocolo explícito. Timeout não autoriza afrouxar essas garantias.

Privacidade

O experimento usa somente dados Ethereum públicos e não recebe segredos de notas,
valores privados, carteiras ou histórico DOM. Não demonstra uma prova privada de
resgate. A futura publicação deve limitar-se a domínios, compromissos, provas e
dados públicos necessários ao pagamento; nenhum identificador deve obrigar a
revelação do depósito de origem. Valores/endereços Ethereum permanecem públicos.

Fontes fixadas e licença

Helios oficial: https://github.com/a16z/helios
Commit: 2af9b41887e069144ee56cd710f3ddca195473f8, versão 0.12.0.
Código de verificação: ethereum/consensus-core/src/consensus_core.rs.
Fixtures: ethereum/testdata/{bootstrap,updates,finality,optimistic}.json.
Checkpoint de teste: ethereum/tests/sync.rs.
Parâmetros históricos: ethereum/src/config/networks.rs.
fixtures/HELIOS-LICENSE preserva o aviso MIT dos dados/código de referência.
O projeto não é uma auditoria integral do Helios nem uma recomendação de adoção
sem análise das dependências, forks, custos e hipóteses de segurança.

Reprodução

Estrutura esperada a partir da raiz da auditoria:
  reference-helios/                  checkout limpo no commit acima
  integration-check/labs/ethereum-finality/  este laboratório
  integration-check/run-ethereum-finality.sh
O checkout pode ser obtido por git clone/fetch, operações de leitura do remoto.
Não executar push ou implantação. O wrapper verifica o commit e diff do Helios,
monta-o somente para leitura e usa bubblewrap, Rust stable e cache separados.

Primeiro obter dependências, sem executar testes com acesso à rede:
  bash integration-check/run-ethereum-finality.sh --fetch cargo fetch --locked
Depois, isolado da rede:
  bash integration-check/run-ethereum-finality.sh cargo test --offline --locked -- --nocapture
  bash integration-check/run-ethereum-finality.sh cargo fmt --check
  bash integration-check/run-ethereum-finality.sh cargo clippy --offline --locked --all-targets -- -D warnings

Cargo.lock fixa as versões resolvidas deste laboratório, inclusive dependências
transitivas que podem diferir do lock do workspace upstream. O path dependency
não fixa sozinho um commit; o wrapper e results/identity.json fazem essa ligação.
O caminho do toolchain no wrapper corresponde ao ambiente desta auditoria; em
outra máquina ele deve ser ajustado sem alterar os fontes/vetores ou o lock.

Esta etapa reduz uma lacuna demonstrando um componente criptográfico isolado.
A PoC completa de checkpoints, resgate e consenso nativo continua incompleta.

Extensão da etapa 3

examples/export_historical.rs reexecuta os mesmos fixtures e emite a visão
finalizada para o experimento irmão ethereum-authenticated-events. Esse exemplo
tem bootstrap/rede/slot fixos e não aceita uma raiz arbitrária por RPC/arquivo.
Ele permite compor a verificação BLS/SSZ com provas de recibos reais históricos.
Não é uma interface de produção e não muda os limites de confiança acima.
O pacote publicado localmente da etapa 2 continua imutável; os manifests locais
foram atualizados para refletir essa extensão e os novos logs de regressão.

Extensão da etapa 4 — recibos no próprio processo Rust

src/receipts.rs acrescenta verify_receipt ao cliente histórico: a raiz vem do
estado privado, e o chamador fornece apenas identidade do bloco, índice, bytes
do recibo e nós da prova. VerifiedReceipt/VerifiedLog são tipos opacos; não há
importação de um JSON que declare estar verificado. A política de evento ainda
pertence ao protocolo consumidor e não autoriza emissão por si só.

A suíte completa agora contém 24 testes Rust aprovados: os 12 originais, 7 de
integração de recibos, 3 de codificação e 2 compile_fail de isolamento da API.
Os erros de compilação E0451 impressos nesses dois casos são o resultado esperado.
Foram verificados 167 recibos históricos, 32 eventos USDT e 5 transações falhas.
Provas vêm de EthereumJS e são conferidas por alloy-trie 0.9.8. Os tipos 0 e 2
aparecem no bloco; tipo 1 foi testado somente no codec, com envelope sintético.

O helper adicional não muda as hipóteses do cliente histórico e não o torna
compatível com a Ethereum atual. O estado ainda não participa do consenso DOM.
Ver ../../checkpoint-poc-results/STAGE4-ASSESSMENT.txt e
../../checkpoint-poc-results/NATIVE-BOUNDARY-ASSESSMENT.txt para os limites e
as mudanças nativas necessárias. Resultados e hashes atuais estão em results/.

Extensão da etapa 34 — identidade da política no resultado opaco

O replay completo de checkpoint agora grava no próprio VerifiedCheckpoint um
hash canônico do bootstrap confiável, genesis validators root, forks, registry,
runtime, slot/configuração, domínio e rede que realmente verificaram a prova.
Composição local sem replay recebe hash zero. O estado nativo exige igualdade
com BridgeIdentity, impedindo reutilizar uma capacidade sob outra política. O
teto max_current_slot não integra o hash: a integração DOM o deriva exatamente
do timestamp do bloco. Esta mudança não fornece o witness positivo de registry
real que ainda falta.

Extensão da etapa 164 — depósito canônico da reserva de provas

O decodificador do evento Deposited agora aplica, na própria fronteira Ethereum
autenticada, o mesmo limite estrito do campo escalar BN254 exigido pela
USDOMProofReserve. Um compromisso zero, igual ao módulo ou maior deixa de formar
um VerifiedDeposit; a falha não é mais adiada até a conversão da nota nativa.

O vetor local anterior foi removido porque continha compromissos não canônicos e
autenticava o bytecode do protótipo de quórum. O vetor substituto implanta a
USDOMProofReserve atual em Anvil, produz dois depósitos canônicos no mesmo bloco
e inclui recibos, provas MPT, prova da conta e bytecode real da reserva de provas.
O gerador fica restrito a loopback e chain ID 31337. O Beacon checkpoint usado
pelos testes continua sintético; esse vetor comprova a composição local de
execução, recibo, conta e código, não finalidade Ethereum nem prontidão mainnet.

Extensão da etapa 165 — hash de consenso sem backend nativo

O helper Blake2b-256 usado pelos compromissos de checkpoint e depósito agora
vem de dom-core. A API histórica continua reexportada por dom-crypto, mas o
caminho normal do programa de queima deixou de arrastar secp256k1, Bulletproof e
seus bindings nativos apenas para calcular hashes. O gate de dependências rejeita
o retorno desses pacotes. A árvore do programa ainda contém ring por meio de
tree_hash/ethereum_hashing; a compatibilidade com a zkVM escolhida continua sendo
um requisito aberto, assim como guest, prova, benchmark e verificador EVM reais.

Extensão da etapa 166 — SHA-256/SSZ Ethereum sem backend nativo

ethereum_hashing 0.7.0, tree_hash 0.10.0 e ssz_types 0.11.0 agora são crates
locais selecionados explicitamente por path. O primeiro usa somente RustCrypto
SHA-256; os outros preservam os fontes publicados e apontam para a pilha local.
Não foi usado [patch] global. O gate confere os manifests reais pelo grafo Cargo
e proíbe ring. O hash isolado compila para riscv32im-unknown-none-elf, mas isso
não substitui a compilação, benchmark, prova e auditoria do guest zkVM completo.

Extensão da etapa 167 — guest finalizado RISC Zero

A relação UDFINL02 agora compila dentro de um guest RISC Zero 3.0.6 RV32IM.
O builder Rust 1.97 foi fixado por digest e uma segunda compilação limpa
reproduziu exatamente o ProgramBinary e ImageID registrados. Isto demonstra a
portabilidade do código de finalidade Ethereum para a zkVM escolhida, mas ainda
não existe uma testemunha positiva que combine finalidade Beacon, evento do
registro de checkpoints e uma queima DOM real. Benchmark válido, receipt,
verificador EVM e revisão independente permanecem obrigatórios.
