# ETAPA 1632B — suíte Node completa offline

Data: 2026-10-27

## Resultado final

A suíte direta `node --test test/node/*.test.mjs`, com toolchains fixadas e variáveis de proxy/Node removidas, terminou:

- tests: 1545
- pass: 1545
- fail: 0
- cancelled: 0
- skipped: 0
- todo: 0
- duração reportada pelo runner: 120236.872 ms
- tempo de parede: 120.39 s
- RSS máximo: 286816 KiB

Nenhuma rede, prova longa, Ledger, deploy, fundo ou push foi usado.

## Regressões corrigidas

O wrapper `npm test` não chegou à suíte porque o `pretest` executa o lint Solidity com `-D warnings`; 21 avisos de lint preexistentes abortaram antes do build. Como o build `--force` havia limpado `out/`, a primeira execução Node direta encontrou artefatos ausentes. Os artefatos foram restaurados com `forge build --offline --force`.

A nova configuração canônica de artefato (`storageLayout`) alterou hashes dos JSONs sem alterar os bytecodes vinculados. As evidências locais de deployment e operational gas foram regeneradas contra os artefatos atuais; os testes focais passaram 6/6.

A repetição completa então revelou uma corrida real em `remove-private-directory-durable.mjs`: após um processo renomear um orphan para um claim `.purge`, outro processo podia reclamar e remover esse mesmo nome antes do primeiro `rm`, produzindo `ENOENT`. A remoção agora aceita somente esse `ENOENT` pós-claim concorrente; qualquer outro erro permanece fatal. O teste concorrente passou vinte repetições consecutivas antes da suíte final completa.
