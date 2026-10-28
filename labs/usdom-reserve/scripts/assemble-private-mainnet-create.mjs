#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {assembleLedgerEip1559CreateTransaction} from '../sdk/ledger-eip1559-create-transaction.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
try {
  if(process.argv.length!==3) throw new Error('prepared CREATE path required');
  const prepared=parseStrictJsonBytes(await readDirectFile(process.argv[2],{minimum:2,maximum:1024*1024,
    exactMode:0o600,label:'prepared CREATE'}),{label:'prepared CREATE'});
  const signature=readFileSync(0,'utf8').trim();
  process.stdout.write(`${assembleLedgerEip1559CreateTransaction(prepared,signature)}\n`);
} catch(error) { writeReleaseFailure('assemble-private-mainnet-create',error);process.exitCode=1; }
