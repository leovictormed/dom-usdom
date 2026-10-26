#!/usr/bin/env node
import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import fs from 'node:fs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {validateClosedMainnetDepositRawTransaction} from '../sdk/closed-mainnet-deposit-execution.mjs';
import {readPrivateRawTransaction} from '../sdk/private-raw-transaction.mjs';

try {
  if(process.argv.length!==5) throw new Error('usage: check-closed-mainnet-deposit-raw.mjs PACKAGE INDEX NONCE');
  const packageValue=parseStrictJson(fs.readFileSync(process.argv[2],'utf8'),{label:'deposit package',maxDepth:16});
  if(process.env.USDOM_CLOSED_MAINNET_DEPOSIT_RAW!==undefined) throw new Error('raw transaction environment values are forbidden');
  const raw=readPrivateRawTransaction(process.env.USDOM_CLOSED_MAINNET_DEPOSIT_RAW_FILE);
  const result=validateClosedMainnetDepositRawTransaction({raw,packageValue,index:Number(process.argv[3]),nonce:process.argv[4]});
  process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
} catch(error){
  writePilotFailure('closed-mainnet-deposit-raw-check',error);
}
