#!/usr/bin/env node
import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import fs from 'node:fs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {validateClosedMainnetDepositPackage} from '../sdk/closed-mainnet-deposit.mjs';
try {
  if(process.argv.length!==3) throw new Error('package path required');
  const value=parseStrictJson(fs.readFileSync(process.argv[2],'utf8'),{label:'closed deposit package',maxDepth:16});
  validateClosedMainnetDepositPackage(value);
  process.stdout.write(`${JSON.stringify(value,null,2)}\n`);
} catch(error){writePilotFailure('closed-mainnet-deposit-check',error);process.exitCode=1;}
