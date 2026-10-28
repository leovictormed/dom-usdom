#!/usr/bin/env node
import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateClosedMainnetDepositPackage} from '../sdk/closed-mainnet-deposit.mjs';
try {
  if(process.argv.length!==3) throw new Error('package path required');
  const bytes=await readDirectFile(process.argv[2],{
    minimum:2,maximum:4*1024*1024,label:'closed deposit package',
  });
  const value=parseStrictJsonBytes(bytes,{label:'closed deposit package',maxBytes:4*1024*1024,
    maxDepth:64,maxNodes:100_000,maxStringBytes:4*1024*1024,
    maxObjectEntries:10_000,maxArrayEntries:10_000});
  validateClosedMainnetDepositPackage(value);
  process.stdout.write(`${JSON.stringify(value,null,2)}\n`);
} catch(error){writePilotFailure('closed-mainnet-deposit-check',error);process.exitCode=1;}
