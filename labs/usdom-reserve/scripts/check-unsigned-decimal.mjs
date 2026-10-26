#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {canonicalUnsignedDecimal} from '../sdk/ethereum-quantity.mjs';

try {
  if(process.argv.length!==3&&process.argv.length!==4) {
    throw new Error('usage: check-unsigned-decimal.mjs VALUE [MAXIMUM]');
  }
  let maximum;
  if(process.argv.length===4) maximum=BigInt(canonicalUnsignedDecimal(process.argv[3]));
  process.stdout.write(`${canonicalUnsignedDecimal(process.argv[2],{maximum})}\n`);
} catch(error) {
  writeReleaseFailure('check-unsigned-decimal',error);
  process.exitCode=1;
}
