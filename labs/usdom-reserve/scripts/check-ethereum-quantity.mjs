#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {canonicalEthereumQuantity} from '../sdk/ethereum-quantity.mjs';

try {
  if(process.argv.length!==3&&process.argv.length!==4) {
    throw new Error('usage: check-ethereum-quantity.mjs QUANTITY [UPPER_BOUND_QUANTITY]');
  }
  const value=canonicalEthereumQuantity(process.argv[2]);
  if(process.argv.length===4) {
    const upper=canonicalEthereumQuantity(process.argv[3]);
    if(BigInt(value)>BigInt(upper)) throw new Error('Ethereum quantity exceeds the supplied upper bound');
  }
  process.stdout.write(`${value}\n`);
} catch(error) {
  writeReleaseFailure('check-ethereum-quantity',error);
  process.exitCode=1;
}
