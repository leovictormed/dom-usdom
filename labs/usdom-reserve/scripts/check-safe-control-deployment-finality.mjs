#!/usr/bin/env node
import {canonicalEthereumQuantity,canonicalUnsignedDecimal,MAX_ETHEREUM_QUANTITY_UINT64}
  from '../sdk/ethereum-quantity.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';

try {
  const [finalizedHeight,receiptBlockNumber]=process.argv.slice(2);
  if(process.argv.length!==4) throw new Error('Safe finality inputs invalid');
  const finalized=canonicalUnsignedDecimal(finalizedHeight,{maximum:MAX_ETHEREUM_QUANTITY_UINT64});
  const receipt=canonicalEthereumQuantity(receiptBlockNumber,{maximum:MAX_ETHEREUM_QUANTITY_UINT64});
  if(BigInt(finalized)<BigInt(receipt)) throw new Error('Safe deployment receipt is not finalized');
} catch(error) {
  writeReleaseFailure('check-safe-control-deployment-finality',error);
  process.exitCode=1;
}
