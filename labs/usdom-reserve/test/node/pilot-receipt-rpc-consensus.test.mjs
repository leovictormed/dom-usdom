import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
test('every pilot RPC receipt comparison binds identity, block and gas fields',()=>{
  for(const file of ['execute-closed-mainnet-deposit.sh','execute-closed-mainnet-redemption.sh']) {
    const source=readFileSync(new URL(`../../scripts/${file}`,import.meta.url),'utf8');
    assert.match(source,/receipt_gas=\$\(jq -er '\.gasUsed'/);
    assert.match(source,/receipt_price=\$\(jq -er '\.effectiveGasPrice'/);
    const rpcComparisons=source.split('\n').filter(line=>line.includes(".gasUsed==$gas")&&line.includes(".effectiveGasPrice==$price"));
    assert.ok(rpcComparisons.length>=1);
    for(const comparison of rpcComparisons) {
      assert.match(comparison,/transactionHash/); assert.match(comparison,/blockNumber/);
      assert.match(comparison,/blockHash/); assert.match(comparison,/status/);
    }
  }
});
