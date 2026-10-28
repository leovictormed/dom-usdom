import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
test('every pilot RPC receipt comparison binds identity, block and gas fields',()=>{
  for(const file of ['execute-closed-mainnet-deposit.sh','execute-closed-mainnet-redemption.sh']) {
    const source=readFileSync(new URL(`../../scripts/${file}`,import.meta.url),'utf8');
    assert.match(source,/timeout --foreground --signal=TERM --kill-after=5s 1800s \\\n\s+cast receipt "\$tx_hash" --confirmations 2 --json --rpc-url "\$rpc1" \| head -c 65537/);
    assert.equal((source.match(/cast receipt "\$tx_hash" --confirmations 2/g)??[]).length,1);
    const expectedRpcReads=file==='execute-closed-mainnet-deposit.sh'?3:1;
    assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s \\\n\s+cast receipt "\$tx_hash" --json --rpc-url "\$rpc" \| head -c 65537/g)??[]).length,expectedRpcReads);
    assert.equal((source.match(/cast receipt "\$tx_hash" --json --rpc-url "\$rpc"/g)??[]).length,expectedRpcReads);
    const expectedSites=expectedRpcReads+1;
    assert.equal((source.match(/cast receipt[^\n]+\| head -c 65537/g)??[]).length,expectedSites);
    assert.equal((source.match(/test "\$\(stat_run -c '%s' "\$(?:rpc_receipt|receipt_candidate|candidate|observed)"\)" -le 65536/g)??[]).length,expectedSites);
    assert.ok((source.match(/node scripts\/check-private-strict-json-file\.mjs "\$(?:rpc_receipt|receipt_candidate|candidate|observed)"/g)??[]).length>=expectedSites);
    assert.match(source,/receipt_gas=\$\(jq_run -er '\.gasUsed'/);
    assert.match(source,/receipt_price=\$\(jq_run -er '\.effectiveGasPrice'/);
    const rpcComparisons=source.split('\n').filter(line=>line.includes(".gasUsed==$gas")&&line.includes(".effectiveGasPrice==$price"));
    assert.ok(rpcComparisons.length>=1);
    for(const comparison of rpcComparisons) {
      assert.match(comparison,/transactionHash/); assert.match(comparison,/blockNumber/);
      assert.match(comparison,/blockHash/); assert.match(comparison,/status/);
    }
  }
});
