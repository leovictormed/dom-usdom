import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validatePilotGasFunding} from '../../sdk/pilot-gas-funding.mjs';
test('gas funding requires dual-RPC agreement and full worst-case coverage',()=>{
  assert.deepEqual(validatePilotGasFunding({balanceA:'100',balanceB:'100',maximumCost:'60'}),
    {balanceWei:'100',maximumCostWei:'60',surplusWei:'40'});
  assert.equal(validatePilotGasFunding({balanceA:'60',balanceB:'60',maximumCost:'60'}).surplusWei,'0');
  for(const value of [{balanceA:'59',balanceB:'59',maximumCost:'60'},
    {balanceA:'100',balanceB:'99',maximumCost:'60'},{balanceA:'0100',balanceB:'0100',maximumCost:'60'},
    {balanceA:'9'.repeat(100000),balanceB:'9'.repeat(100000),maximumCost:'60'},
    {balanceA:(1n<<256n).toString(),balanceB:(1n<<256n).toString(),maximumCost:'60'},
    {balanceA:'100',balanceB:'100',maximumCost:'0'},{balanceA:'-1',balanceB:'-1',maximumCost:'1'}]) {
    assert.throws(()=>validatePilotGasFunding(value));
  }
});
test('both pilot executors check gas funding before signing and before publishing',()=>{
  for(const file of ['execute-closed-mainnet-deposit.sh','execute-closed-mainnet-redemption.sh']) {
    const source=readFileSync(new URL(`../../scripts/${file}`,import.meta.url),'utf8');
    assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s \\\n\s+node scripts\/check-pilot-gas-funding\.mjs/g)??[]).length,2);
    assert.equal((source.match(/node scripts\/check-pilot-gas-funding\.mjs/g)??[]).length,2);
    const checks=[...source.matchAll(/check-pilot-gas-funding\.mjs/g)].map(match=>match.index);
    assert.equal(checks.length,2); assert.ok(checks[0]<source.indexOf('cast mktx'));
    const publish=source.indexOf('publish-private-raw-transaction.mjs');
    assert.ok(publish>0); assert.ok(checks[1]<publish);
    assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s \\\n\s+cast balance "\$(?:funder|signer)" --block pending --rpc-url "\$rpc[12]" \| head -c 80/g)??[]).length,4);
    assert.equal((source.match(/cast balance "\$(?:funder|signer)" --block pending/g)??[]).length,4);
    assert.equal((source.match(/is_canonical_rpc_uint "\$gas_balance[12]"/g)??[]).length,4);
  }
});
