import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
test('restart authenticates complete finality marker identity and file metadata',()=>{
  for(const [file,schema] of [
    ['execute-closed-mainnet-deposit.sh','usdom-closed-mainnet-deposit-finality-v1'],
    ['execute-closed-mainnet-redemption.sh','usdom-closed-mainnet-redemption-finality-v1'],
  ]) {
    const source=readFileSync(new URL(`../../scripts/${file}`,import.meta.url),'utf8');
    assert.match(source,/test -f "\$finality_record" && test ! -L "\$finality_record"/);
    assert.match(source,/stat -c '%a:%h' "\$finality_record"/);
    for(const binding of [`.schema=="${schema}"`,'transactionHash','blockNumber','blockHash',
      'finalizedRpcCount==2','gasUsed','effectiveGasPrice','actualCost','maximumCost']) {
      assert.ok(source.includes(binding),`${file} missing ${binding}`);
    }
  }
});
