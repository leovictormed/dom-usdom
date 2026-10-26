import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const directory=new URL('../../scripts/',import.meta.url);
const cases=new Map([
 ['plan-authenticated-economic-receipt-set.sh',1],
 ['plan-authenticated-randomx-receipt-set.sh',1],
 ['plan-authenticated-finalized-burn.sh',1],
 ['plan-authenticated-checkpoint-outer.sh',1],
 ['plan-authenticated-checkpoint-segment-set.sh',1],
 ['run-closed-mainnet-node.sh',2],
 ['collect-ethereum-checkpoint-consensus.sh',2],
]);

for(const [script,expectedGenericCalls] of cases) test(`${script} authenticates cataloged timeout calls`,async()=>{
 const source=await readFile(new URL(script,directory),'utf8');
 assert.match(source,/pin_runtime_tool timeout/);
 assert.match(source,/run_pinned_timeout\(\) \{ assert_runtime_tool timeout; "\$timeout_bin" "\$@"; \}/);
 assert.equal([...source.matchAll(/run_pinned_timeout --signal=/g)].length,expectedGenericCalls);
 assert.doesNotMatch(source,/(?:^|[|;]\s*)timeout --signal=/m);
});
