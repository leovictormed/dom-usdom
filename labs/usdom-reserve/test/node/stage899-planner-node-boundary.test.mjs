import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const directory=new URL('../../scripts/',import.meta.url);
const cases=new Map([
 ['plan-authenticated-economic-receipt-set.sh',5],
 ['plan-authenticated-randomx-receipt-set.sh',4],
 ['plan-authenticated-finalized-burn.sh',7],
 ['plan-authenticated-checkpoint-outer.sh',4],
 ['plan-authenticated-checkpoint-segment-set.sh',10],
]);

for(const [planner,expectedCalls] of cases) test(`${planner} authenticates bounded Node children`,async()=>{
 const source=await readFile(new URL(planner,directory),'utf8');
 assert.match(source,/source "\$LAB_ROOT\/scripts\/pinned-shell-tool-functions\.sh"/);
 assert.match(source,/pin_runtime_tool node; pin_runtime_tool timeout/);
 assert.match(source,/run_pinned_node_timed\(\) \{ assert_runtime_tool node; assert_runtime_tool timeout; "\$timeout_bin"[^\n]*"\$node_bin" "\$@"; \}/);
 assert.equal([...source.matchAll(/run_pinned_node_timed\s/g)].length,expectedCalls);
 assert.doesNotMatch(source,/(?:^|[;|]\s*)timeout\s[^\n]*\snode\s/m);
 assert.doesNotMatch(source,/(?:^|[;|]\s*)node\s/m);
});
