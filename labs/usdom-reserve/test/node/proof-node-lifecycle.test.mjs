import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const expected=new Map([
  ['plan-authenticated-economic-receipt-set.sh',5],
  ['plan-authenticated-randomx-receipt-set.sh',4],
  ['plan-authenticated-finalized-burn.sh',7],
  ['export-canonical-finalized-burn-source.sh',5],
  ['export-authenticated-randomx-statement.sh',6],
  ['export-authenticated-randomx-statement-set.sh',6],
  ['plan-authenticated-checkpoint-segment-set.sh',10],
  ['plan-authenticated-checkpoint-outer.sh',4],
]);

test('all finite Node children in proof planning and export share a deadline',()=>{
  let total=0;
  for(const [name,count] of expected){
    const script=fileURLToPath(new URL(`../../scripts/${name}`,import.meta.url));
    assert.equal(spawnSync('bash',['-n',script]).status,0,name);
    const source=readFileSync(script,'utf8');
    if(['export-canonical-finalized-burn-source.sh','export-authenticated-randomx-statement.sh','export-authenticated-randomx-statement-set.sh'].includes(name)) {
      assert.match(source,/source "\$LAB_ROOT\/scripts\/pinned-shell-tool-functions\.sh"/);
      for(const tool of name.endsWith('-set.sh')?['node','jq','cargo','timeout']:['node','cargo','timeout']) {
        assert.match(source,new RegExp(`pin_runtime_tool ${tool}`));
        assert.match(source,new RegExp(`${tool}\\(\\) \\{ assert_runtime_tool ${tool}; "\\$${tool}_bin" "\\$@"; \\}`));
      }
    }
    assert.doesNotMatch(source,/^\s*node\s|\|\s*node\s/m,name);
    const bounded=source.match(/run_pinned_node_timed\s+|timeout --signal=TERM --kill-after=2s 120s node\s/g)??[];
    assert.equal(bounded.length,count,name);
    total+=bounded.length;
  }
  assert.equal(total,47);
});
