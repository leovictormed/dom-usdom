import assert from 'node:assert/strict';
import {readdirSync,readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import test from 'node:test';

const root=fileURLToPath(new URL('../../scripts/',import.meta.url));

test('all shell Node removal children are bounded, reattested and absence checked',()=>{
  let removals=0;
  for(const name of readdirSync(root).filter(name=>name.endsWith('.sh')).sort()){
    const file=path.join(root,name),source=readFileSync(file,'utf8');
    const offsets=[...source.matchAll(/rmSync\(/g)].map(match=>match.index);
    if(offsets.length===0) continue;
    assert.equal(spawnSync('bash',['-n',file]).status,0,name);
    for(const offset of offsets){
      removals++;
      const window=source.slice(Math.max(0,offset-700),Math.min(source.length,offset+900));
      assert.match(window,/--signal=TERM --kill-after=5s 30s/,`${name}:${offset}: deadline`);
      assert.match(window,/> \/dev\/null 2> \/dev\/null/,`${name}:${offset}: output`);
      const before=window.slice(0,window.indexOf('rmSync('));
      const after=window.slice(window.indexOf('rmSync('));
      assert.match(before,/(?:assert_node_unchanged|assert_runtime_tool node|assert_tool_unchanged node)/,`${name}:${offset}: pre-node`);
      assert.match(before,/(?:assert_timeout_unchanged|assert_runtime_tool timeout|assert_tool_unchanged timeout|run_pinned_timeout)/,`${name}:${offset}: pre-timeout`);
      assert.match(after,/(?:assert_node_unchanged|assert_runtime_tool node|assert_tool_unchanged node)/,`${name}:${offset}: post-node`);
      assert.match(after,/(?:assert_timeout_unchanged|assert_runtime_tool timeout|assert_tool_unchanged timeout)/,`${name}:${offset}: post-timeout`);
      assert.match(after,/test ! -e/,`${name}:${offset}: absence`);
    }
  }
  assert.equal(removals,33);
});

test('durable directory remover invocation is bounded, reattested and absence checked',()=>{
  const name='observe-finalized-deposit-wallet.sh';
  const source=readFileSync(path.join(root,name),'utf8');
  const matches=[...source.matchAll(/remove-private-directory-durable\.mjs/g)];
  assert.equal(matches.length,1);
  const offset=matches[0].index,window=source.slice(offset-250,offset+350);
  assert.match(window,/run_pinned_timeout --foreground --signal=TERM --kill-after=5s 30s/);
  assert.match(window,/> \/dev\/null 2> \/dev\/null/);
  assert.match(window,/assert_node_unchanged[\s\S]*assert_runtime_tool timeout[\s\S]*test ! -e "\$OBSERVED_STATE"/);
});
