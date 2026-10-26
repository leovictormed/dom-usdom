import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

const modules=[
  ['safe-control-deployment.mjs',1],
  ['safe-control-observation.mjs',3],
  ['safe-control-recovery-plan.mjs',1],
  ['safe-control-recovery-execution.mjs',1],
];

test('all Safe provider defaults are bounded and every ownership boundary destroys',()=>{
  let defaults=0;
  for(const [name,minimumFinalizers] of modules){
    const source=readFileSync(new URL(`../../sdk/${name}`,import.meta.url),'utf8');
    assert.doesNotMatch(source,/new JsonRpcProvider\s*\(/,name);
    defaults+=(source.match(/new BoundedMainnetPreflightProvider\s*\(/g)??[]).length;
    assert.ok((source.match(/provider\?\.destroy/g)??[]).length>=minimumFinalizers,name);
  }
  // Seven defaults include one pass-through public API; six boundaries instantiate providers.
  assert.equal(defaults,7);
});
