import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const files=[
 '../../../../crates/dom-node/src/bin/dom-usdom-export-randomx-statement-set.rs',
 '../../../../crates/dom-usdom-randomx-proof-host/src/bin/prove-aggregate.rs',
 '../../../../crates/dom-usdom-randomx-proof-host/src/bin/prove.rs',
 '../../../../crates/dom-usdom-randomx-proof-host/src/bin/plan.rs',
 '../../../../crates/dom-usdom-randomx-proof-host/src/bin/plan-aggregate.rs',
 '../../../../crates/dom-usdom-economic-proof-host/src/bin/prove.rs',
 '../../../../crates/dom-usdom-economic-proof-host/src/bin/plan.rs',
 '../../../../crates/dom-usdom-finalized-burn-proof-host/src/bin/prove.rs',
 '../../../../crates/dom-usdom-finalized-burn-proof-host/src/bin/package-evm.rs'
];

test('production proof failures emit fixed diagnostics instead of error chains',async()=>{
 const sources=await Promise.all(files.map(path=>readFile(new URL(path,import.meta.url),'utf8')));
 assert.equal(sources.reduce((sum,source)=>sum+(source.match(/eprintln!\(/g)||[]).length,0),9);
 for(const source of sources){
  assert.doesNotMatch(source,/eprintln!\([^;]*\{error\}/s);
  assert.match(source,/if let Err\(_error\) = run\(\)/);
 }
});
