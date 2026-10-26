import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const files=[
 'dom-node/src/bin/dom-usdom-build-finalized-deposit-witness.rs',
 'dom-node/src/bin/dom-usdom-observe-finalized-deposit.rs',
 'dom-node/src/bin/dom-usdom-bootstrap-tpm-wallet-authority.rs',
 'dom-node/src/bin/dom-usdom-manifest-check.rs',
 'dom-node/src/bin/dom-usdom-export-preactivation-anchor.rs',
 'dom-node/src/bin/dom-usdom-wallet-tpm-keystore.rs',
 'dom-node/src/bin/dom-usdom-submit-private-burn.rs',
 'dom-node/src/bin/dom-usdom-register-finalized-deposit.rs',
 'dom-node/src/bin/dom-usdom-recover-wallet-at-checkpoint.rs',
 'dom-node/src/bin/dom-usdom-build-private-burn.rs',
 'dom-node/src/bin/dom-usdom-export-finalized-burn-source.rs',
 'dom-node/src/bin/dom-usdom-export-checkpoint-source.rs',
 'dom-node/src/bin/dom-usdom-export-checkpoint-source-set.rs',
 'dom-usdom-finalized-burn-proof-host/src/bin/plan.rs',
 'dom-usdom-checkpoint-proof-host/src/bin/plan-outer.rs',
 'dom-usdom-checkpoint-proof-host/src/bin/package-outer-evm.rs',
 'dom-usdom-checkpoint-proof-host/src/bin/plan.rs',
 'dom-usdom-checkpoint-proof-host/src/bin/prove-outer.rs',
 'dom-usdom-checkpoint-proof-host/src/bin/prove.rs'
];

test('Result-returning USDOM entrypoints use fixed explicit stderr wrappers',async()=>{
 const sources=await Promise.all(files.map(path=>readFile(
  new URL(`../../../../crates/${path}`,import.meta.url),'utf8')));
 assert.equal(sources.length,19);
 for(const source of sources){
  assert.doesNotMatch(source,/fn main\(\)\s*->\s*(?:anyhow::)?Result/);
  assert.match(source,/(?:async )?fn run\(\)\s*->/);
  assert.match(source,/(?:async )?fn main\(\)\s*\{\s*if let Err\(_error\) = run\(\)(?:\.await)?/s);
  assert.doesNotMatch(source,/eprintln!\([^;]*\{(?:_?error)\}/s);
  assert.match(source,/std::process::exit\(1\)/);
 }
});
