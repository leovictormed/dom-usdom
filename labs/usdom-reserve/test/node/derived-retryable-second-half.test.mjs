import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

const scripts=new URL('../../scripts/',import.meta.url);
const secondHalf=[
  'materialize-production-preactivation-core.sh','materialize-production-release-core.sh',
  'materialize-production-solidity-pins.sh','materialize-release-provenance.sh',
  'materialize-safe-control-release-config.sh','materialize-safe-control-release-metadata.sh',
  'observe-authenticated-checkpoint.sh','observe-finalized-deposit-wallet.sh',
  'plan-authenticated-checkpoint-outer.sh','plan-authenticated-checkpoint-segment-set.sh',
  'plan-authenticated-economic-receipt-set.sh','plan-authenticated-finalized-burn.sh',
  'plan-authenticated-randomx-aggregate-set.sh','plan-authenticated-randomx-receipt-set.sh',
];

test('second 14 derived retryable writers remain nominally inventoried',()=>{
  assert.equal(secondHalf.length,14);
  for(const file of secondHalf) assert.ok(readFileSync(new URL(file,scripts),'utf8').length>0,file);
});

test('checkpoint outer planner invalidates completion before support files and installs index last',()=>{
  const source=readFileSync(new URL('plan-authenticated-checkpoint-outer.sh',scripts),'utf8');
  const plan=source.indexOf('--bin dom-usdom-plan-checkpoint-outer');
  const removal=source.indexOf('remove-private-file-durable.mjs',plan);
  const loop=source.indexOf('for name in checkpoint-statement-v6.bin checkpoint-outer-chain.bin checkpoint-outer-proof-job-index.json',removal);
  assert.ok(plan>=0 && plan<removal && removal<loop);
  assert.match(source,/checkpoint-statement-v6\.bin checkpoint-outer-chain\.bin checkpoint-outer-proof-job-index\.json/);
});
