import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

const scripts=new URL('../../scripts/',import.meta.url);
const firstHalf=[
  'candidate-monitor.mjs','collect-finalized-deposit-source.sh',
  'export-authenticated-randomx-statement-set.sh','export-authenticated-randomx-statement.sh',
  'export-canonical-checkpoint-source-set.sh','export-canonical-checkpoint-source.sh',
  'export-canonical-finalized-burn-source.sh','export-dom-preactivation-anchor.sh',
  'materialize-ethereum-checkpoint-source-catalog.sh','materialize-limited-mainnet-policy.sh',
  'materialize-mainnet-preflight-attestation.mjs','materialize-mainnet-preflight-attestation.sh',
  'materialize-native-preactivation-facts.sh','materialize-preactivation-policy.sh',
];

test('first 14 derived retryable writers remain nominally inventoried',()=>{
  assert.equal(firstHalf.length,14);
  for(const file of firstHalf) assert.ok(readFileSync(new URL(file,scripts),'utf8').length>0,file);
});

test('single RandomX statement invalidates report before statement and republishes report last',()=>{
  const source=readFileSync(new URL('export-authenticated-randomx-statement.sh',scripts),'utf8');
  const proof=source.indexOf('--bin dom-usdom-export-randomx-statement');
  const remove=source.indexOf('remove-private-file-durable.mjs" "$REPORT"',proof);
  const statement=source.indexOf('install-private-file-stdin.mjs" "$OUTPUT"',remove);
  const report=source.indexOf('install-private-file-stdin.mjs" "$REPORT"',statement);
  assert.ok(proof>=0 && proof<remove && remove<statement && statement<report);
});
