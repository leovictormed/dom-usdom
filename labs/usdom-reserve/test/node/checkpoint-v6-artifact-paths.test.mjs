import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const repositoryRoot=new URL('../../../../',import.meta.url);
const activeFiles=[
  'crates/dom-node/src/bin/dom-usdom-export-finalized-burn-source.rs',
  'crates/dom-usdom-checkpoint-proof-host/src/lib.rs',
  'labs/usdom-reserve/scripts/plan-authenticated-checkpoint-outer.sh',
  'labs/usdom-reserve/scripts/prove-authenticated-checkpoint-outer.sh',
  'labs/usdom-reserve/scripts/package-authenticated-checkpoint-outer-evm-proof.sh',
  'labs/usdom-reserve/scripts/export-canonical-finalized-burn-source.sh',
  'labs/usdom-reserve/scripts/prepare-authenticated-checkpoint-submission.mjs',
  'labs/usdom-reserve/scripts/prove-authenticated-finalized-burn.sh',
  'labs/usdom-reserve/sdk/checkpoint-capacity-artifact-collector.mjs',
];

const source=async relative=>readFile(new URL(relative,repositoryRoot),'utf8');

test('every active checkpoint artifact producer and consumer uses the V6 path',async()=>{
  for(const relative of activeFiles) {
    const value=await source(relative);
    assert.match(value,/checkpoint-statement-v6\.bin/,relative);
    assert.doesNotMatch(value,/checkpoint-statement-v5\.bin/,relative);
  }
});

test('capacity execution parses V6 and the collector requires its exact 551 bytes',async()=>{
  const [executor,collector,submission]=await Promise.all([
    source('labs/usdom-reserve/scripts/run-checkpoint-capacity-e2e.mjs'),
    source('labs/usdom-reserve/sdk/checkpoint-capacity-artifact-collector.mjs'),
    source('labs/usdom-reserve/sdk/checkpoint-submission.mjs'),
  ]);
  assert.match(executor,/parseCheckpointStatementV6/);
  assert.doesNotMatch(executor,/parseCheckpointStatementV5/);
  assert.match(collector,/checkpoint-statement-v6\.bin',\{minimum:551,maximum:551\}/);
  assert.match(submission,/const statementMagic=Buffer\.from\('UDCPST06'/);
  assert.match(submission,/bytes\.length!==statementBytes/);
});
