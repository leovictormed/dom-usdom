import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const deployment=readFileSync(new URL('../../scripts/execute-mainnet-deployment.sh',import.meta.url),'utf8');
const deposit=readFileSync(new URL('../../scripts/execute-closed-mainnet-deposit.sh',import.meta.url),'utf8');
const preflight=readFileSync(new URL('../../sdk/mainnet-preflight.mjs',import.meta.url),'utf8');

test('partial contract deployment can only resume as the exact ordered generation',()=>{
  assert.match(deployment,/while \(\( prior < index \)\)/);
  for(const marker of ['packageSha256','releaseConfigSha256','observationDocumentSha256',
    'initcodeHash','runtimeCodeHash','receiptBlockHash','finalizedBlockHash']) {
    assert.ok(deployment.includes(marker),marker);
  }
  assert.ok((deployment.match(/assert_prior_deployments_finalized "\$endpoint"/g)??[]).length>=3);
  assert.match(deployment,/contract-deployment-\$prior-evidence\.json/);
});

test('partial generation cannot admit deposits and reserve must remain paused at cold start',()=>{
  const readiness=deposit.indexOf('check-mainnet-readiness.mjs real-funds');
  const ledger=deposit.indexOf('cast wallet address --ledger');
  assert.ok(readiness>=0&&readiness<ledger);
  assert.match(preflight,/reserve\?\.paused !== true/);
  assert.match(preflight,/reserve pending queue/);
  assert.match(preflight,/reserve_balance_nonzero/);
});
