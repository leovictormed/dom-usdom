import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';

test('burn block producer is exactly-one, tip-bound, secret-launched and durable',()=>{
  const source=readFileSync('scripts/mine-closed-mainnet-burn-block.mjs','utf8');
  assert.match(source,/USDOM_SECRET_NODE_LAUNCHER/);
  assert.match(source,/closedMainnetMineRequest\(before\)/);
  assert.match(source,/validateClosedMainnetMineResponse/);
  assert.match(source,/private-burn-submission-v1\.json/);
  assert.match(source,/private-burn-index\.json/);
  assert.match(source,/exactlyOneBlock:true,continuousMining:false/);
  assert.match(source,/writePrivateFileDurableNew\(receiptFile/);
});

test('generated DAG separates burn, its checkpoint, and payout',()=>{
  const plan=spawnSync(process.execPath,['scripts/write-open-claims-execution-plan.mjs'],{encoding:'utf8'});
  assert.equal(plan.status,0,plan.stderr);
  const phases=JSON.parse(plan.stdout).phaseOrder;
  const burn=phases.indexOf('submit-pilot-burn-secret');
  const checkpoint=phases.indexOf('produce-checkpoint-evidence-secret');
  const payout=phases.indexOf('execute-pilot-redemption-secret');
  assert.ok(burn>=0&&burn<checkpoint&&checkpoint<payout);
  const checkpointScript=spawnSync('/usr/bin/bash',['scripts/generate-closed-mainnet-phase-command.sh','produce-checkpoint-evidence-secret'],{encoding:'utf8'}).stdout;
  assert.match(checkpointScript,/private-burn-block-production-v1\.json/);
  assert.match(checkpointScript,/observe:authenticated-checkpoint[\s\S]*materialize:authenticated-checkpoint-witness[\s\S]*export:canonical-finalized-burn-source/);
});
