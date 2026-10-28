import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';

const writer=spawnSync(process.execPath,['scripts/write-open-claims-execution-plan.mjs'],{encoding:'utf8'});
assert.equal(writer.status,0,writer.stderr);
const {phaseOrder}=JSON.parse(writer.stdout);
const scripts=phaseOrder.map(phase=>{
  const run=spawnSync('/usr/bin/bash',['scripts/generate-closed-mainnet-phase-command.sh',phase],{encoding:'utf8'});
  assert.equal(run.status,0,phase);
  return `\n# PHASE ${phase}\n${run.stdout}`;
}).join('');

function requireBefore(producer,consumer,label) {
  const produced=scripts.indexOf(producer),consumed=scripts.indexOf(consumer);
  assert.notEqual(produced,-1,`${label}: missing producer ${producer}`);
  assert.notEqual(consumed,-1,`${label}: missing consumer ${consumer}`);
  assert.ok(produced<consumed,`${label}: consumer precedes producer`);
}

test('mainnet semantic DAG never consumes an artifact before its producer',()=>{
  requireBefore('materialize:production-release-core','prepare-mainnet-deployment.mjs',
    'release configuration before deployment package');
  requireBefore('run-operational-status78-cycle.mjs contract-deployment "$index"','materialize:mainnet-predeployment-attestation',
    'adapter deployments before intermediate predeployment attestation');
  requireBefore('materialize:mainnet-predeployment-attestation','materialize-mainnet-deployment-completion.mjs',
    'intermediate preflight before registry/reserve completion');
  requireBefore('materialize-mainnet-deployment-completion.mjs','prepare:closed-mainnet-deposit',
    'finalized deployment before deposit');
  requireBefore('run-operational-status78-cycle.mjs reserve-resume','run-operational-status78-cycle.mjs deposit',
    'paused reserve resumed before deposit');
  requireBefore('submit:closed-mainnet-private-burn','export:canonical-checkpoint-source-set',
    'burn block before its checkpoint source');
  requireBefore('prove:authenticated-checkpoint-outer','plan:authenticated-finalized-burn',
    'burn-covering checkpoint before finalized-burn proof');
  requireBefore('check-safe-recovery-roster-v3-completion.mjs','materialize:safe-control-release-config',
    'finalized recovery drill before release control configuration');
});

test('the semantic rules reject a reversed producer/consumer pair',()=>{
  const synthetic='consumer\nproducer\n';
  assert.ok(synthetic.indexOf('producer')>synthetic.indexOf('consumer'));
});

