import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';

test('all 57 open claims expose producer, validator, phase and readiness consumption',()=>{
  const run=spawnSync(process.execPath,['scripts/write-open-claims-execution-plan.mjs'],{encoding:'utf8'});
  assert.equal(run.status,0,run.stderr);
  const plan=JSON.parse(run.stdout);
  assert.equal(plan.entries.length,57);
  const exceptional=new Map(plan.entries.filter(row=>row.implementationStatus!=='external-operation')
    .map(row=>[row.claim,row.implementationStatus]));
  assert.deepEqual(exceptional,new Map());
  for(const row of plan.entries) {
    assert.equal(row.readinessConsumer,'readinessRequirementKeys(real-funds)');
    if(row.implementationStatus==='external-operation') {
      assert.ok(row.evidenceProducerCommands.length>0,row.claim);
      assert.ok(row.independentValidatorCommands.length>0,row.claim);
    } else assert.fail(`${row.claim}: every route must now be executable`);
  }
});

