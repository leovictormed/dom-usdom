import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import test from 'node:test';

const root=path.resolve(import.meta.dirname,'../..');
const node='/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node';
const read=file=>readFileSync(path.join(root,file),'utf8');

test('current runbook is bound to the 23-phase plan and distinguishes both fund authorizations',()=>{
  const result=spawnSync(node,['scripts/write-open-claims-execution-plan.mjs'],{cwd:root,encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  const plan=JSON.parse(result.stdout),runbook=read('docs/CLOSED-MAINNET-LINUX-RUNBOOK.md');
  assert.equal(plan.phaseOrder.length,23);
  assert.equal(plan.claimCount,33);
  assert.match(runbook,/23 fases ordenadas e 33 rotas/);
  assert.match(runbook,/permissão-base de produção/);
  assert.match(runbook,/não autoriza sozinha o depósito piloto/);
  assert.match(runbook,/autorização Safe 2-de-3 separada/);
  assert.doesNotMatch(runbook,/aprovação única vincula produção, implantação, fundos reais/);
});

test('current deployment and gas authorities state only final measured values',()=>{
  const policy=read('sdk/mainnet-deployment-execution.mjs');
  const deployment=JSON.parse(read('docs/LOCAL-DEPLOYMENT-GAS-MEASUREMENT-2026-10-26.json'));
  const operational=JSON.parse(read('docs/LOCAL-OPERATIONAL-GAS-MEASUREMENT-2026-10-26.json'));
  assert.match(policy,/4,764,316/);assert.match(policy,/20,339 B/);
  assert.doesNotMatch(policy,/4,786,403|20,446 B|4,673,187|20,003 B/);
  assert.equal(deployment.contracts.reserve.runtimeBytes,20339);
  assert.equal(deployment.contracts.reserve.gasUsed,'4764316');
  assert.equal(deployment.aggregate.sequenceGasLimit,'12500000');
  assert.equal(operational.schema,'usdom-local-operational-gas-measurement/v3');
  assert.equal(operational.productionRequirementsRemainFalse,true);
});

test('readiness diagnostic explicitly denies action authorization',async()=>{
  const {summarizeReadinessBlockers}=await import('../../sdk/readiness-diagnostics.mjs');
  const diagnostic=summarizeReadinessBlockers([]);
  assert.equal(diagnostic.actionAuthorized,false);
  assert.match(diagnostic.scope,/never authorize signing, broadcast, deployment or movement of funds/);
});
