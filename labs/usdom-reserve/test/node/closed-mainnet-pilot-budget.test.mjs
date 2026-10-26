import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validateClosedMainnetPilotBudget} from '../../sdk/closed-mainnet-pilot-budget.mjs';
const d='50000000000000000',r='100000000000000000';
test('pilot budget enforces exact transaction, phase and aggregate ceilings',()=>{
  assert.equal(validateClosedMainnetPilotBudget({depositMaximumCosts:[d,d,d],
    redemptionMaximumCosts:[r,r]}).totalMaximumCostWei,'350000000000000000');
  for(const value of [
    {depositMaximumCosts:['50000000000000001'],redemptionMaximumCosts:[]},
    {depositMaximumCosts:[d,d,d,d],redemptionMaximumCosts:[]},
    {depositMaximumCosts:[],redemptionMaximumCosts:['100000000000000001']},
    {depositMaximumCosts:[],redemptionMaximumCosts:[r,r,r]},
    {depositMaximumCosts:['01'],redemptionMaximumCosts:[]},
    {depositMaximumCosts:['0'],redemptionMaximumCosts:[]},
  ]) assert.throws(()=>validateClosedMainnetPilotBudget(value));
});
test('both executors enforce cumulative budget before signing and broadcast',()=>{
  for(const name of ['deposit','redemption']) {
    const source=readFileSync(new URL(`../../scripts/execute-closed-mainnet-${name}.sh`,import.meta.url),'utf8');
    const proposed=source.indexOf('check_pilot_budget "$proposed_cost"');
    const signing=source.indexOf(`AUTORIZO ASSINAR ${name==='deposit'?'DEPOSITO':'RESGATE'} MAINNET`);
    assert.ok(proposed>0&&proposed<signing);
    const publish=source.indexOf(`AUTORIZO TRANSMITIR ${name==='deposit'?'DEPOSITO':'RESGATE'} MAINNET`);
    assert.ok(source.lastIndexOf('check_pilot_budget',publish)<publish);
  }
});
