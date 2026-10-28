import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {closedPilotEmergencyAbortPlan} from '../../sdk/closed-pilot-emergency-abort.mjs';
const reserve=readFileSync(new URL('../../contracts/USDOMProofReserve.sol',import.meta.url),'utf8');
test('every pilot boundary has a fail-closed abort plan without fictional recovery',()=>{
 for(const phase of ['before-approve','after-approve','after-deposit','after-issuance','after-burn','after-queue','after-payout']) {
  const plan=closedPilotEmergencyAbortPlan(phase);
  assert.deepEqual(plan.immediate,['guardian-safe-pause','guardian-safe-close-deposits']);
  assert(plan.prohibited.includes('collateral-sweep'));
  assert(plan.prohibited.includes('deposit-refund'));
 }
 assert.deepEqual(closedPilotEmergencyAbortPlan('after-approve').allowance,
  ['funder-revoke-allowance-after-pause-confirmed']);
 assert.throws(()=>closedPilotEmergencyAbortPlan('unknown'));
});
test('permanent closure blocks new debt but preserves renewal and payout path',()=>{
 assert.match(reserve,/bool renewal = provedStatement != bytes32\(0\);[\s\S]*if \(renewal\)/);
 assert.doesNotMatch(reserve,/if \(depositsClosed && !renewal\) revert DepositsClosed\(\)/);
 const close=reserve.match(/function closeDeposits\([\s\S]*?function pauseQueueEpoch/)[0];
 assert.doesNotMatch(close,/totalProvedDebtAmount\s*=|delete provedBurn|transfer\(/);
 assert.match(reserve,/function executeWithdrawal\([\s\S]*totalProvedDebtAmount -= burn\.amount/);
});
