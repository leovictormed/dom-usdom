import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validateClosedMainnetFinancialConservation} from '../../sdk/closed-mainnet-financial-conservation.mjs';
const h=n=>'0x'+n.repeat(64);
function fixture(){return {
  depositPackage:{amountBaseUnits:'1000000',depositId:h('1')},
  depositExecution:{amountBaseUnits:'1000000',allowanceBefore:'0',allowanceAfter:'0',steps:3,
    reserveBalanceAfter:'8000000',outstandingAfter:'1000000'},
  issuanceIndex:{schema:'usdom-finalized-deposit-witness-v1',amount_base_units:'1000000',
    deposit_id:h('1'),witness_verified:true,relation_executed:true,broadcasts:false,mines:false},
  redemptionPackage:{amountBaseUnits:'1000000',burnId:h('2'),requestId:h('3')},
  redemptionExecution:{amountBaseUnits:'1000000',steps:2,burnId:h('2'),requestId:h('3'),
    finalizedAcrossRpcCount:2,reserveBalanceBefore:'8000000',reserveBalanceAfter:'7000000',
    outstandingBefore:'1000000',outstandingAfter:'0',totalProvedDebtBefore:'1000000',totalProvedDebtAfter:'0'},
};}
test('one-USDT pilot conserves exact collateral and permanent proved debt',()=>{
  const value=fixture(); assert.equal(validateClosedMainnetFinancialConservation(value).amountBaseUnits,'1000000');
  for(const mutate of [v=>v.depositExecution.allowanceBefore='1',v=>v.depositExecution.allowanceAfter='1',
    v=>v.issuanceIndex.deposit_id=h('4'),v=>v.issuanceIndex.amount_base_units='999999',
    v=>v.redemptionExecution.reserveBalanceBefore='8000001',v=>v.redemptionExecution.reserveBalanceAfter='7000001',
    v=>v.redemptionExecution.outstandingBefore='1000001',v=>v.redemptionExecution.totalProvedDebtBefore='2000000',
    v=>v.redemptionExecution.totalProvedDebtAfter='1',v=>v.redemptionExecution.burnId=h('4')]) {
    const changed=structuredClone(value); mutate(changed);
    assert.throws(()=>validateClosedMainnetFinancialConservation(changed));
  }
});
test('executors enforce exact allowance stages, permanent identity and replay terminal flags',()=>{
  const deposit=readFileSync(new URL('../../scripts/execute-closed-mainnet-deposit.sh',import.meta.url),'utf8');
  const redemption=readFileSync(new URL('../../scripts/execute-closed-mainnet-redemption.sh',import.meta.url),'utf8');
  assert.match(deposit,/allowanceBaseUnits:"0"/);
  assert.match(deposit,/check_deposit_state "\$index" "\$rpc"/);
  assert.match(deposit,/\[\[ \$step == 1 \]\] && allowance_expected=1000000/);
  assert.match(deposit,/\[\[ \$step == 2 \]\]/);
  for(const getter of ['provedBurnStatements','provedBurnDebts','provedRequestBurns','paidBurns','paidRequests']) {
    assert.ok(redemption.includes(`${getter}(bytes32)`),getter);
  }
  assert.match(redemption,/test "\$debt1" = 1000000/);
  assert.ok(redemption.indexOf('check_burn_unused "$rpc"')<redemption.indexOf('publish-private-raw-transaction.mjs'));
});
