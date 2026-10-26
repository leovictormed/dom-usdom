import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validateClosedMainnetPayoutEvidence} from '../../sdk/closed-mainnet-payout-evidence.mjs';
const raw='ab'.repeat(32),token='0x'+'11'.repeat(20),recipient='0x'+'22'.repeat(20);
function fixture() {
  const baseline={schema:'usdom-closed-mainnet-redemption-payout-baseline-v1',chainId:'1',
    packageSha256:raw,token,reserve:'0x'+'33'.repeat(20),recipient,recipientBalanceBaseUnits:'9000000',reserveBalanceBaseUnits:'8000000',
    totalReleasedBaseUnits:'2000000',outstandingBaseUnits:'6000000',totalProvedDebtBaseUnits:'1000000',
    observedAt:'finalized',rpcCount:2,snapshotBlockNumber:'19000000',snapshotBlockHash:'0x'+'66'.repeat(32)};
  const execution={schema:'usdom-closed-mainnet-redemption-execution-v1',packageSha256:raw,
    chainId:'1',steps:2,burnId:'0x'+'44'.repeat(32),requestId:'0x'+'55'.repeat(32),
    payoutBaselineSha256:raw,token,recipient,recipientBalanceBefore:'9000000',
    recipientBalanceAfter:'10000000',reserveBalanceBefore:'8000000',reserveBalanceAfter:'7000000',
    totalReleasedBefore:'2000000',totalReleasedAfter:'3000000',outstandingBefore:'6000000',
    outstandingAfter:'5000000',totalProvedDebtBefore:'1000000',totalProvedDebtAfter:'0',
    amountBaseUnits:'1000000',finalizedAcrossRpcCount:2,outputLast:true,
    snapshotBlockNumber:'19000064',snapshotBlockHash:'0x'+'77'.repeat(32)};
  const packageValue={ethereumChainId:'1',amountBaseUnits:'1000000',broadcastAuthorized:false,
    reserve:baseline.reserve,recipient,burnId:execution.burnId,requestId:execution.requestId};
  return {baseline,baselineSha256:raw,execution,packageValue};
}
test('payout evidence requires exact one-USDT finalized delta bound to baseline',()=>{
  const value=fixture(); assert.equal(validateClosedMainnetPayoutEvidence(value),value.execution);
  for(const mutate of [v=>v.execution.recipientBalanceAfter='9999999',v=>v.execution.recipientBalanceBefore='09000000',
    v=>v.execution.payoutBaselineSha256='cd'.repeat(32),v=>v.execution.packageSha256='cd'.repeat(32),
    v=>v.execution.token=recipient,v=>v.baseline.rpcCount=1,v=>v.execution.finalizedAcrossRpcCount=1,
    v=>v.execution.reserveBalanceAfter='7000001',v=>v.execution.totalReleasedAfter='2999999',
    v=>v.baseline.totalProvedDebtBaseUnits='2000000',
    v=>v.execution.outstandingAfter='5000001',v=>v.execution.totalProvedDebtAfter='1',
    v=>v.baseline.snapshotBlockHash='0x01',v=>v.execution.snapshotBlockNumber='019000064',
    v=>v.execution.outputLast=false,v=>v.execution.chainId='31337',v=>v.execution.steps=1,
    v=>v.execution.burnId='0x'+'66'.repeat(32),v=>v.packageValue.reserve='0x'+'77'.repeat(20),
    v=>v.packageValue.recipient='0x'+'77'.repeat(20)]) {
    const changed=structuredClone(value); mutate(changed);
    assert.throws(()=>validateClosedMainnetPayoutEvidence(changed));
  }
});
test('executor captures baseline before execute signing and reconciles both RPC balances',()=>{
  const source=readFileSync(new URL('../../scripts/execute-closed-mainnet-redemption.sh',import.meta.url),'utf8');
  assert.ok(source.indexOf('closed-mainnet-redemption-payout-baseline.json')<source.indexOf('AUTORIZO ASSINAR RESGATE MAINNET ETAPA $index'));
  assert.match(source,/recipientBalanceBaseUnits/); assert.match(source,/BigInt\(process\.argv\[1\]\)\+1000000n/);
  assert.match(source,/balanceOf\(address\)\(uint256\)/); assert.match(source,/payoutBaselineSha256/);
  assert.match(source,/totalReleased\(\)\(uint256\)/); assert.match(source,/outstanding\(\)\(uint256\)/);
  assert.match(source,/totalProvedDebtAmount\(\)\(uint256\)/); assert.match(source,/totalProvedDebtBefore/);
  assert.match(source,/snapshotBlockNumber/); assert.match(source,/snapshotBlockHash/);
  assert.match(source,/check-closed-mainnet-payout-evidence\.mjs/);
});
