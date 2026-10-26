import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validateClosedMainnetDepositEvidence} from '../../sdk/closed-mainnet-deposit-evidence.mjs';
const raw='ab'.repeat(32),address=n=>'0x'+n.repeat(40);
function fixture() {
  const baseline={schema:'usdom-closed-mainnet-deposit-financial-baseline-v1',chainId:'1',
    packageSha256:raw,funder:address('1'),token:address('2'),reserve:address('3'),
    funderBalanceBaseUnits:'5000000',reserveBalanceBaseUnits:'7000000',
    totalDepositedBaseUnits:'6000000',outstandingBaseUnits:'4000000',
    allowanceBaseUnits:'0',
    observedAt:'finalized',rpcCount:2};
  const execution={schema:'usdom-closed-mainnet-deposit-execution-v1',packageSha256:raw,
    chainId:'1',steps:3,
    amountBaseUnits:'1000000',financialBaselineSha256:raw,
    funderBalanceBefore:'5000000',funderBalanceAfter:'4000000',
    reserveBalanceBefore:'7000000',reserveBalanceAfter:'8000000',
    totalDepositedBefore:'6000000',totalDepositedAfter:'7000000',
    outstandingBefore:'4000000',outstandingAfter:'5000000',allowanceBefore:'0',allowanceAfter:'0',outputLast:true};
  const packageValue={ethereumChainId:'1',amountBaseUnits:'1000000',broadcastAuthorized:false,
    releaseConfigSha256:raw,funder:baseline.funder,token:baseline.token,reserve:baseline.reserve};
  return {baseline,baselineSha256:raw,execution,packageValue};
}
test('deposit evidence binds four exact one-USDT financial deltas',()=>{
  const value=fixture(); assert.equal(validateClosedMainnetDepositEvidence(value),value.execution);
  for(const mutate of [v=>v.execution.funderBalanceAfter='4000001',v=>v.execution.reserveBalanceAfter='7999999',
    v=>v.execution.totalDepositedAfter='7000001',v=>v.execution.outstandingAfter='4999999',
    v=>v.execution.funderBalanceBefore='05000000',v=>v.execution.allowanceBefore='1',
    v=>v.execution.allowanceAfter='1',v=>v.baseline.allowanceBaseUnits='1',
    v=>v.execution.financialBaselineSha256='cd'.repeat(32),v=>v.baseline.rpcCount=1,
    v=>v.execution.outputLast=false,v=>v.execution.chainId='31337',v=>v.execution.steps=2,
    v=>v.packageValue.funder=address('4'),v=>v.packageValue.reserve=address('4')]) {
    const changed=structuredClone(value); mutate(changed);
    assert.throws(()=>validateClosedMainnetDepositEvidence(changed));
  }
});
test('executor snapshots before signing and verifies deposit record plus dual-RPC deltas',()=>{
  const source=readFileSync(new URL('../../scripts/execute-closed-mainnet-deposit.sh',import.meta.url),'utf8');
  assert.ok(source.indexOf('usdom-closed-mainnet-deposit-financial-baseline-v1')
    <source.indexOf('AUTORIZO ASSINAR DEPOSITO MAINNET ETAPA $index'));
  assert.match(source,/totalDeposited\(\)\(uint256\)/); assert.match(source,/outstanding\(\)\(uint256\)/);
  assert.match(source,/deposits\(bytes32\)\(address,uint64,bytes32\)/);
  assert.match(source,/financialBaselineSha256/); assert.match(source,/funderBalanceAfter/);
});
