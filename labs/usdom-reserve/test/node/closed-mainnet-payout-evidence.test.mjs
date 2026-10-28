import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validateClosedMainnetPayoutEvidence} from '../../sdk/closed-mainnet-payout-evidence.mjs';
import {redemptionAuthorityFixture,fixtureDigest} from './terminal-evidence-authority-fixtures.mjs';
const raw='ab'.repeat(32),token='0x'+'11'.repeat(20),recipient='0x'+'22'.repeat(20);
function fixture() {
  const authority=redemptionAuthorityFixture(recipient),{packageValue,packageBytes}=authority;
  const packageSha256=fixtureDigest(packageBytes);
  const baseline={schema:'usdom-closed-mainnet-redemption-payout-baseline-v1',chainId:'1',
    packageSha256,token:packageValue.token,reserve:packageValue.reserve,recipient,recipientBalanceBaseUnits:'9000000',reserveBalanceBaseUnits:'8000000',
    totalReleasedBaseUnits:'2000000',outstandingBaseUnits:'6000000',totalProvedDebtBaseUnits:'1000000',
    observedAt:'finalized',rpcCount:2,snapshotBlockNumber:'19000000',snapshotBlockHash:'0x'+'66'.repeat(32)};
  const baselineBytes=Buffer.from(JSON.stringify(baseline)),baselineSha256=fixtureDigest(baselineBytes);
  const executeFinality={schema:'usdom-closed-mainnet-redemption-finality-v2',transactionHash:'0x'+'88'.repeat(32),
    blockNumber:'19000032',blockHash:'0x'+'99'.repeat(32),transactionIndex:'7',finalizedRpcCount:2,
    gasUsed:'100000',effectiveGasPrice:'2000000000',actualCost:'200000000000000',maximumCost:'300000000000000'};
  const executeFinalityBytes=Buffer.from(JSON.stringify(executeFinality));
  const executeFinalitySha256=fixtureDigest(executeFinalityBytes);
  const execution={schema:'usdom-closed-mainnet-redemption-execution-v2',packageSha256,
    chainId:'1',steps:2,burnId:packageValue.burnId,requestId:packageValue.requestId,
    payoutBaselineSha256:baselineSha256,executeFinalitySha256,token:packageValue.token,recipient,recipientBalanceBefore:'9000000',
    recipientBalanceAfter:'10000000',reserveBalanceBefore:'8000000',reserveBalanceAfter:'7000000',
    totalReleasedBefore:'2000000',totalReleasedAfter:'3000000',outstandingBefore:'6000000',
    outstandingAfter:'5000000',totalProvedDebtBefore:'1000000',totalProvedDebtAfter:'0',
    amountBaseUnits:'1000000',finalizedAcrossRpcCount:2,outputLast:true,
    snapshotBlockNumber:'19000064',snapshotBlockHash:'0x'+'77'.repeat(32)};
  const executionBytes=Buffer.from(JSON.stringify(execution));
  return {...authority,baseline,baselineBytes,baselineSha256,packageSha256,execution,executionBytes,
    executeFinality,executeFinalityBytes,executeFinalitySha256};
}
test('payout evidence requires exact one-USDT finalized delta bound to baseline',()=>{
  const value=fixture(); assert.equal(validateClosedMainnetPayoutEvidence(value),value.execution);
  for(const mutate of [v=>v.execution.recipientBalanceAfter='9999999',v=>v.execution.recipientBalanceBefore='09000000',
    v=>v.baseline.extra='ambiguous',v=>v.execution.extra='ambiguous',
    v=>delete v.baseline.observedAt,v=>delete v.execution.outputLast,
    v=>v.execution.payoutBaselineSha256='cd'.repeat(32),v=>v.execution.packageSha256='cd'.repeat(32),
    v=>v.packageSha256='cd'.repeat(32),
    v=>v.execution.token=recipient,v=>v.baseline.rpcCount=1,v=>v.execution.finalizedAcrossRpcCount=1,
    v=>v.execution.reserveBalanceAfter='7000001',v=>v.execution.totalReleasedAfter='2999999',
    v=>v.execution.recipientBalanceAfter='9'.repeat(100000),
    v=>v.execution.recipientBalanceAfter=(1n<<256n).toString(),
    v=>v.baseline.totalProvedDebtBaseUnits='2000000',
    v=>v.execution.outstandingAfter='5000001',v=>v.execution.totalProvedDebtAfter='1',
    v=>v.baseline.snapshotBlockHash='0x01',v=>v.execution.snapshotBlockNumber='019000064',
    v=>v.baseline.snapshotBlockNumber='9'.repeat(100000),
    v=>v.baseline.snapshotBlockNumber=(1n<<64n).toString(),
    v=>v.execution.snapshotBlockNumber='9'.repeat(100000),
    v=>v.execution.snapshotBlockNumber=(1n<<64n).toString(),
    v=>v.execution.snapshotBlockNumber=v.baseline.snapshotBlockNumber,
    v=>v.execution.executeFinalitySha256='cd'.repeat(32),
    v=>v.executeFinality.blockNumber=v.baseline.snapshotBlockNumber,
    v=>v.executeFinality.transactionIndex='07',
    v=>v.execution.snapshotBlockNumber=(BigInt(v.executeFinality.blockNumber)-1n).toString(),
    v=>{v.execution.snapshotBlockNumber=v.executeFinality.blockNumber;v.execution.snapshotBlockHash='0x'+'aa'.repeat(32);},
    v=>v.execution.snapshotBlockNumber=(BigInt(v.baseline.snapshotBlockNumber)-1n).toString(),
    v=>v.execution.outputLast=false,v=>v.execution.chainId='31337',v=>v.execution.steps=1,
    v=>v.execution.burnId='0x'+'66'.repeat(32),v=>v.packageValue.reserve='0x'+'77'.repeat(20),
    v=>v.packageValue.recipient='0x'+'77'.repeat(20),v=>v.packageValue.token='0x'+'77'.repeat(20)]) {
    const changed=structuredClone(value); mutate(changed);
    assert.throws(()=>validateClosedMainnetPayoutEvidence(changed));
  }
});
test('payout terminal evidence rejects coordinated package B under submission authority A',()=>{
  const value=fixture(),foreign=redemptionAuthorityFixture('0x0000000000000000000000000000000000000099');
  value.packageValue=foreign.packageValue; value.packageBytes=foreign.packageBytes;
  value.packageSha256=fixtureDigest(foreign.packageBytes); value.baseline.packageSha256=value.packageSha256;
  value.baseline.recipient=foreign.packageValue.recipient; value.baselineBytes=Buffer.from(JSON.stringify(value.baseline));
  value.baselineSha256=fixtureDigest(value.baselineBytes); value.execution.packageSha256=value.packageSha256;
  value.execution.recipient=foreign.packageValue.recipient; value.execution.payoutBaselineSha256=value.baselineSha256;
  value.executionBytes=Buffer.from(JSON.stringify(value.execution));
  assert.throws(()=>validateClosedMainnetPayoutEvidence(value),/not canonical|stale or foreign/);
});
test('payout rejects coordinated finality bytes outside the baseline-to-snapshot interval',()=>{
  for(const mutate of [
    v=>v.executeFinality.blockNumber=v.baseline.snapshotBlockNumber,
    v=>v.executeFinality.transactionIndex='07',
    v=>v.execution.snapshotBlockNumber=(BigInt(v.executeFinality.blockNumber)-1n).toString(),
    v=>{v.execution.snapshotBlockNumber=v.executeFinality.blockNumber;v.execution.snapshotBlockHash='0x'+'aa'.repeat(32);},
  ]) {
    const value=fixture(); mutate(value);
    value.executeFinalityBytes=Buffer.from(JSON.stringify(value.executeFinality));
    value.executeFinalitySha256=fixtureDigest(value.executeFinalityBytes);
    value.execution.executeFinalitySha256=value.executeFinalitySha256;
    value.executionBytes=Buffer.from(JSON.stringify(value.execution));
    assert.throws(()=>validateClosedMainnetPayoutEvidence(value),/execute finality authority/);
  }
});
test('executor captures baseline before execute signing and reconciles both RPC balances',()=>{
  const source=readFileSync(new URL('../../scripts/execute-closed-mainnet-redemption.sh',import.meta.url),'utf8');
  assert.ok(source.indexOf('closed-mainnet-redemption-payout-baseline.json')
    <source.indexOf('AUTORIZO ASSINAR RESGATE ETAPA $index NONCE $nonce HASH $data_hash'));
  assert.match(source,/recipientBalanceBaseUnits/); assert.match(source,/BigInt\(process\.argv\[1\]\)\+1000000n/);
  assert.match(source,/balanceOf\(address\)\(uint256\)/); assert.match(source,/payoutBaselineSha256/); assert.match(source,/executeFinalitySha256/);
  assert.match(source,/totalReleased\(\)\(uint256\)/); assert.match(source,/outstanding\(\)\(uint256\)/);
  assert.match(source,/totalProvedDebtAmount\(\)\(uint256\)/); assert.match(source,/totalProvedDebtBefore/);
  assert.match(source,/snapshotBlockNumber/); assert.match(source,/snapshotBlockHash/);
  assert.match(source,/check-closed-mainnet-payout-evidence\.mjs/);
  assert.match(source,/check-private-strict-json-file\.mjs "\$execution_candidate"/);
  assert.match(source,/timeout --foreground --signal=TERM --kill-after=5s 120s \\\n\s+node scripts\/check-closed-mainnet-payout-evidence\.mjs "\$payout_baseline" "\$execution_candidate" "\$package" "\$finality_record"/);
});

test('payout exact schemas cannot be satisfied through inherited fields',()=>{
  const baselineCase=fixture();
  delete baselineCase.baseline.observedAt; baselineCase.baseline.extra='ambiguous';
  Object.setPrototypeOf(baselineCase.baseline,{observedAt:'finalized'});
  assert.throws(()=>validateClosedMainnetPayoutEvidence(baselineCase));

  const executionCase=fixture();
  delete executionCase.execution.outputLast; executionCase.execution.extra='ambiguous';
  Object.setPrototypeOf(executionCase.execution,{outputLast:true});
  assert.throws(()=>validateClosedMainnetPayoutEvidence(executionCase));
});
