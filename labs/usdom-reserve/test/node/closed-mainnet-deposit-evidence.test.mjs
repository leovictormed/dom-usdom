import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validateClosedMainnetDepositEvidence} from '../../sdk/closed-mainnet-deposit-evidence.mjs';
import {depositAuthorityFixture,fixtureDigest} from './terminal-evidence-authority-fixtures.mjs';
const raw='ab'.repeat(32),address=n=>'0x'+n.repeat(40);
function fixture() {
  const authority=depositAuthorityFixture(),{packageValue,packageBytes}=authority;
  const packageSha256=fixtureDigest(packageBytes);
  const baseline={schema:'usdom-closed-mainnet-deposit-financial-baseline-v2',chainId:'1',
    packageSha256,funder:packageValue.funder,token:packageValue.token,reserve:packageValue.reserve,
    funderBalanceBaseUnits:'5000000',reserveBalanceBaseUnits:'7000000',
    totalDepositedBaseUnits:'6000000',outstandingBaseUnits:'4000000',
    allowanceBaseUnits:'0',
    observedAt:'finalized',rpcCount:2,snapshotBlockNumber:'19000000',snapshotBlockHash:'0x'+'66'.repeat(32)};
  const baselineBytes=Buffer.from(JSON.stringify(baseline)),baselineSha256=fixtureDigest(baselineBytes);
  const depositFinality={schema:'usdom-closed-mainnet-deposit-finality-v2',transactionHash:'0x'+'33'.repeat(32),
    blockNumber:'19000032',blockHash:'0x'+'77'.repeat(32),transactionIndex:'8',finalizedRpcCount:2,
    gasUsed:'100000',effectiveGasPrice:'2000000000',actualCost:'200000000000000',maximumCost:'300000000000000'};
  const depositFinalityBytes=Buffer.from(JSON.stringify(depositFinality));
  const depositFinalitySha256=fixtureDigest(depositFinalityBytes);
  const execution={schema:'usdom-closed-mainnet-deposit-execution-v3',packageSha256,
    chainId:'1',steps:3,
    amountBaseUnits:'1000000',financialBaselineSha256:baselineSha256,depositFinalitySha256,
    snapshotBlockNumber:'19000064',snapshotBlockHash:'0x'+'88'.repeat(32),
    funderBalanceBefore:'5000000',funderBalanceAfter:'4000000',
    reserveBalanceBefore:'7000000',reserveBalanceAfter:'8000000',
    totalDepositedBefore:'6000000',totalDepositedAfter:'7000000',
    outstandingBefore:'4000000',outstandingAfter:'5000000',allowanceBefore:'0',allowanceAfter:'0',outputLast:true,
    transactionHashes:['0x'+'11'.repeat(32),'0x'+'22'.repeat(32),'0x'+'33'.repeat(32)]};
  const executionBytes=Buffer.from(JSON.stringify(execution));
  return {...authority,baseline,baselineBytes,baselineSha256,packageSha256,execution,executionBytes,
    depositFinality,depositFinalityBytes,depositFinalitySha256};
}
test('deposit evidence binds four exact one-USDT financial deltas',()=>{
  const value=fixture(); assert.equal(validateClosedMainnetDepositEvidence(value),value.execution);
  for(const mutate of [v=>v.execution.funderBalanceAfter='4000001',v=>v.execution.reserveBalanceAfter='7999999',
    v=>v.execution.totalDepositedAfter='7000001',v=>v.execution.outstandingAfter='4999999',
    v=>v.execution.funderBalanceBefore='05000000',v=>v.execution.allowanceBefore='1',
    v=>v.execution.funderBalanceBefore='9'.repeat(100000),
    v=>v.execution.funderBalanceBefore=(1n<<256n).toString(),
    v=>v.execution.allowanceAfter='1',v=>v.baseline.allowanceBaseUnits='1',
    v=>v.execution.financialBaselineSha256='cd'.repeat(32),v=>v.baseline.rpcCount=1,
    v=>v.packageSha256='cd'.repeat(32),
    v=>v.execution.outputLast=false,v=>v.execution.chainId='31337',v=>v.execution.steps=2,
    v=>v.packageValue.funder=address('4'),v=>v.packageValue.reserve=address('4'),
    v=>{v.baseline.extra='ambiguous';},v=>{delete v.baseline.observedAt;},
    v=>{v.execution.extra='ambiguous';},v=>{delete v.execution.outputLast;}]) {
    const changed=structuredClone(value); mutate(changed);
    assert.throws(()=>validateClosedMainnetDepositEvidence(changed));
  }
});
test('deposit terminal evidence rejects coordinated package B under upstream authority A',()=>{
  const value=fixture(),foreign=depositAuthorityFixture('0x0000000000000000000000000000000000000030');
  value.packageValue=foreign.packageValue; value.packageBytes=foreign.packageBytes;
  value.packageSha256=fixtureDigest(foreign.packageBytes);
  value.baseline.packageSha256=value.packageSha256; value.baseline.reserve=foreign.packageValue.reserve;
  value.baselineBytes=Buffer.from(JSON.stringify(value.baseline)); value.baselineSha256=fixtureDigest(value.baselineBytes);
  value.execution.packageSha256=value.packageSha256; value.execution.financialBaselineSha256=value.baselineSha256;
  value.executionBytes=Buffer.from(JSON.stringify(value.execution));
  assert.throws(()=>validateClosedMainnetDepositEvidence(value),/authenticated upstream authority/);
});
test('deposit rejects coordinated finality outside the baseline-to-snapshot interval',()=>{
  for(const mutate of [
    v=>v.depositFinality.blockNumber=v.baseline.snapshotBlockNumber,
    v=>v.depositFinality.transactionIndex='08',
    v=>v.execution.snapshotBlockNumber=(BigInt(v.depositFinality.blockNumber)-1n).toString(),
    v=>{v.execution.snapshotBlockNumber=v.depositFinality.blockNumber;v.execution.snapshotBlockHash='0x'+'99'.repeat(32);},
  ]) {
    const value=fixture(); mutate(value);
    value.depositFinalityBytes=Buffer.from(JSON.stringify(value.depositFinality));
    value.depositFinalitySha256=fixtureDigest(value.depositFinalityBytes);
    value.execution.depositFinalitySha256=value.depositFinalitySha256;
    value.executionBytes=Buffer.from(JSON.stringify(value.execution));
    assert.throws(()=>validateClosedMainnetDepositEvidence(value),/deposit finality authority/);
  }
});
test('executor snapshots before signing and verifies deposit record plus dual-RPC deltas',()=>{
  const source=readFileSync(new URL('../../scripts/execute-closed-mainnet-deposit.sh',import.meta.url),'utf8');
  assert.ok(source.indexOf('usdom-closed-mainnet-deposit-financial-baseline-v2')
    <source.indexOf('AUTORIZO ASSINAR DEPOSITO ETAPA $index NONCE $nonce HASH $data_hash'));
  assert.match(source,/totalDeposited\(\)\(uint256\)/); assert.match(source,/outstanding\(\)\(uint256\)/);
  assert.match(source,/deposits\(bytes32\)\(address,uint64,bytes32\)/);
  assert.match(source,/financialBaselineSha256/); assert.match(source,/depositFinalitySha256/); assert.match(source,/funderBalanceAfter/);
  assert.match(source,/check-private-strict-json-file\.mjs "\$execution_candidate"/);
  assert.match(source,/timeout --foreground --signal=TERM --kill-after=5s 120s \\\n\s+node scripts\/check-closed-mainnet-deposit-evidence\.mjs "\$deposit_baseline" "\$execution_candidate" "\$package" "\$finality_record"/);
});
