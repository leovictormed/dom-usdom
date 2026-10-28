import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validateClosedMainnetFinancialConservation} from '../../sdk/closed-mainnet-financial-conservation.mjs';
const h=n=>'0x'+n.repeat(64);
function fixture(){return {
  depositPackage:{amountBaseUnits:'1000000',depositId:h('1'),funder:'0x'+'12'.repeat(20),
    receivingCommitment:'0x'+'03'.repeat(32),releaseConfigSha256:'4'.repeat(64)},
  depositExecution:{amountBaseUnits:'1000000',allowanceBefore:'0',allowanceAfter:'0',steps:3,
    reserveBalanceBefore:'7000000',reserveBalanceAfter:'8000000',totalDepositedBefore:'0',
    totalDepositedAfter:'1000000',outstandingBefore:'0',outstandingAfter:'1000000',
    transactionHashes:[h('a'),h('b'),h('5')]},
  issuanceIndex:{schema:'usdom-finalized-deposit-witness-v1',native_manifest_sha256:'1'.repeat(64),
    source_file:'finalized-deposit-source.json',source_sha256:'3'.repeat(64),
    release_config_sha256:'4'.repeat(64),source_transaction_hash:h('5'),
    funder:'0x'+'12'.repeat(20),deposit_block_number:'5',deposit_block_hash:h('6'),
    finalized_beacon_slot:'8',finalized_beacon_root:h('7'),finalized_execution_block_number:'7',
    finalized_execution_block_hash:h('8'),replay_slot:'8',deposit_policy_hash:h('9'),
    witness_sha256:'2'.repeat(64),witness_file:'finalized-deposit-witness.bin',witness_bytes:1024,
    amount_base_units:'1000000',deposit_id:h('1'),receiving_commitment:'0x'+'03'.repeat(32),
    transaction_index:2,receipt_log_index:0,
    witness_verified:true,relation_executed:true,broadcasts:false,mines:false},
  redemptionPackage:{amountBaseUnits:'1000000',burnId:h('2'),requestId:h('3')},
  redemptionExecution:{amountBaseUnits:'1000000',steps:2,burnId:h('2'),requestId:h('3'),
    finalizedAcrossRpcCount:2,reserveBalanceBefore:'8000000',reserveBalanceAfter:'7000000',
    recipientBalanceBefore:'5000000',recipientBalanceAfter:'6000000',totalReleasedBefore:'0',
    totalReleasedAfter:'1000000',outstandingBefore:'1000000',outstandingAfter:'0',
    totalProvedDebtBefore:'1000000',totalProvedDebtAfter:'0'},
};}
test('one-USDT pilot conserves exact collateral and permanent proved debt',()=>{
  const value=fixture(); assert.equal(validateClosedMainnetFinancialConservation(value).amountBaseUnits,'1000000');
  for(const mutate of [v=>v.depositExecution.allowanceBefore='1',v=>v.depositExecution.allowanceAfter='1',
    v=>v.issuanceIndex.deposit_id=h('4'),v=>v.issuanceIndex.amount_base_units='999999',
    v=>v.redemptionExecution.reserveBalanceBefore='8000001',v=>v.redemptionExecution.reserveBalanceAfter='7000001',
    v=>v.redemptionExecution.outstandingBefore='1000001',v=>v.redemptionExecution.totalProvedDebtBefore='2000000',
    v=>v.issuanceIndex.funder='0x'+'13'.repeat(20),
    v=>v.issuanceIndex.receiving_commitment='0x'+'04'.repeat(32),
    v=>v.issuanceIndex.release_config_sha256='5'.repeat(64),
    v=>v.issuanceIndex.source_transaction_hash=h('4'),
    v=>v.depositExecution.transactionHashes[2]=h('4'),
    v=>v.depositExecution.transactionHashes.pop(),
    v=>v.depositExecution.reserveBalanceBefore='7000001',
    v=>v.depositExecution.totalDepositedBefore='1',
    v=>v.depositExecution.outstandingBefore='1',
    v=>v.redemptionExecution.recipientBalanceAfter='6000001',
    v=>v.redemptionExecution.totalReleasedAfter='999999',
    v=>v.redemptionExecution.reserveBalanceAfter='9'.repeat(100000),
    v=>v.redemptionExecution.reserveBalanceAfter=(1n<<256n).toString(),
    v=>v.redemptionExecution.totalProvedDebtAfter='1',v=>v.redemptionExecution.burnId=h('4'),
    v=>{v.issuanceIndex.unexpected=true;},v=>{delete v.issuanceIndex.witness_sha256;},
    v=>v.issuanceIndex.witness_bytes=0,v=>v.issuanceIndex.witness_bytes=4*1024*1024+1]) {
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
