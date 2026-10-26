import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {Interface,Wallet,keccak256,sha256} from 'ethers';
import {buildClosedMainnetRedemptionPackage,validateClosedMainnetRedemptionPackage,
  validateClosedMainnetRedemptionRawTransaction,CLOSED_REDEMPTION_PRIORITY_FEE_PER_GAS}
  from '../../sdk/closed-mainnet-redemption-execution.mjs';

const h=n=>'0x'+n.toString(16).padStart(2,'0').repeat(32);
const tuple='(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 finalityBeaconSlot,uint64 validUntil)';
const iface=new Interface([`function queueWithdrawal(${tuple},bytes)`,`function executeWithdrawal(${tuple})`]);
function fixture(recipient='0x0000000000000000000000000000000000000040') {
  const burn={burnId:h(1),requestId:h(2),recipient,amount:'1000000',domDomain:h(3),height:'4',
    blockHash:h(5),stateRoot:h(6),finalityBeaconSlot:'7',validUntil:'9999999999'};
  const proof='0x73c457ba'+'11'.repeat(256),data=iface.encodeFunctionData('queueWithdrawal',[burn,proof]);
  return {schema:'usdom-authenticated-finalized-burn-submission-v1',ethereumChainId:'1',
    to:'0x0000000000000000000000000000000000000020',value:'0',method:'queueWithdrawal',burn,
    proof:{selector:'0x73c457ba',bytes:260,sha256:(awaitHash(proof))},statementHash:h(8),
    journalDigest:sha256(h(8)),data,dataKeccak256:keccak256(data),source:{
      releaseConfigSha256:'11'.repeat(32),verifierManifestSha256:'12'.repeat(32),
      sourceIndexPath:'evidence/finalized-burn-source/finalized-burn-source-index.json',sourceIndexSha256:'13'.repeat(32),
      inputPath:'evidence/finalized-burn-source/finalized-burn-input.bin',inputSha256:'14'.repeat(32),
      receiptIndexPath:'evidence/finalized-burn-receipt/finalized-burn-receipt-index.json',receiptIndexSha256:'15'.repeat(32),
      proofIndexPath:'evidence/finalized-burn-evm-proof/finalized-burn-evm-proof-index.json',proofIndexSha256:'16'.repeat(32),
      sealPath:'evidence/finalized-burn-evm-proof/finalized-burn-evm-seal.bin',imageId:h(17),groth16VerifierParameters:h(18),
    },broadcastAuthorized:false};
}
function awaitHash(hex) { return (awaitHash.crypto??=requireHash)(Buffer.from(hex.slice(2),'hex')); }
import {createHash} from 'node:crypto';
const requireHash=b=>createHash('sha256').update(b).digest('hex');

test('redemption fixes queue then execute for one USDOM with broadcast disabled',()=>{
  const submission=fixture(),value=buildClosedMainnetRedemptionPackage(submission);
  assert.equal(value.amountBaseUnits,'1000000'); assert.equal(value.broadcastAuthorized,false);
  assert.deepEqual(value.transactions.map(x=>x.name),['queue-withdrawal','execute-withdrawal']);
  assert.equal(validateClosedMainnetRedemptionPackage(value,submission),value);
  for(const mutate of [v=>v.transactions.reverse(),v=>v.broadcastAuthorized=true,
    v=>v.amountBaseUnits='2',v=>v.transactions[1].data='0x']) {
    const changed=structuredClone(value); mutate(changed);
    assert.throws(()=>validateClosedMainnetRedemptionPackage(changed,submission));
  }
});

test('raw validation binds nonce, chain, zero value, calldata and fee bounds',async()=>{
  const wallet=new Wallet('0x0123456789012345678901234567890123456789012345678901234567890123');
  const value=buildClosedMainnetRedemptionPackage(fixture(wallet.address)),expected=value.transactions[0];
  const tx={type:2,chainId:1,nonce:9,to:expected.to,value:0,data:expected.data,gasLimit:500000n,
    maxFeePerGas:10_000_000_000n,maxPriorityFeePerGas:CLOSED_REDEMPTION_PRIORITY_FEE_PER_GAS,accessList:[]};
  const raw=await wallet.signTransaction(tx);
  assert.equal(validateClosedMainnetRedemptionRawTransaction({raw,packageValue:value,index:0,nonce:'9'}).value,'0');
  for(const changed of [{...tx,value:1},{...tx,chainId:31337},{...tx,nonce:10},{...tx,data:'0x'}]) {
    const changedRaw=await wallet.signTransaction(changed);
    assert.throws(()=>validateClosedMainnetRedemptionRawTransaction({raw:changedRaw,packageValue:value,index:0,nonce:'9'}));
  }
  const wrongSigner=new Wallet('0x1123456789012345678901234567890123456789012345678901234567890123');
  const wrongRaw=await wrongSigner.signTransaction(tx);
  assert.throws(()=>validateClosedMainnetRedemptionRawTransaction({raw:wrongRaw,packageValue:value,index:0,nonce:'9'}));
});

test('executor separates every signature/publication and finalizes across two RPCs',()=>{
  const source=readFileSync(new URL('../../scripts/execute-closed-mainnet-redemption.sh',import.meta.url),'utf8');
  assert.match(source,/AUTORIZO ASSINAR RESGATE MAINNET ETAPA \$index/);
  assert.match(source,/AUTORIZO TRANSMITIR RESGATE MAINNET ETAPA \$index/);
  assert.match(source,/pendingWithdrawals\(bytes32\)/); assert.match(source,/cast block finalized/);
  assert.match(source,/paidBurns\(bytes32\)/); assert.match(source,/outputLast:true/);
  assert.match(source,/mainnet_genesis=0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3/);
  assert.match(source,/test "\$number1" = "\$number2"/); assert.match(source,/test "\$hash1" = "\$hash2"/);
  assert.match(source,/reserveRuntimeCodeHash/); assert.match(source,/reserveConfigHash\(\)\(bytes32\)/);
  assert.doesNotMatch(source,/cast send|--private-key|--mnemonic|sleep /);
});
