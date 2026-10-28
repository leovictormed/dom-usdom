import test from 'node:test';
import assert from 'node:assert/strict';
import {validatePilotTransactionEvidence,validatePilotTransactionOrder} from '../../sdk/closed-mainnet-pilot-evidence.mjs';

const address=n=>'0x'+n.repeat(40),hash=n=>'0x'+n.repeat(64);
function fixture(){
  const transaction={name:'deposit-usdt',to:address('2'),dataKeccak256:hash('3')};
  const validation={schema:'usdom-closed-mainnet-deposit-raw-validation-v1',index:'2',chainId:'1',
    name:transaction.name,value:'0',from:address('1'),nonce:'7',token:address('7'),reserve:address('8'),
    to:transaction.to,dataKeccak256:transaction.dataKeccak256,transactionHash:hash('a'),
    gasLimit:'100000',maxFeePerGas:'1000000000',maxPriorityFeePerGas:'200000000',
    maximumCost:'100000000000000'};
  const receipt={status:'0x1',transactionHash:validation.transactionHash,from:validation.from,
    to:validation.to,blockNumber:'0x123',blockHash:hash('b'),transactionIndex:'0x2',gasUsed:'0x5208',
    effectiveGasPrice:'0x3b9aca00'};
  const finality={schema:'usdom-closed-mainnet-deposit-finality-v2',
    transactionHash:validation.transactionHash,blockNumber:receipt.blockNumber,
    blockHash:receipt.blockHash,transactionIndex:receipt.transactionIndex,finalizedRpcCount:2,gasUsed:'21000',effectiveGasPrice:'1000000000',
    actualCost:'21000000000000',maximumCost:validation.maximumCost};
  const packageValue={token:validation.token,reserve:validation.reserve};
  return {kind:'deposit',index:2,receipt,validation,finality,transaction,signer:address('1'),packageValue};
}

test('pilot receipt chain is bound to chain, plan, signer, transaction and finalized block',()=>{
  assert.equal(validatePilotTransactionEvidence(fixture()),true);
  const mutations=[
    v=>v.validation.chainId='31337',v=>v.validation.index='1',v=>v.validation.from=address('6'),
    v=>v.validation.to=address('6'),v=>v.validation.dataKeccak256=hash('6'),
    v=>v.receipt.transactionHash=hash('6'),v=>v.receipt.from=address('6'),
    v=>v.receipt.to=address('6'),v=>v.receipt.status='0x0',v=>v.finality.blockNumber='0x124',
    v=>v.finality=null,
    v=>v.finality.blockHash=hash('6'),v=>v.finality.transactionIndex='0x3',v=>v.finality.finalizedRpcCount=1,
    v=>v.validation.nonce='07',v=>v.validation.nonce='9'.repeat(100000),
    v=>v.validation.nonce=(1n<<64n).toString(),v=>v.validation.maximumCost='1',
    v=>v.validation.gasLimit='0',v=>v.validation.maxFeePerGas='100000000001',
    v=>v.validation.maxPriorityFeePerGas='1000000001',v=>v.validation.token=address('6'),
    v=>v.validation.reserve=address('6'),v=>{v.validation.unexpected='field';},
    v=>v.receipt.blockNumber='0x00',v=>v.receipt.blockNumber='0xABC',
    v=>v.receipt.blockNumber='0x'+'f'.repeat(100000),
    v=>v.receipt.blockNumber='0x10000000000000000',
    v=>v.validation.transactionHash=v.validation.transactionHash.toUpperCase().replace('0X','0x'),
    v=>v.receipt.transactionHash=v.receipt.transactionHash.toUpperCase().replace('0X','0x'),
    v=>v.receipt.blockHash=v.receipt.blockHash.toUpperCase().replace('0X','0x'),
    v=>{v.finality.unexpected='field';},v=>v.finality.actualCost='21000000000001',
    v=>v.finality.blockHash=v.finality.blockHash.toUpperCase().replace('0X','0x'),
    v=>{delete v.finality.maximumCost;},v=>v.receipt.gasUsed='0x0',
  ];
  for(const mutate of mutations){const value=structuredClone(fixture());mutate(value);
    assert.throws(()=>validatePilotTransactionEvidence(value));}
});

test('redemption validation has its own exact bounded schema',()=>{
  const value=fixture();
  value.kind='redemption'; value.index=0;
  value.validation={...value.validation,
    schema:'usdom-closed-mainnet-redemption-raw-validation-v1',index:'0'};
  delete value.validation.token; delete value.validation.reserve;
  value.finality.schema='usdom-closed-mainnet-redemption-finality-v2';
  assert.equal(validatePilotTransactionEvidence(value),true);
  for(const mutate of [
    v=>{v.validation.token=address('7');},
    v=>{v.validation.nonce=(1n<<64n).toString();},
    v=>{v.validation.gasLimit='2500001';},
    v=>{v.validation.maximumCost='100000000000001';},
  ]) {
    const adversarial=structuredClone(value); mutate(adversarial);
    assert.throws(()=>validatePilotTransactionEvidence(adversarial));
  }
});

test('redemption receipt sequence requires strict block and transaction order',()=>{
 const first={blockNumber:'0x10',transactionIndex:'0x2'};
 const second={blockNumber:'0x10',transactionIndex:'0x3'};
 assert.deepEqual(validatePilotTransactionOrder([first,second],'redemption receipts'),[first,second]);
 for(const changed of [
  [first,{...second,transactionIndex:'0x2'}],
  [first,{...second,transactionIndex:'0x1'}],
  [first,{...second,blockNumber:'0xf'}],
 ]) assert.throws(()=>validatePilotTransactionOrder(changed,'redemption receipts'),
  /strict canonical transaction order/);
});
