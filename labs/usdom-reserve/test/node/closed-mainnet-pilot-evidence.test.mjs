import test from 'node:test';
import assert from 'node:assert/strict';
import {validatePilotTransactionEvidence} from '../../sdk/closed-mainnet-pilot-evidence.mjs';

const address=n=>'0x'+n.repeat(40),hash=n=>'0x'+n.repeat(64);
function fixture(){
  const transaction={name:'deposit-usdt',to:address('2'),dataKeccak256:hash('3')};
  const validation={schema:'usdom-closed-mainnet-deposit-raw-validation-v1',index:'2',chainId:'1',
    name:transaction.name,value:'0',from:address('1'),to:transaction.to,
    dataKeccak256:transaction.dataKeccak256,transactionHash:hash('4')};
  const receipt={status:'0x1',transactionHash:validation.transactionHash,from:validation.from,
    to:validation.to,blockNumber:'0x123',blockHash:hash('5')};
  const finality={schema:'usdom-closed-mainnet-deposit-finality-v1',
    transactionHash:validation.transactionHash,blockNumber:receipt.blockNumber,
    blockHash:receipt.blockHash,finalizedRpcCount:2};
  return {kind:'deposit',index:2,receipt,validation,finality,transaction,signer:address('1')};
}

test('pilot receipt chain is bound to chain, plan, signer, transaction and finalized block',()=>{
  assert.equal(validatePilotTransactionEvidence(fixture()),true);
  const mutations=[
    v=>v.validation.chainId='31337',v=>v.validation.index='1',v=>v.validation.from=address('6'),
    v=>v.validation.to=address('6'),v=>v.validation.dataKeccak256=hash('6'),
    v=>v.receipt.transactionHash=hash('6'),v=>v.receipt.from=address('6'),
    v=>v.receipt.to=address('6'),v=>v.receipt.status='0x0',v=>v.finality.blockNumber='0x124',
    v=>v.finality.blockHash=hash('6'),v=>v.finality.finalizedRpcCount=1,
  ];
  for(const mutate of mutations){const value=structuredClone(fixture());mutate(value);
    assert.throws(()=>validatePilotTransactionEvidence(value));}
});
