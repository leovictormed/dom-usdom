import test from 'node:test';
import assert from 'node:assert/strict';
import {
  closedMainnetMineRequest,
  validateClosedMainnetMineResponse,
  validatePersistedIssuanceBlock,
  validateQueuedIssuanceReceipt
} from '../../sdk/closed-mainnet-block.mjs';

const identity=Object.freeze({network:'mainnet',network_magic:'444f4d31',
  chain_id:'11'.repeat(32),genesis_hash:'22'.repeat(32),tip_height:0,tip_hash:'22'.repeat(32)});

test('closed Mainnet request binds one exact current tip',()=>{
  const request=closedMainnetMineRequest(identity);
  assert.deepEqual(request,{expected_tip_height:0,expected_tip_hash:'22'.repeat(32)});
  assert.equal(validateClosedMainnetMineResponse({schema_version:1,height:1,
    block_hash:'33'.repeat(32),initialized_genesis:false,count:1},request).height,1);
  const genesis=closedMainnetMineRequest(null);
  assert.equal(validateClosedMainnetMineResponse({schema_version:1,height:0,
    block_hash:'22'.repeat(32),initialized_genesis:true,count:1},genesis).height,0);
});

test('closed Mainnet response rejects count, height, hash and mode substitutions',()=>{
  const request=closedMainnetMineRequest(identity);
  const valid={schema_version:1,height:1,block_hash:'33'.repeat(32),initialized_genesis:false,count:1};
  for(const mutation of [
    {...valid,count:2},{...valid,height:0},{...valid,block_hash:'0'.repeat(64)},
    {...valid,block_hash:'AA'.repeat(32)},{...valid,initialized_genesis:true}
  ]) assert.throws(()=>validateClosedMainnetMineResponse(mutation,request));
  assert.throws(()=>closedMainnetMineRequest({...identity,network:'regtest'}));
});

test('queued issuance must bind the same chain and exact pre-mining tip',()=>{
  const receipt={schema:'usdom-finalized-deposit-issuance-submission-v1',state:'queued',
    mined:false,candidateId:`0x${'44'.repeat(32)}`,domChainId:`0x${identity.chain_id}`,
    domGenesisHash:`0x${identity.genesis_hash}`,depositId:`0x${'77'.repeat(32)}`,
    witnessSha256:'88'.repeat(32),amountBaseUnits:'1000000',noteCommitment:`0x${'99'.repeat(32)}`,
    broadcastsEthereum:false,
    observedTipHeight:'0',observedTipHash:`0x${identity.tip_hash}`};
  assert.equal(validateQueuedIssuanceReceipt(receipt,identity),receipt);
  for(const mutation of [
    {...receipt,state:'mined'},{...receipt,mined:true},{...receipt,observedTipHeight:'1'},
    {...receipt,observedTipHash:`0x${'55'.repeat(32)}`},{...receipt,domChainId:`0x${'66'.repeat(32)}`}
  ]) assert.throws(()=>validateQueuedIssuanceReceipt(mutation,identity));
});

test('durable issuance block remains bound to the exact canonical tip',()=>{
  const submission={candidateId:`0x${'44'.repeat(32)}`,depositId:`0x${'77'.repeat(32)}`,
    domChainId:`0x${identity.chain_id}`,domGenesisHash:`0x${identity.genesis_hash}`,
    observedTipHeight:'0',observedTipHash:`0x${identity.tip_hash}`};
  const tip={...identity,tip_height:1,tip_hash:'aa'.repeat(32)};
  const receipt={schema:'usdom-closed-mainnet-issuance-block-v1',candidateId:submission.candidateId,
    depositId:submission.depositId,parentHeight:'0',parentHash:submission.observedTipHash,
    blockHeight:'1',blockHash:`0x${tip.tip_hash}`,domChainId:submission.domChainId,
    domGenesisHash:submission.domGenesisHash,exactlyOneBlock:true,continuousMining:false,
    issuanceObserved:false,producedAt:'2026-10-26T12:00:00.000Z'};
  assert.equal(validatePersistedIssuanceBlock(receipt,submission,tip),receipt);
  assert.throws(()=>validatePersistedIssuanceBlock(receipt,submission,{...tip,tip_hash:'bb'.repeat(32)}));
});
