import test from 'node:test';
import assert from 'node:assert/strict';
import {classifyRecoverableSafeDeploymentTargetConsensus} from '../../sdk/safe-control-deployment-target.mjs';

const safe='0x0000000000000000000000000000000000000100';
const packageDocument={controls:[{role:'governance',safe}]};
function factory({code='0x',nonce=0,hash='0x'+'11'.repeat(32),chainId=1n}={}) {
  return ()=>({
    getNetwork:async()=>({chainId}),getBlock:async()=>({number:100,hash}),
    pinFinalizedSnapshot(number,observedHash){assert.equal(number,100);assert.equal(observedHash,hash);},
    getCode:async()=>code,getTransactionCount:async()=>nonce,destroy:async()=>{},
  });
}

test('two RPCs classify a code-empty nonce-zero CREATE2 destination as vacant',async()=>{
  assert.deepEqual(await classifyRecoverableSafeDeploymentTargetConsensus({
    packageDocument,role:'governance',rpcUrls:['a','b'],providerFactory:factory(),
  }),{state:'vacant',role:'governance',address:safe});
});

test('CREATE2 target classification rejects EIP-684 nonce occupancy and RPC disagreement',async()=>{
  await assert.rejects(classifyRecoverableSafeDeploymentTargetConsensus({
    packageDocument,role:'governance',rpcUrls:['a','b'],providerFactory:factory({nonce:1}),
  }),/nonzero nonce/);
  let reads=0;
  await assert.rejects(classifyRecoverableSafeDeploymentTargetConsensus({
    packageDocument,role:'governance',rpcUrls:['a','b'],providerFactory:()=>{
      const provider=factory()();
      provider.getCode=async()=>reads++===0?'0x':'0x6000';
      return provider;
    },
  }),/changed/);
});
