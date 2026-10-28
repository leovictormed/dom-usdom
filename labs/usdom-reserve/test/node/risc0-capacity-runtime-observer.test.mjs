import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {observePinnedRiscZeroRuntime} from '../../sdk/risc0-capacity-runtime-observer.mjs';
import {PINNED_RISC0_MAINNET_V3} from '../../sdk/risc0-verifier-reference.mjs';

const sources=[
  {sourceId:'alpha',url:'https://alpha.invalid/'},
  {sourceId:'beta',url:'https://beta.invalid/'},
];
const runtime=(await readFile(new URL('../fixtures/risc0-mainnet-v3-runtime.hex',import.meta.url),'utf8')).trim();
const reference=PINNED_RISC0_MAINNET_V3;
const hash='0x'+'11'.repeat(32);
const rpc=async({source,method,params})=>{
  assert(['alpha','beta'].includes(source.sourceId));
  if(method==='eth_chainId') return '0x1';
  if(method==='eth_getBlockByNumber') {
    if(params[0]==='finalized') return {number:source.sourceId==='alpha'?'0x20':'0x21',hash};
    return {number:'0x20',hash};
  }
  if(method==='eth_getCode') return runtime;
  throw new Error('unexpected RPC method');
};

test('capacity observer rechecks identical pinned runtime at a common finalized block',async()=>{
  const result=await observePinnedRiscZeroRuntime({reference,sources,rpc});
  assert.equal(result.finalizedBlockNumber,'32');
  assert.equal(result.finalizedBlockHash,hash);
  assert.equal(result.runtimeCode,runtime);
  assert.deepEqual(result.sourceIds,['alpha','beta']);
  assert.equal(result.endpointSha256.length,2);
  assert(Object.isFrozen(result));
});

test('capacity observer rejects source, chain, block and runtime substitutions',async()=>{
  await assert.rejects(observePinnedRiscZeroRuntime({reference,sources:[...sources].reverse(),rpc}),
    /ordered/);
  await assert.rejects(observePinnedRiscZeroRuntime({reference,sources:[sources[0],sources[0]],rpc}),
    /distinct/);
  await assert.rejects(observePinnedRiscZeroRuntime({reference,sources:[
    sources[0],{sourceId:'beta',url:'http://beta.invalid'},
  ],rpc}),/credential-free HTTPS/);
  await assert.rejects(observePinnedRiscZeroRuntime({reference,sources,rpc:async value=>
    value.method==='eth_chainId'?'0x7a69':rpc(value)}),/not Ethereum mainnet/);
  await assert.rejects(observePinnedRiscZeroRuntime({reference,sources,rpc:async value=>{
    if(value.method==='eth_getBlockByNumber' && value.params[0]==='0x20'
        && value.source.sourceId==='beta') return {number:'0x20',hash:'0x'+'22'.repeat(32)};
    return rpc(value);
  }}),/disagree/);
  await assert.rejects(observePinnedRiscZeroRuntime({reference,sources,rpc:async value=>
    value.method==='eth_getCode'?'0x6000':rpc(value)}),/reviewed pin/);
  for(const number of [`0x${'f'.repeat(100000)}`,'0x10000000000000000','0x20'.toUpperCase()]) {
    await assert.rejects(observePinnedRiscZeroRuntime({reference,sources,rpc:async value=>
      value.method==='eth_getBlockByNumber'&&value.params[0]==='finalized'
        ?{number,hash}:rpc(value)}),/canonical Ethereum block/);
  }
});
