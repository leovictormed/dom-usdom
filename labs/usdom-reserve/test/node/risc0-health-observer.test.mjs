import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {Interface} from 'ethers';
import {createRiscZeroHealthSourceCatalog} from '../../sdk/risc0-health-source-catalog.mjs';
import {
  collectRiscZeroHealthSources,
  observeRiscZeroMainnetHealth,
  reconcileRiscZeroHealthSources,
  riscZeroRpcEndpointHash,
} from '../../sdk/risc0-health-observer.mjs';

const reference=JSON.parse(await readFile(
  new URL('../../config/risc0-ethereum-mainnet-v3.json',import.meta.url),'utf8'));
const urls=['https://rpc-a.invalid/','https://rpc-b.invalid/'];
const catalog=createRiscZeroHealthSourceCatalog({sources:urls.map((url,index)=>({
  sourceId:`rpc-${index+1}`,operatorId:`operator-${index+1}`,
  providerId:`provider-${index+1}`,infrastructureId:`infra-${index+1}`,
  endpointHash:riscZeroRpcEndpointHash(url),
}))});
const endpoints=urls.map((url,index)=>({sourceId:`rpc-${index+1}`,url}));

test('multi-RPC collector binds every observation to the release catalog without returning URLs',async()=>{
  const providers=[];
  const sources=await collectRiscZeroHealthSources({reference,catalog,endpoints,
    providerFactory:(url,identity)=>{
      const provider={url,identity,destroyed:false,destroy(){this.destroyed=true;}};
      providers.push(provider);
      return provider;
    },observer:async()=>({finalized:'same-snapshot'})});
  assert.deepEqual(sources,catalog.sources.map(identity=>({...identity,
    observation:{finalized:'same-snapshot'}})));
  assert.equal(JSON.stringify(sources).includes('secret-'),false);
  assert(providers.every(provider=>provider.destroyed));
});

test('multi-RPC collector fails closed when finalized health views diverge',async()=>{
  let calls=0;
  await assert.rejects(collectRiscZeroHealthSources({reference,catalog,endpoints,
    providerFactory:url=>({url,destroy(){}}),observer:async()=>({
      finalizedBlockHash:'0x'+(++calls===1?'11':'22').repeat(32),
    })}),/cataloged RPCs disagree/);
  assert.throws(()=>reconcileRiscZeroHealthSources([
    {observation:{paused:false}},{observation:{paused:true}},
  ]),/disagree/);
});

test('multi-RPC collector rejects endpoint substitution before opening a provider',async()=>{
  let opened=0;
  const changed=structuredClone(endpoints);
  changed[1].url='https://rpc-c.invalid/';
  await assert.rejects(collectRiscZeroHealthSources({reference,catalog,endpoints:changed,
    providerFactory:()=>{ opened++; return {}; },observer:async()=>({})}),/does not match approved/);
  assert.equal(opened,0,'all endpoint identities must validate before any network access');
});

test('multi-RPC collector rejects duplicate, missing and non-HTTPS endpoint inputs',async()=>{
  await assert.rejects(collectRiscZeroHealthSources({reference,catalog,
    endpoints:[endpoints[0],endpoints[0]],providerFactory:()=>({}),observer:async()=>({})}),/distinct/);
  await assert.rejects(collectRiscZeroHealthSources({reference,catalog,endpoints:[endpoints[0]],
    providerFactory:()=>({}),observer:async()=>({})}),/every approved/);
  for(const endpoint of ['http://rpc.invalid/','https://rpc.invalid/secret',
    'https://rpc.invalid/?key=secret','https://user:secret@rpc.invalid/','https://127.0.0.1/']) {
    assert.throws(()=>riscZeroRpcEndpointHash(endpoint),/HTTPS/);
  }
});

test('multi-RPC collector redacts endpoint secrets from observation failures',async()=>{
  await assert.rejects(collectRiscZeroHealthSources({reference,catalog,endpoints,
    providerFactory:url=>({url,destroy(){}}),observer:async({provider})=>{
      throw new Error(`request failed at ${provider.url}`);
    }}),error=>{
      assert.equal(error.message.includes('secret-'),false);
      assert.match(error.message,/\[redacted RPC URL\]/);
      return true;
    });
});

function healthProvider({changedCode=false}={}) {
 const direct=new Interface(['function SELECTOR() view returns (bytes4)',
  'function VERSION() view returns (string)']);
 const stop=new Interface(['function paused() view returns (bool)','function verifier() view returns (address)']);
 let codeReads=0;
 let pinned=null;
 return {pinFinalizedSnapshot(number,hash){
  pinned={tag:number,hash}; return pinned;
 },async send(method,params) {
  if(method==='eth_chainId') return '0x1';
  if(method==='eth_getBlockByNumber'&&params[0]==='0x0') return {
   number:'0x0',hash:'0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3'};
  if(method==='eth_getBlockByNumber') return {number:'0x10',hash:'0x'+'ab'.repeat(32)};
  if(method==='eth_getCode') {
   codeReads++;
   return changedCode&&codeReads>2?'0x6002':'0x6001';
  }
  throw new Error(`unexpected ${method} ${params}`);
 },async call(transaction) {
  const selector=transaction.data.slice(0,10);
  if(selector===direct.getFunction('SELECTOR').selector) {
   return direct.encodeFunctionResult('SELECTOR',[reference.verifier_selector]);
  }
  if(selector===direct.getFunction('VERSION').selector) {
   return direct.encodeFunctionResult('VERSION',[reference.verifier_version]);
  }
  if(selector===stop.getFunction('paused').selector) return stop.encodeFunctionResult('paused',[false]);
  if(selector===stop.getFunction('verifier').selector) {
   return stop.encodeFunctionResult('verifier',[reference.verifier_address]);
  }
  throw new Error('unexpected call');
 }};
}

test('health observer re-reads code and state at one stable finalized snapshot',async()=>{
 const observation=await observeRiscZeroMainnetHealth({reference,provider:healthProvider()});
 assert.equal(observation.finalizedBlockHash,observation.snapshotBlockHashAfter);
 await assert.rejects(()=>observeRiscZeroMainnetHealth({reference,
  provider:healthProvider({changedCode:true})}),/snapshot changed/);
});

test('health command uses only catalog-matched bounded sources',async()=>{
 const source=await readFile(new URL('../../scripts/check-risc0-health.mjs',import.meta.url),'utf8');
 assert.match(source,/collectRiscZeroHealthSources/);
 assert.match(source,/evidence\/risc0-health-sources\.json/);
 assert.match(source,/USDOM_RISC0_RPC_URL_/);
 assert.doesNotMatch(source,/JsonRpcProvider|ETHEREUM_RPC_URL/);
});
