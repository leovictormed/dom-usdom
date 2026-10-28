import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {keccak256,toUtf8Bytes} from 'ethers';
import {buildEthereumCheckpointSourceCatalog,collectEthereumCheckpointConsensus as collectRaw,
  ETHEREUM_MAINNET_GENESIS_VALIDATORS_ROOT,requestBeaconJson}
  from '../../sdk/ethereum-checkpoint-consensus.mjs';

const bootstrap=JSON.parse(readFileSync(new URL(
  '../../../usdom-ethereum-finality/fixtures/mainnet-fulu-bootstrap.json',import.meta.url),'utf8'));
const root='0xa8f19965d0082e1f0c6099cc2a73aa6315d3a7eae012731480140defae43e30f';
const epoch='482688';
const boundarySlot=BigInt(epoch)*32n;
const freshTime=BigInt('1606824023')+(boundarySlot+64n)*12n;
const genesis={data:{genesis_time:'1606824023',genesis_validators_root:
  ETHEREUM_MAINNET_GENESIS_VALIDATORS_ROOT,genesis_fork_version:'0x00000000'}};
const finality={execution_optimistic:false,data:{previous_justified:{epoch:'8',root:'0x'+'21'.repeat(32)},
  current_justified:{epoch:'9',root:'0x'+'31'.repeat(32)},finalized:{epoch,root}}};
const header={execution_optimistic:false,finalized:true,data:{root,canonical:true,header:{
  message:bootstrap.data.header.beacon,signature:'0x'+'00'.repeat(96)}}};
const sources=[1,2,3].map(index=>({operatorId:`operator-${index}`,url:`https://beacon${index}.example/api`}));
const catalog={schema:'usdom-ethereum-checkpoint-source-catalog-v1',sources:sources.map(source=>({
  operatorId:source.operatorId,originKeccak256:keccak256(toUtf8Bytes(new URL(source.url).origin))}))};
const collectEthereumCheckpointConsensus=options=>collectRaw({...options,catalog:options.catalog??catalog});

function responder({finalityBySource=new Map(),headerValue=header,genesisValue=genesis,
  bootstrapValue=bootstrap}={}) {
  return async url=>{
    if(url.includes('/beacon/genesis')) return structuredClone(genesisValue);
    if(url.includes('/finality_checkpoints')) {
      const source=/beacon([0-9])/.exec(url)?.[1];
      return structuredClone(finalityBySource.get(source)??finality);
    }
    if(url.includes('/beacon/headers/')) return structuredClone(headerValue);
    if(url.includes('/light_client/bootstrap/')) return structuredClone(bootstrapValue);
    throw new Error('unexpected test URL');
  };
}

test('collects one stable mainnet checkpoint from three independent operators',async()=>{
  const result=await collectEthereumCheckpointConsensus({sources,request:responder(),nowUnix:freshTime});
  assert.deepEqual(result,{schema:'usdom-ethereum-checkpoint-consensus-v1',network:'ethereum-mainnet',
    checkpointEpoch:epoch,checkpointSlot:boundarySlot.toString(),checkpointRoot:root,sourceCount:'3',
    sourceSetCommitment:'0x17e2b9564cfb224015c7b97c92790ba197c95ccfad0a1dc95e7d219755bf9477',
    observedAtUnix:freshTime.toString()});
});

test('rejects duplicate operator identity or HTTPS origin',async()=>{
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources:[sources[0],sources[0],sources[2]],
    request:responder()}),/pairwise distinct/);
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources:[sources[0],
    {...sources[1],url:sources[0].url},sources[2]],request:responder()}),/pairwise distinct/);
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources:[...sources.slice(0,2),
    {operatorId:'operator-3',url:'http:\/\/beacon3.example'}],request:responder()}),/credential-free HTTPS/);
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources:[
    {operatorId:'operator-1',url:'https://shared.example:443/api'},
    {operatorId:'operator-2',url:'https://shared.example:444/api'},sources[2]],
  }),/hostnames must be pairwise distinct/);
  assert.throws(()=>buildEthereumCheckpointSourceCatalog([
    {operatorId:'operator-1',url:'https://127.0.0.1:443/api'},sources[1],sources[2]],
  ),/public DNS hostname/);
});

test('rejects free labels or origins outside the fixed public catalog',async()=>{
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources:[...sources.slice(0,2),
    {...sources[2],operatorId:'invented'}],request:responder()}),/fixed catalog/);
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources:[...sources.slice(0,2),
    {...sources[2],url:'https:\/\/attacker.example/api'}],request:responder()}),/fixed catalog/);
  const reordered={...catalog,sources:[catalog.sources[1],catalog.sources[0],catalog.sources[2]]};
  await assert.rejects(()=>collectRaw({sources,catalog:reordered,request:responder()}),/must be sorted/);
});

test('catalog builder persists only sorted public identities and origin commitments',()=>{
  const built=buildEthereumCheckpointSourceCatalog([...sources].reverse());
  assert.deepEqual(built,catalog);
  const serialized=JSON.stringify(built);
  for(const source of sources) assert.doesNotMatch(serialized,new RegExp(new URL(source.url).hostname));
});

test('rejects wrong network, optimistic or noncanonical observations',async()=>{
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources,request:responder({genesisValue:{data:{
    ...genesis.data,genesis_time:'1'}}})}),/not Ethereum mainnet/);
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources,request:responder({headerValue:{
    ...header,execution_optimistic:true}})}),/unsafe/);
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources,request:responder({headerValue:{
    ...header,data:{...header.data,canonical:false}}})}),/not canonical/);
});

test('rejects oversized Beacon decimals before numeric conversion',async()=>{
  const oversized={...finality,data:{...finality.data,finalized:{
    ...finality.data.finalized,epoch:'9'.repeat(100000),
  }}};
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources,
    request:responder({finalityBySource:new Map([['1',oversized]])})}),/canonical decimal/);
  const overflow={...finality,data:{...finality.data,finalized:{
    ...finality.data.finalized,epoch:(1n<<64n).toString(),
  }}};
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources,
    request:responder({finalityBySource:new Map([['1',overflow]])})}),/uint64/);
});

test('rejects source disagreement and checkpoints that move during observation',async()=>{
  const disagreement=new Map([['2',{...finality,data:{...finality.data,finalized:{epoch:'10',
    root:'0x'+'99'.repeat(32)}}}]]);
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources,request:responder({
    finalityBySource:disagreement})}),/(different header root|disagree)/);
  let calls=0;
  const moving=async url=>{
    if(url.includes('/beacon/genesis')) return genesis;
    if(url.includes('/beacon/headers/')) return header;
    if(url.includes('/light_client/bootstrap/')) return bootstrap;
    calls++;
    return calls>3?{...finality,data:{...finality.data,finalized:{epoch:'11',root}}}:finality;
  };
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources,request:moving}),
    /changed during observation/);
});

test('never emits source URLs or operator IDs',async()=>{
  const result=await collectEthereumCheckpointConsensus({sources,request:responder(),nowUnix:freshTime});
  const serialized=JSON.stringify(result);
  for(const source of sources) {
    assert.doesNotMatch(serialized,new RegExp(source.operatorId));
    assert.doesNotMatch(serialized,new RegExp(new URL(source.url).hostname));
  }
});

test('bounded HTTP reader rejects oversized and malformed responses',async()=>{
  const headers=new Headers({'content-type':'application/json'});
  await assert.rejects(()=>requestBeaconJson('https://beacon.example/test',{maxBytes:4,
    fetchImpl:async()=>new Response('12345',{status:200,headers})}),/size limit/);
  await assert.rejects(()=>requestBeaconJson('https://beacon.example/test',{
    fetchImpl:async()=>new Response('{',{status:200,headers})}),/Beacon API response/);
  await assert.rejects(()=>requestBeaconJson('https://beacon.example/test',{
    fetchImpl:async()=>new Response('{"ok":true,"\\u006fk":false}',{status:200,headers})}),
    /duplicate object key/);
  assert.equal((await requestBeaconJson('https://beacon.example/test',{
    fetchImpl:async()=>new Response('{"ok":true}',{status:200,headers})})).ok,true);
  await assert.rejects(()=>requestBeaconJson('http://beacon.example/test',{
    environment:{},fetchImpl:async()=>new Response('{"ok":true}',{status:200,headers})}),/HTTPS/);
  await assert.rejects(()=>requestBeaconJson('https://beacon.example/test',{
    environment:{HTTPS_PROXY:'https://proxy.example'},
    fetchImpl:async()=>new Response('{"ok":true}',{status:200,headers})}),/unsafe HTTPS/);
  await assert.rejects(()=>requestBeaconJson('https://beacon.example/secret-private',{
    environment:{},fetchImpl:async()=>{throw new Error('secret token=private');}}),error=>{
    assert.match(String(error?.message),/transport failed/);
    assert.doesNotMatch(String(error?.message),/secret|private/);
    return true;
  });
  for(const options of [{maxBytes:Infinity},{maxBytes:0},{timeoutMs:Infinity},{timeoutMs:0}]) {
    await assert.rejects(()=>requestBeaconJson('https://beacon.example/test',{
      ...options,environment:{},fetchImpl:async()=>new Response('{}')}),/transport bounds/);
  }
  await assert.rejects(()=>requestBeaconJson('https://127.0.0.1/test',{
    environment:{},fetchImpl:async()=>new Response('{}')}),/public DNS hostname/);
});

test('requires a Rust-compatible bootstrap bound to the exact checkpoint',async()=>{
  const badRoot=structuredClone(bootstrap);
  badRoot.data.header.beacon.body_root='0x'+'99'.repeat(32);
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources,request:responder({
    bootstrapValue:badRoot}),nowUnix:freshTime}),/does not bind/);
  const badBranch=structuredClone(bootstrap);
  badBranch.data.current_sync_committee_branch[0]='0x'+'99'.repeat(32);
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources,request:responder({
    bootstrapValue:badBranch}),nowUnix:freshTime}),/proof is invalid/);
  const unsupported={...bootstrap,version:'gloas'};
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources,request:responder({
    bootstrapValue:unsupported}),nowUnix:freshTime}),/unsupported by the Rust light client/);
});

test('rejects stale or future weak-subjectivity checkpoints',async()=>{
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources,request:responder(),
    nowUnix:BigInt('1606824023')+(boundarySlot+257n)*12n}),/freshness window/);
  await assert.rejects(()=>collectEthereumCheckpointConsensus({sources,request:responder(),
    nowUnix:BigInt('1606824023')+(boundarySlot-1n)*12n}),/freshness window/);
});
