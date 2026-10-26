import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {Wallet,getCreateAddress,keccak256,toUtf8Bytes} from 'ethers';
import {deriveMainnetDeploymentIdentity,observeMainnetDeploymentIdentity as observeIdentity,
  validateMainnetDeploymentIdentityObservation}
  from '../../sdk/mainnet-deployment-identity.mjs';

const template=JSON.parse(readFileSync(fileURLToPath(new URL(
  '../../config/proof-reserve.unconfigured.json',import.meta.url)),'utf8'));
const deployer=new Wallet('0x0123456789012345678901234567890123456789012345678901234567890123').address;
const genesis='0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3';
const observeMainnetDeploymentIdentity=input=>observeIdentity({...input,
  sourceOriginCommitments:input.sourceOriginCommitments??input.providers.map((_,index)=>
    `0x${(index+1).toString(16).padStart(64,'0')}`),
});

class Provider {
  constructor({chainId=1n,block=20_000_000,nonce=7,pending=nonce,deployerCode='0x',occupied=[],
    occupiedNonce=[]}={}) {
    Object.assign(this,{chainId,block,nonce,pending,deployerCode,occupied:new Set(occupied),
      occupiedNonce:new Set(occupiedNonce)});
  }
  async getNetwork() { return {chainId:this.chainId}; }
  async getBlock(tag) { return tag===0?{number:0,hash:genesis}:
    {number:this.block,hash:`0x${this.block.toString(16).padStart(64,'0')}`}; }
  pinFinalizedSnapshot(number,hash,{allowPendingNonce}={}) {
    assert.equal(number,this.block);
    assert.equal(hash,`0x${this.block.toString(16).padStart(64,'0')}`);
    assert.equal(allowPendingNonce,true);
  }
  async getTransactionCount(address,tag) {
    if(address.toLowerCase()===deployer.toLowerCase()) return tag==='pending'?this.pending:this.nonce;
    return this.occupiedNonce.has(address.toLowerCase())?1:0;
  }
  async getCode(address) {
    if(address.toLowerCase()===deployer.toLowerCase()) return this.deployerCode;
    return this.occupied.has(address.toLowerCase())?'0x6000':'0x';
  }
}

test('deployment identity derives four consecutive CREATE addresses from one Ledger EOA',()=>{
  const result=deriveMainnetDeploymentIdentity({releaseConfig:template,deployer,baseNonce:'7'});
  assert.deepEqual(result.plans.map(plan=>plan.nonce),['7','8','9','10']);
  for(let index=0;index<4;index++) {
    assert.equal(result.plans[index].expectedContract,
      getCreateAddress({from:deployer,nonce:7+index}));
  }
  assert.equal(result.configuration.verifierDeployer,deployer);
  assert.equal(result.configuration.deployerNonce,'10');
  assert.equal(result.configuration.productionReady,false);
  assert.equal(result.configuration.realFundsAuthorized,false);
  assert.deepEqual(deriveMainnetDeploymentIdentity({
    releaseConfig:result.configuration,deployer,baseNonce:'7',
  }).configuration,result.configuration);
});

test('dual-RPC identity observation rejects nonce, chain, EOA and address hazards',async()=>{
  const valid=await observeMainnetDeploymentIdentity({releaseConfig:template,deployer,
    providers:[new Provider(),new Provider()]});
  assert.equal(valid.observation.baseNonce,'7');
  assert.equal(valid.observation.rpcObservations.length,2);
  assert.equal(valid.observation.plans.length,4);
  for(const providers of [
    [new Provider(),new Provider({nonce:8})],
    [new Provider(),new Provider({block:20_000_001})],
    [new Provider({pending:8}),new Provider()],
    [new Provider({chainId:31337n}),new Provider()],
    [Object.assign(new Provider(),{getBlock:async tag=>tag===0?{number:0,hash:'0x'+'11'.repeat(32)}:
      ({number:20_000_000,hash:`0x${(20_000_000).toString(16).padStart(64,'0')}`})}),new Provider()],
    [new Provider({deployerCode:'0x6000'}),new Provider()],
    [new Provider({occupied:[getCreateAddress({from:deployer,nonce:7}).toLowerCase()]}),new Provider()],
    [new Provider({occupied:[getCreateAddress({from:deployer,nonce:10}).toLowerCase()]}),new Provider()],
    [new Provider({occupiedNonce:[getCreateAddress({from:deployer,nonce:7}).toLowerCase()]}),new Provider()],
    [new Provider({occupiedNonce:[getCreateAddress({from:deployer,nonce:10}).toLowerCase()]}),new Provider()],
  ]) await assert.rejects(observeMainnetDeploymentIdentity({releaseConfig:template,deployer,providers}));
});

test('deployment identity refuses authorization, collisions, drift and nonce overflow',()=>{
  for(const releaseConfig of [
    {...template,productionReady:true},
    {...template,realFundsAuthorized:true},
    {...template,deploymentMethod:'CREATE2'},
    {...template,verifierDeployer:new Wallet('0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd').address},
    {...template,governance:getCreateAddress({from:deployer,nonce:7})},
  ]) assert.throws(()=>deriveMainnetDeploymentIdentity({releaseConfig,deployer,baseNonce:'7'}));
  assert.throws(()=>deriveMainnetDeploymentIdentity({
    releaseConfig:template,deployer,baseNonce:(2n**64n-3n).toString(),
  }));
  assert.deepEqual(deriveMainnetDeploymentIdentity({releaseConfig:template,deployer,
    baseNonce:(2n**64n-4n).toString()}).plans.map(value=>value.nonce),[
    (2n**64n-4n).toString(),(2n**64n-3n).toString(),
    (2n**64n-2n).toString(),(2n**64n-1n).toString(),
  ]);
});

test('deployment identity never propagates provider errors that may contain RPC secrets',async()=>{
  const secret='https://rpc.example.invalid/v2/SECRET_API_KEY';
  const failing={getNetwork:async()=>{throw new Error(`request failed for ${secret}`);}};
  await assert.rejects(observeMainnetDeploymentIdentity({
    releaseConfig:template,deployer,providers:[failing,new Provider()],
  }),error=>error.message==='RPC 1 deployment-identity observation failed'
      &&!error.message.includes('SECRET_API_KEY'));
});

test('deployment identity rechecks the finalized snapshot and supports catalog source identities',async()=>{
 const changed=new Provider();
 let reads=0;
 changed.getBlock=async tag=>{
  reads++;
  if(tag===0) return {number:0,hash:genesis};
  return {number:changed.block,hash:`0x${(changed.block+(tag==='finalized'?0:1)).toString(16).padStart(64,'0')}`};
 };
 await assert.rejects(observeMainnetDeploymentIdentity({releaseConfig:template,deployer,
  providers:[changed,new Provider()],sourceIds:['operator-a','operator-b']}),/snapshot changed/);
 const valid=await observeMainnetDeploymentIdentity({releaseConfig:template,deployer,
  providers:[new Provider(),new Provider(),new Provider()],
  sourceIds:['operator-a','operator-b','operator-c']});
 assert.deepEqual(valid.observation.rpcObservations.map(value=>value.source),
  ['operator-a','operator-b','operator-c']);
 assert.deepEqual(valid.observation.rpcObservations.map(value=>value.originKeccak256),[
  `0x${'0'.repeat(63)}1`,`0x${'0'.repeat(63)}2`,`0x${'0'.repeat(63)}3`,
 ]);
 assert.equal(validateMainnetDeploymentIdentityObservation({observation:valid.observation,
  releaseConfigAfter:valid.configuration}),valid.observation);
 assert.equal(validateMainnetDeploymentIdentityObservation({observation:valid.observation,
  releaseConfigAfter:{...valid.configuration,productionReady:true,realFundsAuthorized:true}}),
 valid.observation);
 for(const mutate of [
  value=>{value.rpcConsensus.sources.pop();},
  value=>{value.rpcObservations[0].originKeccak256='0x'+'09'.repeat(32);},
  value=>{value.plans[0].nonce='8';},
  value=>{value.releaseConfigBefore.token=value.releaseConfigBefore.governance;},
 ]) {
  const changed=structuredClone(valid.observation); mutate(changed);
  await assert.rejects(async()=>validateMainnetDeploymentIdentityObservation({observation:changed,
    releaseConfigAfter:valid.configuration}));
 }
 const rehash=value=>{
  const body={...value}; delete body.observationHash;
  value.observationHash=keccak256(toUtf8Bytes(JSON.stringify(body)));
 };
 for(const mutate of [
  value=>{value.rpcObservations[0].extra=true;},
  value=>{delete value.rpcObservations[0].finalizedBlockHash;},
  value=>{value.rpcObservations[0].genesisBlockHash='0x'+'12'.repeat(32);},
  value=>{value.rpcObservations[0].finalizedBlockNumber='01';},
  value=>{value.rpcObservations[0].finalizedBlockNumber=(2n**64n).toString();},
  value=>{value.rpcObservations[0].pendingNonce=7;},
  value=>{value.rpcObservations[1].finalizedBlockHash='0x'+'12'.repeat(32);},
  value=>{value.rpcObservations[1].source=value.rpcObservations[0].source;},
  value=>{value.rpcObservations[1].originKeccak256=value.rpcObservations[0].originKeccak256;},
 ]) {
  const changed=structuredClone(valid.observation); mutate(changed); rehash(changed);
  assert.throws(()=>validateMainnetDeploymentIdentityObservation({observation:changed}));
 }
 await assert.rejects(observeIdentity({releaseConfig:template,deployer,
  providers:[new Provider(),new Provider()],sourceIds:['operator-a','operator-b'],
  sourceOriginCommitments:['0x'+'01'.repeat(32),'0x'+'01'.repeat(32)]}),/commitments/);
});

test('deployment identity materializer uses bounded catalog sources and redacts their URLs',()=>{
 const source=readFileSync(fileURLToPath(new URL(
  '../../scripts/prepare-mainnet-deployment-identity-materialization.mjs',import.meta.url)),'utf8');
 assert.match(source,/BoundedMainnetPreflightProvider/);
 assert.match(source,/matchMainnetPreflightRpcSources/);
 assert.match(source,/currentCatalogBytes\.equals\(catalogBytes\)/);
 assert.match(source,/writeReleaseFailure\('prepare-mainnet-deployment-identity-materialization'/);
 assert.doesNotMatch(source,/JsonRpcProvider|ETHEREUM_RPC_URL/);
});

test('deployment package binds and rereads the exact identity observation bytes',()=>{
 const source=readFileSync(fileURLToPath(new URL(
  '../../scripts/prepare-mainnet-deployment.mjs',import.meta.url)),'utf8');
 for(const marker of ['USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION',
  'USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION_SHA256',
  'validateMainnetDeploymentIdentityObservation','observationDocumentSha256:observationSha',
  'currentObservation.equals(observationBytes)']) assert.ok(source.includes(marker),marker);
 assert.match(source,/path\.isAbsolute\(observationPath\)/);
});
