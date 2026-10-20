import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {getCreateAddress,keccak256} from 'ethers';
import {buildMainnetDeploymentPackage} from '../../sdk/deployment-package.mjs';

const address=n=>'0x'+n.toString(16).padStart(40,'0');
const hash=n=>'0x'+n.toString(16).padStart(64,'0');

function fixture() {
  const make=(name,from,nonce,data)=>({from,nonce:String(nonce),data,
    expectedContract:getCreateAddress({from,nonce}),expectedInitcodeHash:keccak256(data),
    expectedRuntimeCodeHash:hash(name)});
  const deployer=address(100);
  return {releaseConfigSha256:'ab'.repeat(32),plans:{
    finalizedBurnVerifier:make(1,deployer,7,'0x6001'),
    checkpointVerifier:make(2,deployer,8,'0x6002'),
    checkpointRegistry:make(3,deployer,9,'0x6003'),
    reserve:make(4,deployer,10,'0x6004'),
  }};
}

test('deployment package is deterministic, unsigned and dependency ordered',()=>{
  const input=fixture();
  const first=buildMainnetDeploymentPackage(input);
  const second=buildMainnetDeploymentPackage(structuredClone(input));
  assert.deepEqual(second,first);
  assert.equal(first.schema,'usdom-mainnet-deployment-package-v1');
  assert.equal(first.chainId,'1');
  assert.deepEqual(first.transactions.map(tx=>tx.name),[
    'finalizedBurnVerifier','checkpointVerifier','checkpointRegistry','reserve',
  ]);
  for(const tx of first.transactions) {
    assert.equal(tx.to,null);
    assert.equal(tx.value,'0');
    assert(!('privateKey' in tx));
    assert(!('signature' in tx));
    assert.equal(tx.initcodeHash,input.plans[tx.name].expectedInitcodeHash.toLowerCase());
  }
});

test('deployment package rejects address, nonce, dependency and schema substitution',()=>{
  const cases=[
    value=>{value.plans.reserve.expectedContract=address(99);},
    value=>{value.plans.reserve.nonce=value.plans.checkpointRegistry.nonce;
      value.plans.reserve.expectedContract=value.plans.checkpointRegistry.expectedContract;},
    value=>{value.plans.finalizedBurnVerifier.nonce='11';
      value.plans.finalizedBurnVerifier.expectedContract=getCreateAddress({
        from:value.plans.finalizedBurnVerifier.from,nonce:11,
      });},
    value=>{value.plans.extra={};},
    value=>{value.plans.reserve.data='0x';},
    value=>{value.plans.finalizedBurnVerifier.expectedInitcodeHash=hash(99);},
    value=>{value.plans.checkpointVerifier.expectedInitcodeHash=hash(98);},
    value=>{delete value.plans.reserve.expectedInitcodeHash;},
    value=>{value.releaseConfigSha256='0x01';},
  ];
  for(const mutate of cases) {
    const value=fixture(); mutate(value);
    assert.throws(()=>buildMainnetDeploymentPackage(value));
  }
});

test('deployment CLI fails closed before producing a package for the unconfigured release',()=>{
  const script=fileURLToPath(new URL('../../scripts/prepare-mainnet-deployment.mjs',import.meta.url));
  const result=spawnSync(process.execPath,[script],{encoding:'utf8'});
  assert.equal(result.status,1);
  assert.equal(result.stdout,'');
  assert.match(result.stderr,/not production-ready/);
});
