import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {getCreateAddress,keccak256} from 'ethers';
import {buildMainnetDeploymentPackage,validateMainnetDeploymentLedgerHandoff,
  validateMainnetDeploymentPackage} from '../../sdk/deployment-package.mjs';

const address=n=>'0x'+n.toString(16).padStart(40,'0');
const hash=n=>'0x'+n.toString(16).padStart(64,'0');

function fixture() {
  const make=(name,from,nonce,data)=>({from,nonce:String(nonce),data,
    expectedContract:getCreateAddress({from,nonce}),expectedInitcodeHash:keccak256(data),
    expectedRuntimeCodeHash:hash(name)});
  const deployer=address(100);
  const plans={
    finalizedBurnVerifier:make(1,deployer,7,'0x6001'),
    checkpointVerifier:make(2,deployer,8,'0x6002'),
    checkpointRegistry:make(3,deployer,9,'0x6003'),
    reserve:make(4,deployer,10,'0x6004'),
  };
  const approvedArtifacts=Object.fromEntries(Object.entries(plans).map(([name,plan])=>[name,{
    expectedContract:plan.expectedContract,expectedInitcodeHash:plan.expectedInitcodeHash,
    expectedRuntimeCodeHash:plan.expectedRuntimeCodeHash,
  }]));
  return {releaseConfigSha256:'ab'.repeat(32),observationDocumentSha256:'cd'.repeat(32),
   observationHash:hash(88),plans,approvedArtifacts};
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
    value=>{value.plans.checkpointVerifier.nonce='12';
      value.plans.checkpointVerifier.expectedContract=getCreateAddress({
        from:value.plans.checkpointVerifier.from,nonce:12,
      }); value.approvedArtifacts.checkpointVerifier.expectedContract=
        value.plans.checkpointVerifier.expectedContract;},
    value=>{value.plans.reserve.from=address(101);
      value.plans.reserve.expectedContract=getCreateAddress({from:address(101),nonce:10});
      value.approvedArtifacts.reserve.expectedContract=value.plans.reserve.expectedContract;},
    value=>{value.plans.extra={};},
    value=>{value.plans.reserve.data='0x';},
    value=>{value.plans.finalizedBurnVerifier.expectedInitcodeHash=hash(99);},
    value=>{value.plans.checkpointVerifier.expectedInitcodeHash=hash(98);},
    value=>{delete value.plans.reserve.expectedInitcodeHash;},
    value=>{[value.plans.finalizedBurnVerifier,value.plans.checkpointVerifier]=
      [value.plans.checkpointVerifier,value.plans.finalizedBurnVerifier];},
    value=>{value.approvedArtifacts.reserve.expectedRuntimeCodeHash=hash(99);},
    value=>{delete value.approvedArtifacts.checkpointRegistry;},
    value=>{value.releaseConfigSha256='0x01';},
    value=>{value.observationDocumentSha256='0x01';},
    value=>{delete value.observationHash;},
  ];
  for(const mutate of cases) {
    const value=fixture(); mutate(value);
    assert.throws(()=>buildMainnetDeploymentPackage(value));
  }
});

test('deployment package rejects a sequence above the audited aggregate gas budget',()=>{
  const value=fixture();
  for(const name of Object.keys(value.plans)) {
    const data=`0x${'ff'.repeat(40_000)}`;
    value.plans[name].data=data;
    value.plans[name].expectedInitcodeHash=keccak256(data);
    value.approvedArtifacts[name].expectedInitcodeHash=value.plans[name].expectedInitcodeHash;
  }
  assert.throws(()=>buildMainnetDeploymentPackage(value),/aggregate gas policy/);
});

test('durable deployment package validator closes top-level and transaction schemas',()=>{
  const valid=buildMainnetDeploymentPackage(fixture());
  assert.deepEqual(validateMainnetDeploymentPackage(valid),valid);
  const mutations=[
    value=>{value.extra=true;},
    value=>{delete value.releaseConfigSha256;},
    value=>{value.chainId=1;},
    value=>{value.schema='usdom-mainnet-deployment-package-v2';},
    value=>{value.transactions[0].extra=true;},
    value=>{delete value.transactions[0].initcodeHash;},
    value=>{value.transactions[0].name='reserve';},
    value=>{value.transactions[0].nonce='07';},
    value=>{value.transactions[0].data=value.transactions[0].data.toUpperCase();},
    value=>{[value.transactions[0],value.transactions[1]]=[value.transactions[1],value.transactions[0]];},
  ];
  for(const mutate of mutations) {
    const value=structuredClone(valid); mutate(value);
    assert.throws(()=>validateMainnetDeploymentPackage(value));
  }
});

test('Ledger handoff schema is exact and cross-linked to the reviewed package',()=>{
  const packageValue=buildMainnetDeploymentPackage(fixture());
  const packageBytes=Buffer.from(JSON.stringify(packageValue));
  const packageSha256=createHash('sha256').update(packageBytes).digest('hex');
  const handoff={schema:'usdom-mainnet-deployment-ledger-handoff-v1',chainId:'1',
    releaseConfigSha256:packageValue.releaseConfigSha256,packageSha256,
    rpcCatalogSha256:'12'.repeat(32),
    observationDocumentSha256:packageValue.observationDocumentSha256,
    observationHash:packageValue.observationHash,transaction:packageValue.transactions[2]};
  assert.equal(validateMainnetDeploymentLedgerHandoff({handoff,packageValue,packageBytes,index:2,
    packageSha256}),
    handoff);
  for(const mutate of [
    value=>{value.extra=true;},value=>{delete value.rpcCatalogSha256;},
    value=>{value.chainId=1;},value=>{value.packageSha256='00'.repeat(32);},
    value=>{value.observationHash=hash(99);},value=>{value.transaction={...value.transaction,extra:true};},
    value=>{value.transaction=packageValue.transactions[1];},
  ]) {
    const value=structuredClone(handoff); mutate(value);
    assert.throws(()=>validateMainnetDeploymentLedgerHandoff({
      handoff:value,packageValue,index:2,packageSha256,
      packageBytes,
    }));
  }
  const detached=structuredClone(packageValue);
  detached.transactions[2].nonce='99';
  assert.throws(()=>validateMainnetDeploymentLedgerHandoff({handoff,packageValue:detached,
    packageBytes,index:2,packageSha256}),/bytes differ from reviewed authority/);
});

test('deployment package rejects null integrity commitments',()=>{
  for(const field of ['releaseConfigSha256','observationDocumentSha256']) {
    const value=fixture(); value[field]='00'.repeat(32);
    assert.throws(()=>buildMainnetDeploymentPackage(value),/SHA-256|commitments/);
  }
  const value=fixture(); value.observationHash=`0x${'00'.repeat(32)}`;
  assert.throws(()=>buildMainnetDeploymentPackage(value),/commitments/);
});

test('deployment CLI fails closed before producing a package for the unconfigured release',()=>{
  const script=fileURLToPath(new URL('../../scripts/prepare-mainnet-deployment.mjs',import.meta.url));
  const result=spawnSync(process.execPath,[script],{encoding:'utf8'});
  assert.equal(result.status,1);
  assert.equal(result.stdout,'');
  assert.deepEqual(JSON.parse(result.stderr),{schema:'usdom-release-safe-diagnostic/v1',ok:false,
    operation:'prepare-mainnet-deployment',code:'RELEASE_OPERATION_REJECTED'});
});

test('deployment producer derives and reconciles all four source-built artifacts',async()=>{
  const source=await readFile(new URL('../../scripts/prepare-mainnet-deployment.mjs',import.meta.url),'utf8');
  for(const marker of [
    'deriveFinalizedBurnVerifierArtifactBinding','deriveCheckpointVerifierArtifactBinding',
    'deriveCheckpointRegistryArtifactBinding','deriveReserveArtifactBinding',
    "assertEqual(finalizedBinding.initcodeHash,releaseConfig.verifierInitcodeHash",
    "assertEqual(checkpointBinding.initcodeHash,releaseConfig.checkpointVerifierInitcodeHash",
    'validateImmutablePatchManifest(reserveBinding)',
    'approvedArtifacts:{',
  ]) assert.ok(source.includes(marker),marker);
});
