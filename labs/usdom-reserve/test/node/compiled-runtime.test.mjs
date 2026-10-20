import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {
  deriveCheckpointRegistryInitcodeHash,
  deriveCheckpointRegistryRuntimeCodeHash,
  deriveReserveInitcodeHash,
  deriveReserveRuntimeCodeHash,
} from '../../sdk/compiled-runtime.mjs';

const address=n=>'0x'+n.toString(16).padStart(40,'0');
const hash=n=>'0x'+n.toString(16).padStart(64,'0');
const artifactUrl=new URL('../../out/USDOMProofReserve.sol/USDOMProofReserve.json',import.meta.url);
const registryArtifactUrl=new URL('../../out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json',import.meta.url);
const rootUrl=new URL('../../',import.meta.url);

function release() {
  return {token:address(1),tokenCodeHash:hash(2),verifier:address(3),verifierCodeHash:hash(4),
    verifierConfigHash:hash(5),reserveConfigHash:hash(6),domDomain:hash(7),
    activationScheduleCommitment:hash(18),governance:address(8),
    governanceCodeHash:hash(9),guardian:address(10),guardianCodeHash:hash(11),
    withdrawalDelaySeconds:'21600',governanceDelaySeconds:'172800',maxOutstandingBaseUnits:'100000000000',
    outflowCapacityBaseUnitsPerDay:'2000000000'};
}

async function loadBuild() {
  const artifact=JSON.parse(await readFile(artifactUrl,'utf8'));
  const sourceContents=Object.create(null);
  for(const source of Object.keys(artifact.metadata.sources)) sourceContents[source]=await readFile(new URL(source,rootUrl));
  return {artifact,sourceContents};
}

function registryRelease() {
  return {domDomain:hash(21),checkpointDomNetworkMagic:'2712847316',activationScheduleCommitment:hash(22),
    checkpointDomChainId:hash(40),checkpointFirstV4Height:'100001',checkpointActivationEmptyStateRoot:hash(29),
    checkpointIntervalBlocks:'360',checkpointConfirmationDepthBlocks:'30',
    checkpointChallengePeriodSeconds:'172800',
    checkpointVerifier:address(23),checkpointVerifierCodeHash:hash(24),checkpointVerifierConfigHash:hash(25),
    checkpointGuardian:address(26),checkpointGuardianCodeHash:hash(27),checkpointInitialHeight:'100000',
    checkpointInitialBlock:hash(28),checkpointInitialStateRoot:hash(29),checkpointInitialContextHash:hash(30),
    checkpointInitialTotalDifficulty:'1000000'};
}

async function loadRegistryBuild() {
  const artifact=JSON.parse(await readFile(registryArtifactUrl,'utf8'));
  const sourceContents=Object.create(null);
  for(const source of Object.keys(artifact.metadata.sources)) sourceContents[source]=await readFile(new URL(source,rootUrl));
  return {artifact,sourceContents};
}

test('source-verified immutable patching deterministically derives deployed reserve runtime',async()=>{
  const {artifact,sourceContents}=await loadBuild();
  const config=release();
  const derived=deriveReserveRuntimeCodeHash({artifact,releaseConfig:config,sourceContents});
  assert.equal(derived.runtimeCodeHash,'0xa3c8e3823a57d78a12f265902f5de1b175ddfc8a56e845195b2892eadf300888');
  assert.equal(derived.runtimeSize,14660);
  assert.equal(derived.sourceCount,Object.keys(artifact.metadata.sources).length);
  assert.match(derived.compilerVersion,/^0\.8\.37\+commit\./);
  const initcode=deriveReserveInitcodeHash({artifact,releaseConfig:config,sourceContents});
  assert.equal(initcode.initcodeHash,'0x2b73bf1ce995b7b026f609c7abe3e333df30bd0f9e7a32194ee1bf71dcd20c55');
  assert.equal(initcode.initcodeSize,18601);
  assert.equal(initcode.sourceCount,derived.sourceCount);

  const mutations={token:address(12),tokenCodeHash:hash(12),verifier:address(13),verifierCodeHash:hash(13),
    verifierConfigHash:hash(14),reserveConfigHash:hash(15),domDomain:hash(16),
    activationScheduleCommitment:hash(27),governance:address(17),
    governanceCodeHash:hash(18),guardian:address(19),guardianCodeHash:hash(20),withdrawalDelaySeconds:'21601',
    governanceDelaySeconds:'172801',maxOutstandingBaseUnits:'100000000001',
    outflowCapacityBaseUnitsPerDay:'2000000001'};
  for(const [field,value] of Object.entries(mutations)) {
    const changed=deriveReserveRuntimeCodeHash({artifact,releaseConfig:{...config,[field]:value},sourceContents});
    assert.notEqual(changed.runtimeCodeHash,derived.runtimeCodeHash,field);
    if (['token','verifier','domDomain','activationScheduleCommitment','governance','guardian','withdrawalDelaySeconds','governanceDelaySeconds',
      'maxOutstandingBaseUnits','outflowCapacityBaseUnitsPerDay'].includes(field)) {
      const changedInitcode=deriveReserveInitcodeHash({artifact,releaseConfig:{...config,[field]:value},sourceContents});
      assert.notEqual(changedInitcode.initcodeHash,initcode.initcodeHash,`initcode ${field}`);
    }
  }

  const staleSources={...sourceContents,'contracts/USDOMProofReserve.sol':new Uint8Array([1])};
  assert.throws(()=>deriveReserveRuntimeCodeHash({artifact,releaseConfig:config,sourceContents:staleSources}),/source hash mismatch/);
  const corrupt=structuredClone(artifact);
  Object.values(corrupt.deployedBytecode.immutableReferences)[0][0].length=31;
  assert.throws(()=>deriveReserveRuntimeCodeHash({artifact:corrupt,releaseConfig:config,sourceContents}),/location/);
  const linkedCreation=structuredClone(artifact);
  linkedCreation.bytecode.linkReferences={x:{Y:[{start:0,length:20}]}};
  assert.throws(()=>deriveReserveInitcodeHash({artifact:linkedCreation,releaseConfig:config,sourceContents}),/linked creation/);
  assert.throws(()=>deriveReserveInitcodeHash({artifact,releaseConfig:{...config,domDomain:'0x01'},sourceContents}),/bytes32/);
  assert.throws(()=>deriveReserveInitcodeHash({artifact,releaseConfig:{...config,token:'invalid'},sourceContents}),/address/i);
  assert.throws(()=>deriveReserveInitcodeHash({artifact,releaseConfig:{...config,withdrawalDelaySeconds:1n<<64n},sourceContents}),/range/);

  const settingsMutations=[
    a=>{a.metadata.compiler.version='0.8.36+commit.4a9f1e15';},
    a=>{a.metadata.settings.optimizer.enabled=false;},a=>{a.metadata.settings.optimizer.runs=201;},
    a=>{a.metadata.settings.evmVersion='shanghai';},a=>{a.metadata.settings.metadata.bytecodeHash='ipfs';},
    a=>{a.metadata.settings.viaIR=true;},a=>{a.metadata.settings.libraries={x:{Y:address(1)}};},
    a=>{a.metadata.settings.compilationTarget={'contracts/USDOMReserve.sol':'USDOMReserve'};},
    a=>{a.metadata.settings.remappings=a.metadata.settings.remappings.filter(x=>!x.startsWith('@openzeppelin/contracts/='));},
  ];
  for(const mutate of settingsMutations) {
    const changed=structuredClone(artifact); mutate(changed);
    assert.throws(()=>deriveReserveRuntimeCodeHash({artifact:changed,releaseConfig:config,sourceContents}),/unexpected|forbidden/);
  }
});

test('source-verified immutable patching derives checkpoint registry runtime and initcode',async()=>{
  const {artifact,sourceContents}=await loadRegistryBuild();
  const config=registryRelease();
  const runtime=deriveCheckpointRegistryRuntimeCodeHash({artifact,releaseConfig:config,sourceContents});
  const initcode=deriveCheckpointRegistryInitcodeHash({artifact,releaseConfig:config,sourceContents});
  assert.equal(runtime.runtimeCodeHash,'0x61cd4c489d20d8059ecfcba643f39974ca05463ac54fa8d91a755e95f0f871d6');
  assert.equal(runtime.runtimeSize,6059);
  assert.equal(initcode.initcodeHash,'0x3b730a4a66ce70ed5ff53dfeff3d2bdb63790179f7ca4c5e8f794cc8ad965e3b');
  assert.equal(initcode.initcodeSize,9435);
  assert.equal(runtime.sourceCount,Object.keys(artifact.metadata.sources).length);
  assert.equal(initcode.sourceCount,runtime.sourceCount);

  const immutableMutations={domDomain:hash(30),checkpointDomNetworkMagic:'2712847315',
    checkpointDomChainId:hash(41),checkpointFirstV4Height:'100002',checkpointActivationEmptyStateRoot:hash(42),
    checkpointIntervalBlocks:'359',checkpointConfirmationDepthBlocks:'29',
    checkpointChallengePeriodSeconds:'172801',
    activationScheduleCommitment:hash(31),checkpointVerifier:address(32),
    checkpointVerifierCodeHash:hash(33),checkpointVerifierConfigHash:hash(34),
    checkpointGuardian:address(35),checkpointGuardianCodeHash:hash(36)};
  for(const [field,value] of Object.entries(immutableMutations)) {
    assert.notEqual(deriveCheckpointRegistryRuntimeCodeHash({artifact,releaseConfig:{...config,[field]:value},sourceContents})
      .runtimeCodeHash,runtime.runtimeCodeHash,field);
  }
  const constructorMutations={domDomain:hash(30),checkpointDomNetworkMagic:'2712847315',
    checkpointDomChainId:hash(41),checkpointFirstV4Height:'100002',checkpointActivationEmptyStateRoot:hash(42),
    activationScheduleCommitment:hash(31),checkpointVerifier:address(32),checkpointGuardian:address(35),
    checkpointIntervalBlocks:'359',checkpointConfirmationDepthBlocks:'29',
    checkpointChallengePeriodSeconds:'172801',checkpointInitialHeight:'100001',
    checkpointInitialBlock:hash(37),checkpointInitialStateRoot:hash(38),checkpointInitialContextHash:hash(39),
    checkpointInitialTotalDifficulty:'1000001'};
  for(const [field,value] of Object.entries(constructorMutations)) {
    assert.notEqual(deriveCheckpointRegistryInitcodeHash({artifact,releaseConfig:{...config,[field]:value},sourceContents})
      .initcodeHash,initcode.initcodeHash,field);
  }
  assert.throws(()=>deriveCheckpointRegistryRuntimeCodeHash({artifact,releaseConfig:{...config,
    checkpointDomNetworkMagic:1n<<32n},sourceContents}),/range/);
  assert.throws(()=>deriveCheckpointRegistryInitcodeHash({artifact,releaseConfig:{...config,
    checkpointInitialHeight:1n<<64n},sourceContents}),/range/);
  const wrongTarget=structuredClone(artifact);
  wrongTarget.metadata.settings.compilationTarget={'contracts/USDOMProofReserve.sol':'USDOMProofReserve'};
  assert.throws(()=>deriveCheckpointRegistryRuntimeCodeHash({artifact:wrongTarget,releaseConfig:config,sourceContents}),
    /unexpected compilation target/);
});
