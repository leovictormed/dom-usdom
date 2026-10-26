import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {
  deriveCheckpointRegistryArtifactBinding,
  deriveCheckpointRegistryInitcodeHash,
  deriveCheckpointRegistryRuntimeCodeHash,
  deriveReserveArtifactBinding,
  deriveReserveInitcodeHash,
  deriveReserveRuntimeCodeHash,
} from '../../sdk/compiled-runtime.mjs';
import {checkpointRegistryConfigHash} from '../../sdk/checkpoint-registry.mjs';
import {proofReserveDeploymentConfigHash,safeOwnersCommitment} from '../../sdk/configuration.mjs';

const address=n=>'0x'+n.toString(16).padStart(40,'0');
const hash=n=>'0x'+n.toString(16).padStart(64,'0');
const artifactUrl=new URL('../../out/USDOMProofReserve.sol/USDOMProofReserve.json',import.meta.url);
const registryArtifactUrl=new URL('../../out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json',import.meta.url);
const rootUrl=new URL('../../',import.meta.url);

function release() {
  return {token:address(1),tokenCodeHash:hash(2),verifier:address(3),verifierCodeHash:hash(4),
    verifierConfigHash:hash(5),reserveConfigHash:hash(6),domDomain:hash(7),
    checkpointRegistry:address(41),checkpointRegistryRuntimeCodeHash:hash(42),
    checkpointRegistryConfigHash:hash(43),
    activationScheduleCommitment:hash(18),governance:address(8),
    governanceCodeHash:hash(9),governanceImplementation:address(28),governanceImplementationCodeHash:hash(29),
    governanceOwnersCommitment:hash(32),
    guardian:address(10),guardianCodeHash:hash(11),guardianImplementation:address(30),
    guardianImplementationCodeHash:hash(31),
    guardianOwnersCommitment:hash(33),
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
  const value={ethereumChainId:'1',checkpointRegistry:address(41),
    domDomain:hash(21),checkpointDomNetworkMagic:'2712847316',activationScheduleCommitment:hash(22),
    checkpointDomChainId:hash(40),checkpointFirstV4Height:'100001',checkpointActivationEmptyStateRoot:hash(29),
    checkpointIntervalBlocks:'360',checkpointConfirmationDepthBlocks:'30',
    checkpointChallengePeriodSeconds:'172800',
    checkpointVerifier:address(23),checkpointVerifierCodeHash:hash(24),checkpointVerifierConfigHash:hash(25),
    checkpointGuardian:address(26),checkpointGuardianCodeHash:hash(27),
    checkpointGuardianImplementation:address(32),checkpointGuardianImplementationCodeHash:hash(33),
    checkpointGuardianOwners:[address(51),address(52),address(53)],
    checkpointInitialHeight:'100000',
    checkpointInitialBlock:hash(28),checkpointInitialStateRoot:hash(29),checkpointInitialContextHash:hash(30),
    checkpointInitialTotalDifficulty:'1000000'};
  value.checkpointRegistryConfigHash=checkpointRegistryConfigHash({
    ethereumChainId:value.ethereumChainId,registry:value.checkpointRegistry,bridgeDomain:value.domDomain,
    domNetworkMagic:value.checkpointDomNetworkMagic,domChainId:value.checkpointDomChainId,
    firstV4Height:value.checkpointFirstV4Height,
    activationEmptyStateRoot:value.checkpointActivationEmptyStateRoot,
    activationScheduleCommitment:value.activationScheduleCommitment,
    checkpointInterval:value.checkpointIntervalBlocks,
    confirmationDepth:value.checkpointConfirmationDepthBlocks,
    challengePeriod:value.checkpointChallengePeriodSeconds,verifier:value.checkpointVerifier,
    verifierCodeHash:value.checkpointVerifierCodeHash,verifierConfigHash:value.checkpointVerifierConfigHash,
    guardian:value.checkpointGuardian,guardianCodeHash:value.checkpointGuardianCodeHash,
    guardianImplementation:value.checkpointGuardianImplementation,
    guardianImplementationCodeHash:value.checkpointGuardianImplementationCodeHash,
    guardianOwnersCommitment:safeOwnersCommitment(value.checkpointGuardianOwners),
    initialHeight:value.checkpointInitialHeight,initialBlock:value.checkpointInitialBlock,
    initialStateRoot:value.checkpointInitialStateRoot,initialContextHash:value.checkpointInitialContextHash,
    initialTotalDifficulty:value.checkpointInitialTotalDifficulty,
  }).checkpointConfigHash;
  return value;
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
  assert.ok(artifact.abi.some(item=>item.type==='function'&&item.name==='pendingQueueSnapshot'));
  assert.ok(artifact.abi.some(item=>item.type==='function'&&item.name==='pendingBurnPage'));
  for(const name of ['totalProvedDebtAmount','depositsClosed','gracefullyShutdown']) {
    assert.ok(artifact.abi.some(item=>item.type==='function'&&item.name===name),name);
  }
  assert.equal(derived.runtimeCodeHash,'0x4caa392f8579cf64d68802609a9e54e094e4a493e409543ecfc84edbd7263202');
  assert.notEqual(derived.runtimeCodeHash,'0x1d2a2b4b2e8cfffc96dee68d2cdf9d4f822f36f8a50707f3b7f2c8b005682498');
  assert.equal(derived.runtimeSize,20100);
  assert.equal(derived.immutableReferenceCount,68);
  assert.equal(derived.immutablePatchManifest.length,23);
  assert.equal(derived.immutablePatchManifestHash,
    '0x98b3d7d62f0e1e1e07e1da2834d400900fa4a8eba5584f090018478d8292c425');
  const derivedBytes=Buffer.from(derived.runtimeBytecode.slice(2),'hex');
  for(const entry of derived.immutablePatchManifest) {
    assert.match(entry.encoded,/^0x[0-9a-f]{64}$/);
    if(entry.type==='address') assert.equal(entry.encoded.slice(2,26),'0'.repeat(24),entry.name);
    if(entry.type==='uint64') assert.equal(entry.encoded.slice(2,50),'0'.repeat(48),entry.name);
    for(const offset of entry.locations) {
      assert.equal(`0x${derivedBytes.subarray(offset,offset+32).toString('hex')}`,entry.encoded,
        `${entry.name} at ${offset}`);
    }
  }
  assert.equal(derived.sourceCount,Object.keys(artifact.metadata.sources).length);
  assert.match(derived.compilerVersion,/^0\.8\.37\+commit\./);
  const initcode=deriveReserveInitcodeHash({artifact,releaseConfig:config,sourceContents});
  assert.equal(initcode.initcodeHash,'0xa9d466335ea9eda3010202cf52125b7fb96e6494e8b8e5db5fcd0ecd35309784');
  assert.notEqual(initcode.initcodeHash,'0xe4719f8fd72f041494b0ce88f4f51321e4d882b248e3ff02a3cefe88162b9fe0');
  assert.equal(initcode.initcodeSize,26498);
  assert.equal(initcode.sourceCount,derived.sourceCount);
  const creationBytes=Buffer.from(artifact.bytecode.object.slice(2),'hex');
  const constructorBytes=Buffer.from(initcode.initcode.slice(2+creationBytes.length*2),'hex');
  assert.equal(constructorBytes.length,11*32);
  const word=index=>constructorBytes.subarray(index*32,(index+1)*32).toString('hex');
  const addressWord=value=>'0'.repeat(24)+value.slice(2).toLowerCase();
  const uintWord=value=>BigInt(value).toString(16).padStart(64,'0');
  assert.deepEqual([word(0),word(1),word(2),word(3),word(4),word(5),word(6),
    word(7),word(8),word(9),word(10)],[
    addressWord(config.token),addressWord(config.verifier),addressWord(config.checkpointRegistry),
    config.domDomain.slice(2),config.activationScheduleCommitment.slice(2),
    addressWord(config.governance),addressWord(config.guardian),uintWord(config.withdrawalDelaySeconds),
    uintWord(config.governanceDelaySeconds),uintWord(config.maxOutstandingBaseUnits),
    uintWord(config.outflowCapacityBaseUnitsPerDay),
  ]);

  const mutations={token:address(12),tokenCodeHash:hash(12),verifier:address(13),verifierCodeHash:hash(13),
    verifierConfigHash:hash(14),checkpointRegistry:address(14),
    checkpointRegistryRuntimeCodeHash:hash(44),checkpointRegistryConfigHash:hash(45),
    reserveConfigHash:hash(15),domDomain:hash(16),
    activationScheduleCommitment:hash(27),governance:address(17),
    governanceCodeHash:hash(18),governanceImplementation:address(37),governanceImplementationCodeHash:hash(38),
    governanceOwnersCommitment:hash(41),
    guardian:address(19),guardianCodeHash:hash(20),guardianImplementation:address(39),
    guardianImplementationCodeHash:hash(40),withdrawalDelaySeconds:'21601',
    guardianOwnersCommitment:hash(42),
    governanceDelaySeconds:'172801',maxOutstandingBaseUnits:'100000000001',
    outflowCapacityBaseUnitsPerDay:'2000000001'};
  for(const [field,value] of Object.entries(mutations)) {
    const changed=deriveReserveRuntimeCodeHash({artifact,releaseConfig:{...config,[field]:value},sourceContents});
    if (['reserveConfigHash','activationScheduleCommitment'].includes(field)) {
      assert.equal(changed.runtimeCodeHash,derived.runtimeCodeHash,`${field} is constructor state`);
    } else assert.notEqual(changed.runtimeCodeHash,derived.runtimeCodeHash,field);
    if (['token','verifier','checkpointRegistry','domDomain','activationScheduleCommitment','governance','guardian','withdrawalDelaySeconds','governanceDelaySeconds',
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
  const overlap=structuredClone(artifact);
  const overlapLists=Object.values(overlap.deployedBytecode.immutableReferences);
  overlapLists[1][0].start=overlapLists[0][0].start;
  assert.throws(()=>deriveReserveRuntimeCodeHash({artifact:overlap,releaseConfig:config,sourceContents}),
    /overlapping immutable locations/);
  const occupiedPlaceholder=structuredClone(artifact);
  const firstLocation=Object.values(occupiedPlaceholder.deployedBytecode.immutableReferences)[0][0];
  const occupiedBytes=Buffer.from(occupiedPlaceholder.deployedBytecode.object.slice(2),'hex');
  occupiedBytes[firstLocation.start]=1;
  occupiedPlaceholder.deployedBytecode.object=`0x${occupiedBytes.toString('hex')}`;
  assert.throws(()=>deriveReserveRuntimeCodeHash({artifact:occupiedPlaceholder,
    releaseConfig:config,sourceContents}),/placeholder is not zero-filled/);
  const linkedCreation=structuredClone(artifact);
  linkedCreation.bytecode.linkReferences={x:{Y:[{start:0,length:20}]}};
  assert.throws(()=>deriveReserveInitcodeHash({artifact:linkedCreation,releaseConfig:config,sourceContents}),/linked creation/);
  assert.throws(()=>deriveReserveInitcodeHash({artifact,releaseConfig:{...config,domDomain:'0x01'},sourceContents}),/bytes32/);
  assert.throws(()=>deriveReserveInitcodeHash({artifact,releaseConfig:{...config,token:'invalid'},sourceContents}),/address/i);
  assert.throws(()=>deriveReserveInitcodeHash({artifact,releaseConfig:{...config,withdrawalDelaySeconds:1n<<64n},sourceContents}),/range/);
  const constructorDrift=structuredClone(artifact);
  const constructor=constructorDrift.abi.find(item=>item.type==='constructor');
  [constructor.inputs[0].components[0],constructor.inputs[0].components[1]]=
    [constructor.inputs[0].components[1],constructor.inputs[0].components[0]];
  assert.throws(()=>deriveReserveInitcodeHash({artifact:constructorDrift,releaseConfig:config,sourceContents}),
    /constructor tuple order or type drifted/);

  const settingsMutations=[
    a=>{a.metadata.compiler.version='0.8.36+commit.4a9f1e15';},
    a=>{a.metadata.settings.optimizer.enabled=false;},a=>{a.metadata.settings.optimizer.runs=201;},
    a=>{a.metadata.settings.evmVersion='shanghai';},a=>{a.metadata.settings.metadata.bytecodeHash='ipfs';},
    a=>{a.metadata.settings.viaIR=false;},a=>{a.metadata.settings.libraries={x:{Y:address(1)}};},
    a=>{a.metadata.settings.compilationTarget={'contracts/USDOMReserve.sol':'USDOMReserve'};},
    a=>{a.metadata.settings.remappings=a.metadata.settings.remappings.filter(x=>!x.startsWith('@openzeppelin/contracts/='));},
  ];
  for(const mutate of settingsMutations) {
    const changed=structuredClone(artifact); mutate(changed);
    assert.throws(()=>deriveReserveRuntimeCodeHash({artifact:changed,releaseConfig:config,sourceContents}),/unexpected|forbidden/);
  }
});

test('reserve artifact binding fails closed on stale owner-bound configuration',async()=>{
  const {artifact,sourceContents}=await loadBuild();
  const base={...release(),ethereumChainId:'1',reserve:address(50)};
  const fields={...base}; delete fields.reserveConfigHash;
  base.reserveConfigHash=proofReserveDeploymentConfigHash(fields).reserveConfigHash;
  const binding=deriveReserveArtifactBinding({artifact,releaseConfig:base,sourceContents});
  assert.equal(binding.reserveConfigHash,base.reserveConfigHash);
  assert.match(binding.runtimeCodeHash,/^0x[0-9a-f]{64}$/);
  assert.match(binding.initcodeHash,/^0x[0-9a-f]{64}$/);
  assert.throws(()=>deriveReserveArtifactBinding({artifact,
    releaseConfig:{...base,governanceOwnersCommitment:hash(60)},sourceContents}),/reserveConfigHash/);
  assert.throws(()=>deriveReserveArtifactBinding({artifact,
    releaseConfig:{...base,guardianOwnersCommitment:undefined},sourceContents}),/nonzero bytes32/);
});

test('source-verified immutable patching derives checkpoint registry runtime and initcode',async()=>{
  const {artifact,sourceContents}=await loadRegistryBuild();
  const config=registryRelease();
  const runtime=deriveCheckpointRegistryRuntimeCodeHash({artifact,releaseConfig:config,sourceContents});
  const initcode=deriveCheckpointRegistryInitcodeHash({artifact,releaseConfig:config,sourceContents});
  assert.equal(runtime.runtimeCodeHash,'0x0df35fbfe5d5742ff906a993e68c69d09ba2c1943878c52ae9cb43b61a1dac65');
  assert.equal(runtime.runtimeSize,10163);
  assert.equal(initcode.initcodeHash,'0x5b6088c2f0aeb727f77fe3fd9cd8022749837675231014269ebbd0d5e1550fd7');
  assert.equal(initcode.initcodeSize,15058);
  assert.equal(runtime.sourceCount,Object.keys(artifact.metadata.sources).length);
  assert.equal(initcode.sourceCount,runtime.sourceCount);
  const binding=deriveCheckpointRegistryArtifactBinding({artifact,releaseConfig:config,sourceContents});
  assert.equal(binding.runtimeCodeHash,runtime.runtimeCodeHash);
  assert.equal(binding.initcodeHash,initcode.initcodeHash);
  assert.equal(binding.checkpointRegistryConfigHash,config.checkpointRegistryConfigHash);
  const reordered={...config,checkpointGuardianOwners:[...config.checkpointGuardianOwners].reverse()};
  assert.equal(deriveCheckpointRegistryRuntimeCodeHash({artifact,releaseConfig:reordered,
    sourceContents}).runtimeCodeHash,runtime.runtimeCodeHash);
  assert.equal(deriveCheckpointRegistryInitcodeHash({artifact,releaseConfig:reordered,
    sourceContents}).initcodeHash,initcode.initcodeHash);

  const immutableMutations={domDomain:hash(30),checkpointDomNetworkMagic:'2712847315',
    checkpointDomChainId:hash(41),checkpointFirstV4Height:'100002',checkpointActivationEmptyStateRoot:hash(42),
    checkpointIntervalBlocks:'359',checkpointConfirmationDepthBlocks:'29',
    checkpointChallengePeriodSeconds:'172801',
    activationScheduleCommitment:hash(31),checkpointVerifier:address(32),
    checkpointVerifierCodeHash:hash(33),checkpointVerifierConfigHash:hash(34),
    checkpointGuardian:address(35),checkpointGuardianCodeHash:hash(36),
    checkpointGuardianImplementation:address(37),checkpointGuardianImplementationCodeHash:hash(38)};
  for(const [field,value] of Object.entries(immutableMutations)) {
    const changed=deriveCheckpointRegistryRuntimeCodeHash({artifact,releaseConfig:{...config,[field]:value},sourceContents})
      .runtimeCodeHash;
    if(['activationScheduleCommitment','checkpointActivationEmptyStateRoot'].includes(field)) {
      assert.equal(changed,runtime.runtimeCodeHash,`${field} is constructor state`);
    } else assert.notEqual(changed,runtime.runtimeCodeHash,field);
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
  assert.throws(()=>deriveCheckpointRegistryArtifactBinding({artifact,releaseConfig:{...config,
    checkpointRegistryConfigHash:hash(63)},sourceContents}),/configuration hash differs/);
  const staleSources={...sourceContents,'contracts/DOMCheckpointRegistry.sol':new Uint8Array([1])};
  assert.throws(()=>deriveCheckpointRegistryArtifactBinding({artifact,releaseConfig:config,
    sourceContents:staleSources}),/source hash mismatch/);
});
