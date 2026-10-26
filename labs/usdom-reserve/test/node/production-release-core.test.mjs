import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {materializeProductionReleaseCore,NATIVE_RELEASE_FACTS_SCHEMA} from '../../sdk/production-release-core.mjs';
import {safeOwnersCommitment} from '../../sdk/configuration.mjs';

const address=n=>'0x'+n.toString(16).padStart(40,'0');
const hash=n=>'0x'+n.toString(16).padStart(64,'0');
const release=()=>{const governanceOwners=[address(40),address(41),address(42)];
 const guardianOwners=[address(43),address(44),address(45)];
 const checkpointGuardianOwners=[address(46),address(47),address(48)];
 return {productionReady:false,ethereumChainId:'1',token:address(1),tokenCodeHash:hash(2),
  reserve:address(3),verifier:address(4),verifierCodeHash:null,verifierInitcodeHash:null,
  verifierConfigHash:null,reserveConfigHash:null,reserveRuntimeCodeHash:null,reserveInitcodeHash:null,
  domDomain:null,activationScheduleCommitment:null,checkpointRegistry:address(5),
  checkpointRegistryConfigHash:null,checkpointVerifier:address(6),checkpointVerifierCodeHash:null,
  checkpointRegistryRuntimeCodeHash:null,checkpointRegistryInitcodeHash:null,
  checkpointVerifierInitcodeHash:null,
  checkpointVerifierConfigHash:null,checkpointGuardian:address(7),checkpointGuardianCodeHash:hash(8),
  checkpointGuardianImplementation:address(9),checkpointGuardianImplementationCodeHash:hash(10),
  checkpointDomNetworkMagic:null,checkpointDomChainId:null,checkpointFirstV4Height:null,
  checkpointActivationEmptyStateRoot:null,checkpointIntervalBlocks:null,
  checkpointConfirmationDepthBlocks:null,checkpointChallengePeriodSeconds:null,
  checkpointInitialHeight:null,checkpointInitialBlock:null,checkpointInitialStateRoot:null,
  checkpointInitialContextHash:null,checkpointInitialTotalDifficulty:null,nativeEthereumTrustedCheckpoint:null,
  governance:address(11),governanceCodeHash:hash(12),governanceImplementation:address(13),
  governanceImplementationCodeHash:hash(14),governanceOwnersCommitment:safeOwnersCommitment(governanceOwners),
  guardian:address(15),guardianCodeHash:hash(16),
  guardianImplementation:address(17),guardianImplementationCodeHash:hash(18),
  guardianOwnersCommitment:safeOwnersCommitment(guardianOwners),governanceOwners,guardianOwners,checkpointGuardianOwners,withdrawalDelaySeconds:'86400',
  governanceDelaySeconds:'172800',maxOutstandingBaseUnits:'1000000',outflowCapacityBaseUnitsPerDay:'1000000',
  realFundsAuthorized:false};};
const facts=()=>({schema:NATIVE_RELEASE_FACTS_SCHEMA,nativeEthereumTrustedCheckpoint:hash(19),
  domDomain:hash(20),activationScheduleCommitment:hash(21),checkpointDomNetworkMagic:'1146047793',
  checkpointDomChainId:hash(22),checkpointFirstV4Height:'100001',
  checkpointActivationEmptyStateRoot:hash(23),checkpointIntervalBlocks:'360',
  checkpointConfirmationDepthBlocks:'30',checkpointChallengePeriodSeconds:'172800',
  checkpointInitialHeight:'100000',checkpointInitialBlock:hash(24),checkpointInitialStateRoot:hash(23),
  checkpointInitialContextHash:hash(25),checkpointInitialTotalDifficulty:'1000000'});
const finalizedBurnVerifier={runtimeCodeHash:hash(26),initcodeHash:hash(32),configHash:hash(27)};
const checkpointVerifier={runtimeCodeHash:hash(28),initcodeHash:hash(33),configHash:hash(29)};

test('one native fact set derives both exact contract configuration hashes',()=>{
  const core=materializeProductionReleaseCore({releaseConfig:release(),nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier,deferReserveArtifact:true,
    deferCheckpointRegistryArtifact:true});
  const checkpointRegistryArtifact={runtimeCodeHash:hash(36),initcodeHash:hash(37),
    configHash:core.checkpointRegistryConfigHash};
  assert.equal(core.reserveConfigHash,null);
  const reserveCore=materializeProductionReleaseCore({releaseConfig:core,nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier,deferReserveArtifact:true,checkpointRegistryArtifact});
  const reserveArtifact={runtimeCodeHash:hash(34),initcodeHash:hash(35),configHash:reserveCore.reserveConfigHash};
  const result=materializeProductionReleaseCore({releaseConfig:reserveCore,nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier,reserveArtifact,checkpointRegistryArtifact});
  assert.match(result.reserveConfigHash,/^0x[0-9a-f]{64}$/);
  assert.match(result.checkpointRegistryConfigHash,/^0x[0-9a-f]{64}$/);
  assert.equal(result.verifierCodeHash,finalizedBurnVerifier.runtimeCodeHash);
  assert.equal(result.verifierInitcodeHash,finalizedBurnVerifier.initcodeHash);
  assert.equal(result.checkpointVerifierConfigHash,checkpointVerifier.configHash);
  assert.equal(result.checkpointVerifierInitcodeHash,checkpointVerifier.initcodeHash);
  assert.equal(result.reserveRuntimeCodeHash,reserveArtifact.runtimeCodeHash);
  assert.equal(result.reserveInitcodeHash,reserveArtifact.initcodeHash);
  assert.equal(result.checkpointRegistryRuntimeCodeHash,checkpointRegistryArtifact.runtimeCodeHash);
  assert.equal(result.productionReady,false); assert.equal(result.realFundsAuthorized,false);
  assert.deepEqual(materializeProductionReleaseCore({releaseConfig:result,nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier,reserveArtifact,checkpointRegistryArtifact}),result);
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:reserveCore,nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier,reserveArtifact:{...reserveArtifact,configHash:hash(99)},
    checkpointRegistryArtifact}),
  /reserve artifact config hash/);
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:release(),nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier}),/checkpoint registry artifact is required/);
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:{...release(),
    reserveRuntimeCodeHash:hash(34)},nativeFacts:facts(),finalizedBurnVerifier,checkpointVerifier,
    deferReserveArtifact:true}),/partially materialized/);
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:result,nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier,deferReserveArtifact:true}),/transition mode|deferred|checkpoint registry artifact/);
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:core,nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier,reserveArtifact}),/checkpoint registry artifact is required/);
});

test('release core rejects drift, bad bootstrap, extra facts and authorization',()=>{
  const mutations=[
    {releaseConfig:{...release(),productionReady:true},nativeFacts:facts()},
    {releaseConfig:release(),nativeFacts:{...facts(),checkpointInitialHeight:'99999'}},
    {releaseConfig:release(),nativeFacts:{...facts(),activationScheduleCommitment:null}},
    {releaseConfig:release(),nativeFacts:{...facts(),checkpointInitialStateRoot:hash(99)}},
    {releaseConfig:release(),nativeFacts:(()=>{const value=facts();delete value.activationScheduleCommitment;return value;})()},
    {releaseConfig:release(),nativeFacts:{...facts(),extra:true}},
    {releaseConfig:{...release(),domDomain:hash(31)},nativeFacts:facts()},
    {releaseConfig:{...release(),governanceOwnersCommitment:hash(31)},nativeFacts:facts()},
    {releaseConfig:{...release(),verifierCodeHash:finalizedBurnVerifier.runtimeCodeHash},nativeFacts:facts()},
    {releaseConfig:{...release(),checkpointVerifierConfigHash:checkpointVerifier.configHash},nativeFacts:facts()},
    {releaseConfig:{...release(),checkpointRegistryInitcodeHash:hash(38)},nativeFacts:facts()},
    {releaseConfig:{...release(),governanceOwners:[address(40),address(42),address(41)]},nativeFacts:facts()},
  ];
  for(const value of mutations) assert.throws(()=>materializeProductionReleaseCore({...value,
    finalizedBurnVerifier,checkpointVerifier}));
});

test('root materializer uses unified verifier bindings and rechecks its release template',async()=>{
  const [prepare,wrapper]=await Promise.all([
    readFile(new URL('../../scripts/prepare-production-release-core-materialization.mjs',import.meta.url),'utf8'),
    readFile(new URL('../../scripts/materialize-production-release-core.sh',import.meta.url),'utf8'),
  ]);
  for(const marker of ['deriveFinalizedBurnVerifierArtifactBinding','deriveReserveArtifactBinding',
    'deriveCheckpointVerifierArtifactBinding','expectedConfigHash:finalized.verifierConfigHash',
    'expectedConfigHash:checkpoint.verifierConfigHash','initcodeHash:finalizedBinding.initcodeHash',
    'initcodeHash:checkpointBinding.initcodeHash','initcodeHash:reserveBinding.initcodeHash',
    'deferReserveArtifact:true','deferCheckpointRegistryArtifact:true',
    'deriveCheckpointRegistryArtifactBinding','initcodeHash:registryBinding.initcodeHash',
    "build('out/USDOMProofReserve.sol/USDOMProofReserve.json')",'release-core input changed']) {
    assert.ok(prepare.includes(marker),marker);
  }
  assert.match(wrapper,/target_sha256=\$\(sha256sum "\$target"/);
  assert.match(wrapper,/sha256sum "\$target".*"\$target_sha256"/s);
  assert.match(wrapper,/flock -n 9/);
  assert.match(wrapper,/install-release-config-stdin\.mjs/);
  assert.match(wrapper,/\.reserveRuntimeCodeHash != null and \.reserveInitcodeHash != null/);
  assert.match(wrapper,/target_sha256=\$\(sha256sum "\$target"/);
  assert.match(wrapper,/if ! cmp -s "\$temporary" "\$target"/);
});
