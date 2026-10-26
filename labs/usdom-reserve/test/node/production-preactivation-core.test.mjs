import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {NATIVE_PREACTIVATION_FACTS_SCHEMA,materializeProductionPreActivationCore}
  from '../../sdk/production-preactivation-core.mjs';
import {safeOwnersCommitment} from '../../sdk/configuration.mjs';

const address=n=>'0x'+n.toString(16).padStart(40,'0');
const hash=n=>'0x'+n.toString(16).padStart(64,'0');
const release=()=>{const governanceOwners=[address(40),address(41),address(42)];
 const guardianOwners=[address(43),address(44),address(45)];
 const checkpointGuardianOwners=[address(46),address(47),address(48)]; return ({productionReady:false,realFundsAuthorized:false,ethereumChainId:'1',
  token:address(1),tokenCodeHash:hash(2),reserve:address(3),verifier:address(4),
  verifierCodeHash:null,verifierInitcodeHash:null,verifierConfigHash:null,reserveConfigHash:null,
  reserveRuntimeCodeHash:null,reserveInitcodeHash:null,domDomain:null,
  activationScheduleCommitment:null,checkpointRegistry:address(5),checkpointRegistryConfigHash:null,
  checkpointRegistryRuntimeCodeHash:null,checkpointRegistryInitcodeHash:null,
  checkpointVerifier:address(6),checkpointVerifierCodeHash:null,checkpointVerifierInitcodeHash:null,
  checkpointVerifierConfigHash:null,
  checkpointGuardian:address(7),checkpointGuardianCodeHash:hash(8),
  checkpointGuardianImplementation:address(9),checkpointGuardianImplementationCodeHash:hash(10),
  checkpointDomNetworkMagic:null,checkpointDomChainId:null,checkpointFirstV4Height:null,
  checkpointActivationEmptyStateRoot:null,checkpointIntervalBlocks:null,
  checkpointConfirmationDepthBlocks:null,checkpointChallengePeriodSeconds:null,
  checkpointInitialHeight:null,checkpointInitialBlock:null,checkpointInitialStateRoot:null,
  checkpointInitialContextHash:null,checkpointInitialTotalDifficulty:null,
  nativeEthereumTrustedCheckpoint:null,governance:address(11),governanceCodeHash:hash(12),
  governanceImplementation:address(13),governanceImplementationCodeHash:hash(14),
  governanceOwnersCommitment:safeOwnersCommitment(governanceOwners),
  guardian:address(15),guardianCodeHash:hash(16),guardianImplementation:address(17),
  guardianImplementationCodeHash:hash(18),guardianOwnersCommitment:safeOwnersCommitment(guardianOwners),
  governanceOwners,guardianOwners,checkpointGuardianOwners,withdrawalDelaySeconds:'86400',
  governanceDelaySeconds:'172800',maxOutstandingBaseUnits:'1000000',
  outflowCapacityBaseUnitsPerDay:'1000000'});};
const facts=()=>({schema:NATIVE_PREACTIVATION_FACTS_SCHEMA,nativeEthereumTrustedCheckpoint:hash(19),
  domDomain:hash(20),checkpointDomNetworkMagic:'1146047793',checkpointDomChainId:hash(21),
  checkpointFirstV4Height:'100001',checkpointIntervalBlocks:'360',
  checkpointConfirmationDepthBlocks:'30',checkpointChallengePeriodSeconds:'172800',
  checkpointInitialHeight:'100000',checkpointInitialBlock:hash(22),
  checkpointInitialContextHash:hash(23),checkpointInitialTotalDifficulty:'1000000'});
const finalizedBurnVerifier={runtimeCodeHash:hash(24),initcodeHash:hash(28),configHash:hash(25)};
const checkpointVerifier={runtimeCodeHash:hash(26),initcodeHash:hash(29),configHash:hash(27)};

test('pre-activation core derives Registry pins and defers reserve identity until Registry build',()=>{
  const value=materializeProductionPreActivationCore({releaseConfig:release(),nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier});
  assert.equal(value.reservePreActivationConfigHash,null);
  assert.equal(value.checkpointRegistryConfigHash,value.releaseConfig.checkpointRegistryConfigHash);
  for(const field of ['activationScheduleCommitment','checkpointActivationEmptyStateRoot',
    'checkpointInitialStateRoot','reserveConfigHash']) assert.equal(value.releaseConfig[field],null,field);
  assert.equal(value.releaseConfig.verifierCodeHash,finalizedBurnVerifier.runtimeCodeHash);
  assert.equal(value.releaseConfig.verifierInitcodeHash,finalizedBurnVerifier.initcodeHash);
  assert.equal(value.releaseConfig.checkpointVerifierConfigHash,checkpointVerifier.configHash);
  assert.equal(value.releaseConfig.checkpointVerifierInitcodeHash,checkpointVerifier.initcodeHash);
});

test('pre-activation core rejects drift, authorization and dependent fields',()=>{
  const cases=[
    {releaseConfig:{...release(),productionReady:true},nativeFacts:facts()},
    {releaseConfig:{...release(),activationScheduleCommitment:hash(1)},nativeFacts:facts()},
    {releaseConfig:{...release(),reserveRuntimeCodeHash:hash(1)},nativeFacts:facts()},
    {releaseConfig:{...release(),reserveInitcodeHash:hash(1)},nativeFacts:facts()},
    {releaseConfig:{...release(),verifierCodeHash:hash(1)},nativeFacts:facts()},
    {releaseConfig:{...release(),checkpointVerifierInitcodeHash:hash(1)},nativeFacts:facts()},
    {releaseConfig:{...release(),checkpointRegistryRuntimeCodeHash:hash(1)},nativeFacts:facts()},
    {releaseConfig:release(),nativeFacts:{...facts(),checkpointFirstV4Height:'100002'}},
    {releaseConfig:release(),nativeFacts:{...facts(),extra:true}},
    {releaseConfig:{...release(),domDomain:hash(31)},nativeFacts:facts()},
    {releaseConfig:{...release(),guardianOwnersCommitment:hash(31)},nativeFacts:facts()},
    {releaseConfig:{...release(),governanceOwners:[address(40),address(40),address(41)]},nativeFacts:facts()},
  ];
  for(const value of cases) assert.throws(()=>materializeProductionPreActivationCore({...value,
    finalizedBurnVerifier,checkpointVerifier}),undefined,JSON.stringify(value));
});

test('preactivation root uses artifact bindings and rechecks the template',async()=>{
  const [prepare,wrapper]=await Promise.all([
    readFile(new URL('../../scripts/prepare-production-preactivation-core-materialization.mjs',import.meta.url),'utf8'),
    readFile(new URL('../../scripts/materialize-production-preactivation-core.sh',import.meta.url),'utf8'),
  ]);
  for(const marker of ['deriveFinalizedBurnAdapterArtifactBinding','deriveCheckpointAdapterArtifactBinding',
    'expectedConfigHash:burnIdentity.verifierConfigHash',
    'expectedConfigHash:checkpointIdentity.verifierConfigHash','initcodeHash:burnBinding.initcodeHash',
    'initcodeHash:checkpointBinding.initcodeHash','pre-activation input changed']) {
    assert.ok(prepare.includes(marker),marker);
  }
  assert.match(wrapper,/target_sha256=\$\(sha256sum "\$target"/);
  assert.match(wrapper,/sha256sum "\$target".*"\$target_sha256"/s);
  assert.match(wrapper,/flock -n 9/);
});
