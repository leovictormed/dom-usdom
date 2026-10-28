import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {materializeProductionReleaseCore,NATIVE_RELEASE_FACTS_SCHEMA} from '../../sdk/production-release-core.mjs';
import {safeOwnersCommitment} from '../../sdk/configuration.mjs';
import {activationSchedule} from '../../sdk/activation-schedule.mjs';
import {deriveDomDomain} from '../../sdk/preactivation-policy.mjs';
import {SAFE_MAINNET_IDENTITY} from '../../sdk/safe-control-deployment.mjs';

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
  checkpointGuardianImplementation:SAFE_MAINNET_IDENTITY.singleton,
  checkpointGuardianImplementationCodeHash:SAFE_MAINNET_IDENTITY.singletonCodeHash,
  checkpointDomNetworkMagic:null,checkpointDomChainId:null,checkpointFirstV4Height:null,
  checkpointActivationEmptyStateRoot:null,checkpointIntervalBlocks:null,
  checkpointConfirmationDepthBlocks:null,checkpointChallengePeriodSeconds:null,
  checkpointInitialHeight:null,checkpointInitialBlock:null,checkpointInitialStateRoot:null,
  checkpointInitialContextHash:null,checkpointInitialTotalDifficulty:null,nativeEthereumTrustedCheckpoint:null,
  governance:address(11),governanceCodeHash:hash(12),
  governanceImplementation:SAFE_MAINNET_IDENTITY.singleton,
  governanceImplementationCodeHash:SAFE_MAINNET_IDENTITY.singletonCodeHash,
  governanceOwnersCommitment:safeOwnersCommitment(governanceOwners),
  guardian:address(15),guardianCodeHash:hash(16),
  guardianImplementation:SAFE_MAINNET_IDENTITY.singleton,
  guardianImplementationCodeHash:SAFE_MAINNET_IDENTITY.singletonCodeHash,
  guardianOwnersCommitment:safeOwnersCommitment(guardianOwners),governanceOwners,guardianOwners,checkpointGuardianOwners,withdrawalDelaySeconds:'86400',
  governanceDelaySeconds:'172800',maxOutstandingBaseUnits:'1000000',outflowCapacityBaseUnitsPerDay:'1000000',
  realFundsAuthorized:false};};
const facts=(releaseConfig=release())=>{const checkpointDomNetworkMagic='1146047793',checkpointDomChainId=hash(22);
 const checkpointFirstV4Height='100001',checkpointActivationEmptyStateRoot=hash(23);
 const activationScheduleCommitment=activationSchedule({networkMagic:checkpointDomNetworkMagic,
  chainId:checkpointDomChainId,firstV4Height:checkpointFirstV4Height,
  emptyStateRoot:checkpointActivationEmptyStateRoot}).commitment;
 return {schema:NATIVE_RELEASE_FACTS_SCHEMA,nativeEthereumTrustedCheckpoint:hash(19),
  domDomain:deriveDomDomain({domNetworkMagic:checkpointDomNetworkMagic,domChainId:checkpointDomChainId,
    ethereumChainId:releaseConfig.ethereumChainId,reserve:releaseConfig.reserve,
    checkpointRegistry:releaseConfig.checkpointRegistry}),activationScheduleCommitment,checkpointDomNetworkMagic,
  checkpointDomChainId,checkpointFirstV4Height,
  checkpointActivationEmptyStateRoot,checkpointIntervalBlocks:'360',
  checkpointConfirmationDepthBlocks:'30',checkpointChallengePeriodSeconds:'172800',
  checkpointInitialHeight:'100000',checkpointInitialBlock:hash(24),checkpointInitialStateRoot:hash(23),
  checkpointInitialContextHash:hash(25),checkpointInitialTotalDifficulty:'1000000'};};
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
    finalizedBurnVerifier,checkpointVerifier,reserveArtifact,checkpointRegistryArtifact,
    completeTechnicalProduction:true});
  assert.match(result.reserveConfigHash,/^0x[0-9a-f]{64}$/);
  assert.match(result.checkpointRegistryConfigHash,/^0x[0-9a-f]{64}$/);
  assert.equal(result.verifierCodeHash,finalizedBurnVerifier.runtimeCodeHash);
  assert.equal(result.verifierInitcodeHash,finalizedBurnVerifier.initcodeHash);
  assert.equal(result.checkpointVerifierConfigHash,checkpointVerifier.configHash);
  assert.equal(result.checkpointVerifierInitcodeHash,checkpointVerifier.initcodeHash);
  assert.equal(result.reserveRuntimeCodeHash,reserveArtifact.runtimeCodeHash);
  assert.equal(result.reserveInitcodeHash,reserveArtifact.initcodeHash);
  assert.equal(result.checkpointRegistryRuntimeCodeHash,checkpointRegistryArtifact.runtimeCodeHash);
  assert.equal(result.productionReady,true); assert.equal(result.realFundsAuthorized,false);
  assert.deepEqual(materializeProductionReleaseCore({releaseConfig:result,nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier,reserveArtifact,checkpointRegistryArtifact,
    completeTechnicalProduction:true}),result);
  assert.equal(materializeProductionReleaseCore({releaseConfig:reserveCore,nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier,reserveArtifact,checkpointRegistryArtifact,
    completeTechnicalProduction:false}).productionReady,false);
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:reserveCore,nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier,deferReserveArtifact:true,checkpointRegistryArtifact,
    completeTechnicalProduction:true}),/technical production readiness/);
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:reserveCore,nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier,reserveArtifact:{...reserveArtifact,configHash:hash(99)},
    checkpointRegistryArtifact}),
  /reserve artifact config hash/);
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:reserveCore,nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier,
    checkpointRegistryArtifact:{...checkpointRegistryArtifact,configHash:hash(99)},
    deferReserveArtifact:true}),/checkpoint registry artifact config hash/);
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:result,nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier,reserveArtifact,
    checkpointRegistryArtifact:{...checkpointRegistryArtifact,runtimeCodeHash:hash(98)},
    completeTechnicalProduction:true}),
  /checkpointRegistryRuntimeCodeHash/);
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:result,nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier,reserveArtifact,
    checkpointRegistryArtifact:{...checkpointRegistryArtifact,initcodeHash:hash(98)},
    completeTechnicalProduction:true}),
  /checkpointRegistryInitcodeHash/);
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:release(),nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier}),/checkpoint registry artifact is required/);
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:{...release(),
    reserveRuntimeCodeHash:hash(34)},nativeFacts:facts(),finalizedBurnVerifier,checkpointVerifier,
    deferReserveArtifact:true}),/partially materialized/);
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:result,nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier,deferReserveArtifact:true,
    completeTechnicalProduction:true}),/transition mode|deferred|checkpoint registry artifact/);
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:core,nativeFacts:facts(),
    finalizedBurnVerifier,checkpointVerifier,reserveArtifact}),/checkpoint registry artifact is required/);
});

test('release core rejects drift, bad bootstrap, extra facts and authorization',()=>{
  const controlCollision=release();
  controlCollision.checkpointGuardianOwners[0]=controlCollision.governance;
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:controlCollision,
    nativeFacts:facts(controlCollision),finalizedBurnVerifier,checkpointVerifier}),
  /must not be a configured contract address/);
  const roleCollision=release();
  roleCollision.checkpointVerifier=roleCollision.verifier;
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:roleCollision,
    nativeFacts:facts(roleCollision),finalizedBurnVerifier,checkpointVerifier}),
  /contract roles must use distinct addresses/);
  const implementationIdentityDrift=release();
  implementationIdentityDrift.guardianImplementation=address(99);
  implementationIdentityDrift.guardianImplementationCodeHash=hash(99);
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:implementationIdentityDrift,
    nativeFacts:facts(implementationIdentityDrift),finalizedBurnVerifier,checkpointVerifier}),
  /must match the pinned singleton identity/);
  const implementationCollision=release();
  implementationCollision.checkpointGuardianOwners[0]=implementationCollision.guardianImplementation;
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:implementationCollision,
    nativeFacts:facts(implementationCollision),finalizedBurnVerifier,checkpointVerifier}),
  /must not be a configured contract address/);
  const infrastructureCollision=release();
  infrastructureCollision.checkpointGuardianOwners[0]=SAFE_MAINNET_IDENTITY.factory;
  assert.throws(()=>materializeProductionReleaseCore({releaseConfig:infrastructureCollision,
    nativeFacts:facts(infrastructureCollision),finalizedBurnVerifier,checkpointVerifier}),
  /must not be a configured contract address/);
  const mutations=[
    {releaseConfig:{...release(),productionReady:true},nativeFacts:facts()},
    {releaseConfig:release(),nativeFacts:{...facts(),checkpointInitialHeight:'99999'}},
    {releaseConfig:release(),nativeFacts:{...facts(),activationScheduleCommitment:null}},
    {releaseConfig:release(),nativeFacts:{...facts(),activationScheduleCommitment:hash(21)}},
    {releaseConfig:release(),nativeFacts:{...facts(),domDomain:hash(20)}},
    {releaseConfig:release(),nativeFacts:{...facts(),checkpointInitialStateRoot:hash(99)}},
    {releaseConfig:release(),nativeFacts:{...facts(),checkpointInitialTotalDifficulty:'9'.repeat(100000)}},
    {releaseConfig:release(),nativeFacts:{...facts(),checkpointFirstV4Height:(1n<<64n).toString()}},
    {releaseConfig:release(),nativeFacts:(()=>{const value=facts();delete value.activationScheduleCommitment;return value;})()},
    {releaseConfig:release(),nativeFacts:{...facts(),extra:true}},
    {releaseConfig:{...release(),domDomain:hash(31)},nativeFacts:facts()},
    {releaseConfig:{...release(),governanceOwnersCommitment:hash(31)},nativeFacts:facts()},
    {releaseConfig:{...release(),verifierCodeHash:finalizedBurnVerifier.runtimeCodeHash},nativeFacts:facts()},
    {releaseConfig:{...release(),checkpointVerifierConfigHash:checkpointVerifier.configHash},nativeFacts:facts()},
    {releaseConfig:{...release(),checkpointRegistryInitcodeHash:hash(38)},nativeFacts:facts()},
    {releaseConfig:{...release(),governanceOwners:[address(40),address(42),address(41)]},nativeFacts:facts()},
    {releaseConfig:{...release(),checkpointGuardianOwners:[address(46),address(47),address(40)]},
      nativeFacts:facts()},
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
  for(const marker of ["'registry-pins'","'reserve-pins'","stage==='registry-pins'",
    "stage==='reserve-pins'",'deferCheckpointRegistryArtifact:true']) assert.ok(prepare.includes(marker),marker);
  assert.match(wrapper,/registry-pins\|reserve-pins\|final/);
  assert.match(wrapper,/scripts\/prepare-production-release-core-materialization\.mjs "\$stage"/);
  assert.match(wrapper,/target_sha256=\$\(sha256sum "\$target"/);
  assert.match(wrapper,/sha256sum "\$target".*"\$target_sha256"/s);
  assert.match(wrapper,/flock -n 9/);
  assert.match(wrapper,/replace-locked-source-stdin\.mjs/);
  assert.match(wrapper,/"\$target_sha256" "\$parent_device" "\$parent_inode" "\$python3_bin" "\$python3_sha256"/);
  assert.match(wrapper,/pin_tool python3/);
  assert.match(wrapper,/\.reserveRuntimeCodeHash != null and \.reserveInitcodeHash != null/);
  assert.match(wrapper,/target_sha256=\$\(sha256sum "\$target"/);
  assert.match(wrapper,/if ! cmp -s "\$temporary" "\$target"/);
  assert.match(wrapper,/stat -Lc '%u:%a:%h' "\$target"/);
  assert.equal((wrapper.match(/cmp -s "\$temporary" "\$target"/g)??[]).length,5);
  assert.match(wrapper,/sync -f "\$config_directory"\ncmp -s "\$temporary" "\$target"/);
  assert.match(wrapper,/prepare-production-release-core-materialization\.mjs "\$stage" > "\$temporary\.rechecked"/);
  assert.equal((wrapper.match(/cmp -s "\$temporary" "\$temporary\.rechecked"/g)??[]).length,3);
});
