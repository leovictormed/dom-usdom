import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {materializeProductionSolidityPins,verifyProductionVerifierBindings}
  from '../../sdk/production-solidity-pins.mjs';
import {checkpointRegistryPreActivationConfigHash} from '../../sdk/checkpoint-registry.mjs';
import {safeOwnersCommitment} from '../../sdk/configuration.mjs';
import {execFileSync,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {getCreateAddress} from 'ethers';
import {deriveDomDomain} from '../../sdk/preactivation-policy.mjs';

const hash=byte=>'0x'+byte.repeat(64);
const address=byte=>'0x'+byte.repeat(40);
const release={ethereumChainId:'1',productionReady:false,realFundsAuthorized:false,
  deploymentMethod:'CREATE',deployer:address('a'),deployerNonce:'1',
  verifierDeployer:address('b'),verifierDeployerNonce:'2',
  checkpointRegistryDeployer:address('c'),checkpointRegistryDeployerNonce:'3',
  checkpointVerifierDeployer:address('d'),checkpointVerifierDeployerNonce:'4',
  verifierCodeHash:hash('1'),verifierInitcodeHash:hash('6'),verifierConfigHash:hash('2'),
  reserveConfigHash:hash('3'),checkpointVerifierCodeHash:hash('4'),
  checkpointVerifierInitcodeHash:hash('7'),checkpointVerifierConfigHash:hash('5'),
  checkpointRegistryConfigHash:hash('6'),checkpointRegistryRuntimeCodeHash:hash('f'),
  reserve:address('1'),token:address('2'),tokenCodeHash:hash('7'),
  verifier:address('3'),domDomain:hash('8'),activationScheduleCommitment:hash('9'),governance:address('4'),
  governanceCodeHash:hash('a'),governanceImplementation:address('4'),
  governanceImplementationCodeHash:hash('a'),governanceOwnersCommitment:hash('1'),
  guardian:address('5'),guardianCodeHash:hash('b'),
  guardianImplementation:address('5'),guardianImplementationCodeHash:hash('b'),
  guardianOwnersCommitment:hash('2'),
  withdrawalDelaySeconds:'86400',governanceDelaySeconds:'172800',maxOutstandingBaseUnits:'1000000',
  outflowCapacityBaseUnitsPerDay:'1000000',checkpointRegistry:address('6'),
  checkpointDomNetworkMagic:'2712847316',checkpointDomChainId:hash('c'),checkpointFirstV4Height:'101',
  checkpointActivationEmptyStateRoot:hash('d'),checkpointIntervalBlocks:'100',
  checkpointConfirmationDepthBlocks:'10',checkpointChallengePeriodSeconds:'172800',
  checkpointVerifier:address('7'),checkpointGuardian:address('8'),checkpointGuardianCodeHash:hash('e'),
  checkpointGuardianImplementation:address('8'),checkpointGuardianImplementationCodeHash:hash('e'),
  governanceOwners:[address('9'),address('a'),address('b')],
  guardianOwners:[address('c'),address('d'),address('e')],
  checkpointGuardianOwners:[address('6'),address('7'),address('8')],
  checkpointInitialHeight:'100',checkpointInitialBlock:hash('f'),checkpointInitialStateRoot:hash('d'),
  checkpointInitialContextHash:hash('1'),checkpointInitialTotalDifficulty:'1000000'};
release.reserve=getCreateAddress({from:release.deployer,nonce:BigInt(release.deployerNonce)});
release.verifier=getCreateAddress({from:release.verifierDeployer,nonce:BigInt(release.verifierDeployerNonce)});
release.checkpointRegistry=getCreateAddress({from:release.checkpointRegistryDeployer,
  nonce:BigInt(release.checkpointRegistryDeployerNonce)});
release.checkpointVerifier=getCreateAddress({from:release.checkpointVerifierDeployer,
  nonce:BigInt(release.checkpointVerifierDeployerNonce)});
release.domDomain=deriveDomDomain({domNetworkMagic:release.checkpointDomNetworkMagic,
  domChainId:release.checkpointDomChainId,ethereumChainId:release.ethereumChainId,
  reserve:release.reserve,checkpointRegistry:release.checkpointRegistry});
release.governanceOwnersCommitment=safeOwnersCommitment(release.governanceOwners);
release.guardianOwnersCommitment=safeOwnersCommitment(release.guardianOwners);
const reserve=`contract USDOMProofReserve {
bytes32 public constant PRODUCTION_VERIFIER_CODE_HASH = bytes32(0);
bytes32 public constant PRODUCTION_VERIFIER_CONFIG_HASH = bytes32(0);
bytes32 public constant PRODUCTION_RESERVE_PREACTIVATION_CONFIG_HASH = bytes32(0);
}\n`;
const registry=`contract DOMCheckpointRegistry {
bytes32 public constant PRODUCTION_VERIFIER_CODE_HASH = bytes32(0);
bytes32 public constant PRODUCTION_VERIFIER_CONFIG_HASH = bytes32(0);
bytes32 public constant PRODUCTION_CHECKPOINT_CONFIG_HASH = bytes32(0);
}\n`;

release.checkpointRegistryConfigHash=checkpointRegistryPreActivationConfigHash({
  ethereumChainId:release.ethereumChainId,registry:release.checkpointRegistry,
  bridgeDomain:release.domDomain,domNetworkMagic:release.checkpointDomNetworkMagic,
  domChainId:release.checkpointDomChainId,firstV4Height:release.checkpointFirstV4Height,
  checkpointInterval:release.checkpointIntervalBlocks,
  confirmationDepth:release.checkpointConfirmationDepthBlocks,
  challengePeriod:release.checkpointChallengePeriodSeconds,verifier:release.checkpointVerifier,
  verifierCodeHash:release.checkpointVerifierCodeHash,
  verifierConfigHash:release.checkpointVerifierConfigHash,guardian:release.checkpointGuardian,
  guardianCodeHash:release.checkpointGuardianCodeHash,
  guardianImplementation:release.checkpointGuardianImplementation,
  guardianImplementationCodeHash:release.checkpointGuardianImplementationCodeHash,
  guardianOwnersCommitment:safeOwnersCommitment(release.checkpointGuardianOwners),
  initialHeight:release.checkpointInitialHeight,
  initialBlock:release.checkpointInitialBlock,initialContextHash:release.checkpointInitialContextHash,
  initialTotalDifficulty:release.checkpointInitialTotalDifficulty,
}).checkpointConfigHash;

test('materializes all six acyclic mainnet pins and is idempotent',()=>{
  const first=materializeProductionSolidityPins({releaseConfig:release,reserveSource:reserve,
    checkpointRegistrySource:registry});
  for(const value of [release.verifierCodeHash,release.verifierConfigHash,
    release.checkpointVerifierCodeHash,release.checkpointVerifierConfigHash]) {
    assert.match(first.reserveSource+first.checkpointRegistrySource,new RegExp(value));
  }
  assert.doesNotMatch(first.reserveSource+first.checkpointRegistrySource,/PRODUCTION_\w+_HASH\s*=\s*bytes32\(0\)/);
  const second=materializeProductionSolidityPins({releaseConfig:release,
    reserveSource:first.reserveSource,checkpointRegistrySource:first.checkpointRegistrySource});
  assert.deepEqual(second,first);
  const beforeActivation={...release,activationScheduleCommitment:null,
    checkpointActivationEmptyStateRoot:null,checkpointInitialStateRoot:null};
  assert.deepEqual(materializeProductionSolidityPins({releaseConfig:beforeActivation,
    reserveSource:reserve,checkpointRegistrySource:registry}),first);
});

test('reconciles all verifier release identities with source-verified artifact bindings',()=>{
  const bindings={finalizedBurnVerifier:{runtimeCodeHash:release.verifierCodeHash,
    initcodeHash:release.verifierInitcodeHash,configHash:release.verifierConfigHash},
  checkpointVerifier:{runtimeCodeHash:release.checkpointVerifierCodeHash,
    initcodeHash:release.checkpointVerifierInitcodeHash,
    configHash:release.checkpointVerifierConfigHash}};
  assert.deepEqual(verifyProductionVerifierBindings({releaseConfig:release,...bindings}),bindings);
  for(const field of ['verifierCodeHash','verifierInitcodeHash','verifierConfigHash',
    'checkpointVerifierCodeHash','checkpointVerifierInitcodeHash','checkpointVerifierConfigHash']) {
    assert.throws(()=>verifyProductionVerifierBindings({releaseConfig:{...release,[field]:hash('f')},
      ...bindings}),new RegExp(`${field} differs`));
  }
  assert.throws(()=>verifyProductionVerifierBindings({releaseConfig:release,...bindings,
    finalizedBurnVerifier:{...bindings.finalizedBurnVerifier,extra:hash('e')}}),/exact source-verified/);
});

test('verifier adapter source graphs are independent from sources that embed their code hashes',()=>{
  for(const [adapterName,boundaryName,interfaceName,forbidden] of [
    ['DOMFinalizedBurnRiscZeroVerifier','IDOMFinalizedBurnVerifier','IDOMFinalizedBurnVerifier',
      'USDOMProofReserve'],
    ['DOMCheckpointRiscZeroVerifier','IDOMCheckpointVerifier','IDOMCheckpointVerifier',
      'DOMCheckpointRegistry'],
  ]) {
    const adapter=readFileSync(new URL(`../../contracts/${adapterName}.sol`,import.meta.url),'utf8');
    const boundary=readFileSync(new URL(`../../contracts/${boundaryName}.sol`,import.meta.url),'utf8');
    assert.match(adapter,new RegExp(`from "\\./${boundaryName}\\.sol"`));
    assert.doesNotMatch(adapter,new RegExp(`${forbidden}\\.sol`));
    assert.match(boundary,new RegExp(`interface ${interfaceName}`));
    assert.doesNotMatch(boundary,new RegExp(`PRODUCTION_|${forbidden}`));
  }
});

test('staged pinning derives registry before its runtime is available, then reserve',()=>{
  const registryStage=materializeProductionSolidityPins({releaseConfig:{...release,
    checkpointRegistryRuntimeCodeHash:null},reserveSource:reserve,checkpointRegistrySource:registry,
    component:'checkpointRegistry'});
  assert.deepEqual(Object.keys(registryStage),['checkpointRegistrySource']);
  assert.doesNotMatch(registryStage.checkpointRegistrySource,/PRODUCTION_\w+_HASH\s*=\s*bytes32\(0\)/);
  const reserveStage=materializeProductionSolidityPins({releaseConfig:release,reserveSource:reserve,
    checkpointRegistrySource:registry,component:'reserve'});
  assert.deepEqual(Object.keys(reserveStage),['reserveSource']);
  assert.doesNotMatch(reserveStage.reserveSource,/PRODUCTION_\w+_HASH\s*=\s*bytes32\(0\)/);
  assert.throws(()=>materializeProductionSolidityPins({releaseConfig:release,reserveSource:reserve,
    checkpointRegistrySource:registry,component:'foreign'}),/component/);
});

test('dependency direction is acyclic: registry ignores its runtime while reserve consumes it',()=>{
  const changed={...release,checkpointRegistryRuntimeCodeHash:hash('d')};
  const registryBefore=materializeProductionSolidityPins({releaseConfig:release,
    reserveSource:reserve,checkpointRegistrySource:registry,component:'checkpointRegistry'});
  const registryAfter=materializeProductionSolidityPins({releaseConfig:changed,
    reserveSource:reserve,checkpointRegistrySource:registry,component:'checkpointRegistry'});
  assert.equal(registryAfter.checkpointRegistrySource,registryBefore.checkpointRegistrySource);
  const reserveBefore=materializeProductionSolidityPins({releaseConfig:release,
    reserveSource:reserve,checkpointRegistrySource:registry,component:'reserve'});
  const reserveAfter=materializeProductionSolidityPins({releaseConfig:changed,
    reserveSource:reserve,checkpointRegistrySource:registry,component:'reserve'});
  assert.notEqual(reserveAfter.reserveSource,reserveBefore.reserveSource);
});

test('rejects authorization, zero, missing, duplicate and conflicting pins',()=>{
  for(const changed of [
    {...release,productionReady:true},{...release,realFundsAuthorized:true},
    {...release,verifierCodeHash:hash('0')},{...release,checkpointVerifierConfigHash:null},
  ]) assert.throws(()=>materializeProductionSolidityPins({releaseConfig:changed,reserveSource:reserve,
    checkpointRegistrySource:registry}));
  assert.throws(()=>materializeProductionSolidityPins({releaseConfig:release,
    reserveSource:reserve+reserve,checkpointRegistrySource:registry}),/exactly one/);
  const conflicting=reserve.replace('bytes32(0)',hash('f'));
  assert.throws(()=>materializeProductionSolidityPins({releaseConfig:release,reserveSource:conflicting,
    checkpointRegistrySource:registry}),/differs/);
});

test('refuses source pinning when Safe owner commitments or role separation drift',()=>{
  const mutations=[
    {...release,governanceOwnersCommitment:hash('f')},
    {...release,guardianOwnersCommitment:hash('f')},
    {...release,checkpointGuardianOwners:[...release.checkpointGuardianOwners.slice(0,2),
      release.governanceOwners[0]]},
  ];
  for(const releaseConfig of mutations) {
    assert.throws(()=>materializeProductionSolidityPins({releaseConfig,reserveSource:reserve,
      checkpointRegistrySource:registry}),/owner commitments|globally distinct/);
  }
});

test('refuses source pinning for a mismatched CREATE plan or DOM domain',()=>{
  for(const releaseConfig of [
    {...release,deploymentMethod:'CREATE2'},
    {...release,deployerNonce:'2'},
    {...release,verifierDeployerNonce:'3'},
    {...release,checkpointRegistryDeployerNonce:'4'},
    {...release,checkpointVerifierDeployerNonce:'5'},
    {...release,domDomain:hash('f')},
  ]) assert.throws(()=>materializeProductionSolidityPins({releaseConfig,reserveSource:reserve,
    checkpointRegistrySource:registry}),/CREATE|deployment plan|DOM domain/);
});

test('rejects a stale registry configuration before either component is materialized',()=>{
  const stale={...release,checkpointRegistryConfigHash:hash('a')};
  assert.notEqual(stale.checkpointRegistryConfigHash,release.checkpointRegistryConfigHash);
  for(const component of ['reserve','checkpointRegistry','both']) {
    assert.throws(()=>materializeProductionSolidityPins({releaseConfig:stale,reserveSource:reserve,
      checkpointRegistrySource:registry,component}),
    /checkpointRegistryConfigHash differs from the exact release fields/);
  }
  assert.match(reserve,/PRODUCTION_VERIFIER_CODE_HASH = bytes32\(0\)/);
  assert.match(registry,/PRODUCTION_VERIFIER_CODE_HASH = bytes32\(0\)/);
});

test('the checked-in contracts retain exactly the materializable declarations',()=>{
  const actualReserve=readFileSync(new URL('../../contracts/USDOMProofReserve.sol',import.meta.url),'utf8');
  const actualRegistry=readFileSync(new URL('../../contracts/DOMCheckpointRegistry.sol',import.meta.url),'utf8');
  const result=materializeProductionSolidityPins({releaseConfig:release,reserveSource:actualReserve,
    checkpointRegistrySource:actualRegistry});
  assert.doesNotMatch(result.reserveSource,
    /PRODUCTION_(?:VERIFIER_CODE|VERIFIER_CONFIG|RESERVE_PREACTIVATION_CONFIG)_HASH\s*=\s*bytes32\(0\)/);
  assert.doesNotMatch(result.checkpointRegistrySource,
    /PRODUCTION_(?:VERIFIER_CODE|VERIFIER_CONFIG|CHECKPOINT_CONFIG)_HASH\s*=\s*bytes32\(0\)/);
});

test('writer is single-component and binds all inputs before replacement',()=>{
  const writerUrl=new URL('../../scripts/materialize-production-solidity-pins.sh',import.meta.url);
  const writerPath=fileURLToPath(writerUrl);
  const project=fileURLToPath(new URL('../..',import.meta.url));
  const writer=readFileSync(writerUrl,'utf8');
  assert.match(writer,/exec 9<"\$project\/config"/);
  assert.match(writer,/exec 8<"\$project\/contracts"/);
  assert.match(writer,/contracts_directory_identity=.*\/proc\/self\/fd\/8/);
  assert.match(writer,/reserve=\/proc\/self\/fd\/8\/USDOMProofReserve\.sol/);
  assert.match(writer,/assert_project_directories\n\s+replacement_status=0\n\s+"\$timeout_bin"[\s\S]*replace-locked-source-stdin\.mjs/);
  assert.match(writer,/assert_inputs_unchanged\n\s+sync -f "\$candidate"\n\s+assert_inputs_unchanged\n\s+assert_project_directories\n\s+replacement_status=0\n\s+"\$timeout_bin"/);
  assert.match(writer,/prepare-production-solidity-pins\.mjs "\$component" > "\$temporary\/rechecked-envelope\.json"/);
  assert.match(writer,/cmp -s "\$temporary\/rechecked-envelope\.json" "\$temporary\/envelope\.json"/);
  assert.match(writer,/verify_reserve_ratification\(\)/);
  assert.match(writer,/check-reserve-pin-ratification\.mjs "\$ratification_proposal"/);
  assert.match(writer,/replace-locked-source-stdin\.mjs "\$install_target" "\$candidate_sha256"[\s\S]*"\$contracts_directory_device" "\$contracts_directory_inode"[\s\S]*"\$python3_bin" "\$python3_sha256" <"\$candidate"/);
  assert.match(writer,/replacement_status=0[\s\S]*replace-locked-source-stdin\.mjs[\s\S]*\|\| replacement_status=\$\?[\s\S]*replacement_status == 80[\s\S]*if assert_installed_stable; then[\s\S]*else\n\s+exit 80/);
  assert.match(writer,/elif \(\( replacement_status != 0 \)\); then\n\s+exit "\$replacement_status"/);
  assert.match(writer,/cleanup\(\)[\s\S]*\(\( status != 0 \)\) \|\| status=1[\s\S]*exit "\$status"/);
  assert.doesNotMatch(writer,/else\n\s+status=1\n\s+fi\n\s+exit "\$status"/);
  assert.doesNotMatch(writer,/\bmv -T\b/);
  assert.equal((writer.match(/assert_installed_stable/g)??[]).length,4);
  assert.match(writer,/prepare-production-solidity-pins\.mjs "\$component" > "\$post_envelope"/);
  assert.match(writer,/cmp -s "\$post_candidate" "\$target"/);
  assert.match(writer,/sync -f \/proc\/self\/fd\/8\nassert_project_directories\nassert_installed_stable/);
  assert.doesNotMatch(writer,/\$target\.new/);
  execFileSync('bash',['-n',writerPath]);
  for(const args of [[],['both'],['foreign']]) {
    const result=spawnSync('bash',[writerPath,...args],{cwd:project,encoding:'utf8'});
    assert.equal(result.status,64,`args ${JSON.stringify(args)} must be rejected before preparation`);
    assert.match(result.stderr,/Usage:.*checkpointRegistry.*reserve RATIFICATION_PROPOSAL/);
  }
  const missing=spawnSync('bash',[writerPath,'reserve'],{cwd:project,encoding:'utf8'});
  assert.equal(missing.status,64); assert.match(missing.stderr,/RATIFICATION_PROPOSAL/);
});
