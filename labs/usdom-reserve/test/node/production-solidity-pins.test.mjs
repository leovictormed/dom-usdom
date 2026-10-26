import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {materializeProductionSolidityPins} from '../../sdk/production-solidity-pins.mjs';
import {execFileSync} from 'node:child_process';

const hash=byte=>'0x'+byte.repeat(64);
const address=byte=>'0x'+byte.repeat(40);
const release={ethereumChainId:'1',productionReady:false,realFundsAuthorized:false,
  verifierCodeHash:hash('1'),verifierConfigHash:hash('2'),reserveConfigHash:hash('3'),
  checkpointVerifierCodeHash:hash('4'),checkpointVerifierConfigHash:hash('5'),
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

test('writer binds configuration and both source inputs before replacement',()=>{
  const writer=readFileSync(new URL('../../scripts/materialize-production-solidity-pins.sh',import.meta.url),'utf8');
  assert.match(writer,/exec 9<"\$project\/config"/);
  assert.match(writer,/exec 8<"\$project\/contracts"/);
  assert.equal((writer.match(/sha256sum "\$config"/g)??[]).length,3);
  assert.match(writer,/cmp -s "\$temporary\/reserve\.sol" "\$reserve"/);
  assert.match(writer,/cmp -s "\$temporary\/registry\.sol" "\$registry"/);
  execFileSync('bash',['-n',new URL('../../scripts/materialize-production-solidity-pins.sh',import.meta.url).pathname]);
});
