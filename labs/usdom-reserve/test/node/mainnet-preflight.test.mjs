import test from 'node:test';
import assert from 'node:assert/strict';
import {getCreateAddress} from 'ethers';
import {assessMainnetPreflight as assessPreflight,EMPTY_CODE_HASH} from '../../sdk/mainnet-preflight.mjs';
import {PINNED_RISC0_MAINNET_V3} from '../../sdk/risc0-verifier-reference.mjs';

const assessMainnetPreflight=args=>assessPreflight({
  ...args,riscZeroReference:{...PINNED_RISC0_MAINNET_V3},
});

const address=n=>'0x'+n.toString(16).padStart(40,'0');
const hash=n=>'0x'+n.toString(16).padStart(64,'0');

function release() {
  const deployer=address(1),deployerNonce='7',checkpointRegistryDeployer=address(2),checkpointRegistryDeployerNonce='9';
  const verifierDeployer=address(10),verifierDeployerNonce='3';
  const checkpointVerifierDeployer=address(11),checkpointVerifierDeployerNonce='4';
  return {ethereumChainId:'1',deploymentMethod:'CREATE',deployer,deployerNonce,
    reserve:getCreateAddress({from:deployer,nonce:BigInt(deployerNonce)}),
    reserveRuntimeCodeHash:hash(20),reserveInitcodeHash:hash(21),token:address(3),tokenCodeHash:hash(30),
    verifierDeployer,verifierDeployerNonce,
    verifier:getCreateAddress({from:verifierDeployer,nonce:BigInt(verifierDeployerNonce)}),
    verifierInitcodeHash:hash(24),
    verifierCodeHash:hash(40),verifierConfigHash:hash(41),reserveConfigHash:hash(42),domDomain:hash(43),
    activationScheduleCommitment:hash(54),
    checkpointRegistryDeployer,checkpointRegistryDeployerNonce,
    checkpointRegistry:getCreateAddress({from:checkpointRegistryDeployer,nonce:BigInt(checkpointRegistryDeployerNonce)}),
    checkpointRegistryRuntimeCodeHash:hash(22),checkpointRegistryInitcodeHash:hash(23),
    checkpointRegistryConfigHash:hash(44),checkpointVerifierDeployer,checkpointVerifierDeployerNonce,
    checkpointVerifier:getCreateAddress({from:checkpointVerifierDeployer,
      nonce:BigInt(checkpointVerifierDeployerNonce)}),checkpointVerifierInitcodeHash:hash(25),
    checkpointVerifierCodeHash:hash(45),
    checkpointVerifierConfigHash:hash(46),checkpointGuardian:address(8),checkpointGuardianCodeHash:hash(47),
    checkpointDomNetworkMagic:'3669344250',checkpointDomChainId:hash(55),checkpointFirstV4Height:'101',
    checkpointActivationEmptyStateRoot:hash(49),checkpointIntervalBlocks:'360',
    checkpointConfirmationDepthBlocks:'30',checkpointChallengePeriodSeconds:'172800',
    checkpointInitialHeight:'100',checkpointInitialBlock:hash(48),checkpointInitialStateRoot:hash(49),
    checkpointInitialContextHash:hash(51),
    checkpointInitialTotalDifficulty:'1000000',
    governance:address(5),governanceCodeHash:hash(50),guardian:address(6),guardianCodeHash:hash(60),
    withdrawalDelaySeconds:'86400',governanceDelaySeconds:'172800',maxOutstandingBaseUnits:'100000000000',
    outflowCapacityBaseUnitsPerDay:'2000000000'};
}

function baseObservation(config=release()) {
  return {chainId:'1',finalizedBlockNumber:'22000000',finalizedBlockHash:hash(70),
    snapshotBlockHashAfter:hash(70),deployerNonce:'7',
    checkpointRegistryDeployerNonce:'9',
    codeHashes:{reserve:EMPTY_CODE_HASH,token:config.tokenCodeHash,verifier:config.verifierCodeHash,
      governance:config.governanceCodeHash,guardian:config.guardianCodeHash,checkpointRegistry:EMPTY_CODE_HASH,
      checkpointVerifier:config.checkpointVerifierCodeHash,checkpointGuardian:config.checkpointGuardianCodeHash},
    verifierConfigHash:config.verifierConfigHash,checkpointVerifierConfigHash:config.checkpointVerifierConfigHash,
    riscZeroVerifier:{address:PINNED_RISC0_MAINNET_V3.verifier_address,
      codeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
      selector:PINNED_RISC0_MAINNET_V3.verifier_selector,version:PINNED_RISC0_MAINNET_V3.verifier_version},
    riscZeroEmergencyStop:{address:PINNED_RISC0_MAINNET_V3.emergency_stop_wrapper_address,
      codeHash:PINNED_RISC0_MAINNET_V3.emergency_stop_wrapper_runtime_code_hash,
      paused:false,verifier:PINNED_RISC0_MAINNET_V3.verifier_address},
    token:{decimals:'6',paused:false,deprecated:false,basisPointsRate:'0',maximumFee:'0',
      reserveBlacklisted:false,reserveBalance:'0'},
    finalizedBurnVerifierDeployment:{status:true,from:config.verifierDeployer,
      nonce:config.verifierDeployerNonce,creates:config.verifier,derivedCreateAddress:config.verifier,
      blockNumber:'21999997',
      blockHash:hash(75),canonicalBlockHash:hash(75),transactionHash:hash(76),to:null,value:'0',
      inputHash:config.verifierInitcodeHash},
    checkpointVerifierDeployment:{status:true,from:config.checkpointVerifierDeployer,
      nonce:config.checkpointVerifierDeployerNonce,creates:config.checkpointVerifier,
      derivedCreateAddress:config.checkpointVerifier,
      blockNumber:'21999996',blockHash:hash(77),canonicalBlockHash:hash(77),transactionHash:hash(78),
      to:null,value:'0',inputHash:config.checkpointVerifierInitcodeHash}};
}

function postObservation(config=release()) {
  const observation=baseObservation(config);
  observation.codeHashes.reserve=config.reserveRuntimeCodeHash;
  observation.codeHashes.checkpointRegistry=config.checkpointRegistryRuntimeCodeHash;
  observation.deployment={status:true,from:config.deployer,nonce:config.deployerNonce,creates:config.reserve,
    derivedCreateAddress:config.reserve,
    blockNumber:'21999999',blockHash:hash(71),canonicalBlockHash:hash(71),transactionHash:hash(73),to:null,value:'0',
    inputHash:config.reserveInitcodeHash};
  observation.checkpointRegistryDeployment={status:true,from:config.checkpointRegistryDeployer,
    nonce:config.checkpointRegistryDeployerNonce,creates:config.checkpointRegistry,
    derivedCreateAddress:config.checkpointRegistry,
    blockNumber:'21999998',blockHash:hash(72),canonicalBlockHash:hash(72),transactionHash:hash(74),to:null,value:'0',
    inputHash:config.checkpointRegistryInitcodeHash,checkpointEventCount:'1',checkpointEvent:{
      address:config.checkpointRegistry,bridgeDomain:config.domDomain,
      domNetworkMagic:config.checkpointDomNetworkMagic,domHeight:config.checkpointInitialHeight,
      domBlock:config.checkpointInitialBlock,domStateRoot:config.checkpointInitialStateRoot,
      checkpointConfigHash:config.checkpointRegistryConfigHash,
    }};
  observation.reserve={token:config.token,tokenCodeHash:config.tokenCodeHash,verifier:config.verifier,
    verifierCodeHash:config.verifierCodeHash,verifierConfigHash:config.verifierConfigHash,
    reserveConfigHash:config.reserveConfigHash,domDomain:config.domDomain,
    activationScheduleCommitment:config.activationScheduleCommitment,governance:config.governance,
    governanceCodeHash:config.governanceCodeHash,guardian:config.guardian,
    guardianCodeHash:config.guardianCodeHash,withdrawalDelay:config.withdrawalDelaySeconds,
    governanceDelay:config.governanceDelaySeconds,maxOutstanding:config.maxOutstandingBaseUnits,
    outflowCapacity:config.outflowCapacityBaseUnitsPerDay,paused:true,queueEpoch:'1',resumeReadyAt:'0',
    totalDeposited:'0',totalReleased:'0',totalPendingAmount:'0',pendingCount:'0'};
  observation.checkpointRegistry={checkpointConfigHash:config.checkpointRegistryConfigHash,
    bridgeDomain:config.domDomain,domNetworkMagic:config.checkpointDomNetworkMagic,
    domChainId:config.checkpointDomChainId,firstV4Height:config.checkpointFirstV4Height,
    activationEmptyStateRoot:config.checkpointActivationEmptyStateRoot,
    activationScheduleCommitment:config.activationScheduleCommitment,verifier:config.checkpointVerifier,
    checkpointInterval:config.checkpointIntervalBlocks,confirmationDepth:config.checkpointConfirmationDepthBlocks,
    challengePeriod:config.checkpointChallengePeriodSeconds,
    verifierCodeHash:config.checkpointVerifierCodeHash,verifierConfigHash:config.checkpointVerifierConfigHash,
    guardian:config.checkpointGuardian,guardianCodeHash:config.checkpointGuardianCodeHash,
    latestHeight:config.checkpointInitialHeight,checkpointCount:'1',halted:false,
    latestBlock:config.checkpointInitialBlock,latestStateRoot:config.checkpointInitialStateRoot,
    latestContextHash:config.checkpointInitialContextHash,
    latestTotalDifficulty:config.checkpointInitialTotalDifficulty};
  observation.checkpointRegistryCandidate={statementHash:hash(0),height:'0',readyAt:'0',blockHash:hash(0),
    stateRoot:hash(0),contextHash:hash(0),totalDifficulty:'0',confirmationHeight:'0',confirmationBlock:hash(0),
    confirmationTotalDifficulty:'0',confirmationTimestamp:'0'};
  observation.checkpointRegistrySlot0=config.checkpointRegistryConfigHash;
  return observation;
}

test('predeployment preflight accepts only the exact finalized empty address and release identities',()=>{
  const config=release();
  assert.equal(assessMainnetPreflight({phase:'predeployment',releaseConfig:config,
    observation:baseObservation(config)}).ready,true);
  const changes=[
    o=>{o.chainId='31337';},o=>{o.chainId=1;},o=>{o.extra=true;},o=>{o.token.extra=true;},
    o=>{o.finalizedBlockHash=hash(0);},o=>{o.snapshotBlockHashAfter=hash(71);},
    o=>{o.deployerNonce='8';},
    o=>{o.checkpointRegistryDeployerNonce='10';},
    o=>{o.finalizedBurnVerifierDeployment.inputHash=hash(99);},
    o=>{o.finalizedBurnVerifierDeployment.derivedCreateAddress=address(99);},
    o=>{delete o.checkpointVerifierDeployment.transactionHash;},
    o=>{o.finalizedBurnVerifierDeployment.extra=true;},
    o=>{o.codeHashes.reserve=hash(1);},o=>{o.codeHashes.verifier=hash(2);},
    o=>{o.codeHashes.checkpointRegistry=hash(3);},o=>{o.codeHashes.checkpointVerifier=hash(4);},
    o=>{o.codeHashes.checkpointGuardian=hash(5);},o=>{o.verifierConfigHash=hash(6);},
    o=>{o.checkpointVerifierConfigHash=hash(7);},o=>{o.token.paused=true;},o=>{o.token.deprecated=true;},
    o=>{o.riscZeroVerifier.address=address(99);},o=>{o.riscZeroVerifier.codeHash=hash(99);},
    o=>{o.riscZeroVerifier.selector='0x01020304';},o=>{o.riscZeroVerifier.version='other';},
    o=>{o.riscZeroEmergencyStop.address=address(99);},
    o=>{o.riscZeroEmergencyStop.codeHash=hash(99);},
    o=>{o.riscZeroEmergencyStop.verifier=address(99);},o=>{o.riscZeroEmergencyStop.paused=true;},
    o=>{o.token.basisPointsRate='1';},o=>{o.token.maximumFee='1';},o=>{o.token.reserveBlacklisted=true;},
    o=>{o.token.reserveBalance='1';},
  ];
  for(const change of changes) {
    const observation=baseObservation(config); change(observation);
    assert.equal(assessMainnetPreflight({phase:'predeployment',releaseConfig:config,observation}).ready,false);
  }
  const invalidPlan=release(); invalidPlan.reserve=address(9);
  assert.equal(assessMainnetPreflight({phase:'predeployment',releaseConfig:invalidPlan,
    observation:baseObservation(invalidPlan)}).ready,false);
  const invalidRegistryPlan=release(); invalidRegistryPlan.checkpointRegistry=address(9);
  assert.equal(assessMainnetPreflight({phase:'predeployment',releaseConfig:invalidRegistryPlan,
    observation:baseObservation(invalidRegistryPlan)}).ready,false);
  const invalidVerifierPlan=release(); invalidVerifierPlan.verifier=address(9);
  assert.equal(assessMainnetPreflight({phase:'predeployment',releaseConfig:invalidVerifierPlan,
    observation:baseObservation(invalidVerifierPlan)}).ready,false);
  const invalidCheckpointVerifierPlan=release(); invalidCheckpointVerifierPlan.checkpointVerifier=address(9);
  assert.equal(assessMainnetPreflight({phase:'predeployment',releaseConfig:invalidCheckpointVerifierPlan,
    observation:baseObservation(invalidCheckpointVerifierPlan)}).ready,false);
  const numericReleaseChain=release(); numericReleaseChain.ethereumChainId=1;
  assert.equal(assessMainnetPreflight({phase:'predeployment',releaseConfig:numericReleaseChain,
    observation:baseObservation(numericReleaseChain)}).ready,false);
  const changedReference={...PINNED_RISC0_MAINNET_V3,verifier_address:address(99)};
  assert.equal(assessPreflight({phase:'predeployment',releaseConfig:config,
    observation:baseObservation(config),riscZeroReference:changedReference}).ready,false);
});

test('postdeployment preflight binds transaction, runtime, immutables and empty paused cold start',()=>{
  const config=release();
  assert.equal(assessMainnetPreflight({phase:'postdeployment',releaseConfig:config,
    observation:postObservation(config)}).ready,true);
  const changes=[
    o=>{o.snapshotBlockHashAfter=hash(71);},o=>{o.codeHashes.reserve=hash(21);},
    o=>{o.finalizedBurnVerifierDeployment.status=false;},
    o=>{o.finalizedBurnVerifierDeployment.from=address(9);},
    o=>{o.finalizedBurnVerifierDeployment.nonce='4';},
    o=>{o.finalizedBurnVerifierDeployment.creates=address(9);},
    o=>{o.finalizedBurnVerifierDeployment.derivedCreateAddress=address(9);},
    o=>{o.finalizedBurnVerifierDeployment.to=address(9);},
    o=>{o.finalizedBurnVerifierDeployment.value='1';},
    o=>{o.finalizedBurnVerifierDeployment.inputHash=hash(99);},
    o=>{o.finalizedBurnVerifierDeployment.transactionHash=hash(0);},
    o=>{o.finalizedBurnVerifierDeployment.blockHash=hash(99);},
    o=>{o.finalizedBurnVerifierDeployment.blockNumber='22000001';},
    o=>{o.finalizedBurnVerifierDeployment.extra=true;},
    o=>{o.checkpointVerifierDeployment.status=false;},
    o=>{o.checkpointVerifierDeployment.from=address(9);},
    o=>{o.checkpointVerifierDeployment.nonce='5';},
    o=>{o.checkpointVerifierDeployment.creates=address(9);},
    o=>{o.checkpointVerifierDeployment.derivedCreateAddress=address(9);},
    o=>{o.checkpointVerifierDeployment.to=address(9);},
    o=>{o.checkpointVerifierDeployment.value='1';},
    o=>{o.checkpointVerifierDeployment.inputHash=hash(99);},
    o=>{delete o.checkpointVerifierDeployment.transactionHash;},
    o=>{o.checkpointVerifierDeployment.blockHash=hash(99);},
    o=>{o.checkpointVerifierDeployment.blockNumber='22000001';},
    o=>{o.checkpointVerifierDeployment.extra=true;},
    o=>{o.deployment.status=false;},o=>{o.deployment.from=address(9);},
    o=>{o.deployment.nonce='8';},o=>{o.deployment.creates=address(9);},
    o=>{o.deployment.derivedCreateAddress=address(9);},
    o=>{o.deployment.to=address(9);},o=>{o.deployment.value='1';},o=>{o.deployment.inputHash=hash(22);},
    o=>{delete o.deployment.transactionHash;},o=>{o.deployment.transactionHash=hash(0);},
    o=>{o.deployment.extra=true;},
    o=>{o.deployment.blockHash=hash(72);},o=>{o.deployment.blockNumber='22000001';},
    o=>{o.reserve.reserveConfigHash=hash(99);},
    o=>{o.reserve.activationScheduleCommitment=hash(99);},
    o=>{o.reserve.governance=address(9);},o=>{o.reserve.governanceCodeHash=hash(99);},
    o=>{o.reserve.withdrawalDelay='1';},o=>{o.reserve.paused=false;},o=>{o.reserve.queueEpoch='2';},
    o=>{o.reserve.resumeReadyAt='1';},o=>{o.reserve.totalDeposited='1';},o=>{o.token.reserveBalance='1';},
    o=>{o.codeHashes.checkpointRegistry=hash(24);},o=>{o.checkpointRegistryDeployment.status=false;},
    o=>{o.checkpointRegistryDeployment.from=address(9);},o=>{o.checkpointRegistryDeployment.nonce='10';},
    o=>{o.checkpointRegistryDeployment.creates=address(9);},
    o=>{o.checkpointRegistryDeployment.derivedCreateAddress=address(9);},
    o=>{o.checkpointRegistryDeployment.to=address(9);},o=>{o.checkpointRegistryDeployment.value='1';},
    o=>{o.checkpointRegistryDeployment.inputHash=hash(25);},
    o=>{delete o.checkpointRegistryDeployment.transactionHash;},
    o=>{o.checkpointRegistryDeployment.transactionHash='invalid';},
    o=>{o.checkpointRegistryDeployment.checkpointEvent.extra=true;},
    o=>{o.checkpointRegistryDeployment.blockHash=hash(73);},
    o=>{o.checkpointRegistryDeployment.blockNumber='22000001';},
    o=>{o.checkpointRegistryDeployment.checkpointEventCount='2';},
    o=>{o.checkpointRegistryDeployment.checkpointEvent.address=address(9);},
    o=>{o.checkpointRegistryDeployment.checkpointEvent.bridgeDomain=hash(80);},
    o=>{o.checkpointRegistryDeployment.checkpointEvent.domNetworkMagic='1';},
    o=>{o.checkpointRegistryDeployment.checkpointEvent.domHeight='101';},
    o=>{o.checkpointRegistryDeployment.checkpointEvent.domBlock=hash(81);},
    o=>{o.checkpointRegistryDeployment.checkpointEvent.domStateRoot=hash(82);},
    o=>{o.checkpointRegistryDeployment.checkpointEvent.checkpointConfigHash=hash(83);},
    o=>{o.checkpointRegistry.checkpointConfigHash=hash(90);},
    o=>{o.checkpointRegistry.domChainId=hash(90);},
    o=>{o.checkpointRegistry.firstV4Height='102';},
    o=>{o.checkpointRegistry.checkpointInterval='359';},o=>{o.checkpointRegistry.confirmationDepth='29';},
    o=>{o.checkpointRegistry.challengePeriod='172801';},
    o=>{o.checkpointRegistry.activationEmptyStateRoot=hash(90);},
    o=>{o.checkpointRegistry.bridgeDomain=hash(91);},o=>{o.checkpointRegistry.domNetworkMagic='1';},
    o=>{o.checkpointRegistry.activationScheduleCommitment=hash(92);},
    o=>{o.checkpointRegistry.verifier=address(9);},o=>{o.checkpointRegistry.verifierCodeHash=hash(93);},
    o=>{o.checkpointRegistry.verifierConfigHash=hash(94);},o=>{o.checkpointRegistry.guardian=address(9);},
    o=>{o.checkpointRegistry.guardianCodeHash=hash(95);},
    o=>{o.checkpointRegistry.latestHeight='101';},o=>{o.checkpointRegistry.latestBlock=hash(92);},
    o=>{o.checkpointRegistry.latestStateRoot=hash(93);},o=>{o.checkpointRegistry.latestTotalDifficulty='1000001';},
    o=>{o.checkpointRegistry.checkpointCount='2';},
    o=>{o.checkpointRegistryCandidate.statementHash=hash(1);},
    o=>{o.checkpointRegistry.halted=true;},o=>{o.checkpointRegistrySlot0=hash(94);},
  ];
  for(const change of changes) {
    const observation=postObservation(config); change(observation);
    assert.equal(assessMainnetPreflight({phase:'postdeployment',releaseConfig:config,observation}).ready,false);
  }
  assert.throws(()=>assessMainnetPreflight({phase:'other',releaseConfig:config,observation:{}}),/phase/);
});

test('observed uints must use canonical unsigned decimal strings',()=>{
  const config=release();
  for(const value of [null,false,'',' ','0x0','00',0,-0]) {
    const observation=postObservation(config);
    observation.reserve.resumeReadyAt=value;
    assert.equal(assessMainnetPreflight({phase:'postdeployment',releaseConfig:config,observation}).ready,false,
      `zero substitute ${String(value)} (${typeof value})`);
  }
  for(const value of [true,'01','0x1',1,1n]) {
    const observation=postObservation(config);
    observation.reserve.queueEpoch=value;
    assert.equal(assessMainnetPreflight({phase:'postdeployment',releaseConfig:config,observation}).ready,false,
      `one substitute ${String(value)} (${typeof value})`);
  }
  const eventCount=postObservation(config);
  eventCount.checkpointRegistryDeployment.checkpointEventCount=1;
  assert.equal(assessMainnetPreflight({phase:'postdeployment',releaseConfig:config,
    observation:eventCount}).ready,false);
});
