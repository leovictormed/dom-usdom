import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {getCreateAddress} from 'ethers';
import {assessMainnetPreflight as assessPreflight,EMPTY_CODE_HASH,ETHEREUM_MAINNET_USDT,
  ETHEREUM_MAINNET_USDT_CODE_HASH,ETHEREUM_MAINNET_GENESIS_BLOCK_HASH} from '../../sdk/mainnet-preflight.mjs';
import {prepareMainnetPreflightMaterialization} from '../../sdk/mainnet-preflight-materialization.mjs';
import {PINNED_RISC0_MAINNET_V3} from '../../sdk/risc0-verifier-reference.mjs';
import {SAFE_MAINNET_IDENTITY} from '../../sdk/safe-control-deployment.mjs';
import {rpcConsensusEvidence} from '../../sdk/rpc-consensus-evidence.mjs';
import {safeOwnersCommitment} from '../../sdk/configuration.mjs';
import {FINALIZED_BURN_PROOF_ACCEPTED_HASH} from '../../sdk/verifier-config.mjs';
import {CHECKPOINT_PROOF_ACCEPTED_HASH} from '../../sdk/checkpoint-verifier-config.mjs';

const assessMainnetPreflight=args=>assessPreflight({
  ...args,riscZeroReference:{...PINNED_RISC0_MAINNET_V3},
});

test('cold-start collector uses one atomic queue snapshot and does not traverse an empty queue',()=>{
  const script=readFileSync(new URL('../../scripts/check-mainnet-preflight.mjs',import.meta.url),'utf8');
  assert.ok(script.includes('reserve.pendingQueueSnapshot(callOptions)'));
  assert.ok(script.includes("const adapterNames=['riscZeroVerifier','riscZeroVerifierCodeHash'"));
  assert.ok(script.includes("'function availableOutflow() view returns (uint256)'"));
  assert.ok(script.includes('function pendingBurnPage(uint64 expectedQueueEpoch'));
  for(const getter of ['pendingCount','totalPendingAmount','firstPendingBurn','lastPendingBurn']) {
    assert.ok(!script.includes(`'${getter}'`),getter);
  }
  assert.ok(!script.includes('reserve.pendingBurnPage('));
});

test('pilot executor rechecks live multisource authorities before its first signature prompt',()=>{
  const source=readFileSync(new URL('../../scripts/execute-closed-mainnet-deposit.sh',import.meta.url),'utf8');
  assert.match(source,/check-mainnet-preflight\.mjs authority-recheck/);
  assert.match(source,/if \[\[ \$index == 0 \]\]; then recheck_live_authorities; fi[\s\S]*?AUTORIZO ASSINAR/);
  assert.match(source,/AUTORIZO ASSINAR[\s\S]*?test "\$answer"[\s\S]*?recheck_live_authorities[\s\S]*?cast mktx/);
  assert.match(source,/AUTORIZO TRANSMITIR[\s\S]*?test "\$answer"[\s\S]*?recheck_live_authorities[\s\S]*?publish-private-raw-transaction/);
});

const materializationInputs=(phase,observation)=>{
  const releaseConfig=release();
  const result=assessMainnetPreflight({phase,releaseConfig,observation});
  const rpcConsensus=rpcConsensusEvidence([
    {sourceId:'operator-a',originKeccak256:'0x'+'11'.repeat(32)},
    {sourceId:'operator-b',originKeccak256:'0x'+'22'.repeat(32)},
  ]);
  return {phase,report:{...result,observation,rpcConsensus},releaseConfig,
    riscZeroReference:{...PINNED_RISC0_MAINNET_V3},
    evidence:{mainnetPredeploymentAttestationReport:null,mainnetColdStartAttestationReport:null},
    requirements:{production_mainnet_predeployment_preflight_passed:false,
      production_mainnet_cold_start_attestation_completed:false}};
};

const address=n=>'0x'+n.toString(16).padStart(40,'0');
const hash=n=>'0x'+n.toString(16).padStart(64,'0');

function release() {
  const deployer=address(1),deployerNonce='7',checkpointRegistryDeployer=address(2),checkpointRegistryDeployerNonce='9';
  const verifierDeployer=address(10),verifierDeployerNonce='3';
  const checkpointVerifierDeployer=address(11),checkpointVerifierDeployerNonce='4';
  return {productionReady:true,realFundsAuthorized:false,
    ethereumChainId:'1',deploymentMethod:'CREATE',deployer,deployerNonce,
    reserve:getCreateAddress({from:deployer,nonce:BigInt(deployerNonce)}),
    reserveRuntimeCodeHash:hash(20),reserveInitcodeHash:hash(21),token:ETHEREUM_MAINNET_USDT,
    tokenCodeHash:ETHEREUM_MAINNET_USDT_CODE_HASH,tokenOwner:address(77),tokenOwnerCodeHash:EMPTY_CODE_HASH,
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
    checkpointGuardianImplementation:address(18),checkpointGuardianImplementationCodeHash:hash(57),
    checkpointDomNetworkMagic:'3669344250',checkpointDomChainId:hash(55),checkpointFirstV4Height:'101',
    checkpointActivationEmptyStateRoot:hash(49),checkpointIntervalBlocks:'360',
    checkpointConfirmationDepthBlocks:'30',checkpointChallengePeriodSeconds:'172800',
    checkpointInitialHeight:'100',checkpointInitialBlock:hash(48),checkpointInitialStateRoot:hash(49),
    checkpointInitialContextHash:hash(51),
    checkpointInitialTotalDifficulty:'1000000',
    governance:address(5),governanceCodeHash:hash(50),governanceImplementation:address(15),
    governanceImplementationCodeHash:hash(51),guardian:address(6),guardianCodeHash:hash(60),
    guardianImplementation:address(16),guardianImplementationCodeHash:hash(61),
    governanceOwners:[address(101),address(102),address(103)],
    guardianOwners:[address(104),address(105),address(106)],
    checkpointGuardianOwners:[address(107),address(108),address(109)],
    governanceOwnersCommitment:safeOwnersCommitment([address(101),address(102),address(103)]),
    guardianOwnersCommitment:safeOwnersCommitment([address(104),address(105),address(106)]),
    withdrawalDelaySeconds:'86400',governanceDelaySeconds:'172800',maxOutstandingBaseUnits:'100000000000',
    outflowCapacityBaseUnitsPerDay:'2000000000'};
}

function baseObservation(config=release()) {
  return {chainId:'1',genesisBlockHash:ETHEREUM_MAINNET_GENESIS_BLOCK_HASH,
    finalizedBlockNumber:'22000000',finalizedBlockHash:hash(70),
    snapshotBlockHashAfter:hash(70),deployerNonce:'7',
    checkpointRegistryDeployerNonce:'9',
    codeHashes:{reserve:EMPTY_CODE_HASH,token:config.tokenCodeHash,verifier:config.verifierCodeHash,
      governance:config.governanceCodeHash,guardian:config.guardianCodeHash,checkpointRegistry:EMPTY_CODE_HASH,
      governanceImplementation:config.governanceImplementationCodeHash,
      guardianImplementation:config.guardianImplementationCodeHash,
      checkpointVerifier:config.checkpointVerifierCodeHash,checkpointGuardian:config.checkpointGuardianCodeHash,
      checkpointGuardianImplementation:config.checkpointGuardianImplementationCodeHash},
    verifierConfigHash:config.verifierConfigHash,checkpointVerifierConfigHash:config.checkpointVerifierConfigHash,
    verifierProofAccepted:FINALIZED_BURN_PROOF_ACCEPTED_HASH,
    checkpointVerifierProofAccepted:CHECKPOINT_PROOF_ACCEPTED_HASH,
    finalizedBurnVerifier:{address:config.verifier,riscZeroVerifier:PINNED_RISC0_MAINNET_V3.verifier_address,
      riscZeroVerifierCodeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
      verifierSelector:PINNED_RISC0_MAINNET_V3.verifier_selector,imageId:hash(91),deploymentChainId:'1',
      verifierConfigHash:config.verifierConfigHash,proofAccepted:FINALIZED_BURN_PROOF_ACCEPTED_HASH},
    checkpointVerifier:{address:config.checkpointVerifier,riscZeroVerifier:PINNED_RISC0_MAINNET_V3.verifier_address,
      riscZeroVerifierCodeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
      verifierSelector:PINNED_RISC0_MAINNET_V3.verifier_selector,imageId:hash(92),deploymentChainId:'1',
      verifierConfigHash:config.checkpointVerifierConfigHash,proofAccepted:CHECKPOINT_PROOF_ACCEPTED_HASH},
    controlPlaneImplementations:{governance:config.governanceImplementation,
      guardian:config.guardianImplementation,checkpointGuardian:config.checkpointGuardianImplementation},
    controlPlanePolicies:{
      governance:{nonce:'0',threshold:'2',owners:[address(101),address(102),address(103)],
        ownerCodeHashes:[EMPTY_CODE_HASH,EMPTY_CODE_HASH,EMPTY_CODE_HASH],modules:[],modulesNext:address(1),guard:address(0),
        fallbackHandler:SAFE_MAINNET_IDENTITY.fallbackHandler,
        fallbackHandlerCodeHash:SAFE_MAINNET_IDENTITY.fallbackHandlerCodeHash},
      guardian:{nonce:'0',threshold:'2',owners:[address(104),address(105),address(106)],
        ownerCodeHashes:[EMPTY_CODE_HASH,EMPTY_CODE_HASH,EMPTY_CODE_HASH],modules:[],modulesNext:address(1),guard:address(0),
        fallbackHandler:SAFE_MAINNET_IDENTITY.fallbackHandler,
        fallbackHandlerCodeHash:SAFE_MAINNET_IDENTITY.fallbackHandlerCodeHash},
      checkpointGuardian:{nonce:'0',threshold:'2',owners:[address(107),address(108),address(109)],modules:[],
        ownerCodeHashes:[EMPTY_CODE_HASH,EMPTY_CODE_HASH,EMPTY_CODE_HASH],modulesNext:address(1),guard:address(0),
        fallbackHandler:SAFE_MAINNET_IDENTITY.fallbackHandler,
        fallbackHandlerCodeHash:SAFE_MAINNET_IDENTITY.fallbackHandlerCodeHash},
    },
    riscZeroVerifier:{address:PINNED_RISC0_MAINNET_V3.verifier_address,
      codeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
      selector:PINNED_RISC0_MAINNET_V3.verifier_selector,version:PINNED_RISC0_MAINNET_V3.verifier_version},
    riscZeroEmergencyStop:{address:PINNED_RISC0_MAINNET_V3.emergency_stop_wrapper_address,
      codeHash:PINNED_RISC0_MAINNET_V3.emergency_stop_wrapper_runtime_code_hash,
      paused:false,verifier:PINNED_RISC0_MAINNET_V3.verifier_address},
    token:{name:'Tether USD',symbol:'USDT',decimals:'6',totalSupply:'1000000000000',owner:address(77),
      ownerCodeHash:EMPTY_CODE_HASH,paused:false,deprecated:false,upgradedAddress:address(0),
      basisPointsRate:'0',maximumFee:'0',reserveBlacklisted:false,reserveBalance:'0',
      eip1967Implementation:hash(0),eip1967Admin:hash(0),eip1967Beacon:hash(0)},
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
    governanceImplementation:config.governanceImplementation,
    governanceImplementationCodeHash:config.governanceImplementationCodeHash,
    governanceOwnersCommitment:config.governanceOwnersCommitment,
    guardianCodeHash:config.guardianCodeHash,guardianImplementation:config.guardianImplementation,
    guardianImplementationCodeHash:config.guardianImplementationCodeHash,
    guardianOwnersCommitment:config.guardianOwnersCommitment,
    withdrawalDelay:config.withdrawalDelaySeconds,
    governanceDelay:config.governanceDelaySeconds,maxOutstanding:config.maxOutstandingBaseUnits,
    outflowCapacity:config.outflowCapacityBaseUnitsPerDay,paused:true,depositsClosed:false,
    gracefullyShutdown:false,resumeReadyAt:'0',
    totalDeposited:'0',totalReleased:'0',totalProvedDebtAmount:'0',
    pendingQueue:{epoch:'1',count:'0',amount:'0',firstBurnId:hash(0),lastBurnId:hash(0)},
    outstanding:'0',unreservedCollateral:'0',availableOutflow:config.outflowCapacityBaseUnitsPerDay,
    controlPlaneHealthy:true};
  observation.checkpointRegistry={checkpointConfigHash:config.checkpointRegistryConfigHash,
    bridgeDomain:config.domDomain,domNetworkMagic:config.checkpointDomNetworkMagic,
    domChainId:config.checkpointDomChainId,firstV4Height:config.checkpointFirstV4Height,
    activationEmptyStateRoot:config.checkpointActivationEmptyStateRoot,
    activationScheduleCommitment:config.activationScheduleCommitment,verifier:config.checkpointVerifier,
    checkpointInterval:config.checkpointIntervalBlocks,confirmationDepth:config.checkpointConfirmationDepthBlocks,
    challengePeriod:config.checkpointChallengePeriodSeconds,
    verifierCodeHash:config.checkpointVerifierCodeHash,verifierConfigHash:config.checkpointVerifierConfigHash,
    guardian:config.checkpointGuardian,guardianCodeHash:config.checkpointGuardianCodeHash,
    guardianImplementation:config.checkpointGuardianImplementation,
    guardianImplementationCodeHash:config.checkpointGuardianImplementationCodeHash,
    guardianOwnersCommitment:safeOwnersCommitment(config.checkpointGuardianOwners),
    latestHeight:config.checkpointInitialHeight,checkpointCount:'1',halted:false,gracefullyShutdown:false,
    latestIssuanceClosed:false,
    latestBlock:config.checkpointInitialBlock,latestStateRoot:config.checkpointInitialStateRoot,
    latestContextHash:config.checkpointInitialContextHash,
    latestTotalDifficulty:config.checkpointInitialTotalDifficulty,latestTotalIssued:'0',latestTotalBurned:'0',
    previousTotalIssued:'0',previousTotalBurned:'0',guardianControlHealthy:true};
  observation.checkpointRegistryCandidate={statementHash:hash(0),height:'0',readyAt:'0',blockHash:hash(0),
    stateRoot:hash(0),contextHash:hash(0),totalDifficulty:'0',totalIssued:'0',totalBurned:'0',
    issuanceClosed:false,confirmationHeight:'0',confirmationBlock:hash(0),
    confirmationTotalDifficulty:'0',confirmationTimestamp:'0'};
  observation.checkpointRegistrySlot0=config.checkpointRegistryConfigHash;
  return observation;
}

test('preflight accepts three distinct owner trios across distinct role Safes',()=>{
  const config=release();
  const observation=baseObservation(config);
  assert.notEqual(config.governance.toLowerCase(),config.guardian.toLowerCase());
  assert.notEqual(config.governance.toLowerCase(),config.checkpointGuardian.toLowerCase());
  assert.notEqual(config.guardian.toLowerCase(),config.checkpointGuardian.toLowerCase());
  assert.equal(new Set(Object.values(observation.controlPlanePolicies).flatMap(value=>value.owners)).size,9);
  assert.equal(assessMainnetPreflight({phase:'predeployment',releaseConfig:config,observation}).ready,true);
});

test('authority recheck binds current Safes and USDT immediately before the first signature',()=>{
  const config=release();
  const observation=baseObservation(config);
  observation.codeHashes.reserve=config.reserveRuntimeCodeHash;
  observation.codeHashes.checkpointRegistry=config.checkpointRegistryRuntimeCodeHash;
  assert.equal(assessMainnetPreflight({phase:'authority-recheck',releaseConfig:config,observation}).ready,true);
  for(const change of [
    value=>{value.controlPlanePolicies.governance.nonce='1';},
    value=>{value.controlPlanePolicies.guardian.modules=[address(99)];},
    value=>{value.controlPlanePolicies.checkpointGuardian.guard=address(99);},
    value=>{value.token.paused=true;},value=>{value.token.deprecated=true;},
    value=>{value.token.maximumFee='1';},value=>{value.token.reserveBlacklisted=true;},
    value=>{value.token.reserveBalance='1';},value=>{value.genesisBlockHash=hash(99);},
  ]) {
    const changed=structuredClone(observation); change(changed);
    assert.equal(assessMainnetPreflight({phase:'authority-recheck',releaseConfig:config,
      observation:changed}).ready,false);
  }
});

test('preflight accepts either explicit fund-authorization state but rejects unconfigured drift',()=>{
  for(const authorized of [false,true]) {
    const config={...release(),realFundsAuthorized:authorized};
    assert.equal(assessMainnetPreflight({phase:'predeployment',releaseConfig:config,
      observation:baseObservation(config)}).ready,true);
  }
  for(const realFundsAuthorized of [null,'false',0]) {
    const config={...release(),realFundsAuthorized};
    const report=assessMainnetPreflight({phase:'predeployment',releaseConfig:config,
      observation:baseObservation(config)});
    assert.equal(report.ready,false);
    assert(report.blockers.some(value=>value.code==='release_plan_invalid'));
  }
});

test('predeployment preflight accepts only the exact finalized empty address and release identities',()=>{
  const config=release();
  assert.equal(assessMainnetPreflight({phase:'predeployment',releaseConfig:config,
    observation:baseObservation(config)}).ready,true);
  const changes=[
    o=>{o.chainId='31337';},o=>{o.chainId=1;},o=>{o.genesisBlockHash=hash(99);},
    o=>{o.extra=true;},o=>{o.token.extra=true;},
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
    o=>{o.verifierProofAccepted=hash(7);},o=>{o.checkpointVerifierProofAccepted=hash(8);},
    o=>{o.controlPlaneImplementations.governance=address(99);},
    o=>{o.controlPlaneImplementations.guardian=address(99);},
    o=>{o.controlPlaneImplementations.checkpointGuardian=address(99);},
    o=>{o.controlPlanePolicies.governance.threshold='1';},
    o=>{o.controlPlanePolicies.governance.nonce='1';},
    o=>{o.controlPlanePolicies.governance.owners[2]=address(104);},
    o=>{o.controlPlanePolicies.guardian.owners.reverse();},
    o=>{o.controlPlanePolicies.guardian.owners.pop();},
    o=>{o.controlPlanePolicies.checkpointGuardian.modules=[address(99)];},
    o=>{o.controlPlanePolicies.governance.owners[1]=o.controlPlanePolicies.governance.owners[0];},
    o=>{o.controlPlanePolicies.guardian.modulesNext=address(2);},
    o=>{o.controlPlanePolicies.checkpointGuardian.ownerCodeHashes[1]=hash(99);},
    o=>{o.controlPlanePolicies.governance.guard=address(99);},
    o=>{o.controlPlanePolicies.guardian.fallbackHandler=address(99);},
    o=>{o.controlPlanePolicies.checkpointGuardian.fallbackHandlerCodeHash=hash(99);},
    o=>{o.checkpointVerifierConfigHash=hash(7);},o=>{o.token.paused=true;},o=>{o.token.deprecated=true;},
    o=>{o.riscZeroVerifier.address=address(99);},o=>{o.riscZeroVerifier.codeHash=hash(99);},
    o=>{o.riscZeroVerifier.selector='0x01020304';},o=>{o.riscZeroVerifier.version='other';},
    o=>{o.riscZeroEmergencyStop.address=address(99);},
    o=>{o.riscZeroEmergencyStop.codeHash=hash(99);},
    o=>{o.riscZeroEmergencyStop.verifier=address(99);},o=>{o.riscZeroEmergencyStop.paused=true;},
    o=>{o.token.name='US Dollar';},o=>{o.token.symbol='USD';},o=>{o.token.totalSupply='0';},
    o=>{o.token.owner=address(0);},o=>{o.token.ownerCodeHash='bad';},o=>{o.token.upgradedAddress=address(99);},
    o=>{o.token.eip1967Implementation=hash(99);},o=>{o.token.eip1967Admin=hash(99);},
    o=>{o.token.eip1967Beacon=hash(99);},o=>{o.token.basisPointsRate='1';},
    o=>{o.token.maximumFee='1';},o=>{o.token.reserveBlacklisted=true;},
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
  const changedTokenOwner=release(); changedTokenOwner.tokenOwner=address(88);
  assert.equal(assessMainnetPreflight({phase:'predeployment',releaseConfig:changedTokenOwner,
    observation:baseObservation(changedTokenOwner)}).ready,false);
  const reusedSafe=release(); reusedSafe.guardian=reusedSafe.governance;
  assert.equal(assessMainnetPreflight({phase:'predeployment',releaseConfig:reusedSafe,
    observation:baseObservation(reusedSafe)}).ready,false);
  for(const field of ['verifierInitcodeHash','checkpointVerifierCodeHash',
    'checkpointRegistryConfigHash','reserveRuntimeCodeHash']) {
    const partialRelease=release(); partialRelease[field]=null;
    assert.equal(assessMainnetPreflight({phase:'predeployment',releaseConfig:partialRelease,
      observation:baseObservation(partialRelease)}).ready,false,field);
  }
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
    o=>{o.finalizedBurnVerifier.riscZeroVerifier=address(99);},
    o=>{o.finalizedBurnVerifier.riscZeroVerifierCodeHash=hash(99);},
    o=>{o.finalizedBurnVerifier.verifierSelector='0x00000000';},
    o=>{o.finalizedBurnVerifier.imageId=hash(0);},
    o=>{o.finalizedBurnVerifier.deploymentChainId='2';},
    o=>{o.checkpointVerifier.verifierConfigHash=hash(99);},
    o=>{o.checkpointVerifier.proofAccepted=hash(99);},
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
    o=>{o.reserve.withdrawalDelay='1';},o=>{o.reserve.paused=false;},o=>{o.reserve.depositsClosed=true;},
    o=>{o.reserve.gracefullyShutdown=true;},o=>{o.reserve.pendingQueue.epoch='2';},
    o=>{o.reserve.controlPlaneHealthy=false;},
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
    o=>{o.checkpointRegistry.guardianImplementation=address(9);},
    o=>{o.checkpointRegistry.guardianImplementationCodeHash=hash(96);},
    o=>{o.checkpointRegistry.guardianOwnersCommitment=hash(97);},
    o=>{o.checkpointRegistry.latestHeight='101';},o=>{o.checkpointRegistry.latestBlock=hash(92);},
    o=>{o.checkpointRegistry.latestStateRoot=hash(93);},o=>{o.checkpointRegistry.latestTotalDifficulty='1000001';},
    o=>{o.checkpointRegistry.gracefullyShutdown=true;},o=>{o.checkpointRegistry.latestIssuanceClosed=true;},
    o=>{o.checkpointRegistry.latestTotalIssued='1';},o=>{o.checkpointRegistry.latestTotalBurned='1';},
    o=>{o.checkpointRegistry.previousTotalIssued='1';},o=>{o.checkpointRegistry.previousTotalBurned='1';},
    o=>{o.checkpointRegistry.checkpointCount='2';},
    o=>{o.checkpointRegistry.guardianControlHealthy=false;},
    o=>{o.reserve.pendingQueue.firstBurnId=hash(1);},o=>{o.reserve.pendingQueue.lastBurnId=hash(1);},
    o=>{o.reserve.pendingQueue.count='1';},o=>{o.reserve.pendingQueue.amount='1';},
    o=>{o.reserve.outstanding='1';},o=>{o.reserve.unreservedCollateral='1';},
    o=>{o.reserve.availableOutflow='1';},
    o=>{o.checkpointRegistryCandidate.statementHash=hash(1);},
    o=>{o.checkpointRegistryCandidate.totalIssued='1';},o=>{o.checkpointRegistryCandidate.totalBurned='1';},
    o=>{o.checkpointRegistryCandidate.issuanceClosed=true;},
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
    observation.reserve.pendingQueue.epoch=value;
    assert.equal(assessMainnetPreflight({phase:'postdeployment',releaseConfig:config,observation}).ready,false,
      `one substitute ${String(value)} (${typeof value})`);
  }
  const eventCount=postObservation(config);
  eventCount.checkpointRegistryDeployment.checkpointEventCount=1;
  assert.equal(assessMainnetPreflight({phase:'postdeployment',releaseConfig:config,
    observation:eventCount}).ready,false);
  for(const value of ['9'.repeat(79),(1n<<256n).toString()]) {
    const observation=postObservation(config);
    observation.token.totalSupply=value;
    assert.equal(assessMainnetPreflight({phase:'postdeployment',releaseConfig:config,
      observation}).ready,false,'oversized uint256 must fail before BigInt work');
  }
  const oversizedHeight=postObservation(config);
  oversizedHeight.finalizedBlockNumber=(1n<<64n).toString();
  assert.equal(assessMainnetPreflight({phase:'postdeployment',releaseConfig:config,
    observation:oversizedHeight}).ready,false);
  const oversizedNonceConfig=release();
  const oversizedNonceObservation=baseObservation(oversizedNonceConfig);
  oversizedNonceConfig.deployerNonce='9'.repeat(100_000);
  assert.equal(assessMainnetPreflight({phase:'predeployment',releaseConfig:oversizedNonceConfig,
    observation:oversizedNonceObservation}).ready,false);
});

test('materializes only an independently recomputed zero-blocker predeployment report',()=>{
  const config=release();
  const inputs=materializationInputs('predeployment',baseObservation(config));
  const prepared=prepareMainnetPreflightMaterialization(inputs);
  assert.equal(prepared.evidencePath,'evidence/mainnet-predeployment-attestation.json');
  assert.deepEqual(JSON.parse(prepared.reportContent),inputs.report);
  assert.deepEqual(JSON.parse(prepared.evidenceContent).mainnetPredeploymentAttestationReport,
    prepared.document);
  assert.equal(JSON.parse(prepared.requirementsContent)
    .production_mainnet_predeployment_preflight_passed,true);
  for(const change of [
    value=>{value.report.finalizedBlockHash=hash(99);},
    value=>{value.report.ready=false;},
    value=>{value.report.blockerCount=1;},
    value=>{value.report.extra=true;},
    value=>{value.report.observation.snapshotBlockHashAfter=hash(99);},
    value=>{value.evidence.mainnetPredeploymentAttestationReport={path:'evidence/other.json',sha256:'0'.repeat(64)};},
  ]) {
    const candidate=structuredClone(inputs); change(candidate);
    assert.throws(()=>prepareMainnetPreflightMaterialization(candidate));
  }
});

test('materializes the exact independently recomputed cold-start report idempotently',()=>{
  const config=release();
  const inputs=materializationInputs('postdeployment',postObservation(config));
  const first=prepareMainnetPreflightMaterialization(inputs);
  assert.equal(first.evidencePath,'evidence/mainnet-cold-start-attestation.json');
  const repeated=prepareMainnetPreflightMaterialization({
    ...inputs,
    evidence:{...inputs.evidence,mainnetColdStartAttestationReport:first.document},
    requirements:{...inputs.requirements,production_mainnet_cold_start_attestation_completed:true},
  });
  assert.deepEqual(repeated,first);
  assert.equal(JSON.parse(first.requirementsContent)
    .production_mainnet_cold_start_attestation_completed,true);
});
