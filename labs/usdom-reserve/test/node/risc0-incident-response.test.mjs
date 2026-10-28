import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {ContractFactory,keccak256} from 'ethers';
import {localEvm} from './helpers/evm.mjs';
import {
  buildRiscZeroIncidentResponsePlan,
  executeRiscZeroIncidentResponse,
} from '../../sdk/risc0-incident-response.mjs';
import {createRiscZeroHealthSourceCatalog} from '../../sdk/risc0-health-source-catalog.mjs';

const hash=value=>'0x'+value.toString(16).padStart(64,'0');
const reference=JSON.parse(await readFile(
  new URL('../../config/risc0-ethereum-mainnet-v3.json',import.meta.url),'utf8'));
const healthObservation=paused=>({chainId:'1',
  genesisBlockHash:'0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3',
  finalizedBlockNumber:'26233306',
  finalizedBlockHash:hash(3),snapshotBlockHashAfter:hash(3),
  riscZeroVerifier:{address:reference.verifier_address,codeHash:reference.observed_runtime_code_hash,
    selector:reference.verifier_selector,version:reference.verifier_version},
  riscZeroEmergencyStop:{address:reference.emergency_stop_wrapper_address,
    codeHash:reference.emergency_stop_wrapper_runtime_code_hash,paused,verifier:reference.verifier_address}});
const approvedSources=Array.from({length:4},(_,index)=>({
  sourceId:`independent-rpc-${index+1}`,operatorId:`operator-${index+1}`,
  providerId:`provider-${index+1}`,infrastructureId:`infra-${index+1}`,
  endpointHash:hash(100+index),
}));
const approvedSourceCatalog=createRiscZeroHealthSourceCatalog({sources:approvedSources});
const sources=(observation,count=2)=>approvedSources.slice(0,count).map(identity=>({
  ...identity,observation:structuredClone(observation),
}));
const targets=(reserve=1,registry=2)=>({reserve:{address:'0x'+reserve.toString(16).padStart(40,'0'),
  runtimeCodeHash:hash(10)},checkpointRegistry:{address:'0x'+registry.toString(16).padStart(40,'0'),
  runtimeCodeHash:hash(11)}});
const responseSnapshot=(approved=targets(),overrides={})=>({ethereumChainId:'31337',
  reserve:{...approved.reserve,queueEpoch:'1',pilotAuthorizationGeneration:'0',paused:false,resumeReadyAt:'0',...overrides.reserve},
  checkpointRegistry:{...approved.checkpointRegistry,halted:false,...overrides.checkpointRegistry}});

test('healthy upstream produces no control-plane action',()=>{
  const approved=targets();
  const plan=buildRiscZeroIncidentResponsePlan({reference,approvedSourceCatalog,
    sources:sources(healthObservation(false),1),
    responseSnapshot:responseSnapshot(approved),approvedTargets:approved});
  assert.equal(plan.classification,'healthy');
  assert.deepEqual(plan.actions,[]);
});

test('confirmed upstream stop binds reserve pause before irreversible checkpoint halt',()=>{
  const approved=targets();
  const plan=buildRiscZeroIncidentResponsePlan({reference,approvedSourceCatalog,
    sources:sources(healthObservation(true)),
    responseSnapshot:responseSnapshot(approved),approvedTargets:approved});
  assert.equal(plan.classification,'confirmed-upstream-incident');
  assert.deepEqual(plan.assessment.blockerCodes,['risc0_estop_active']);
  assert.deepEqual(plan.actions.map(({role})=>role),['reserveGuardian','checkpointGuardian']);
  assert.equal(plan.actions[0].precondition.queueEpoch,'1');
  assert.equal(plan.actions[0].to,approved.reserve.address);
  assert.equal(plan.actions[1].to,approved.checkpointRegistry.address);
});

test('untrusted observation can pause reserve but cannot permanently halt checkpoints',()=>{
  const approved=targets();
  const malformed={...healthObservation(true),snapshotBlockHashAfter:hash(99)};
  const plan=buildRiscZeroIncidentResponsePlan({reference,approvedSourceCatalog,
    sources:sources(malformed,1),
    responseSnapshot:responseSnapshot(approved),approvedTargets:approved});
  assert.equal(plan.classification,'unconfirmed-health-failure');
  assert.deepEqual(plan.actions.map(({role})=>role),['reserveGuardian']);
});

test('health failure cancels a resume that governance scheduled before the incident',()=>{
  const approved=targets();
  const plan=buildRiscZeroIncidentResponsePlan({reference,approvedSourceCatalog,
    sources:sources(healthObservation(true),1),
    responseSnapshot:responseSnapshot(approved,{reserve:{paused:true,resumeReadyAt:'2000000000'}}),
    approvedTargets:approved});
  assert.equal(plan.classification,'unconfirmed-health-failure');
  assert.deepEqual(plan.actions.map(({role})=>role),['reserveGuardian']);
  assert.deepEqual(plan.actions[0].precondition,
    {queueEpoch:'1',pilotAuthorizationGeneration:'0',paused:true,resumeReadyAt:'2000000000'});
  assert.deepEqual(plan.actions[0].postcondition,{paused:true,resumeReadyAt:'0',pilotAuthorizationGeneration:'1'});
});

test('incident response rejects oversized snapshot integers before conversion',()=>{
  const approved=targets();
  for(const reserve of [
    {queueEpoch:'9'.repeat(100000)},
    {queueEpoch:(1n<<64n).toString()},
  ]) assert.throws(()=>buildRiscZeroIncidentResponsePlan({reference,approvedSourceCatalog,
    sources:sources(healthObservation(true),1),
    responseSnapshot:responseSnapshot(approved,{reserve}),approvedTargets:approved}),
  /canonical uint|exceeds uint64/);
});

test('unavailable upstream stop state cannot authorize an irreversible checkpoint halt',()=>{
  const approved=targets();
  const unavailable=healthObservation(false);
  unavailable.riscZeroEmergencyStop.paused=null;
  const plan=buildRiscZeroIncidentResponsePlan({reference,approvedSourceCatalog,
    sources:sources(unavailable,1),
    responseSnapshot:responseSnapshot(approved),approvedTargets:approved});
  assert.equal(plan.classification,'unconfirmed-health-failure');
  assert.deepEqual(plan.assessment.blockerCodes,['risc0_estop_state_invalid']);
  assert.deepEqual(plan.actions.map(({role})=>role),['reserveGuardian']);
});

test('one unhealthy RPC or disagreeing RPCs cannot authorize permanent halt',()=>{
  const approved=targets();
  const stopped=healthObservation(true);
  const single=buildRiscZeroIncidentResponsePlan({reference,approvedSourceCatalog,
    sources:sources(stopped,1),
    responseSnapshot:responseSnapshot(approved),approvedTargets:approved});
  assert.equal(single.classification,'unconfirmed-health-failure');
  assert.deepEqual(single.actions.map(({role})=>role),['reserveGuardian']);
  const divergent=sources(stopped);
  divergent[1].observation.riscZeroEmergencyStop.paused=false;
  const disagreement=buildRiscZeroIncidentResponsePlan({reference,approvedSourceCatalog,
    sources:divergent,
    responseSnapshot:responseSnapshot(approved),approvedTargets:approved});
  assert.equal(disagreement.classification,'unconfirmed-health-failure');
  assert.equal(disagreement.assessment.observationsIdentical,false);
  assert.deepEqual(disagreement.actions.map(({role})=>role),['reserveGuardian']);
  assert.throws(()=>buildRiscZeroIncidentResponsePlan({reference,approvedSourceCatalog,
    sources:[{...approvedSources[0],observation:stopped},
      {...approvedSources[0],observation:stopped}],
    responseSnapshot:responseSnapshot(approved),approvedTargets:approved}),/distinct/);
});

test('caller labels cannot impersonate an approved independent RPC operator',()=>{
  const approved=targets();
  const stopped=healthObservation(true);
  const forged=sources(stopped);
  forged[1]={...forged[0],sourceId:approvedSources[1].sourceId};
  assert.throws(()=>buildRiscZeroIncidentResponsePlan({reference,approvedSourceCatalog,sources:forged,
    responseSnapshot:responseSnapshot(approved),approvedTargets:approved}),/not an approved release source/);
  const unknown=sources(stopped);
  unknown[1]={...unknown[1],sourceId:'invented-rpc'};
  assert.throws(()=>buildRiscZeroIncidentResponsePlan({reference,approvedSourceCatalog,sources:unknown,
    responseSnapshot:responseSnapshot(approved),approvedTargets:approved}),/not an approved release source/);
  const repeatedOperator=structuredClone(approvedSources);
  repeatedOperator[1].operatorId=repeatedOperator[0].operatorId;
  assert.throws(()=>buildRiscZeroIncidentResponsePlan({reference,
    approvedSourceCatalog:{...approvedSourceCatalog,sources:repeatedOperator},
    sources:sources(stopped),responseSnapshot:responseSnapshot(approved),approvedTargets:approved}),
  /operator identities must be distinct/);
  const repeatedEndpoint=structuredClone(approvedSources);
  repeatedEndpoint[1].endpointHash=repeatedEndpoint[0].endpointHash;
  assert.throws(()=>buildRiscZeroIncidentResponsePlan({reference,
    approvedSourceCatalog:{...approvedSourceCatalog,sources:repeatedEndpoint},
    sources:sources(stopped),responseSnapshot:responseSnapshot(approved),approvedTargets:approved}),
  /endpoint hashes must be distinct/);
  for(const [field,pattern] of [['providerId',/provider identities must be distinct/],
    ['infrastructureId',/infrastructure identities must be distinct/]]) {
    const repeated=structuredClone(approvedSources);
    repeated[1][field]=repeated[0][field];
    assert.throws(()=>buildRiscZeroIncidentResponsePlan({reference,
      approvedSourceCatalog:{...approvedSourceCatalog,sources:repeated},sources:sources(stopped),
      responseSnapshot:responseSnapshot(approved),approvedTargets:approved}),pattern);
  }
});

async function artifact(path) {
  return JSON.parse(await readFile(new URL(`../../out/${path}`,import.meta.url),'utf8'));
}

test('isolated response drill changes both real contract states and verifies inclusion',async t=>{
  const rpc=await localEvm(t);
  const provider=rpc.provider;
  const owner=await provider.getSigner(0);
  const deploy=async(path,args=[])=>{
    const value=await artifact(path);
    return (await new ContractFactory(value.abi,value.bytecode.object,owner).deploy(...args)).waitForDeployment();
  };
  const token=await deploy('Mocks.sol/HostileToken.json');
  const governance=await deploy('Mocks.sol/MockGovernance.json');
  const reserveGuardianContract=await deploy('Mocks.sol/MockGovernance.json');
  const checkpointGuardianContract=await deploy('Mocks.sol/MockGovernance.json');
  const burnVerifier=await deploy('USDOMProofReserve.t.sol/MockFinalizedBurnVerifier.json');
  const checkpointVerifier=await deploy('DOMCheckpointRegistry.t.sol/MockDOMCheckpointVerifier.json');
  const checkpointRegistry=await deploy('DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json',[{
    bridgeDomain:hash(20),domNetworkMagic:0xa1b2c3d4,domChainId:hash(31),firstV4Height:100001,
    activationEmptyStateRoot:hash(32),activationScheduleCommitment:hash(21),checkpointInterval:360,
    confirmationDepth:30,challengePeriod:172800,verifier:checkpointVerifier.target,
    guardian:checkpointGuardianContract.target,initialHeight:100000,initialBlock:hash(34),
    initialStateRoot:hash(32),initialContextHash:hash(35),initialTotalDifficulty:1_000_000n,
  }]);
  const reserve=await deploy('USDOMProofReserve.sol/USDOMProofReserve.json',[{
    token:token.target,verifier:burnVerifier.target,checkpointRegistry:checkpointRegistry.target,
    domDomain:hash(20),activationScheduleCommitment:hash(21),governance:governance.target,
    guardian:reserveGuardianContract.target,withdrawalDelay:86400,governanceDelay:172800,
    maxOutstanding:100_000_000_000n,outflowCapacity:2_000_000_000n,pilotRestricted:false,
  }]);
  const approved={reserve:{address:reserve.target,runtimeCodeHash:keccak256(await provider.getCode(reserve.target))},
    checkpointRegistry:{address:checkpointRegistry.target,
      runtimeCodeHash:keccak256(await provider.getCode(checkpointRegistry.target))}};
  const incidentObservation=healthObservation(true);
  const incidentSources=sources(incidentObservation);
  const plan=buildRiscZeroIncidentResponsePlan({reference,approvedSourceCatalog,sources:incidentSources,
    approvedTargets:approved,
    responseSnapshot:{ethereumChainId:'31337',reserve:{...approved.reserve,queueEpoch:'1',pilotAuthorizationGeneration:'0',paused:false,
      resumeReadyAt:'0'},
      checkpointRegistry:{...approved.checkpointRegistry,halted:false}}});
  const adapter=contract=>({getAddress:()=>contract.getAddress(),
    sendTransaction:transaction=>contract.execute(transaction.to,transaction.data)});
  const report=await executeRiscZeroIncidentResponse({plan,reference,approvedSourceCatalog,
    sources:incidentSources,
    approvedTargets:approved,reserve,checkpointRegistry,
    reserveGuardian:adapter(reserveGuardianContract),checkpointGuardian:adapter(checkpointGuardianContract)});
  assert.equal(report.status,'contained');
  assert.deepEqual(report.transactions.map(({role})=>role),['reserveGuardian','checkpointGuardian']);
  assert.equal(await reserve.paused(),true);
  assert.equal(await reserve.queueEpoch(),2n);
  assert.equal(await checkpointRegistry.halted(),true);
  await assert.rejects(reserve.deposit.staticCall(1,hash(40),hash(41)));
});

test('executor rejects a stale reserve generation before any checkpoint halt',async()=>{
  const approved=targets();
  const incidentSources=sources(healthObservation(true));
  const plan=buildRiscZeroIncidentResponsePlan({reference,approvedSourceCatalog,
    sources:incidentSources,
    responseSnapshot:responseSnapshot(approved),approvedTargets:approved});
  const provider={getNetwork:async()=>({chainId:31337n}),getCode:async addressValue=>
    addressValue===approved.reserve.address?'0x6001':'0x6002'};
  plan.snapshot.reserve.runtimeCodeHash=keccak256('0x6001');
  plan.snapshot.checkpointRegistry.runtimeCodeHash=keccak256('0x6002');
  // Rebuilding is required after any snapshot mutation; the immutable plan hash
  // prevents the executor from accepting this forged fixture.
  const reserve={runner:{provider},getAddress:async()=>approved.reserve.address};
  const checkpointRegistry={runner:{provider},getAddress:async()=>approved.checkpointRegistry.address};
  await assert.rejects(executeRiscZeroIncidentResponse({plan,reference,approvedSourceCatalog,
    sources:incidentSources,
    approvedTargets:approved,reserve,checkpointRegistry,
    reserveGuardian:{},checkpointGuardian:{}}),/plan hash mismatch/);
});

test('executor re-pauses an already paused reserve and proves scheduled resume cancellation',async()=>{
  const reserveCode='0x6001';
  const checkpointCode='0x6002';
  const approved=targets();
  approved.reserve.runtimeCodeHash=keccak256(reserveCode);
  approved.checkpointRegistry.runtimeCodeHash=keccak256(checkpointCode);
  const incidentSources=sources(healthObservation(true),1);
  const plan=buildRiscZeroIncidentResponsePlan({reference,approvedSourceCatalog,
    sources:incidentSources,responseSnapshot:responseSnapshot(approved,
      {reserve:{paused:true,resumeReadyAt:'2000000000'}}),approvedTargets:approved});
  const provider={getNetwork:async()=>({chainId:31337n}),getCode:async addressValue=>
    addressValue===approved.reserve.address?reserveCode:checkpointCode};
  let paused=true;
  let resumeReadyAt=2000000000n;
  const guardianAddress='0x0000000000000000000000000000000000000003';
  const reserve={runner:{provider},getAddress:async()=>approved.reserve.address,
    queueEpoch:async()=>1n,pilotAuthorizationGeneration:async()=>0n,paused:async()=>paused,resumeReadyAt:async()=>resumeReadyAt,
    guardian:async()=>guardianAddress};
  const checkpointRegistry={runner:{provider},getAddress:async()=>approved.checkpointRegistry.address};
  const reserveGuardian={getAddress:async()=>guardianAddress,sendTransaction:async()=>{
    paused=true;
    resumeReadyAt=0n;
    return {wait:async()=>({status:1,hash:hash(90),blockNumber:12})};
  }};
  const report=await executeRiscZeroIncidentResponse({plan,reference,approvedSourceCatalog,
    sources:incidentSources,approvedTargets:approved,reserve,checkpointRegistry,
    reserveGuardian,checkpointGuardian:{}});
  assert.equal(report.status,'reserve-paused');
  assert.equal(resumeReadyAt,0n);
  assert.deepEqual(report.transactions.map(({role})=>role),['reserveGuardian']);
});

test('executor recomputes the plan and rejects a substituted healthy observation',async()=>{
  const approved=targets();
  const plan=buildRiscZeroIncidentResponsePlan({reference,approvedSourceCatalog,
    sources:sources(healthObservation(true)),
    responseSnapshot:responseSnapshot(approved),approvedTargets:approved});
  await assert.rejects(executeRiscZeroIncidentResponse({plan,reference,approvedSourceCatalog,
    sources:sources(healthObservation(false)),approvedTargets:approved,reserve:{},checkpointRegistry:{},
    reserveGuardian:{},checkpointGuardian:{}}),/authenticated observation/);
});
