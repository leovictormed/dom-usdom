import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

import {Interface,id} from 'ethers';
import {
  BURN_STATEMENT_TYPE,
  BURN_STATEMENT_TYPEHASH,
  finalizedBurnFields,
} from '../../sdk/proof-reserve.mjs';
import {
  CHECKPOINT_EVENT_SIGNATURE,
  CHECKPOINT_EVENT_TOPIC0,
  CHECKPOINT_STATEMENT_TYPEHASH,
  NATIVE_STATE_VERSION,
  TRANSITION_BATCH_VERSION,
} from '../../sdk/checkpoint-registry.mjs';
import {CHECKPOINT_STATEMENT_V6_BYTES} from '../../sdk/checkpoint-submission.mjs';

const root=new URL('../../',import.meta.url);
const read=relative=>readFile(new URL(relative,root),'utf8');
const json=async relative=>JSON.parse(await read(relative));

const finalizedBurnComponents=[
  ['burnId','bytes32'],['requestId','bytes32'],['recipient','address'],['amount','uint64'],
  ['domDomain','bytes32'],['height','uint64'],['blockHash','bytes32'],['stateRoot','bytes32'],
  ['finalityBeaconSlot','uint64'],['validUntil','uint64'],
];
const checkpointComponents=[
  ['previousHeight','uint64'],['previousBlock','bytes32'],['previousStateRoot','bytes32'],
  ['previousContextHash','bytes32'],['previousTotalDifficulty','uint256'],['height','uint64'],
  ['blockHash','bytes32'],['stateRoot','bytes32'],['contextHash','bytes32'],
  ['totalDifficulty','uint256'],['totalIssued','uint128'],['totalBurned','uint128'],
  ['issuanceClosed','bool'],['confirmationHeight','uint64'],['confirmationBlock','bytes32'],
  ['confirmationTotalDifficulty','uint256'],['confirmationTimestamp','uint64'],
];
const tuple=components=>`(${components.map(([,type])=>type).join(',')})`;
const functionSignatures={
  queueWithdrawal:`queueWithdrawal(${tuple(finalizedBurnComponents)},bytes)`,
  executeWithdrawal:`executeWithdrawal(${tuple(finalizedBurnComponents)})`,
  checkpointStatementHash:`checkpointStatementHash(${tuple(checkpointComponents)})`,
  submitCheckpointCandidate:`submitCheckpointCandidate(${tuple(checkpointComponents)},bytes)`,
};
const eventShapes={
  Deposited:[['bytes32',true],['address',true],['uint64',false],['bytes32',false]],
  WithdrawalQueued:[['bytes32',true],['bytes32',true],['bytes32',false],['uint64',false],['uint64',false]],
  FinalizedBurnProved:[['bytes32',true],[tuple(finalizedBurnComponents),false]],
  WithdrawalLeaseV2:[['bytes32',true],['bytes32',true],['uint64',false],['uint64',true],
    ['bytes32',false],['uint64',false],['uint64',false],['uint64',false],['bool',false]],
  Released:[['bytes32',true],['bytes32',true],['address',true],['uint64',false],['uint64',false],
    ['bytes32',false],['bytes32',false],['uint64',false]],
  Checkpoint:[['bytes32',true],['uint32',true],['uint64',false],['bytes32',false],['bytes32',false],['bytes32',false]],
  CheckpointBootstrap:[['bytes32',true],['uint32',true],['uint64',false],['bytes32',false],['bytes32',false],['bytes32',false]],
  CheckpointCandidate:[['bytes32',true],['uint32',true],['uint64',false],['bytes32',false],['bytes32',false],
    ['bytes32',false],['uint256',false],['uint64',false],['bytes32',false],['uint256',false],
    ['uint64',false],['uint64',false],['bytes32',false]],
  CheckpointCandidateEconomics:[['bytes32',true],['uint128',false],['uint128',false],['bool',false]],
  CheckpointFinalizedV2:[['bytes32',true],['bytes32',false],['uint256',false],['uint128',false],
    ['uint128',false],['bool',false],['uint256',false]],
};

function assertAbiCompatibility(reserveAbi,registryAbi) {
  const interfaces={...new Interface(reserveAbi),...new Interface(registryAbi)};
  void interfaces;
  const reserve=new Interface(reserveAbi), registry=new Interface(registryAbi);
  for(const [name,signature] of Object.entries(functionSignatures)) {
    const iface=name==='checkpointStatementHash'||name==='submitCheckpointCandidate'?registry:reserve;
    const fragment=iface.getFunction(name);
    assert(fragment,`missing ${name}`);
    assert.equal(fragment.format('sighash'),signature,`${name} ABI drift`);
    assert.equal(fragment.selector,id(signature).slice(0,10),`${name} selector drift`);
    const components=fragment.inputs[0].components;
    assert.deepEqual(components.map(value=>[value.name,value.type]),
      name.startsWith('checkpoint')||name.startsWith('submit')?checkpointComponents:finalizedBurnComponents,
      `${name} tuple names/order drift`);
  }
  for(const [name,shape] of Object.entries(eventShapes)) {
    const iface=name.startsWith('Checkpoint')?registry:reserve;
    const event=iface.getEvent(name);
    assert(event,`missing ${name}`);
    assert.deepEqual(event.inputs.map(value=>[value.format('sighash'),value.indexed]),shape,
      `${name} event/index drift`);
    assert.equal(event.topicHash,id(event.format('sighash')),`${name} topic drift`);
  }
}

test('Solidity artifacts and JS schemas expose one exact current ABI',async()=>{
  const reserve=await json('out/USDOMProofReserve.sol/USDOMProofReserve.json');
  const registry=await json('out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json');
  assertAbiCompatibility(reserve.abi,registry.abi);
  assert.deepEqual(finalizedBurnFields.map(value=>[value.name,value.type]),finalizedBurnComponents);
  assert.equal(BURN_STATEMENT_TYPEHASH,id(BURN_STATEMENT_TYPE));
  assert.equal(CHECKPOINT_EVENT_TOPIC0,id(CHECKPOINT_EVENT_SIGNATURE));
});

test('Rust public statements match Solidity/JS type strings and reject legacy framing',async()=>{
  const [burnRust,checkpointRust,reserveSol,registrySol]=await Promise.all([
    read('../../crates/dom-usdom-finalized-burn-program/src/lib.rs'),
    read('../../crates/dom-usdom-checkpoint-statement/src/lib.rs'),
    read('contracts/USDOMProofReserve.sol'),read('contracts/DOMCheckpointRegistry.sol'),
  ]);
  assert.match(burnRust,new RegExp(`FINALIZED_BURN_STATEMENT_TYPE: &str = "${BURN_STATEMENT_TYPE.replace(/[()]/g,'\\$&')}"`));
  assert(reserveSol.includes(`"${BURN_STATEMENT_TYPE}"`));
  const checkpointType='DOMCheckpointV4(bytes32 bridgeDomain,uint32 domNetworkMagic,uint16 nativeStateVersion,uint16 transitionBatchVersion,uint64 previousHeight,bytes32 previousBlock,bytes32 previousStateRoot,bytes32 previousContextHash,uint256 previousTotalDifficulty,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 domContextHash,uint256 domTotalDifficulty,uint128 totalIssued,uint128 totalBurned,bool issuanceClosed,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp,uint256 ethereumChainId,address registry,bytes32 activationScheduleCommitment,bytes32 checkpointConfigHash)';
  assert(checkpointRust.includes(`const V6_TYPE_STRING: &str = "${checkpointType}"`));
  assert(registrySol.includes(`"${checkpointType}"`));
  assert.equal(CHECKPOINT_STATEMENT_TYPEHASH,id(checkpointType));
  assert.match(checkpointRust,/const V6_MAGIC: &\[u8; 8\] = b"UDCPST06";/);
  assert.match(checkpointRust,/const V6_VERSION: u16 = 6;/);
  assert.equal(CHECKPOINT_STATEMENT_V6_BYTES,551);
  assert.equal(NATIVE_STATE_VERSION,3n);
  assert.equal(TRANSITION_BATCH_VERSION,4n);
  assert.match(burnRust,/FINALIZED_BURN_PROVER_MAGIC: &\[u8; 8\] = b"UDFINL04"/);
  assert.match(burnRust,/FINALIZED_BURN_PROVER_INPUT_VERSION: u16 = 4/);
});

test('ABI and schema mutations fail closed',async()=>{
  const reserve=(await json('out/USDOMProofReserve.sol/USDOMProofReserve.json')).abi;
  const registry=(await json('out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json')).abi;
  const mutations=[
    [reserve.map(item=>item.name==='Released'?{...item,inputs:item.inputs.map((v,i)=>i===2?{...v,indexed:false}:v)}:item),registry],
    [reserve.map(item=>item.name==='queueWithdrawal'?{...item,inputs:[{...item.inputs[0],components:[...item.inputs[0].components].reverse()},item.inputs[1]]}:item),registry],
    [reserve,registry.map(item=>item.name==='Checkpoint'?{...item,inputs:item.inputs.map((v,i)=>i===1?{...v,indexed:false}:v)}:item)],
    [reserve,registry.map(item=>item.name==='submitCheckpointCandidate'?{...item,inputs:[{...item.inputs[0],components:item.inputs[0].components.map((v,i)=>i===10?{...v,type:'uint256',internalType:'uint256'}:v)},item.inputs[1]]}:item)],
  ];
  for(const [mutatedReserve,mutatedRegistry] of mutations) {
    assert.throws(()=>assertAbiCompatibility(mutatedReserve,mutatedRegistry));
  }
});
