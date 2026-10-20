import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CHECKPOINT_BOOTSTRAP_EVENT_TOPIC0,
  CHECKPOINT_EVENT_TOPIC0,
  checkpointRegistryConfigHash,
  checkpointStatementHash,
} from '../../sdk/checkpoint-registry.mjs';

const address=byte=>'0x'+byte.repeat(20);
const hash=byte=>'0x'+byte.repeat(32);
const configuration=()=>({
  ethereumChainId:'1',registry:address('11'),bridgeDomain:hash('22'),domNetworkMagic:'2712847316',
  domChainId:hash('dd'),firstV4Height:'100001',activationEmptyStateRoot:hash('aa'),
  activationScheduleCommitment:hash('33'),checkpointInterval:'360',confirmationDepth:'30',
  challengePeriod:'172800',verifier:address('44'),verifierCodeHash:hash('55'),
  verifierConfigHash:hash('66'),guardian:address('77'),guardianCodeHash:hash('88'),
  initialHeight:'100000',initialBlock:hash('99'),initialStateRoot:hash('aa'),
  initialContextHash:hash('ee'),initialTotalDifficulty:'1000000',
});
const checkpoint=()=>({
  previousHeight:'100000',previousBlock:hash('99'),previousStateRoot:hash('aa'),
  previousContextHash:hash('ee'),previousTotalDifficulty:'1000000',height:'100360',
  blockHash:hash('bb'),stateRoot:hash('cc'),contextHash:hash('ff'),
  totalDifficulty:'1000360',confirmationHeight:'100390',confirmationBlock:hash('dd'),
  confirmationTotalDifficulty:'1000390',confirmationTimestamp:'1700000000',
});

test('checkpoint registry configuration and statement vectors are deterministic',()=>{
  const result=checkpointRegistryConfigHash(configuration());
  assert.equal(result.identityHash,'0x51991663d2f95ef9dc42eb5d77d1cbd4ce8a66049a3966e58f73813d0bc1f282');
  assert.equal(result.bootstrapHash,'0x1635e006cbe7f4554d6025cfa2ed032af863e8212f3284f2093ff7b63971f7c0');
  assert.equal(result.checkpointConfigHash,'0x4ab7848ffc06d09ea7462a0ff65ec55e364749839a79a71815171dd1543a1615');
  assert.equal(checkpointStatementHash(configuration(),checkpoint()),
    '0xaea1d132059ed25184d27671e5c52061f53f6f767074d6aa10c0ce35fc11249e');
  assert.equal(CHECKPOINT_EVENT_TOPIC0,'0x620d9063aa9b939d1e51ea40c2e557313fcaacfde713bec8ad6844480561c30b');
  assert.notEqual(CHECKPOINT_BOOTSTRAP_EVENT_TOPIC0,CHECKPOINT_EVENT_TOPIC0);
});

test('checkpoint registry hashing rejects ambiguity, zero identities and nonextensions',()=>{
  const base=configuration();
  for(const changed of [
    {...base,extra:true},{...base,ethereumChainId:'0'},{...base,registry:address('00')},
    {...base,bridgeDomain:hash('00')},{...base,domNetworkMagic:'0'},
    {...base,domChainId:hash('00')},{...base,firstV4Height:'100002'},
    {...base,activationEmptyStateRoot:hash('ab')},
    {...base,checkpointInterval:'0'},{...base,checkpointInterval:'361'},
    {...base,confirmationDepth:'0'},{...base,confirmationDepth:'361'},
    {...base,challengePeriod:'86399'},{...base,challengePeriod:'2592001'},
    {...base,activationScheduleCommitment:hash('00')},{...base,verifier:base.guardian},
    {...base,verifierCodeHash:hash('00')},{...base,verifierConfigHash:hash('00')},
    {...base,guardianCodeHash:hash('00')},{...base,initialHeight:'0'},
    {...base,initialBlock:hash('00')},{...base,initialStateRoot:hash('00')},
    {...base,initialContextHash:hash('00')},
    {...base,initialTotalDifficulty:'0'},
  ]) assert.throws(()=>checkpointRegistryConfigHash(changed));
  const incomplete={...base}; delete incomplete.guardian;
  assert.throws(()=>checkpointRegistryConfigHash(incomplete),/exact/);

  const statement=checkpoint();
  assert.throws(()=>checkpointStatementHash(base,{...statement,height:'100359'}));
  assert.throws(()=>checkpointStatementHash(base,{...statement,confirmationHeight:'100391'}));
  assert.throws(()=>checkpointStatementHash(base,{...statement,blockHash:statement.previousBlock}));
  assert.throws(()=>checkpointStatementHash(base,{...statement,confirmationBlock:statement.blockHash}));
  assert.throws(()=>checkpointStatementHash(base,{...statement,totalDifficulty:statement.previousTotalDifficulty}));
  assert.throws(()=>checkpointStatementHash(base,{...statement,
    confirmationTotalDifficulty:statement.totalDifficulty}));
  assert.throws(()=>checkpointStatementHash(base,{...statement,confirmationTimestamp:'0'}));
  assert.throws(()=>checkpointStatementHash(base,{...statement,stateRoot:hash('00')}));
  assert.throws(()=>checkpointStatementHash(base,{...statement,contextHash:hash('00')}));
  assert.throws(()=>checkpointStatementHash(base,{...statement,contextHash:statement.previousContextHash}));
  assert.throws(()=>checkpointStatementHash(base,{...statement,extra:true}),/exact/);
});

test('every checkpoint configuration and statement field changes its commitment',()=>{
  const base=configuration();
  const initial=checkpointRegistryConfigHash(base).checkpointConfigHash;
  const replacements={
    ethereumChainId:'2',registry:address('12'),bridgeDomain:hash('23'),domNetworkMagic:'2712847315',
    domChainId:hash('de'),activationScheduleCommitment:hash('34'),verifier:address('45'),
    verifierCodeHash:hash('56'),verifierConfigHash:hash('67'),guardian:address('78'),
    guardianCodeHash:hash('89'),initialBlock:hash('9a'),initialContextHash:hash('ef'),checkpointInterval:'359',
    confirmationDepth:'29',challengePeriod:'172801',initialTotalDifficulty:'1000001',
  };
  for(const [field,value] of Object.entries(replacements)) {
    assert.notEqual(checkpointRegistryConfigHash({...base,[field]:value}).checkpointConfigHash,initial,field);
  }
  assert.notEqual(checkpointRegistryConfigHash({...base,initialHeight:'100001',firstV4Height:'100002'})
    .checkpointConfigHash,initial,'initialHeight/firstV4Height');
  assert.notEqual(checkpointRegistryConfigHash({...base,initialStateRoot:hash('ab'),
    activationEmptyStateRoot:hash('ab')}).checkpointConfigHash,initial,'initialStateRoot/emptyRoot');
  const statement=checkpoint();
  const statementHash=checkpointStatementHash(base,statement);
  for(const [field,value] of Object.entries({
    previousBlock:hash('98'),previousStateRoot:hash('a9'),previousContextHash:hash('ed'),
    previousTotalDifficulty:'999999',blockHash:hash('bc'),stateRoot:hash('cd'),contextHash:hash('fe'),
    totalDifficulty:'1000361',
    confirmationBlock:hash('de'),confirmationTotalDifficulty:'1000391',confirmationTimestamp:'1700000001',
  })) assert.notEqual(checkpointStatementHash(base,{...statement,[field]:value}),statementHash,field);
  assert.notEqual(checkpointStatementHash(base,{...statement,previousHeight:'99999',height:'100359',
    confirmationHeight:'100389'}),statementHash,'heights');
});
