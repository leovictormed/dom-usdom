import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CHECKPOINT_BOOTSTRAP_EVENT_TOPIC0,
  CHECKPOINT_EVENT_TOPIC0,
  checkpointRegistryConfigHash,
  checkpointRegistryPreActivationConfigHash,
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
  guardianImplementation:address('76'),guardianImplementationCodeHash:hash('87'),
  guardianOwnersCommitment:hash('86'),
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
  assert.equal(result.identityHash,'0x11cd228d22cdceda0b914d30e3dfeeaef819d6e2bad0034a946a5ddcd3e0c686');
  assert.equal(result.bootstrapHash,'0xf8591c9c8169cc7215201eb029f31ca134dada9d0f2694d95e304a327d641191');
  assert.equal(result.checkpointConfigHash,'0xd1bce3af1e93f8459bf52ce2b272557a3619a386df2266917071a3586fc09179');
  const {activationScheduleCommitment: _activation,activationEmptyStateRoot: _empty,
    initialStateRoot: _initial,...preActivation}=configuration();
  assert.equal(checkpointRegistryPreActivationConfigHash(preActivation).checkpointConfigHash,
    result.checkpointConfigHash);
  assert.equal(checkpointStatementHash(configuration(),checkpoint()),
    '0xa63ee4c9e2bc911751f9c3be20911042c0c114b8d0fba3fd9234a34f60136c19');
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
    {...base,guardianImplementation:address('00')},{...base,guardianImplementationCodeHash:hash('00')},
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
    domChainId:hash('de'),verifier:address('45'),
    verifierCodeHash:hash('56'),verifierConfigHash:hash('67'),guardian:address('78'),
    guardianCodeHash:hash('89'),guardianImplementation:address('79'),
    guardianImplementationCodeHash:hash('8a'),initialBlock:hash('9a'),initialContextHash:hash('ef'),checkpointInterval:'359',
    confirmationDepth:'29',challengePeriod:'172801',initialTotalDifficulty:'1000001',
  };
  for(const [field,value] of Object.entries(replacements)) {
    assert.notEqual(checkpointRegistryConfigHash({...base,[field]:value}).checkpointConfigHash,initial,field);
  }
  const changedActivation={...base,activationScheduleCommitment:hash('34')};
  assert.equal(checkpointRegistryConfigHash(changedActivation).checkpointConfigHash,initial,
    'pre-activation registry identity must not depend on activation');
  assert.notEqual(checkpointStatementHash(changedActivation,checkpoint()),
    checkpointStatementHash(base,checkpoint()),'checkpoint statement must bind activation');
  assert.notEqual(checkpointRegistryConfigHash({...base,initialHeight:'100001',firstV4Height:'100002'})
    .checkpointConfigHash,initial,'initialHeight/firstV4Height');
  const changedRoot={...base,initialStateRoot:hash('ab'),activationEmptyStateRoot:hash('ab')};
  assert.equal(checkpointRegistryConfigHash(changedRoot).checkpointConfigHash,initial,
    'pre-activation registry identity must not depend on the activation state root');
  assert.notEqual(checkpointStatementHash(changedRoot,{...checkpoint(),previousStateRoot:hash('ab')}),
    checkpointStatementHash(base,checkpoint()),'checkpoint statement must bind the activation state root');
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
