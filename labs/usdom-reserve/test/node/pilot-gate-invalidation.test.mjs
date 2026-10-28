import assert from 'node:assert/strict';
import test from 'node:test';
import {validatePilotGateFinality,validatePilotGateInvalidation,validatePilotGateInvalidationSequence} from '../../sdk/pilot-gate-invalidation.mjs';
const hash=n=>'0x'+n.toString(16).padStart(64,'0');
const gate={schema:'usdom-pilot-deposit-gate-finalized/v2',transactionHash:hash(1),safeTxHash:hash(2),blockNumber:'100',blockHash:hash(3),transactionIndex:'4',finalizedBlockNumber:'110',finalizedBlockHash:hash(4),snapshotCommitment:hash(5),expectedAuthorization:hash(6),generation:'7'};
const terminal=(kind='clear')=>({schema:`usdom-pilot-deposit-gate-${kind}-finalized/v2`,transactionHash:hash(7),blockNumber:'100',blockHash:hash(3),transactionIndex:'5',finalizedBlockNumber:'111',finalizedBlockHash:hash(8),snapshotCommitment:hash(5),generation:'7'});

test('gate invalidation follows gate at a canonical transaction position',()=>{
 assert.equal(validatePilotGateFinality(gate).index,4n);
 assert.equal(validatePilotGateInvalidation(terminal(),'clear').index,5n);
 assert.equal(validatePilotGateInvalidationSequence(gate,terminal(),'clear').kind,'clear');
 assert.equal(validatePilotGateInvalidationSequence(gate,terminal('cancel'),'cancel').kind,'cancel');
});

test('gate invalidation rejects reused or reversed same-block position',()=>{
 for(const index of ['4','3']) assert.throws(()=>validatePilotGateInvalidationSequence(gate,{...terminal(),transactionIndex:index},'clear'),/does not follow/);
});

test('gate invalidation rejects fork and finalized-head discontinuity',()=>{
 assert.throws(()=>validatePilotGateInvalidationSequence(gate,{...terminal(),blockHash:hash(9)},'clear'),/block hash differs/);
 assert.throws(()=>validatePilotGateInvalidationSequence(gate,{...terminal(),finalizedBlockNumber:'109'},'clear'),/regressed/);
 assert.throws(()=>validatePilotGateInvalidationSequence(gate,{...terminal(),finalizedBlockNumber:'110',finalizedBlockHash:hash(9)},'clear'),/finalized hash differs/);
});

test('gate invalidation rejects generation, schema and numeric ambiguity',()=>{
 assert.throws(()=>validatePilotGateInvalidationSequence(gate,{...terminal(),generation:'8'},'clear'),/generation differs/);
 assert.throws(()=>validatePilotGateInvalidationSequence(gate,{...terminal(),transactionIndex:'05'},'clear'),/canonical decimal/);
 assert.throws(()=>validatePilotGateInvalidationSequence(gate,{...terminal(),extra:true},'clear'),/schema/);
});
