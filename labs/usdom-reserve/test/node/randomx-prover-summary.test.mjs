import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseRandomxProverSummary,reconcileRandomxProverSummary,
} from '../../sdk/randomx-prover-summary.mjs';

const hash=byte=>byte.repeat(64);
const valid=()=>`status: proved-and-verified
receipt_count: 390
job_index_sha256: ${hash('a')}
receipt_index_sha256: ${hash('b')}
receipt_kind: succinct
dev_mode: false
mines: false
`;

test('RandomX prover summary binds the verified job and receipt indexes',()=>{
  const summary=parseRandomxProverSummary(valid());
  assert.equal(summary.receiptCount,390);
  assert.equal(reconcileRandomxProverSummary(summary,summary),true);
});

test('RandomX prover summary rejects false claims and post-verification substitution',()=>{
  for(const mutation of [
    value=>value.replace('proved-and-verified','proved'),
    value=>value.replace('receipt_count: 390','receipt_count: 0'),
    value=>value.replace(hash('a'),'0'.repeat(64)),
    value=>value.replace('receipt_kind: succinct','receipt_kind: fake'),
    value=>value.replace('dev_mode: false','dev_mode: true'),
    value=>value.replace('mines: false','mines: true'),
    value=>value+'extra\n',
  ]) assert.throws(()=>parseRandomxProverSummary(mutation(valid())));
  const summary=parseRandomxProverSummary(valid());
  for(const observed of [
    {...summary,receiptCount:389},{...summary,jobIndexSha256:hash('c')},
    {...summary,receiptIndexSha256:hash('d')},
  ]) assert.throws(()=>reconcileRandomxProverSummary(summary,observed),/changed/);
});
