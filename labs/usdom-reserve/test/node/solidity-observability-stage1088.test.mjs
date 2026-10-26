import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

const reserve=readFileSync(new URL('../../contracts/USDOMProofReserve.sol',import.meta.url),'utf8');
const registry=readFileSync(new URL('../../contracts/DOMCheckpointRegistry.sol',import.meta.url),'utf8');

test('withdrawal leases expose debt identity amount generation finality and renewal',()=>{
  assert.match(reserve,/event WithdrawalLeaseV2\([\s\S]*burnId[\s\S]*requestId[\s\S]*amount[\s\S]*queueEpoch[\s\S]*statementHash[\s\S]*readyAt[\s\S]*expiresAt[\s\S]*finalityBeaconSlot[\s\S]*renewal/);
  assert.match(reserve,/_emitWithdrawalLease\(burn, statementHash, readyAt, expiresAt, renewal\)/);
});

test('discard and payment expose amount epoch and remaining permanent debt',()=>{
  assert.match(reserve,/event WithdrawalDiscardedV2\([\s\S]*burnId[\s\S]*requestId[\s\S]*amount[\s\S]*leaseEpoch/);
  assert.equal((reserve.match(/_emitWithdrawalDiscarded\(burnId, pending\)/g)??[]).length,3);
  assert.match(reserve,/function _emitWithdrawalDiscarded[\s\S]*emit WithdrawalDiscarded\([\s\S]*emit WithdrawalDiscardedV2\(/);
  assert.match(reserve,/event ProvedDebtSettled\([\s\S]*amount[\s\S]*leaseEpoch[\s\S]*remainingProvedDebt/);
  assert.match(reserve,/_emitProvedDebtSettled\(burn, pending\.queueEpoch\)/);
});

test('candidate economics and final state are reconstructable by statement hash',()=>{
  assert.match(registry,/event CheckpointCandidateEconomics\([\s\S]*statementHash[\s\S]*totalIssued[\s\S]*totalBurned[\s\S]*issuanceClosed/);
  assert.match(registry,/emit CheckpointCandidateEconomics\([\s\S]*checkpoint\.totalIssued[\s\S]*checkpoint\.totalBurned[\s\S]*checkpoint\.issuanceClosed/);
  assert.match(registry,/event CheckpointFinalizedV2\([\s\S]*statementHash[\s\S]*domContextHash[\s\S]*domTotalDifficulty[\s\S]*totalIssued[\s\S]*totalBurned[\s\S]*issuanceClosed[\s\S]*checkpointCount/);
  assert.match(registry,/emit CheckpointFinalizedV2\([\s\S]*current\.statementHash[\s\S]*current\.contextHash[\s\S]*current\.totalDifficulty[\s\S]*current\.totalIssued[\s\S]*current\.totalBurned[\s\S]*latestIssuanceClosed[\s\S]*checkpointCount/);
});
