import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const reserve = readFileSync(new URL('../../contracts/USDOMProofReserve.sol', import.meta.url), 'utf8');
const state = readFileSync(new URL('../../../../crates/dom-usdom-state/src/lib.rs', import.meta.url), 'utf8');
const chain = readFileSync(new URL('../../../../crates/dom-chain/src/native_usdom_v4.rs', import.meta.url), 'utf8');
const guest = readFileSync(new URL('../../../../crates/dom-usdom-finalized-burn-program/src/lib.rs', import.meta.url), 'utf8');

test('fresh-finality renewal preserves the permanent debt and terminal payout identities', () => {
  assert.match(reserve, /BURN_DEBT_TYPEHASH = keccak256\([\s\S]*FinalizedBurnDebt\([^)]*stateRoot,uint64 validUntil,uint256 ethereumChainId,address reserve,bytes32 activationScheduleCommitment\)/);
  assert.match(reserve, /bytes32 debtHash = burnDebtHash\(burn\);[\s\S]*provedDebt != debtHash \|\| provedRequestBurn != burn\.burnId[\s\S]*revert AlreadyUsed\(\);[\s\S]*_requireRecentFinalitySlot\(burn\.finalityBeaconSlot\);/);
  assert.match(reserve, /_verify\(statementHash, proof\);[\s\S]*provedBurnDebts\[burn\.burnId\] = debtHash;/);
  assert.match(reserve, /burn\.finalityBeaconSlot < provedFinalitySlot[\s\S]*revert AlreadyUsed\(\)/);
  assert.match(reserve, /_verify\(statementHash, proof\);[\s\S]*provedBurnFinalitySlots\[burn\.burnId\] = burn\.finalityBeaconSlot/);
  assert.doesNotMatch(reserve, /if \(provedStatement != statementHash \|\| provedRequestBurn/);
  assert.match(reserve, /paidBurns\[burn\.burnId\] = true;\s*paidRequests\[burn\.requestId\] = true;\s*_removePending/);
  assert.match(reserve, /paidBurns\[burn\.burnId\] \|\| paidRequests\[burn\.requestId\]/);
});

test('native consensus and persistence bind nullifier, burn and request exactly once behind the reorg floor', () => {
  assert.match(state, /self\.burn_request_ids\.contains\(&value\.record\.request_id\)/);
  assert.match(state, /self\.burns\.contains_key\(&value\.record\.burn_id\)/);
  assert.match(state, /self\.nullifiers\.contains\(nullifier\)/);
  assert.match(state, /self\.burn_request_ids\.insert\(value\.record\.request_id\)/);
  assert.match(state, /candidate\.apply_burn\(context, value\)\?/);
  assert.match(state, /burn_request_ids\.insert\(record\.request_id\)/);
  assert.match(chain, /mainnet_verified_native_burn_checkpoint_becomes_consensus_reorg_floor/);
  assert.match(chain, /reorg would undo checkpoint/);
});

test('renewed proof authenticates later finality while public statement excludes private history', () => {
  assert.match(guest, /irreversible_historical_burn_remains_provable_under_later_finality/);
  assert.match(guest, /later_finality\.beacon_slot \+= 216_000/);
  assert.match(guest, /assert_ne!\(renewed_output, original_output\)/);
  const statement = guest.match(/let expected = FinalizedBurnStatement \{([\s\S]*?)\n\s*\};/)?.[1] ?? '';
  for (const field of ['burn_id','request_id','recipient','amount','dom_domain','height','block_hash','state_root','finality_beacon_slot','valid_until','ethereum_chain_id','reserve','activation_schedule_commitment']) {
    assert.match(statement, new RegExp(`\\b${field}:`), field);
  }
  for (const privateField of ['nullifier','note','sender','memo','spend_key','view_key','transfer_history']) {
    assert.doesNotMatch(statement, new RegExp(`\\b${privateField}:`), privateField);
  }
});
