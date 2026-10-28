import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const reserve = readFileSync(new URL('../../contracts/USDOMProofReserve.sol', import.meta.url), 'utf8');
const registry = readFileSync(new URL('../../contracts/DOMCheckpointRegistry.sol', import.meta.url), 'utf8');
const solidityTest = readFileSync(new URL('../solidity/USDOMProofReserve.t.sol', import.meta.url), 'utf8');

test('ingress can close permanently without disabling debt renewal or payout', () => {
  assert.match(reserve, /bool public depositsClosed/);
  assert.match(reserve, /function closeDeposits\(\) external[\s\S]*_requireEmergencyAuthority\(\);[\s\S]*_requireControlPlaneUnchanged\(\);[\s\S]*depositsClosed = true/);
  const deposit = reserve.match(/function deposit\([\s\S]*?\n\s*\}/)?.[0] ?? '';
  assert.match(deposit, /if \(depositsClosed\) revert DepositsClosed\(\)/);
  const queue = reserve.match(/function queueWithdrawal\([\s\S]*?\n\s*\}/)?.[0] ?? '';
  const execute = reserve.match(/function executeWithdrawal\([\s\S]*?\n\s*\}/)?.[0] ?? '';
  assert.doesNotMatch(queue, /depositsClosed/);
  assert.doesNotMatch(execute, /depositsClosed/);
  assert.doesNotMatch(reserve, /depositsClosed = false/);
});

test('shutdown adds no sweep, admin payout or debt erasure path', () => {
  assert.doesNotMatch(reserve, /function (?:sweep|withdrawCollateral|adminPayout|refundDeposit)/i);
  assert.doesNotMatch(reserve, /delete provedBurn|delete paidBurn|delete paidRequest/);
  assert.match(solidityTest, /testDepositShutdownBlocksIngressButAllowsFirstProofAndPayouts/);
  assert.match(solidityTest, /closeDeposits[\s\S]*queueWithdrawal[\s\S]*executeWithdrawal/);
});

test('pause and registry halt remain fail-closed without economic state mutation', () => {
  assert.match(reserve, /function _pauseState\(\) private[\s\S]*\+\+queueEpoch[\s\S]*totalPendingAmount = 0/);
  assert.doesNotMatch(reserve, /function _pauseState[\s\S]{0,1200}totalReleased/);
  assert.match(registry, /function haltPermanently\(\) external[\s\S]*halted = true/);
  assert.match(registry, /function submitCheckpointCandidate[\s\S]*if \(halted\) revert IsHalted/);
  assert.match(registry, /function finalizeCheckpoint[\s\S]*if \(halted\) revert IsHalted/);
  assert.doesNotMatch(registry, /delete latest|latestHeight = 0|latestBlock = bytes32\(0\)/);
});

test('proved debts remain renewable under fresh finality after an outage', () => {
  assert.match(reserve, /provedBurnDebts\[burn\.burnId\]/);
  assert.match(reserve, /burn\.finalityBeaconSlot < provedFinalitySlot/);
  assert.match(reserve, /_requireRecentFinalitySlot\(burn\.finalityBeaconSlot\)/);
  assert.match(reserve, /_verify\(statementHash, proof\)/);
  assert.match(reserve, /provedBurnFinalitySlots\[burn\.burnId\] = burn\.finalityBeaconSlot/);
});
