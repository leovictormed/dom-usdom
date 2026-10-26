import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const reserve = readFileSync(new URL('../../contracts/USDOMProofReserve.sol', import.meta.url), 'utf8');
const registry = readFileSync(new URL('../../contracts/DOMCheckpointRegistry.sol', import.meta.url), 'utf8');

test('reserve terminal state requires all local liabilities and a resumed control plane', () => {
  const shutdown = reserve.match(/function finalizeGracefulShutdown\([\s\S]*?\n    function pause\(/);
  assert.ok(shutdown);
  for (const predicate of [
    '!depositsClosed', 'paused', 'totalDeposited != totalReleased', 'outstanding() != 0',
    'totalProvedDebtAmount != 0', 'pendingCount != 0', 'totalPendingAmount != 0',
    'firstPendingBurn != bytes32(0)', 'lastPendingBurn != bytes32(0)',
  ]) assert.ok(shutdown[0].includes(predicate), `missing ${predicate}`);
  assert.match(shutdown[0], /_requireControlPlaneUnchanged\(\);\s*_requireCheckpointRegistryUnchanged\(\);/);
});

test('cross-contract shutdown binds the same cumulative collateral total', () => {
  const shutdown = reserve.match(/function finalizeGracefulShutdown\([\s\S]*?\n    function pause\(/);
  assert.ok(shutdown);
  assert.match(shutdown[0], /issuedWord != bytes32\(totalDeposited\)/);
  assert.match(shutdown[0], /burnedWord != issuedWord/);
  assert.match(shutdown[0], /shutdownWord != bytes32\(uint256\(1\)\)/);
  assert.match(shutdown[0], /closureWord != bytes32\(uint256\(1\)\)/);
});

test('registry shutdown is proof-authorized, terminal, and distinct from emergency halt', () => {
  const graceful = registry.match(/function finalizeGracefulShutdown\([\s\S]*?\n    function haltPermanently/);
  const emergency = registry.match(/function haltPermanently\([\s\S]*?\n    function _checkpointConfigHash/);
  assert.ok(graceful && emergency);
  assert.match(graceful[0], /if \(halted\) revert IsHalted\(\)/);
  assert.match(graceful[0], /!latestIssuanceClosed \|\| latestTotalBurned != latestTotalIssued/);
  assert.match(graceful[0], /_requireGuardianUnchanged\(\);\s*_requireVerifierUnchanged\(\);/);
  assert.match(graceful[0], /halted = true;\s*gracefullyShutdown = true;\s*delete candidate;/);
  assert.doesNotMatch(emergency[0], /gracefullyShutdown = true/);
});

test('post-shutdown checkpoint races fail before candidate or ledger mutation', () => {
  const submit = registry.match(/function submitCheckpointCandidate\([\s\S]*?\n    function _selectCandidate/);
  const finalize = registry.match(/function finalizeCheckpoint\([\s\S]*?\n    \/\/\/ @notice Permissionlessly/);
  assert.ok(submit && finalize);
  assert.match(submit[0], /if \(halted\) revert IsHalted\(\);/);
  assert.match(finalize[0], /if \(halted\) revert IsHalted\(\);/);
  assert.match(reserve, /function deposit\([\s\S]*?if \(depositsClosed\) revert DepositsClosed\(\)/);
  assert.doesNotMatch(reserve, /depositsClosed = false|gracefullyShutdown = false/);
});

test('expired or emergency-invalidated queue leases cannot hide proved debt', () => {
  const removal = reserve.match(/function _removePending\([\s\S]*?\n    function _hasActivePendingRequest/);
  const pause = reserve.match(/function _pauseState\([\s\S]*?\n    function scheduleResume/);
  assert.ok(removal && pause);
  assert.doesNotMatch(removal[0], /totalProvedDebtAmount/);
  assert.doesNotMatch(pause[0], /totalProvedDebtAmount\s*=/);
  assert.match(reserve, /totalProvedDebtAmount != 0[\s\S]*revert NotGracefullyClosable\(\)/);
});
