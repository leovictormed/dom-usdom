import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const source = readFileSync(new URL('../../contracts/USDOMProofReserve.sol', import.meta.url), 'utf8');

test('admission deadline and renewable queue lease are separate clocks', () => {
  assert.match(source, /uint64 expiresAt = _timestampAfter\(MAX_CERTIFICATE_LIFETIME\);/);
  assert.match(source, /if \(burn\.validUntil > expiresAt\) \{\s*revert InvalidCertificateWindow\(\);/);
  assert.doesNotMatch(source, /burn\.validUntil < block\.timestamp/);
  assert.match(source, /PendingWithdrawal\([\s\S]*readyAt, expiresAt, queueEpoch/);
  assert.match(source, /if \(block\.timestamp > pending\.expiresAt\) revert StaleCertificate\(\)/);
});

test('every proof admission is recent and renewal finality never regresses', () => {
  const renewal = source.match(/if \(renewal\) \{([\s\S]*?)\n\s*\} else \{([\s\S]*?)\n\s*\}/);
  assert.ok(renewal, 'renewal branches');
  assert.match(renewal[1], /burn\.finalityBeaconSlot < provedFinalitySlot/);
  assert.match(renewal[1], /_requireRecentFinalitySlot\(burn\.finalityBeaconSlot\)/);
  assert.match(renewal[2], /_requireRecentFinalitySlot\(burn\.finalityBeaconSlot\)/);
  assert.match(source, /_verify\(statementHash, proof\);[\s\S]*provedBurnFinalitySlots\[burn\.burnId\] = burn\.finalityBeaconSlot/);
  assert.doesNotMatch(source, /if \(renewal\)[\s\S]{0,800}_verify\(provedStatement, proof\)/);
  assert.match(source, /finalityBeaconSlot > currentSlot \|\| currentSlot - finalityBeaconSlot > MAX_FINALITY_AGE_SLOTS/);
});

test('pause, expiry and pruning release leases without erasing permanent debt or paid state', () => {
  assert.match(source, /\+\+queueEpoch;[\s\S]*pendingCount = 0;[\s\S]*firstPendingBurn = bytes32\(0\)/);
  assert.match(source, /pending\.queueEpoch == queueEpoch && block\.timestamp <= pending\.expiresAt/);
  assert.match(source, /provedBurnStatements\[burn\.burnId\] = statementHash;[\s\S]*provedBurnDebts\[burn\.burnId\] = debtHash/);
  assert.doesNotMatch(source, /delete provedBurn(?:Statements|Debts|FinalitySlots|RequestBurns)/);
  assert.doesNotMatch(source, /paidBurns\[[^\]]+\] = false|paidRequests\[[^\]]+\] = false/);
  assert.match(source, /paidBurns\[burn\.burnId\] = true;\s*paidRequests\[burn\.requestId\] = true/);
});

test('proved unpaid debt keeps collateral reserved independently of its queue lease', () => {
  assert.match(source, /uint256 credited = outstanding\(\);[\s\S]*totalProvedDebtAmount > credited[\s\S]*return credited - totalProvedDebtAmount;/);
  assert.match(source, /if \(!renewal\) \{[\s\S]*totalProvedDebtAmount \+= burn\.amount;/);
  assert.match(source, /totalReleased \+= burn\.amount;\s*totalProvedDebtAmount -= burn\.amount;/);
  assert.doesNotMatch(source, /function _removePending[\s\S]*totalProvedDebtAmount -=/);
  assert.doesNotMatch(source, /function _pauseState[\s\S]*totalProvedDebtAmount = 0/);
});

test('recipient freeze delays payment without suppressing irreversible debt admission', () => {
  const queue = source.match(/function queueWithdrawal[\s\S]*?function executeWithdrawal/)[0];
  const execute = source.match(/function executeWithdrawal[\s\S]*?function discardWithdrawal/)[0];
  assert.match(queue, /_requireTokenUsable\(address\(this\), address\(this\)\)/);
  assert.doesNotMatch(queue, /_requireTokenUsable\(address\(this\), burn\.recipient\)/);
  assert.match(execute, /_requireTokenUsable\(address\(this\), burn\.recipient\)/);
});

test('renewal can alter only finality while payout still consumes exact queued statement', () => {
  assert.match(source, /FinalizedBurnDebt\(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 validUntil,uint256 ethereumChainId,address reserve,bytes32 activationScheduleCommitment\)/);
  assert.match(source, /pending\.statementHash != burnStatementHash\(burn\)/);
  assert.match(source, /pending\.requestId/);
  assert.match(source, /_callToken\(abi\.encodeCall\(IERC20\.transfer, \(burn\.recipient, burn\.amount\)\)\)/);
});
