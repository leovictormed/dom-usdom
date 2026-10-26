import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const source = readFileSync(new URL('../../contracts/USDOMProofReserve.sol', import.meta.url), 'utf8');

test('public collateral arithmetic fails closed before subtraction', () => {
  assert.match(source, /if \(totalReleased > totalDeposited\) revert Insolvent\(\);\s*return totalDeposited - totalReleased;/);
  assert.match(source, /uint256 credited = outstanding\(\);\s*if \(totalProvedDebtAmount > credited\) revert Insolvent\(\);\s*return credited - totalProvedDebtAmount;/);
});

test('payout revalidates exact permanent debt identity and latest renewal slot', () => {
  const execution = source.match(/function executeWithdrawal\([\s\S]*?\n    function discardWithdrawal/);
  assert.ok(execution, 'executeWithdrawal body');
  assert.match(execution[0], /pending\.statementHash != burnStatementHash\(burn\)/);
  assert.match(execution[0], /provedBurnDebts\[burn\.burnId\] != burnDebtHash\(burn\)/);
  assert.match(execution[0], /provedRequestBurns\[burn\.requestId\] != burn\.burnId/);
  assert.match(execution[0], /provedBurnFinalitySlots\[burn\.burnId\] != burn\.finalityBeaconSlot/);
  assert.match(execution[0], /totalProvedDebtAmount -= burn\.amount;[\s\S]*_removePending\(burn\.burnId, pending\);[\s\S]*_callToken/);
});

test('lease disposal and emergency invalidation cannot release permanent debt', () => {
  const removal = source.match(/function _removePending\([\s\S]*?\n    function _hasActivePendingRequest/);
  const pause = source.match(/function _pauseState\([\s\S]*?\n    function scheduleResume/);
  assert.ok(removal && pause);
  assert.doesNotMatch(removal[0], /totalProvedDebtAmount/);
  assert.doesNotMatch(pause[0], /totalProvedDebtAmount\s*=/);
  assert.match(source, /!depositsClosed \|\| paused \|\| totalDeposited != totalReleased[\s\S]*totalProvedDebtAmount != 0/);
});

test('reserve is a constructor deployment with no upgrade or arbitrary state mutation surface', () => {
  assert.match(source, /constructor\(Config memory config\)/);
  assert.doesNotMatch(source, /\b(?:upgradeTo|upgradeToAndCall|delegatecall|selfdestruct)\b/);
  assert.doesNotMatch(source, /function\s+(?:set|initialize)[A-Z_]/);
});

test('proof admission probes reserve policy without self-transfer or recipient censorship', () => {
  const queue = source.match(/function queueWithdrawal\([\s\S]*?\n    function executeWithdrawal/);
  const execution = source.match(/function executeWithdrawal\([\s\S]*?\n    function discardWithdrawal/);
  assert.ok(queue && execution);
  assert.match(queue[0], /_requireTokenUsable\(address\(this\), address\(this\)\)/);
  assert.doesNotMatch(queue[0], /_requireTokenUsable\(address\(this\), burn\.recipient\)/);
  assert.doesNotMatch(queue[0], /_callToken\(/);
  assert.match(queue[0], /burn\.amount > unreservedCollateral\(\)[\s\S]*_tokenBalanceOf\(address\(this\)\) < outstanding\(\)[\s\S]*_verify\(statementHash, proof\);[\s\S]*totalProvedDebtAmount \+= burn\.amount/);
  assert.match(execution[0], /_requireTokenUsable\(address\(this\), burn\.recipient\)[\s\S]*_callToken\(abi\.encodeCall\(IERC20\.transfer/);
});
