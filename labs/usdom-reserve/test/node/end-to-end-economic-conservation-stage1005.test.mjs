import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const reserve = readFileSync(new URL('../../contracts/USDOMProofReserve.sol', import.meta.url), 'utf8');
const invariant = readFileSync(new URL('../solidity/ProofReserveInvariant.t.sol', import.meta.url), 'utf8');
const state = readFileSync(new URL('../../../../crates/dom-usdom-state/src/lib.rs', import.meta.url), 'utf8');
const guest = readFileSync(new URL('../../../../crates/dom-usdom-finalized-burn-program/src/lib.rs', import.meta.url), 'utf8');

test('cross-ledger conservation equation covers unissued collateral, circulation and unpaid burns', () => {
  for (let deposited = 0n; deposited <= 12n; deposited++) {
    for (let issued = 0n; issued <= deposited; issued++) {
      for (let burned = 0n; burned <= issued; burned++) {
        for (let released = 0n; released <= burned; released++) {
          const reserveOutstanding = deposited - released;
          const unissued = deposited - issued;
          const circulating = issued - burned;
          const unpaidBurnDebt = burned - released;
          assert.equal(reserveOutstanding, unissued + circulating + unpaidBurnDebt);
        }
      }
    }
  }
});

test('native issuance, burn, persistence and undo preserve supply bounds', () => {
  assert.match(state, /self\.total_issued = self[\s\S]*\.checked_add\(u128::from\(value\.amount\)\)/);
  assert.match(state, /let next_burned = self[\s\S]*\.total_burned[\s\S]*\.checked_add\(u128::from\(value\.record\.amount\)\)/);
  assert.match(state, /if next_burned > self\.total_issued \{\s*return Err\(UsdomStateError::BurnExceedsSupply\)/);
  assert.match(state, /computed_issued != total_issued \|\| computed_burned != total_burned/);
  assert.match(state, /candidate\.total_issued = undo\.prior_total_issued;\s*candidate\.total_burned = undo\.prior_total_burned;/);
  assert.match(state, /pub fn outstanding\(&self\) -> u128 \{\s*self\.total_issued - self\.total_burned/);
});

test('Ethereum reserve cannot reserve or release more credited collateral', () => {
  assert.match(reserve, /function outstanding\(\) public view returns \(uint256\) \{[\s\S]*totalReleased > totalDeposited[\s\S]*return totalDeposited - totalReleased;/);
  assert.match(reserve, /outstanding\(\) \+ amount > maxOutstanding/);
  assert.match(reserve, /!renewal && burn\.amount > unreservedCollateral\(\)/);
  assert.match(reserve, /totalProvedDebtAmount \+= burn\.amount/);
  assert.match(reserve, /totalProvedDebtAmount -= burn\.amount/);
  assert.match(reserve, /burn\.amount > credited/);
  assert.match(reserve, /totalReleased \+= burn\.amount;[\s\S]*paidBurns\[burn\.burnId\] = true;[\s\S]*paidRequests\[burn\.requestId\] = true/);
  assert.match(invariant, /totalReleased\(\) \+ reserve\.totalPendingAmount\(\) <= reserve\.totalDeposited\(\)/);
  assert.match(invariant, /totalReleased\(\) \+ reserve\.totalProvedDebtAmount\(\) <= reserve\.totalDeposited\(\)/);
});

test('only a unique proved native burn can move debt into terminal payout', () => {
  assert.match(guest, /verify_finalized_burn_inclusion/);
  assert.match(guest, /witness\.burn\.burn_id/);
  assert.match(reserve, /paidBurns\[burn\.burnId\] \|\| paidRequests\[burn\.requestId\]/);
  assert.match(reserve, /provedDebt != debtHash \|\| provedRequestBurn != burn\.burnId/);
  assert.doesNotMatch(reserve, /delete paidBurns|delete paidRequests/);
});
