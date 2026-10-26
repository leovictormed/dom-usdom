import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repo = path.resolve(import.meta.dirname, "../../../..");
const source = (relative) => fs.readFileSync(path.join(repo, relative), "utf8");

function removalBody(contract) {
  const start = contract.indexOf("function _removePending");
  const end = contract.indexOf("function _hasActivePendingRequest", start);
  return contract.slice(start, end < 0 ? contract.indexOf("function availableOutflow", start) : end);
}

test("both queues validate accounting and reciprocal links before active-generation splice", () => {
  for (const file of ["USDOMProofReserve.sol", "USDOMReserve.sol"]) {
    const splice = removalBody(source(`labs/usdom-reserve/contracts/${file}`));
    assert.match(splice, /pendingCount == 0 \|\| totalPendingAmount < pending\.amount/u, file);
    assert.match(splice, /previous\.next != burnId/u, file);
    assert.match(splice, /following\.previous != burnId/u, file);
    assert.ok(splice.indexOf("totalPendingAmount < pending.amount") < splice.indexOf("totalPendingAmount -= pending.amount"), file);
  }
});

test("old-generation cleanup cannot erase a replacement request mapping", () => {
  for (const file of ["USDOMProofReserve.sol", "USDOMReserve.sol"]) {
    const splice = removalBody(source(`labs/usdom-reserve/contracts/${file}`));
    assert.match(splice, /pendingRequests\[pending\.requestId\] == burnId/u, file);
  }
});

test("proof queue rejects corrupted generation headers and live-neighbor stale cleanup", () => {
  const contract = source("labs/usdom-reserve/contracts/USDOMProofReserve.sol");
  const prune = contract.slice(contract.indexOf("function pruneExpired"), contract.indexOf("function availableOutflow"));
  const splice = removalBody(contract);

  assert.match(prune, /pending\.statementHash == bytes32\(0\)/u);
  assert.match(prune, /pending\.queueEpoch != queueEpoch/u);
  assert.match(prune, /pending\.previous != bytes32\(0\)/u);
  assert.match(splice, /firstPendingBurn == burnId \|\| lastPendingBurn == burnId/u);
  assert.match(splice, /previous\.queueEpoch == queueEpoch && previous\.next == burnId/u);
  assert.match(splice, /following\.queueEpoch == queueEpoch && following\.previous == burnId/u);
});

test("prototype invariant and regression exercise prune, epoch reset and exact ID reuse", () => {
  const invariant = source("labs/usdom-reserve/test/solidity/ReserveInvariant.t.sol");
  assert.match(invariant, /function prune\(uint16 maximum\)/u);
  assert.match(invariant, /selectors\[15\] = handler\.prune\.selector/u);

  const regression = source("labs/usdom-reserve/test/solidity/USDOMReserve.t.sol");
  assert.match(regression, /testRotationResetAllowsExactIdsOnlyAfterStaleEntryCleanup/u);
  assert.match(regression, /reserve\.discardWithdrawal\(b\.burnId\)/u);
  assert.match(regression, /b\.epoch = reserve\.currentEpoch\(\)/u);
  assert.match(regression, /reserve\.pendingRequests\(b\.requestId\), b\.burnId/u);
});
