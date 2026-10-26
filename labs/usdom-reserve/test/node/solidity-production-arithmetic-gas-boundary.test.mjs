import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repo = path.resolve(import.meta.dirname, "../../../..");
const source = (relative) => fs.readFileSync(path.join(repo, relative), "utf8");

test("both RISC Zero adapters cap verifier gas and copy no returndata", () => {
  for (const file of ["DOMFinalizedBurnRiscZeroVerifier.sol", "DOMCheckpointRiscZeroVerifier.sol"]) {
    const body = source(`labs/usdom-reserve/contracts/${file}`);
    assert.match(body, /RISC_ZERO_VERIFIER_GAS_LIMIT = 4_500_000/u, file);
    assert.match(body, /staticcall\(RISC_ZERO_VERIFIER_GAS_LIMIT,[^\n]+, 0, 0\)/u, file);
    assert.doesNotMatch(body, /staticcall\(gas\(\),/u, file);
    assert.match(body, /returnSize != 0/u, file);
  }
});

test("queue splice validates accounting and reciprocal links before mutation", () => {
  const reserve = source("labs/usdom-reserve/contracts/USDOMProofReserve.sol");
  const start = reserve.indexOf("function _removePending");
  const end = reserve.indexOf("function _hasActivePendingRequest", start);
  const splice = reserve.slice(start, end);
  assert.match(splice, /pendingCount == 0 \|\| totalPendingAmount < pending\.amount/u);
  assert.match(splice, /previous\.queueEpoch != queueEpoch \|\| previous\.next != burnId/u);
  assert.match(splice, /following\.queueEpoch != queueEpoch \|\| following\.previous != burnId/u);
  assert.ok(splice.indexOf("totalPendingAmount < pending.amount") < splice.indexOf("totalPendingAmount -= pending.amount"));
});

test("challenge and reserve timestamp additions check uint64 headroom first", () => {
  const registry = source("labs/usdom-reserve/contracts/DOMCheckpointRegistry.sol");
  const reserve = source("labs/usdom-reserve/contracts/USDOMProofReserve.sol");
  assert.match(registry, /_timestampAfter\(challengePeriod\)/u);
  assert.match(registry, /block\.timestamp > type\(uint64\)\.max - delay/u);
  assert.match(reserve, /block\.timestamp > type\(uint64\)\.max - delay/u);

  const tests = source("labs/usdom-reserve/test/solidity/DOMCheckpointRegistry.t.sol");
  assert.match(tests, /testChallengeTimestampOverflowUsesProtocolError/u);
  assert.match(tests, /vm\.warp\(type\(uint64\)\.max\)/u);
});
