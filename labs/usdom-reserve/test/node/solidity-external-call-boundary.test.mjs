import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (name) => readFileSync(new URL(`../../contracts/${name}`, import.meta.url), "utf8");
const reserves = [read("USDOMReserve.sol"), read("USDOMProofReserve.sol")];
const registry = read("DOMCheckpointRegistry.sol");
const burnAdapter = read("DOMFinalizedBurnRiscZeroVerifier.sol");
const checkpointAdapter = read("DOMCheckpointRiscZeroVerifier.sol");
const tests = readFileSync(new URL("../solidity/USDTPolicy.t.sol", import.meta.url), "utf8");

for (const source of reserves) {
  assert.match(source, /TOKEN_GAS_LIMIT = 500_000/);
  assert.match(source, /staticcall\(TOKEN_GAS_LIMIT, target,[\s\S]*returndatasize\(\)[\s\S]*returnSize != 32/);
  assert.match(source, /call\(TOKEN_GAS_LIMIT, target,[\s\S]*returnSize != 0[\s\S]*returnSize != 32/);
  assert.match(source, /uint256\(word\) > 1/);
  assert.doesNotMatch(source, /IUSDTPolicy policy/);
  assert.doesNotMatch(source, /token\.balanceOf\(/);
}
for (const source of [registry, reserves[1]]) {
  assert.match(source, /function _staticcallWord[\s\S]*staticcall\(gasLimit,[\s\S]*returnSize == 32/);
}
for (const source of [burnAdapter, checkpointAdapter]) {
  assert.match(source, /RISC_ZERO_VERIFIER_GAS_LIMIT/);
  assert.match(source, /staticcall\(RISC_ZERO_VERIFIER_GAS_LIMIT,[\s\S]*returnSize != 0/);
  assert.match(source, /uint256\(word\) & type\(uint224\)\.max/);
}
assert.match(tests, /testPolicyReturnBombAndDirtyBooleanFailClosedAtBoundedBoundary/);
console.log("Solidity external-call boundaries: ok");
