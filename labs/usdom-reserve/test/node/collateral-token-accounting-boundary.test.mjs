import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const reserve = readFileSync(new URL("../../contracts/USDOMReserve.sol", import.meta.url), "utf8");
const proof = readFileSync(new URL("../../contracts/USDOMProofReserve.sol", import.meta.url), "utf8");
const invariant = readFileSync(new URL("../solidity/ReserveInvariant.t.sol", import.meta.url), "utf8");
const policy = readFileSync(new URL("../solidity/USDTPolicy.t.sol", import.meta.url), "utf8");

for (const source of [reserve, proof]) {
  assert.match(source, /bytes32 public immutable tokenCodeHash;/);
  assert.match(source, /address\(token\)\.codehash != tokenCodeHash/);
  assert.match(source, /return totalDeposited - totalReleased;/);
  assert.match(source, /balanceOf\(address\(this\)\) \+ burn\.amount != reserveBefore|_tokenBalanceOf\(address\(this\)\) \+ burn\.amount != reserveBefore/);
  assert.match(source, /balanceOf\(burn\.recipient\) != recipientBefore \+ burn\.amount|_tokenBalanceOf\(burn\.recipient\) != recipientBefore \+ burn\.amount/);
  assert.match(source, /IUSDTPolicy\.paused[\s\S]*IUSDTPolicy\.deprecated[\s\S]*IUSDTPolicy\.basisPointsRate[\s\S]*IUSDTPolicy\.maximumFee/);
}
assert.match(proof, /uint256 credited = outstanding\(\);[\s\S]*totalProvedDebtAmount > credited[\s\S]*return credited - totalProvedDebtAmount;/);
assert.match(proof, /totalProvedDebtAmount \+= burn\.amount/);
assert.match(proof, /totalProvedDebtAmount -= burn\.amount/);
assert.match(proof, /IUSDTPolicy\.upgradedAddress[\s\S]*!= bytes32\(0\)/);
assert.match(reserve, /burn\.amount > unreservedCollateral\(\)/);
assert.match(reserve, /elapsed >= REFILL_PERIOD/);
assert.match(invariant, /ghostDeposited/);
assert.match(invariant, /ghostPaid/);
assert.match(invariant, /ghostDonated/);
assert.match(invariant, /reserve\.tokenCodeHash\(\).*address\(token\)\.codehash/);
assert.match(policy, /testChangedTokenRuntimeCannotMutateCollateralLedger/);
console.log("collateral/token accounting boundary: ok");
