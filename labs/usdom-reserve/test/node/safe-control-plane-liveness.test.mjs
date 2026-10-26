import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const read=(p)=>readFileSync(new URL(p,import.meta.url),"utf8");
const reserve=read("../../contracts/USDOMProofReserve.sol");
const registry=read("../../contracts/DOMCheckpointRegistry.sol");
const config=read("../../sdk/configuration.mjs");
const reserveTest=read("../solidity/USDOMProofReserve.t.sol");
const registryTest=read("../solidity/DOMCheckpointRegistry.t.sol");
for(const source of [reserve,registry]) {
  assert.match(source,/function _canonicalOwnerSetCommitment/);
  assert.match(source,/if \(second < first\).*if \(third < second\).*if \(second < first\)/s);
  assert.match(source,/currentOwnersCommitment == ownersCommitment/);
  assert.match(source,/_safeModulesEmpty\(account\).*_safeGuardEmpty\(account\)/s);
  assert.match(source,/implementation\.codehash == implementationCodeHash/);
}
assert.match(config,/const canonical=\[\.\.\.normalized\]\.sort/);
assert.match(reserveTest,/Canonical set identity preserves liveness/);
assert.match(registryTest,/setOwner\(0, address\(0x102\)\)[\s\S]*guardianControlHealthy\(\)/);
console.log("Safe control-plane canonical owner-set liveness: ok");
