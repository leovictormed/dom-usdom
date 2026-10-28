import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const prep=readFileSync(new URL("../../scripts/prepare-recoverable-safe-controls.mjs",import.meta.url),"utf8");
const sdk=readFileSync(new URL("../../sdk/safe-control-deployment.mjs",import.meta.url),"utf8");
const runbook=readFileSync(new URL("../../docs/CLOSED-MAINNET-LINUX-RUNBOOK.md",import.meta.url),"utf8");
assert.match(prep,/USDOM_SAFE_OWNER_IDENTITIES/);
assert.match(prep,/readDirectFile\(ownerIdentityPath/);
assert.match(prep,/exactMode:0o600/);
assert.match(prep,/currentOwnerIdentityBytes\.equals\(ownerIdentityBytes\)/);
assert.doesNotMatch(prep,/USDOM_SAFE_PRIMARY_OWNER/);
assert.match(sdk,/RECOVERABLE_SAFE_THRESHOLD = 2/);
assert.match(sdk,/RECOVERABLE_SAFE_OWNER_COUNT = 3/);
assert.match(sdk,/Safe owners must be distinct/);
assert.match(sdk,/every Safe owner must be a hardware-wallet EOA/);
assert.match(runbook,/três owners exclusivos e\s+quórum 2-de-3/);
assert.match(runbook,/materialize:mainnet-deployment-identity/);
assert.match(runbook,/sign:native-release-attestations/);
assert.match(runbook,/generate-closed-mainnet-phase-command\.sh enroll-safe-owners-secret/);
assert.match(runbook,/generate-closed-mainnet-phase-command\.sh execute-safe-controls-deployment-secret/);
assert.match(runbook,/generate-closed-mainnet-phase-command\.sh prepare-safe-recovery-secret/);
for(const forbidden of ['--private-key','--mnemonic','threshold == "1"','PLACEHOLDER','SUBSTITUA']) {
  assert.equal(runbook.includes(forbidden),false,forbidden);
}
console.log("Safe owner ceremony: ok");
