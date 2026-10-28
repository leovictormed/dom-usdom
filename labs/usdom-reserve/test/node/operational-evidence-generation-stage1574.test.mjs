import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const root=new URL('../../',import.meta.url);
const source=name=>readFile(new URL(name,root),'utf8');

test('mutable operational evidence is release, generation or live-state bound',async()=>{
 const [deposit,payout,phase,deployment,gas,capacity,health]=await Promise.all([
  source('sdk/closed-mainnet-deposit-evidence.mjs'),
  source('sdk/closed-mainnet-payout-evidence.mjs'),
  source('scripts/check-closed-mainnet-phase-artifacts.mjs'),
  source('sdk/deployment-evidence.mjs'),
  source('sdk/production-operational-gas-evidence.mjs'),
  source('sdk/checkpoint-proof-capacity-report.mjs'),
  source('sdk/risc0-health.mjs'),
 ]);
 for(const text of [deposit,payout]) {
  assert.match(text,/packageSha256/);
  assert.match(text,/baseline\.packageSha256!==packageSha256/);
 }
 assert.match(phase,/packageSha256:loaded\.get\('depositPackage'\)\.sha256/);
 assert.match(phase,/packageSha256:loaded\.get\('redemptionPackage'\)\.sha256/);
 for(const field of ['releaseConfigSha256','packageSha256','rpcCatalogSha256',
  'observationDocumentSha256']) assert.match(deployment,new RegExp(field));
 assert.match(gas,/releaseConfigSha256:job\.releaseConfigSha256/);
 assert.match(gas,/jobCommitment:job\.jobCommitment/);
 assert.match(capacity,/report\.releaseId!==evidence\?\.releaseId/);
 assert.match(capacity,/report\.sourceCommit!==evidence\?\.sourceCommit/);
 assert.match(health,/snapshotBlockHashAfter/);
 assert.match(health,/risc0_finalized_snapshot_changed/);
});

test('immutable build evidence is reusable only through exact content and toolchain pins',async()=>{
 const [reserve,verifier,localGas]=await Promise.all([
  source('sdk/reserve-reproducible-build-report.mjs'),
  source('sdk/verifier-reproducible-build-report.mjs'),
  source('sdk/local-operational-gas-evidence.mjs'),
 ]);
 for(const text of [reserve,verifier]) {
  assert.match(text,/sourceCommit/);
  assert.match(text,/artifactExecutableSha256|runtimeCodeHash/);
 }
 assert.match(localGas,/operational gas input hash changed/);
 assert.match(localGas,/productionRequirementsRemainFalse/);
});
