import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {readinessRequirementKeys} from '../../sdk/mainnet-readiness.mjs';

const node=process.execPath;
const root=new URL('../../',import.meta.url);
const requirements=JSON.parse(await readFile(new URL('../../config/production-requirements.json',import.meta.url)));
const generated=spawnSync(node,['scripts/write-open-claims-execution-plan.mjs'],{
  cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'},
});
assert.equal(generated.status,0,generated.stderr);
const plan=JSON.parse(generated.stdout);

test('current readiness has 57 routed claims and no obsolete Ledger or Linux transport gate',()=>{
  const readiness=new Set(readinessRequirementKeys('real-funds'));
  assert.equal(plan.claimCount,57);
  assert.equal(plan.entries.length,57);
  for(const obsolete of [
    'production_ledger_compatibility_disabled',
    'production_onekey_official_ble_transport_pinned',
    'production_onekey_desktop_electron_ble_handoff_authenticated_and_pinned',
    'production_onekey_usb_fallback_disabled',
    'production_onekey_eip1559_and_eip712_signing_verified',
  ]) assert.equal(readiness.has(obsolete),false,obsolete);
});

test('mobile Safe claims have concrete phases while external evidence remains false',()=>{
  const mobile=plan.entries.filter(({claim})=>claim.startsWith('production_onekey_'));
  assert.equal(mobile.length,24);
  assert.equal(mobile.filter(({claim})=>claim.startsWith('production_onekey_ios_safe_custody_')).length,8);
  assert.equal(mobile.filter(({claim})=>claim.startsWith('production_onekey_ios_relayer_')).length,6);
  assert.equal(mobile.filter(({phase})=>phase==='migrate-safe-owners-hardware-secret').length,10);
  assert.equal(mobile.filter(({phase})=>phase==='authorize-pilot-funds-secret').length,6);
  assert.equal(mobile.filter(({phase})=>phase==='execute-pilot-deposit-secret').length,8);
  for(const {claim,evidenceProducerCommands,independentValidatorCommands} of mobile) {
    assert.equal(requirements[claim],false,claim);
    assert.ok(evidenceProducerCommands.length>0,claim);
    assert.ok(independentValidatorCommands.length>0,claim);
  }
});

test('owner migration requires four Safes, twelve proofs, OneKey iPhone and zero Ledger',async()=>{
  const generator=await readFile(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
  assert.match(generator,/\["checkpointGuardian","governance","reserveGuardian","usdtCustody"\]/);
  assert.match(generator,/\(\.proofs\|length\)==12/);
  assert.match(generator,/prepare-onekey-ios-safe-mainnet-pilot\.sh --advance-custody/);
  assert.match(generator,/custody-proof-bundle-complete/);
  assert.doesNotMatch(generator,/--ledger|wallet address --ledger|wallet sign --data|prepare-ledger|assemble-ledger/i);
});
