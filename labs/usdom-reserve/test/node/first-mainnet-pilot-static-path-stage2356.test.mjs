import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const generator=readFileSync(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
const orchestrator=readFileSync(new URL('../../scripts/prepare-onekey-ios-safe-mainnet-pilot.sh',import.meta.url),'utf8');

test('owner onboarding and twelve custody signatures are separate resumable scopes',()=>{
  for(const marker of ['--status-onboarding','--advance-onboarding','--status-custody','--advance-custody','onboarding-complete','custody-proof-bundle-complete']) assert.match(orchestrator,new RegExp(marker));
  assert.ok(orchestrator.indexOf('[[ $mode != --advance-onboarding ]]')<orchestrator.indexOf(': "${USDOM_SAFE_PACKAGE:?required}"'));
  assert.ok(orchestrator.indexOf('[[ $mode != --advance-custody ]]')<orchestrator.indexOf('custody_authority='));
});

test('migration derives one prospective package before the mobile custody loop',()=>{
  const result=spawnSync('bash',['scripts/generate-closed-mainnet-phase-command.sh','migrate-safe-owners-hardware-secret'],{encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
  assert.equal(result.status,0,result.stderr);
  const source=result.stdout;
  const onboarding=source.indexOf('--advance-onboarding'),prepare=source.indexOf('prepare:recoverable-safe-controls'),custody=source.indexOf('--advance-custody');
  assert.ok(onboarding>=0&&prepare>onboarding&&custody>prepare);
  assert.match(source,/USDOM_PILOT_STATE_DIR\/safe-owner-identities-v2\.json/);
  assert.match(source,/USDOM_PILOT_STATE_DIR\/safe-owner-hardware-custody-proofs-v1\.json/);
  assert.doesNotMatch(source,/pilot-identity-and-offline-recovery-drill-complete/);
  assert.equal(spawnSync('bash',['-n'],{input:source,encoding:'utf8'}).status,0);
});

test('pilot funder comes from finalized usdtCustody Safe and never a null template',()=>{
  const start=generator.indexOf('  authorize-pilot-funds-secret)'),end=generator.indexOf('  execute-pilot-deposit-secret)');
  const phase=generator.slice(start,end);
  assert.match(phase,/USDOM_SAFE_BASELINE/);
  assert.match(phase,/\.role=="usdtCustody"/);
  assert.match(phase,/exactly one finalized USDT custody Safe is required/);
  assert.doesNotMatch(phase,/onekey-ios-safe-usdt-custody-authority\.unconfigured\.json/);
});
