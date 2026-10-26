import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');
const scriptsDir=path.join(component,'scripts');
const memoryBearing=[
  'submit-closed-mainnet-private-burn.sh','register-finalized-deposit-wallet.sh',
  'observe-finalized-deposit-wallet.sh','drill-closed-mainnet-wallet-recovery.sh',
  'bootstrap-closed-mainnet-tpm-authority.sh','build-finalized-deposit-witness.sh',
  'execute-mainnet-deployment.sh','execute-recoverable-safe-recovery.sh',
  'sign-release-authorizations.sh','sign-checkpoint-bootstrap-ratification.sh',
  'sign-recoverable-safe-recovery.sh',
];

test('every credential or signature memory-bearing shell disables tracing and core dumps',async()=>{
  for(const name of memoryBearing) {
    const source=await readFile(path.join(scriptsDir,name),'utf8');
    assert.match(source,/set \+x/,
      `${name}: inherited xtrace must stop before sensitive variables`);
    assert.match(source,/unset BASH_XTRACEFD/,
      `${name}: inherited xtrace descriptor must be detached`);
    assert.match(source,/if ! ulimit -c 0; then[\s\S]*exit 1[\s\S]*fi/,
      `${name}: core disabling must fail closed`);
    assert.ok(source.indexOf('set +x')<source.indexOf('command -v'),`${name}: tracing stops before children`);
  }
});

test('release/native wrappers stop inherited tracing before delegating',async()=>{
  for(const name of ['sign-native-release-attestations.sh','sign-production-release-authorization.sh']) {
    const source=await readFile(path.join(scriptsDir,name),'utf8');
    assert.ok(source.indexOf('set +x')<source.indexOf('exec bash'));
    assert.ok(source.indexOf('unset BASH_XTRACEFD')<source.indexOf('exec bash'));
  }
});

test('password and TPM authorization values are never exported or placed in argv',async()=>{
  const names=memoryBearing.slice(0,5);
  for(const name of names) {
    const source=await readFile(path.join(scriptsDir,name),'utf8');
    assert.doesNotMatch(source,/export\s+(?:recovery_password|tpm_owner_authorization)/);
    assert.doesNotMatch(source,/--(?:password|recovery-password|owner-auth)(?:=|\s+)"?\$(?:recovery_password|tpm_owner_authorization)/);
  }
});

test('local hardening suppresses inherited xtrace and propagates zero core limit',()=>{
  const body='set +x; unset BASH_XTRACEFD 2>/dev/null || true; ulimit -c 0 || exit 1; secret=never-print-this; bash -c \'test "$(ulimit -c)" = 0\'';
  const result=spawnSync('bash',['-x','-c',body],{encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  assert.doesNotMatch(result.stderr,/never-print-this/);
});
