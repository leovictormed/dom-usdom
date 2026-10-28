import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const generator=path.join(root,'scripts/generate-closed-mainnet-phase-command.sh');
const phases=[
  'enroll-safe-owners-secret','migrate-safe-owners-hardware-secret',
  'execute-safe-controls-deployment-secret','prepare-safe-recovery-secret',
  'execute-safe-recovery-secret','derive-deployment-identity-secret',
  'execute-mainnet-deployment-secret','execute-reserve-resume-secret',
  'prepare-native-wallet-secret','execute-pilot-deposit-secret','submit-pilot-burn-secret',
  'execute-pilot-redemption-secret','produce-checkpoint-evidence-secret',
];

test('every secret phase disables tracing, core dumps and ambient injection before secrets',()=>{
  for(const phase of phases) {
    const generated=spawnSync('/usr/bin/bash',[generator,phase],{
      cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin',BASH_ENV:'/attacker',
        NODE_OPTIONS:'--require=/attacker',HTTPS_PROXY:'https://attacker.invalid'},
    });
    assert.equal(generated.status,0,`${phase}: ${generated.stderr}`);
    const source=generated.stdout;
    assert.equal(spawnSync('/usr/bin/bash',['-n'],{input:source,encoding:'utf8'}).status,0,phase);
    const trace=source.indexOf('set +x'),strict=source.indexOf('set -euo pipefail');
    const core=source.indexOf('ulimit -c 0'),project=source.indexOf('export USDOM_PROJECT=');
    assert.equal(trace,0,`${phase} must disable inherited xtrace first`);
    assert.ok(trace<strict&&strict<core&&core<project,`${phase} protection order`);
    assert.match(source,/unset BASH_XTRACEFD/);
    assert.match(source,/unset BASH_ENV ENV CDPATH NODE_OPTIONS NODE_PATH/);
    assert.match(source,/HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY/);
    assert.match(source,/SSLKEYLOGFILE SSL_CERT_FILE SSL_CERT_DIR CURL_CA_BUNDLE NODE_EXTRA_CA_CERTS/);
    assert.match(source,/for fd_path in \/proc\/\$\$\/fd\/\*/);
    assert.match(source,/exec \{inherited_fd\}>&-/);
    assert.doesNotMatch(source,/(^|\n)\s*(?:eval|source|\.)\s+/);
    assert.doesNotMatch(source,/(?:chmod|install\s+-m)\s+0?(?:666|777)\b/);
  }
});

test('generator itself does not interpolate caller-controlled phase text or secret environment',()=>{
  const source=readFileSync(generator,'utf8');
  assert.match(source,/case "\$phase" in/);
  const attack=spawnSync('/usr/bin/bash',[generator,'$(touch /tmp/usdom-injection)'],{
    cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'},
  });
  assert.notEqual(attack.status,0);
  assert.doesNotMatch(`${attack.stdout}${attack.stderr}`,/NODE_OPTIONS|HTTPS_PROXY|attacker/);
});

test('owner enrollment imports only the already verified OneKey identities',()=>{
  const generated=spawnSync('/usr/bin/bash',[generator,'enroll-safe-owners-secret'],{
    cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'},
  });
  assert.equal(generated.status,0,generated.stderr);
  assert.match(generated.stdout,/prepare-onekey-ios-safe-mainnet-pilot\.sh --status-onboarding/);
  assert.match(generated.stdout,/safe-owner-identities-v2\.json/);
  assert.match(generated.stdout,/owner-\$\(\(owner_index\+1\)\)-evidence\.json/);
  assert.doesNotMatch(generated.stdout,/wallet new|safe-keystores|--password/);
});
