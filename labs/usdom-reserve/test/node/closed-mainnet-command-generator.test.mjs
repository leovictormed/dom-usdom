import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';

const generator=fs.readFileSync(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
const dagChecker=fs.readFileSync(new URL('../../scripts/check-closed-mainnet-phase-artifacts.mjs',import.meta.url),'utf8');
const toolchainChecker=fs.readFileSync(new URL('../../scripts/check-mainnet-toolchain.mjs',import.meta.url),'utf8');
const toolchainLock=JSON.parse(fs.readFileSync(new URL('../../config/mainnet-toolchain-lock.json',import.meta.url),'utf8'));
const solcBootstrap=fs.readFileSync(new URL('../../scripts/bootstrap-solc-0.8.37.sh',import.meta.url),'utf8');
const solcMaterializer=fs.readFileSync(new URL('../../scripts/materialize-solc-toolchain-lock.mjs',import.meta.url),'utf8');
const runbook=fs.readFileSync(new URL('../../docs/CLOSED-MAINNET-LINUX-RUNBOOK.md',import.meta.url),'utf8');
const generatorPath=fileURLToPath(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url));
const phases=['prerequisites','enroll-safe-owners-secret','migrate-safe-owners-hardware-secret',
 'prepare-safe-controls','execute-safe-controls-deployment-secret','validate-local','derive-deployment-identity-secret','prepare-deployment',
 'prepare-safe-recovery-secret','execute-safe-recovery-secret','materialize-safe-control-config',
 'execute-pilot-deposit-secret','execute-pilot-redemption-secret','checklist','readiness'];

assert.doesNotMatch(runbook,/safe-package-primary\.json/);
assert.match(runbook,/safe-package\.json/);
assert.match(generator,/readonly project=\/home\/leonardov\/usdom-security-audit-20261015\/implementation-dom-protocol\/labs\/usdom-reserve/);
assert.match(generator,/readonly evidence=\/home\/leonardov\/usdom-mainnet-private\/control-plane/);
assert.match(generator,/enroll-safe-owners-secret/);
assert.match(generator,/\.threshold=="2"/);
assert.match(generator,/for role in governance reserveGuardian checkpointGuardian/);
assert.match(generator,/for slot in primary secondary recovery/);
assert.match(generator,/wallet new "\$USDOM_SAFE_KEYSTORE_DIRECTORY" "\$name" --password/);
assert.match(generator,/safe-owner-identities\/v2/);
assert.match(generator,/unique\|length\)==9/);
assert.match(generator,/--no-clobber --reflink=never/);
assert.match(generator,/stat -c '%u:%a:%h'/);
assert.match(generator,/stat -c '%d:%i'/);
assert.match(generator,/USDOM_SAFE_PUBLIC_BUNDLE/);
assert.match(generator,/usdom-safe-owner-hardware-custody-proofs\/v1/);
assert.match(generator,/USDOM Safe Owner Custody Proof/);
assert.match(generator,/wallet sign --data --from-file "\$typed" --ledger/);
assert.match(generator,/wallet verify --address "\$owner" --data --from-file/);
assert.match(generator,/Durable two-step publication/);
assert.match(generator,/Authenticated hardware owner migration was already complete or recovered after an interrupted publication/);
assert.match(generator,/check-safe-owner-hardware-custody-proofs\.mjs/);
assert.match(generator,/owner=\$\(jq -nr --argjson owners "\$owners_json"/);
assert.doesNotMatch(generator,/owner=\$\(jq -er[^\n]+"\$target_package"/);
assert.match(generator,/with_entries\(\.value \|= map\(ascii_downcase\)\|sort\)/);
assert.match(generator,/export USDOM_SAFE_OWNER_IDENTITIES="\$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"/);
assert.match(generator,/safe-recovery-transitions-v2\.json/);
assert.match(generator,/sign:recoverable-safe-recovery/);
assert.match(generator,/check-safe-recovery-replacement-proofs\.mjs/);
assert.match(generator,/execute-safe-recovery-secret/);
assert.match(generator,/execute-safe-controls-deployment-secret/);
assert.match(generator,/execute:recoverable-safe-recovery/);
assert.match(generator,/usdom-safe-recovery-session\/v2/);
assert.match(generator,/Authenticated Safe recovery session resumed without discarding durable signatures/);
assert.match(generator,/broadcasting is intentionally absent/);
assert.doesNotMatch(generator,/replacement_proof_candidate"\+/);
assert.match(generator,/write:recoverable-safe-release-evidence/);
assert.match(generator,/materialize:safe-control-release-config/);
assert.doesNotMatch(generator,/export USDOM_MAINNET_PREFLIGHT_RPC_SOURCES='/);
assert.match(generator,/USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE/);
assert.doesNotMatch(generator,/--unsafe-password|CAST_PASSWORD/);
assert.match(generator,/export PATH=\/usr\/lib\/chatgpt\/resources\/cua_node\/bin:[^\n]+:\/bin\n/);
assert.doesNotMatch(generator,/export PATH=.*\\\$PATH/);
assert.match(generator,/if test -e "\$USDOM_SAFE_OWNER_IDENTITIES"/);
assert.match(generator,/cmp -s "\$candidate" "\$USDOM_SAFE_PACKAGE"/);
assert.match(generator,/cmp -s "\$candidate" "\$USDOM_MAINNET_DEPLOYMENT_PACKAGE"/);
assert.match(generator,/node scripts\/check-mainnet-toolchain\.mjs/);
assert.match(generator,/npm_config_offline=true/);
assert.match(generator,/CARGO_NET_OFFLINE=true/);
assert.match(generator,/FOUNDRY_OFFLINE=true/);
assert.match(generator,/missing pre-staged solc 0\.8\.37/);
assert.doesNotMatch(generator,/execute:mainnet-deployment|cast send|cast publish/);
assert.match(generator,/USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION_SHA256=\$\(sha256sum/);
assert.match(generator,/node scripts\/check-closed-mainnet-phase-artifacts\.mjs/);
assert.doesNotMatch(generator,/check_file\(\).*test -s/);
assert.match(dagChecker,/validateRecoverableSafeControlBaseline\(baseline,safePackage\)/);
assert.match(dagChecker,/bound-to-owners-awaiting-baseline/);
assert.match(dagChecker,/validateMainnetDeploymentIdentityObservation/);
assert.match(dagChecker,/validateMainnetDeploymentPackage\(deployment\)/);
assert.match(dagChecker,/deployment\.observationDocumentSha256!==loaded\.get\('identity'\)\.sha256/);
assert.match(dagChecker,/deployment\.releaseConfigSha256!==sha\(releaseBytes\)/);
assert.equal(toolchainLock.schema,'usdom-mainnet-toolchain-lock/v1');
assert.equal(toolchainLock.executables.length,8);
assert.equal(toolchainLock.solc.version,'0.8.37');
assert.match(toolchainChecker,/solc 0\.8\.37 is not pre-staged and hash-locked/);
assert.doesNotMatch(toolchainChecker,/execFile|spawn|https?:\/\//);
assert.match(solcBootstrap,/curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https'/);
assert.match(solcBootstrap,/test "\$\(sha256sum "\$candidate" \| awk '\{print \$1\}'\)" = "\$expected"/);
assert.match(solcBootstrap,/ln "\$candidate" "\$target"/);
assert.doesNotMatch(solcBootstrap,/curl[^\n]*\|\s*(?:sh|bash)/);
assert.match(solcMaterializer,/O_NOFOLLOW/);
assert.match(solcMaterializer,/fstatSync\(descriptor\)/);
assert.doesNotMatch(solcMaterializer,/\bstatSync\(descriptor\)/);
assert.match(solcMaterializer,/lock\.solc\.sha256=manifest\.sha256/);
assert.match(solcMaterializer,/renameSync\(temporary,lockPath\)/);

for(const phase of phases){
  const result=spawnSync('bash',[generatorPath,phase],{encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
  assert.equal(result.status,0,result.stderr);
  assert.equal(result.stderr,'');
  assert.doesNotMatch(result.stdout,/PRIVATE_KEY|MNEMONIC|SEED_PHRASE|PLACEHOLDER|REPLACE_ME/);
  assert.doesNotMatch(result.stdout,/[\u0000\u0001-\u0008\u000b\u000c\u000e-\u001f\u007f]/);
  const syntax=spawnSync('bash',['-n'],{encoding:'utf8',input:result.stdout,env:{PATH:'/usr/bin:/bin'}});
  assert.equal(syntax.status,0,syntax.stderr);
  if(phase==='prepare-safe-recovery-secret'){
    assert.match(result.stdout,/proofs:\$proofs\}' > "\$replacement_proof_candidate"\n# Publish only after all three replacement keys prove possession\./);
    assert.doesNotMatch(result.stdout,/replacement_proof_candidate"\+/);
    const sessionInstall=result.stdout.indexOf('install-private-file-new-stdin.mjs --json "$USDOM_SAFE_RECOVERY_SESSION"');
    const transitionInstall=result.stdout.indexOf('install-private-file-new-stdin.mjs --json "$USDOM_SAFE_RECOVERY_TRANSITIONS_FILE" < "$transition_candidate"');
    assert.ok(sessionInstall>=0&&transitionInstall>sessionInstall,'recovery session must be durable before expanded files');
    assert.match(result.stdout,/assemble-recoverable-safe-recovery\.mjs > "\$transaction_candidate"/);
    assert.match(result.stdout,/cmp -s "\$source" "\$target"/);
  }
  if(phase==='migrate-safe-owners-hardware-secret'||phase==='prepare-safe-recovery-secret'){
    assert.match(result.stdout,/readonly timeout_bin=\/usr\/bin\/timeout/);
    for(const line of result.stdout.split('\n').filter(value=>value.includes('--ledger'))){
      assert.match(line,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s "\$cast_bin"/);
    }
    assert.doesNotMatch(result.stdout,/(?:^|\n)\s*(?:owner|replacement|signature)=\$\(cast wallet/);
  }
}

for(const hostile of ['$()','$(touch /tmp/usdom-injection)','`id`','*','../readiness','readiness\nchecklist','readiness\u0001']){
  const result=spawnSync('bash',[generatorPath,hostile],{encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
  assert.equal(result.status,64);
  assert.equal(result.stdout,'');
}
