import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';

const generator=fs.readFileSync(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
const publicCreateOnceInstaller=fs.readFileSync(new URL(
  '../../scripts/install-public-file-create-once-stdin.mjs',import.meta.url),'utf8');
const dagChecker=fs.readFileSync(new URL('../../scripts/check-closed-mainnet-phase-artifacts.mjs',import.meta.url),'utf8');
const toolchainChecker=fs.readFileSync(new URL('../../scripts/check-mainnet-toolchain.mjs',import.meta.url),'utf8');
const toolchainLock=JSON.parse(fs.readFileSync(new URL('../../config/mainnet-toolchain-lock.json',import.meta.url),'utf8'));
const solcBootstrap=fs.readFileSync(new URL('../../scripts/bootstrap-solc-0.8.37.sh',import.meta.url),'utf8');
const solcMaterializer=fs.readFileSync(new URL('../../scripts/materialize-solc-toolchain-lock.mjs',import.meta.url),'utf8');
const runbook=fs.readFileSync(new URL('../../docs/CLOSED-MAINNET-LINUX-RUNBOOK.md',import.meta.url),'utf8');
const generatorPath=fileURLToPath(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url));
const phases=['prerequisites','enroll-safe-owners-secret','migrate-safe-owners-hardware-secret',
 'prepare-safe-controls','execute-safe-controls-deployment-secret','materialize-safe-control-config',
 'validate-local','verify-risc0-trusted-setup','derive-deployment-identity-secret','prepare-deployment','execute-mainnet-deployment-secret',
 'execute-reserve-resume-secret','measure-release-capacity','prepare-native-wallet-secret',
 'finalize-native-privacy-ceremony-secret','authorize-pilot-funds-secret',
 'execute-pilot-deposit-secret','submit-pilot-burn-secret','produce-checkpoint-evidence-secret',
 'execute-pilot-redemption-secret','prepare-safe-recovery-secret','execute-safe-recovery-secret','readiness'];

assert.doesNotMatch(runbook,/safe-package-primary\.json/);
assert.match(runbook,/safe-package\.json/);
assert.match(generator,/readonly project=\/home\/leonardov\/usdom-security-audit-20261015\/implementation-dom-protocol\/labs\/usdom-reserve/);
assert.match(generator,/readonly evidence=\/home\/leonardov\/usdom-mainnet-private\/control-plane/);
assert.match(generator,/enroll-safe-owners-secret/);
assert.match(generator,/\.threshold=="2"/);
assert.match(generator,/prepare-onekey-ios-safe-mainnet-pilot\.sh --status-onboarding/);
assert.match(generator,/owner-\$\(\(owner_index\+1\)\)-evidence\.json/);
assert.doesNotMatch(generator,/wallet new "\$USDOM_SAFE_KEYSTORE_DIRECTORY"/);
assert.match(generator,/safe-owner-identities\/v2/);
assert.match(generator,/unique\|length\)==3/);
assert.doesNotMatch(generator,/cp --no-clobber/);
assert.doesNotMatch(generator,/install -d -m 0(?:700|755) "\$USDOM_SAFE_/);
assert.match(generator,/ensure-private-directory-path\.py "\$USDOM_SAFE_PUBLIC_DIRECTORY" 0755/);
assert.match(generator,/read-private-file-stdout\.mjs "\$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES"[\s\S]*install-public-file-create-once-stdin\.mjs "\$USDOM_SAFE_PUBLIC_BUNDLE"/);
assert.match(generator,/read-release-config-file-stdout\.mjs "\$USDOM_SAFE_PUBLIC_BUNDLE"/);
assert.equal((generator.match(/read-release-config-file-stdout\.mjs "\$USDOM_SAFE_PUBLIC_BUNDLE"/g)??[]).length,3);
assert.doesNotMatch(generator,/(?:jq -e[^\n]+|cat) "\$USDOM_SAFE_PUBLIC_BUNDLE"/);
assert.match(generator,/stat -c '%u:%a:%h' "\$USDOM_SAFE_PUBLIC_BUNDLE"/);
assert.match(publicCreateOnceInstaller,/writeFileDurable\(process\.argv\[2\],contents,\{maximum:1024\*1024,mode:0o644,replace:false\}\)/);
assert.match(publicCreateOnceInstaller,/readDirectFile\(process\.argv\[2\]/);
assert.match(publicCreateOnceInstaller,/exactMode:0o644/);
assert.doesNotMatch(publicCreateOnceInstaller,/O_CREAT|readFile\(process\.argv\[2\]\)/);
assert.match(generator,/stat -c '%u:%a:%h'/);
assert.match(generator,/stat -c '%d:%i'/);
assert.match(generator,/USDOM_SAFE_PUBLIC_BUNDLE/);
assert.match(generator,/four separate 2-of-3 Safe roles, backed by three distinct physical owner identities and twelve role\/slot custody proofs/);
assert.match(runbook,/Uma\s+assinatura única nunca satisfaz o contrato/);
assert.match(runbook,/quórum protótipo de\s+atestadores 3-de-4 não é configurado por este piloto/);
assert.match(runbook,/owners disjuntos; nenhuma chave pode ocupar dois papéis/);
assert.match(generator,/usdom-safe-owner-hardware-custody-proofs\/v1/);
assert.match(generator,/WalletConnect EIP-712 owner evidence accepted/);
assert.match(generator,/USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG/);
assert.match(generator,/USDOM_ONEKEY_IOS_PHYSICAL_EVIDENCE_DIRECTORY/);
assert.doesNotMatch(generator,/--ledger|wallet address|wallet sign/);
assert.match(generator,/check-safe-owner-hardware-custody-proofs\.mjs/);
assert.match(generator,/check-safe-owner-hardware-custody-proofs\.mjs/);
assert.match(generator,/with_entries\(\.value \|= \(map\(ascii_downcase\)\|sort\)\)/);
assert.match(generator,/candidate_owners=\$\(jq -ceS/);
assert.match(generator,/proof_owners=\$\(jq -ceS/);
assert.match(generator,/test "\$candidate_owners" = "\$proof_owners"/);
assert.doesNotMatch(generator,/test "\$\(jq -cS '\.ownersByRole\|with_entries/);
assert.match(generator,/export USDOM_SAFE_OWNER_IDENTITIES="\$identities_snapshot"/);
assert.match(generator,/prepare-safe-recovery-roster-v3-step\.sh/);
assert.match(generator,/execute-safe-recovery-roster-v3-step\.sh/);
assert.match(generator,/USDOM_SAFE_RECOVERY_ROSTER_PROOFS/);
assert.match(generator,/execute-safe-recovery-secret/);
assert.match(generator,/execute-safe-controls-deployment-secret/);
assert.match(generator,/execute-safe-recovery-roster-v3-step\.sh/);
assert.match(generator,/execute-safe-recovery-roster-v3-step\.sh/);
assert.match(generator,/prepare-safe-recovery-roster-v3-step\.sh/);
assert.match(generator,/USDOM_SAFE_RECOVERY_RELAYER_POLICY/);
assert.doesNotMatch(generator,/replacement_proof_candidate"\+/);
assert.match(generator,/write:recoverable-safe-release-evidence/);
assert.match(generator,/materialize:safe-control-release-config/);
assert.doesNotMatch(generator,/export USDOM_MAINNET_PREFLIGHT_RPC_SOURCES='/);
assert.match(generator,/USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE/);
assert.doesNotMatch(generator,/--unsafe-password|CAST_PASSWORD/);
assert.match(generator,/export PATH=\/usr\/lib\/chatgpt\/resources\/cua_node\/bin:[^\n]+:\/bin\n/);
assert.doesNotMatch(generator,/export PATH=.*\\\$PATH/);
assert.match(generator,/if test -e "\$USDOM_SAFE_OWNER_IDENTITIES"/);
assert.match(generator,/install-private-file-immutable-stdin\.mjs --json "\$USDOM_SAFE_PACKAGE"/);
assert.match(generator,/install-private-file-immutable-stdin\.mjs --json "\$USDOM_MAINNET_DEPLOYMENT_PACKAGE" <"\$candidate"/);
assert.match(generator,/read-private-file-stdout\.mjs "\$USDOM_MAINNET_DEPLOYMENT_PACKAGE" >"\$installed"/);
assert.match(generator,/cmp -s "\$candidate" "\$installed"/);
assert.doesNotMatch(generator,/if test -e "\$USDOM_MAINNET_DEPLOYMENT_PACKAGE"/);
assert.match(generator,/node scripts\/check-mainnet-toolchain\.mjs/);
assert.match(generator,/npm_config_offline=true/);
assert.match(generator,/CARGO_NET_OFFLINE=true/);
assert.match(generator,/FOUNDRY_OFFLINE=true/);
assert.match(generator,/missing pre-staged solc 0\.8\.37/);
const deploymentExecutePhase=generator.slice(generator.indexOf('  execute-mainnet-deployment-secret)'),
  generator.indexOf('  prepare-native-wallet-secret)'));
assert.match(deploymentExecutePhase,/run-operational-status78-cycle\.mjs contract-deployment/);
assert.doesNotMatch(generator.slice(0,generator.indexOf('  execute-mainnet-deployment-secret)')),
  /run-operational-status78-cycle\.mjs contract-deployment|cast send|cast publish/);
assert.match(generator,/USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION_SHA256=\$\(node scripts\/read-private-file-stdout\.mjs[^\n]+\| sha256sum/);
assert.match(generator,/node scripts\/check-closed-mainnet-phase-artifacts\.mjs/);
assert.doesNotMatch(generator,/check_file\(\).*test -s/);
assert.match(dagChecker,/validateRecoverableSafeControlBaseline\(baseline,safePackage\)/);
assert.match(dagChecker,/bound-to-owners-awaiting-baseline/);
assert.match(dagChecker,/validateMainnetDeploymentIdentityObservation/);
assert.match(dagChecker,/validateMainnetDeploymentPackage\(deployment\)/);
assert.match(dagChecker,/deployment\.observationDocumentSha256!==loaded\.get\('identity'\)\.sha256/);
assert.match(dagChecker,/deployment\.releaseConfigSha256!==releaseSnapshot\.sha256/);
assert.equal(toolchainLock.schema,'usdom-mainnet-toolchain-lock/v1');
assert.equal(toolchainLock.executables.length,9);
assert.deepEqual(toolchainLock.executables.map(value=>value.name),
  ['bash','node','npm','forge','cast','rustc','cargo','python3','jq']);
assert.equal(toolchainLock.solc.version,'0.8.37');
assert.match(toolchainChecker,/solc 0\.8\.37 is not pre-staged and hash-locked/);
assert.doesNotMatch(toolchainChecker,/execFile|spawn|https?:\/\//);
assert.match(solcBootstrap,/curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https'/);
assert.match(solcBootstrap,/test "\$\(sha256sum "\$candidate" \| awk '\{print \$1\}'\)" = "\$expected"/);
assert.match(solcBootstrap,/ln "\$candidate" "\$target"/);
assert.doesNotMatch(solcBootstrap,/curl[^\n]*\|\s*(?:sh|bash)/);
assert.match(solcMaterializer,/O_NOFOLLOW/);
assert.match(solcMaterializer,/fstatSync\(descriptor\)/);
assert.match(solcMaterializer,/execFileSync\(`\/proc\/self\/fd\/\$\{descriptor\}`/);
assert.ok(solcMaterializer.indexOf('sha(binary)!==manifest.sha256')
  <solcMaterializer.indexOf('execFileSync(`/proc/self/fd/${descriptor}`'));
assert.doesNotMatch(solcMaterializer,/execFileSync\(expectedPath/);
assert.match(solcMaterializer,/openSync\(descriptorLockPath,[\s\n]*constants\.O_RDONLY\|constants\.O_NOFOLLOW\|constants\.O_CLOEXEC\)/);
assert.match(solcMaterializer,/const lockStat=fstatSync\(lockDescriptor\)/);
assert.match(solcMaterializer,/\(lockStat\.mode&0o777\)!==0o600/);
assert.match(solcMaterializer,/before=readFileSync\(lockDescriptor\)/);
assert.doesNotMatch(solcMaterializer,/const before=readFileSync\(lockPath\)/);
assert.match(solcMaterializer,/const assertLockUnchanged=\(\)=>/);
assert.match(solcMaterializer,/if\(stat\[field\]!==lockIdentity\[field\]\)/);
assert.equal((solcMaterializer.match(/assertLockUnchanged\(\)/g)??[]).length,2);
assert.doesNotMatch(solcMaterializer,/readFileSync\(lockPath\)\.compare/);
assert.doesNotMatch(solcMaterializer,/\bstatSync\(descriptor\)/);
assert.match(solcMaterializer,/lock\.solc\.sha256=manifest\.sha256/);
assert.match(solcMaterializer,/replaceLockedParentFileDurable/);
assert.match(solcMaterializer,/expectedPreviousSha256:sha\(before\)/);
assert.match(solcMaterializer,/expectedParentDevice:String\(directoryIdentity\.dev\)/);
assert.match(solcMaterializer,/expectedMode:0o600/);
assert.match(solcMaterializer,/durableReplacementFailureExitCode\(error\)/);
assert.doesNotMatch(solcMaterializer,/renameSync\(/);
assert.match(solcMaterializer,/readFileSync\(installed\)\.compare\(after\)!==0/);

for(const phase of phases){
  const result=spawnSync('bash',[generatorPath,phase],{encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
  assert.equal(result.status,0,result.stderr);
  assert.equal(result.stderr,'');
  assert.doesNotMatch(result.stdout,/PRIVATE_KEY|MNEMONIC|SEED_PHRASE|PLACEHOLDER|REPLACE_ME/);
  assert.doesNotMatch(result.stdout,/<[A-Za-z][A-Za-z0-9 _.-]*>|YOUR_[A-Z_]+|CHANGE_ME|\bTODO\b|\bTBD\b/);
  assert.doesNotMatch(result.stdout,/[\u0000\u0001-\u0008\u000b\u000c\u000e-\u001f\u007f]/);
  const syntax=spawnSync('bash',['-n'],{encoding:'utf8',input:result.stdout,env:{PATH:'/usr/bin:/bin'}});
  assert.equal(syntax.status,0,syntax.stderr);
  if(phase==='prepare-safe-recovery-secret'){
    assert.match(result.stdout,/prepare-safe-recovery-roster-v3-step\.sh/);
    assert.match(result.stdout,/USDOM_SAFE_RECOVERY_ROSTER_PROOFS/);
    assert.doesNotMatch(result.stdout,/safe-recovery-transactions-v2/);
    assert.doesNotMatch(result.stdout,/--ledger|wallet address|wallet sign|prepare-ledger|assemble-ledger/);
  }
  if(phase==='migrate-safe-owners-hardware-secret'){
    assert.match(result.stdout,/check-safe-owner-hardware-custody-proofs\.mjs/);
    assert.match(result.stdout,/WalletConnect EIP-712 owner evidence accepted/);
    assert.doesNotMatch(result.stdout,/--ledger|wallet address|wallet sign|prepare-ledger|assemble-ledger/);
  }
  if(phase==='prepare-native-wallet-secret'){
    assert.match(result.stdout,/prepare:native-receiving-wallet > "\$candidate"/);
    assert.match(result.stdout,/install-private-file-immutable-stdin\.mjs "\$USDOM_NATIVE_RECEIVING_WALLET_PUBLIC"/);
    assert.match(result.stdout,/read-private-file-stdout\.mjs "\$USDOM_NATIVE_RECEIVING_WALLET_PUBLIC" > "\$installed"/);
    assert.match(result.stdout,/cmp -s "\$candidate" "\$installed"/);
    assert.match(result.stdout,/usdom-native-receiving-wallet-public-v1/);
    assert.doesNotMatch(result.stdout,/cat .*recovery\.usdom|read-private-file-stdout\.mjs .*recovery\.usdom/);
  }
  if(phase==='prepare-safe-controls'){
    assert.doesNotMatch(result.stdout,/if test -e "\$USDOM_SAFE_PACKAGE"/);
    assert.doesNotMatch(result.stdout,/install-private-file-new-stdin\.mjs --json "\$USDOM_SAFE_PACKAGE"/);
    assert.match(result.stdout,/install-private-file-immutable-stdin\.mjs --json "\$USDOM_SAFE_PACKAGE"/);
    assert.match(result.stdout,/owner_identity_source=\$USDOM_SAFE_HARDWARE_OWNER_IDENTITIES/);
    assert.match(result.stdout,/custody_proofs_source=\$USDOM_SAFE_HARDWARE_CUSTODY_PROOFS/);
    assert.match(result.stdout,/identities_snapshot="\$temporary\/owner-identities\.json"/);
    assert.match(result.stdout,/proofs_snapshot="\$temporary\/custody-proofs\.json"/);
    assert.match(result.stdout,/read-private-file-stdout\.mjs "\$owner_identity_source" \| sha256sum/);
    assert.match(result.stdout,/read-private-file-stdout\.mjs "\$custody_proofs_source" \| sha256sum/);
    assert.match(result.stdout,/\.threshold=="2"/);
    assert.match(result.stdout,/unique\|length\)==3/);
    assert.doesNotMatch(result.stdout,/jq [^\n]*"\$USDOM_SAFE_HARDWARE_(?:OWNER_IDENTITIES|CUSTODY_PROOFS)"/);
    assert.doesNotMatch(result.stdout,/sha256sum "\$USDOM_SAFE_PACKAGE"/);
  }
}

assert.doesNotMatch(runbook,/<[A-Za-z][A-Za-z0-9 _.-]*>|YOUR_[A-Z_]+|CHANGE_ME|\bPLACEHOLDER\b|\bREPLACE_ME\b/);

for(const hostile of ['$()','$(touch /tmp/usdom-injection)','`id`','*','../readiness','readiness\nchecklist','readiness\u0001']){
  const result=spawnSync('bash',[generatorPath,hostile],{encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
  assert.equal(result.status,64);
  assert.equal(result.stdout,'');
}

for(const phase of ['submit-pilot-burn-secret','execute-pilot-redemption-secret']) {
  const result=spawnSync('bash',[generatorPath,phase],{encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
  assert.equal(result.status,0,result.stderr);
  assert.match(result.stdout,/check:native-finalized-deposit-vector/);
}
