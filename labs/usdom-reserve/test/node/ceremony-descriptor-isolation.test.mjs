import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');
const scriptsDir=path.join(component,'scripts');
const cores=[
  'execute-mainnet-deployment.sh','execute-recoverable-safe-recovery.sh',
  'sign-release-authorizations.sh','sign-checkpoint-bootstrap-ratification.sh',
  'sign-recoverable-safe-recovery.sh',
];

test('deployment, Safe and signing cores drop caller fds before child resolution',async()=>{
  for(const name of cores) {
    const source=await readFile(path.join(scriptsDir,name),'utf8');
    assert.match(source,/for fd_path in \/proc\/\$\$\/fd\/\*/);
    assert.match(source,/exec \{inherited_fd\}>&-/);
    assert.ok(source.indexOf('exec {inherited_fd}>&-')<source.indexOf('command -v'),`${name}: closure must precede child resolution`);
  }
  for(const name of ['sign-native-release-attestations.sh','sign-production-release-authorization.sh']) {
    const source=await readFile(path.join(scriptsDir,name),'utf8');
    assert.ok(source.indexOf('exec {inherited_fd}>&-')<source.indexOf('exec bash'),`${name}: wrapper must isolate before exec`);
  }
});

test('stdin remains for explicit consent and Ledger selection only, then closes',async()=>{
  const deploy=await readFile(path.join(scriptsDir,'execute-mainnet-deployment.sh'),'utf8');
  const deployLast=deploy.indexOf('Digite AUTORIZO TRANSMITIR DEPLOY MAINNET');
  const deployClose=deploy.indexOf('exec </dev/null',deployLast);
  assert.ok(deployLast>=0 && deployClose>deployLast);
  assert.doesNotMatch(deploy.slice(deployClose),/read -r -p/);

  const safe=await readFile(path.join(scriptsDir,'execute-recoverable-safe-recovery.sh'),'utf8');
  const safeConsent=safe.indexOf('Digite AUTORIZO TRES SWAPOWNER SAFE MAINNET');
  const safeClose=safe.indexOf('exec </dev/null',safeConsent);
  assert.ok(safeConsent>=0 && safeClose>safeConsent);
  assert.doesNotMatch(safe.slice(safeClose),/read -r -p/);

  for(const name of ['sign-release-authorizations.sh','sign-checkpoint-bootstrap-ratification.sh',
    'sign-recoverable-safe-recovery.sh']) {
    const source=await readFile(path.join(scriptsDir,name),'utf8');
    const lastLedgerPrompt=source.lastIndexOf('Conecte somente');
    const close=source.indexOf('exec </dev/null',lastLedgerPrompt);
    assert.ok(lastLedgerPrompt>=0 && close>lastLedgerPrompt,`${name}: close after Ledger prompts`);
    assert.doesNotMatch(source.slice(close),/read -r -p/);
  }
});

test('local proc-fd boundary excludes injected fd and unread stdin',()=>{
  const body=`set -euo pipefail
for fd_path in /proc/$$/fd/*; do
  inherited_fd=\${fd_path##*/}
  [[ "$inherited_fd" =~ ^[0-9]+$ ]] || exit 1
  ((inherited_fd > 2)) || continue
  [[ "$inherited_fd" == 255 ]] && continue
  exec {inherited_fd}>&-
done
exec </dev/null
bash -c 'test ! -e /proc/$$/fd/9; if IFS= read -r value; then exit 91; fi; printf isolated'
`;
  const wrapper='secret=$(mktemp); trap \'rm -f "$secret"\' EXIT; printf raw-signature >"$secret"; exec 9<"$secret"; exec bash -c "$1"';
  const result=spawnSync('bash',['-c',wrapper,'bash',body],{input:'authorization-leftover\n',encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  assert.equal(result.stdout,'isolated');
  assert.equal(result.stderr,'');
});
