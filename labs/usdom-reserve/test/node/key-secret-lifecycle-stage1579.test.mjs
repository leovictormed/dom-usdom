import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const root=new URL('../..',import.meta.url);
const read=name=>readFileSync(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
const protectedScripts=[
  'configure-release-signing-key.sh',
  'prepare-native-receiving-wallet.sh',
  'run-secret-node-entrypoint.sh',
];

test('key and wallet entrypoints establish the secret boundary before tools or prompts',()=>{
  const sensitiveAction={
    'configure-release-signing-key.sh':/\n\s+ssh-keygen -q/,
    'prepare-native-receiving-wallet.sh':/\nread -r -s -p/,
    'run-secret-node-entrypoint.sh':/\nexec "\$ENV_BIN" -i/,
  };
  for(const name of protectedScripts) {
    const source=read(name);
    assert.equal(source.indexOf('set +x'),source.indexOf('set +x\n'),name);
    assert.ok(source.indexOf('set +x')<source.indexOf('set -euo pipefail'),name);
    assert.ok(source.indexOf('ulimit -c 0')<source.search(sensitiveAction[name]),name);
    assert.match(source,/set \+o history/);
    assert.match(source,/export HISTFILE=\/dev\/null/);
    assert.match(source,/for fd_path in \/proc\/\$\$\/fd\/\*/);
    assert.match(source,/exec \{inherited_fd\}>&-/);
    assert.match(source,/umask 077/);
  }
});

test('release key prompt cannot inherit loader, agent, proxy or language injection',()=>{
  const source=read('configure-release-signing-key.sh');
  for(const variable of ['LD_PRELOAD','NODE_OPTIONS','PYTHONPATH','SSH_AUTH_SOCK','GPG_AGENT_INFO','HTTPS_PROXY','SSLKEYLOGFILE']) {
    assert.match(source,new RegExp(`unset[\\s\\S]{0,500}\\b${variable}\\b`),variable);
  }
  assert.match(source,/ssh-keygen -q -t ed25519 -a 100/);
  assert.doesNotMatch(source,/--no-passphrase|-N ['"]{2}/);
});

test('operator key roles remain globally distinct and backups are encrypted create-once copies',()=>{
  const generator=read('generate-closed-mainnet-phase-command.sh');
  assert.match(generator,/\(\[ \$owners\[\] \]\|flatten\|map\(ascii_downcase\)\|unique\|length\)==9/);
  assert.match(generator,/install-private-file-immutable-stdin\.mjs "\$backup"/);
  assert.match(generator,/stat -c '%d:%i' "\$keystore"[\s\S]*stat -c '%d:%i' "\$backup"/);
  assert.match(generator,/Nao reutilize senhas/);
  assert.doesNotMatch(generator,/export\s+(?:PRIVATE_KEY|MNEMONIC|PASSWORD|PASSPHRASE)=/);
});

test('native recovery material is passphrase protected, create-only and recovery-drilled',()=>{
  const wallet=read('prepare-native-receiving-wallet.sh');
  const recovery=read('drill-closed-mainnet-wallet-recovery.sh');
  assert.match(wallet,/\$\{#PASSPHRASE_FIRST\} < 16/);
  assert.match(wallet,/unset PASSPHRASE_FIRST PASSPHRASE_SECOND/);
  assert.match(wallet,/--password-file "\$PASSWORD_FILE"/);
  assert.match(recovery,/Wallet recovery drill requires an interactive terminal/);
  assert.match(recovery,/recovery-drill-v1/);
  assert.doesNotMatch(`${wallet}\n${recovery}`,/--password(?:=|\s+)"?\$(?:PASSPHRASE|recovery_password)/);
});
