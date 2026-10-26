import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');
const scripts=[
  'execute-mainnet-deployment.sh','execute-recoverable-safe-recovery.sh',
  'sign-release-authorizations.sh','sign-checkpoint-bootstrap-ratification.sh',
  'sign-recoverable-safe-recovery.sh',
];
const dangerous=[
  'LD_PRELOAD','LD_LIBRARY_PATH','DYLD_INSERT_LIBRARIES','DYLD_LIBRARY_PATH',
  'NODE_OPTIONS','NODE_PATH','NODE_DEBUG','NODE_DEBUG_NATIVE','SSLKEYLOGFILE',
  'RUST_LOG','RUSTFLAGS','RUSTC_WRAPPER','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY',
  'http_proxy','https_proxy','all_proxy','no_proxy',
];

test('deploy, Safe and Ledger ceremonies sanitize ambient child controls',async()=>{
  for(const name of scripts) {
    const source=await readFile(path.join(component,'scripts',name),'utf8');
    for(const variable of dangerous) assert.match(source,new RegExp(`\\b${variable}\\b`),`${name}: ${variable}`);
    assert.match(source,/for inherited_name in \$\{!FOUNDRY_@\} \$\{!CAST_@\}; do unset "\$inherited_name"; done/);
    assert.ok(source.indexOf('unset LD_PRELOAD')<source.indexOf('command -v'),`${name}: sanitize before tools`);
    assert.doesNotMatch(source,/export\s+(?:NODE_OPTIONS|NODE_PATH|NODE_DEBUG|SSLKEYLOGFILE|LD_PRELOAD|RUST_LOG|FOUNDRY_|CAST_)/);
  }
});

test('network executors fix tool search, locale and operating-system HOME before discovery',async()=>{
  for(const name of ['execute-mainnet-deployment.sh','execute-recoverable-safe-recovery.sh']) {
    const source=await readFile(path.join(component,'scripts',name),'utf8');
    assert.match(source,/export PATH=\/usr\/lib\/chatgpt\/resources\/cua_node\/bin:[^\n]+:\/bin/);
    assert.doesNotMatch(source,/export PATH=.*\$PATH/);
    assert.match(source,/export LANG=C LC_ALL=C TZ=UTC/);
    assert.ok(source.indexOf('export PATH=')<source.indexOf('command -v'));
    assert.match(source,/os\.userInfo\(\)\.homedir/);
    assert.match(source,/\$\{HOME:-\} == "\$account_home"/);
    assert.match(source,/8#\$home_mode & 8#022/);
  }
});

test('sanitizer removes hostile loader, proxy, Node, Rust, Foundry and Cast variables',()=>{
  const script=`set -eu
unset LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH NODE_OPTIONS NODE_PATH NODE_DEBUG NODE_DEBUG_NATIVE SSLKEYLOGFILE RUST_LOG RUSTFLAGS RUSTC_WRAPPER HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
for inherited_name in \${!FOUNDRY_@} \${!CAST_@}; do unset "$inherited_name"; done
for name in "$@"; do [[ -z \${!name+x} ]] || exit 1; done`;
  const env={...process.env};
  for(const name of dangerous) env[name]='attacker-controlled';
  env.FOUNDRY_PROFILE='evil'; env.FOUNDRY_CONFIG='/tmp/evil'; env.CAST_ASYNC='true'; env.CAST_RPC_URL='https://secret';
  const names=[...dangerous,'FOUNDRY_PROFILE','FOUNDRY_CONFIG','CAST_ASYNC','CAST_RPC_URL'];
  const result=spawnSync('bash',['-c',script,'bash',...names],{env});
  assert.equal(result.status,0,result.stderr.toString());
});
