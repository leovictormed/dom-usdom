import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');
const scripts=[
  'submit-closed-mainnet-private-burn.sh','register-finalized-deposit-wallet.sh',
  'observe-finalized-deposit-wallet.sh','drill-closed-mainnet-wallet-recovery.sh',
  'bootstrap-closed-mainnet-tpm-authority.sh','build-finalized-deposit-witness.sh',
];
const dangerous=[
  'LD_PRELOAD','LD_LIBRARY_PATH','DYLD_INSERT_LIBRARIES','DYLD_LIBRARY_PATH',
  'NODE_OPTIONS','NODE_PATH','NODE_DEBUG','NODE_DEBUG_NATIVE','SSLKEYLOGFILE',
  'RUST_LOG','RUSTFLAGS','RUSTC_WRAPPER','CARGO_BUILD_RUSTC_WRAPPER',
  'CARGO_ENCODED_RUSTFLAGS','CARGO_TARGET_DIR','CARGO_BUILD_TARGET',
  'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy','all_proxy','no_proxy',
];

test('credential-bearing wallet, TPM and witness flows sanitize child controls',async()=>{
  for(const name of scripts) {
    const source=await readFile(path.join(component,'scripts',name),'utf8');
    for(const variable of dangerous) assert.match(source,new RegExp(`\\b${variable}\\b`),`${name}: ${variable}`);
    assert.match(source,/for inherited_name in \$\{!FOUNDRY_@\} \$\{!CAST_@\}; do unset "\$inherited_name"; done/);
    assert.ok(source.indexOf('unset LD_PRELOAD')<source.indexOf('command -v'),`${name}: sanitize before tools`);
    assert.doesNotMatch(source,/\$\{!CARGO_@\}/,'CARGO_HOME must remain usable');
  }
});

test('credential-flow sanitizer removes hostile controls but preserves required HOME and CARGO_HOME',()=>{
  const script=`set -eu
unset LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH NODE_OPTIONS NODE_PATH NODE_DEBUG NODE_DEBUG_NATIVE SSLKEYLOGFILE RUST_LOG RUSTFLAGS RUSTC_WRAPPER CARGO_BUILD_RUSTC_WRAPPER CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR CARGO_BUILD_TARGET HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
for inherited_name in \${!FOUNDRY_@} \${!CAST_@}; do unset "$inherited_name"; done
for name in "$@"; do [[ -z \${!name+x} ]] || exit 1; done
[[ $HOME == /home/operator && $CARGO_HOME == /home/operator/.cargo ]]`;
  const env={HOME:'/home/operator',CARGO_HOME:'/home/operator/.cargo'};
  for(const name of dangerous) env[name]='attacker-controlled';
  env.FOUNDRY_PROFILE='evil'; env.CAST_RPC_URL='https://secret';
  const result=spawnSync('bash',['-c',script,'bash',...dangerous,'FOUNDRY_PROFILE','CAST_RPC_URL'],{env});
  assert.equal(result.status,0,result.stderr.toString());
});
