import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');

test('token-bearing launchers clear ambient environment with pinned env',async()=>{
  const issuance=await readFile(path.join(component,'scripts/run-secret-node-entrypoint.sh'),'utf8');
  const observer=await readFile(path.join(component,'scripts/observe-authenticated-checkpoint.sh'),'utf8');
  for(const source of [issuance,observer]) {
    assert.match(source,/ENV_BIN=\$\(realpath "\$\(command -v env\)"\)/);
    assert.match(source,/env_identity=\$\(stat[\s\S]*env_sha256=\$\(sha256sum/);
    assert.match(source,/exec "\$ENV_BIN" -i/);
    assert.doesNotMatch(source,/NODE_OPTIONS|NODE_PATH|NODE_DEBUG|SSLKEYLOGFILE/);
  }
  assert.match(issuance,/exec "\$ENV_BIN" -i HOME="\$HOME" USDOM_SECRET_NODE_LAUNCHER=1[\s\S]*"\$NODE_BIN"/);
  assert.match(observer,/exec "\$ENV_BIN" -i[\s\S]*USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE="\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE"[\s\S]*"\$NODE_BIN"/);
});

test('ambient bearer, profiling and Node injection variables are absent under the allowlist',()=>{
  const ambient={HOME:'/home/operator',NODE_OPTIONS:'--require=/tmp/steal.js',NODE_DEBUG:'http',
    SSLKEYLOGFILE:'/tmp/keys',BEARER_TOKEN:'secret',USDOM_RPC_URL:'https://secret'};
  const issuance={HOME:ambient.HOME,USDOM_SECRET_NODE_LAUNCHER:'1'};
  const observer={USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:'/secure/catalog.json'};
  assert.deepEqual(Object.keys(issuance).sort(),['HOME','USDOM_SECRET_NODE_LAUNCHER']);
  assert.deepEqual(Object.keys(observer),['USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE']);
  for(const child of [issuance,observer]) for(const forbidden of ['NODE_OPTIONS','NODE_DEBUG','SSLKEYLOGFILE','BEARER_TOKEN','USDOM_RPC_URL'])
    assert.equal(child[forbidden],undefined);
});
