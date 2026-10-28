import assert from 'node:assert/strict';
import {chmodSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test from 'node:test';
const root=new URL('../..',import.meta.url).pathname;
const read=relative=>readFileSync(`${root}/${relative}`,'utf8');

test('generated phases derive and bind reusable execution RPC inputs without hand editing',()=>{
  const generator=read('scripts/generate-closed-mainnet-phase-command.sh');
  assert.match(generator,/materialize-checkpoint-runtime-rpc-sources\.mjs/);
  assert.match(generator,/USDOM_CHECKPOINT_RATIFICATION_RPC_SOURCES_FILE="\\\$USDOM_CHECKPOINT_RUNTIME_RPC_SOURCES_FILE"/);
  assert.match(generator,/USDOM_CHECKPOINT_FINALIZED_RPC_SOURCES_FILE="\\\$USDOM_CHECKPOINT_RUNTIME_RPC_SOURCES_FILE"/);
  assert.match(generator,/stat -c '%u:%a:%h'/);
});

test('checkpoint witness command obtains every paired endpoint through hidden prompts',()=>{
  const wrapper=read('scripts/collect-authenticated-checkpoint-witness-source.sh');
  assert.match(wrapper,/source "\$ROOT\/scripts\/pinned-shell-tool-functions\.sh"/);
  assert.match(wrapper,/pin_runtime_tool node/);
  assert.match(wrapper,/node\(\) \{ assert_runtime_tool node; "\$node_bin" "\$@"; \}/);
  assert.match(wrapper,/pin_runtime_tool jq/);
  assert.match(wrapper,/jq\(\) \{ assert_runtime_tool jq; "\$jq_bin" "\$@"; \}/);
  assert.match(wrapper,/read -r -s execution_url/);
  assert.match(wrapper,/read -r -s beacon_url/);
  assert.match(wrapper,/USDOM_CHECKPOINT_WITNESS_RPC_SOURCES_FILE=\$temporary/);
  assert.match(wrapper,/stat -c '%u:%a:%h'/);
  assert.match(wrapper,/unset USDOM_CHECKPOINT_WITNESS_RPC_SOURCES_FILE/);
  assert.doesNotMatch(wrapper,/echo .*url|printf .*\$execution_url|printf .*\$beacon_url/);
  assert.equal(spawnSync('bash',['-n',`${root}/scripts/collect-authenticated-checkpoint-witness-source.sh`]).status,0);
  const pkg=JSON.parse(read('package.json'));
  assert.equal(pkg.scripts['collect:authenticated-checkpoint-witness-source'],
    './scripts/mainnet-tool-dispatcher bash scripts/collect-authenticated-checkpoint-witness-source.sh');
});

test('runtime pin rejects a tool replaced after authentication',()=>{
  const directory=mkdtempSync(path.join(tmpdir(),'usdom-tool-swap-'));
  try {
    const tool=path.join(directory,'witness-tool');
    writeFileSync(tool,'#!/bin/sh\nexit 0\n'); chmodSync(tool,0o700);
    const helper=`${root}/scripts/pinned-shell-tool-functions.sh`;
    const script=`PATH=${directory}:/usr/bin:/bin; source ${helper}; pin_runtime_tool witness-tool; printf '#!/bin/sh\\nexit 1\\n' > ${tool}; chmod 0700 ${tool}; assert_runtime_tool witness-tool`;
    const result=spawnSync('/bin/bash',['-c',script],{encoding:'utf8'});
    assert.notEqual(result.status,0);
  } finally { rmSync(directory,{recursive:true,force:true}); }
});

test('derived execution RPC file is create-once-or-equal and rejects drift',()=>{
  const source=read('scripts/materialize-checkpoint-runtime-rpc-sources.mjs');
  assert.match(source,/readDirectFile/);
  assert.match(source,/exactMode:0o600/);
  assert.match(source,/writePrivateFileDurableNewOrEqual/);
  assert.doesNotMatch(source,/console\.log|process\.stdout\.write/);
});

test('operational gas phase generates its complete public run configuration interactively',()=>{
  const wrapper=read('scripts/prepare-production-operational-gas-inputs.sh');
  for(const token of ['transaction_hash','calldata_sha','reserveRuntimeCodeHash','governanceCodeHash',
    'usdom-production-operational-gas-run-config/v1','usdom-production-operational-gas-rpc-sources/v1',
    'install-private-file-immutable-stdin.mjs']) assert.match(wrapper,new RegExp(token));
  assert.doesNotMatch(wrapper,/TODO|PLACEHOLDER|CHANGE_ME/);
  assert.equal((wrapper.match(/read-private-file-stdout\.mjs/g)??[]).length,2);
  assert.equal((wrapper.match(/cmp -s "\$candidate" "\$installed"/g)??[]).length,2);
  assert.match(wrapper,/usdom-operational-gas-installed\.XXXXXXXX/);
  assert.equal(spawnSync('bash',['-n',`${root}/scripts/prepare-production-operational-gas-inputs.sh`]).status,0);
  const generator=read('scripts/generate-closed-mainnet-phase-command.sh');
  assert.match(generator,/prepare-production-operational-gas-inputs\.sh[\s\S]*prepare-production-operational-gas-job-v2\.mjs/);
});
