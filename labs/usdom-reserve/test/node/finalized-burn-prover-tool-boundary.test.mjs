import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import test from 'node:test';

const root=path.resolve(import.meta.dirname,'../..');

test('finalized-burn prover checks authenticate Cargo and JQ before every use',()=>{
  for(const name of ['check-finalized-burn-prover-e2e.sh','check-finalized-burn-planner-handoff.sh']) {
    const file=path.join(root,'scripts',name);
    assert.equal(spawnSync('/bin/bash',['-n',file]).status,0,name);
    const source=readFileSync(file,'utf8');
    assert.match(source,/source "\$LAB_ROOT\/scripts\/pinned-shell-tool-functions\.sh"/,name);
    for(const tool of ['cargo','jq']) {
      assert.match(source,new RegExp(`pin_runtime_tool ${tool}`),name);
      assert.match(source,new RegExp(`${tool}\\(\\) \\{ assert_runtime_tool ${tool}; "\\$${tool}_bin" "\\$@"; \\}`),name);
    }
  }
});

test('checkpoint source exporters authenticate Node and Cargo before every use',()=>{
  for(const name of ['export-canonical-checkpoint-source.sh','export-canonical-checkpoint-source-set.sh']) {
    const file=path.join(root,'scripts',name);
    assert.equal(spawnSync('/bin/bash',['-n',file]).status,0,name);
    const source=readFileSync(file,'utf8');
    assert.match(source,/source "\$LAB_ROOT\/scripts\/pinned-shell-tool-functions\.sh"/,name);
    for(const tool of ['node','cargo']) {
      assert.match(source,new RegExp(`pin_runtime_tool ${tool}`),name);
      assert.match(source,new RegExp(`${tool}\\(\\) \\{ assert_runtime_tool ${tool}; "\\$${tool}_bin" "\\$@"; \\}`),name);
    }
  }
});

test('checkpoint source catalog never bypasses its authenticated JQ',()=>{
  const file=path.join(root,'scripts','materialize-ethereum-checkpoint-source-catalog.sh');
  assert.equal(spawnSync('/bin/bash',['-n',file]).status,0);
  const source=readFileSync(file,'utf8');
  assert.match(source,/assert_tool_unchanged jq\nif "\$jq_bin" -e 'any\(/);
  assert.doesNotMatch(source,/\nif jq -e /);
});

test('deployment identity authenticates Cast for every RPC query',()=>{
  const file=path.join(root,'scripts','materialize-mainnet-deployment-identity.sh');
  assert.equal(spawnSync('/bin/bash',['-n',file]).status,0);
  const source=readFileSync(file,'utf8');
  assert.match(source,/pin_runtime_tool cast/);
  assert.match(source,/cast\(\) \{ assert_runtime_tool cast; "\$cast_bin" "\$@"; \}/);
  assert.doesNotMatch(source,/\n(?:function )?cast\s*=/);
});

test('release provenance authenticates Git and SSH key inspection',()=>{
  const file=path.join(root,'scripts','materialize-release-provenance.sh');
  assert.equal(spawnSync('/bin/bash',['-n',file]).status,0);
  const source=readFileSync(file,'utf8');
  for(const [tool,variable] of [['git','git'],['ssh-keygen','ssh_keygen']]) {
    assert.match(source,new RegExp(`pin_runtime_tool ${tool}`));
    assert.match(source,new RegExp(`${tool.replace('-','\\-')}\\(\\) \\{ assert_runtime_tool ${tool}; "\\$${variable}_bin" "\\$@"; \\}`));
  }
});
