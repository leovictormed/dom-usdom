import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const root=new URL('../../scripts/',import.meta.url);
const observer=await readFile(new URL('observe-authenticated-checkpoint.sh',root),'utf8');
const configure=await readFile(new URL('configure-release-signing-key.sh',root),'utf8');

test('checkpoint observer binds bounded Node and env files and their parents',()=>{
 for(const value of ['node_size','node_directory_identity','env_size','env_directory_identity'])
  assert.match(observer,new RegExp(`${value}=\\$\\(stat`));
 assert.match(observer,/node_size > 0 && node_size <= 512 \* 1024 \* 1024/);
 assert.match(observer,/env_size > 0 && env_size <= 512 \* 1024 \* 1024/);
 assert.match(observer,/node_directory_identity[\s\S]*node_sha256[\s\S]*node_directory_identity/);
 assert.match(observer,/env_directory_identity[\s\S]*env_sha256[\s\S]*env_directory_identity/);
});

test('release-key configurator never resolves Node at the allowed-signers mutation',()=>{
 assert.match(configure,/node_size > 0 && node_size <= 512 \* 1024 \* 1024/);
 assert.match(configure,/assert_node_unchanged\(\)[\s\S]*node_parent_identity[\s\S]*node_sha256/);
 assert.match(configure,/\| \{ assert_node_unchanged; "\$node_bin" "\$component\/scripts\/install-private-file-stdin\.mjs"/);
 assert.doesNotMatch(configure,/\|\s*node\s/);
});
