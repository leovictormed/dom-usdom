import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const helper=await readFile(new URL('../../../../crates/dom-node/src/private_staging_directory.rs',import.meta.url),'utf8');
const consumers=[
 'dom-usdom-observe-finalized-deposit.rs','dom-usdom-register-finalized-deposit.rs',
 'dom-usdom-recover-wallet-at-checkpoint.rs','dom-usdom-build-private-burn.rs'
];

test('all four private-state boundaries publish through shared staging authority',async()=>{
 const sources=await Promise.all(consumers.map(name=>readFile(
  new URL(`../../../../crates/dom-node/src/bin/${name}`,import.meta.url),'utf8')));
 assert.equal(sources.length,4);
 for(const source of sources){
  assert.match(source,/PrivateStagingDirectory::create\(/);
  assert.match(source,/staging\.publish\(\)\?/);
 }
});

test('publish audits every path-created child through retained descriptor',()=>{
 assert.match(helper,/pub fn publish[\s\S]*self\.audit_private_children\(\)\?[\s\S]*renameat_with/);
 assert.match(helper,/const MAX_STAGED_CHILDREN: usize = 64/);
 assert.match(helper,/OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::CLOEXEC/);
 for(const predicate of ['named.dev() != actual.dev()','named.ino() != actual.ino()','actual.nlink() != 1','0o600'])
  assert.ok(helper.includes(predicate),predicate);
 assert.match(helper,/impl Drop for PrivateStagingDirectory[\s\S]*remove_dir_all[\s\S]*fsync/);
});
