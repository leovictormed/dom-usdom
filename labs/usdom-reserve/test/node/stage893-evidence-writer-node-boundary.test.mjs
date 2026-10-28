import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const directory=new URL('../../scripts/',import.meta.url);
const writers=[
 'write-checkpoint-bootstrap-ratification-observation.sh',
 'write-checkpoint-bootstrap-ratification-report.sh',
 'write-checkpoint-bootstrap-ratification-request.sh',
 'write-checkpoint-finalized-event-report.sh',
 'write-checkpoint-finalized-event-rpc-catalog.sh',
 'write-checkpoint-finalized-transaction-reference.sh',
 'write-mainnet-fork-rehearsal-report.sh',
 'write-native-release-attestation-requests.sh',
 'write-operations-review-report.sh',
 'write-recoverable-safe-release-evidence.sh',
 'write-release-authorization-request.sh',
 'write-security-validation-report.sh',
];
const pythonPinnedWriters=new Set([
 'write-operations-review-report.sh',
 'write-security-validation-report.sh',
]);

for(const writer of writers) test(`${writer} authenticates Node at every child boundary`,async()=>{
 const source=await readFile(new URL(writer,directory),'utf8');
 assert.match(source,/source "\$(?:ROOT|project)\/scripts\/pinned-shell-tool-functions\.sh"/);
 assert.match(source,/pin_runtime_tool node/);
 const wrapper=source.indexOf('node() { assert_runtime_tool node; "$node_bin" "$@"; }');
 assert.ok(wrapper>0);
 const direct=[...source.matchAll(/^node\s/gm)].map(match=>match.index);
 assert.ok(direct.every(index=>index>wrapper));
 assert.doesNotMatch(source,/timeout\s[^\n]*\snode\s/);
 if(pythonPinnedWriters.has(writer)) {
  assert.match(source,/pin_runtime_tool python3/);
  assert.match(source,/"\$python3_bin" "\$python3_sha256"/);
  assert.match(source,/assert_runtime_tool node; assert_runtime_tool timeout; assert_runtime_tool python3\n\s*"\$timeout_bin"[^\n]*"\$node_bin"[^\n]*replace-locked-source-stdin\.mjs/);
 }
 if(writer==='write-release-authorization-request.sh') {
  assert.match(source,/temporary_identity=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$temporary"\)/);
  assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$temporary" 2>\/dev\/null\) == "\$temporary_identity"/);
 }
 for(const match of source.matchAll(/"\$timeout_bin"[^\n]*"\$node_bin"/g)) {
  const prefix=source.slice(Math.max(0,match.index-120),match.index);
  assert.match(prefix,/assert_runtime_tool node; assert_runtime_tool timeout;(?: assert_runtime_tool python3)?\s*$/);
 }
});
