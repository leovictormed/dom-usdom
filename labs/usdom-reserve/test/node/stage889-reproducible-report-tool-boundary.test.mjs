import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const directory=new URL('../../scripts/',import.meta.url);
const writers=[
 'write-reserve-reproducible-build-report.sh',
 'write-verifier-reproducible-build-report.sh',
 'write-checkpoint-registry-reproducible-build-report.sh',
 'write-checkpoint-verifier-reproducible-build-report.sh',
];
const helper=await readFile(new URL('pinned-shell-tool-functions.sh',directory),'utf8');

test('shared runtime pin binds file, parent, size and hash with post-hash rechecks',()=>{
 for(const expected of [
  'size <= 512 * 1024 * 1024', "stat -Lc '%h'", "stat -Lc '%d:%i:%u:%a'",
  "stat -Lc '%d:%i:%s:%Y:%Z'", 'sha256sum "$path"',
 ]) assert.ok(helper.includes(expected),`missing shared pin boundary: ${expected}`);
 assert.match(helper,/sha256sum "\$path"[\s\S]*stat -Lc '%d:%i:%s:%Y:%Z'[\s\S]*stat -Lc '%d:%i:%u:%a'/);
});

for(const writer of writers) test(`${writer} authenticates every Node/JQ/timeout call`,async()=>{
 const source=await readFile(new URL(writer,directory),'utf8');
 assert.match(source,/source "\$project\/scripts\/pinned-shell-tool-functions\.sh"/);
 for(const tool of ['node','jq','timeout'])
  assert.match(source,new RegExp(`pin_runtime_tool ${tool}`));
 assert.match(source,/jq\(\) \{ assert_runtime_tool jq; "\$jq_bin" "\$@"; \}/);
 const children=[...source.matchAll(/assert_runtime_tool node; assert_runtime_tool timeout;(?: assert_runtime_tool python3)?\s*"\$timeout_bin"[^\n]*"\$node_bin"/g)];
 assert.equal(children.length,10);
 assert.doesNotMatch(source,/(?:^|[;|]\s*)timeout\s[^\n]*\snode\s/m);
});
