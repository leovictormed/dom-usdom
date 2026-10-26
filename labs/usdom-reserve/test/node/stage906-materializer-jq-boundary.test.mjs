import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const directory=new URL('../../scripts/',import.meta.url);
const cases=new Map([
 ['materialize-release-provenance.sh',7],
 ['materialize-mainnet-deployment-identity.sh',7],
 ['materialize-preactivation-policy.sh',2],
]);

for(const [script,expectedCalls] of cases) test(`${script} authenticates every JQ call`,async()=>{
 const source=await readFile(new URL(script,directory),'utf8');
 assert.match(source,/source "\$project\/scripts\/pinned-shell-tool-functions\.sh"/);
 assert.match(source,/pin_runtime_tool jq/);
 const wrapper='jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }';
 const boundary=source.indexOf(wrapper);
 assert.ok(boundary>0);
 const calls=[...source.matchAll(/(^|[;|]\s*)jq\s/gm)].filter(match=>match.index>boundary);
 assert.equal(calls.length,expectedCalls);
});
