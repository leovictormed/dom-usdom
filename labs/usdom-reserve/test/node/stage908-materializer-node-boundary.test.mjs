import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const directory=new URL('../../scripts/',import.meta.url);
const cases=new Map([
 ['materialize-release-provenance.sh',5],
 ['materialize-mainnet-deployment-identity.sh',10],
 ['materialize-preactivation-policy.sh',1],
]);

for(const [script,expectedCalls] of cases) test(`${script} authenticates every Node call`,async()=>{
 const source=await readFile(new URL(script,directory),'utf8');
 assert.match(source,/pin_runtime_tool node/);
 const wrapper='node() { assert_runtime_tool node; "$node_bin" "$@"; }';
 const boundary=source.indexOf(wrapper);
 assert.ok(boundary>0);
 const calls=[...source.matchAll(/(^|[;|]\s*)node\s/gm)].filter(match=>match.index>boundary);
 assert.equal(calls.length,expectedCalls);
 assert.doesNotMatch(source,/timeout\s[^\n]*\snode\s/);
});
