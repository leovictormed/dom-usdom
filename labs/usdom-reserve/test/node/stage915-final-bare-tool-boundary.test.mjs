import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const directory=new URL('../../scripts/',import.meta.url);
const cases=[
 ['commit-release-source.sh','node',2],
 ['commit-release-evidence.sh','node',4],
 ['prepare-closed-mainnet-private-burn.sh','node',2],
 ['provision-closed-mainnet-tpm-keystore.sh','node',2],
 ['prepare-native-receiving-wallet.sh','jq',1],
 ['submit-closed-mainnet-private-burn.sh','jq',2],
];

for(const [script,tool,expectedCalls] of cases) test(`${script} authenticates final ${tool} baseline calls`,async()=>{
 const source=await readFile(new URL(script,directory),'utf8');
 assert.match(source,new RegExp(`pin_runtime_tool ${tool}`));
 const wrapper=`${tool}() { assert_runtime_tool ${tool}; "$${tool}_bin" "$@"; }`;
 const boundary=source.indexOf(wrapper);
 assert.ok(boundary>0);
 const calls=[...source.matchAll(new RegExp(`(^|[;|]\\s*)${tool}\\s`,'gm'))]
  .filter(match=>match.index>boundary);
 assert.equal(calls.length,expectedCalls);
});
