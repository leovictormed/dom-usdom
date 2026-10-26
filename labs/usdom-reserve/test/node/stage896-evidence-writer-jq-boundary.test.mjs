import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const directory=new URL('../../scripts/',import.meta.url);
const cases=new Map([
 ['write-release-authorization-request.sh',2],
 ['write-checkpoint-bootstrap-ratification-report.sh',3],
 ['write-recoverable-safe-release-evidence.sh',7],
 ['write-native-release-attestation-requests.sh',2],
 ['write-mainnet-fork-rehearsal-report.sh',3],
 ['write-operations-review-report.sh',3],
 ['write-checkpoint-finalized-event-report.sh',3],
 ['write-security-validation-report.sh',3],
]);

for(const [writer,expectedCalls] of cases) test(`${writer} wraps its cataloged JQ calls`,async()=>{
 const source=await readFile(new URL(writer,directory),'utf8');
 assert.match(source,/pin_runtime_tool jq/);
 const wrapper='jq() { assert_runtime_tool jq; "$jq_bin" "$@"; }';
 const boundary=source.indexOf(wrapper);
 assert.ok(boundary>0);
 const calls=[...source.matchAll(/(^|[;|]\s*)jq\s/gm)].filter(match=>match.index>boundary);
 assert.equal(calls.length,expectedCalls);
 assert.ok(calls.every(match=>match.index>boundary));
});
