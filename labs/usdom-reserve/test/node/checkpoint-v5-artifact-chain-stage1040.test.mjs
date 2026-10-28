import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';

const root=new URL('../../../../',import.meta.url);
const gate=new URL('labs/usdom-reserve/scripts/check-checkpoint-v5-artifact-chain-stage1040.py',root);

const audit=spawnSync('python3',[gate.pathname,'--audit-current'],{cwd:root,encoding:'utf8'});
assert.equal(audit.status,0,audit.stderr);
const report=JSON.parse(audit.stdout);
assert.equal(report.schema,'usdom-checkpoint-v6-artifact-chain-audit-v1');
assert.equal(report.ready,true);
assert.deepEqual(report.failures,[]);
for(const field of ['segmentImageId','outerImageId','finalizedBurnImageId']) {
  assert.match(report[field],/^[0-9a-f]{64}$/);
  assert.notEqual(report[field],'0'.repeat(64));
}

// Release mode must independently accept the same fully reconciled chain.
const release=spawnSync('python3',[gate.pathname],{cwd:root,encoding:'utf8'});
assert.equal(release.status,0,release.stderr);
assert.deepEqual(JSON.parse(release.stdout),report);

console.log('checkpoint V6 artifact chain stage1040: complete V6/V4 chain accepted');
