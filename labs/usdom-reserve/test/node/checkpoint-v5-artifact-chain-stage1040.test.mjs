import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';

const root=new URL('../../../../',import.meta.url);
const gate=new URL('labs/usdom-reserve/scripts/check-checkpoint-v5-artifact-chain-stage1040.py',root);

const audit=spawnSync('python3',[gate.pathname,'--audit-current'],{cwd:root,encoding:'utf8'});
assert.equal(audit.status,0,audit.stderr);
const report=JSON.parse(audit.stdout);
assert.equal(report.schema,'usdom-checkpoint-v6-artifact-chain-audit-v1');
assert.equal(report.ready,false);
assert.ok(report.failures.includes('segment provenance is not UDCSTN04'));
assert.ok(report.failures.includes('outer provenance is not UDCPST06'));
assert.ok(report.failures.includes('burn provenance does not bind UDCPST06'));
assert.ok(report.failures.includes('burn provenance does not pin the rebuilt outer ImageID'));

// Release mode must reject the same stale chain. This remains true until all
// three guests and every downstream pin are rebuilt and reconciled together.
const release=spawnSync('python3',[gate.pathname],{cwd:root,encoding:'utf8'});
assert.equal(release.status,1,'stale artifact chain unexpectedly passed release mode');
assert.deepEqual(JSON.parse(release.stdout),report);

console.log(`checkpoint V6 artifact chain stage1040: ${report.failures.length} stale bindings rejected`);
