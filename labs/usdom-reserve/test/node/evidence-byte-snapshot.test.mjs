import assert from 'node:assert/strict';
import test from 'node:test';
import {assertEvidenceByteSnapshotsUnchanged} from '../../sdk/evidence-byte-snapshot.mjs';

test('evidence snapshot recheck accepts identical bytes',async()=>{
  const snapshots=new Map([['evidence/a.json',Buffer.from('{"a":1}\n')]]);
  await assert.doesNotReject(assertEvidenceByteSnapshotsUnchanged(snapshots,
    async name=>Buffer.from(snapshots.get(name))));
});

test('evidence snapshot recheck rejects mutation before final readiness output',async()=>{
  const snapshots=new Map([['evidence/a.json',Buffer.from('{"a":1}\n')]]);
  await assert.rejects(assertEvidenceByteSnapshotsUnchanged(snapshots,
    async()=>Buffer.from('{"a":2}\n')),/evidence changed during readiness assessment/);
});

test('evidence snapshot recheck fails closed on disappearance or invalid reread',async()=>{
  const snapshots=new Map([['evidence/a.json',Buffer.from('{"a":1}\n')]]);
  await assert.rejects(assertEvidenceByteSnapshotsUnchanged(snapshots,
    async()=>{ throw Object.assign(new Error('missing'),{code:'ENOENT'}); }),/missing/);
  await assert.rejects(assertEvidenceByteSnapshotsUnchanged(snapshots,
    async()=>'{"a":1}\n'),/evidence changed during readiness assessment/);
});

test('snapshot recheck identifies non-evidence readiness authorities',async()=>{
  const snapshots=new Map([['config/proof-reserve.unconfigured.json',Buffer.from('{}\n')]]);
  await assert.rejects(assertEvidenceByteSnapshotsUnchanged(snapshots,
    async()=>Buffer.from('{ }\n'),{label:'readiness authority'}),
  /readiness authority changed during readiness assessment/);
});
