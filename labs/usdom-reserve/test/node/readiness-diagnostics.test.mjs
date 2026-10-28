import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {readinessBlockerGroup,summarizeReadinessBlockers} from '../../sdk/readiness-diagnostics.mjs';

test('groups cascading blockers without changing or satisfying them',()=>{
  const blockers=[
    {code:'release_reserve_missing'},
    {code:'release_governance_missing'},
    {code:'evidence_reserveArtifact_missing'},
    {code:'requirement_production_finality'},
  ];
  const summary=summarizeReadinessBlockers(blockers,{buildSkipped:true});
  assert.equal(blockers.length,4);
  assert.deepEqual(summary.groups,[
    {group:'release-configuration',count:2},
    {group:'evidence-and-attestations',count:1},
    {group:'requirements-and-authorization',count:1},
  ]);
  assert.equal(summary.buildSkipped,true);
  assert.match(summary.limitation,/intentionally not executed/);
});

test('classifies control plane and malformed codes fail closed',()=>{
  assert.equal(readinessBlockerGroup('control_plane_governance_missing'),'control-plane');
  assert.equal(readinessBlockerGroup(null),'uncategorized');
});

test('full and no-build readiness reports both include the non-authorizing summary',async()=>{
  const source=await readFile(new URL('../../scripts/check-mainnet-readiness.mjs',import.meta.url),'utf8');
  assert.match(source,/const output=\{\.\.\.report,diagnostic:summarizeReadinessBlockers/);
  assert.match(source,/buildSkipped:diagnosticNoBuild/);
  assert.match(source,/console\.log\(JSON\.stringify\(output,null,2\)\)/);
  assert.doesNotMatch(source,/else console\.log\(JSON\.stringify\(report/);
});
