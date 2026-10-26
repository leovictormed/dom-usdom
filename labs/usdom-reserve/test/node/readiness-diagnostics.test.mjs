import test from 'node:test';
import assert from 'node:assert/strict';
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
