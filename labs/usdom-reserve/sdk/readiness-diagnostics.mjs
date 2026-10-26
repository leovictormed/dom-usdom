const PREFIX_GROUPS=Object.freeze([
  [/^release_(?!evidence_)/,'release-configuration'],
  [/^(evidence_|release_evidence_|.*_(report|attestation)_)/,'evidence-and-attestations'],
  [/^requirements?_/,'requirements-and-authorization'],
  [/^(repository_|source_)/,'repository-and-provenance'],
  [/^operator_|^trusted_release_/,'operator-authorization'],
  [/^control_plane_/,'control-plane'],
  [/^native_/,'native-runtime-and-attestations'],
]);

export function readinessBlockerGroup(code) {
  if(typeof code!=='string'||code.length===0) return 'uncategorized';
  for(const [pattern,group] of PREFIX_GROUPS) if(pattern.test(code)) return group;
  if(code.includes('verifier')) return 'verifier-configuration';
  if(code.includes('checkpoint')) return 'checkpoint-and-finality';
  if(code.includes('compiled_')) return 'compiled-artifact-bindings';
  return 'other';
}

export function summarizeReadinessBlockers(blockers,{buildSkipped=false}={}) {
  if(!Array.isArray(blockers)) throw new TypeError('readiness blockers must be an array');
  const counts=new Map();
  for(const blocker of blockers) {
    const group=readinessBlockerGroup(blocker?.code);
    counts.set(group,(counts.get(group)??0)+1);
  }
  const groups=[...counts].map(([group,count])=>({group,count}))
    .sort((a,b)=>b.count-a.count||a.group.localeCompare(b.group));
  return Object.freeze({
    schema:'usdom-readiness-diagnostic/v1',
    buildSkipped,
    limitation:buildSkipped
      ? 'Compiled-artifact and native-runtime validation was intentionally not executed; related blockers are diagnostic and cannot be cleared by this report.'
      : null,
    groups,
  });
}
