import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const root=new URL('../../',import.meta.url);
const read=relative=>readFile(new URL(relative,root),'utf8');

test('execute recovery phase requires semantic final completion validation',async()=>{
  const generator=await read('scripts/generate-closed-mainnet-phase-command.sh');
  const phase=generator.slice(generator.indexOf('  execute-safe-recovery-secret)'),
    generator.indexOf('  materialize-safe-control-config)'));
  assert.match(phase,/execute-safe-recovery-roster-v3-step\.sh/);
  assert.match(phase,/check-safe-recovery-roster-v3-completion\.mjs/);
  assert.doesNotMatch(phase,/test -f .*safe-recovery-finalized-(?:report|bundle)/);
});

test('completion checker binds finalized graph, replacement possession and 2-of-3 liveness',async()=>{
  const checker=await read('scripts/check-safe-recovery-roster-v3-completion.mjs');
  for(const required of [
    'buildProofBundle','nextRecoveryOrdinal','recovery-v3-step-${i}-completion.json',
    'finalizedStepCount:12','replacementProofCount:3',"liveness:'2-of-3-common-roster'",
    'changed during validation',
  ]) assert.match(checker,new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
});

test('readiness consumes both semantic drill evidence and output-last completion bundle',async()=>{
  const readiness=await read('sdk/mainnet-readiness.mjs');
  const finalBundle=await read('sdk/safe-recovery-evidence-bundle.mjs');
  assert.match(readiness,/validateRecoverableSafeControlReleaseArtifactSet/);
  assert.match(readiness,/validateSafeRecoveryEvidenceBundleShape/);
  assert.match(finalBundle,/replacementProofsDocumentSha256/);
  assert.match(finalBundle,/usdom-safe-recovery-evidence-bundle\/v2/);
  assert.match(readiness,/finalBundle\.packageHash!==bundle\.packageHash/);
  assert.match(readiness,/finalBundle\.recoveryHash!==bundle\.recoveryHash/);
  assert.match(readiness,/production_control_plane_recovery_drill_passed/);
});
