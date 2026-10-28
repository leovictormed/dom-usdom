import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {buildOperationalClaimsLedger,applyOperationalClaimsLedger,
  operationalClaimsReleaseBinding,validateOperationalClaimsLedger}
  from '../../sdk/operational-claims-ledger.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const generated=spawnSync(process.execPath,['scripts/write-open-claims-execution-plan.mjs'],{
  cwd:root,encoding:null,env:{PATH:'/usr/bin:/bin'},maxBuffer:16*1024*1024,
});
assert.equal(generated.status,0,generated.stderr.toString());
const planBytes=generated.stdout,plan=JSON.parse(planBytes);
const requirementsBytes=await readFile(path.join(root,'config/production-requirements.json'));
const requirements=JSON.parse(requirementsBytes);
const releaseConfigBytes=Buffer.from('{"release":"one"}\n');
const releaseEvidenceBytes=Buffer.from('{"evidence":"one"}\n');
const planSha256=createHash('sha256').update(planBytes).digest('hex');
const phaseCatalogSha256=createHash('sha256').update(`${JSON.stringify(plan.phaseArtifacts)}\n`).digest('hex');
const phaseGenerationIdentity={schema:'usdom-closed-mainnet-phase-generation/v1',
  planSha256,planPath:`/home/leonardov/usdom-mainnet-public/open-claims-execution-plan-v1-${planSha256}.json`,
  phaseCount:plan.phaseOrder.length,phaseCatalogSha256,evidenceDirectoryDevice:'2049',
  evidenceDirectoryInode:'817263'};
const phaseGenerationBytes=Buffer.from(`${JSON.stringify(phaseGenerationIdentity)}\n`);
const artifactStatuses=[['owners','verified'],['safePackage','bound-to-owners-awaiting-baseline'],
  ['baseline','verified'],['identity','verified'],['deployment','verified'],
  ['predeploymentAttestation','deferred-to-readiness'],['coldStartAttestation','deferred-to-readiness'],
  ['depositPackage','verified'],['depositExecution','verified'],['redemptionPackage','verified'],
  ['redemptionExecution','verified'],['financialConservation','verified'],['pilot','reconciled']];
const phaseArtifactAudit={schema:'usdom-closed-mainnet-phase-checklist/v1',
  artifacts:artifactStatuses.map(([artifact,status])=>({artifact,status}))};
const phaseArtifactAuditBytes=Buffer.from(`${JSON.stringify(phaseArtifactAudit,null,2)}\n`);
const binding=operationalClaimsReleaseBinding({planBytes,plan,requirementsBytes,
  releaseConfigBytes,releaseEvidenceBytes,phaseGenerationBytes,phaseGenerationIdentity,
  phaseArtifactAuditBytes});
const phaseCompletionBytes=new Map();
const completionHashes=[];
for(const artifact of plan.phaseArtifacts.slice(0,-1)) {
  const bytes=Buffer.from(`${JSON.stringify({
    schema:'usdom-closed-mainnet-phase-completion/v1',planSha256:binding.planSha256,
    phaseCatalogSha256:binding.phaseCatalogSha256,evidenceDirectoryDevice:'2049',
    evidenceDirectoryInode:'817263',phase:artifact.phase,ordinal:artifact.ordinal,
    phaseScriptSha256:artifact.generatedScriptSha256,
    predecessorCompletionSha256:[...completionHashes],
  })}\n`);
  phaseCompletionBytes.set(artifact.phase,bytes);
  completionHashes.push(createHash('sha256').update(bytes).digest('hex'));
}

test('ledger closes all planned claims without changing source policy or plan identity',()=>{
  const ledger=buildOperationalClaimsLedger({binding,plan,phaseCompletionBytes});
  assert.equal(ledger.claimCount,33);
  assert.equal(new Set(ledger.entries.map(entry=>entry.claim)).size,33);
  validateOperationalClaimsLedger(ledger,{binding,plan,phaseCompletionBytes});
  const effective=applyOperationalClaimsLedger(requirements,ledger);
  for(const {claim} of plan.entries) {
    assert.equal(requirements[claim],false);
    assert.equal(effective[claim],true);
  }
  assert.equal(binding.planSha256,operationalClaimsReleaseBinding({planBytes,plan,
    requirementsBytes,releaseConfigBytes,releaseEvidenceBytes,phaseGenerationBytes,
    phaseGenerationIdentity,phaseArtifactAuditBytes}).planSha256);
});

test('ledger rejects rollback, reordering, foreign completion and release substitution',()=>{
  const ledger=buildOperationalClaimsLedger({binding,plan,phaseCompletionBytes});
  for(const mutate of [
    value=>value.entries.pop(),
    value=>[value.entries[0],value.entries[1]]=[value.entries[1],value.entries[0]],
    value=>{value.entries[0].phaseCompletionSha256='0'.repeat(64);},
    value=>{value.headSha256='0'.repeat(64);},
  ]) {
    const candidate=structuredClone(ledger); mutate(candidate);
    assert.throws(()=>validateOperationalClaimsLedger(candidate,{binding,plan,phaseCompletionBytes}),
      /stale, truncated, reordered or foreign/);
  }
  const foreignBinding={...binding,releaseConfigSha256:'f'.repeat(64)};
  assert.throws(()=>validateOperationalClaimsLedger(ledger,{binding:foreignBinding,plan,
    phaseCompletionBytes}),/stale, truncated, reordered or foreign/);
});

test('release binding rejects a plan object detached from its hash preimage',()=>{
  const detached=structuredClone(plan);
  detached.phaseArtifacts[0].generatedScriptBytes+=1;
  assert.throws(()=>operationalClaimsReleaseBinding({planBytes,plan:detached,requirementsBytes,
    releaseConfigBytes,releaseEvidenceBytes,phaseGenerationBytes,phaseGenerationIdentity,
    phaseArtifactAuditBytes}),/plan bytes differ from parsed authority/);
});

test('ledger rejects copied generation receipts and partial multi-claim closure',()=>{
  const copied=new Map(phaseCompletionBytes);
  const firstPhase=plan.phaseArtifacts[0].phase;
  const completion=JSON.parse(copied.get(firstPhase));
  completion.evidenceDirectoryInode='817264';
  copied.set(firstPhase,Buffer.from(`${JSON.stringify(completion)}\n`));
  assert.throws(()=>buildOperationalClaimsLedger({binding,plan,phaseCompletionBytes:copied}),
    /another evidence generation|foreign or noncanonical/);

  const sharedPhase=[...new Set(plan.entries.map(row=>row.phase))].find(phase=>
    plan.entries.filter(row=>row.phase===phase).length>1);
  assert(sharedPhase);
  const partialPlan=structuredClone(plan);
  partialPlan.entries=partialPlan.entries.filter((row,index)=>
    row.phase!==sharedPhase||index!==partialPlan.entries.findIndex(value=>value.phase===sharedPhase));
  partialPlan.claimCount=partialPlan.entries.length;
  assert.throws(()=>buildOperationalClaimsLedger({binding,plan:partialPlan,phaseCompletionBytes}),
    /schema or phase order is invalid/);

  const reassigned=structuredClone(plan);
  const targets=reassigned.entries.filter(row=>row.phase===sharedPhase);
  targets[0].phase=reassigned.phaseOrder[0]; targets[0].phaseOrdinal=1;
  assert.throws(()=>validateOperationalClaimsLedger(
    buildOperationalClaimsLedger({binding,plan,phaseCompletionBytes}),
    {binding,plan:reassigned,phaseCompletionBytes}),/stale, truncated, reordered or foreign/);
});

test('ledger cannot be reused after terminal artifact evidence changes',()=>{
  const ledger=buildOperationalClaimsLedger({binding,plan,phaseCompletionBytes});
  const changed=structuredClone(phaseArtifactAudit); changed.artifacts[0].status='missing';
  const changedAudit=Buffer.from(`${JSON.stringify(changed,null,2)}\n`);
  assert.throws(()=>operationalClaimsReleaseBinding({planBytes,plan,requirementsBytes,
    releaseConfigBytes,releaseEvidenceBytes,phaseGenerationBytes,phaseGenerationIdentity,
    phaseArtifactAuditBytes:changedAudit}),/incomplete|lacks/);
  changed.artifacts[0].status='verified'; changed.artifacts[0].evidenceGeneration='changed';
  const validChangedAudit=Buffer.from(`${JSON.stringify(changed,null,2)}\n`);
  const changedBinding=operationalClaimsReleaseBinding({planBytes,plan,requirementsBytes,
    releaseConfigBytes,releaseEvidenceBytes,phaseGenerationBytes,phaseGenerationIdentity,
    phaseArtifactAuditBytes:validChangedAudit});
  assert.throws(()=>validateOperationalClaimsLedger(ledger,{binding:changedBinding,plan,
    phaseCompletionBytes}),/stale, truncated, reordered or foreign/);
});

test('readiness consumes the ledger and the final phase materializes it before assessment',async()=>{
  const readiness=await readFile(path.join(root,'scripts/check-mainnet-readiness.mjs'),'utf8');
  const generator=await readFile(path.join(root,'scripts/generate-closed-mainnet-phase-command.sh'),'utf8');
  const materializer=await readFile(path.join(root,'scripts/materialize-operational-claims-ledger.mjs'),'utf8');
  assert.match(readiness,/validateOperationalClaimsLedger/);
  assert.match(readiness,/applyOperationalClaimsLedger/);
  const materialize=generator.indexOf('materialize-operational-claims-ledger.mjs');
  const assess=generator.indexOf('check-mainnet-readiness.mjs closed-mainnet');
  assert.ok(materialize>0&&assess>materialize);
  assert.match(readiness,/check-closed-mainnet-phase-artifacts\.mjs','require-pilot-complete'/);
  assert.match(materializer,/check-closed-mainnet-phase-artifacts\.mjs','require-pilot-complete'/);
});
