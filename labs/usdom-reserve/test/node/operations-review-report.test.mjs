import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {buildOperationsReviewReport,serializeOperationsReviewReport,
  validateOperationsReviewReport} from '../../sdk/operations-review-report.mjs';
import {parseStrictJsonBytes} from '../../sdk/strict-json.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');
const doc=name=>({path:`evidence/${name}.json`,sha256:sha(name)});
const evidence={schema:1,releaseId:'release-1',sourceCommit:'a'.repeat(40),sourceTag:'usdom-v1.2.3',
 securityValidationReport:doc('security'),riscZeroHealthSourceCatalog:doc('health'),
 realFinalizedEndToEndReport:doc('burn'),checkpointProofCapacityReport:doc('checkpoint'),
 controlPlaneEvidenceBundle:doc('controls'),controlPlaneSeparationReport:doc('separation'),
 controlPlaneRecoveryDrillReport:doc('control-recovery'),
 mainnetPredeploymentAttestationReport:doc('predeployment'),
 nativeScheduledRuntimeActivationAttestationReport:doc('activation')};
const address=byte=>'0x'+byte.repeat(20);
const releaseConfig={ethereumChainId:'1',reserve:address('11'),checkpointRegistry:address('22'),
 governance:address('33'),guardian:address('44'),checkpointGuardian:address('55'),
 reserveConfigHash:'0x'+'66'.repeat(32),checkpointRegistryConfigHash:'0x'+'77'.repeat(32)};
const context={releaseEvidence:evidence,releaseConfig,runbookSha256:sha('runbook')};

test('operations report binds exact release, runbook and distinct operational evidence',()=>{
 const report=buildOperationsReviewReport(context);
 assert.equal(report.status,'reviewed');
 assert(Object.values(report.reviewAssertions).every(Boolean));
 assert.deepEqual(validateOperationsReviewReport(report,context),report);
 assert(serializeOperationsReviewReport(report).equals(
  serializeOperationsReviewReport(buildOperationsReviewReport(context))));
});

test('operations report rejects altered assertions, evidence and release identity',()=>{
 const report=buildOperationsReviewReport(context);
 const mutations=[
  value=>{value.reviewAssertions.nativeRuntimeActivationReviewed=false;},
  value=>{value.operationalEvidence.controlPlaneRecoveryDrillReport.sha256=sha('other');},
  value=>{value.reserve=address('99');},
  value=>{value.runbookSha256=sha('other');},
  value=>{value.extra=true;},
 ];
 for(const mutate of mutations) {
  const changed=structuredClone(report); mutate(changed);
  assert.throws(()=>validateOperationsReviewReport(changed,context));
 }
});

test('operations report rejects incomplete, duplicated and ambiguous inputs',()=>{
 for(const input of [
  {releaseEvidence:{...evidence,sourceCommit:null}},
  {releaseEvidence:{...evidence,securityValidationReport:null}},
  {releaseEvidence:{...evidence,nativeScheduledRuntimeActivationAttestationReport:
    {...evidence.securityValidationReport}}},
  {releaseConfig:{...releaseConfig,ethereumChainId:'31337'}},
  {releaseConfig:{...releaseConfig,governance:address('00')}},
  {runbookSha256:'bad'},
 ]) assert.throws(()=>buildOperationsReviewReport({...context,...input}));
});

test('operations-review JSON boundary rejects duplicate escaped keys and invalid UTF-8',()=>{
 for(const bytes of [
  Buffer.from('{"schema":"a","\\u0073chema":"b"}\n'),
  Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
 ]) assert.throws(()=>parseStrictJsonBytes(bytes,{label:'operations review',maxBytes:4*1024*1024,
  maxDepth:64}),/duplicate (?:object )?key|invalid UTF-8/);
});

test('fixed operations writer is locked, create-once and has no live capability',async()=>{
 const [prepare,writer]=await Promise.all([
  readFile(new URL('../../scripts/prepare-operations-review-report.mjs',import.meta.url),'utf8'),
  readFile(new URL('../../scripts/write-operations-review-report.sh',import.meta.url),'utf8'),
 ]);
 for(const expected of [
  "evidencePath='config/mainnet-release-evidence.unconfigured.json'",
  "releasePath='config/proof-reserve.unconfigured.json'",
  "runbookPath='docs/CLOSED-MAINNET-LINUX-RUNBOOK.md'",
 ]) assert.match(prepare,new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
 assert.match(prepare,/evidenceAfter\.equals\(evidenceBytes\)/);
 assert.match(prepare,/releaseAfter\.equals\(releaseBytes\)/);
 assert.match(prepare,/runbookAfter\.equals\(runbook\)/);
 assert.match(prepare,/for\(const name of OPERATIONS_REVIEW_EVIDENCE_NAMES\)/);
 assert.match(prepare,/parseStrictJsonBytes\(bytes/);
 assert.doesNotMatch(prepare,/bytes\.toString\(['"]utf8['"]\)/);
 assert.match(prepare,/createHash\('sha256'\)\.update\(bytes\)\.digest\('hex'\)!==document\.sha256/);
 assert.match(prepare,/for\(const \[relative,before\] of operationalBytes\)/);
 assert.match(prepare,/if\(!after\.equals\(before\)\)/);
 assert.match(writer,/flock -n 8/);
 assert.match(writer,/flock -n 9/);
 assert.match(writer,/chmod 0600 "\$report"/);
 assert.match(writer,/install-private-file-immutable-stdin\.mjs/);
 assert.match(writer,/cmp -s "\$metadata_snapshot" "\$metadata_current"/);
 assert.match(writer,/install-release-config-stdin\.mjs/);
 assert.doesNotMatch(`${prepare}\n${writer}`,/\bcurl\b|cast (?:send|publish)|ledger|git (?:push|commit|tag)/i);
});
