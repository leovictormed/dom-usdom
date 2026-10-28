import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {buildMainnetForkRehearsalReport,forkRehearsalEvidenceDocumentSha256,
  serializeMainnetForkRehearsalReport,
  validateMainnetForkRehearsalReport}
  from '../../sdk/mainnet-fork-rehearsal-report.mjs';
import {parseStrictJsonBytes} from '../../sdk/strict-json.mjs';

const ids=['ethereum-reorganization','dom-reorganization','ethereum-unavailability',
  'dom-unavailability','censorship','recovery'];
const decisions=['reject-conflicting-ethereum-finality','reject-dom-reorg-below-checkpoint-floor',
  'halt-ethereum-dependent-issuance-and-redemption','halt-checkpoint-advancement-and-redemption',
  'preserve-permissionless-retry-without-bypass','resume-only-after-release-bound-recovery-drill'];
const releaseEvidence={schema:1,releaseId:'release-1',sourceCommit:'a'.repeat(40),sourceTag:'usdom-v1'};
const releaseConfig={ethereumChainId:'1',reserveConfigHash:'0x'+'11'.repeat(32),
  checkpointRegistryConfigHash:'0x'+'22'.repeat(32),activationScheduleCommitment:'0x'+'33'.repeat(32)};

function fixture() {
  const generationId='ab'.repeat(32),forkBlockNumber='22000000',forkBlockHash='0x'+'cd'.repeat(32);
  const evidenceFiles={};
  const scenarios=ids.map((id,index)=>{
    const fault={path:`evidence/fork-rehearsal/raw/${id}-fault.json`,sha256:(index+1).toString(16).padStart(64,'0')};
    const recovery={path:`evidence/fork-rehearsal/raw/${id}-recovery.json`,
      sha256:(index+11).toString(16).padStart(64,'0')};
    const scenario={id,faultObserved:true,decisionObserved:decisions[index],unsafeTransitionCount:'0',
      fundLossBaseUnits:'0',recoveryObserved:true,startedAtUnix:String(1000+index*10),
      finishedAtUnix:String(1009+index*10),preStateCommitment:'0x'+(40+index).toString(16).repeat(32),
      faultStateCommitment:'0x'+(40+index).toString(16).repeat(32),
      postRecoveryStateCommitment:'0x'+(40+index).toString(16).repeat(32),
      faultEvidence:fault,recoveryEvidence:recovery};
    evidenceFiles[fault.path]={sha256:fault.sha256,document:{
      schema:'usdom-mainnet-fork-fault-evidence-v1',scenarioId:id,releaseId:'release-1',
      sourceCommit:'a'.repeat(40),commandId:`${id}-fault-assertion`,assertionExitCode:'0',
      observedDecision:decisions[index],preStateCommitment:scenario.preStateCommitment,
      faultStateCommitment:scenario.faultStateCommitment,unsafeTransitionCount:'0',
      fundLossBaseUnits:'0',generationId,forkBlockNumber,forkBlockHash,
      capturedAtUnix:scenario.startedAtUnix}};
    evidenceFiles[recovery.path]={sha256:recovery.sha256,document:{
      schema:'usdom-mainnet-fork-recovery-evidence-v1',scenarioId:id,releaseId:'release-1',
      sourceCommit:'a'.repeat(40),commandId:`${id}-recovery-assertion`,assertionExitCode:'0',
      recoveryObserved:true,postRecoveryStateCommitment:scenario.postRecoveryStateCommitment,
      generationId,forkBlockNumber,forkBlockHash,capturedAtUnix:scenario.finishedAtUnix}};
    fault.sha256=forkRehearsalEvidenceDocumentSha256(evidenceFiles[fault.path].document);
    recovery.sha256=forkRehearsalEvidenceDocumentSha256(evidenceFiles[recovery.path].document);
    evidenceFiles[fault.path].sha256=fault.sha256;
    evidenceFiles[recovery.path].sha256=recovery.sha256;
    return scenario;
  });
  return {observations:{schema:'usdom-mainnet-fork-rehearsal-observations-v1',releaseId:'release-1',
    sourceCommit:'a'.repeat(40),sourceTag:'usdom-v1',ethereumChainId:'1',
    reserveConfigHash:releaseConfig.reserveConfigHash,
    checkpointRegistryConfigHash:releaseConfig.checkpointRegistryConfigHash,
    activationScheduleCommitment:releaseConfig.activationScheduleCommitment,
    generationId,forkBlockNumber,forkBlockHash,rpcSourceIds:['drpc','publicnode'],
    rpcEndpointHashes:['c5b9f7564a09b1b2bbdff2c7145d474bbc2ccd025460d9c5b097a39474b7980c',
      '7b71d04b616d2ce47598465ad04d63da212a14b1317f965044bf325b749a6746'],
    startedAtUnix:'1000',finishedAtUnix:'1100',scenarios},releaseEvidence:{...releaseEvidence},
    releaseConfig:{...releaseConfig},evidenceFiles};
}

test('builds a release-bound semantic report for all six failure domains',()=>{
  const input=fixture();
  const report=buildMainnetForkRehearsalReport(input);
  assert.equal(report.schema,'usdom-mainnet-fork-rehearsal-report-v1');
  assert.equal(report.status,'passed');
  assert.equal(report.scenarioCount,'6');
  assert.deepEqual(report.scenarios.map(value=>value.id),ids);
  assert.match(report.observationsSha256,/^[0-9a-f]{64}$/);
  const serialized=serializeMainnetForkRehearsalReport(report);
  assert.equal(serialized.at(-1),0x0a);
  assert.deepEqual(JSON.parse(serialized),report);
  assert.equal(validateMainnetForkRehearsalReport({...input,report}),true);
});

test('validator rejects a forged passed report and noncanonical extra fields',()=>{
  const input=fixture();
  const report=structuredClone(buildMainnetForkRehearsalReport(input));
  report.scenarios[0].unsafeTransitionCount='1';
  assert.throws(()=>validateMainnetForkRehearsalReport({...input,report}),/fail-closed outcome/);
  const extra=structuredClone(buildMainnetForkRehearsalReport(input)); extra.reviewed=true;
  assert.throws(()=>validateMainnetForkRehearsalReport({...input,report:extra}),/exact supported schema/);
});

test('rejects release provenance and immutable configuration drift',()=>{
  for(const mutate of [
    value=>{value.observations.releaseId='other';},
    value=>{value.observations.sourceCommit='b'.repeat(40);},
    value=>{value.observations.ethereumChainId='2';},
    value=>{value.observations.reserveConfigHash='0x'+'99'.repeat(32);},
    value=>{value.observations.checkpointRegistryConfigHash='0x'+'99'.repeat(32);},
    value=>{value.observations.activationScheduleCommitment='0x'+'99'.repeat(32);},
    value=>{value.observations.generationId='99'.repeat(32);},
    value=>{value.observations.forkBlockHash='0x'+'99'.repeat(32);},
    value=>{value.observations.rpcSourceIds=['attacker','publicnode'];},
  ]) {
    const input=fixture(); mutate(input);
    assert.throws(()=>buildMainnetForkRehearsalReport(input),/(exact release|differs|invalid)/);
  }
});

test('rejects every unsafe, lossy, bypassed, or unrecovered scenario',()=>{
  for(const [field,value] of [['faultObserved',false],['decisionObserved','accept'],
    ['unsafeTransitionCount','1'],['fundLossBaseUnits','1'],['recoveryObserved',false]]) {
    const input=fixture(); input.observations.scenarios[0][field]=value;
    assert.throws(()=>buildMainnetForkRehearsalReport(input),/fail-closed outcome/);
  }
  const changed=fixture(); changed.observations.scenarios[1].faultStateCommitment='0x'+'77'.repeat(32);
  assert.throws(()=>buildMainnetForkRehearsalReport(changed),/changed protected state/);
  const incompleteRecovery=fixture();
  incompleteRecovery.observations.scenarios[1].postRecoveryStateCommitment='0x'+'77'.repeat(32);
  assert.throws(()=>buildMainnetForkRehearsalReport(incompleteRecovery),/exact protected pre-fault state/);
});

test('rejects oversized decimal evidence before numeric conversion',()=>{
  for(const mutate of [
    value=>{value.observations.startedAtUnix='9'.repeat(100000);},
    value=>{value.observations.finishedAtUnix='9'.repeat(100000);},
    value=>{value.observations.scenarios[0].finishedAtUnix='9'.repeat(100000);},
  ]) {
    const input=fixture(); mutate(input);
    assert.throws(()=>buildMainnetForkRehearsalReport(input),/canonical decimal/);
  }
});

test('rejects raw machine evidence that does not prove the declared outcome',()=>{
  for(const mutate of [
    document=>{document.assertionExitCode='1';},
    document=>{document.observedDecision='accept-conflict';},
    document=>{document.unsafeTransitionCount='1';},
    document=>{document.fundLossBaseUnits='1';},
    document=>{document.sourceCommit='b'.repeat(40);},
  ]) {
    const input=fixture();
    const path=input.observations.scenarios[0].faultEvidence.path;
    mutate(input.evidenceFiles[path].document);
    assert.throws(()=>buildMainnetForkRehearsalReport(input),/(bytes do not match|required decision|binding differs)/);
  }
  const recovery=fixture();
  const path=recovery.observations.scenarios[5].recoveryEvidence.path;
  recovery.evidenceFiles[path].document.recoveryObserved=false;
  assert.throws(()=>buildMainnetForkRehearsalReport(recovery),/(bytes do not match|prove restoration)/);
  const reversed=fixture();
  const recoveryPath=reversed.observations.scenarios[0].recoveryEvidence.path;
  reversed.evidenceFiles[recoveryPath].document.capturedAtUnix=
    reversed.observations.scenarios[0].startedAtUnix;
  const faultPath=reversed.observations.scenarios[0].faultEvidence.path;
  reversed.evidenceFiles[faultPath].document.capturedAtUnix=
    String(BigInt(reversed.observations.scenarios[0].startedAtUnix)+1n);
  for(const evidencePath of [recoveryPath,faultPath]) {
    const entry=reversed.evidenceFiles[evidencePath];
    entry.sha256=forkRehearsalEvidenceDocumentSha256(entry.document);
    const scenario=reversed.observations.scenarios[0];
    if(evidencePath===recoveryPath) scenario.recoveryEvidence.sha256=entry.sha256;
    else scenario.faultEvidence.sha256=entry.sha256;
  }
  assert.throws(()=>buildMainnetForkRehearsalReport(reversed),/recovery evidence predates fault evidence/);
});

test('rejects missing, reordered, stale, duplicate, mismatched, or extra evidence',()=>{
  const missing=fixture(); missing.observations.scenarios.pop();
  assert.throws(()=>buildMainnetForkRehearsalReport(missing),/all six/);
  const reordered=fixture(); [reordered.observations.scenarios[0],reordered.observations.scenarios[1]]=
    [reordered.observations.scenarios[1],reordered.observations.scenarios[0]];
  assert.throws(()=>buildMainnetForkRehearsalReport(reordered),/canonical order/);
  const stale=fixture(); stale.observations.finishedAtUnix=String(1000+8*86400);
  assert.throws(()=>buildMainnetForkRehearsalReport(stale),/time window/);
  const duplicate=fixture(); duplicate.observations.scenarios[1].faultEvidence=
    {...duplicate.observations.scenarios[0].faultEvidence};
  assert.throws(()=>buildMainnetForkRehearsalReport(duplicate),/independent/);
  const mismatch=fixture(); mismatch.evidenceFiles[mismatch.observations.scenarios[0].faultEvidence.path].sha256=
    'f'.repeat(64);
  assert.throws(()=>buildMainnetForkRehearsalReport(mismatch),/content hash mismatch/);
  const extra=fixture(); extra.evidenceFiles['evidence/fork-rehearsal/raw/extra.json']={
    sha256:'e'.repeat(64),document:{}};
  assert.throws(()=>buildMainnetForkRehearsalReport(extra),/extra files/);
});

test('preparer rechecks release, observations and every dynamic raw evidence file',async()=>{
  const source=await readFile(new URL(
    '../../scripts/prepare-mainnet-fork-rehearsal-report.mjs',import.meta.url),'utf8');
  assert.match(source,/observationsAfter\.equals\(observationsBytes\)/);
  assert.match(source,/evidenceAfter\.equals\(evidenceBytes\)/);
  assert.match(source,/releaseAfter\.equals\(releaseBytes\)/);
  assert.match(source,/rawAfter\.some\(\(bytes,index\)=>!bytes\.equals/);
  assert.match(source,/rawBytes\.set\(relative,content\)/);
  assert.match(source,/parseStrictJsonBytes\(bytes/);
  assert.match(source,/parseStrictJsonBytes\(content/);
  assert.doesNotMatch(source,/\.toString\(['"]utf8['"]\)/);
  for(const input of ['observationsBytes','evidenceBytes','releaseBytes']) {
    assert.match(source,new RegExp(`parse\\([^,]+,${input}\\)`));
  }
});

test('fork-rehearsal JSON authority rejects duplicate escaped keys and invalid UTF-8',()=>{
  for(const bytes of [
    Buffer.from('{"schema":"a","\\u0073chema":"b"}\n'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) assert.throws(()=>parseStrictJsonBytes(bytes,{label:'fork rehearsal',maxBytes:16*1024*1024,
    maxDepth:32}),/duplicate (?:object )?key|invalid UTF-8/);
});
