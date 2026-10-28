import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {
  buildResidualRiskReport,serializeResidualRiskReport,validateResidualRiskReport,
} from '../../sdk/residual-risk-report.mjs';
import {parseStrictJsonBytes} from '../../sdk/strict-json.mjs';

const address=byte=>'0x'+byte.repeat(20);
const hash=byte=>'0x'+byte.repeat(32);
const sha=byte=>byte.repeat(32);
const releaseEvidence={schema:1,releaseId:'usdom-v1.2.3',sourceCommit:'a'.repeat(40),
 sourceTag:'usdom-v1.2.3',reproducibleBuildReport:{path:'evidence/build.json',sha256:sha('11')},
 residualRiskAcceptanceReport:null};
const releaseConfig={productionReady:true,realFundsAuthorized:true,ethereumChainId:'1',
 governance:address('11'),reserve:address('22'),token:address('33'),reserveConfigHash:hash('44'),
 checkpointRegistryConfigHash:hash('55'),activationScheduleCommitment:hash('66'),
 maxOutstandingBaseUnits:'1000000',outflowCapacityBaseUnitsPerDay:'10000',
 withdrawalDelaySeconds:'86400',governanceDelaySeconds:'172800'};
const requirements={finality_evaluation:{selected_production_mechanism:'ethereum-checkpoint-finality'},
 checkpoint_poc_authorization:{production_mechanism_approved:true}};

test('residual-risk report is deterministic and binds release evidence without a hash cycle',()=>{
 const before=structuredClone(releaseEvidence);
 const report=buildResidualRiskReport({releaseEvidence,releaseConfig,requirements,
  draftSha256:sha('77')});
 assert.equal(report.schema,'usdom-residual-risk-report/v1');
 assert.equal(report.status,'presented-for-governance-acceptance');
 assert.equal(report.risks.length,12);
 assert(report.risks.every((risk,index)=>risk.id===`R${index+1}`&&risk.accepted===false));
 assert.match(report.evidenceEnvelopeSha256,/^[0-9a-f]{64}$/);
 assert.deepEqual(releaseEvidence,before);
 const bytes=serializeResidualRiskReport(report);
 assert(bytes.equals(serializeResidualRiskReport(buildResidualRiskReport({
  releaseEvidence:{...releaseEvidence,residualRiskAcceptanceReport:{
   path:'evidence/residual-risk/residual-risk-acceptance-report.json',sha256:sha('88'),
  }},releaseConfig,requirements,draftSha256:sha('77')}))));
 assert.equal(createHash('sha256').update(bytes).digest('hex').length,64);
 assert.deepEqual(validateResidualRiskReport(report,{releaseEvidence,releaseConfig,requirements,
  draftSha256:sha('77')}),report);
});

test('semantic validation rejects altered risks and release-bound fields',()=>{
 const context={releaseEvidence,releaseConfig,requirements,draftSha256:sha('77')};
 for(const mutate of [
  report=>{report.risks[0].accepted=true;},
  report=>{report.risks[0].title='generic risk';},
  report=>{report.risks.pop();},
  report=>{report.reserveConfigHash=hash('99');},
  report=>{report.selectedFinality='operator-quorum';},
  report=>{report.draftSha256=sha('99');},
  report=>{report.extra=true;},
 ]) {
  const report=structuredClone(buildResidualRiskReport(context)); mutate(report);
  assert.throws(()=>validateResidualRiskReport(report,context));
 }
});

test('builder rejects non-mainnet, zero commitments, malformed limits and release tags',()=>{
 for(const mutate of [
  value=>{value.releaseConfig.ethereumChainId='31337';},
  value=>{value.releaseConfig.activationScheduleCommitment=hash('00');},
  value=>{value.releaseConfig.maxOutstandingBaseUnits='01';},
  value=>{value.releaseConfig.withdrawalDelaySeconds='0';},
  value=>{value.releaseConfig.governanceDelaySeconds='9'.repeat(100000);},
  value=>{value.releaseConfig.outflowCapacityBaseUnitsPerDay=(1n<<64n).toString();},
  value=>{value.releaseEvidence.sourceTag='latest';},
 ]) {
  const value={releaseEvidence:structuredClone(releaseEvidence),releaseConfig:{...releaseConfig},
   requirements:structuredClone(requirements),draftSha256:sha('77')};
  mutate(value); assert.throws(()=>buildResidualRiskReport(value));
 }
});

test('residual-risk report rejects incomplete release and unapproved finality',()=>{
 for(const input of [
  {releaseEvidence:{...releaseEvidence,sourceCommit:null}},
  {releaseConfig:{...releaseConfig,productionReady:false}},
  {releaseConfig:{...releaseConfig,realFundsAuthorized:null}},
  {releaseConfig:{...releaseConfig,reserveConfigHash:null}},
  {requirements:{...requirements,checkpoint_poc_authorization:{production_mechanism_approved:false}}},
  {requirements:{...requirements,finality_evaluation:{selected_production_mechanism:'operator-quorum'}}},
  {draftSha256:'bad'},
 ]) assert.throws(()=>buildResidualRiskReport({releaseEvidence,releaseConfig,requirements,
  draftSha256:sha('77'),...input}));
});

test('fixed preparer rechecks every release input before emitting the report',async()=>{
 const source=await readFile(new URL('../../scripts/prepare-residual-risk-report.mjs',
  import.meta.url),'utf8');
 for(const check of [
  /evidenceAfter\.equals\(evidenceBytes\)/,
  /releaseAfter\.equals\(releaseBytes\)/,
  /requirementsAfter\.equals\(requirementsBytes\)/,
  /draftAfter\.equals\(draft\)/,
 ]) assert.match(source,check);
 assert.match(source,/residual-risk inputs changed during preparation/);
 assert.match(source,/parseStrictJsonBytes\(bytes/);
 assert.doesNotMatch(source,/bytes\.toString\(['"]utf8['"]\)/);
 for(const input of ['evidenceBytes','releaseBytes','requirementsBytes']) {
  assert.match(source,new RegExp(`parse\\([^,]+,${input}\\)`));
 }
});

test('residual-risk JSON authority rejects duplicate escaped keys and invalid UTF-8',()=>{
 for(const bytes of [
  Buffer.from('{"schema":"a","\\u0073chema":"b"}\n'),
  Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
 ]) assert.throws(()=>parseStrictJsonBytes(bytes,{label:'residual risk',maxBytes:4*1024*1024,
  maxDepth:64}),/duplicate (?:object )?key|invalid UTF-8/);
});

test('residual-risk presentation binds but does not grant real-funds authorization',()=>{
 const context={releaseEvidence,releaseConfig:{...releaseConfig,realFundsAuthorized:false},requirements,
  draftSha256:sha('77')};
 const report=buildResidualRiskReport(context);
 assert.equal(report.realFundsAuthorized,false);
 assert.deepEqual(validateResidualRiskReport(report,context),report);
 assert.throws(()=>validateResidualRiskReport(report,{...context,
  releaseConfig:{...context.releaseConfig,realFundsAuthorized:true}}));
});
