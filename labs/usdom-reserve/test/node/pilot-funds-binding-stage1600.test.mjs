import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {validatePilotFundsReleaseValidation} from '../../sdk/pilot-funds-release-validation.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const repositoryRoot=path.resolve(root,'../..');
const sha=value=>createHash('sha256').update(value).digest('hex');
const bytes=value=>Buffer.from(JSON.stringify(value));

function fixture() {
 const evidence=JSON.parse(readFileSync(path.join(root,'config/mainnet-release-evidence.unconfigured.json')));
 const lockBytes=readFileSync(path.join(root,'config/mainnet-toolchain-lock.json'));
 const lock=JSON.parse(lockBytes),cargoBytes=readFileSync(path.join(repositoryRoot,'Cargo.lock'));
 evidence.releaseId='pilot-r1'; evidence.sourceCommit='a'.repeat(40); evidence.sourceTag='usdom-v1.0.0';
 const runs=['checkpoint390','randomxCache','nativePrivacy'].map((kind,index)=>({kind,
  runId:String(index+1).repeat(64),commandManifestSha256:String(index+1).repeat(64),
  runSha256:'4'.repeat(64),terminalSha256:'5'.repeat(64),processLogSha256:'6'.repeat(64),
  eventsSha256:'7'.repeat(64),supervisorSha256:'8'.repeat(64),
  startedAt:`2026-10-27T0${index}:00:00Z`,finishedAt:`2026-10-27T0${index}:00:01Z`}));
 const report={schema:'usdom-release-validation-report/v1',status:'passed',releaseId:evidence.releaseId,
  sourceCommit:evidence.sourceCommit,sourceTag:evidence.sourceTag,toolchainLockSha256:sha(lockBytes),
  cargoLockSha256:sha(cargoBytes),runs};
 const reportBytes=bytes(report); evidence.releaseValidationReport={path:'evidence/release-validation-report.json',sha256:sha(reportBytes)};
 lock.files.find(item=>item.path==='../../Cargo.lock').sha256=sha(cargoBytes);
 const adjustedLockBytes=bytes(lock); report.toolchainLockSha256=sha(adjustedLockBytes);
 const finalReportBytes=bytes(report); evidence.releaseValidationReport.sha256=sha(finalReportBytes);
 return {reportBytes:finalReportBytes,releaseEvidenceBytes:bytes(evidence),
  toolchainLockBytes:adjustedLockBytes,cargoLockBytes:cargoBytes,
  reportRelativePath:'evidence/release-validation-report.json'};
}

test('pilot funds accepts only the exact semantically valid release-vector report',()=>{
 const input=fixture();
 assert.equal(validatePilotFundsReleaseValidation(input).reportSha256,sha(input.reportBytes));
 for(const mutate of [
  copy=>{copy.reportRelativePath='evidence/other.json';},
  copy=>{copy.reportBytes=Buffer.from(copy.reportBytes); copy.reportBytes[copy.reportBytes.length-2]^=1;},
  copy=>{copy.cargoLockBytes=Buffer.concat([copy.cargoLockBytes,Buffer.from('\n')]);},
 ]) {
  const copy={...input}; mutate(copy);
  assert.throws(()=>validatePilotFundsReleaseValidation(copy));
 }
});

test('live pre-funds check rebinds all authorized inputs and rejects reuse',()=>{
 const source=readFileSync(path.join(root,'scripts/check-pilot-funds-authorization-live.mjs'),'utf8');
 for(const required of ['pilot-funds-authorization-consumed.json','validatePilotFundsReleaseValidation',
  'validatePilotFundsPlanBinding','snapshot.deploymentPackageSha256','snapshot.nativePrivacyInstallationSha256',
  'snapshot.checkpointCapacityEvidenceSha256','snapshot.finalizedBurnCapacityEvidenceSha256',
  'snapshot.operationalGasEvidenceSha256','snapshot.releaseValidationReportSha256','bindingAgain.some']) {
  assert.match(source,new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
 }
});
