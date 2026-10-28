import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {buildProductionOperationalGasMeasurementJob,
 validateLocalOperationalGasEvidence} from '../../sdk/local-operational-gas-evidence.mjs';
const root=path.resolve(import.meta.dirname,'../..');
const evidencePath=path.join(root,'docs/LOCAL-OPERATIONAL-GAS-MEASUREMENT-2026-10-26.json');
test('local operational gas evidence binds legacy and pilot scenarios without satisfying production',async()=>{
 const report=JSON.parse(await readFile(evidencePath,'utf8'));
 assert.equal(validateLocalOperationalGasEvidence(report,{root}),report);
 assert(BigInt(report.scenarios.queueWithdrawal.gasUsed)>0n);
 assert(BigInt(report.scenarios.pruneExpired256.gasUsed)>0n);
 assert(BigInt(report.scenarios.pruneDiscardable256.gasUsed)>0n);
 assert(BigInt(report.scenarios.safeAdminOverhead.gasUsed)>0n);
 const ceilings={authorizePilotDeposit:250000n,cancelPilotDepositAuthorization:175000n,
  clearExpiredPilotDepositAuthorization:75000n,authorizedPilotDeposit:300000n,
  schedulePermissionlessDeposits:200000n,executePermissionlessDeposits:100000n};
 for(const [name,ceiling] of Object.entries(ceilings)) {
  const scenario=report.scenarios[name];
  const measured=scenario.modeledSafeUpperBoundGas??scenario.gasUsed;
  assert(BigInt(measured)<=ceiling,`${name} exceeds its local audited ceiling`);
 }
 for(const mutate of [v=>v.runs=1,v=>v.scenarios.queueWithdrawal.proofBytes=259,
  v=>v.scenarios.pruneExpired256.removed=255,v=>v.scenarios.pruneDiscardable256.inputCount=255,
  v=>v.scenarios.safeAdminOverhead.threshold=1,
  v=>v.scenarios.authorizePilotDeposit.modeledSafeUpperBoundGas='250001',
  v=>v.scenarios.cancelPilotDepositAuthorization.generation=1,
  v=>v.scenarios.clearExpiredPilotDepositAuthorization.calldataBytes=67,
  v=>v.scenarios.authorizedPilotDeposit.generationAfter=0,
  v=>v.scenarios.schedulePermissionlessDeposits.safeOverheadBasisGas='1',
  v=>v.scenarios.executePermissionlessDeposits.opened=false,
  v=>v.productionRequirementsRemainFalse=false]) {
   const changed=structuredClone(report);mutate(changed);
   assert.throws(()=>validateLocalOperationalGasEvidence(changed,{root}));
 }
});
test('local operational gas rejects oversized counters before numeric conversion',async()=>{
 const report=JSON.parse(await readFile(evidencePath,'utf8'));
 for(const mutate of [v=>v.scenarios.queueWithdrawal.gasUsed='9'.repeat(100000),
  v=>v.scenarios.safeAdminOverhead.gasUsed=(1n<<64n).toString()]) {
   const changed=structuredClone(report);mutate(changed);
   assert.throws(()=>validateLocalOperationalGasEvidence(changed));
 }
});
test('post-pin production job remains incomplete and requires exact release identities',async()=>{
 const localEvidence=JSON.parse(await readFile(evidencePath,'utf8'));
 const h='0x'+'11'.repeat(32);
 const release={ethereumChainId:'1',productionReady:true,reserve:'0x'+'22'.repeat(20),
  reserveRuntimeCodeHash:h,reserveConfigHash:h,governanceImplementationCodeHash:h,
  guardianImplementationCodeHash:h};
 const releaseBytes=Buffer.from(JSON.stringify(release));
 const localEvidenceBytes=Buffer.from(JSON.stringify(localEvidence));
 const releaseSha256=createHash('sha256').update(releaseBytes).digest('hex');
 const localEvidenceSha256=createHash('sha256').update(localEvidenceBytes).digest('hex');
 const job=buildProductionOperationalGasMeasurementJob({localEvidence,release,
  releaseBytes,localEvidenceBytes,releaseSha256,localEvidenceSha256});
 assert.equal(job.requiredRuns,2);assert.equal(job.requiredIndependentRpcSources,2);
 assert.equal(job.measurementComplete,false);assert.equal(job.localEvidenceSatisfiesProduction,false);
 const inactiveRelease={...release,productionReady:false};
 const inactiveReleaseBytes=Buffer.from(JSON.stringify(inactiveRelease));
 assert.throws(()=>buildProductionOperationalGasMeasurementJob({localEvidence,
  localEvidenceBytes,release:inactiveRelease,releaseBytes:inactiveReleaseBytes,
  releaseSha256:createHash('sha256').update(inactiveReleaseBytes).digest('hex'),localEvidenceSha256}));
 assert.throws(()=>buildProductionOperationalGasMeasurementJob({localEvidence:{...localEvidence,runs:1},
  localEvidenceBytes,release,releaseBytes,releaseSha256,localEvidenceSha256}),
 /bytes differ from parsed authority/);
});
test('measurement source uses two exact runs and no external RPC',async()=>{
 const source=await readFile(path.join(root,'scripts/measure-local-operational-gas.mjs'),'utf8');
 assert.match(source,/const first=await oneRun\(\),second=await oneRun\(\)/);
 assert.match(source,/JSON\.stringify\(first\)!==JSON\.stringify\(second\)/);
 assert.match(source,/pruneExpired\(256\)/);assert.match(source,/pruneDiscardable\(discardIds\)/);
 assert.match(source,/safeVersion:'1\.4\.1'/);assert.match(source,/proofBytes:260/);
 for(const marker of ['authorizePilotDeposit','cancelPilotDepositAuthorization',
  'clearExpiredPilotDepositAuthorization','authorizedPilotDeposit',
  'schedulePermissionlessDeposits','executePermissionlessDeposits']) assert.match(source,new RegExp(marker));
 assert.match(source,/2_000_000_000n,true/);
 assert.match(source,/modeledSafeUpperBoundGas/);
 assert.doesNotMatch(source,/https?:\/\/(?!127\.0\.0\.1)/);
});
test('production job ingress uses one bounded strict descriptor snapshot per authority',async()=>{
 const source=await readFile(path.join(root,'scripts/prepare-production-operational-gas-job.mjs'),'utf8');
 assert.match(source,/constants\.O_RDONLY\|constants\.O_NOFOLLOW\|constants\.O_CLOEXEC/);
 assert.match(source,/before\.size>1024n\*1024n/);
 assert.match(source,/\(before\.mode&0o777n\)!==0o600n/);
 assert.match(source,/before\.dev!==named\.dev\|\|before\.ino!==named\.ino/);
 assert.match(source,/set changed during capture/);
 assert.match(source,/parseStrictJson\(bytes\.toString\('utf8'\)/);
 assert.match(source,/release:release\.value/);
 assert.match(source,/releaseSha256:release\.sha256/);
 assert.match(source,/localEvidence:local\.value/);
 assert.match(source,/localEvidenceSha256:local\.sha256/);
 assert.doesNotMatch(source,/JSON\.parse|readFileSync\(process\.argv/);
});
test('local checker captures report requirements and canonical artifact allowlist together',async()=>{const source=await readFile(path.join(root,'scripts/check-local-operational-gas.mjs'),'utf8');assert.match(source,/const items=openSet/);assert.match(source,/revalidate\(items\)/);assert.match(source,/artifactBytes=new Map/);assert.match(source,/safe-1\.4\.1-mainnet\.json/);assert.match(source,/artifact path differs from canonical allowlist/);assert.match(source,/startsWith\(root\+path\.sep\)/);});
