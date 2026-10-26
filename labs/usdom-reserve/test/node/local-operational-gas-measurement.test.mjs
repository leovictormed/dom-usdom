import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {buildProductionOperationalGasMeasurementJob,
 validateLocalOperationalGasEvidence} from '../../sdk/local-operational-gas-evidence.mjs';
const root=path.resolve(import.meta.dirname,'../..');
const evidencePath=path.join(root,'docs/LOCAL-OPERATIONAL-GAS-MEASUREMENT-2026-10-26.json');
test('local operational gas evidence binds four maximal scenarios without satisfying production',async()=>{
 const report=JSON.parse(await readFile(evidencePath,'utf8'));
 assert.equal(validateLocalOperationalGasEvidence(report,{root}),report);
 assert(BigInt(report.scenarios.queueWithdrawal.gasUsed)>0n);
 assert(BigInt(report.scenarios.pruneExpired256.gasUsed)>0n);
 assert(BigInt(report.scenarios.pruneDiscardable256.gasUsed)>0n);
 assert(BigInt(report.scenarios.safeAdminOverhead.gasUsed)>0n);
 for(const mutate of [v=>v.runs=1,v=>v.scenarios.queueWithdrawal.proofBytes=259,
  v=>v.scenarios.pruneExpired256.removed=255,v=>v.scenarios.pruneDiscardable256.inputCount=255,
  v=>v.scenarios.safeAdminOverhead.threshold=1,v=>v.productionRequirementsRemainFalse=false]) {
   const changed=structuredClone(report);mutate(changed);
   assert.throws(()=>validateLocalOperationalGasEvidence(changed,{root}));
 }
});
test('post-pin production job remains incomplete and requires exact release identities',async()=>{
 const localEvidence=JSON.parse(await readFile(evidencePath,'utf8'));
 const h='0x'+'11'.repeat(32),raw='11'.repeat(32);
 const release={ethereumChainId:'1',productionReady:true,reserve:'0x'+'22'.repeat(20),
  reserveRuntimeCodeHash:h,reserveConfigHash:h,governanceImplementationCodeHash:h,
  guardianImplementationCodeHash:h};
 const job=buildProductionOperationalGasMeasurementJob({localEvidence,release,
  releaseSha256:raw,localEvidenceSha256:raw});
 assert.equal(job.requiredRuns,2);assert.equal(job.requiredIndependentRpcSources,2);
 assert.equal(job.measurementComplete,false);assert.equal(job.localEvidenceSatisfiesProduction,false);
 assert.throws(()=>buildProductionOperationalGasMeasurementJob({localEvidence,
  release:{...release,productionReady:false},releaseSha256:raw,localEvidenceSha256:raw}));
});
test('measurement source uses two exact runs and no external RPC',async()=>{
 const source=await readFile(path.join(root,'scripts/measure-local-operational-gas.mjs'),'utf8');
 assert.match(source,/const first=await oneRun\(\),second=await oneRun\(\)/);
 assert.match(source,/JSON\.stringify\(first\)!==JSON\.stringify\(second\)/);
 assert.match(source,/pruneExpired\(256\)/);assert.match(source,/pruneDiscardable\(discardIds\)/);
 assert.match(source,/safeVersion:'1\.4\.1'/);assert.match(source,/proofBytes:260/);
 assert.doesNotMatch(source,/https?:\/\/(?!127\.0\.0\.1)/);
});
