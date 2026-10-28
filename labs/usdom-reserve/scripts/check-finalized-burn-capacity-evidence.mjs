import {createHash} from 'node:crypto';
import {lstat} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateFinalizedBurnCapacityReport} from '../sdk/finalized-burn-capacity-report.mjs';
import {PINNED_RISC0_MAINNET_V3} from '../sdk/risc0-verifier-reference.mjs';
import {parseProverResourceMetrics} from '../sdk/prover-resource-metrics.mjs';
import {proofArtifacts} from './run-finalized-burn-capacity-e2e.mjs';

if(process.argv.length!==2) throw new Error('fixed finalized-burn capacity validator accepts no arguments');
const runId=process.env.USDOM_FINALIZED_BURN_PROOF_RUN_ID;
if(typeof runId!=='string'||!/^[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*$/.test(runId)) {
  throw new Error('USDOM_FINALIZED_BURN_PROOF_RUN_ID must select the exact completed run');
}
const runRoot=path.join(os.homedir(),'.local/share/dom-usdom/prover-capacity/finalized-burn/evm-runs',runId);
const metadata=await lstat(runRoot);
if(!metadata.isDirectory()||metadata.isSymbolicLink()||metadata.uid!==process.getuid()||(metadata.mode&0o077)!==0) {
  throw new Error('capacity run directory is unsafe');
}
const [reportBytes,statusBytes]=await Promise.all([
  readDirectFile(path.join(runRoot,'capacity-report.json'),{minimum:2,maximum:1024*1024,privateMode:true,label:'capacity report'}),
  readDirectFile(path.join(runRoot,'run-status.json'),{minimum:2,maximum:64*1024,privateMode:true,label:'capacity run status'}),
]);
const report=parseStrictJsonBytes(reportBytes,{label:'capacity report',maxBytes:1024*1024,maxDepth:32});
const status=parseStrictJsonBytes(statusBytes,{label:'capacity run status',maxBytes:64*1024,maxDepth:8});
const reportSha256=createHash('sha256').update(reportBytes).digest('hex');
if(JSON.stringify(Object.keys(status).sort())!==JSON.stringify(['recordedAt','reportSha256','runId','schema','status'].sort())
    ||status.schema!=='usdom-finalized-burn-capacity-run-v1'||status.status!=='succeeded'
    ||status.runId!==runId||status.reportSha256!==reportSha256) {
  throw new Error('capacity completion does not authenticate the selected report');
}
validateFinalizedBurnCapacityReport(report,{riscZeroReference:PINNED_RISC0_MAINNET_V3});
const workLab=path.join(runRoot,'work/labs/usdom-reserve');
async function validatePreservedArtifacts() {
  const [artifacts,input,metrics,isolatedReceipt]=await Promise.all([
    proofArtifacts(workLab),
    readDirectFile(path.join(workLab,'evidence/finalized-burn-source/finalized-burn-input.bin'),
      {minimum:1,maximum:16*1024*1024,privateMode:true,label:'capacity source input'}),
    readDirectFile(path.join(runRoot,'input-snapshots/source-prover-time.log'),
      {minimum:1,maximum:1024*1024,privateMode:true,label:'capacity source metrics'}),
    readDirectFile(path.join(runRoot,'isolated-evm-receipt.json'),
      {minimum:2,maximum:64*1024,privateMode:true,label:'isolated EVM receipt'}),
  ]);
  const measured=parseProverResourceMetrics(metrics.toString('utf8'));
  if(input.length!==report.inputBytes||createHash('sha256').update(input).digest('hex')!==report.inputSha256
      ||artifacts.receiptIdentity.sha256!==report.succinctReceiptSha256
      ||String(artifacts.receiptIdentity.bytes)!==report.succinctReceiptBytes
      ||artifacts.groth16Identity.sha256!==report.groth16ReceiptSha256
      ||String(artifacts.groth16Identity.bytes)!==report.groth16ReceiptBytes
      ||createHash('sha256').update(artifacts.seal).digest('hex')!==report.evmSealSha256
      ||String(artifacts.seal.length)!==report.evmSealBytes
      ||measured.provingWallMilliseconds!==report.provingWallMilliseconds
      ||measured.peakResidentKiB!==report.peakResidentKiB
      ||createHash('sha256').update(isolatedReceipt).digest('hex')!==report.isolatedEvmReceiptSha256) {
    throw new Error('capacity report differs from its preserved proof, metrics or EVM receipt artifacts');
  }
}
await validatePreservedArtifacts();
await validatePreservedArtifacts();
const [finalReportBytes,finalStatusBytes]=await Promise.all([
  readDirectFile(path.join(runRoot,'capacity-report.json'),{minimum:reportBytes.length,maximum:reportBytes.length,privateMode:true,label:'capacity report final recheck'}),
  readDirectFile(path.join(runRoot,'run-status.json'),{minimum:statusBytes.length,maximum:statusBytes.length,privateMode:true,label:'capacity run status final recheck'}),
]);
if(!finalReportBytes.equals(reportBytes)||!finalStatusBytes.equals(statusBytes)) {
  throw new Error('capacity completion changed during artifact revalidation');
}
process.stdout.write(`${JSON.stringify({status:'verified',runId,reportSha256})}\n`);
