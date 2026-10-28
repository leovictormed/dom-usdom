import {createHash} from 'node:crypto';
import {lstat} from 'node:fs/promises';
import os from 'node:os'; import path from 'node:path'; import {fileURLToPath} from 'node:url';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurableNew} from '../sdk/durable-private-file.mjs';
import {durableReplacementFailureExitCode,replaceLockedParentFileDurable} from '../sdk/durable-locked-parent-replacement.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {snapshotExecutable} from '../sdk/stable-executable.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {isExactReleaseEvidenceShape} from '../sdk/release-evidence-schema.mjs';
import {validateFinalizedBurnCapacityReport} from '../sdk/finalized-burn-capacity-report.mjs';
import {buildFinalizedBurnCapacityArtifactManifest} from '../sdk/finalized-burn-capacity-artifact-manifest.mjs';
import {parseProverResourceMetrics} from '../sdk/prover-resource-metrics.mjs';
import {PINNED_RISC0_MAINNET_V3} from '../sdk/risc0-verifier-reference.mjs';
import {proofArtifacts} from './run-finalized-burn-capacity-e2e.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const pythonExecutable=await snapshotExecutable('python3');
const sha256=value=>createHash('sha256').update(value).digest('hex');
try {
const runId=process.env.USDOM_FINALIZED_BURN_PROOF_RUN_ID;
if(process.argv.length!==2||typeof runId!=='string'||!/^[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*$/.test(runId)) throw new Error('exact finalized-burn capacity run ID required');
const runRoot=path.join(os.homedir(),'.local/share/dom-usdom/prover-capacity/finalized-burn/evm-runs',runId);
const [reportBytes,manifestBytes,evidenceBytes]=await Promise.all([
 readDirectFile(path.join(runRoot,'capacity-report.json'),{minimum:2,maximum:1024*1024,privateMode:true,label:'capacity report'}),
 readDirectFile(path.join(runRoot,'artifact-manifest.json'),{minimum:2,maximum:16*1024*1024,privateMode:true,label:'capacity manifest'}),
 readDirectProjectFile(root,'config/mainnet-release-evidence.unconfigured.json')]);
const report=parseStrictJsonBytes(reportBytes,{label:'capacity report',maxBytes:1024*1024,maxDepth:32});
validateFinalizedBurnCapacityReport(report,{riscZeroReference:PINNED_RISC0_MAINNET_V3});
if(report.runId!==runId||createHash('sha256').update(manifestBytes).digest('hex')!==report.artifactManifestSha256) throw new Error('capacity report does not bind run manifest');
const regenerated=await buildFinalizedBurnCapacityArtifactManifest(runRoot,runId);
if(!regenerated.bytes.equals(manifestBytes)) throw new Error('capacity manifest differs from complete run graph');
const workLab=path.join(runRoot,'work/labs/usdom-reserve');
const artifacts=await proofArtifacts(workLab);
const [input,metricsBytes,isolatedReceipt]=await Promise.all([
 readDirectFile(path.join(workLab,'evidence/finalized-burn-source/finalized-burn-input.bin'),{minimum:1,maximum:16*1024*1024,privateMode:true,label:'capacity input'}),
 readDirectFile(path.join(runRoot,'input-snapshots/source-prover-time.log'),{minimum:1,maximum:1024*1024,privateMode:true,label:'capacity metrics'}),
 readDirectFile(path.join(runRoot,'isolated-evm-receipt.json'),{minimum:2,maximum:64*1024,privateMode:true,label:'capacity EVM receipt'}),
]);
const metrics=parseProverResourceMetrics(metricsBytes.toString('utf8'));
if(createHash('sha256').update(input).digest('hex')!==report.inputSha256||input.length!==report.inputBytes
 ||artifacts.receiptIdentity.sha256!==report.succinctReceiptSha256||String(artifacts.receiptIdentity.bytes)!==report.succinctReceiptBytes
 ||artifacts.groth16Identity.sha256!==report.groth16ReceiptSha256||String(artifacts.groth16Identity.bytes)!==report.groth16ReceiptBytes
 ||createHash('sha256').update(artifacts.seal).digest('hex')!==report.evmSealSha256||String(artifacts.seal.length)!==report.evmSealBytes
 ||metrics.provingWallMilliseconds!==report.provingWallMilliseconds||metrics.peakResidentKiB!==report.peakResidentKiB
 ||createHash('sha256').update(isolatedReceipt).digest('hex')!==report.isolatedEvmReceiptSha256) throw new Error('capacity report differs from preserved graph');
const evidence=parseStrictJsonBytes(evidenceBytes,{label:'release evidence',maxBytes:4*1024*1024,maxDepth:64});
if(!isExactReleaseEvidenceShape(evidence)) throw new Error('release evidence schema is invalid');
const reportPath='evidence/finalized-burn-capacity/finalized-burn-capacity-report.json';
const manifestPath='evidence/finalized-burn-capacity/finalized-burn-capacity-artifact-manifest.json';
const descriptor={path:reportPath,sha256:createHash('sha256').update(reportBytes).digest('hex')};
if(evidence.finalizedBurnCapacityReport!==null&&JSON.stringify(evidence.finalizedBurnCapacityReport)!==JSON.stringify(descriptor)) throw new Error('release already binds another capacity report');
for(const [relative,bytes] of [[reportPath,reportBytes],[manifestPath,manifestBytes]]) {
 try { await writePrivateFileDurableNew(path.join(root,relative),bytes); }
 catch(error) { if(error.message!=='durable target already exists') throw error; const current=await readDirectProjectFile(root,relative,{privateMode:true});if(!current.equals(bytes))throw new Error('installed capacity evidence differs'); }
}
const finalManifest=await buildFinalizedBurnCapacityArtifactManifest(runRoot,runId);
if(!finalManifest.bytes.equals(manifestBytes)) throw new Error('capacity graph changed during materialization');
const updated={...evidence,finalizedBurnCapacityReport:descriptor};
const target=path.join(root,'config/mainnet-release-evidence.unconfigured.json');
const parent=path.dirname(target),parentMetadata=await lstat(parent);
if(!parentMetadata.isDirectory()||parentMetadata.isSymbolicLink()
    ||parentMetadata.uid!==process.getuid()||(parentMetadata.mode&0o022)!==0) {
  throw new Error('release evidence parent is unsafe');
}
const updatedBytes=Buffer.from(JSON.stringify(updated,null,2)+'\n');
await replaceLockedParentFileDurable({target,contents:updatedBytes,expectedSha256:sha256(updatedBytes),
 expectedPreviousSha256:sha256(evidenceBytes),expectedParentDevice:String(parentMetadata.dev),
 expectedParentInode:String(parentMetadata.ino),metadataInspectorExecutable:pythonExecutable.path,
 metadataInspectorSha256:pythonExecutable.sha256,expectedMode:0o600});
process.stdout.write(`${JSON.stringify({status:'materialized',runId,path:reportPath,sha256:descriptor.sha256})}\n`);
} catch(error) {
 writeReleaseFailure('materialize-finalized-burn-capacity-release-evidence',error);
 process.exitCode=durableReplacementFailureExitCode(error);
}
