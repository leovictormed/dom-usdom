import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import {lstat,mkdir,readdir} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurableNew} from '../sdk/durable-private-file.mjs';
import {durableReplacementFailureExitCode,replaceLockedParentFileDurable}
  from '../sdk/durable-locked-parent-replacement.mjs';
import {
  CHECKPOINT_CAPACITY_EVIDENCE_PATH,
  CHECKPOINT_CAPACITY_MANIFEST_PATH,
  prepareCheckpointCapacityReleaseEvidenceMaterialization,
} from '../sdk/checkpoint-capacity-release-evidence-materialization.mjs';
import {validateReleaseSourceBoundary} from '../sdk/release-source-boundary.mjs';
import {PINNED_RISC0_MAINNET_V3} from '../sdk/risc0-verifier-reference.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {captureCheckpointCapacityRun} from '../sdk/checkpoint-run-snapshot.mjs';
import {buildCheckpointCapacityArtifactManifest,collectCheckpointCapacityArtifacts} from '../sdk/checkpoint-capacity-artifact-collector.mjs';
import {buildCheckpointProofCapacityReport} from '../sdk/checkpoint-proof-capacity-report.mjs';
import {snapshotExecutable} from '../sdk/stable-executable.mjs';
import {runPinnedExecutable} from '../sdk/pinned-executable-child.mjs';

process.umask(0o077);

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const repositoryRoot=path.resolve(root,'../..');
const projectRelative=path.relative(repositoryRoot,root).split(path.sep).join('/');
const currentUid=process.getuid();
const runsRoot=path.join(os.homedir(),'.local/share/dom-usdom/prover-capacity/checkpoint/runs');
const runIdPattern=/^[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*$/;
const releasePath='config/proof-reserve.unconfigured.json';
const verifierPath='config/checkpoint-verifier.unconfigured.json';
const evidencePath='config/mainnet-release-evidence.unconfigured.json';
const gitExecutable=await snapshotExecutable('git');
const pythonExecutable=await snapshotExecutable('python3');

const rawSha=value=>createHash('sha256').update(value).digest('hex');
function fail(message) { throw new Error(message); }

function requireAccountHome() {
  const home=os.homedir(),accountHome=os.userInfo().homedir;
  if(!path.isAbsolute(home) || home==='/' || home!==process.env.HOME || home!==accountHome) {
    fail('HOME must be the current operating-system account home');
  }
}

function exact(value,fields,label) {
  if(!value || typeof value!=='object' || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...fields].sort())) {
    fail(`${label} must contain exact fields`);
  }
}

async function requireDirectory(target,{privateMode=true}={}) {
  const metadata=await lstat(target);
  if(!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid!==currentUid
      || (privateMode && (metadata.mode&0o077)!==0)) fail(`unsafe checkpoint evidence directory: ${target}`);
}

async function readPrivateFile(target,{maximum=4*1024*1024}={}) {
  return readDirectFile(target,{minimum:1,maximum,privateMode:true,
    label:'checkpoint evidence file'});
}

async function captureGit(args,{maximum=16*1024*1024}={}) {
  try {
    const result=await runPinnedExecutable(gitExecutable,args,{cwd:repositoryRoot,
      maxBuffer:maximum,timeout:30_000});
    if(result.stderr.length!==0) fail('Git inspection wrote stderr');
    try { return new TextDecoder('utf-8',{fatal:true}).decode(result.stdout); }
    catch { return fail('Git inspection returned invalid UTF-8'); }
  } finally { /* runPinnedExecutable rechecks and reaps the full process group */ }
}

async function assertSourceBoundary(sourceCommit) {
  const [head,status]=await Promise.all([
    captureGit(['rev-parse','HEAD']),
    captureGit(['status','--porcelain=v1','-z','--untracked-files=all']),
  ]);
  validateReleaseSourceBoundary({head:head.trim(),sourceCommit,status,projectRelative});
}

async function latestCompletedRun(sourceCommit) {
  await requireDirectory(runsRoot);
  const entries=(await readdir(runsRoot,{withFileTypes:true}))
    .filter(entry=>entry.isDirectory() && runIdPattern.test(entry.name))
    .map(entry=>entry.name).sort().reverse();
  if(entries.length===0) fail('no release-specific checkpoint capacity run is available');
  const runId=entries[0],runRoot=path.join(runsRoot,runId);
  await requireDirectory(runRoot);
  const snapshot=await captureCheckpointCapacityRun(runRoot);
  try {
    const {statusBytes,reportBytes}=snapshot;
    const status=parseStrictJsonBytes(statusBytes,{label:'checkpoint capacity run status'});
    exact(status,['recordedAt','reportSha256','runId','schema','sourceCommit','status'],
      'checkpoint capacity run status');
    if(status.schema!=='usdom-checkpoint-capacity-run-v1' || status.status!=='succeeded'
        || status.runId!==runId || status.sourceCommit!==sourceCommit
        || !/^[0-9a-f]{64}$/.test(status.reportSha256)
        || status.reportSha256!==rawSha(reportBytes)
        || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3})?Z$/.test(status.recordedAt)) {
      fail('latest checkpoint capacity run is not a canonical success for this source commit');
    }
    const report=parseStrictJsonBytes(reportBytes,{label:'checkpoint capacity report',maxBytes:4*1024*1024,maxDepth:64});
    const manifestBytes=await readPrivateFile(path.join(runRoot,'artifact-manifest.json'),{maximum:16*1024*1024});
    const manifest=parseStrictJsonBytes(manifestBytes,{label:'checkpoint capacity artifact manifest',maxBytes:16*1024*1024,maxDepth:16});
    if(manifest?.schema!=='usdom-checkpoint-capacity-artifact-manifest/v1'||manifest.runId!==runId
        ||rawSha(manifestBytes)!==report.artifactManifestSha256||report.runId!==runId
        ||report.artifactManifestPath!=='artifact-manifest.json') fail('checkpoint capacity manifest identity is invalid');
    return {runId,runRoot,statusBytes,reportBytes,manifestBytes,snapshot,report};
  } catch(error) { await snapshot.cleanup(); throw error; }
}

async function assertRunUnchanged({snapshot,runRoot,manifestBytes}) {
  await snapshot.assertOriginsUnchanged();
  const current=await readPrivateFile(path.join(runRoot,'artifact-manifest.json'),{maximum:16*1024*1024});
  if(!current.equals(manifestBytes)) fail('checkpoint capacity artifact manifest changed during materialization');
}

async function reconstructRunReport(latest,validation) {
  const regeneratedManifest=await buildCheckpointCapacityArtifactManifest(
    path.join(latest.runRoot,'work/labs/usdom-reserve'),latest.runId);
  if(!regeneratedManifest.bytes.equals(latest.manifestBytes)) {
    fail('checkpoint capacity manifest differs from the complete preserved artifact inventory');
  }
  const layerByName=new Map(latest.report.layers.map(layer=>[layer.name,layer]));
  const metric=name=>({provingWallMilliseconds:layerByName.get(name)?.provingWallMilliseconds,
    peakResidentKiB:layerByName.get(name)?.peakResidentKiB});
  const collected=await collectCheckpointCapacityArtifacts(
    path.join(latest.runRoot,'work/labs/usdom-reserve'),{
      checkpointVerifierConfig:validation.checkpointVerifierConfig,
      metrics:{randomx:metric('randomx'),randomxAggregate:metric('randomx-aggregate'),
        segment:metric('segment'),outer:metric('outer'),compression:{
          provingWallMilliseconds:latest.report.compressionWallMilliseconds,
          peakResidentKiB:latest.report.compressionPeakResidentKiB,
        }},
      beforeOriginRecheck:()=>assertRunUnchanged(latest),
    });
  const {schema,artifactSetCommitmentSchema,outerJournalDigestSha256,layers,...base}=latest.report;
  const reconstructed=buildCheckpointProofCapacityReport(base,collected.measuredLayers,validation);
  if(JSON.stringify(reconstructed)!==JSON.stringify(latest.report)) {
    fail('checkpoint capacity report differs from its preserved receipt graph');
  }
}

async function ensureDirectParent(relative) {
  const components=path.dirname(relative).split('/');
  let current=root;
  for(const component of components) {
    current=path.join(current,component);
    try { await mkdir(current,{mode:0o700}); }
    catch(error) { if(error?.code!=='EEXIST') throw error; }
    const metadata=await lstat(current);
    if(!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid!==currentUid) {
      fail(`unsafe materialization directory: ${current}`);
    }
  }
}

async function compareAndSwapEvidence(relative,content,previousBytes) {
  if(typeof relative!=='string' || relative==='' || relative.startsWith('/') || relative.includes('\\')
      || relative.split('/').some(part=>part==='' || part==='.' || part==='..')) {
    fail('materialization path is not canonical');
  }
  await ensureDirectParent(relative);
  const target=path.join(root,relative),parent=path.dirname(target),metadata=await lstat(parent);
  if(!metadata.isDirectory()||metadata.isSymbolicLink()||metadata.uid!==currentUid
      ||(metadata.mode&0o022)!==0) fail('release evidence parent is unsafe');
  const bytes=Buffer.from(content);
  await replaceLockedParentFileDurable({target,contents:bytes,expectedSha256:rawSha(bytes),
    expectedPreviousSha256:rawSha(previousBytes),expectedParentDevice:String(metadata.dev),
    expectedParentInode:String(metadata.ino),metadataInspectorExecutable:pythonExecutable.path,
    metadataInspectorSha256:pythonExecutable.sha256,expectedMode:0o600});
}

async function immutableWrite(relative,content) {
  await ensureDirectParent(relative);
  const target=path.join(root,relative),bytes=Buffer.from(content);
  try { await writePrivateFileDurableNew(target,bytes); }
  catch(error) {
    if(error?.message!=='durable target already exists') throw error;
    const existing=await readDirectFile(target,{minimum:bytes.length,maximum:bytes.length,
      privateMode:true,label:'immutable checkpoint capacity evidence'});
    if(!existing.equals(bytes)) fail('immutable checkpoint capacity evidence already differs');
  }
}

async function assertInputsUnchanged({releaseBytes,verifierBytes,evidenceBytes}) {
  const [currentRelease,currentVerifier,currentEvidence]=await Promise.all([
    readDirectProjectFile(root,releasePath),readDirectProjectFile(root,verifierPath),
    readDirectProjectFile(root,evidencePath),
  ]);
  if(!currentEvidence.equals(evidenceBytes)) fail('release evidence changed during materialization');
  if(!currentRelease.equals(releaseBytes) || !currentVerifier.equals(verifierBytes)) {
    fail('release or checkpoint verifier configuration changed during materialization');
  }
}

async function main() {
  if(process.argv.length!==2) fail('this fixed checkpoint evidence materializer accepts no arguments');
  requireAccountHome();
  const [releaseBytes,verifierBytes,evidenceBytes]=await Promise.all([
    readDirectProjectFile(root,releasePath),readDirectProjectFile(root,verifierPath),
    readDirectProjectFile(root,evidencePath),
  ]);
  const releaseConfig=parseStrictJsonBytes(releaseBytes,{label:releasePath});
  const checkpointVerifierConfig=parseStrictJsonBytes(verifierBytes,{label:verifierPath});
  const evidence=parseStrictJsonBytes(evidenceBytes,{label:evidencePath});
  if(!/^[0-9a-f]{40}$/.test(evidence.sourceCommit??'')) {
    fail('release evidence sourceCommit is not configured');
  }
  await assertSourceBoundary(evidence.sourceCommit);
  const latest=await latestCompletedRun(evidence.sourceCommit);
  let primaryError=null,successRecord=null;
  try {
    const validation={evidence,releaseConfig,checkpointVerifierConfig,
      riscZeroReference:PINNED_RISC0_MAINNET_V3};
    await reconstructRunReport(latest,validation);
    const prepared=prepareCheckpointCapacityReleaseEvidenceMaterialization({
      report:latest.report,...validation,
    });
    await assertSourceBoundary(evidence.sourceCommit);
    await assertInputsUnchanged({releaseBytes,verifierBytes,evidenceBytes});
    await assertRunUnchanged(latest);
    await immutableWrite(CHECKPOINT_CAPACITY_EVIDENCE_PATH,prepared.reportContent);
    await immutableWrite(CHECKPOINT_CAPACITY_MANIFEST_PATH,latest.manifestBytes);
    await assertSourceBoundary(evidence.sourceCommit);
    await assertInputsUnchanged({releaseBytes,verifierBytes,evidenceBytes});
    await assertRunUnchanged(latest);
    await compareAndSwapEvidence(evidencePath,prepared.evidenceContent,evidenceBytes);
    await assertSourceBoundary(evidence.sourceCommit);
    await assertInputsUnchanged({releaseBytes,verifierBytes,evidenceBytes:Buffer.from(prepared.evidenceContent)});
    await assertRunUnchanged(latest);
    const [installedReport,installedManifest,installedEvidence]=await Promise.all([
      readDirectFile(path.join(root,CHECKPOINT_CAPACITY_EVIDENCE_PATH),{
        minimum:Buffer.byteLength(prepared.reportContent),
        maximum:Buffer.byteLength(prepared.reportContent),privateMode:true,
        label:'installed checkpoint capacity release report',
      }),
      readDirectFile(path.join(root,CHECKPOINT_CAPACITY_MANIFEST_PATH),{
        minimum:latest.manifestBytes.length,maximum:latest.manifestBytes.length,privateMode:true,
        label:'installed checkpoint capacity artifact manifest',
      }),
      readDirectProjectFile(root,evidencePath),
    ]);
    if(!installedReport.equals(Buffer.from(prepared.reportContent))
        ||!installedManifest.equals(latest.manifestBytes)
        ||!installedEvidence.equals(Buffer.from(prepared.evidenceContent))) {
      fail('installed checkpoint capacity release generation differs from prepared bytes');
    }
    successRecord={ok:true,runId:latest.runId,path:CHECKPOINT_CAPACITY_EVIDENCE_PATH,
      sha256:prepared.sha256,broadcastAuthorized:false};
  } catch(error) {
    primaryError=error;
    throw error;
  } finally {
    try { await latest.snapshot.cleanup(); }
    catch(cleanupError) { if(primaryError===null) throw cleanupError; }
  }
  console.log(JSON.stringify(successRecord,null,2));
}

try { await main(); }
catch(error) {
  writeReleaseFailure('materialize-checkpoint-capacity-release-evidence',error);
  process.exitCode=durableReplacementFailureExitCode(error);
}
