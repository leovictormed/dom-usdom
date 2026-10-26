import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import {lstat,mkdir,readdir} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurable,writePrivateFileDurableNew} from '../sdk/durable-private-file.mjs';
import {
  FINALIZED_BURN_E2E_EVIDENCE_PATH,prepareFinalizedBurnReleaseEvidenceMaterialization,
} from '../sdk/finalized-burn-release-evidence-materialization.mjs';
import {validateReleaseSourceBoundary} from '../sdk/release-source-boundary.mjs';
import {PINNED_RISC0_MAINNET_V3} from '../sdk/risc0-verifier-reference.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {captureFinalizedBurnReleaseRun} from '../sdk/release-run-snapshot.mjs';
import {snapshotExecutable} from '../sdk/stable-executable.mjs';
import {runPinnedExecutable} from '../sdk/pinned-executable-child.mjs';

process.umask(0o077);

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const repositoryRoot=path.resolve(root,'../..');
const projectRelative=path.relative(repositoryRoot,root).split(path.sep).join('/');
const currentUid=process.getuid();
const runsRoot=path.join(os.homedir(),'.local/share/dom-usdom/prover-release/finalized-burn/runs');
const runIdPattern=/^[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*$/;
const releasePath='config/proof-reserve.unconfigured.json';
const verifierPath='config/finalized-burn-verifier.unconfigured.json';
const evidencePath='config/mainnet-release-evidence.unconfigured.json';
const gitExecutable=await snapshotExecutable('git');

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
      || (privateMode && (metadata.mode&0o077)!==0)) fail(`unsafe release evidence directory: ${target}`);
}

async function readPrivateFile(target,{maximum=4*1024*1024}={}) {
  return readDirectFile(target,{minimum:1,maximum,privateMode:true,label:'release evidence file'});
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
  if(entries.length===0) fail('no release-specific finalized-burn run is available');
  const runId=entries[0],runRoot=path.join(runsRoot,runId);
  await requireDirectory(runRoot);
  const snapshot=await captureFinalizedBurnReleaseRun(runRoot);
  try {
    const {statusBytes,reportBytes}=snapshot;
    const status=parseStrictJson(statusBytes.toString('utf8'),{label:'finalized-burn run status'});
    exact(status,['recordedAt','reportSha256','runId','schema','sourceCommit','status'],
      'finalized-burn run status');
    if(status.schema!=='usdom-finalized-burn-release-run-v1' || status.status!=='succeeded'
        || status.runId!==runId || status.sourceCommit!==sourceCommit
        || !/^[0-9a-f]{64}$/.test(status.reportSha256)
        || status.reportSha256!==rawSha(reportBytes)
        || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3})?Z$/.test(status.recordedAt)) {
      fail('latest finalized-burn release run is not a canonical success for this source commit');
    }
    return {runId,runRoot,statusBytes,reportBytes,snapshot,
      report:parseStrictJson(reportBytes.toString('utf8'),{
        label:'finalized-burn E2E report',maxBytes:4*1024*1024,maxDepth:48,
      })};
  } catch(error) {
    await snapshot.cleanup();
    throw error;
  }
}

async function assertRunUnchanged({snapshot}) {
  await snapshot.assertOriginsUnchanged();
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

async function atomicWrite(relative,content) {
  if(typeof relative!=='string' || relative==='' || relative.startsWith('/') || relative.includes('\\')
      || relative.split('/').some(part=>part==='' || part==='.' || part==='..')) {
    fail('materialization path is not canonical');
  }
  await ensureDirectParent(relative);
  await writePrivateFileDurable(path.join(root,relative),content);
}

async function immutableWrite(relative,content) {
  await ensureDirectParent(relative);
  const target=path.join(root,relative),bytes=Buffer.from(content);
  try { await writePrivateFileDurableNew(target,bytes); }
  catch(error) {
    if(error?.message!=='durable target already exists') throw error;
    const existing=await readDirectFile(target,{minimum:bytes.length,maximum:bytes.length,
      privateMode:true,label:'immutable finalized-burn release evidence'});
    if(!existing.equals(bytes)) fail('immutable finalized-burn release evidence already differs');
  }
}

async function assertInputsUnchanged({releaseBytes,verifierBytes,evidenceBytes}) {
  const [currentRelease,currentVerifier,currentEvidence]=await Promise.all([
    readDirectProjectFile(root,releasePath),readDirectProjectFile(root,verifierPath),
    readDirectProjectFile(root,evidencePath),
  ]);
  if(!currentEvidence.equals(evidenceBytes)) fail('release evidence changed during materialization');
  if(!currentRelease.equals(releaseBytes) || !currentVerifier.equals(verifierBytes)) {
    fail('release or verifier configuration changed during materialization');
  }
}

async function main() {
  if(process.argv.length!==2) fail('this fixed finalized-burn evidence materializer accepts no arguments');
  requireAccountHome();
  const [releaseBytes,verifierBytes,evidenceBytes]=await Promise.all([
    readDirectProjectFile(root,releasePath),readDirectProjectFile(root,verifierPath),
    readDirectProjectFile(root,evidencePath),
  ]);
  const releaseConfig=parseStrictJson(releaseBytes.toString('utf8'),{label:releasePath});
  const verifierConfig=parseStrictJson(verifierBytes.toString('utf8'),{label:verifierPath});
  const evidence=parseStrictJson(evidenceBytes.toString('utf8'),{label:evidencePath});
  if(!/^[0-9a-f]{40}$/.test(evidence.sourceCommit??'')) {
    fail('release evidence sourceCommit is not configured');
  }
  await assertSourceBoundary(evidence.sourceCommit);
  const latest=await latestCompletedRun(evidence.sourceCommit);
  try {
    const prepared=prepareFinalizedBurnReleaseEvidenceMaterialization({report:latest.report,evidence,
      releaseConfig,verifierConfig,riscZeroReference:PINNED_RISC0_MAINNET_V3});
    await assertSourceBoundary(evidence.sourceCommit);
    await assertInputsUnchanged({releaseBytes,verifierBytes,evidenceBytes});
    await assertRunUnchanged(latest);
    await immutableWrite(FINALIZED_BURN_E2E_EVIDENCE_PATH,prepared.reportContent);
    await assertSourceBoundary(evidence.sourceCommit);
    await assertInputsUnchanged({releaseBytes,verifierBytes,evidenceBytes});
    await assertRunUnchanged(latest);
    await atomicWrite(evidencePath,prepared.evidenceContent);
    await assertSourceBoundary(evidence.sourceCommit);
    await assertInputsUnchanged({releaseBytes,verifierBytes,evidenceBytes:Buffer.from(prepared.evidenceContent)});
    await assertRunUnchanged(latest);
    const [installedReport,installedEvidence]=await Promise.all([
      readDirectFile(path.join(root,FINALIZED_BURN_E2E_EVIDENCE_PATH),{
        minimum:Buffer.byteLength(prepared.reportContent),
        maximum:Buffer.byteLength(prepared.reportContent),privateMode:true,
        label:'installed finalized-burn release report',
      }),
      readDirectProjectFile(root,evidencePath),
    ]);
    if(!installedReport.equals(Buffer.from(prepared.reportContent))
        ||!installedEvidence.equals(Buffer.from(prepared.evidenceContent))) {
      fail('installed finalized-burn release generation differs from prepared bytes');
    }
    console.log(JSON.stringify({ok:true,runId:latest.runId,path:FINALIZED_BURN_E2E_EVIDENCE_PATH,
      sha256:prepared.sha256,broadcastAuthorized:false},null,2));
  } finally {
    await latest.snapshot.cleanup();
  }
}

try { await main(); }
catch(error) {
  writePilotFailure('finalized-burn-evidence-materialize',error);
  process.exitCode=1;
}
