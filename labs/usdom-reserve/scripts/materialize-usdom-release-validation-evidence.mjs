#!/usr/bin/env node
import {createHash} from 'node:crypto';
import {lstat,mkdtemp,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path'; import {fileURLToPath} from 'node:url';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {durableReplacementFailureExitCode,replaceLockedParentFileDurable}
 from '../sdk/durable-locked-parent-replacement.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {isExactReleaseEvidenceShape} from '../sdk/release-evidence-schema.mjs';
import {collectReleaseEvidenceDocumentPaths} from '../sdk/release-evidence-document-paths.mjs';
import {validateReleaseValidationReport} from '../sdk/release-validation-report.mjs';
import {validateReleaseSourceBoundary} from '../sdk/release-source-boundary.mjs';
import {snapshotExecutable,snapshotExecutablePath,assertExecutableUnchanged} from '../sdk/stable-executable.mjs';
import {runPinnedExecutable} from '../sdk/pinned-executable-child.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';

process.umask(0o077);
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const repositoryRoot=path.resolve(root,'../..');
const projectRelative=path.relative(repositoryRoot,root).split(path.sep).join('/');
const evidencePath='config/mainnet-release-evidence.unconfigured.json';
const lockPath='config/mainnet-toolchain-lock.json';
const reportPath='evidence/release-validation-report.json';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const fail=message=>{throw new Error(message);};

async function gitBoundary(git,sourceCommit) {
 const capture=async args=>{
  const result=await runPinnedExecutable(git,['-C',repositoryRoot,...args],{
    encoding:'buffer',maxBuffer:8*1024*1024,timeout:30_000});
  if(result.stderr.length!==0) fail('Git source-boundary inspection wrote stderr');
  return result.stdout;
 };
 const [head,status]=await Promise.all([capture(['rev-parse','HEAD']),
  capture(['status','--porcelain=v1','-z','--untracked-files=all'])]);
 const decode=bytes=>new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 const headText=decode(head);
 if(!/^[0-9a-f]{40}\n$/.test(headText)) fail('Git HEAD output is not exactly one lowercase commit plus LF');
 validateReleaseSourceBoundary({head:headText.slice(0,-1),sourceCommit,
  status:decode(status),projectRelative});
}

async function main() {
 if(process.argv.length!==2) fail('this fixed release-vector evidence materializer accepts no arguments');
 const git=await snapshotExecutable('git');
 const [evidenceBytes,lockBytes,reportBytes]=await Promise.all([
  readDirectProjectFile(root,evidencePath),readDirectProjectFile(root,lockPath),
  readDirectFile(path.join(root,reportPath),{minimum:2,maximum:4*1024*1024,privateMode:true,
    label:'release validation report'}),
 ]);
 const evidence=parseStrictJsonBytes(evidenceBytes,{label:evidencePath,maxDepth:32});
 const lock=parseStrictJsonBytes(lockBytes,{label:lockPath,maxDepth:16});
 const report=parseStrictJsonBytes(reportBytes,{label:reportPath,maxDepth:24});
 if(!isExactReleaseEvidenceShape(evidence)) fail('release evidence schema is incompatible');
 const existingPaths=collectReleaseEvidenceDocumentPaths(evidence,{
  skipTopLevelKey:'releaseValidationReport'});
 if(existingPaths.includes(reportPath)) fail('release validation report path is already used by another slot');
 const cargoLockSha256=lock?.files?.find(item=>item?.path==='../../Cargo.lock')?.sha256;
 validateReleaseValidationReport(report,{releaseEvidence:evidence,
  toolchainLockSha256:sha(lockBytes),cargoLockSha256});
 await gitBoundary(git,evidence.sourceCommit);
 const pythonLock=lock?.executables?.find(item=>item?.name==='python3');
 if(!pythonLock||typeof pythonLock.realpath!=='string'||typeof pythonLock.sha256!=='string') {
  fail('pinned Python identity is absent');
 }
 const python=await snapshotExecutablePath(pythonLock.realpath);
 if(python.sha256!==pythonLock.sha256) fail('pinned Python snapshot differs from toolchain lock');
 const ids=Object.fromEntries(report.runs.map(run=>[run.kind,run.runId]));
 const temporary=await mkdtemp(path.join(os.tmpdir(),'usdom-release-validation-recheck-'));
 try {
  const candidate=path.join(temporary,'report.json');
  const result=await runPinnedExecutable(python,[
   path.join(root,'scripts/materialize-usdom-release-validation-report.py'),
   '--repository',repositoryRoot,'--jobs-directory',path.join(os.homedir(),'.config/usdom-proof/jobs'),
   '--state-root',path.join(os.homedir(),'.local/state/usdom-proof'),
   '--release-evidence',path.join(root,evidencePath),'--output',candidate,
   '--checkpoint390-run-id',ids.checkpoint390,'--randomxCache-run-id',ids.randomxCache,
   '--nativePrivacy-run-id',ids.nativePrivacy],{cwd:root,env:{HOME:os.homedir(),LANG:'C.UTF-8',LC_ALL:'C.UTF-8'},
    maxBuffer:1024*1024,timeout:120_000});
  if(result.stderr.length!==0||!result.stdout.equals(Buffer.from(`${sha(reportBytes)}\n`))) {
   fail('raw release-vector authentication returned ambiguous output');
  }
  const reproduced=await readDirectFile(candidate,{minimum:reportBytes.length,maximum:reportBytes.length,
    privateMode:true,label:'reproduced release validation report'});
  if(!reproduced.equals(reportBytes)) fail('release validation report is not reproducible from raw supervised evidence');
 } finally { await rm(temporary,{recursive:true,force:true}); }
 const reference={path:reportPath,sha256:sha(reportBytes)};
 if(evidence.releaseValidationReport!==null
     &&JSON.stringify(evidence.releaseValidationReport)!==JSON.stringify(reference)) {
  fail('release validation evidence slot already differs');
 }
 const next={...evidence,releaseValidationReport:reference};
 const nextBytes=Buffer.from(JSON.stringify(next,null,2)+'\n');
 const [evidenceAgain,lockAgain,reportAgain]=await Promise.all([
  readDirectProjectFile(root,evidencePath),readDirectProjectFile(root,lockPath),
  readDirectFile(path.join(root,reportPath),{minimum:reportBytes.length,maximum:reportBytes.length,
    privateMode:true,label:'release validation report recheck'}),
 ]);
 if(!evidenceAgain.equals(evidenceBytes)||!lockAgain.equals(lockBytes)||!reportAgain.equals(reportBytes)) {
  fail('release validation inputs changed before publication');
 }
 await gitBoundary(git,evidence.sourceCommit);
 const target=path.join(root,evidencePath),parent=path.dirname(target),parentMetadata=await lstat(parent);
 if(!parentMetadata.isDirectory()||parentMetadata.isSymbolicLink()
     ||parentMetadata.uid!==process.getuid()||(parentMetadata.mode&0o022)!==0) {
  fail('release validation evidence parent is unsafe');
 }
 await replaceLockedParentFileDurable({target,contents:nextBytes,expectedSha256:sha(nextBytes),
  expectedPreviousSha256:sha(evidenceBytes),expectedParentDevice:String(parentMetadata.dev),
  expectedParentInode:String(parentMetadata.ino),metadataInspectorExecutable:python.path,
  metadataInspectorSha256:python.sha256,expectedMode:0o600});
 await assertExecutableUnchanged(git);
 await assertExecutableUnchanged(python);
 const installed=await readDirectProjectFile(root,evidencePath);
 if(!installed.equals(nextBytes)) fail('installed release validation reference differs');
 console.log(JSON.stringify({ok:true,path:reportPath,sha256:reference.sha256},null,2));
}
try { await main(); } catch(error) {
 writeReleaseFailure('release-validation-evidence',error);
 process.exitCode=durableReplacementFailureExitCode(error);
}
