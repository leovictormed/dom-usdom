#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {lstat,mkdir} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {removePrivateFileDurableIfExists,writeFileDurable} from '../sdk/durable-private-file.mjs';
import {durableReplacementFailureExitCode,replaceLockedParentFileDurable}
  from '../sdk/durable-locked-parent-replacement.mjs';
import {createHash} from 'node:crypto';
import {
  MAINNET_PREFLIGHT_MATERIALIZATION,prepareMainnetPreflightMaterialization,
} from '../sdk/mainnet-preflight-materialization.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {captureMainnetPreflightInputs} from '../sdk/mainnet-preflight-input-snapshot.mjs';
import {snapshotExecutable} from '../sdk/stable-executable.mjs';

process.umask(0o077);
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const phase=process.argv[2];
const releasePath='config/proof-reserve.unconfigured.json';
const evidencePath='config/mainnet-release-evidence.unconfigured.json';
const requirementsPath='config/production-requirements.json';
const riscZeroPath='config/risc0-ethereum-mainnet-v3.json';
const rpcCatalogPath='config/mainnet-preflight-rpc-catalog.json';
const inputNames={
  predeployment:'mainnet-predeployment-attestation.json',
  postdeployment:'mainnet-cold-start-attestation.json',
};
const pythonExecutable=await snapshotExecutable('python3');
const sha256=value=>createHash('sha256').update(value).digest('hex');
function fail(message) { throw new Error(message); }
const json=(bytes,label)=>parseStrictJsonBytes(bytes,{label,maxBytes:16*1024*1024,maxDepth:96});

async function ensureEvidenceDirectory() {
  const target=path.join(root,'evidence');
  try { await mkdir(target,{mode:0o700}); }
  catch(error) { if(error?.code!=='EEXIST') throw error; }
  const metadata=await lstat(target);
  if(!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid!==process.getuid()
      || (metadata.mode&0o022)!==0) fail('evidence directory is unsafe');
}
async function installEvidence(relative,content) {
  const expected=Buffer.from(content);
  try {
    const existing=await readDirectProjectFile(root,relative,{minimum:1,maximum:16*1024*1024,
      exactMode:0o600,label:'existing mainnet preflight evidence'});
    if(!existing.equals(expected)) fail('mainnet preflight evidence path already contains different bytes');
  } catch(error) {
    if(error?.code!=='ENOENT') throw error;
    await writeFileDurable(path.join(root,relative),expected,{mode:0o600,replace:false});
  }
}
async function compareAndSwapReleaseEvidence(content,previousBytes) {
  const target=path.join(root,evidencePath),parent=path.dirname(target),metadata=await lstat(parent);
  if(!metadata.isDirectory()||metadata.isSymbolicLink()||metadata.uid!==process.getuid()
      ||(metadata.mode&0o022)!==0) fail('release evidence parent is unsafe');
  const bytes=Buffer.from(content);
  await replaceLockedParentFileDurable({target,contents:bytes,expectedSha256:sha256(bytes),
    expectedPreviousSha256:sha256(previousBytes),expectedParentDevice:String(metadata.dev),
    expectedParentInode:String(metadata.ino),metadataInspectorExecutable:pythonExecutable.path,
    metadataInspectorSha256:pythonExecutable.sha256,expectedMode:0o644});
}
async function main() {
  if(process.argv.length!==3 || !MAINNET_PREFLIGHT_MATERIALIZATION[phase]) {
    fail('usage: materialize-mainnet-preflight-attestation.mjs <predeployment|postdeployment>');
  }
  const accountHome=os.userInfo().homedir;
  if(os.homedir()!==accountHome || process.env.HOME!==accountHome || !path.isAbsolute(accountHome)) {
    fail('HOME must be the current operating-system account home');
  }
  // The report is derived and retryable. Invalidate its completion pointer and
  // old bytes before reading the private report, so a failed renewal cannot
  // leave an earlier generation advertised as current.
  const policy=MAINNET_PREFLIGHT_MATERIALIZATION[phase];
  const currentEvidenceBytes=await readDirectProjectFile(root,evidencePath,{minimum:1,
    maximum:16*1024*1024,exactMode:0o644,label:'mainnet release evidence'});
  const currentEvidence=json(currentEvidenceBytes,evidencePath);
  if(!Object.hasOwn(currentEvidence,policy.evidenceField)) {
    fail('release evidence does not contain the required preflight slot');
  }
  const invalidated=Buffer.from(`${JSON.stringify({...currentEvidence,
    [policy.evidenceField]:null},null,2)}\n`);
  await compareAndSwapReleaseEvidence(invalidated,currentEvidenceBytes);
  await removePrivateFileDurableIfExists(path.join(root,policy.evidencePath));
  const inputPath=path.join(accountHome,'usdom-mainnet-private/control-plane',inputNames[phase]);
  const snapshot=await captureMainnetPreflightInputs({report:inputPath,
    release:path.join(root,releasePath),evidence:path.join(root,evidencePath),
    requirements:path.join(root,requirementsPath),riscZero:path.join(root,riscZeroPath),
    rpcCatalog:path.join(root,rpcCatalogPath)});
  let primaryError=null,successRecord=null;
  try {
    const prepared=prepareMainnetPreflightMaterialization({
      phase,report:json(snapshot.report,'private mainnet preflight report'),
      releaseConfig:json(snapshot.release,releasePath),evidence:json(snapshot.evidence,evidencePath),
      requirements:json(snapshot.requirements,requirementsPath),
      riscZeroReference:json(snapshot.riscZero,riscZeroPath),
      rpcCatalog:json(snapshot.rpcCatalog,rpcCatalogPath),
    });
    await ensureEvidenceDirectory();
    await snapshot.assertOriginsUnchanged();
    await installEvidence(prepared.evidencePath,prepared.reportContent);
    await snapshot.assertOriginsUnchanged();
    // Production requirements are source-bound policy. Operational conclusions
    // are committed later in the release-bound claims ledger, so this ceremony
    // must preserve the policy bytes exactly.
    const requirementsBytes=Buffer.from(prepared.requirementsContent);
    const expectedGeneration={report:snapshot.report,release:snapshot.release,
      evidence:snapshot.evidence,requirements:requirementsBytes,riscZero:snapshot.riscZero,
      rpcCatalog:snapshot.rpcCatalog};
    await snapshot.assertOriginsEqual(expectedGeneration);
    await compareAndSwapReleaseEvidence(prepared.evidenceContent,snapshot.evidence);
    const evidenceBytes=Buffer.from(prepared.evidenceContent);
    const completedGeneration={...expectedGeneration,evidence:evidenceBytes};
    const expectedReport=Buffer.from(prepared.reportContent);
    const verifyInstalledGeneration=async()=>{
      const [installedReport,installedRequirements,installedEvidence]=await Promise.all([
        readDirectProjectFile(root,prepared.evidencePath,{minimum:1,maximum:16*1024*1024,
          exactMode:0o600,label:'installed mainnet preflight report'}),
        readDirectProjectFile(root,requirementsPath,{minimum:1,maximum:16*1024*1024,
          exactMode:0o644,label:'installed mainnet production requirements'}),
        readDirectProjectFile(root,evidencePath,{minimum:1,maximum:16*1024*1024,
          exactMode:0o644,label:'installed mainnet release evidence'}),
      ]);
      if(!installedReport.equals(expectedReport)
          || !installedRequirements.equals(requirementsBytes)
          || !installedEvidence.equals(evidenceBytes)) {
        fail('completed mainnet preflight generation does not match prepared bytes');
      }
    };
    await snapshot.assertOriginsEqual(completedGeneration);
    await verifyInstalledGeneration();
    // Close both sides of the final read: a non-cooperating writer cannot swap
    // an origin or installed output between the last snapshot and success.
    await snapshot.assertOriginsEqual(completedGeneration);
    await verifyInstalledGeneration();
    await snapshot.assertOriginsEqual(completedGeneration);
    successRecord={ok:true,phase,path:prepared.evidencePath,
      sha256:prepared.document.sha256,broadcastAuthorized:false};
  } catch(error) {
    primaryError=error;
    throw error;
  } finally {
    try { await snapshot.cleanup(); }
    catch(cleanupError) { if(primaryError===null) throw cleanupError; }
  }
  console.log(JSON.stringify(successRecord,null,2));
}
try { await main(); }
catch(error) {
  writeReleaseFailure('materialize-mainnet-preflight-attestation',error);
  process.exitCode=durableReplacementFailureExitCode(error);
}
