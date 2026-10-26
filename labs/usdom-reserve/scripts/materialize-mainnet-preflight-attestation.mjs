#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {lstat,mkdir} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {removePrivateFileDurableIfExists,writeFileDurable} from '../sdk/durable-private-file.mjs';
import {
  MAINNET_PREFLIGHT_MATERIALIZATION,prepareMainnetPreflightMaterialization,
} from '../sdk/mainnet-preflight-materialization.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {captureMainnetPreflightInputs} from '../sdk/mainnet-preflight-input-snapshot.mjs';

process.umask(0o077);
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const phase=process.argv[2];
const releasePath='config/proof-reserve.unconfigured.json';
const evidencePath='config/mainnet-release-evidence.unconfigured.json';
const requirementsPath='config/production-requirements.json';
const riscZeroPath='config/risc0-ethereum-mainnet-v3.json';
const inputNames={
  predeployment:'mainnet-predeployment-attestation.json',
  postdeployment:'mainnet-cold-start-attestation.json',
};
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
  await writeFileDurable(path.join(root,evidencePath),invalidated,{mode:0o644});
  await removePrivateFileDurableIfExists(path.join(root,policy.evidencePath));
  const inputPath=path.join(accountHome,'usdom-mainnet-private/control-plane',inputNames[phase]);
  const snapshot=await captureMainnetPreflightInputs({report:inputPath,
    release:path.join(root,releasePath),evidence:path.join(root,evidencePath),
    requirements:path.join(root,requirementsPath),riscZero:path.join(root,riscZeroPath)});
  try {
    const prepared=prepareMainnetPreflightMaterialization({
      phase,report:json(snapshot.report,'private mainnet preflight report'),
      releaseConfig:json(snapshot.release,releasePath),evidence:json(snapshot.evidence,evidencePath),
      requirements:json(snapshot.requirements,requirementsPath),
      riscZeroReference:json(snapshot.riscZero,riscZeroPath),
    });
    await ensureEvidenceDirectory();
    await snapshot.assertOriginsUnchanged();
    await installEvidence(prepared.evidencePath,prepared.reportContent);
    await snapshot.assertOriginsUnchanged();
    await writeFileDurable(path.join(root,evidencePath),prepared.evidenceContent,{mode:0o644});
    await snapshot.assertOriginsUnchanged();
    await writeFileDurable(path.join(root,requirementsPath),prepared.requirementsContent,{mode:0o644});
    console.log(JSON.stringify({ok:true,phase,path:prepared.evidencePath,
      sha256:prepared.document.sha256,broadcastAuthorized:false},null,2));
  } finally { await snapshot.cleanup(); }
}
try { await main(); }
catch(error) { writeReleaseFailure('materialize-mainnet-preflight-attestation',error); process.exitCode=1; }
