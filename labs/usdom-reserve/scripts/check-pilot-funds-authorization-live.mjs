#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import {lstat} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile,readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {resolveReleaseAuthorizationRpcSources,withReleaseAuthorizationProviders,
  collectPilotFundsAuthorizationApprovalConsensus} from '../sdk/release-authorization-rpc.mjs';
import {validatePilotFundsAuthorizationState,validatePilotFundsPlanBinding,
  validatePilotFundsReleaseBinding} from '../sdk/pilot-funds-authorization.mjs';
import {requireOperationalTlsClock} from '../sdk/mainnet-preflight-rpc.mjs';
import {validatePilotFundsReleaseValidation} from '../sdk/pilot-funds-release-validation.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const paths=['evidence/authorization/pilot-funds-snapshot.json',
  'evidence/authorization/pilot-funds-authorization-state.json',
  'config/proof-reserve.unconfigured.json','config/mainnet-preflight-rpc-catalog.json'];
const generationPath='/home/leonardov/usdom-mainnet-private/control-plane/.phase-generation.json';
const fail=message=>{throw new Error(message);};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const projectPath=value=>{
 if(typeof value!=='string'||value.length===0) fail('pilot release-evidence path is absent');
 const absolute=path.resolve(root,value),relative=path.relative(root,absolute).split(path.sep).join('/');
 if(relative.startsWith('../')||path.resolve(root,relative)!==absolute) fail('pilot input path escapes the project');
 return relative;
};
async function requireAbsent(target) {
 try { await lstat(target); fail('pilot-funds authorization was already consumed'); }
 catch(error) { if(error?.code!=='ENOENT') throw error; }
}

try {
 if(process.argv.length!==2) fail('live pilot-funds authorization checker accepts no arguments');
 const bytes=await Promise.all(paths.map((value,index)=>readDirectProjectFile(root,value,
  {exactMode:index<2?0o600:0o644})));
 const [snapshot,stored,release,catalog]=bytes.map((value,index)=>
  parseStrictJsonBytes(value,{label:paths[index],maxDepth:32}));
 const generationBytes=await readDirectFile(generationPath,{minimum:2,maximum:64*1024,
  exactMode:0o600,label:'phase generation identity'});
 const generation=parseStrictJsonBytes(generationBytes,{label:'phase generation identity'});
 validatePilotFundsPlanBinding(snapshot,generation);
 validatePilotFundsReleaseBinding(snapshot,createHash('sha256').update(bytes[2]).digest('hex'));
 validatePilotFundsAuthorizationState({state:stored,snapshot,releaseConfig:release,
  depositAmountBaseUnits:snapshot.pilotDepositBaseUnits});
 const rpcPath=process.env.USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE;
 const controlDirectory=path.dirname(path.resolve(rpcPath));
 const consumed=path.join(controlDirectory,'pilot-funds-authorization-consumed.json');
 await requireAbsent(consumed);
 const [releaseEvidenceBytes,toolchainBytes,cargoLockBytes]=await Promise.all([
  readDirectProjectFile(root,'config/mainnet-release-evidence.unconfigured.json'),
  readDirectProjectFile(root,'config/mainnet-toolchain-lock.json'),readDirectFile(path.resolve(root,'../../Cargo.lock'))]);
 const evidence=parseStrictJsonBytes(releaseEvidenceBytes,{label:'mainnet release evidence',maxDepth:32});
 const reportRelative=projectPath(evidence?.releaseValidationReport?.path);
 const checkpointRelative=projectPath(evidence?.checkpointProofCapacityReport?.path);
 const burnRelative=projectPath(evidence?.realFinalizedEndToEndReport?.path);
 const bindingPaths=[process.env.USDOM_MAINNET_DEPLOYMENT_PACKAGE,
  path.join(root,'evidence/control-plane/safe-control-release-evidence-bundle.json'),
  '/home/leonardov/.local/share/dom-usdom/mainnet-privacy/installation.json',
  path.join(root,checkpointRelative),path.join(root,burnRelative),process.env.USDOM_OPERATIONAL_GAS_EVIDENCE,
  path.join(root,'docs/RESIDUAL-RISK-ACCEPTANCE-DRAFT-2026-10-16.md'),path.join(root,reportRelative)];
 if(bindingPaths.some(value=>typeof value!=='string'||value.length===0)) fail('pilot snapshot input path is absent');
 const privateIndexes=new Set([0,1,2,3,4,5,7]);
 const readBindings=()=>Promise.all(bindingPaths.map((value,index)=>readDirectFile(value,
  {minimum:1,maximum:8*1024*1024,exactMode:privateIndexes.has(index)?0o600:null,label:`pilot snapshot input ${index}`})));
 const bindingBytes=await readBindings();
 const expected=[snapshot.deploymentPackageSha256,snapshot.safeControlBundleSha256,
  snapshot.nativePrivacyInstallationSha256,snapshot.checkpointCapacityEvidenceSha256,
  snapshot.finalizedBurnCapacityEvidenceSha256,snapshot.operationalGasEvidenceSha256,
  snapshot.residualRiskDraftSha256,snapshot.releaseValidationReportSha256];
 bindingBytes.forEach((value,index)=>{if(sha(value)!==expected[index]) fail(`pilot snapshot input ${index} changed after authorization`);});
 validatePilotFundsReleaseValidation({reportBytes:bindingBytes[7],releaseEvidenceBytes,
  toolchainLockBytes:toolchainBytes,cargoLockBytes,reportRelativePath:reportRelative});
 const rpcBytes=await readDirectFile(rpcPath,{minimum:2,maximum:1024*1024,exactMode:0o600,
  label:'live pilot authorization RPC sources'});
 const capturedRuntime=parseStrictJsonBytes(rpcBytes,{label:'live pilot authorization RPC sources'});
 const runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',
  {label:'live pilot authorization RPC sources'});
 if(JSON.stringify(runtimeSources)!==JSON.stringify(capturedRuntime)) {
  fail('live pilot authorization RPC sources changed before provider creation');
 }
 const sources=resolveReleaseAuthorizationRpcSources({catalog,runtimeSources});
 const finalizedObservation=await withReleaseAuthorizationProviders(sources,providers=>
  collectPilotFundsAuthorizationApprovalConsensus({providers,releaseConfig:release,
   authorization:stored.authorization,sources}));
 const currentBytes=await Promise.all(paths.map((value,index)=>readDirectProjectFile(root,value,
  {exactMode:index<2?0o600:0o644})));
 const [releaseEvidenceAgain,toolchainAgain,cargoAgain,bindingAgain]=await Promise.all([
  readDirectProjectFile(root,'config/mainnet-release-evidence.unconfigured.json'),
  readDirectProjectFile(root,'config/mainnet-toolchain-lock.json'),readDirectFile(path.resolve(root,'../../Cargo.lock')),
  readBindings()]);
 if(currentBytes.some((value,index)=>!value.equals(bytes[index]))
    ||!releaseEvidenceAgain.equals(releaseEvidenceBytes)||!toolchainAgain.equals(toolchainBytes)
    ||!cargoAgain.equals(cargoLockBytes)||bindingAgain.some((value,index)=>!value.equals(bindingBytes[index]))
    ||!(await readDirectFile(generationPath,{minimum:generationBytes.length,
      maximum:generationBytes.length,exactMode:0o600,label:'phase generation identity'})).equals(generationBytes)
    ||!(await readDirectFile(rpcPath,{minimum:rpcBytes.length,maximum:rpcBytes.length,
      exactMode:0o600,label:'live pilot authorization RPC sources'})).equals(rpcBytes)) {
  fail('live pilot authorization inputs changed during finalized observation');
 }
 await requireAbsent(consumed);
 const current={...stored,finalizedObservation};
 validatePilotFundsAuthorizationState({state:current,snapshot,releaseConfig:release,
  depositAmountBaseUnits:snapshot.pilotDepositBaseUnits});
 const observed=BigInt(finalizedObservation.finalizedBlockTimestamp);
 const previous=BigInt(stored.finalizedObservation.finalizedBlockTimestamp);
 const nowMs=requireOperationalTlsClock(Date.now()),now=BigInt(Math.floor(nowMs/1000));
 if(observed<previous||now>BigInt(stored.authorization.validUntil)
    ||observed>now+15n||now-observed>30n*60n) {
  fail('pilot authorization is stale, expired or regressed at the live finalized boundary');
 }
 process.stdout.write(JSON.stringify({schema:'usdom-pilot-funds-live-recheck/v1',
  digest:stored.digest,finalizedBlockHash:finalizedObservation.finalizedBlockHash,
  finalizedBlockTimestamp:finalizedObservation.finalizedBlockTimestamp,rpcCount:sources.length})+'\n');
} catch(error) { writeReleaseFailure('check-pilot-funds-authorization-live',error); process.exitCode=1; }
