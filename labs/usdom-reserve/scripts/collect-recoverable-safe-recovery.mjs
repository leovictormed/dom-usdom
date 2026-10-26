#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {matchMainnetPreflightRpcSources} from '../sdk/mainnet-preflight-rpc.mjs';
import {collectRecoverableSafeControlRecoveryConsensus}
  from '../sdk/safe-control-rpc-consensus.mjs';
import {validateRecoverableSafeRecoveryPlan} from '../sdk/safe-control-recovery-plan.mjs';
import {validateFinalizedSafeRecoveryExecution} from '../sdk/safe-control-recovery-execution.mjs';
import {rpcConsensusEvidence} from '../sdk/rpc-consensus-evidence.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const catalogPath='config/mainnet-preflight-rpc-catalog.json';
let runtimeSources=[];

async function strictFile(file,label) {
  if(typeof file!=='string'||file.length===0) throw new Error(`${label} path is required`);
  const bytes=await readDirectFile(file,{minimum:1,maximum:2*1024*1024,label});
  return {path:file,label,bytes,value:parseStrictJson(bytes.toString('utf8'),
    {label,maxBytes:2*1024*1024,maxDepth:32})};
}

try {
  const packageInput=await strictFile(process.env.USDOM_SAFE_PACKAGE,'recoverable Safe package');
  const baselineInput=await strictFile(process.env.USDOM_SAFE_BASELINE,'recoverable Safe baseline');
  const planInput=await strictFile(process.env.USDOM_SAFE_RECOVERY_PLAN,'recoverable Safe recovery plan');
  const transactionsInput=await strictFile(process.env.USDOM_SAFE_RECOVERY_TRANSACTIONS,
    'recoverable Safe recovery transaction package');
  const catalogBytes=await readDirectProjectFile(root,catalogPath,{
    minimum:1,maximum:1024*1024,label:catalogPath});
  const evidenceDirectory=process.env.USDOM_CONTROL_EVIDENCE_DIRECTORY;
  if(typeof evidenceDirectory!=='string'||evidenceDirectory.length===0) {
    throw new Error('control evidence directory is required');
  }
  const roles=['governance','reserveGuardian','checkpointGuardian'];
  const executionInputs=await Promise.all(roles.map(role=>strictFile(
    path.join(evidenceDirectory,`${role}-finalized-execution.json`),`${role} finalized execution`)));
  const packageDocument=packageInput.value,baselineSnapshot=baselineInput.value;
  const plan=planInput.value;
  validateRecoverableSafeRecoveryPlan(plan);
  const catalog=parseStrictJson(catalogBytes.toString('utf8'),{label:catalogPath,maxDepth:16});
  runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  const sources=matchMainnetPreflightRpcSources(catalog,runtimeSources);
  const transactions=Object.create(null);
  for(const [index,role] of roles.entries()) {
    const execution=executionInputs[index].value;
    validateFinalizedSafeRecoveryExecution({plan,transactionPackage:transactionsInput.value,
      execution});
    if(execution.role!==role||JSON.stringify(execution.rpcConsensus)!==JSON.stringify(
      rpcConsensusEvidence(sources))) throw new Error(`${role} finalized execution reference is invalid`);
    transactions[role]=execution.transactionHash;
  }
  const result=await collectRecoverableSafeControlRecoveryConsensus({
    packageDocument,
    baselineSnapshot,
    transitionsByRole:plan.transitionsByRole,
    transactions,
    sources,
  });
  for(const input of [packageInput,baselineInput,planInput,transactionsInput,...executionInputs]) {
    const current=await readDirectFile(input.path,{minimum:input.bytes.length,
      maximum:input.bytes.length,label:input.label});
    if(!current.equals(input.bytes)) throw new Error(`${input.label} changed during recovery collection`);
  }
  const catalogAfter=await readDirectProjectFile(root,catalogPath,{
    minimum:catalogBytes.length,maximum:catalogBytes.length,label:catalogPath});
  if(!catalogAfter.equals(catalogBytes)) throw new Error('RPC catalog changed during recovery collection');
  process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('collect-recoverable-safe-recovery',error);
  process.exitCode=1;
}
