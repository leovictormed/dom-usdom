#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {SafeRecoveryNotFinalizedError} from '../sdk/safe-control-recovery-execution.mjs';
import {matchMainnetPreflightRpcSources} from '../sdk/mainnet-preflight-rpc.mjs';
import {observeFinalizedSafeRecoveryExecutionConsensus} from '../sdk/safe-control-rpc-consensus.mjs';
import {validateRecoverableSafeRecoveryEnvelope} from '../sdk/safe-control-recovery-envelope.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const catalogPath='config/mainnet-preflight-rpc-catalog.json';
let runtimeSources=[];

async function strictFile(path,label) {
  if(typeof path!=='string'||path.length===0) throw new Error(`${label} path is required`);
  const bytes=await readDirectFile(path,{minimum:1,maximum:2*1024*1024,label});
  return {path,label,bytes,value:parseStrictJson(bytes.toString('utf8'),
    {label,maxBytes:2*1024*1024,maxDepth:32})};
}

try {
  const [planInput,transactionsInput,envelopeInput,catalogBytes]=await Promise.all([
    strictFile(process.env.USDOM_SAFE_RECOVERY_PLAN,'Safe recovery plan'),
    strictFile(process.env.USDOM_SAFE_RECOVERY_TRANSACTIONS,'Safe recovery transaction package'),
    strictFile(process.env.USDOM_SAFE_RECOVERY_ENVELOPE,'Safe recovery envelope'),
    readDirectProjectFile(root,catalogPath,{minimum:1,maximum:1024*1024,label:catalogPath}),
  ]);
  const catalog=parseStrictJson(catalogBytes.toString('utf8'),{label:catalogPath,maxDepth:16});
  runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  const sources=matchMainnetPreflightRpcSources(catalog,runtimeSources);
  validateRecoverableSafeRecoveryEnvelope(planInput.value,transactionsInput.value,envelopeInput.value);
  const result=await observeFinalizedSafeRecoveryExecutionConsensus({
    plan:planInput.value,
    transactionPackage:transactionsInput.value,
    role:envelopeInput.value.role,
    sources,
  });
  for(const input of [planInput,transactionsInput,envelopeInput]) {
    const current=await readDirectFile(input.path,{minimum:input.bytes.length,
      maximum:input.bytes.length,label:input.label});
    if(!current.equals(input.bytes)) throw new Error(`${input.label} changed during execution observation`);
  }
  const catalogAfter=await readDirectProjectFile(root,catalogPath,{
    minimum:catalogBytes.length,maximum:catalogBytes.length,label:catalogPath});
  if(!catalogAfter.equals(catalogBytes)) throw new Error('RPC catalog changed during execution observation');
  process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
} catch(error) {
  if(error instanceof SafeRecoveryNotFinalizedError) {
    process.stderr.write('USDOM_SAFE_RECOVERY_NOT_FINALIZED\n');
    process.exitCode=3;
  } else {
    writeReleaseFailure('observe-recoverable-safe-recovery-execution',error);
    process.exitCode=1;
  }
}
