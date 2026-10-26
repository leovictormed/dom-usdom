#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {matchMainnetPreflightRpcSources} from '../sdk/mainnet-preflight-rpc.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {prepareRecoverableSafeRecoveryEnvelope} from '../sdk/safe-control-recovery-envelope.mjs';

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
  const planInput=await strictFile(process.env.USDOM_SAFE_RECOVERY_PLAN,'Safe recovery plan');
  const transactionsInput=await strictFile(
    process.env.USDOM_SAFE_RECOVERY_TRANSACTIONS,'Safe recovery transaction package');
  const catalogBytes=await readDirectProjectFile(root,catalogPath,{
    minimum:1,maximum:1024*1024,label:catalogPath});
  const catalog=parseStrictJson(catalogBytes.toString('utf8'),{label:catalogPath,maxDepth:16});
  runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  const sources=matchMainnetPreflightRpcSources(catalog,runtimeSources);
  const result=await prepareRecoverableSafeRecoveryEnvelope({
    plan:planInput.value,
    transactionPackage:transactionsInput.value,
    role:process.env.USDOM_SAFE_RECOVERY_ROLE,
    relayerOwner:process.env.USDOM_SAFE_RELAYER_OWNER,
    sources,
  });
  for(const input of [planInput,transactionsInput]) {
    const current=await readDirectFile(input.path,{minimum:input.bytes.length,
      maximum:input.bytes.length,label:input.label});
    if(!current.equals(input.bytes)) throw new Error(`${input.label} changed during envelope planning`);
  }
  const currentCatalogBytes=await readDirectProjectFile(root,catalogPath,{
    minimum:catalogBytes.length,maximum:catalogBytes.length,label:catalogPath});
  if(!currentCatalogBytes.equals(catalogBytes)) {
    throw new Error('Safe recovery RPC catalog changed during envelope planning');
  }
  process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-recoverable-safe-recovery-envelope',error);
  process.exitCode=1;
}
