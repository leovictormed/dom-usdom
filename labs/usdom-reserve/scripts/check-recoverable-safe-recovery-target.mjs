#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {matchMainnetPreflightRpcSources} from '../sdk/mainnet-preflight-rpc.mjs';
import {observeRecoverableSafeControlRoleBeforeRecovery} from '../sdk/safe-control-observation.mjs';
import {validateRecoverableSafeRecoveryEnvelope} from '../sdk/safe-control-recovery-envelope.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const catalogPath='config/mainnet-preflight-rpc-catalog.json';
let runtimeSources=[];
const privateInputBytes=[];
async function readPrivateInput(target,options) {
  const bytes=await readDirectFile(target,options);
  privateInputBytes.push(bytes);
  return bytes;
}
try {
  const packagePath=process.env.USDOM_SAFE_PACKAGE;
  if(typeof packagePath!=='string'||packagePath.length===0) {
    throw new Error('USDOM_SAFE_PACKAGE is required');
  }
  const packageBytes=await readPrivateInput(packagePath,{
    minimum:1,maximum:1024*1024,label:'recoverable Safe package',
  });
  const packageDocument=parseStrictJson(packageBytes.toString('utf8'),{
    label:'recoverable Safe package',maxBytes:1024*1024,maxDepth:16,
  });
  const planPath=process.env.USDOM_SAFE_RECOVERY_PLAN;
  const transactionsPath=process.env.USDOM_SAFE_RECOVERY_TRANSACTIONS;
  const envelopePath=process.env.USDOM_SAFE_RECOVERY_ENVELOPE;
  const [planBytes,transactionsBytes,envelopeBytes]=await Promise.all([
    readPrivateInput(planPath,{minimum:1,maximum:2*1024*1024,label:'Safe recovery plan'}),
    readPrivateInput(transactionsPath,{minimum:1,maximum:2*1024*1024,
      label:'Safe recovery transaction package'}),
    readPrivateInput(envelopePath,{minimum:1,maximum:2*1024*1024,label:'Safe recovery envelope'}),
  ]);
  const plan=parseStrictJson(planBytes.toString('utf8'),{label:'Safe recovery plan',maxDepth:32});
  const transactions=parseStrictJson(transactionsBytes.toString('utf8'),{
    label:'Safe recovery transaction package',maxDepth:32});
  const envelope=parseStrictJson(envelopeBytes.toString('utf8'),{
    label:'Safe recovery envelope',maxDepth:32});
  validateRecoverableSafeRecoveryEnvelope(plan,transactions,envelope);
  const catalogBytes=await readDirectProjectFile(root,catalogPath,{
    minimum:1,maximum:1024*1024,label:catalogPath});
  const catalog=parseStrictJson(catalogBytes.toString('utf8'),{label:catalogPath,maxDepth:16});
  runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  const sources=matchMainnetPreflightRpcSources(catalog,runtimeSources);
  const results=await Promise.all(sources.map(source=>observeRecoverableSafeControlRoleBeforeRecovery({
    packageDocument,role:envelope.role,rpcUrl:source.url,
  })));
  const canonical=results.map(result=>JSON.stringify(result));
  if(canonical.some(result=>result!==canonical[0])) {
    throw new Error('independent Safe target RPC observations disagree');
  }
  const [currentPackageBytes,currentPlanBytes,currentTransactionsBytes,currentEnvelopeBytes,
    currentCatalogBytes]=await Promise.all([
    readPrivateInput(packagePath,{minimum:packageBytes.length,maximum:packageBytes.length,
      label:'recoverable Safe package'}),
    readPrivateInput(planPath,{minimum:planBytes.length,maximum:planBytes.length,
      label:'Safe recovery plan'}),
    readPrivateInput(transactionsPath,{minimum:transactionsBytes.length,maximum:transactionsBytes.length,
      label:'Safe recovery transaction package'}),
    readPrivateInput(envelopePath,{minimum:envelopeBytes.length,maximum:envelopeBytes.length,
      label:'Safe recovery envelope'}),
    readDirectProjectFile(root,catalogPath,{minimum:catalogBytes.length,maximum:catalogBytes.length,
      label:catalogPath}),
  ]);
  if(!currentPackageBytes.equals(packageBytes)||!currentPlanBytes.equals(planBytes)
      ||!currentTransactionsBytes.equals(transactionsBytes)||!currentEnvelopeBytes.equals(envelopeBytes)
      ||!currentCatalogBytes.equals(catalogBytes)) {
    throw new Error('recoverable Safe target inputs changed during preflight');
  }
  const result=results[0];
  process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('check-recoverable-safe-recovery-target',error);
  process.exitCode=1;
} finally {
  for(const bytes of privateInputBytes) bytes.fill(0);
}
