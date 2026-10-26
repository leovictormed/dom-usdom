#!/usr/bin/env node
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {BoundedMainnetPreflightProvider,matchMainnetPreflightRpcSources}
  from '../sdk/mainnet-preflight-rpc.mjs';
import {classifyRecoverableSafeDeploymentTargetConsensus}
  from '../sdk/safe-control-deployment-target.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
try {
  const role=process.argv[2];
  const packagePath=process.env.USDOM_SAFE_PACKAGE;
  if(process.argv.length!==3||typeof packagePath!=='string'||!path.isAbsolute(packagePath)) {
    throw new Error('Usage: check-safe-control-deployment-target.mjs ROLE with USDOM_SAFE_PACKAGE');
  }
  const [packageBytes,catalogBytes]=await Promise.all([
    readDirectFile(packagePath,{minimum:1,maximum:1024*1024,exactMode:0o600,label:'Safe package'}),
    readDirectProjectFile(root,'config/mainnet-preflight-rpc-catalog.json',{
      minimum:1,maximum:1024*1024,label:'mainnet RPC catalog'}),
  ]);
  const packageDocument=parseStrictJson(packageBytes.toString('utf8'),{label:'Safe package'});
  const catalog=parseStrictJson(catalogBytes.toString('utf8'),{label:'mainnet RPC catalog'});
  const runtime=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{
    label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  const sources=matchMainnetPreflightRpcSources(catalog,runtime);
  const result=await classifyRecoverableSafeDeploymentTargetConsensus({
    packageDocument,role,rpcUrls:sources.map(value=>value.url),
    providerFactory:url=>new BoundedMainnetPreflightProvider(url),
  });
  const [packageAfter,catalogAfter]=await Promise.all([
    readDirectFile(packagePath,{minimum:packageBytes.length,maximum:packageBytes.length,
      exactMode:0o600,label:'Safe package'}),
    readDirectProjectFile(root,'config/mainnet-preflight-rpc-catalog.json',{
      minimum:catalogBytes.length,maximum:catalogBytes.length,label:'mainnet RPC catalog'}),
  ]);
  if(!packageAfter.equals(packageBytes)||!catalogAfter.equals(catalogBytes)) {
    throw new Error('Safe deployment target inputs changed during observation');
  }
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch(error) {
  writeReleaseFailure('check-safe-control-deployment-target',error);
  process.exitCode=1;
}
