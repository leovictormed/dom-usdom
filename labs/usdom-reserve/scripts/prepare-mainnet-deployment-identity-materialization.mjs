#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {getAddress} from 'ethers';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {observeMainnetDeploymentIdentity} from '../sdk/mainnet-deployment-identity.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {BoundedMainnetPreflightProvider,matchMainnetPreflightRpcSources}
  from '../sdk/mainnet-preflight-rpc.mjs';

let sources=[];
try {
  if(process.argv.length!==2) throw new Error('this fixed command accepts no arguments');
  const deployer=getAddress(process.env.USDOM_MAINNET_DEPLOYER??'');
  const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
  const relative='config/proof-reserve.unconfigured.json';
  const catalogRelative='config/mainnet-preflight-rpc-catalog.json';
  const [before,catalogBytes]=await Promise.all([
    readDirectProjectFile(root,relative,{exactMode:0o644,maximum:1024*1024}),
    readDirectProjectFile(root,catalogRelative,{exactMode:0o644,maximum:1024*1024}),
  ]);
  const releaseConfig=parseStrictJson(before.toString('utf8'),{label:'proof-reserve release config'});
  const catalog=parseStrictJson(catalogBytes.toString('utf8'),{label:'mainnet preflight RPC catalog'});
  const runtime=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  sources=matchMainnetPreflightRpcSources(catalog,runtime);
  const providers=sources.map(source=>new BoundedMainnetPreflightProvider(source.url));
  let result;
  try { result=await observeMainnetDeploymentIdentity({releaseConfig,deployer,providers,
    sourceIds:sources.map(source=>source.sourceId),
    sourceOriginCommitments:catalog.sources.map(source=>source.originKeccak256)}); }
  finally { for(const provider of providers) provider.destroy(); }
  const [current,currentCatalogBytes]=await Promise.all([
    readDirectProjectFile(root,relative,{
      minimum:before.length,maximum:before.length,exactMode:0o644,
    }),
    readDirectProjectFile(root,catalogRelative,{
      minimum:catalogBytes.length,maximum:catalogBytes.length,exactMode:0o644,
    }),
  ]);
  if(!current.equals(before)||!currentCatalogBytes.equals(catalogBytes)) {
    throw new Error('release configuration or RPC catalog changed during observation');
  }
  process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-mainnet-deployment-identity-materialization',error);
  process.exitCode=1;
}
