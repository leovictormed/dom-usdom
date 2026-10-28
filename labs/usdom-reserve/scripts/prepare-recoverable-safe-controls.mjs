#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {
  BoundedMainnetPreflightProvider,matchMainnetPreflightRpcSources,
} from '../sdk/mainnet-preflight-rpc.mjs';
import {prepareRecoverableSafeControlDeployments} from '../sdk/safe-control-deployment.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const catalogPath='config/mainnet-preflight-rpc-catalog.json';
const ownerIdentityPath=process.env.USDOM_SAFE_OWNER_IDENTITIES;
let runtimeSources=[];
try {
  if(typeof ownerIdentityPath!=='string'||ownerIdentityPath.length===0) {
    throw new Error('USDOM_SAFE_OWNER_IDENTITIES is required');
  }
  const [catalogBytes,ownerIdentityBytes]=await Promise.all([
    readDirectProjectFile(root,catalogPath,{minimum:1,maximum:1024*1024,label:catalogPath}),
    readDirectFile(ownerIdentityPath,{minimum:1,maximum:4096,exactMode:0o600,label:'Safe owner identities'}),
  ]);
  const catalog=parseStrictJson(catalogBytes.toString('utf8'),{label:catalogPath,maxDepth:16});
  const identities=parseStrictJson(ownerIdentityBytes.toString('utf8'),{
    label:'Safe owner identities',maxBytes:4096,maxDepth:4});
  if(JSON.stringify(Object.keys(identities).sort())!==JSON.stringify(['custodySignaturesStatus','evidenceSha256ByOwner','ownersByRole','schema','singleOperator','singleOperatorResidualRisk','threshold'].sort())
      ||identities.schema!=='usdom-safe-owner-identities/v2'||identities.threshold!==2||identities.singleOperator!==true||identities.singleOperatorResidualRisk!==true||identities.custodySignaturesStatus!=='awaiting-safe-package-for-12-custody-signatures') {
    throw new Error('Safe owner identities schema is invalid');
  }
  runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  const sources=matchMainnetPreflightRpcSources(catalog,runtimeSources);
  const ownersByRole=identities.ownersByRole;
  const results=[];
  for(const source of sources) {
    // Each observation owns and closes its provider, including on failure.
    const options={ownersByRole,rpcUrl:source.url,
      providerFactory:()=>new BoundedMainnetPreflightProvider(source.url)};
    const before=await prepareRecoverableSafeControlDeployments(options);
    const after=await prepareRecoverableSafeControlDeployments(options);
    if(JSON.stringify(before)!==JSON.stringify(after)) {
      throw new Error('Safe deployment observation changed during source recheck');
    }
    results.push(before);
  }
  const canonical=results.map(result=>JSON.stringify(result));
  if(canonical.some(result=>result!==canonical[0])) {
    throw new Error('independent Safe deployment RPC observations disagree');
  }
  const [currentCatalogBytes,currentOwnerIdentityBytes]=await Promise.all([
    readDirectProjectFile(root,catalogPath,{
      minimum:catalogBytes.length,maximum:catalogBytes.length,label:catalogPath}),
    readDirectFile(ownerIdentityPath,{minimum:ownerIdentityBytes.length,maximum:ownerIdentityBytes.length,
      exactMode:0o600,label:'Safe owner identities'}),
  ]);
  if(!currentCatalogBytes.equals(catalogBytes)||!currentOwnerIdentityBytes.equals(ownerIdentityBytes)) {
    throw new Error('Safe deployment inputs changed during preparation');
  }
  const result=results[0];
  process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-recoverable-safe-controls',error);
  process.exitCode=1;
}
