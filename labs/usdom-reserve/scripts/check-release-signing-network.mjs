#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {collectReleaseAuthorizationAnchor,resolveReleaseAuthorizationRpcSources,
  validateReleaseSigningNetworkObservation,
  withReleaseAuthorizationProviders} from '../sdk/release-authorization-rpc.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const parse=(bytes,label)=>parseStrictJson(bytes.toString('utf8'),{
  label,maxBytes:4*1024*1024,maxDepth:64,
});

try {
  if(process.argv.length!==4) throw new Error('usage: check-release-signing-network REQUEST CONFIG');
  const requestPath=path.resolve(process.argv[2]);
  const configPath=path.resolve(process.argv[3]);
  const [requestBytes,configBytes,catalogBytes]=await Promise.all([
    readDirectFile(requestPath,{minimum:1,maximum:4*1024*1024,exactMode:0o600,
      label:'release signing request snapshot'}),
    readDirectFile(configPath,{minimum:1,maximum:4*1024*1024,exactMode:0o600,
      label:'release configuration snapshot'}),
    readDirectProjectFile(root,'config/mainnet-preflight-rpc-catalog.json',{
      minimum:1,maximum:1024*1024,exactMode:0o644,label:'mainnet preflight RPC catalog'}),
  ]);
  const request=parse(requestBytes,'release signing request snapshot');
  const releaseConfig=parse(configBytes,'release configuration snapshot');
  const catalog=parse(catalogBytes,'mainnet preflight RPC catalog');
  const runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  const sources=resolveReleaseAuthorizationRpcSources({catalog,runtimeSources});
  const observed=await withReleaseAuthorizationProviders(sources,providers=>
    collectReleaseAuthorizationAnchor({providers,releaseConfig,sources}));
  validateReleaseSigningNetworkObservation({authorized:request?.finalizedAnchor,observed});
  const [requestAfter,configAfter,catalogAfter]=await Promise.all([
    readDirectFile(requestPath,{minimum:requestBytes.length,maximum:requestBytes.length,
      exactMode:0o600,label:'release signing request snapshot'}),
    readDirectFile(configPath,{minimum:configBytes.length,maximum:configBytes.length,
      exactMode:0o600,label:'release configuration snapshot'}),
    readDirectProjectFile(root,'config/mainnet-preflight-rpc-catalog.json',{
      minimum:catalogBytes.length,maximum:catalogBytes.length,exactMode:0o644,
      label:'mainnet preflight RPC catalog'}),
  ]);
  if(!requestAfter.equals(requestBytes)||!configAfter.equals(configBytes)
      ||!catalogAfter.equals(catalogBytes)) throw new Error('release signing inputs changed during observation');
  process.stdout.write('PASS: finalized governance and RPC source identities remain valid for signing\n');
} catch(error) {
  writeReleaseFailure('check-release-signing-network',error);
  process.exitCode=1;
}
