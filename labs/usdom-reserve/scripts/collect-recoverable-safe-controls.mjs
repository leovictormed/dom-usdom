#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {matchMainnetPreflightRpcSources} from '../sdk/mainnet-preflight-rpc.mjs';
import {collectRecoverableSafeControlSnapshotConsensus}
  from '../sdk/safe-control-rpc-consensus.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const catalogPath='config/mainnet-preflight-rpc-catalog.json';
let runtimeSources=[];

try {
  const packagePath=process.env.USDOM_SAFE_PACKAGE;
  if(typeof packagePath!=='string'||packagePath.length===0) {
    throw new Error('USDOM_SAFE_PACKAGE is required');
  }
  const packageBytes=await readDirectFile(packagePath,{
    minimum:1,maximum:1024*1024,label:'recoverable Safe package',
  });
  const packageDocument=parseStrictJson(packageBytes.toString('utf8'),{
    label:'recoverable Safe package',maxBytes:1024*1024,maxDepth:16,
  });
  const catalogBytes=await readDirectProjectFile(root,catalogPath,{
    minimum:1,maximum:1024*1024,label:catalogPath,
  });
  const catalog=parseStrictJson(catalogBytes.toString('utf8'),{label:catalogPath,maxDepth:16});
  runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  const sources=matchMainnetPreflightRpcSources(catalog,runtimeSources);
  const result=await collectRecoverableSafeControlSnapshotConsensus({packageDocument,sources});
  const [packageAfter,catalogAfter]=await Promise.all([
    readDirectFile(packagePath,{minimum:1,maximum:1024*1024,label:'recoverable Safe package'}),
    readDirectProjectFile(root,catalogPath,{minimum:1,maximum:1024*1024,label:catalogPath}),
  ]);
  if(!packageAfter.equals(packageBytes)||!catalogAfter.equals(catalogBytes)) {
    throw new Error('recoverable Safe collector inputs changed during collection');
  }
  process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('collect-recoverable-safe-controls',error);
  process.exitCode=1;
}
