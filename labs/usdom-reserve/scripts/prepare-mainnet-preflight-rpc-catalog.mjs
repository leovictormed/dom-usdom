#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {clearRuntimeSecretJson,readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {buildMainnetPreflightRpcCatalog} from '../sdk/mainnet-preflight-rpc.mjs';
let sources;
try {
  if(process.argv.length!==2) throw new Error('this fixed catalog preparer accepts no arguments');
  sources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  process.stdout.write(`${JSON.stringify(buildMainnetPreflightRpcCatalog(sources),null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-mainnet-preflight-rpc-catalog',error);
  process.exitCode=1;
} finally {
  clearRuntimeSecretJson(sources);
}
