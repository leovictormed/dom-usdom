#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {clearRuntimeSecretJson,readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {buildCheckpointFinalizedEventRpcCatalog} from '../sdk/checkpoint-finalized-event-collector.mjs';
let sources;
try {
  if(process.argv.length!==2) throw new Error('this fixed catalog preparer accepts no arguments');
  sources=readRuntimeSecretJsonFile('USDOM_CHECKPOINT_FINALIZED_RPC_SOURCES',{label:'USDOM_CHECKPOINT_FINALIZED_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  process.stdout.write(`${JSON.stringify(buildCheckpointFinalizedEventRpcCatalog(sources),null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-checkpoint-finalized-event-rpc-catalog',error);
  process.exitCode=1;
} finally {
  clearRuntimeSecretJson(sources);
}
