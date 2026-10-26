#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {collectReleaseAuthorizationAnchor,resolveReleaseAuthorizationRpcSources,
  withReleaseAuthorizationProviders} from '../sdk/release-authorization-rpc.mjs';
import {buildCheckpointBootstrapRatificationSigningRequest}
  from '../sdk/checkpoint-bootstrap-ratification-request.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const inputs=['config/mainnet-release-evidence.unconfigured.json',
  'config/proof-reserve.unconfigured.json',
  'evidence/native-preactivation/ethereum-checkpoint-consensus.json',
  'config/native-preactivation-facts.unconfigured.json',
  'config/mainnet-preflight-rpc-catalog.json'];
const publicInputs=new Set([inputs[0],inputs[1],inputs[4]]);
const options=(relative)=>({minimum:2,maximum:4*1024*1024,
  exactMode:publicInputs.has(relative)?0o644:0o600,
  label:relative});
const read=()=>Promise.all(inputs.map(relative=>readDirectProjectFile(root,relative,options(relative))));
const parse=(bytes,label)=>parseStrictJson(bytes.toString('utf8'),{label,maxBytes:4*1024*1024,maxDepth:64});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');

try {
  if(process.argv.length!==2) throw new Error('this command accepts no arguments');
  const bytes=await read();
  const [releaseEvidence,releaseConfig,checkpointConsensus,nativeFacts,catalog]=bytes.map(
    (value,index)=>parse(value,inputs[index]));
  const runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  const sources=resolveReleaseAuthorizationRpcSources({catalog,runtimeSources});
  const finalizedAnchor=await withReleaseAuthorizationProviders(sources,providers=>
    collectReleaseAuthorizationAnchor({providers,releaseConfig,sources}));
  const request=buildCheckpointBootstrapRatificationSigningRequest({releaseEvidence,releaseConfig,
    checkpointConsensus,nativeFacts,finalizedAnchor,inputDocuments:{
      releaseEvidenceSha256:sha(bytes[0]),releaseConfigSha256:sha(bytes[1]),
      checkpointConsensusSha256:sha(bytes[2]),nativeFactsSha256:sha(bytes[3]),
    }});
  const after=await read();
  if(after.some((value,index)=>!value.equals(bytes[index]))) {
    throw new Error('ratification request inputs changed during preparation');
  }
  process.stdout.write(`${JSON.stringify(request,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-checkpoint-bootstrap-ratification-request',error);
  process.exitCode=1;
}
