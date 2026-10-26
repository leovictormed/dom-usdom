#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {collectCheckpointBootstrapRatificationObservation}
  from '../sdk/checkpoint-bootstrap-ratification-collector.mjs';
import {validateCheckpointBootstrapRatificationSigningRequest}
  from '../sdk/checkpoint-bootstrap-ratification-request.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const inputPaths=['config/checkpoint-bootstrap-ratification-rpc-catalog.json',
  'config/mainnet-release-evidence.unconfigured.json','config/proof-reserve.unconfigured.json',
  'evidence/native-preactivation/ethereum-checkpoint-consensus.json',
  'config/native-preactivation-facts.unconfigured.json',
  'evidence/checkpoint-bootstrap/ratification-signing-request.json',
  'evidence/checkpoint-bootstrap/ratification-signing-request.sha256',
  'evidence/checkpoint-bootstrap/ratification-signature.hex',
  'evidence/checkpoint-bootstrap/ratification-signature.sha256'];
const readInputs=()=>Promise.all(inputPaths.map(relative=>readDirectProjectFile(root,relative,
  {minimum:2,maximum:1024*1024,exactMode:relative.startsWith('evidence/checkpoint-bootstrap/')
    ?0o600:undefined,label:relative})));
try {
  if(process.argv.length!==2) throw new Error('this fixed collector accepts no arguments');
  const rpcSources=readRuntimeSecretJsonFile('USDOM_CHECKPOINT_RATIFICATION_RPC_SOURCES',{label:'USDOM_CHECKPOINT_RATIFICATION_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  const inputBytes=await readInputs();
  const [catalog,releaseEvidence,releaseConfig,checkpointConsensus,nativeFacts,request]=inputBytes
    .slice(0,6).map((bytes,index)=>parseStrictJson(bytes.toString('utf8'),{label:inputPaths[index],
      maxBytes:1024*1024,maxDepth:24}));
  const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
  const requestSha=inputBytes[6].toString('ascii').trim();
  const signature=inputBytes[7].toString('ascii').trim();
  const signatureSha=inputBytes[8].toString('ascii').trim();
  if(!/^[0-9a-f]{64}$/.test(requestSha)||requestSha!==sha(inputBytes[5])
      ||!/^[0-9a-f]{64}$/.test(signatureSha)||signatureSha!==sha(inputBytes[7])) {
    throw new Error('ratification request or signature SHA-256 differs from fixed bytes');
  }
  validateCheckpointBootstrapRatificationSigningRequest({request,releaseEvidence,releaseConfig,
    checkpointConsensus,nativeFacts,finalizedAnchor:request.finalizedAnchor,inputDocuments:{
      releaseEvidenceSha256:sha(inputBytes[1]),releaseConfigSha256:sha(inputBytes[2]),
      checkpointConsensusSha256:sha(inputBytes[3]),nativeFactsSha256:sha(inputBytes[4]),
    }});
  const observation=await collectCheckpointBootstrapRatificationObservation({catalog,rpcSources,
    releaseEvidence,releaseConfig,checkpointConsensus,nativeFacts,signature});
  const currentInputBytes=await readInputs();
  if(currentInputBytes.some((bytes,index)=>!bytes.equals(inputBytes[index]))) {
    throw new Error('checkpoint bootstrap ratification inputs changed during collection');
  }
  process.stdout.write(`${JSON.stringify(observation,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('collect-checkpoint-bootstrap-ratification-observation',error);
  process.exitCode=1;
}
