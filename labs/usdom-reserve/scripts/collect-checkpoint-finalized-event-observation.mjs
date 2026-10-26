#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {collectCheckpointFinalizedEventObservation} from '../sdk/checkpoint-finalized-event-collector.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const inputPaths=['config/checkpoint-finalized-event-rpc-catalog.json',
  'config/mainnet-release-evidence.unconfigured.json','config/proof-reserve.unconfigured.json',
  'evidence/checkpoint-submission/checkpoint-submission.json',
  'evidence/checkpoint-finalized-event/transaction-reference.json',
  'evidence/checkpoint-finalized-event/transaction-reference.sha256'];
const readInputs=()=>Promise.all(inputPaths.map(relative=>readDirectProjectFile(root,relative,
  {minimum:2,maximum:4*1024*1024,exactMode:relative.startsWith('evidence/checkpoint-finalized-event/')
    ?0o600:undefined,label:relative})));
try {
  if(process.argv.length!==2) throw new Error('this fixed collector accepts no arguments');
  const rpcSources=readRuntimeSecretJsonFile('USDOM_CHECKPOINT_FINALIZED_RPC_SOURCES',{label:'USDOM_CHECKPOINT_FINALIZED_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  const inputBytes=await readInputs();
  const [catalog,releaseEvidence,releaseConfig,submission,reference]=inputBytes.slice(0,5).map((bytes,index)=>
    parseStrictJsonBytes(bytes,{label:inputPaths[index],maxBytes:1024*1024,maxDepth:24}));
  const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
  const referenceSha=inputBytes[5].toString('ascii').trim();
  const expected={schema:'usdom-checkpoint-finalized-transaction-reference-v1',
    releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
    ethereumChainId:'1',checkpointRegistry:releaseConfig.checkpointRegistry,
    checkpointRegistryConfigHash:releaseConfig.checkpointRegistryConfigHash,
    submissionDocumentSha256:sha(inputBytes[3]),transactionHash:reference.transactionHash};
  if(!/^[0-9a-f]{64}$/.test(referenceSha)||referenceSha!==sha(inputBytes[4])
      ||JSON.stringify(reference)!==JSON.stringify(expected)
      ||submission.ethereumChainId!=='1'
      ||String(submission.registry).toLowerCase()!==String(releaseConfig.checkpointRegistry).toLowerCase()
      ||submission.checkpointConfigHash!==releaseConfig.checkpointRegistryConfigHash) {
    throw new Error('checkpoint transaction reference differs from authenticated submission or release');
  }
  const transactionHash=reference.transactionHash;
  const observation=await collectCheckpointFinalizedEventObservation({catalog,rpcSources,
    transactionHash,releaseEvidence,releaseConfig});
  const currentInputBytes=await readInputs();
  if(currentInputBytes.some((bytes,index)=>!bytes.equals(inputBytes[index]))) {
    throw new Error('checkpoint finalized-event inputs changed during collection');
  }
  process.stdout.write(`${JSON.stringify(observation,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('collect-checkpoint-finalized-event-observation',error);
  process.exitCode=1;
}
