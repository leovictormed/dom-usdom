#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const paths=['config/mainnet-release-evidence.unconfigured.json','config/proof-reserve.unconfigured.json',
  'evidence/checkpoint-submission/checkpoint-submission.json'];
const read=()=>Promise.all(paths.map(relative=>readDirectProjectFile(root,relative,{
  minimum:2,maximum:4*1024*1024,label:relative})));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
try {
  if(process.argv.length!==2) throw new Error('this command accepts no arguments');
  const transactionHash=process.env.USDOM_CHECKPOINT_FINALIZED_TRANSACTION_HASH;
  if(!/^0x[0-9a-fA-F]{64}$/.test(transactionHash??'')||BigInt(transactionHash)===0n) {
    throw new Error('finalized checkpoint transaction hash must be nonzero bytes32');
  }
  const bytes=await read();
  const [releaseEvidence,releaseConfig,submission]=bytes.map((value,index)=>
    parseStrictJsonBytes(value,{label:paths[index],maxBytes:4*1024*1024,maxDepth:64}));
  if(releaseConfig.ethereumChainId!=='1'||submission.ethereumChainId!=='1'
      ||String(submission.registry).toLowerCase()!==String(releaseConfig.checkpointRegistry).toLowerCase()
      ||submission.checkpointConfigHash!==releaseConfig.checkpointRegistryConfigHash) {
    throw new Error('checkpoint submission differs from the production release');
  }
  const reference={schema:'usdom-checkpoint-finalized-transaction-reference-v1',
    releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
    ethereumChainId:'1',checkpointRegistry:releaseConfig.checkpointRegistry,
    checkpointRegistryConfigHash:releaseConfig.checkpointRegistryConfigHash,
    submissionDocumentSha256:sha(bytes[2]),transactionHash:transactionHash.toLowerCase()};
  const after=await read();
  if(after.some((value,index)=>!value.equals(bytes[index]))) {
    throw new Error('checkpoint transaction-reference inputs changed during preparation');
  }
  process.stdout.write(`${JSON.stringify(reference,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-checkpoint-finalized-transaction-reference',error);
  process.exitCode=1;
}
