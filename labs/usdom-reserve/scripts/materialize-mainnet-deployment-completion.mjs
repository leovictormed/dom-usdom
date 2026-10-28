#!/usr/bin/env node
import path from 'node:path';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {buildMainnetDeploymentCompletion,validateMainnetDeploymentCompletion}
  from '../sdk/mainnet-deployment-completion.mjs';

async function capture(file,label,json=true){
  const bytes=await readDirectFile(file,{minimum:2,maximum:4*1024*1024,exactMode:0o600,label});
  return {file,label,bytes,value:json?parseStrictJsonBytes(bytes,{label,maxDepth:32}):null};
}
try {
  const directory=process.env.USDOM_CONTROL_EVIDENCE_DIRECTORY;
  if(!path.isAbsolute(directory??'')) throw new Error('evidence directory is invalid');
  const pkg=await capture(process.env.USDOM_MAINNET_DEPLOYMENT_PACKAGE,'deployment package');
  const stages=[];
  for(let index=0;index<4;index++){
    const prefix=path.join(directory,`contract-deployment-${index}`);
    const [rawTransaction,raw,receipt,completion,anchor]=await Promise.all([
      capture(`${prefix}-raw-transaction.txt`,`deployment ${index} raw transaction`,false),
      capture(`${prefix}-raw-validation.json`,`deployment ${index} raw validation`),
      capture(`${prefix}-receipt.json`,`deployment ${index} receipt`),
      capture(`${prefix}-evidence.json`,`deployment ${index} evidence`),
      capture(`${prefix}-finalized-anchor.json`,`deployment ${index} finalized anchor`),
    ]);
    stages.push({raw:raw.value,receipt:receipt.value,completion:completion.value,anchor:anchor.value,
      rawTransactionBytes:rawTransaction.bytes,rawBytes:raw.bytes,receiptBytes:receipt.bytes,
      completionBytes:completion.bytes,anchorBytes:anchor.bytes,
      inputs:[rawTransaction,raw,receipt,completion,anchor]});
  }
  const inputs={packageValue:pkg.value,packageBytes:pkg.bytes,stages};
  const value=buildMainnetDeploymentCompletion(inputs);
  validateMainnetDeploymentCompletion(value,inputs);
  for(const input of [pkg,...stages.flatMap(stage=>stage.inputs)]){
    const current=await readDirectFile(input.file,{minimum:input.bytes.length,
      maximum:input.bytes.length,exactMode:0o600,label:input.label});
    if(!current.equals(input.bytes)) throw new Error(`${input.label} changed during completion`);
  }
  process.stdout.write(`${JSON.stringify(value,null,2)}\n`);
} catch(error){ writeReleaseFailure('materialize-mainnet-deployment-completion',error); process.exitCode=1; }
