#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {MAINNET_DEPLOYMENT_MAX_SEQUENCE_COST,MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST}
  from '../sdk/mainnet-deployment-execution.mjs';

try {
  if(process.argv.length!==4||!/^[0-3]$/.test(process.argv[2])
      ||!/^(0|[1-9][0-9]*)$/.test(process.argv[3])) throw new Error('index and current maximum cost required');
  const index=Number(process.argv[2]),directory=process.env.USDOM_CONTROL_EVIDENCE_DIRECTORY;
  if(typeof directory!=='string'||!path.isAbsolute(directory)) throw new Error('evidence directory required');
  const current=BigInt(process.argv[3]);
  if(current===0n||current>MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST) throw new Error('current cost exceeds cap');
  let cumulative=current;
  for(let prior=0;prior<index;prior++){
    const bytes=await readDirectFile(path.join(directory,`contract-deployment-${prior}-raw-validation.json`),
      {minimum:1,maximum:64*1024,exactMode:0o600,label:`prior deployment ${prior} validation`});
    const value=parseStrictJson(bytes.toString('utf8'),{label:`prior deployment ${prior} validation`,maxDepth:8});
    if(value.schema!=='usdom-mainnet-deployment-raw-validation-v1'||value.index!==String(prior)
        ||!/^(0|[1-9][0-9]*)$/.test(value.maximumCost??'')) throw new Error('prior cost evidence invalid');
    const cost=BigInt(value.maximumCost);
    if(cost===0n||cost>MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST) throw new Error('prior cost exceeds cap');
    cumulative+=cost;
  }
  if(cumulative>MAINNET_DEPLOYMENT_MAX_SEQUENCE_COST) throw new Error('deployment sequence exceeds 1 ETH cap');
  process.stdout.write(`${cumulative}\n`);
} catch(error){
  writeReleaseFailure('check-mainnet-deployment-sequence-cost',error);
  process.exitCode=1;
}
