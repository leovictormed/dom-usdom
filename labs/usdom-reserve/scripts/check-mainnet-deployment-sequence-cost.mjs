#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {validateDeploymentRawEvidence} from '../sdk/deployment-evidence.mjs';
import {MAINNET_DEPLOYMENT_MAX_SEQUENCE_COST,MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST}
  from '../sdk/mainnet-deployment-execution.mjs';

function boundedCost(value,label) {
  if(typeof value!=='string'||value.length>MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST.toString().length
      ||!/^(0|[1-9][0-9]*)$/.test(value)) throw new Error(`${label} is invalid`);
  const parsed=BigInt(value);
  if(parsed===0n||parsed>MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST) {
    throw new Error(`${label} exceeds cap`);
  }
  return parsed;
}

try {
  if(process.argv.length!==4||!/^[0-3]$/.test(process.argv[2])) {
    throw new Error('index and current maximum cost required');
  }
  const index=Number(process.argv[2]),directory=process.env.USDOM_CONTROL_EVIDENCE_DIRECTORY;
  if(typeof directory!=='string'||!path.isAbsolute(directory)) throw new Error('evidence directory required');
  const current=boundedCost(process.argv[3],'current cost');
  let cumulative=current;
  for(let prior=0;prior<index;prior++){
    const bytes=await readDirectFile(path.join(directory,`contract-deployment-${prior}-raw-validation.json`),
      {minimum:1,maximum:64*1024,exactMode:0o600,label:`prior deployment ${prior} validation`});
    const value=parseStrictJson(bytes.toString('utf8'),{label:`prior deployment ${prior} validation`,maxDepth:8});
    validateDeploymentRawEvidence(value);
    if(value.index!==String(prior)) {
      throw new Error('prior cost evidence invalid');
    }
    const cost=boundedCost(value.maximumCost,'prior cost');
    cumulative+=cost;
  }
  if(cumulative>MAINNET_DEPLOYMENT_MAX_SEQUENCE_COST) throw new Error('deployment sequence exceeds 1 ETH cap');
  process.stdout.write(`${cumulative}\n`);
} catch(error){
  writeReleaseFailure('check-mainnet-deployment-sequence-cost',error);
  process.exitCode=1;
}
