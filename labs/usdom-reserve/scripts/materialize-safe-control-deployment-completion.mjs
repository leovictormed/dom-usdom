#!/usr/bin/env node
import path from 'node:path';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {buildSafeControlDeploymentCompletion,validateSafeControlDeploymentCompletion}
  from '../sdk/safe-control-deployment-completion.mjs';

async function capture(file,label,raw=false){
  const bytes=await readDirectFile(file,{minimum:2,maximum:4*1024*1024,exactMode:0o600,label});
  return {file,label,bytes,value:raw?null:parseStrictJsonBytes(bytes,{label,maxDepth:64})};
}
try {
  const directory=process.env.USDOM_CONTROL_EVIDENCE_DIRECTORY;
  if(!path.isAbsolute(directory??'')) throw new Error('evidence directory is invalid');
  const pkg=await capture(process.env.USDOM_SAFE_PACKAGE,'Safe package');
  const baseline=await capture(process.env.USDOM_SAFE_BASELINE,'Safe deployment baseline');
  const roles=[];
  for(const role of ['governance','reserveGuardian','checkpointGuardian','usdtCustody']) {
    const [journal,raw,validation,receipt]=await Promise.all([
      capture(path.join(directory,`safe-deployment-${role}-journal.json`),`${role} journal`),
      capture(path.join(directory,`safe-deployment-${role}-raw.txt`),`${role} raw`,true),
      capture(path.join(directory,`safe-deployment-${role}-validation.json`),`${role} validation`),
      capture(path.join(directory,`safe-deployment-${role}-receipt.json`),`${role} receipt`),
    ]);
    roles.push({role,journal:journal.value,journalBytes:journal.bytes,rawBytes:raw.bytes,
      validation:validation.value,validationBytes:validation.bytes,receipt:receipt.value,
      receiptBytes:receipt.bytes,inputs:[journal,raw,validation,receipt]});
  }
  const inputs={packageDocument:pkg.value,packageBytes:pkg.bytes,baseline:baseline.value,
    baselineBytes:baseline.bytes,roles};
  const completion=buildSafeControlDeploymentCompletion(inputs);
  validateSafeControlDeploymentCompletion(completion,inputs);
  for(const input of [pkg,baseline,...roles.flatMap(value=>value.inputs)]) {
    const current=await readDirectFile(input.file,{minimum:input.bytes.length,
      maximum:input.bytes.length,exactMode:0o600,label:input.label});
    if(!current.equals(input.bytes)) throw new Error(`${input.label} changed during completion`);
  }
  process.stdout.write(`${JSON.stringify(completion,null,2)}\n`);
} catch(error) { writeReleaseFailure('materialize-safe-control-deployment-completion',error); process.exitCode=1; }
