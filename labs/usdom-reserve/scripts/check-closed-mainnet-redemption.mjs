#!/usr/bin/env node
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {buildClosedMainnetRedemptionPackage,validateClosedMainnetRedemptionPackage,
  validateClosedMainnetRedemptionRawTransaction} from '../sdk/closed-mainnet-redemption-execution.mjs';
import {readPrivateRawTransaction} from '../sdk/private-raw-transaction.mjs';
const read=async(path,label)=>parseStrictJsonBytes(await readDirectFile(path,{
  minimum:2,maximum:4*1024*1024,label,
}),{label,maxBytes:4*1024*1024,maxDepth:64,maxNodes:100_000,maxStringBytes:4*1024*1024,
  maxObjectEntries:10_000,maxArrayEntries:10_000});
try {
  if(![3,4,6].includes(process.argv.length)) {
    throw new Error('usage: check-closed-mainnet-redemption.mjs SUBMISSION [PACKAGE [INDEX NONCE]]');
  }
  const [submissionPath,packagePath,index,nonce]=process.argv.slice(2);
  const submission=await read(submissionPath,'finalized burn submission');
  if(!packagePath) process.stdout.write(JSON.stringify(buildClosedMainnetRedemptionPackage(submission))+'\n');
  else {
    const value=await read(packagePath,'closed mainnet redemption package');
    validateClosedMainnetRedemptionPackage(value,submission);
    if(index===undefined) process.stdout.write(JSON.stringify(value)+'\n');
    else {
      if(process.env.USDOM_CLOSED_MAINNET_REDEMPTION_RAW!==undefined) throw new Error('raw transaction environment values are forbidden');
      process.stdout.write(JSON.stringify(validateClosedMainnetRedemptionRawTransaction({
        raw:readPrivateRawTransaction(process.env.USDOM_CLOSED_MAINNET_REDEMPTION_RAW_FILE),
        packageValue:value,submission,index:Number(index),nonce,
      }))+'\n');
    }
  }
} catch(error) {
  writePilotFailure('check-closed-mainnet-redemption',error);
  process.exitCode=1;
}
