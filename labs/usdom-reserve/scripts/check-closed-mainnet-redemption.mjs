#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {buildClosedMainnetRedemptionPackage,validateClosedMainnetRedemptionPackage,
  validateClosedMainnetRedemptionRawTransaction} from '../sdk/closed-mainnet-redemption-execution.mjs';
import {readPrivateRawTransaction} from '../sdk/private-raw-transaction.mjs';
const [submissionPath,packagePath,index,nonce]=process.argv.slice(2);
const submission=JSON.parse(readFileSync(submissionPath,'utf8'));
if(!packagePath) process.stdout.write(JSON.stringify(buildClosedMainnetRedemptionPackage(submission))+'\n');
else {
  const value=JSON.parse(readFileSync(packagePath,'utf8'));
  validateClosedMainnetRedemptionPackage(value,submission);
  if(index===undefined) process.stdout.write(JSON.stringify(value)+'\n');
  else {
    if(process.env.USDOM_CLOSED_MAINNET_REDEMPTION_RAW!==undefined) throw new Error('raw transaction environment values are forbidden');
    process.stdout.write(JSON.stringify(validateClosedMainnetRedemptionRawTransaction({
      raw:readPrivateRawTransaction(process.env.USDOM_CLOSED_MAINNET_REDEMPTION_RAW_FILE),
      packageValue:value,index:Number(index),nonce,
    }))+'\n');
  }
}
