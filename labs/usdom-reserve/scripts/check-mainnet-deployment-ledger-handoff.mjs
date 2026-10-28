#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {validateMainnetDeploymentLedgerHandoff,validateMainnetDeploymentPackage}
  from '../sdk/deployment-package.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

try {
  if(process.argv.length!==4||!path.isAbsolute(process.argv[2])||!(/^[0-3]$/).test(process.argv[3])) {
    throw new Error('usage: HANDOFF_FILE INDEX_0_TO_3');
  }
  const packagePath=process.env.USDOM_MAINNET_DEPLOYMENT_PACKAGE;
  if(typeof packagePath!=='string'||!path.isAbsolute(packagePath)) throw new Error('package path is invalid');
  const [handoffBytes,packageBytes]=await Promise.all([
    readDirectFile(process.argv[2],{minimum:2,maximum:8*1024*1024,exactMode:0o600,
      label:'deployment Ledger handoff'}),
    readDirectFile(packagePath,{minimum:2,maximum:8*1024*1024,exactMode:0o600,
      label:'reviewed mainnet deployment package'}),
  ]);
  const packageSha256=createHash('sha256').update(packageBytes).digest('hex');
  if(packageSha256!==process.env.USDOM_PACKAGE_SHA256) throw new Error('package SHA-256 mismatch');
  const packageValue=validateMainnetDeploymentPackage(parseStrictJsonBytes(packageBytes,{
    label:'reviewed mainnet deployment package',maxBytes:8*1024*1024,maxDepth:32}));
  validateMainnetDeploymentLedgerHandoff({
    handoff:parseStrictJsonBytes(handoffBytes,{label:'deployment Ledger handoff',
      maxBytes:8*1024*1024,maxDepth:32}),packageValue,packageBytes,index:Number(process.argv[3]),
    packageSha256,
  });
} catch(error) {
  writeReleaseFailure('check-mainnet-deployment-ledger-handoff',error);
  process.exitCode=1;
}
