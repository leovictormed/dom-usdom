#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {validateMainnetDeploymentPackage} from '../sdk/deployment-package.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

let deploymentPackageBytes;
try {
  if(process.argv.length!==4||!path.isAbsolute(process.argv[2])
      ||!/^[0-9a-f]{64}$/.test(process.argv[3])) throw new Error('usage: FILE EXPECTED_SHA256');
  deploymentPackageBytes=await readDirectFile(process.argv[2],{
    minimum:2,maximum:8*1024*1024,exactMode:0o600,label:'reviewed mainnet deployment package',
  });
  if(createHash('sha256').update(deploymentPackageBytes).digest('hex')!==process.argv[3]) {
    throw new Error('reviewed deployment package SHA-256 mismatch');
  }
  validateMainnetDeploymentPackage(parseStrictJsonBytes(deploymentPackageBytes,{
    label:'reviewed mainnet deployment package',maxBytes:8*1024*1024,maxDepth:32,
  }));
} catch(error) {
  writeReleaseFailure('check-mainnet-deployment-package',error);
  process.exitCode=1;
} finally {
  deploymentPackageBytes?.fill(0);
}
