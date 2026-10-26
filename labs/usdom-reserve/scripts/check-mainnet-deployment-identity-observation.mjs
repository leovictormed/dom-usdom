#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {validateMainnetDeploymentIdentityObservation} from '../sdk/mainnet-deployment-identity.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

try {
  if(process.argv.length!==4||!path.isAbsolute(process.argv[2])
      ||!/^[0-9a-f]{64}$/.test(process.argv[3])) throw new Error('usage: FILE EXPECTED_SHA256');
  const bytes=await readDirectFile(process.argv[2],{
    minimum:2,maximum:4*1024*1024,exactMode:0o600,label:'deployment identity observation',
  });
  if(createHash('sha256').update(bytes).digest('hex')!==process.argv[3]) {
    throw new Error('deployment identity observation SHA-256 mismatch');
  }
  validateMainnetDeploymentIdentityObservation({observation:parseStrictJsonBytes(bytes,{
    label:'deployment identity observation',maxBytes:4*1024*1024,maxDepth:64,
  })});
} catch(error) {
  writeReleaseFailure('check-mainnet-deployment-identity-observation',error);
  process.exitCode=1;
}
