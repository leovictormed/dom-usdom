#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {projectDeploymentReceipt} from '../sdk/deployment-evidence.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

try {
  if(process.argv.length!==3||!path.isAbsolute(process.argv[2])) {
    throw new Error('usage: project-deployment-receipt.mjs ABSOLUTE_PATH');
  }
  const bytes=await readDirectFile(process.argv[2],{minimum:2,maximum:1024*1024,exactMode:0o600,
    label:'RPC deployment receipt'});
  const receipt=projectDeploymentReceipt(parseStrictJsonBytes(bytes,
    {label:'RPC deployment receipt',maxDepth:16}));
  process.stdout.write(`${JSON.stringify(receipt,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('project-deployment-receipt',error);
  process.exitCode=1;
}
