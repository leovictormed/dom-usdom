#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseSubmissionHashBytes} from '../sdk/deployment-text-evidence.mjs';

try {
  if(process.argv.length!==3||!path.isAbsolute(process.argv[2])) {
    throw new Error('usage: check-deployment-submission-hash.mjs ABSOLUTE_PATH');
  }
  const bytes=await readDirectFile(process.argv[2],{minimum:67,maximum:67,exactMode:0o600,
    label:'deployment submission hash'});
  process.stdout.write(`${parseSubmissionHashBytes(bytes)}\n`);
} catch(error) {
  writeReleaseFailure('check-deployment-submission-hash',error);
  process.exitCode=1;
}
