#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import process from 'node:process';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

let privateJsonBytes;
try {
  if(process.argv.length!==3 || !path.isAbsolute(process.argv[2])) {
    throw new Error('usage: check-private-strict-json-file.mjs ABSOLUTE_PRIVATE_JSON_FILE');
  }
  privateJsonBytes=await readDirectFile(process.argv[2],{
    minimum:2,maximum:4*1024*1024,exactMode:0o600,label:'private JSON authority',
  });
  parseStrictJsonBytes(privateJsonBytes,{label:'private JSON authority',maxBytes:4*1024*1024,maxDepth:64});
} catch(error) {
  writeReleaseFailure('check-private-strict-json-file',error);
  process.exitCode=1;
} finally {
  privateJsonBytes?.fill(0);
}
