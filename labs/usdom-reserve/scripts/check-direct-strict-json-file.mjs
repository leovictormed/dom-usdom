#!/usr/bin/env node
import path from 'node:path';
import process from 'node:process';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';

let bytes;
try {
  const stdout=process.argv[2]==='--stdout';
  const target=process.argv[stdout?3:2];
  if(process.argv.length!==(stdout?4:3) || !path.isAbsolute(target)) {
    throw new Error('usage: check-direct-strict-json-file.mjs [--stdout] ABSOLUTE_JSON_FILE');
  }
  bytes=await readDirectFile(target,{
    minimum:2,maximum:4*1024*1024,label:'direct JSON authority',
  });
  parseStrictJsonBytes(bytes,{label:'direct JSON authority',maxBytes:4*1024*1024,maxDepth:64});
  if(stdout) await new Promise((resolve,reject)=>process.stdout.write(bytes,error=>error?reject(error):resolve()));
} catch(error) {
  writeReleaseFailure('check-direct-strict-json-file',error);
  process.exitCode=1;
} finally {
  bytes?.fill(0);
}
