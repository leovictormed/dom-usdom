#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {constants} from 'node:fs';
import {open,readFile} from 'node:fs/promises';
try {
  if(process.argv.length!==3) throw new Error('usage: install-public-file-create-once-stdin.mjs TARGET');
  const chunks=[]; for await(const chunk of process.stdin) chunks.push(chunk);
  const contents=Buffer.concat(chunks);
  if(contents.length===0||contents.length>1024*1024) throw new Error('input size is invalid');
  const handle=await open(process.argv[2],constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL
    |constants.O_NOFOLLOW,0o644);
  try { await handle.writeFile(contents); await handle.sync(); }
  finally { await handle.close(); }
  if(!(await readFile(process.argv[2])).equals(contents)) throw new Error('installed file verification failed');
} catch(error) {
  writeReleaseFailure('install-public-file-create-once-stdin',error);
  process.exitCode=1;
}
