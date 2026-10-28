#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {writeFileDurable} from '../sdk/durable-private-file.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
try {
  if(process.argv.length!==3) throw new Error('usage: install-public-file-create-once-stdin.mjs TARGET');
  const chunks=[]; for await(const chunk of process.stdin) chunks.push(chunk);
  const contents=Buffer.concat(chunks);
  if(contents.length===0||contents.length>1024*1024) throw new Error('input size is invalid');
  await writeFileDurable(process.argv[2],contents,{maximum:1024*1024,mode:0o644,replace:false});
  const installed=await readDirectFile(process.argv[2],{
    minimum:contents.length,maximum:contents.length,exactMode:0o644,label:'public create-once target',
  });
  if(!installed.equals(contents)) throw new Error('installed file verification failed');
} catch(error) {
  writeReleaseFailure('install-public-file-create-once-stdin',error);
  process.exitCode=1;
}
