#!/usr/bin/env node
import {installOneKeyPilotRpcSources} from '../sdk/onekey-pilot-rpc-sources.mjs';
if(process.argv.length!==3){console.error('usage: install-onekey-pilot-rpc-sources.mjs OUTPUT (URLs on stdin)');process.exit(64);}
try {
  const chunks=[];
  let size=0;
  for await(const chunk of process.stdin) {
    size+=chunk.length;
    if(size>16384)throw new Error('RPC input size rejected');
    chunks.push(chunk);
  }
  const bytes=Buffer.concat(chunks,size);
  if(bytes.length<4||bytes.includes(0))throw new Error('RPC input size rejected');
  const lines=bytes.toString('utf8').split('\n');
  if(lines.at(-1)==='')lines.pop();
  if(lines.length!==2||lines.some(line=>line.includes('\r')))throw new Error('exactly two RPC input lines required');
  await installOneKeyPilotRpcSources({urls:lines,outputPath:process.argv[2],timeoutMs:5000});
}catch(error){console.error(error?.message??'RPC source installation failed');process.exit(1);}
