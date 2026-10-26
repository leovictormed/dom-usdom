#!/usr/bin/env node
import {writePrivateFileDurable} from '../sdk/durable-private-file.mjs';

const MAXIMUM_BYTES=1024*1024;

if(process.argv.length!==3) {
  console.error('Usage: install-private-file-stdin.mjs ABSOLUTE_TARGET');
  process.exit(64);
}

const target=process.argv[2];
if(typeof target!=='string'||!target.startsWith('/')) {
  throw new Error('private-file target must be absolute');
}

const chunks=[];
let size=0;
for await(const chunk of process.stdin) {
  size+=chunk.length;
  if(size>MAXIMUM_BYTES) throw new Error('private-file input exceeds its size bound');
  chunks.push(chunk);
}
if(size===0) throw new Error('private-file input is empty');
await writePrivateFileDurable(target,Buffer.concat(chunks,size),{maximum:MAXIMUM_BYTES});
