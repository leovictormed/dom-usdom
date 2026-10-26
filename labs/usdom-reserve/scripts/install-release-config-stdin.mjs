#!/usr/bin/env node
import {writeFileDurable} from '../sdk/durable-private-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const MAXIMUM_BYTES=16*1024*1024;

if(process.argv.length!==3) {
  console.error('Usage: install-release-config-stdin.mjs ABSOLUTE_TARGET');
  process.exit(64);
}

const target=process.argv[2];
if(typeof target!=='string'||!target.startsWith('/')) {
  throw new Error('release-config target must be absolute');
}

const chunks=[];
let size=0;
for await(const chunk of process.stdin) {
  size+=chunk.length;
  if(size>MAXIMUM_BYTES) throw new Error('release-config input exceeds its size bound');
  chunks.push(chunk);
}
if(size===0) throw new Error('release-config input is empty');
const bytes=Buffer.concat(chunks,size);
const text=bytes.toString('utf8');
if(!Buffer.from(text,'utf8').equals(bytes)) {
  throw new Error('release-config input is not exact UTF-8');
}
parseStrictJson(text,{label:'release-config input',maxBytes:MAXIMUM_BYTES,maxDepth:128});
await writeFileDurable(target,bytes,{maximum:MAXIMUM_BYTES,mode:0o644});
