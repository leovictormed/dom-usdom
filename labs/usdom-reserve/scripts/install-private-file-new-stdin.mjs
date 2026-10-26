#!/usr/bin/env node
import {writePrivateFileDurableNew} from '../sdk/durable-private-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const MAXIMUM_BYTES=16*1024*1024;

const jsonMode=process.argv.length===4&&process.argv[2]==='--json';
if((!jsonMode&&process.argv.length!==3)||(jsonMode&&process.argv.length!==4)) {
  console.error('Usage: install-private-file-new-stdin.mjs [--json] ABSOLUTE_TARGET');
  process.exit(64);
}
const target=process.argv[jsonMode?3:2];
if(typeof target!=='string'||!target.startsWith('/')) {
  throw new Error('new private-file target must be absolute');
}
const chunks=[];
let size=0;
for await(const chunk of process.stdin) {
  size+=chunk.length;
  if(size>MAXIMUM_BYTES) throw new Error('new private-file input exceeds its size bound');
  chunks.push(chunk);
}
if(size===0) throw new Error('new private-file input is empty');
const bytes=Buffer.concat(chunks,size);
if(jsonMode) {
  let text;
  try { text=new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
  catch { throw new Error('new private JSON input is not valid UTF-8'); }
  parseStrictJson(text,{label:'new private JSON input',maxBytes:MAXIMUM_BYTES,maxDepth:128});
}
await writePrivateFileDurableNew(target,bytes,{maximum:MAXIMUM_BYTES});
