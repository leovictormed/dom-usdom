#!/usr/bin/env node
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurableNew} from '../sdk/durable-private-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const MAXIMUM_BYTES=16*1024*1024;

const jsonMode=process.argv.length===4&&process.argv[2]==='--json';
if((!jsonMode&&process.argv.length!==3)||(jsonMode&&process.argv.length!==4)) {
  console.error('Usage: install-private-file-immutable-stdin.mjs [--json] ABSOLUTE_TARGET');
  process.exit(64);
}
const target=process.argv[jsonMode?3:2];
if(typeof target!=='string'||!target.startsWith('/')) {
  throw new Error('immutable private-file target must be absolute');
}
const chunks=[];
let size=0;
for await(const chunk of process.stdin) {
  size+=chunk.length;
  if(size>MAXIMUM_BYTES) throw new Error('immutable private-file input exceeds its size bound');
  chunks.push(chunk);
}
if(size===0) throw new Error('immutable private-file input is empty');
const expected=Buffer.concat(chunks,size);
if(jsonMode) {
  let text;
  try { text=new TextDecoder('utf-8',{fatal:true}).decode(expected); }
  catch { throw new Error('immutable private JSON input is not valid UTF-8'); }
  parseStrictJson(text,{label:'immutable private JSON input',maxBytes:MAXIMUM_BYTES,maxDepth:128});
}
let existing=null;
try {
  existing=await readDirectFile(target,{
    minimum:1,maximum:MAXIMUM_BYTES,exactMode:0o600,label:'immutable private-file target',
  });
} catch(error) {
  if(error?.code!=='ENOENT') throw error;
}
if(existing===null) {
  await writePrivateFileDurableNew(target,expected,{maximum:MAXIMUM_BYTES});
} else if(!existing.equals(expected)) {
  throw new Error('immutable private-file target contains different bytes');
}
const installed=await readDirectFile(target,{
  minimum:expected.length,maximum:expected.length,exactMode:0o600,
  label:'immutable private-file target',
});
if(!installed.equals(expected)) throw new Error('immutable private-file target content mismatch');
