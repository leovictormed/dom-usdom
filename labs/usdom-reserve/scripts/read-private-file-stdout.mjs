#!/usr/bin/env node
import {readDirectFile} from '../sdk/direct-project-file.mjs';

const MAXIMUM_BYTES=16*1024*1024;

if(process.argv.length!==3) {
  console.error('Usage: read-private-file-stdout.mjs ABSOLUTE_SOURCE');
  process.exit(64);
}

const source=process.argv[2];
if(typeof source!=='string'||!source.startsWith('/')) {
  throw new Error('private-file source must be absolute');
}
const bytes=await readDirectFile(source,{
  minimum:1,maximum:MAXIMUM_BYTES,privateMode:true,label:'private signing input',
});
await new Promise((resolve,reject)=>{
  process.stdout.write(bytes,error=>error?reject(error):resolve());
});
