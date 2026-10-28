#!/usr/bin/env node
import {readDirectFile} from '../sdk/direct-project-file.mjs';

if(process.argv.length!==4) process.exit(64);
const expected=process.argv[3];
if(!/^0x[0-9a-fA-F]{40}$/.test(expected)) process.exit(65);

let bytes;
try {
  bytes=await readDirectFile(process.argv[2],{
    minimum:42,maximum:43,exactMode:0o600,label:'Ledger address output',
  });
  const text=bytes.toString('ascii');
  const match=/^(0x[0-9a-fA-F]{40})\n?$/.exec(text);
  if(!match||match[1].toLowerCase()!==expected.toLowerCase()) process.exit(1);
} finally {
  bytes?.fill(0);
}
