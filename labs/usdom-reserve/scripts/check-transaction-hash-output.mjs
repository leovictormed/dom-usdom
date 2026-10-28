#!/usr/bin/env node
import {readDirectFile} from '../sdk/direct-project-file.mjs';

if(process.argv.length!==4) process.exit(64);
const expected=process.argv[3];
if(!/^0x[0-9a-fA-F]{64}$/.test(expected)) process.exit(65);

let bytes;
try {
  bytes=await readDirectFile(process.argv[2],{
    minimum:66,maximum:67,exactMode:0o600,label:'transaction hash output',
  });
  const match=/^(0x[0-9a-fA-F]{64})\n?$/.exec(bytes.toString('ascii'));
  if(!match||match[1].toLowerCase()!==expected.toLowerCase()) process.exit(1);
} finally {
  bytes?.fill(0);
}
