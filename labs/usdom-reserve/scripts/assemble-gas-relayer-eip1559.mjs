#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {assembleOneKeyEip1559Transaction} from '../sdk/onekey-eip1559-transaction.mjs';

if(process.argv.length!==3){process.stderr.write('usage: assemble-gas-relayer-eip1559.mjs PREPARED\n');process.exit(64);}
const prepared=parseStrictJsonBytes(await readDirectFile(process.argv[2],{minimum:2,maximum:9*1024*1024,
 exactMode:0o600,label:'gas relayer prepared transaction'}),{label:'gas relayer prepared transaction'});
const signature=readFileSync(0,'utf8').trim();
process.stdout.write(`${assembleOneKeyEip1559Transaction(prepared,signature)}\n`);
