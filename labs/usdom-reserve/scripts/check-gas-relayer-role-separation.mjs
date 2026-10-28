#!/usr/bin/env node
import {getAddress,isAddress} from 'ethers';import {readDirectFile} from '../sdk/direct-project-file.mjs';import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
try{if(process.argv.length<4)throw new Error('usage: ADDRESS AUTHORITY...');const candidate=getAddress(process.argv[2]),seen=new Set();
 const visit=value=>{if(typeof value==='string'&&isAddress(value)){seen.add(getAddress(value));return;}if(Array.isArray(value)){for(const item of value)visit(item);return;}if(value&&typeof value==='object')for(const item of Object.values(value))visit(item);};
 for(const file of process.argv.slice(3)){const bytes=await readDirectFile(file,{minimum:2,maximum:8*1024*1024,label:'relayer separation authority'});visit(parseStrictJsonBytes(bytes,{label:'relayer separation authority'}));}
 if(seen.has(candidate))throw new Error('gas relayer overlaps an existing relayer, owner, custody or control authority');process.stdout.write(`${candidate}\n`);
}catch(error){console.error(error.message);process.exitCode=1;}
