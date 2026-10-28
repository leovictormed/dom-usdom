#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {Transaction,getAddress,keccak256} from 'ethers'; import {readDirectFile} from '../sdk/direct-project-file.mjs'; import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
try {
 if(process.argv.length!==4) throw new Error('usage: check-pilot-deposit-gate-raw RAW TRANSACTION_PACKAGE');
 const [rawBytes,packageBytes]=await Promise.all([readDirectFile(process.argv[2],{minimum:4,maximum:1024*1024,exactMode:0o600}),readDirectFile(process.argv[3],{minimum:2,maximum:8*1024*1024,exactMode:0o600})]);
 const raw=rawBytes.toString('utf8').trim(),value=parseStrictJsonBytes(packageBytes,{label:'pilot gate transaction package'}),tx=Transaction.from(raw);
 if(tx.chainId!==1n||tx.value!==0n||getAddress(tx.to)!==getAddress(value.to)||tx.data.toLowerCase()!==value.data||keccak256(tx.data)!==value.dataHash||!tx.from||!tx.signature) throw new Error('pilot gate raw transaction differs from authorized Safe execution');
 process.stdout.write(JSON.stringify({schema:'usdom-pilot-deposit-gate-raw-validation/v1',transactionHash:tx.hash.toLowerCase(),from:getAddress(tx.from),nonce:String(tx.nonce),to:getAddress(tx.to),dataHash:keccak256(tx.data)})+'\n');
} catch(error) { writeReleaseFailure('check-pilot-deposit-gate-raw',error); process.exitCode=1; }
