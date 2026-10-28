#!/usr/bin/env node
import {Transaction,getAddress} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';

const [file,expected,nonce,to,data]=process.argv.slice(2);
if(process.argv.length!==7) process.exit(64);
if(typeof nonce!=='string'||nonce.length>20||!/^(0|[1-9][0-9]*)$/.test(nonce)
    ||BigInt(nonce)>=(1n<<64n)) process.exit(1);
let expectedAddress,toAddress;
try { expectedAddress=getAddress(expected); toAddress=getAddress(to); }
catch { process.exit(1); }
if(typeof data!=='string'||data.length>2+2*131_072
    ||!/^0x(?:[0-9a-f]{2})*$/.test(data)) process.exit(1);
const rawBytes=await readDirectFile(file,{minimum:3,maximum:256*1024,exactMode:0o600,
  label:'Ledger clear-signing raw transaction'});
const rawText=rawBytes.toString('ascii');
const raw=rawText.trim().toLowerCase();
if(rawText!==`${raw}\n`) process.exit(1);
const tx=Transaction.from(raw);
if(tx.serialized!==raw||tx.signature===null||tx.hash===null||tx.type!==2||tx.chainId!==31337n
    ||BigInt(tx.nonce)!==BigInt(nonce)||tx.to===null||getAddress(tx.to)!==toAddress
    ||tx.from===null||getAddress(tx.from)!==expectedAddress||tx.value!==0n
    ||tx.data!==data||tx.gasLimit!==250000n||tx.maxFeePerGas!==2_000_000_000n
    ||tx.maxPriorityFeePerGas!==1_000_000_000n||tx.accessList.length!==0) process.exit(1);
