#!/usr/bin/env node
import {Transaction,getAddress} from 'ethers';
import {readFileSync} from 'node:fs';

const [file,expected,nonce,to,data]=process.argv.slice(2);
if(process.argv.length!==7) process.exit(64);
const raw=readFileSync(file,'ascii').trim().toLowerCase();
const tx=Transaction.from(raw);
if(tx.serialized!==raw||tx.signature===null||tx.hash===null||tx.type!==2||tx.chainId!==31337n
    ||BigInt(tx.nonce)!==BigInt(nonce)||tx.to===null||getAddress(tx.to)!==getAddress(to)
    ||tx.from===null||getAddress(tx.from)!==getAddress(expected)||tx.value!==0n
    ||tx.data!==data.toLowerCase()||tx.gasLimit!==250000n||tx.maxFeePerGas!==2_000_000_000n
    ||tx.maxPriorityFeePerGas!==1_000_000_000n||tx.accessList.length!==0) process.exit(1);
