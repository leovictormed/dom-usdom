#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readFile} from 'node:fs/promises';
import {Interface,Transaction,getAddress,keccak256} from 'ethers';

const iface=new Interface(['function clearExpiredPilotDepositAuthorization(bytes32 expectedSnapshotCommitment,uint64 expectedGeneration)']);
try {
 if(process.argv.length!==6) throw new Error('usage: check-pilot-deposit-gate-clear-raw RAW RESERVE SNAPSHOT_COMMITMENT GENERATION');
 const raw=(await readFile(process.argv[2],'utf8')).trim(),reserve=getAddress(process.argv[3]);
 const snapshot=process.argv[4].toLowerCase(),generation=process.argv[5];
 if(!/^0x[0-9a-f]{64}$/.test(snapshot)||!/^(0|[1-9][0-9]*)$/.test(generation)) throw new Error('invalid snapshot commitment');
 const tx=Transaction.from(raw),expected=iface.encodeFunctionData('clearExpiredPilotDepositAuthorization',[snapshot,generation]).toLowerCase();
 if(tx.chainId!==1n||getAddress(tx.to)!==reserve||tx.value!==0n||tx.data.toLowerCase()!==expected||tx.from===null) throw new Error('expired pilot gate clear raw transaction mismatch');
 process.stdout.write(JSON.stringify({transactionHash:keccak256(raw),from:getAddress(tx.from),nonce:String(tx.nonce),to:reserve,data:expected},null,2)+'\n');
} catch(error) { writeReleaseFailure('check-pilot-deposit-gate-clear-raw',error); process.exitCode=1; }
