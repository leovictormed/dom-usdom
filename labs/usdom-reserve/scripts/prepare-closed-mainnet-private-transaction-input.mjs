#!/usr/bin/env node
import {getAddress,keccak256,ZeroAddress} from 'ethers';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
try {
  if(process.argv.length!==4||!/^(?:0|1|2)$/.test(process.argv[3])) throw new Error('package path and transaction index required');
  const document=parseStrictJsonBytes(await readDirectFile(process.argv[2],{minimum:2,maximum:8*1024*1024,exactMode:0o600,label:'closed-mainnet package'}),{label:'closed-mainnet package',maxBytes:8*1024*1024,maxDepth:32});
  const transaction=document.transactions?.[Number(process.argv[3])];
  if(!transaction||!/^0x[0-9a-fA-F]{40}$/.test(transaction.to??'')||!/^0x(?:[0-9a-fA-F]{2})+$/.test(transaction.data??''))throw new Error('private transaction input invalid');
  const canonicalTo=getAddress(transaction.to),canonicalData=transaction.data.toLowerCase();
  if(canonicalTo===ZeroAddress)throw new Error('private transaction target is zero');
  const dataHash=keccak256(canonicalData);
  if(transaction.dataKeccak256?.toLowerCase()!==dataHash.toLowerCase())throw new Error('private transaction data hash mismatch');
  process.stdout.write(`${JSON.stringify({to:canonicalTo,data:canonicalData,dataHash,selector:canonicalData.slice(0,10)})}\n`);
}catch(error){writeReleaseFailure('prepare-closed-mainnet-private-transaction-input',error);process.exitCode=1;}
