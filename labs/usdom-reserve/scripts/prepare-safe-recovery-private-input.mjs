#!/usr/bin/env node
import {getAddress,keccak256,ZeroAddress} from 'ethers';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

try {
  if(process.argv.length!==4||!['governance','reserveGuardian','checkpointGuardian'].includes(process.argv[2])) {
    throw new Error('role and recovery transactions path required');
  }
  const role=process.argv[2];
  const document=parseStrictJsonBytes(await readDirectFile(process.argv[3],{
    minimum:2,maximum:8*1024*1024,exactMode:0o600,label:'private Safe recovery transactions',
  }),{label:'private Safe recovery transactions',maxBytes:8*1024*1024,maxDepth:32});
  if(!Array.isArray(document.transactions)) throw new Error('recovery transactions missing');
  const matches=document.transactions.filter(transaction=>transaction?.role===role);
  if(matches.length!==1) throw new Error('recovery role is not unique');
  const {to,data,value,dataHash}=matches[0];
  if(!/^0x[0-9a-fA-F]{40}$/.test(to??'')||!/^0x(?:[0-9a-fA-F]{2})+$/.test(data??'')
    ||value!=='0'||dataHash?.toLowerCase()!==keccak256(data).toLowerCase()) {
    throw new Error('Safe recovery private transaction input invalid');
  }
  const canonicalTo=getAddress(to),canonicalData=data.toLowerCase();
  if(canonicalTo===ZeroAddress) throw new Error('Safe recovery transaction target is zero');
  process.stdout.write(`${JSON.stringify({to:canonicalTo,data:canonicalData,value,dataHash:keccak256(canonicalData),selector:canonicalData.slice(0,10)})}\n`);
} catch(error) {
  writeReleaseFailure('prepare-safe-recovery-private-input',error);
  process.exitCode=1;
}
