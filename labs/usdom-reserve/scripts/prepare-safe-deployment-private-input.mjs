#!/usr/bin/env node
import {getAddress,keccak256,ZeroAddress} from 'ethers';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

try {
  if(process.argv.length!==4||!['governance','reserveGuardian','checkpointGuardian','usdtCustody'].includes(process.argv[2])) {
    throw new Error('role and Safe package path required');
  }
  const role=process.argv[2];
  const packageDocument=parseStrictJsonBytes(await readDirectFile(process.argv[3],{
    minimum:2,maximum:8*1024*1024,exactMode:0o600,label:'private Safe package snapshot',
  }),{label:'private Safe package snapshot',maxBytes:8*1024*1024,maxDepth:32});
  const controls=packageDocument.controls;
  if(!Array.isArray(controls)) throw new Error('Safe controls missing');
  const matches=controls.filter(control=>control?.role===role);
  if(matches.length!==1) throw new Error('Safe role is not unique');
  const {to,data}=matches[0];
  if(!/^0x[0-9a-fA-F]{40}$/.test(to??'')||!/^0x(?:[0-9a-fA-F]{2})+$/.test(data??'')) {
    throw new Error('Safe private transaction input invalid');
  }
  const canonicalTo=getAddress(to),canonicalData=data.toLowerCase();
  if(canonicalTo===ZeroAddress) throw new Error('Safe private transaction target is zero');
  process.stdout.write(`${JSON.stringify({to:canonicalTo,data:canonicalData,dataHash:keccak256(canonicalData),selector:canonicalData.slice(0,10)})}\n`);
} catch(error) {
  writeReleaseFailure('prepare-safe-deployment-private-input',error);
  process.exitCode=1;
}
