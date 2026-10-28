#!/usr/bin/env node
import {keccak256} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {planMainnetDeploymentGas} from '../sdk/mainnet-deployment-execution.mjs';
import {prepareOneKeyEip1559CreateTransaction} from '../sdk/onekey-eip1559-transaction.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
try {
  const [mode,file,...args]=process.argv.slice(2);
  if(!['estimate','plan','hash','prepare'].includes(mode)||typeof file!=='string') throw new Error('private CREATE mode and file required');
  const bytes=await readDirectFile(file,{minimum:2,maximum:8*1024*1024,exactMode:0o600,label:'private CREATE handoff'});
  const handoff=parseStrictJsonBytes(bytes,{label:'private CREATE handoff',maxBytes:8*1024*1024,maxDepth:32});
  const transaction=handoff?.transaction;
  if(!transaction||typeof transaction.data!=='string'||!/^0x(?:[0-9a-fA-F]{2})+$/.test(transaction.data)
    ||typeof transaction.from!=='string') throw new Error('private CREATE handoff invalid');
  if(mode==='estimate') {
    if(args.length!==0) throw new Error('estimate takes no extra arguments');
    process.stdout.write(`${JSON.stringify([{from:transaction.from,data:transaction.data},'finalized'])}\n`);
  } else if(mode==='plan') {
    if(args.length!==1) throw new Error('plan maximum estimate required');
    process.stdout.write(`${planMainnetDeploymentGas({name:transaction.name,data:transaction.data,maximumEstimate:args[0]})}\n`);
  } else if(mode==='hash') {
    if(args.length!==0) throw new Error('hash takes no extra arguments');
    process.stdout.write(`${keccak256(transaction.data)}\n`);
  } else {
    if(args.length!==4) throw new Error('prepare nonce, gas, fee and priority required');
    process.stdout.write(`${JSON.stringify(prepareOneKeyEip1559CreateTransaction({from:transaction.from,
      data:transaction.data,nonce:args[0],gasLimit:args[1],maxFeePerGas:args[2],maxPriorityFeePerGas:args[3],
      expectedContract:transaction.expectedContract}))}\n`);
  }
} catch(error) { writeReleaseFailure('prepare-private-mainnet-create',error);process.exitCode=1; }
