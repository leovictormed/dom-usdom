#!/usr/bin/env node
import {getAddress,isAddress,keccak256} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';

const decimal=/^(0|[1-9][0-9]*)$/;
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join('\0')===[...keys].sort().join('\0');
const canonical=value=>typeof value==='string'&&decimal.test(value)&&BigInt(value)<(1n<<256n);
try {
 if(process.argv.length!==9) throw new Error('usage: private input, package, policy, nonce, gas, max fee, priority fee');
 const [inputBytes,packageBytes,policyBytes]=await Promise.all(process.argv.slice(2,5).map(path=>readDirectFile(path,{minimum:2,maximum:8*1024*1024,exactMode:0o600})));
 const input=parseStrictJsonBytes(inputBytes,{label:'private relayer input'}),pkg=parseStrictJsonBytes(packageBytes,{label:'pilot gate package'}),policy=parseStrictJsonBytes(policyBytes,{label:'pilot relayer policy'});
 if(!exact(policy,['schema','chainId','relayer','maxGasLimit','maxFeePerGas','maxPriorityFeePerGas'])||policy.schema!=='usdom-pilot-gate-relayer-policy/v1'||policy.chainId!=='1'||!isAddress(policy.relayer)||getAddress(policy.relayer)!==policy.relayer||![policy.maxGasLimit,policy.maxFeePerGas,policy.maxPriorityFeePerGas].every(canonical)) throw new Error('pilot relayer policy is invalid');
 if(!exact(input,['to','data'])||input.to!==pkg.to||input.data!==pkg.data) throw new Error('private relayer input differs from Safe package');
 const [nonce,gasLimit,maxFeePerGas,maxPriorityFeePerGas]=process.argv.slice(5);
 if(![nonce,gasLimit,maxFeePerGas,maxPriorityFeePerGas].every(canonical)||BigInt(gasLimit)>BigInt(policy.maxGasLimit)||BigInt(maxFeePerGas)>BigInt(policy.maxFeePerGas)||BigInt(maxPriorityFeePerGas)>BigInt(policy.maxPriorityFeePerGas)||BigInt(maxPriorityFeePerGas)>BigInt(maxFeePerGas)) throw new Error('relayer transaction exceeds policy');
 const common={chainId:'1',relayer:policy.relayer,to:getAddress(input.to),value:'0',dataHash:keccak256(input.data),nonce,gasLimit,maxFeePerGas,maxPriorityFeePerGas,maximumGasCost:(BigInt(gasLimit)*BigInt(maxFeePerGas)).toString(),packageHash:keccak256(packageBytes),policyHash:keccak256(policyBytes)};
 const envelope=typeof pkg.safeTxHash==='string'
  ?{schema:'usdom-pilot-gate-relayer-envelope/v1',...common,safeTxHash:pkg.safeTxHash}
  :{schema:'usdom-pilot-direct-relayer-envelope/v1',...common,actionHash:keccak256(input.data)};
 process.stdout.write(`${JSON.stringify(envelope)}\n`);
} catch(error) { writeReleaseFailure('prepare-pilot-gate-relayer-envelope',error);process.exitCode=1; }
