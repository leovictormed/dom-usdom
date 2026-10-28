#!/usr/bin/env node
import {getAddress,isAddress} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateRecoverableSafeRecoveryPlan} from '../sdk/safe-control-recovery-plan.mjs';
const exact=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...k].sort().join(',');
const decimal=v=>typeof v==='string'&&/^(0|[1-9][0-9]*)$/u.test(v)&&BigInt(v)<1n<<256n;
try {
 if(process.argv.length<4||process.argv.length>5)throw new Error('usage: POLICY PLAN [ENVELOPE]');
 const policy=parseStrictJsonBytes(await readDirectFile(process.argv[2],{minimum:2,maximum:65536,exactMode:0o600,privateMode:true,label:'Safe recovery relayer policy'}),{label:'Safe recovery relayer policy'});
 const plan=parseStrictJsonBytes(await readDirectFile(process.argv[3],{minimum:2,maximum:2*1024*1024,exactMode:0o600,label:'Safe recovery plan'}),{label:'Safe recovery plan'});
 validateRecoverableSafeRecoveryPlan(plan);
 if(!exact(policy,['schema','chainId','relayer','maxGasLimit','maxFeePerGas','maxPriorityFeePerGas'])||policy.schema!=='usdom-safe-recovery-relayer-policy/v1'||policy.chainId!=='1'||!isAddress(policy.relayer)||getAddress(policy.relayer)!==policy.relayer||![policy.maxGasLimit,policy.maxFeePerGas,policy.maxPriorityFeePerGas].every(decimal))throw new Error('Safe recovery relayer policy rejected');
 const forbidden=plan.roles.flatMap(role=>[role.safe,...role.requiredSigners]).map(getAddress);
 if(forbidden.includes(policy.relayer))throw new Error('Safe recovery relayer overlaps control authority');
 if(process.argv[4]) {const envelope=parseStrictJsonBytes(await readDirectFile(process.argv[4],{minimum:2,maximum:2*1024*1024,exactMode:0o600,label:'Safe recovery envelope'}),{label:'Safe recovery envelope'});
  if(envelope.relayerOwner!==policy.relayer||BigInt(envelope.gasLimit)>BigInt(policy.maxGasLimit)||BigInt(envelope.maxFeePerGas)>BigInt(policy.maxFeePerGas)||BigInt(envelope.maxPriorityFeePerGas)>BigInt(policy.maxPriorityFeePerGas)||BigInt(envelope.maximumCost)>BigInt(policy.maxGasLimit)*BigInt(policy.maxFeePerGas))throw new Error('Safe recovery envelope exceeds relayer policy');}
 process.stdout.write(`${policy.relayer}\n`);
} catch(error){console.error(error.message);process.exitCode=1;}
