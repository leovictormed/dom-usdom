#!/usr/bin/env node
import {Transaction,getAddress,isAddress,keccak256} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join('\0')===[...keys].sort().join('\0');
try {
 if(process.argv.length!==7) throw new Error('usage: raw, package, envelope, release, policy');
 const [rawBytes,packageBytes,envelopeBytes,releaseBytes,policyBytes]=await Promise.all(process.argv.slice(2).map((path,index)=>readDirectFile(path,{minimum:2,maximum:index===0?1024*1024:8*1024*1024,exactMode:0o600})));
 const rawFile=rawBytes.toString('utf8'),pkg=parseStrictJsonBytes(packageBytes,{label:'pilot gate package'}),envelope=parseStrictJsonBytes(envelopeBytes,{label:'pilot relayer envelope'}),release=parseStrictJsonBytes(releaseBytes,{label:'reserve release'}),policy=parseStrictJsonBytes(policyBytes,{label:'pilot relayer policy'});
 if(!/^0x(?:[0-9a-f]{2})+\n$/.test(rawFile)) throw new Error('relayer raw is not canonical');
 const raw=rawFile.slice(0,-1);
 if(!exact(policy,['schema','chainId','relayer','maxGasLimit','maxFeePerGas','maxPriorityFeePerGas'])||policy.schema!=='usdom-pilot-gate-relayer-policy/v1'||policy.chainId!=='1') throw new Error('pilot relayer policy is invalid');
 const common=['schema','chainId','relayer','to','value','dataHash','nonce','gasLimit','maxFeePerGas','maxPriorityFeePerGas','maximumGasCost','packageHash','policyHash'];
 const safeEnvelope=envelope.schema==='usdom-pilot-gate-relayer-envelope/v1'&&exact(envelope,[...common,'safeTxHash'])&&envelope.safeTxHash===pkg.safeTxHash;
 const directEnvelope=envelope.schema==='usdom-pilot-direct-relayer-envelope/v1'&&exact(envelope,[...common,'actionHash'])&&envelope.actionHash===keccak256(pkg.data)&&pkg.safeTxHash===undefined;
 if((!safeEnvelope&&!directEnvelope)||envelope.chainId!=='1'||!isAddress(envelope.relayer)||envelope.relayer!==policy.relayer||envelope.policyHash!==keccak256(policyBytes)||BigInt(envelope.gasLimit)>BigInt(policy.maxGasLimit)||BigInt(envelope.maxFeePerGas)>BigInt(policy.maxFeePerGas)||BigInt(envelope.maxPriorityFeePerGas)>BigInt(policy.maxPriorityFeePerGas)) throw new Error('pilot relayer envelope is invalid');
 const forbidden=[release.token,release.reserve,release.governance,release.guardian,...(release.governanceOwners??[]),...(release.guardianOwners??[]),...(release.checkpointGuardianOwners??[])].filter(isAddress).map(getAddress);
 if(forbidden.includes(getAddress(envelope.relayer))) throw new Error('relayer overlaps custody or control authority');
 const tx=Transaction.from(raw);
 if(tx.serialized!==raw||(tx.accessList?.length??0)!==0||tx.type!==2||tx.chainId!==1n||!tx.from||getAddress(tx.from)!==getAddress(envelope.relayer)||!tx.to||getAddress(tx.to)!==getAddress(pkg.to)||getAddress(tx.to)!==getAddress(envelope.to)||tx.value!==0n||tx.data!==pkg.data||keccak256(tx.data)!==envelope.dataHash||String(tx.nonce)!==envelope.nonce||String(tx.gasLimit)!==envelope.gasLimit||String(tx.maxFeePerGas)!==envelope.maxFeePerGas||String(tx.maxPriorityFeePerGas)!==envelope.maxPriorityFeePerGas||envelope.maximumGasCost!==(tx.gasLimit*tx.maxFeePerGas).toString()||envelope.packageHash!==keccak256(packageBytes)||!tx.signature||tx.signature.serialized!==tx.signature.serialized.toLowerCase()) throw new Error('relayer raw differs from the authorized execution envelope');
 process.stdout.write(`${JSON.stringify({schema:'usdom-pilot-gate-relayer-raw-validation/v1',transactionHash:tx.hash.toLowerCase(),from:getAddress(tx.from),nonce:String(tx.nonce),to:getAddress(tx.to),dataHash:keccak256(tx.data),maximumGasCost:(tx.gasLimit*tx.maxFeePerGas).toString()})}\n`);
} catch(error) { writeReleaseFailure('check-pilot-gate-relayer-raw',error);process.exitCode=1; }
