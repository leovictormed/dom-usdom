#!/usr/bin/env node
import {createHash} from 'node:crypto';
import {getAddress,keccak256,Transaction} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

const dec=v=>typeof v==='string'&&/^(0|[1-9][0-9]*)$/u.test(v)&&BigInt(v)<1n<<256n;
const sha=b=>createHash('sha256').update(b).digest('hex');
const read=async(p,label,max=8*1024*1024)=>{const bytes=await readDirectFile(p,{minimum:2,maximum:max,exactMode:0o600,label});return {bytes,value:parseStrictJsonBytes(bytes,{label})};};
try {
 if(process.argv.length!==6)throw new Error('usage: ENVELOPE INPUT POLICY KEYSTORE');
 const [envelopeFile,inputFile,policyFile,keystoreFile]=await Promise.all([
  read(process.argv[2],'relayer envelope'),read(process.argv[3],'private transaction input'),
  read(process.argv[4],'relayer policy',1024*1024),read(process.argv[5],'encrypted relayer keystore',4*1024*1024),
 ]);
 const envelope=envelopeFile.value,input=inputFile.value,policy=policyFile.value,keystore=keystoreFile.value;
 const relayer=getAddress(envelope.relayer??envelope.relayerOwner??envelope.from??policy.relayer);
 if(getAddress(policy.relayer)!==relayer||policy.chainId!=='1')throw new Error('relayer policy identity mismatch');
 const crypt=keystore?.crypto??keystore?.Crypto;
 if(keystore?.crypto&&keystore?.Crypto)throw new Error('ambiguous encrypted keystore');
 if(keystore?.version!==3||typeof keystore.address!=='string'||`0x${keystore.address}`.toLowerCase()!==relayer.toLowerCase()
   ||!crypt||typeof crypt!=='object'||!['scrypt','pbkdf2'].includes(crypt.kdf)
   ||crypt.cipher!=='aes-128-ctr'||!/^[0-9a-f]+$/u.test(crypt.ciphertext??'')
   ||!/^[0-9a-f]{64}$/u.test(crypt.mac??''))throw new Error('encrypted keystore identity mismatch');
 if(typeof policy.encryptedKeystoreSha256==='string'&&policy.encryptedKeystoreSha256!==sha(keystoreFile.bytes))throw new Error('encrypted keystore authority mismatch');
 const to=getAddress(input.to),data=input.data;
 if(!/^0x(?:[0-9a-f]{2})*$/u.test(data??''))throw new Error('private calldata is not canonical');
 const value=envelope.value??'0',nonce=envelope.nonce,gasLimit=envelope.gasLimit,
  maxFeePerGas=envelope.maxFeePerGas,maxPriorityFeePerGas=envelope.maxPriorityFeePerGas;
 if(![value,nonce,gasLimit,maxFeePerGas,maxPriorityFeePerGas].every(dec)||value!=='0')throw new Error('relayer quantities rejected');
 if(envelope.to&&getAddress(envelope.to)!==to)throw new Error('relayer target mismatch');
 if(envelope.dataHash&&envelope.dataHash.toLowerCase()!==keccak256(data).toLowerCase())throw new Error('relayer calldata mismatch');
 for(const [field,pfield] of [['gasLimit','maxGasLimit'],['maxFeePerGas','maxFeePerGas'],['maxPriorityFeePerGas','maxPriorityFeePerGas']]) {
  if(!dec(policy[pfield])||BigInt(envelope[field])>BigInt(policy[pfield]))throw new Error(`${field} exceeds relayer policy`);
 }
 if(BigInt(maxPriorityFeePerGas)>BigInt(maxFeePerGas))throw new Error('priority fee exceeds max fee');
 const tx=Transaction.from({type:2,chainId:1n,to,data,value:0n,nonce:BigInt(nonce),gasLimit:BigInt(gasLimit),maxFeePerGas:BigInt(maxFeePerGas),maxPriorityFeePerGas:BigInt(maxPriorityFeePerGas),accessList:[]});
 if(tx.signature!==null||tx.accessList.length!==0)throw new Error('unsigned relayer transaction rejected');
 const request={schema:'usdom-gas-only-relayer-signing/v1',flowSchema:envelope.schema,relayer,chainId:'1',to,dataHash:keccak256(data),value:'0',nonce,gasLimit,maxFeePerGas,maxPriorityFeePerGas,policyHash:keccak256(policyFile.bytes),envelopeHash:keccak256(envelopeFile.bytes),keystoreSha256:sha(keystoreFile.bytes),unsignedHash:tx.unsignedHash,unsignedSerialized:tx.unsignedSerialized};
 process.stdout.write(`${JSON.stringify(request)}\n`);
} catch(error) { console.error(error.message);process.exitCode=1; }
