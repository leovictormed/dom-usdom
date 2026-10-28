#!/usr/bin/env node
import {readFile} from 'node:fs/promises';
import {Interface,Signature,Transaction,TypedDataEncoder,getAddress,keccak256,recoverAddress} from 'ethers';
import {SAFE_TX_TYPES,validateOneKeyIosSafeRelayer} from '../sdk/onekey-ios-safe-relayer.mjs';
const read=async p=>JSON.parse(await readFile(p,'utf8'));
const iface=new Interface(['function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)']);
try {
 const mode=process.argv[2];
 if(mode==='envelope') {
  if(process.argv.length!==10)throw new Error('usage: envelope PLAN OP AUTHORITY SNAPSHOT SIG1 SIG2 OUTER_GAS FEE_JSON');
  const [plan,authority,snapshot,s1,s2,fees]=await Promise.all([read(process.argv[3]),read(process.argv[5]),read(process.argv[6]),read(process.argv[7]),read(process.argv[8]),read(process.argv[9])]);
  const index=Number(process.argv[4]);if(![0,1].includes(index))throw new Error('operation index rejected');
  const op=plan.operations[index],signatures=[s1,s2].map(x=>({owner:getAddress(x.signer),signature:Signature.from(x.signature).serialized})).sort((a,b)=>a.owner.toLowerCase().localeCompare(b.owner.toLowerCase()));
  for(const x of signatures)if(recoverAddress(op.digest,x.signature)!==x.owner)throw new Error('owner signature rejected');
  const m=op.typedData.message,packed=`0x${signatures.map(x=>x.signature.slice(2)).join('')}`;
  const data=iface.encodeFunctionData('execTransaction',[m.to,m.value,m.data,m.operation,m.safeTxGas,m.baseGas,m.gasPrice,m.gasToken,m.refundReceiver,packed]);
  const envelope={schema:'usdom-onekey-ios-safe-relayer-envelope-v1',attempt:1,previousTransactionHash:null,typedData:op.typedData,signatures,outerTransaction:{from:getAddress(authority.relayer),to:getAddress(authority.safe),value:'0',data,nonce:snapshot.pendingNonce,gasLimit:fees.gasLimit,maxFeePerGas:fees.maxFeePerGas,maxPriorityFeePerGas:fees.maxPriorityFeePerGas,chainId:1}};
  validateOneKeyIosSafeRelayer({authority,snapshot,envelope});
  process.stdout.write(`${JSON.stringify({envelope,input:{to:envelope.outerTransaction.to,data},signerEnvelope:{schema:'usdom-safe-deposit-gas-relayer-envelope/v1',relayer:envelope.outerTransaction.from,to:envelope.outerTransaction.to,dataHash:keccak256(data),value:'0',nonce:String(envelope.outerTransaction.nonce),gasLimit:fees.gasLimit,maxFeePerGas:fees.maxFeePerGas,maxPriorityFeePerGas:fees.maxPriorityFeePerGas}})}\n`);
 } else if(mode==='raw') {
  if(process.argv.length!==7)throw new Error('usage: raw ENVELOPE INPUT POLICY RAW');
  const [envelope,input,policy]=await Promise.all([read(process.argv[3]),read(process.argv[4]),read(process.argv[5])]);const raw=(await readFile(process.argv[6],'utf8')).trim();
  const tx=Transaction.from(raw),o=envelope.outerTransaction;
  if(tx.chainId!==1n||tx.from!==getAddress(policy.relayer)||tx.to!==getAddress(input.to)||tx.data!==input.data||tx.value!==0n||tx.nonce!==o.nonce||tx.gasLimit!==BigInt(o.gasLimit)||tx.maxFeePerGas!==BigInt(o.maxFeePerGas)||tx.maxPriorityFeePerGas!==BigInt(o.maxPriorityFeePerGas))throw new Error('signed relayer raw drifted');
  const types={...envelope.typedData.types};delete types.EIP712Domain;
  process.stdout.write(`${JSON.stringify({schema:'usdom-safe-deposit-relayer-raw-validation/v1',transactionHash:tx.hash,from:tx.from,to:tx.to,nonce:String(tx.nonce),dataHash:keccak256(tx.data),safeTxHash:TypedDataEncoder.hash(envelope.typedData.domain,types,envelope.typedData.message)})}\n`);
 } else throw new Error('mode rejected');
} catch(e){console.error(e.message);process.exitCode=1;}
