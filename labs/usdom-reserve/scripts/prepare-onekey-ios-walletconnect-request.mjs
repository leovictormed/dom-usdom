#!/usr/bin/env node
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {readOneKeyIosWalletConnectClientConfig} from '../sdk/onekey-ios-walletconnect-client.mjs';
import {prepareOneKeyIosTypedDataRequest} from '../sdk/onekey-ios-walletconnect-typed-data.mjs';
import {TypedDataEncoder} from 'ethers';

if(process.argv.length!==7) {
 console.error('usage: prepare-onekey-ios-walletconnect-request.mjs CONFIG ENVELOPE PHYSICAL_EVIDENCE EXPECTED_ADDRESS OUTPUT');process.exit(64);
}
try {
 const config=await readOneKeyIosWalletConnectClientConfig(process.argv[2]);
 const envelope=parseStrictJsonBytes(await readDirectFile(process.argv[3],{minimum:2,maximum:2*1024*1024,
  privateMode:true,exactMode:0o600,label:'private EIP-712 envelope'}),{label:'private EIP-712 envelope'});
 if(!envelope||envelope.schema!=='usdom-onekey-eip712-signing/v1'||typeof envelope.digest!=='string'||!envelope.typedData) {
  throw new Error('private EIP-712 envelope rejected');
 }
 const types={...envelope.typedData.types};delete types.EIP712Domain;
 if(TypedDataEncoder.hash(envelope.typedData.domain,types,envelope.typedData.message)!==envelope.digest) {
  throw new Error('EIP-712 envelope digest mismatch');
 }
 const prepared=await prepareOneKeyIosTypedDataRequest({path:process.argv[6],expectedAddress:process.argv[5],
  typedData:envelope.typedData,physicalEvidencePath:process.argv[4],walletConnectProjectId:config.projectId});
 if(prepared.digest!==envelope.digest)throw new Error('EIP-712 envelope digest mismatch');
} catch(error) {console.error(error?.message??'WalletConnect request preparation failed');process.exit(1);}
