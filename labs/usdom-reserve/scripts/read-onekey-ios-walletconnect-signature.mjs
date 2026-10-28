#!/usr/bin/env node
import {getAddress,TypedDataEncoder,verifyTypedData} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {readOneKeyIosTypedDataRequest,ONEKEY_IOS_WC_SCHEMA} from '../sdk/onekey-ios-walletconnect-typed-data.mjs';
const canonical=value=>{if(value===null||typeof value==='boolean'||typeof value==='string')return JSON.stringify(value);
  if(typeof value==='number'&&Number.isSafeInteger(value))return JSON.stringify(value);
  if(Array.isArray(value))return`[${value.map(canonical).join(',')}]`;
  if(value&&typeof value==='object')return`{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  throw new Error('non-canonical typed data');};

if(process.argv.length!==6) {
  console.error('usage: read-onekey-ios-walletconnect-signature.mjs REQUEST RESPONSE EXPECTED_ADDRESS CURRENT_TYPED_DATA');
  process.exit(64);
}
const [, ,requestPath,responsePath,expectedAddress,currentTypedDataPath]=process.argv;
const request=await readOneKeyIosTypedDataRequest(requestPath);
const currentTypedData=parseStrictJsonBytes(await readDirectFile(currentTypedDataPath,{minimum:2,maximum:1024*1024,
  privateMode:true,exactMode:0o600,label:'current Safe recovery typed data'}),{label:'current Safe recovery typed data'});
const currentTypes={...currentTypedData.types};delete currentTypes.EIP712Domain;
const currentDigest=TypedDataEncoder.hash(currentTypedData.domain,currentTypes,currentTypedData.message);
const response=parseStrictJsonBytes(await readDirectFile(responsePath,{minimum:2,maximum:4096,privateMode:true,
  exactMode:0o600,label:'OneKey iOS WalletConnect signature response'}),{label:'OneKey iOS WalletConnect signature response'});
const keys=Object.keys(response).sort().join(',');
if(keys!==['digest','expectedAddress','requestSha256','schema','signature'].sort().join(',')
  ||response.schema!==ONEKEY_IOS_WC_SCHEMA||response.requestSha256!==request.requestSha256
  ||response.digest!==request.digest||response.digest!==currentDigest
  ||getAddress(response.expectedAddress)!==getAddress(expectedAddress)
  ||getAddress(request.expectedAddress)!==getAddress(expectedAddress)
  ||typeof response.signature!=='string'||!/^0x[0-9a-fA-F]{130}$/u.test(response.signature)) {
  throw new Error('OneKey iOS WalletConnect signature response rejected');
}
if(canonical(request.typedData)!==canonical(currentTypedData))throw new Error('OneKey iOS WalletConnect typed data drift');
const types={...request.typedData.types};delete types.EIP712Domain;
if(getAddress(verifyTypedData(request.typedData.domain,types,request.typedData.message,response.signature))!==getAddress(expectedAddress)) {
  throw new Error('OneKey iOS WalletConnect signer mismatch');
}
process.stdout.write(`${response.signature}\n`);
