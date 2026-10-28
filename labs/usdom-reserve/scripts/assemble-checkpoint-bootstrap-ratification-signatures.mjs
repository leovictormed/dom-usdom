#!/usr/bin/env node
import {readFile,writeFile} from 'node:fs/promises';
import {Signature,TypedDataEncoder,getAddress,verifyTypedData} from 'ethers';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

if(process.argv.length!==8) throw new Error('usage: assemble REQUEST OWNER1 OWNER1_SIG OWNER2 OWNER2_SIG OUTPUT');
const request=parseStrictJsonBytes(await readFile(process.argv[2]),{label:'ratification request'});
const types={...request.typedData.types}; delete types.EIP712Domain;
if(TypedDataEncoder.hash(request.typedData.domain,types,request.typedData.message)!==request.ratificationDigest) {
  throw new Error('ratification typed-data digest mismatch');
}
const rows=[];
for(const [expected,path] of [[process.argv[3],process.argv[4]],[process.argv[5],process.argv[6]]]) {
  const text=await readFile(path,'ascii');
  if(!/^0x[0-9a-f]{130}\n$/.test(text)) throw new Error('ratification signature is noncanonical');
  const signature=Signature.from(text.trim());
  if(signature.serialized!==text.trim()) throw new Error('ratification signature serialization differs');
  const address=getAddress(verifyTypedData(request.typedData.domain,types,
    request.typedData.message,signature));
  if(address!==getAddress(expected)) throw new Error('ratification signature owner mismatch');
  rows.push({address,signature:signature.serialized});
}
rows.sort((a,b)=>a.address.toLowerCase().localeCompare(b.address.toLowerCase()));
if(rows[0].address===rows[1].address) throw new Error('ratification signers must be distinct');
await writeFile(process.argv[7],`0x${rows.map(row=>row.signature.slice(2)).join('')}\n`,
  {flag:'wx',mode:0o600});
