#!/usr/bin/env node
import {Signature,TypedDataEncoder,getAddress,verifyTypedData} from 'ethers';
import {pathToFileURL} from 'node:url';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurableNew} from '../sdk/durable-private-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

export async function assembleOneKeySafeSignatures({envelopePath,owner1,signature1Path,
  owner2,signature2Path,outputPath}={}) {
  const envelope=parseStrictJsonBytes(await readDirectFile(envelopePath,{minimum:2,maximum:2*1024*1024,
    privateMode:true,exactMode:0o600,label:'private EIP-712 envelope'}),{label:'private EIP-712 envelope'});
  if(envelope?.schema!=='usdom-onekey-eip712-signing/v1') throw new Error('EIP-712 envelope schema differs');
  const types={...envelope.typedData.types};delete types.EIP712Domain;
  if(TypedDataEncoder.hash(envelope.typedData.domain,types,envelope.typedData.message)!==envelope.digest) {
    throw new Error('EIP-712 envelope digest differs');
  }
  const rows=[];
  for(const [owner,path] of [[owner1,signature1Path],[owner2,signature2Path]]) {
    const text=(await readDirectFile(path,{minimum:133,maximum:133,privateMode:true,exactMode:0o600,
      label:'private OneKey signature'})).toString('ascii');
    if(!/^0x[0-9a-f]{130}\n$/.test(text)) throw new Error('signature is noncanonical');
    const signature=Signature.from(text.trim());
    const address=getAddress(verifyTypedData(envelope.typedData.domain,types,envelope.typedData.message,signature));
    if(address!==getAddress(owner)||signature.serialized!==text.trim()) throw new Error('signature owner differs');
    rows.push({address,signature:signature.serialized});
  }
  rows.sort((a,b)=>a.address.toLowerCase().localeCompare(b.address.toLowerCase()));
  if(rows[0].address===rows[1].address) throw new Error('signers must be distinct');
  try {
    await writePrivateFileDurableNew(outputPath,Buffer.from(`0x${rows.map(row=>row.signature.slice(2)).join('')}\n`,'ascii'),
      {maximum:1024});
  } catch(cause) {
    const error=new Error('OneKey signatures exist but Safe signature output was not durably installed',{cause});
    error.exitCode=80;throw error;
  }
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  if(process.argv.length!==8) {console.error('usage: assemble ENVELOPE OWNER1 SIG1 OWNER2 SIG2 OUTPUT');process.exit(64);}
  try {await assembleOneKeySafeSignatures({envelopePath:process.argv[2],owner1:process.argv[3],
    signature1Path:process.argv[4],owner2:process.argv[5],signature2Path:process.argv[6],outputPath:process.argv[7]});}
  catch(error) {console.error(error?.message??'Safe signature assembly failed');process.exit(error?.exitCode===80?80:1);}
}
