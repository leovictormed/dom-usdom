import {closeSync,fstatSync,openSync,readFileSync,constants} from 'node:fs';
import {parseStrictJsonBytes} from './strict-json.mjs';

export function readPrivateRawTransaction(file) {
  if(typeof file!=='string'||file.length===0) throw new Error('private raw transaction file is required');
  let descriptor,bytes;
  try {
    descriptor=openSync(file,constants.O_RDONLY|constants.O_NOFOLLOW);
    const stat=fstatSync(descriptor,{bigint:true});
    if(!stat.isFile()||stat.nlink!==1n||(stat.mode&0o777n)!==0o600n
        ||stat.uid!==BigInt(process.getuid())||stat.size<3n||stat.size>1024n*1024n) {
      throw new Error('private raw transaction must be a current-user 0600 single-link bounded file');
    }
    bytes=readFileSync(descriptor);
    const after=fstatSync(descriptor,{bigint:true});
    for(const key of ['dev','ino','uid','mode','nlink','size','mtimeNs','ctimeNs']) {
      if(after[key]!==stat[key]) throw new Error('private raw transaction changed while being read');
    }
    if(BigInt(bytes.length)!==stat.size) throw new Error('private raw transaction read was incomplete');
  } finally { if(descriptor!==undefined) closeSync(descriptor); }
  let raw;
  try { raw=bytes.toString('ascii').trim(); } finally { bytes?.fill(0); }
  if(!/^0x[0-9a-f]+$/.test(raw)||raw.length%2!==0) throw new Error('private raw transaction is malformed');
  return raw;
}

export function parseRawTransactionPublicationResponse(bytes) {
  if(!Buffer.isBuffer(bytes)) throw new Error('RPC response bytes are required');
  if(bytes.length===0||bytes.length>64*1024) {
    bytes.fill(0);
    throw new Error('RPC response size is invalid');
  }
  let value;
  try {
    value=parseStrictJsonBytes(bytes,{label:'RPC transaction response',maxBytes:64*1024,maxDepth:8});
  } finally { bytes.fill(0); }
  if(!value||Array.isArray(value)||typeof value!=='object'
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify(['id','jsonrpc','result'])
      ||value.jsonrpc!=='2.0'||value.id!==1||typeof value.result!=='string'
      ||!/^0x[0-9a-fA-F]{64}$/.test(value.result)) throw new Error('RPC transaction response is invalid');
  return value.result.toLowerCase();
}

export async function readBoundedPublicationResponse(response,maximum=64*1024) {
  if(!response?.body||typeof response.body.getReader!=='function'
      ||!Number.isSafeInteger(maximum)||maximum<1) throw new Error('RPC response stream is invalid');
  const declared=response.headers?.get?.('content-length');
  if(declared!==null&&declared!==undefined
      &&(!/^(?:0|[1-9][0-9]*)$/.test(declared)||BigInt(declared)>BigInt(maximum))) {
    await response.body.cancel().catch(()=>{});
    throw new Error('RPC response size is invalid');
  }
  const reader=response.body.getReader(),chunks=[]; let total=0;
  try {
    for(;;) {
      const {done,value}=await reader.read();
      if(done) break;
      if(!(value instanceof Uint8Array)||value.length===0) throw new Error('RPC response stream is invalid');
      total+=value.length;
      if(total>maximum) { value.fill(0); throw new Error('RPC response size is invalid'); }
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks,total);
  } catch(error) {
    for(const chunk of chunks) chunk.fill(0);
    await reader.cancel().catch(()=>{});
    throw error;
  } finally { reader.releaseLock(); }
}
