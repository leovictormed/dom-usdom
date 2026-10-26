#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readPrivateRawTransaction} from '../sdk/private-raw-transaction.mjs';
if(process.argv.length!==4) process.exit(64);
try {
  const url=new URL(process.argv[3]);
  if(url.protocol!=='https:'||url.username||url.password) throw new Error('RPC URL must be credential-free HTTPS');
  const raw=readPrivateRawTransaction(process.argv[2]);
  const response=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_sendRawTransaction',params:[raw]}),
    signal:AbortSignal.timeout(30_000)});
  if(!response.ok) throw new Error('RPC HTTP response rejected');
  const bytes=Buffer.from(await response.arrayBuffer());
  if(bytes.length===0||bytes.length>64*1024) throw new Error('RPC response size is invalid');
  const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)); bytes.fill(0);
  if(!value||JSON.stringify(Object.keys(value).sort())!==JSON.stringify(['id','jsonrpc','result'])
      ||value.jsonrpc!=='2.0'||value.id!==1||typeof value.result!=='string'
      ||!/^0x[0-9a-fA-F]{64}$/.test(value.result)) throw new Error('RPC transaction response is invalid');
  process.stdout.write(`${value.result.toLowerCase()}\n`);
} catch(error) { writeReleaseFailure('publish-private-raw-transaction',error); process.exitCode=1; }
