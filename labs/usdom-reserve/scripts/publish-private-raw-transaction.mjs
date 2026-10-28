#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {parseRawTransactionPublicationResponse,readBoundedPublicationResponse,
  readPrivateRawTransaction} from '../sdk/private-raw-transaction.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {matchMainnetPreflightRpcSources} from '../sdk/mainnet-preflight-rpc.mjs';
if(![4,6].includes(process.argv.length)) process.exit(64);
try {
  let endpoint=process.argv[3];
  if(process.argv.length===6){
    const [sourceBytes,catalogBytes]=await Promise.all([
      readDirectFile(process.argv[3],{minimum:2,maximum:32*1024,exactMode:0o600,label:'private RPC sources'}),
      readDirectFile(process.argv[4],{minimum:2,maximum:1024*1024,exactMode:0o644,label:'public RPC catalog'}),
    ]);
    const sources=parseStrictJsonBytes(sourceBytes,{label:'private RPC sources',maxBytes:32*1024,maxDepth:8});
    const catalog=parseStrictJsonBytes(catalogBytes,{label:'public RPC catalog',maxBytes:1024*1024,maxDepth:8});
    const matched=matchMainnetPreflightRpcSources(catalog,sources),index=Number(process.argv[5]);
    if(!Number.isSafeInteger(index)||index<0||index>=matched.length) {
      throw new Error('private RPC source selection invalid');
    }
    endpoint=matched[index].url;
  }
  const url=new URL(endpoint);
  if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash) {
    throw new Error('RPC URL must be credential-free HTTPS without query or fragment');
  }
  const raw=readPrivateRawTransaction(process.argv[2]);
  const response=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_sendRawTransaction',params:[raw]}),
    redirect:'error',
    signal:AbortSignal.timeout(30_000)});
  if(!response.ok) throw new Error('RPC HTTP response rejected');
  const bytes=await readBoundedPublicationResponse(response);
  process.stdout.write(`${parseRawTransactionPublicationResponse(bytes)}\n`);
} catch(error) { writeReleaseFailure('publish-private-raw-transaction',error); process.exitCode=1; }
