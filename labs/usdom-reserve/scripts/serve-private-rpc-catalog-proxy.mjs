#!/usr/bin/env node
import {randomBytes} from 'node:crypto';
import {closeSync,constants,fstatSync,fsyncSync,lstatSync,openSync,rmSync,writeSync} from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {matchMainnetPreflightRpcSources,requireOperationalTlsClock,
  requireSecureHttpsTransportEnvironment} from '../sdk/mainnet-preflight-rpc.mjs';
import {validatePrivateRpcProxyReady} from '../sdk/private-rpc-proxy-ready.mjs';
import {clearRuntimeSecretJson,readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {parseStrictJson,parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validatePrivateRpcProxyRequest,
  validatePrivateRpcProxyResponse} from '../sdk/private-rpc-proxy-envelope.mjs';
import {matchPrivateRpcProxyCapabilityPath} from '../sdk/private-rpc-proxy-capability.mjs';

const MAX_REQUEST=4*1024*1024;
const MAX_RESPONSE=32*1024*1024;
const MAX_CONCURRENT_REQUESTS=8;
const MAX_REQUESTS_PER_SOURCE=512;
const ALLOWED_METHODS=new Set([
  'eth_blockNumber','eth_chainId','eth_estimateGas','eth_getBlockByNumber','eth_getCode',
  'eth_getTransactionByHash','eth_getTransactionCount','eth_getTransactionReceipt',
  'eth_sendRawTransaction',
]);
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');

if(process.env.USDOM_PRIVATE_RPC_PROXY_LAUNCHER!=='1') {
  process.stderr.write('private RPC proxy requires its hardened launcher\n');
  process.exit(64);
}
delete process.env.USDOM_PRIVATE_RPC_PROXY_LAUNCHER;
requireSecureHttpsTransportEnvironment(process.env);
requireOperationalTlsClock();

async function boundedBody(stream,maximum) {
  const chunks=[]; let length=0,oversized=false;
  const iterator=stream?.[Symbol.asyncIterator]?.();
  if(!iterator) throw new Error('body stream is unavailable');
  try {
    for(;;) {
      const {done,value:chunk}=await iterator.next();
      if(done) break;
      length+=chunk.length;
      if(length>maximum) {
        oversized=true;
        if(typeof stream.destroy==='function') stream.destroy();
        throw new Error('body exceeds proxy limit');
      }
      chunks.push(chunk);
    }
    return Buffer.concat(chunks,length);
  } finally {
    if(oversized&&typeof iterator.return==='function') {
      try { await iterator.return(); } catch {}
    }
    for(const chunk of chunks) chunk.fill(0);
  }
}

function requireBoundedContentLength(value,maximum,label) {
  if(value===undefined||value===null) return;
  if(typeof value!=='string'||value.length>String(maximum).length
      ||!/^(?:0|[1-9][0-9]*)$/.test(value)||BigInt(value)>BigInt(maximum)) {
    throw new Error(`${label} content length exceeds proxy limit`);
  }
}

function requireCanonicalLocalHeaders(request,server) {
  const counts=new Map();
  for(let index=0;index<request.rawHeaders.length;index+=2) {
    const name=request.rawHeaders[index].toLowerCase();
    counts.set(name,(counts.get(name)??0)+1);
  }
  const address=server.address();
  const expectedHost=address&&typeof address==='object'?`127.0.0.1:${address.port}`:'';
  if(request.httpVersion!=='1.1'||counts.get('host')!==1||request.headers.host!==expectedHost
      ||counts.get('content-type')!==1||request.headers['content-type']!=='application/json'
      ||counts.get('content-length')!==1||counts.has('transfer-encoding')
      ||counts.has('content-encoding')||counts.has('expect')||counts.has('upgrade')) {
    throw new Error('local RPC request headers are not canonical');
  }
}

function utf8(bytes,label) {
  try { return new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
  catch { throw new Error(`${label} is not valid UTF-8`); }
}

function endAndZero(response,bytes) {
  let cleared=false;
  const clear=()=>{ if(!cleared) { cleared=true; bytes.fill(0); } };
  response.once('close',clear);
  response.end(bytes,clear);
}

function publishReady(file,value) {
  value=validatePrivateRpcProxyReady(value,{expectedPid:process.pid});
  const descriptor=openSync(file,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL
    |constants.O_NOFOLLOW|constants.O_CLOEXEC,0o600);
  try {
    const bytes=Buffer.from(`${JSON.stringify(value)}\n`);
    let offset=0;
    while(offset<bytes.length) offset+=writeSync(descriptor,bytes,offset,bytes.length-offset);
    fsyncSync(descriptor);
    const stat=fstatSync(descriptor);
    if(!stat.isFile()||stat.uid!==process.getuid()||(stat.mode&0o777)!==0o600||stat.nlink!==1) {
      throw new Error('private RPC readiness file identity is invalid');
    }
    return {dev:stat.dev,ino:stat.ino,uid:stat.uid,mode:stat.mode,nlink:stat.nlink};
  } catch(error) {
    try {
      const opened=fstatSync(descriptor),named=lstatSync(file);
      if(opened.dev===named.dev&&opened.ino===named.ino) rmSync(file);
    } catch {}
    throw error;
  } finally { closeSync(descriptor); }
}

function removeReadyIfOwned(file,identity) {
  if(!identity) return;
  try {
    const stat=lstatSync(file);
    if(!stat.isFile()||stat.isSymbolicLink()) return;
    for(const field of ['dev','ino','uid','mode','nlink']) if(stat[field]!==identity[field]) return;
    rmSync(file);
  } catch(error) { if(error?.code!=='ENOENT') return; }
}

if(process.argv.length!==3||!path.isAbsolute(process.argv[2])) {
  process.stderr.write('private RPC proxy requires one absolute readiness-file path\n');
  process.exit(64);
}
const readyFile=process.argv[2];
const catalogBytes=await readDirectProjectFile(root,'config/mainnet-preflight-rpc-catalog.json',{
  minimum:2,maximum:1024*1024,label:'mainnet preflight RPC catalog'});
const catalog=parseStrictJsonBytes(catalogBytes,{
  label:'mainnet preflight RPC catalog',maxBytes:1024*1024,maxDepth:16});
const runtime=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{
  label:'mainnet preflight RPC sources',maxBytes:32*1024,maxDepth:8});
const sources=matchMainnetPreflightRpcSources(catalog,runtime);
const capability=randomBytes(32);
const requestCounts=sources.map(()=>0);
let activeRequests=0;

const server=http.createServer(async(request,response)=>{
  let admitted=false,body,parsed,payload,reply,payloadHandedOff=false,upstreamController;
  try {
    if(request.method!=='POST') {
      response.writeHead(404,{'cache-control':'no-store','connection':'close'}).end(); return;
    }
    requireCanonicalLocalHeaders(request,server);
    const index=matchPrivateRpcProxyCapabilityPath(request.url,capability,sources.length);
    if(!Number.isSafeInteger(index)||index<0||index>=sources.length) {
      response.writeHead(404,{'cache-control':'no-store','connection':'close'}).end(); return;
    }
    if(activeRequests>=MAX_CONCURRENT_REQUESTS
        ||requestCounts[index]>=MAX_REQUESTS_PER_SOURCE) {
      response.writeHead(429,{'cache-control':'no-store','connection':'close'}).end(); return;
    }
    activeRequests+=1;
    requestCounts[index]+=1;
    admitted=true;
    requireBoundedContentLength(request.headers['content-length'],MAX_REQUEST,'request');
    body=await boundedBody(request,MAX_REQUEST);
    // Reject malformed/batch-smuggling payloads before they reach a paid
    // provider. Cast uses canonical single JSON-RPC objects for this boundary.
    parsed=parseStrictJson(utf8(body,'local RPC proxy request'),{
      label:'local RPC proxy request',maxBytes:MAX_REQUEST,maxDepth:32});
    validatePrivateRpcProxyRequest(parsed,ALLOWED_METHODS);
    upstreamController=new AbortController();
    request.once('aborted',()=>upstreamController.abort());
    response.once('close',()=>{ if(!response.writableFinished) upstreamController.abort(); });
    if(request.aborted||response.destroyed) {
      upstreamController.abort();
      throw new Error('local RPC client disconnected');
    }
    const upstream=await fetch(sources[index].url,{method:'POST',redirect:'error',
      headers:{'content-type':'application/json','accept':'application/json'},body,
      signal:AbortSignal.any([upstreamController.signal,AbortSignal.timeout(120000)])});
    if(!upstream.ok) throw new Error('upstream rejected request');
    requireBoundedContentLength(upstream.headers.get('content-length'),MAX_RESPONSE,'upstream response');
    payload=await boundedBody(upstream.body,MAX_RESPONSE);
    reply=parseStrictJson(utf8(payload,'local RPC proxy response'),{
      label:'local RPC proxy response',maxBytes:MAX_RESPONSE,maxDepth:256});
    validatePrivateRpcProxyResponse(reply,parsed.id);
    if(Object.hasOwn(reply,'error')) {
      const sanitized=Buffer.from(JSON.stringify({jsonrpc:'2.0',id:parsed.id,
        error:{code:-32000,message:'bounded upstream RPC error'}}));
      response.writeHead(200,{'content-type':'application/json','cache-control':'no-store',
        'content-length':String(sanitized.length),'connection':'close'});
      endAndZero(response,sanitized);
      return;
    }
    response.writeHead(200,{'content-type':'application/json','cache-control':'no-store',
      'content-length':String(payload.length),'connection':'close'});
    payloadHandedOff=true;
    endAndZero(response,payload);
  } catch {
    if(!response.destroyed) {
      response.writeHead(502,{'content-type':'application/json','cache-control':'no-store',
        'connection':'close'});
      response.end('{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"bounded upstream RPC failure"}}');
    }
  } finally {
    upstreamController?.abort();
    body?.fill(0);
    clearRuntimeSecretJson(parsed);
    clearRuntimeSecretJson(reply);
    if(!payloadHandedOff) payload?.fill(0);
    if(admitted) activeRequests-=1;
  }
});
server.requestTimeout=125000;
server.headersTimeout=10000;
server.keepAliveTimeout=1000;
server.connectionsCheckingInterval=1000;
server.setTimeout(15000,socket=>socket.destroy());
server.maxConnections=16;
server.dropMaxConnection=true;
server.maxRequestsPerSocket=1;
server.maxHeadersCount=16;
let readyIdentity;
server.listen(0,'127.0.0.1',()=>{
  const address=server.address();
  if(!address||typeof address==='string') process.exit(1);
  const ready={schema:'usdom-private-rpc-catalog-proxy-v1',pid:process.pid,
    urls:sources.map((_,index)=>`http://127.0.0.1:${address.port}/${capability.toString('hex')}/${index}`)};
  try { readyIdentity=publishReady(readyFile,ready); }
  finally { clearRuntimeSecretJson(ready); }
});
let secretsCleared=false;
function clearProxySecrets(){
  if(secretsCleared) return;
  secretsCleared=true;
  removeReadyIfOwned(readyFile,readyIdentity);
  capability.fill(0);
  clearRuntimeSecretJson(runtime);
  clearRuntimeSecretJson(sources);
}
server.once('close',clearProxySecrets);
process.once('exit',clearProxySecrets);
for(const signal of ['SIGINT','SIGTERM','SIGHUP']) process.once(signal,()=>server.close(()=>process.exit(0)));
