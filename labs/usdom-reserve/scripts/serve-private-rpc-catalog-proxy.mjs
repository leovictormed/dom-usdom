#!/usr/bin/env node
import {randomBytes} from 'node:crypto';
import {closeSync,constants,fsyncSync,openSync,writeSync} from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {matchMainnetPreflightRpcSources} from '../sdk/mainnet-preflight-rpc.mjs';
import {validatePrivateRpcProxyReady} from '../sdk/private-rpc-proxy-ready.mjs';
import {clearRuntimeSecretJson,readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {parseStrictJson,parseStrictJsonBytes} from '../sdk/strict-json.mjs';

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

async function boundedBody(stream,maximum) {
  const chunks=[]; let length=0;
  for await(const chunk of stream) {
    length+=chunk.length;
    if(length>maximum) throw new Error('body exceeds proxy limit');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks,length);
}

function utf8(bytes,label) {
  try { return new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
  catch { throw new Error(`${label} is not valid UTF-8`); }
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
  } finally { closeSync(descriptor); }
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
const capability=randomBytes(32).toString('hex');
const requestCounts=sources.map(()=>0);
let activeRequests=0;

const server=http.createServer(async(request,response)=>{
  let admitted=false;
  try {
    if(request.method!=='POST'||request.headers['content-type']?.split(';')[0]!=='application/json') {
      response.writeHead(404,{'cache-control':'no-store','connection':'close'}).end(); return;
    }
    const match=new RegExp(`^/${capability}/([0-9]+)$`).exec(request.url??'');
    const index=match?Number(match[1]):-1;
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
    const body=await boundedBody(request,MAX_REQUEST);
    // Reject malformed/batch-smuggling payloads before they reach a paid
    // provider. Cast uses canonical single JSON-RPC objects for this boundary.
    const parsed=parseStrictJson(utf8(body,'local RPC proxy request'),{
      label:'local RPC proxy request',maxBytes:MAX_REQUEST,maxDepth:32});
    if(!parsed||Array.isArray(parsed)||parsed.jsonrpc!=='2.0'||typeof parsed.method!=='string'
        ||!ALLOWED_METHODS.has(parsed.method)||!Array.isArray(parsed.params)
        ||!['string','number'].includes(typeof parsed.id)) {
      throw new Error('invalid local JSON-RPC request');
    }
    const upstream=await fetch(sources[index].url,{method:'POST',redirect:'error',
      headers:{'content-type':'application/json','accept':'application/json'},body,
      signal:AbortSignal.timeout(120000)});
    if(!upstream.ok) throw new Error('upstream rejected request');
    const payload=await boundedBody(upstream.body,MAX_RESPONSE);
    const reply=parseStrictJson(utf8(payload,'local RPC proxy response'),{
      label:'local RPC proxy response',maxBytes:MAX_RESPONSE,maxDepth:256});
    const hasResult=Object.prototype.hasOwnProperty.call(reply??{},'result');
    const hasError=Object.prototype.hasOwnProperty.call(reply??{},'error');
    if(!reply||Array.isArray(reply)||reply.jsonrpc!=='2.0'||reply.id!==parsed.id
        ||hasResult===hasError
        ||Object.keys(reply).some(key=>!['jsonrpc','id','result','error'].includes(key))
        ||(hasError&&(!reply.error||typeof reply.error!=='object'||Array.isArray(reply.error)
          ||!Number.isSafeInteger(reply.error.code)||typeof reply.error.message!=='string'))) {
      throw new Error('invalid upstream JSON-RPC response');
    }
    response.writeHead(200,{'content-type':'application/json','cache-control':'no-store',
      'content-length':String(payload.length),'connection':'close'});
    response.end(payload);
  } catch {
    response.writeHead(502,{'content-type':'application/json','cache-control':'no-store',
      'connection':'close'});
    response.end('{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"bounded upstream RPC failure"}}');
  } finally {
    if(admitted) activeRequests-=1;
  }
});
server.requestTimeout=125000;
server.headersTimeout=10000;
server.keepAliveTimeout=1000;
server.maxRequestsPerSocket=1;
server.listen(0,'127.0.0.1',()=>{
  const address=server.address();
  if(!address||typeof address==='string') process.exit(1);
  publishReady(readyFile,{schema:'usdom-private-rpc-catalog-proxy-v1',pid:process.pid,
    urls:sources.map((_,index)=>`http://127.0.0.1:${address.port}/${capability}/${index}`)});
});
let secretsCleared=false;
function clearProxySecrets(){ if(secretsCleared) return; secretsCleared=true; clearRuntimeSecretJson(runtime); clearRuntimeSecretJson(sources); }
server.once('close',clearProxySecrets);
process.once('exit',clearProxySecrets);
for(const signal of ['SIGINT','SIGTERM','SIGHUP']) process.once(signal,()=>server.close(()=>process.exit(0)));
