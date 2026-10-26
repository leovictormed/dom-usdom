import {JsonRpcApiProvider,keccak256,toQuantity,toUtf8Bytes} from 'ethers';
import {isIP} from 'node:net';
import {parseStrictJson} from './strict-json.mjs';

export const MAINNET_PREFLIGHT_RPC_CATALOG_SCHEMA='usdom-mainnet-preflight-rpc-catalog-v2';
const operator=/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/;
const hash=/^0x[0-9a-f]{64}$/;
const quantity=/^0x(?:0|[1-9a-f][0-9a-f]*)$/;
const TLS_POLICY='node-default-ca-hostname-expiry-origin-pinned-v1';
const CLOCK_POLICY='utc-wall-clock-sane-v1';
const ethereumMainnetGenesisBlockHash=
  '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3';
function fail(message) { throw new Error(message); }
function sanitizeRpcError(value) {
  const keys=Object.keys(value??{});
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||keys.some(key=>!['code','message','data'].includes(key))
      ||!keys.includes('code')||!keys.includes('message')
      ||!Number.isSafeInteger(value.code)||value.code<-(2**31)||value.code>2**31-1
      ||typeof value.message!=='string'||value.message.length<1
      ||Buffer.byteLength(value.message,'utf8')>1024) {
    fail('JSON-RPC error envelope is invalid');
  }
  return {code:value.code,message:'JSON-RPC request failed'};
}
export function requireSecureHttpsTransportEnvironment(environment=process.env) {
  for(const name of ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy',
    'NODE_EXTRA_CA_CERTS','SSL_CERT_FILE','SSL_CERT_DIR']) {
    if(typeof environment[name]==='string'&&environment[name].length!==0) {
      fail(`unsafe HTTPS transport environment: ${name}`);
    }
  }
  if(environment.NODE_TLS_REJECT_UNAUTHORIZED==='0'
      ||/(?:^|\s)--(?:use-env-proxy|use-openssl-ca|use-system-ca|use-bundled-ca|openssl-config)(?:=|\s|$)/
        .test(environment.NODE_OPTIONS??'')) {
    fail('unsafe HTTPS transport environment');
  }
}
export function requireOperationalTlsClock(nowMs=Date.now()) {
  if(!Number.isSafeInteger(nowMs)||nowMs<Date.UTC(2025,0,1)||nowMs>Date.UTC(2100,0,1)) {
    fail('system clock is outside the TLS operational policy');
  }
  return nowMs;
}
export function validateMainnetPreflightTimeConsensus(samples,{nowMs=Date.now(),
  maximumFinalizedAgeMs=30*60*1000,maximumSourceSkewMs=15*1000,
  maximumLocalCollectionSkewMs=30*1000}={}) {
  requireOperationalTlsClock(nowMs);
  if(!Array.isArray(samples)||samples.length<2||samples.length>5
      ||!Number.isSafeInteger(maximumFinalizedAgeMs)||maximumFinalizedAgeMs<1
      ||!Number.isSafeInteger(maximumSourceSkewMs)||maximumSourceSkewMs<0
      ||!Number.isSafeInteger(maximumLocalCollectionSkewMs)||maximumLocalCollectionSkewMs<0) {
    fail('RPC operational time consensus policy is invalid');
  }
  const parsed=samples.map((sample,index)=>{
    if(!sample||typeof sample!=='object'||Array.isArray(sample)
        ||Object.keys(sample).sort().join(',')!=='collectedAfterMs,collectedBeforeMs,finalizedTimestamp,sourceId'
        ||!operator.test(sample.sourceId??'')||!quantity.test(sample.finalizedTimestamp??'')
        ||!Number.isSafeInteger(sample.collectedBeforeMs)||!Number.isSafeInteger(sample.collectedAfterMs)
        ||sample.collectedAfterMs<sample.collectedBeforeMs) {
      fail(`RPC operational time sample ${index+1} is invalid`);
    }
    const finalizedMs=BigInt(sample.finalizedTimestamp)*1000n;
    if(finalizedMs>BigInt(Number.MAX_SAFE_INTEGER)) fail('RPC finalized timestamp is outside its bound');
    return {...sample,finalizedMs:Number(finalizedMs)};
  });
  if(new Set(parsed.map(value=>value.sourceId)).size!==parsed.length) {
    fail('RPC operational time sources must be distinct');
  }
  const finalized=parsed.map(value=>value.finalizedMs);
  const localStarts=parsed.map(value=>value.collectedBeforeMs);
  const localEnds=parsed.map(value=>value.collectedAfterMs);
  if(Math.max(...finalized)-Math.min(...finalized)>maximumSourceSkewMs) {
    fail('RPC finalized timestamps exceed the source skew policy');
  }
  if(Math.max(...localStarts)-Math.min(...localStarts)>maximumLocalCollectionSkewMs
      ||Math.max(...localEnds)-Math.min(...localEnds)>maximumLocalCollectionSkewMs) {
    fail('RPC local collection clocks exceed the skew policy');
  }
  for(const value of finalized) {
    if(value>nowMs+maximumSourceSkewMs||nowMs-value>maximumFinalizedAgeMs) {
      fail('RPC finalized timestamp is implausible against local wall clock');
    }
  }
  return true;
}
function exact(value,keys,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    fail(`${label} schema is invalid`);
  }
}
function endpoint(value,label) {
  let url; try { url=new URL(value); } catch { fail(`${label} must be an absolute HTTPS URL`); }
  if(url.protocol!=='https:'||url.username||url.password||url.hash||url.search||url.pathname!=='/') {
    fail(`${label} must be a root HTTPS origin without inline credentials, query, path tokens or fragments`);
  }
  const hostname=url.hostname.toLowerCase();
  const unbracketed=hostname.startsWith('[')&&hostname.endsWith(']')?hostname.slice(1,-1):hostname;
  if(hostname.endsWith('.')||hostname==='localhost'||hostname.endsWith('.localhost')
      ||hostname.endsWith('.local')||isIP(unbracketed)!==0||!hostname.includes('.')) {
    fail(`${label} must use a canonical public DNS hostname`);
  }
  return url;
}
function rows(catalog) {
  exact(catalog,['schema','sources'],'preflight RPC catalog');
  if(catalog.schema!==MAINNET_PREFLIGHT_RPC_CATALOG_SCHEMA||!Array.isArray(catalog.sources)
      ||catalog.sources.length<2||catalog.sources.length>5) fail('preflight catalog requires two to five sources');
  const result=catalog.sources.map((row,index)=>{
    exact(row,['operatorId','providerId','infrastructureId','originKeccak256','tlsPolicy','clockPolicy','clientPolicy'],
      `preflight source ${index+1}`);
    if(!operator.test(row.operatorId??'')||!operator.test(row.providerId??'')
        ||!operator.test(row.infrastructureId??'')||row.tlsPolicy!==TLS_POLICY||row.clockPolicy!==CLOCK_POLICY
        ||row.clientPolicy!=='ethereum-execution-client-stable-v1'||!hash.test(row.originKeccak256??'')
        ||BigInt(row.originKeccak256)===0n) fail(`preflight source ${index+1} is invalid`);
    return {...row};
  });
  if(new Set(result.map(row=>row.operatorId)).size!==result.length
      ||new Set(result.map(row=>row.providerId)).size!==result.length
      ||new Set(result.map(row=>row.infrastructureId)).size!==result.length
      ||new Set(result.map(row=>row.originKeccak256)).size!==result.length) fail('preflight sources must be distinct');
  const sorted=[...result].sort((a,b)=>a.operatorId.localeCompare(b.operatorId));
  if(result.some((row,index)=>row.operatorId!==sorted[index].operatorId)) fail('preflight sources must be sorted');
  return result;
}
export function buildMainnetPreflightRpcCatalog(sources) {
  if(!Array.isArray(sources)||sources.length<2||sources.length>5) fail('two to five RPC sources are required');
  const hostnames=[];
  const catalog={schema:MAINNET_PREFLIGHT_RPC_CATALOG_SCHEMA,sources:sources.map((source,index)=>{
    exact(source,['operatorId','providerId','infrastructureId','url','tlsPolicy','clockPolicy','clientPolicy'],
      `runtime preflight source ${index+1}`);
    if(!operator.test(source.operatorId??'')||!operator.test(source.providerId??'')
        ||!operator.test(source.infrastructureId??'')
        ||source.tlsPolicy!==TLS_POLICY||source.clockPolicy!==CLOCK_POLICY
        ||source.clientPolicy!=='ethereum-execution-client-stable-v1') {
      fail(`runtime preflight source ${index+1} is invalid`);
    }
    const url=endpoint(source.url,`runtime preflight source ${index+1} URL`);
    hostnames.push(url.hostname.toLowerCase());
    return {operatorId:source.operatorId,providerId:source.providerId,
      infrastructureId:source.infrastructureId,tlsPolicy:source.tlsPolicy,clientPolicy:source.clientPolicy,
      clockPolicy:source.clockPolicy,
      originKeccak256:keccak256(toUtf8Bytes(url.origin.toLowerCase()))};
  }).sort((a,b)=>a.operatorId.localeCompare(b.operatorId))};
  if(new Set(hostnames).size!==hostnames.length) fail('runtime preflight hostnames must be distinct');
  rows(catalog); return catalog;
}
export function matchMainnetPreflightRpcSources(catalog,sources) {
  const expected=rows(catalog);
  if(!Array.isArray(sources)||sources.length!==expected.length) fail('runtime preflight sources must match catalog');
  const mapped=new Map();
  for(const [index,source] of sources.entries()) {
    exact(source,['operatorId','providerId','infrastructureId','url','tlsPolicy','clockPolicy','clientPolicy'],
      `runtime preflight source ${index+1}`);
    if(mapped.has(source.operatorId)) fail('runtime preflight operators must be distinct');
    const url=endpoint(source.url,`runtime preflight source ${index+1} URL`);
    mapped.set(source.operatorId,{sourceId:source.operatorId,providerId:source.providerId,
      infrastructureId:source.infrastructureId,tlsPolicy:source.tlsPolicy,clientPolicy:source.clientPolicy,url:url.href,
      clockPolicy:source.clockPolicy,
      hash:keccak256(toUtf8Bytes(url.origin.toLowerCase()))});
  }
  const runtimeHostnames=[...mapped.values()].map(source=>new URL(source.url).hostname.toLowerCase());
  if(new Set(runtimeHostnames).size!==runtimeHostnames.length) {
    fail('runtime preflight hostnames must be distinct');
  }
  return expected.map(row=>{
    const source=mapped.get(row.operatorId);
    if(!source||source.hash!==row.originKeccak256||source.providerId!==row.providerId
        ||source.infrastructureId!==row.infrastructureId||source.tlsPolicy!==row.tlsPolicy
        ||source.clockPolicy!==row.clockPolicy||source.clientPolicy!==row.clientPolicy) fail('runtime preflight source differs from catalog');
    return Object.freeze({sourceId:source.sourceId,providerId:source.providerId,
      infrastructureId:source.infrastructureId,tlsPolicy:source.tlsPolicy,clientPolicy:source.clientPolicy,url:source.url,
      clockPolicy:source.clockPolicy,
      originKeccak256:row.originKeccak256});
  });
}

export function mainnetPreflightRpcSourceSet(catalog) {
  const sources=rows(catalog).map(source=>Object.freeze({...source}));
  const sourceSetCommitment=keccak256(toUtf8Bytes(
    `USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_V2\n${sources.map(source=>
      `${source.operatorId}\u0000${source.providerId}\u0000${source.infrastructureId}\u0000${source.originKeccak256}\u0000${source.tlsPolicy}\u0000${source.clockPolicy}\u0000${source.clientPolicy}`).join('\n')}`));
  return Object.freeze({sourceCount:String(sources.length),sourceSetCommitment,
    sources:Object.freeze(sources)});
}

export function validateMainnetPreflightClientIdentity(value,policy) {
  if(policy!=='ethereum-execution-client-stable-v1') fail('RPC client identity policy is invalid');
  if(typeof value!=='string'||value.length<3||Buffer.byteLength(value,'utf8')>256
      ||/[\u0000-\u001f\u007f]/.test(value)
      ||!/^(?:Geth|erigon|Nethermind|besu|reth|EthereumJS|Bor|CoreGeth)\//i.test(value)) {
    fail('RPC client identity is not a recognized Ethereum execution client');
  }
  return value;
}

async function limitedJson(response,maxBytes) {
  if(!response||response.status!==200) fail('JSON-RPC returned a non-200 response');
  const declared=response.headers?.get?.('content-length');
  if(declared!=null&&(!/^(?:0|[1-9][0-9]*)$/.test(declared)||BigInt(declared)>BigInt(maxBytes))) {
    fail('JSON-RPC response exceeds size limit');
  }
  if(!response.body?.getReader) fail('JSON-RPC response body is unavailable');
  const reader=response.body.getReader(),chunks=[]; let size=0;
  for(;;) {
    const {done,value}=await reader.read(); if(done) break; size+=value.byteLength;
    if(size>maxBytes) { await reader.cancel(); fail('JSON-RPC response exceeds size limit'); }
    chunks.push(value);
  }
  const bytes=new Uint8Array(size); let offset=0;
  for(const chunk of chunks) { bytes.set(chunk,offset); offset+=chunk.byteLength; }
  let text; try { text=new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
  catch { fail('JSON-RPC response is not valid UTF-8'); }
  return parseStrictJson(text,{label:'JSON-RPC response',maxBytes,maxDepth:32,
    maxNodes:10_000,maxStringBytes:maxBytes,maxObjectEntries:4096,maxArrayEntries:4096});
}

export class BoundedMainnetPreflightProvider extends JsonRpcApiProvider {
  constructor(url,{fetchImpl=globalThis.fetch,timeoutMs=20_000,maxBytes=1024*1024,
    maxRequests=256,environment=process.env,nowMs=Date.now(),wallClock=Date.now,
    monotonicClock=()=>performance.now()}={}) {
    super(1,{staticNetwork:true,batchMaxCount:1,cacheTimeout:-1});
    this.rpcUrl=endpoint(url,'preflight RPC URL').href;
    if(typeof fetchImpl!=='function') fail('fetch implementation is unavailable');
    requireSecureHttpsTransportEnvironment(environment);
    requireOperationalTlsClock(nowMs);
    if(typeof wallClock!=='function'||typeof monotonicClock!=='function') fail('operational clock source is invalid');
    this.wallClock=wallClock; this.monotonicClock=monotonicClock;
    this.lastWallMs=nowMs; this.lastMonotonicMs=this.monotonicClock();
    if(!Number.isFinite(this.lastMonotonicMs)) fail('operational monotonic clock is invalid');
    if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>120_000) {
      fail('JSON-RPC timeout is outside its bound');
    }
    if(!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>64*1024*1024) {
      fail('JSON-RPC response size limit is outside its bound');
    }
    if(!Number.isSafeInteger(maxRequests)||maxRequests<1||maxRequests>1024) {
      fail('JSON-RPC request count limit is outside its bound');
    }
    this.fetchImpl=fetchImpl; this.timeoutMs=timeoutMs; this.maxBytes=maxBytes;
    this.maxRequests=maxRequests; this.requestCount=0; this._start();
  }
  _requireMonotonicOperationalClock() {
    const wall=this.wallClock(),monotonic=this.monotonicClock();
    requireOperationalTlsClock(wall);
    if(!Number.isFinite(monotonic)||monotonic<this.lastMonotonicMs||wall<this.lastWallMs
        ||Math.abs((wall-this.lastWallMs)-(monotonic-this.lastMonotonicMs))>5000) {
      fail('operational wall clock regressed or diverged');
    }
    this.lastWallMs=wall; this.lastMonotonicMs=monotonic;
  }
  pinFinalizedSnapshot(blockNumber,blockHash,{allowPendingNonce=false}={}) {
    let tag;
    try { tag=toQuantity(BigInt(blockNumber)); } catch { fail('finalized snapshot number is invalid'); }
    if(!hash.test(String(blockHash??'').toLowerCase())) fail('finalized snapshot hash is invalid');
    if(typeof allowPendingNonce!=='boolean') fail('pending nonce policy is invalid');
    const next={tag,hash:String(blockHash).toLowerCase(),allowPendingNonce};
    if(this.finalizedSnapshot
        && (this.finalizedSnapshot.tag!==next.tag||this.finalizedSnapshot.hash!==next.hash
          ||this.finalizedSnapshot.allowPendingNonce!==next.allowPendingNonce)) {
      fail('finalized snapshot cannot be repinned');
    }
    this.finalizedSnapshot=Object.freeze(next);
    return this.finalizedSnapshot;
  }
  _requirePinnedStateRequest(payload) {
    const positions={eth_call:1,eth_estimateGas:1,eth_getBalance:1,eth_getCode:1,
      eth_getStorageAt:2,eth_getTransactionCount:1};
    const position=positions[payload?.method];
    if(position===undefined) return;
    if(!this.finalizedSnapshot) fail('state request precedes finalized snapshot pinning');
    const tag=payload?.params?.[position];
    if(payload.method==='eth_getTransactionCount'&&tag==='pending'
        &&this.finalizedSnapshot.allowPendingNonce) return;
    if(tag!==this.finalizedSnapshot.tag) {
      fail(`${payload.method} is not pinned to the finalized snapshot block`);
    }
  }
  _requireEthereumAuthorityResponse(payload,result) {
    if(payload.method==='eth_chainId'&&result!=='0x1') fail('JSON-RPC chain ID is not Ethereum mainnet');
    if(payload.method==='eth_getBlockByNumber'&&payload.params?.[0]==='0x0') {
      if(!result||typeof result!=='object'||Array.isArray(result)||result.number!=='0x0'
          ||String(result.hash??'').toLowerCase()!==ethereumMainnetGenesisBlockHash) {
        fail('JSON-RPC genesis block is not canonical Ethereum mainnet');
      }
      return;
    }
    if(payload.method!=='eth_getBlockByNumber'||!this.finalizedSnapshot) return;
    const requested=payload.params?.[0];
    if(requested!==this.finalizedSnapshot.tag&&requested!=='finalized') return;
    if(!result||typeof result!=='object'||Array.isArray(result)
        ||!quantity.test(result.number??'')||!hash.test(String(result.hash??'').toLowerCase())
        ||!quantity.test(result.timestamp??'')) {
      fail('JSON-RPC finalized block identity is invalid');
    }
    const observed=BigInt(result.number),pinned=BigInt(this.finalizedSnapshot.tag);
    if(observed<pinned||(observed===pinned
        && String(result.hash).toLowerCase()!==this.finalizedSnapshot.hash)) {
      fail('JSON-RPC finalized block regressed or changed');
    }
    if(requested===this.finalizedSnapshot.tag&&observed!==pinned) {
      fail('JSON-RPC numeric block response does not match its request');
    }
  }
  async _send(payload) {
    this._requireMonotonicOperationalClock();
    if(Array.isArray(payload)) fail('batched JSON-RPC is disabled');
    this.requestCount+=1;
    if(this.requestCount>this.maxRequests) fail('JSON-RPC request count limit exceeded');
    this._requirePinnedStateRequest(payload);
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),this.timeoutMs);
    try {
      let response;
      try {
        response=await this.fetchImpl(this.rpcUrl,{method:'POST',redirect:'error',signal:controller.signal,
          headers:{accept:'application/json','content-type':'application/json'},body:JSON.stringify(payload)});
      } catch { fail('JSON-RPC transport failed'); }
      const value=await limitedJson(response,this.maxBytes);
      if(!value||typeof value!=='object'||Array.isArray(value)||value.jsonrpc!=='2.0'||value.id!==payload.id
          ||(('result' in value)===('error' in value))
          ||Object.keys(value).some(key=>!['jsonrpc','id','result','error'].includes(key))) {
        fail('JSON-RPC response envelope is invalid');
      }
      if('error' in value) value.error=sanitizeRpcError(value.error);
      else this._requireEthereumAuthorityResponse(payload,value.result);
      this._requireMonotonicOperationalClock();
      return [value];
    } finally { clearTimeout(timer); }
  }
}
