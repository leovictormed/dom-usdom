import {keccak256,toUtf8Bytes} from 'ethers';
import {isIP} from 'node:net';
import {parseStrictJson} from './strict-json.mjs';
import {buildCheckpointBootstrapRatificationReport,checkpointBootstrapRatificationDigest,
  CHECKPOINT_BOOTSTRAP_RATIFICATION_OBSERVATION_SCHEMA,
} from './checkpoint-bootstrap-ratification-report.mjs';
import {collectFinalizedEip1271Approvals,validEip1271Signature}
  from './finalized-eip1271-approval.mjs';

export const CHECKPOINT_BOOTSTRAP_RPC_CATALOG_SCHEMA=
  'usdom-checkpoint-bootstrap-ratification-rpc-catalog-v1';
const hash=/^0x[0-9a-f]{64}$/;
const operator=/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/;
const ETHEREUM_MAINNET_GENESIS=
  '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3';

function fail(message) { throw new Error(message); }
function exact(value,keys,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    fail(`${label} schema is invalid`);
  }
}
function endpoint(value,label) {
  let parsed;
  try { parsed=new URL(value); } catch { fail(`${label} must be an absolute HTTPS URL`); }
  if(parsed.protocol!=='https:'||parsed.username||parsed.password||parsed.hash||parsed.search
      ||parsed.pathname!=='/'||parsed.hostname.endsWith('.')||parsed.hostname==='localhost'
      ||parsed.hostname.endsWith('.localhost')||parsed.hostname.endsWith('.local')
      ||isIP(parsed.hostname)!==0||!parsed.hostname.includes('.')) {
    fail(`${label} must be a canonical public root HTTPS origin`);
  }
  return parsed;
}
function rows(catalog) {
  exact(catalog,['schema','sources'],'RPC source catalog');
  if(catalog.schema!==CHECKPOINT_BOOTSTRAP_RPC_CATALOG_SCHEMA||!Array.isArray(catalog.sources)
      ||catalog.sources.length<2||catalog.sources.length>5) fail('RPC source catalog requires two to five sources');
  const values=catalog.sources.map((row,index)=>{
    exact(row,['operatorId','originKeccak256'],`RPC source ${index+1}`);
    if(!operator.test(row.operatorId??'')||!hash.test(row.originKeccak256??'')
        ||BigInt(row.originKeccak256)===0n) fail(`RPC source ${index+1} is invalid`);
    return {...row};
  });
  if(new Set(values.map(row=>row.operatorId)).size!==values.length
      ||new Set(values.map(row=>row.originKeccak256)).size!==values.length) {
    fail('RPC source operators and origins must be pairwise distinct');
  }
  const sorted=[...values].sort((a,b)=>a.operatorId<b.operatorId?-1:a.operatorId>b.operatorId?1:0);
  if(values.some((row,index)=>row.operatorId!==sorted[index].operatorId)) {
    fail('RPC source catalog must be sorted by operatorId');
  }
  return values;
}

export function buildCheckpointBootstrapRpcCatalog(sources) {
  if(!Array.isArray(sources)||sources.length<2||sources.length>5) fail('two to five RPC sources are required');
  const hostnames=[];
  const catalog={schema:CHECKPOINT_BOOTSTRAP_RPC_CATALOG_SCHEMA,sources:sources.map((source,index)=>{
    exact(source,['operatorId','url'],`RPC source ${index+1}`);
    if(!operator.test(source.operatorId??'')) fail(`RPC source ${index+1} operatorId is invalid`);
    const url=endpoint(source.url,`RPC source ${index+1} URL`);
    hostnames.push(url.hostname.toLowerCase());
    return {operatorId:source.operatorId,
      originKeccak256:keccak256(toUtf8Bytes(url.origin.toLowerCase()))};
  }).sort((a,b)=>a.operatorId<b.operatorId?-1:a.operatorId>b.operatorId?1:0)};
  if(new Set(hostnames).size!==hostnames.length) fail('RPC source hostnames must be pairwise distinct');
  rows(catalog);
  return catalog;
}

export function validateCheckpointBootstrapRpcCatalog(catalog) { rows(catalog); return true; }

async function readLimited(response,maxBytes) {
  if(!response||response.status!==200) fail('JSON-RPC returned a non-200 response');
  const declared=response.headers?.get?.('content-length');
  if(declared!=null&&(!/^[0-9]+$/.test(declared)||Number(declared)>maxBytes)) {
    fail('JSON-RPC response exceeds the size limit');
  }
  if(!response.body?.getReader) fail('JSON-RPC response body is unavailable');
  const reader=response.body.getReader(),chunks=[]; let size=0;
  for(;;) {
    const {done,value}=await reader.read(); if(done) break;
    size+=value.byteLength;
    if(size>maxBytes) { await reader.cancel(); fail('JSON-RPC response exceeds the size limit'); }
    chunks.push(value);
  }
  const bytes=new Uint8Array(size); let offset=0;
  for(const chunk of chunks) { bytes.set(chunk,offset); offset+=chunk.byteLength; }
  let text;
  try { text=new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
  catch { fail('JSON-RPC response is not valid UTF-8'); }
  return parseStrictJson(text,{label:'JSON-RPC response',maxBytes,maxDepth:12});
}

export function createBoundedJsonRpcProvider(url,{fetchImpl=globalThis.fetch,timeoutMs=10_000,
  maxBytes=64*1024,maxRequests=256}={}) {
  const endpointUrl=endpoint(url,'RPC URL').href;
  if(typeof fetchImpl!=='function') fail('fetch implementation is unavailable');
  if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>120_000
      ||!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>16*1024*1024
      ||!Number.isSafeInteger(maxRequests)||maxRequests<1||maxRequests>1024) {
    fail('JSON-RPC transport bounds are invalid');
  }
  let nextId=1;
  return {async send(method,params) {
    if(typeof method!=='string'||!Array.isArray(params)) fail('JSON-RPC request is invalid');
    if(nextId>maxRequests) fail('JSON-RPC request count limit exceeded');
    const id=nextId++,controller=new AbortController();
    const timer=setTimeout(()=>controller.abort(),timeoutMs);
    try {
      const response=await fetchImpl(endpointUrl,{method:'POST',redirect:'error',signal:controller.signal,
        headers:{accept:'application/json','content-type':'application/json'},
        body:JSON.stringify({jsonrpc:'2.0',id,method,params})});
      const value=await readLimited(response,maxBytes);
      exact(value,['id','jsonrpc','result'],'JSON-RPC response');
      if(value.jsonrpc!=='2.0'||value.id!==id) fail('JSON-RPC response identity differs');
      return value.result;
    } finally { clearTimeout(timer); }
  }};
}

export async function collectCheckpointBootstrapRatificationObservation({catalog,rpcSources,
  releaseEvidence,releaseConfig,checkpointConsensus,nativeFacts,signature,fetchImpl=globalThis.fetch,
  now=()=>Math.floor(Date.now()/1000),timeoutMs=10_000,maxBytes=64*1024}={}) {
  const catalogRows=rows(catalog);
  if(!Array.isArray(rpcSources)||rpcSources.length!==catalogRows.length) {
    fail('runtime RPC sources must exactly match the public catalog');
  }
  if(!validEip1271Signature(signature)) fail('EIP-1271 signature is malformed or oversized');
  const runtime=new Map();
  const runtimeHostnames=[];
  for(const [index,source] of rpcSources.entries()) {
    exact(source,['operatorId','url'],`runtime RPC source ${index+1}`);
    if(runtime.has(source.operatorId)) fail('runtime RPC operators must be distinct');
    const url=endpoint(source.url,`runtime RPC source ${index+1} URL`);
    runtimeHostnames.push(url.hostname.toLowerCase());
    runtime.set(source.operatorId,{url:url.href,
      originKeccak256:keccak256(toUtf8Bytes(url.origin.toLowerCase()))});
  }
  if(new Set(runtimeHostnames).size!==runtimeHostnames.length) {
    fail('runtime RPC source hostnames must be pairwise distinct');
  }
  const digest=checkpointBootstrapRatificationDigest({releaseEvidence,releaseConfig,
    checkpointConsensus,nativeFacts});
  const approvals=[];
  for(const row of catalogRows) {
    const source=runtime.get(row.operatorId);
    if(!source||source.originKeccak256!==row.originKeccak256) fail('runtime RPC source differs from catalog');
    const provider=createBoundedJsonRpcProvider(source.url,{fetchImpl,timeoutMs,maxBytes});
    const genesis=await provider.send('eth_getBlockByNumber',['0x0',false]);
    if(genesis?.number!=='0x0'||String(genesis?.hash??'').toLowerCase()!==ETHEREUM_MAINNET_GENESIS) {
      fail(`${row.operatorId} is not canonical Ethereum mainnet`);
    }
    const result=await collectFinalizedEip1271Approvals({provider,chainId:'1',
      governance:releaseConfig.governance,
      governanceImplementation:releaseConfig.governanceImplementation,
      governanceImplementationCodeHash:releaseConfig.governanceImplementationCodeHash,
      requests:{ratification:{digest,signature}}});
    if(!result.approvals.ratification.valid||result.snapshotBlockHashAfter!==result.finalizedBlockHash) {
      fail(`${row.operatorId} did not return a stable valid finalized EIP-1271 approval`);
    }
    if(result.governanceCodeHash.toLowerCase()!==releaseConfig.governanceCodeHash.toLowerCase()) {
      fail(`${row.operatorId} governance code hash differs from release`);
    }
    const observed=String(now());
    approvals.push({operatorId:row.operatorId,originKeccak256:row.originKeccak256,
      snapshotBlockNumber:result.finalizedBlockNumber,snapshotBlockHash:result.finalizedBlockHash.toLowerCase(),
      snapshotBlockTimestamp:result.finalizedBlockTimestamp,
      governanceCodeHash:result.governanceCodeHash.toLowerCase(),eip1271MagicValue:'0x1626ba7e',
      observedAtUnix:observed});
  }
  const first=approvals[0];
  if(approvals.some(value=>value.snapshotBlockNumber!==first.snapshotBlockNumber
      ||value.snapshotBlockHash!==first.snapshotBlockHash
      ||value.snapshotBlockTimestamp!==first.snapshotBlockTimestamp)) {
    fail('RPC sources disagree on the finalized snapshot');
  }
  const sourceSetCommitment=keccak256(toUtf8Bytes(
    `USDOM_CHECKPOINT_RATIFICATION_RPC_SOURCES_V1\n${catalogRows.map(row=>
      `${row.operatorId}\u0000${row.originKeccak256}`).join('\n')}`));
  const observation={schema:CHECKPOINT_BOOTSTRAP_RATIFICATION_OBSERVATION_SCHEMA,
    releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
    sourceTag:releaseEvidence.sourceTag,ethereumChainId:'1',governance:releaseConfig.governance,
    ratificationDigest:digest,snapshotBlockNumber:first.snapshotBlockNumber,
    snapshotBlockHash:first.snapshotBlockHash,snapshotBlockTimestamp:first.snapshotBlockTimestamp,
    sourceSetCommitment,approvals};
  buildCheckpointBootstrapRatificationReport({releaseEvidence,releaseConfig,checkpointConsensus,
    nativeFacts,observation});
  return observation;
}
