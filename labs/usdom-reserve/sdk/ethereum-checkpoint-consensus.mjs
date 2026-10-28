import {keccak256,toUtf8Bytes} from 'ethers';
import {createHash} from 'node:crypto';
import {isIP} from 'node:net';
import {parseStrictJson} from './strict-json.mjs';
import {requireSecureHttpsTransportEnvironment} from './mainnet-preflight-rpc.mjs';

export const ETHEREUM_CHECKPOINT_CONSENSUS_SCHEMA='usdom-ethereum-checkpoint-consensus-v1';
export const ETHEREUM_CHECKPOINT_SOURCE_CATALOG_SCHEMA='usdom-ethereum-checkpoint-source-catalog-v1';
export const ETHEREUM_MAINNET_GENESIS_TIME='1606824023';
export const ETHEREUM_MAINNET_GENESIS_VALIDATORS_ROOT=
  '0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95';
export const ETHEREUM_MAINNET_GENESIS_FORK_VERSION='0x00000000';
export const MAX_CHECKPOINT_AGE_SLOTS=8n*32n;
const hashPattern=/^0x[0-9a-fA-F]{64}$/;
const pubkeyPattern=/^0x[0-9a-fA-F]{96}$/;
const operatorPattern=/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/;

function object(value,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value;
}
function decimal(value,bits,label) {
  const maxDigits={8:3,32:10,64:20,128:39,256:78}[bits];
  if(maxDigits===undefined||typeof value!=='string'||value.length>maxDigits
      ||!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${label} must be a canonical decimal string`);
  }
  const parsed=BigInt(value);
  if(parsed>=(1n<<BigInt(bits))) throw new Error(`${label} exceeds uint${bits}`);
  return parsed;
}
function hash(value,label) {
  if(!hashPattern.test(value??'')||BigInt(value)===0n) throw new Error(`${label} must be nonzero bytes32`);
  return value.toLowerCase();
}
function bool(value,label) {
  if(typeof value!=='boolean') throw new Error(`${label} must be boolean`);
  return value;
}
function endpoint(value,label) {
  let url;
  try { url=new URL(value); } catch { throw new Error(`${label} must be an absolute URL`); }
  if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash) {
    throw new Error(`${label} must be credential-free HTTPS without query or fragment`);
  }
  const hostname=url.hostname.toLowerCase();
  const unbracketed=hostname.startsWith('[')&&hostname.endsWith(']')?hostname.slice(1,-1):hostname;
  if(hostname.endsWith('.')||hostname==='localhost'||hostname.endsWith('.localhost')
      ||hostname.endsWith('.local')||isIP(unbracketed)!==0||!hostname.includes('.')) {
    throw new Error(`${label} must use a canonical public DNS hostname`);
  }
  url.pathname=url.pathname.replace(/\/+$/,'');
  return url;
}
function apiUrl(base,path) {
  const result=new URL(base.href);
  result.pathname=`${base.pathname}${path}`.replace(/\/{2,}/g,'/');
  return result.href;
}
function sourceCatalog(catalog) {
  if(!catalog||typeof catalog!=='object'||Array.isArray(catalog)
      ||Object.keys(catalog).length!==2||catalog.schema!==ETHEREUM_CHECKPOINT_SOURCE_CATALOG_SCHEMA
      ||!Array.isArray(catalog.sources)||catalog.sources.length<3||catalog.sources.length>5) {
    throw new Error('Ethereum checkpoint source catalog must use the exact supported schema');
  }
  const rows=catalog.sources.map((row,index)=>{
    if(!row||typeof row!=='object'||Array.isArray(row)||Object.keys(row).length!==2
        ||typeof row.operatorId!=='string'||!operatorPattern.test(row.operatorId)) {
      throw new Error(`source catalog row ${index+1} is invalid`);
    }
    return {operatorId:row.operatorId,originKeccak256:hash(row.originKeccak256,
      `source catalog row ${index+1} originKeccak256`)};
  });
  if(new Set(rows.map(row=>row.operatorId)).size!==rows.length
      ||new Set(rows.map(row=>row.originKeccak256)).size!==rows.length) {
    throw new Error('source catalog identities must be pairwise distinct');
  }
  const sorted=[...rows].sort((left,right)=>
    left.operatorId<right.operatorId?-1:left.operatorId>right.operatorId?1:0);
  if(rows.some((row,index)=>row.operatorId!==sorted[index].operatorId)) {
    throw new Error('source catalog rows must be sorted by operatorId');
  }
  return rows;
}
export function ethereumCheckpointSourceCatalogCommitment(catalog) {
  const rows=sourceCatalog(catalog);
  return keccak256(toUtf8Bytes(`USDOM_ETHEREUM_CHECKPOINT_SOURCE_CATALOG_V1\n${rows.map(row=>
    `${row.operatorId}\u0000${row.originKeccak256}`).join('\n')}`));
}
export function buildEthereumCheckpointSourceCatalog(sources) {
  if(!Array.isArray(sources)||sources.length<3||sources.length>5) {
    throw new Error('three to five independent Beacon API sources are required');
  }
  const hostnames=[];
  const rows=sources.map((source,index)=>{
    if(!source||Object.keys(source).length!==2||typeof source.operatorId!=='string'
        ||!operatorPattern.test(source.operatorId)) throw new Error(`source ${index+1} is invalid`);
    const url=endpoint(source.url,`source ${index+1} URL`);
    hostnames.push(url.hostname.toLowerCase());
    return {operatorId:source.operatorId,originKeccak256:keccak256(toUtf8Bytes(url.origin.toLowerCase()))};
  }).sort((left,right)=>left.operatorId<right.operatorId?-1:left.operatorId>right.operatorId?1:0);
  const catalog={schema:ETHEREUM_CHECKPOINT_SOURCE_CATALOG_SCHEMA,sources:rows};
  if(new Set(hostnames).size!==hostnames.length) {
    throw new Error('Beacon API sources must use pairwise distinct public hostnames');
  }
  sourceCatalog(catalog);
  return Object.freeze(catalog);
}
export async function requestBeaconJson(url,{fetchImpl=globalThis.fetch,timeoutMs=10_000,
  maxBytes=128*1024,environment=process.env}={}) {
  if(typeof fetchImpl!=='function') throw new Error('fetch implementation is unavailable');
  if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>120_000
      ||!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>16*1024*1024) {
    throw new Error('Beacon API transport bounds are invalid');
  }
  requireSecureHttpsTransportEnvironment(environment);
  const target=endpoint(url,'Beacon API URL');
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),timeoutMs);
  try {
    let response;
    try { response=await fetchImpl(target.href,{method:'GET',headers:{accept:'application/json'},
      redirect:'error',signal:controller.signal}); }
    catch { throw new Error('Beacon API transport failed'); }
    if(!response||response.status!==200) throw new Error('Beacon API returned a non-200 response');
    const declared=response.headers?.get?.('content-length');
    if(declared!==null&&declared!==undefined
        &&(!/^(?:0|[1-9][0-9]*)$/.test(declared)
          ||declared.length>String(maxBytes).length||BigInt(declared)>BigInt(maxBytes))) {
      throw new Error('Beacon API response exceeds the size limit');
    }
    if(!response.body?.getReader) throw new Error('Beacon API response body is unavailable');
    const reader=response.body.getReader(),chunks=[];
    let size=0;
    for(;;) {
      const {done,value}=await reader.read();
      if(done) break;
      size+=value.byteLength;
      if(size>maxBytes) {
        await reader.cancel();
        throw new Error('Beacon API response exceeds the size limit');
      }
      chunks.push(value);
    }
    if(size===0) throw new Error('Beacon API response size is invalid');
    const bytes=new Uint8Array(size);
    let offset=0;
    for(const chunk of chunks) { bytes.set(chunk,offset); offset+=chunk.byteLength; }
    let text;
    try { text=new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
    catch { throw new Error('Beacon API response is not valid UTF-8 JSON'); }
    return parseStrictJson(text,{label:'Beacon API response',maxBytes,maxDepth:16,
      maxNodes:10_000,maxStringBytes:maxBytes,maxObjectEntries:4096,maxArrayEntries:4096});
  } finally { clearTimeout(timer); }
}

function validateGenesis(raw,label) {
  const data=object(object(raw,`${label} genesis response`).data,`${label} genesis data`);
  if(data.genesis_time!==ETHEREUM_MAINNET_GENESIS_TIME
      ||String(data.genesis_validators_root).toLowerCase()!==ETHEREUM_MAINNET_GENESIS_VALIDATORS_ROOT
      ||String(data.genesis_fork_version).toLowerCase()!==ETHEREUM_MAINNET_GENESIS_FORK_VERSION) {
    throw new Error(`${label} is not Ethereum mainnet`);
  }
}
function validateFinality(raw,label) {
  const response=object(raw,`${label} finality response`);
  if(bool(response.execution_optimistic,`${label} execution_optimistic`)!==false) {
    throw new Error(`${label} execution_optimistic is unsafe`);
  }
  const data=object(response.data,`${label} finality data`);
  const finalized=object(data.finalized,`${label} finalized checkpoint`);
  return {epoch:decimal(finalized.epoch,64,`${label} finalized epoch`),
    root:hash(finalized.root,`${label} finalized root`)};
}
function bytes(value,pattern,label) {
  if(typeof value!=='string'||!pattern.test(value)) throw new Error(`${label} has invalid encoding`);
  return Buffer.from(value.slice(2),'hex');
}
function sha(left,right) {
  return createHash('sha256').update(left).update(right).digest();
}
function uint64Root(value) {
  const result=Buffer.alloc(32);
  result.writeBigUInt64LE(value);
  return result;
}
function merkleize(chunks) {
  if(chunks.length===0||(chunks.length&(chunks.length-1))!==0) throw new Error('invalid SSZ chunk count');
  let level=chunks;
  while(level.length>1) {
    const next=[];
    for(let index=0;index<level.length;index+=2) next.push(sha(level[index],level[index+1]));
    level=next;
  }
  return level[0];
}
function headerFields(value,label) {
  const message=object(value,label);
  return {slot:decimal(message.slot,64,`${label} slot`),
    proposerIndex:decimal(message.proposer_index,64,`${label} proposer_index`),
    parentRoot:hash(message.parent_root,`${label} parent_root`),
    stateRoot:hash(message.state_root,`${label} state_root`),
    bodyRoot:hash(message.body_root,`${label} body_root`)};
}
function beaconHeaderRoot(header) {
  return '0x'+merkleize([uint64Root(header.slot),uint64Root(header.proposerIndex),
    bytes(header.parentRoot,hashPattern,'parent_root'),bytes(header.stateRoot,hashPattern,'state_root'),
    bytes(header.bodyRoot,hashPattern,'body_root'),Buffer.alloc(32),Buffer.alloc(32),Buffer.alloc(32)])
    .toString('hex');
}
function validateHeader(raw,{label,root,boundarySlot}) {
  const response=object(raw,`${label} header response`);
  if(bool(response.execution_optimistic,`${label} header execution_optimistic`)!==false
      ||bool(response.finalized,`${label} header finalized`)!==true) {
    throw new Error(`${label} header safety flags are unsafe`);
  }
  const data=object(response.data,`${label} header data`);
  if(hash(data.root,`${label} header root`)!==root) throw new Error(`${label} returned a different header root`);
  if(bool(data.canonical,`${label} header canonical`)!==true) throw new Error(`${label} checkpoint is not canonical`);
  const header=headerFields(object(object(data.header,`${label} signed header`).message,
    `${label} header message`),`${label} header`);
  if(header.slot>boundarySlot) throw new Error(`${label} checkpoint root is newer than its epoch boundary`);
  if(beaconHeaderRoot(header)!==root) throw new Error(`${label} header does not hash to checkpoint root`);
  return header;
}
function pubkeyRoot(value,label) {
  const raw=bytes(value,pubkeyPattern,label);
  if(raw.every(byte=>byte===0)) throw new Error(`${label} cannot be zero`);
  return sha(raw.subarray(0,32),Buffer.concat([raw.subarray(32),Buffer.alloc(16)]));
}
function validateBootstrap(raw,{label,root,header}) {
  const response=object(raw,`${label} bootstrap response`);
  const epoch=header.slot/32n;
  const expectedVersion=epoch>=411392n?'fulu':epoch>=364032n?'electra':epoch>=269568n?'deneb':
    epoch>=194048n?'capella':null;
  if(response.version!==expectedVersion) {
    throw new Error(`${label} bootstrap fork is unsupported by the Rust light client`);
  }
  const data=object(response.data,`${label} bootstrap data`);
  const bootstrapHeader=headerFields(object(object(data.header,`${label} bootstrap header`).beacon,
    `${label} bootstrap beacon header`),`${label} bootstrap beacon header`);
  if(beaconHeaderRoot(bootstrapHeader)!==root
      ||Object.keys(header).some(field=>bootstrapHeader[field]!==header[field])) {
    throw new Error(`${label} bootstrap header does not bind the checkpoint header`);
  }
  const committee=object(data.current_sync_committee,`${label} current sync committee`);
  if(!Array.isArray(committee.pubkeys)||committee.pubkeys.length!==512) {
    throw new Error(`${label} current sync committee must have 512 pubkeys`);
  }
  const pubkeyRoots=committee.pubkeys.map((value,index)=>pubkeyRoot(value,
    `${label} sync committee pubkey ${index}`));
  const committeeRoot=sha(merkleize(pubkeyRoots),pubkeyRoot(committee.aggregate_pubkey,
    `${label} aggregate sync committee pubkey`));
  const expectedDepth=response.version==='capella'||response.version==='deneb'?5:6;
  if(!Array.isArray(data.current_sync_committee_branch)
      ||data.current_sync_committee_branch.length!==expectedDepth) {
    throw new Error(`${label} sync committee branch is incompatible with the Rust light client fork`);
  }
  let derived=committeeRoot,index=22n;
  for(const [offset,node] of data.current_sync_committee_branch.entries()) {
    const sibling=bytes(hash(node,`${label} sync committee branch ${offset}`),hashPattern,'branch node');
    derived=(index&1n)===1n?sha(sibling,derived):sha(derived,sibling);
    index>>=1n;
  }
  if('0x'+derived.toString('hex')!==header.stateRoot) {
    throw new Error(`${label} sync committee proof is invalid`);
  }
}

/** Collect an exact finalized weak-subjectivity checkpoint from independent Beacon API operators. */
export async function collectEthereumCheckpointConsensus({sources,catalog,request=requestBeaconJson,
  nowUnix=Math.floor(Date.now()/1000)}={}) {
  if(!Array.isArray(sources)||sources.length<3||sources.length>5) {
    throw new Error('three to five independent Beacon API sources are required');
  }
  const normalized=sources.map((source,index)=>{
    if(!source||Object.keys(source).length!==2||!('operatorId' in source)||!('url' in source)) {
      throw new Error(`source ${index+1} must contain only operatorId and url`);
    }
    if(typeof source.operatorId!=='string'||!operatorPattern.test(source.operatorId)) {
      throw new Error(`source ${index+1} operatorId is invalid`);
    }
    const url=endpoint(source.url,`source ${index+1} URL`);
    return {operatorId:source.operatorId,url,origin:url.origin.toLowerCase(),
      hostname:url.hostname.toLowerCase()};
  });
  if(new Set(normalized.map(value=>value.operatorId)).size!==normalized.length
      ||new Set(normalized.map(value=>value.origin)).size!==normalized.length
      ||new Set(normalized.map(value=>value.hostname)).size!==normalized.length) {
    throw new Error('Beacon API operators, HTTPS origins and hostnames must be pairwise distinct');
  }
  const catalogRows=sourceCatalog(catalog);
  if(catalogRows.length!==normalized.length) throw new Error('source set does not match the fixed catalog');
  const actual=new Map(normalized.map(source=>[source.operatorId,
    keccak256(toUtf8Bytes(source.origin))]));
  if(catalogRows.some(row=>actual.get(row.operatorId)!==row.originKeccak256)) {
    throw new Error('source set does not match the fixed catalog');
  }
  const observed=await Promise.all(normalized.map(async source=>{
    const label=`Beacon operator ${source.operatorId}`;
    const genesis=await request(apiUrl(source.url,'/eth/v1/beacon/genesis'));
    validateGenesis(genesis,label);
    const first=validateFinality(await request(apiUrl(source.url,
      '/eth/v1/beacon/states/head/finality_checkpoints')),label);
    const boundarySlot=first.epoch*32n;
    const header=validateHeader(await request(apiUrl(source.url,
      `/eth/v1/beacon/headers/${first.root}`)),{label,root:first.root,boundarySlot});
    validateBootstrap(await request(apiUrl(source.url,
      `/eth/v1/beacon/light_client/bootstrap/${first.root}`)),{label,root:first.root,header});
    const second=validateFinality(await request(apiUrl(source.url,
      '/eth/v1/beacon/states/head/finality_checkpoints')),label);
    if(second.epoch!==first.epoch||second.root!==first.root) {
      throw new Error(`${label} finalized checkpoint changed during observation`);
    }
    return {operatorId:source.operatorId,origin:source.origin,epoch:first.epoch,root:first.root};
  }));
  const epoch=observed[0].epoch,root=observed[0].root;
  if(observed.some(value=>value.epoch!==epoch||value.root!==root)) {
    throw new Error('independent Beacon API sources disagree on the finalized checkpoint');
  }
  if(typeof nowUnix!=='bigint'&&(!Number.isSafeInteger(nowUnix)||nowUnix<=0)) {
    throw new Error('observedAtUnix must be a positive safe integer or bigint');
  }
  const observedAt=typeof nowUnix==='bigint'?nowUnix:BigInt(nowUnix);
  if(observedAt<=0n||observedAt>=(1n<<64n)) throw new Error('observedAtUnix is outside uint64');
  const genesis=BigInt(ETHEREUM_MAINNET_GENESIS_TIME);
  if(observedAt<genesis) throw new Error('local observation time predates Ethereum mainnet genesis');
  const currentSlot=(observedAt-genesis)/12n,boundarySlot=epoch*32n;
  if(boundarySlot>currentSlot||currentSlot-boundarySlot>MAX_CHECKPOINT_AGE_SLOTS) {
    throw new Error('finalized checkpoint is outside the conservative freshness window');
  }
  const sourceSetCommitment=ethereumCheckpointSourceCatalogCommitment(catalog);
  return Object.freeze({schema:ETHEREUM_CHECKPOINT_CONSENSUS_SCHEMA,network:'ethereum-mainnet',
    checkpointEpoch:epoch.toString(),checkpointSlot:(epoch*32n).toString(),checkpointRoot:root,
    sourceCount:observed.length.toString(),sourceSetCommitment,
    observedAtUnix:observedAt.toString()});
}
