import {getBytes,hexlify,keccak256} from 'ethers';
import {uint} from './reserve.mjs';

export const CHECKPOINT_CONTEXT_MAGIC='UDCCTX02';
export const CHECKPOINT_CONTEXT_VERSION=2;
export const CHECKPOINT_CONTEXT_BYTES=695;
export const CHECKPOINT_CONTEXT_MTP_HEADERS=11;
export const CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS=2;
export const CHECKPOINT_CONTEXT_MAX_SPAN=720n;
export const RANDOMX_SEED_INTERVAL=2048n;
export const RANDOMX_SEED_OFFSET=64n;
const ECONOMIC_STATE_DOMAIN=new TextEncoder().encode('DOM:checkpoint-economic-state:v1');

const zeroHash='0x'+'00'.repeat(32);
const contextFields=Object.freeze([
  'checkpointHeight','checkpointBlock','maxSpan','economicStateRoot','recentHeaders','seedAnchors',
]);
const headerFields=Object.freeze(['height','block','timestamp']);
const seedFields=Object.freeze(['height','block']);

function exact(input,fields,name) {
  if(!input || typeof input!=='object' || Array.isArray(input)
      || Object.keys(input).length!==fields.length || fields.some(field=>!(field in input))) {
    throw new Error(`exact ${name} fields required`);
  }
}

function hash(value,name) {
  if(typeof value!=='string' || !/^0x[0-9a-fA-F]{64}$/.test(value)
      || value.toLowerCase()===zeroHash) throw new Error(`${name} must be nonzero bytes32`);
  return value.toLowerCase();
}

function writeUint(target,offset,value,bytes) {
  let remaining=value;
  for(let index=bytes-1;index>=0;--index) {
    target[offset+index]=Number(remaining&0xffn);
    remaining>>=8n;
  }
  if(remaining!==0n) throw new Error('integer encoding overflow');
}

function writeHash(target,offset,value) { target.set(getBytes(value),offset); }

/** Bind exact UTXO-set and historical-kernel roots into one context field. */
export function checkpointEconomicStateRoot(utxoSetRoot,kernelSetRoot) {
  const utxo=hash(utxoSetRoot,'utxoSetRoot');
  const kernels=hash(kernelSetRoot,'kernelSetRoot');
  const preimage=new Uint8Array(ECONOMIC_STATE_DOMAIN.length+64);
  preimage.set(ECONOMIC_STATE_DOMAIN,0);
  preimage.set(getBytes(utxo),ECONOMIC_STATE_DOMAIN.length);
  preimage.set(getBytes(kernels),ECONOMIC_STATE_DOMAIN.length+32);
  return keccak256(preimage);
}

/** Historical RandomX seed heights that must be carried into the next proof. */
export function requiredHistoricalSeedHeights(checkpointHeight,maxSpan) {
  const height=uint(checkpointHeight,64);
  const span=uint(maxSpan,32);
  if(span===0n || span>CHECKPOINT_CONTEXT_MAX_SPAN) throw new Error('invalid checkpoint context span');
  if(height===(1n<<64n)-1n || height+span>=(1n<<64n)) throw new Error('checkpoint context height overflow');
  const firstEpoch=(height+1n)/RANDOMX_SEED_INTERVAL;
  const lastEpoch=(height+span)/RANDOMX_SEED_INTERVAL;
  const result=[];
  for(let epoch=firstEpoch;epoch<=lastEpoch;++epoch) {
    const seedHeight=epoch===0n?0n:epoch*RANDOMX_SEED_INTERVAL-RANDOMX_SEED_OFFSET;
    if(seedHeight!==0n && seedHeight<=height && result.at(-1)!==seedHeight) result.push(seedHeight);
  }
  if(result.length>CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS) throw new Error('too many seed anchors');
  return result;
}

/** Encode and commit the exact fixed-width UDCCTX02 checkpoint context. */
export function checkpointContext(input) {
  exact(input,contextFields,'checkpoint context');
  const checkpointHeight=uint(input.checkpointHeight,64);
  const checkpointBlock=hash(input.checkpointBlock,'checkpointBlock');
  const maxSpan=uint(input.maxSpan,32);
  const economicStateRoot=hash(input.economicStateRoot,'economicStateRoot');
  if(checkpointHeight<10n || !Array.isArray(input.recentHeaders)
      || input.recentHeaders.length!==CHECKPOINT_CONTEXT_MTP_HEADERS) {
    throw new Error('checkpoint context requires eleven recent headers');
  }
  const firstHeight=checkpointHeight-10n;
  const recentHeaders=input.recentHeaders.map((raw,index)=>{
    exact(raw,headerFields,`recentHeaders[${index}]`);
    const header={height:uint(raw.height,64),block:hash(raw.block,`recentHeaders[${index}].block`),
      timestamp:uint(raw.timestamp,64)};
    if(header.height!==firstHeight+BigInt(index)
        || (index>0 && header.timestamp<=uint(input.recentHeaders[index-1].timestamp,64))) {
      throw new Error('recent headers must have consecutive heights and increasing timestamps');
    }
    return header;
  });
  if(recentHeaders.at(-1).block!==checkpointBlock) throw new Error('recent headers do not end at checkpoint');

  const required=requiredHistoricalSeedHeights(checkpointHeight,maxSpan);
  if(!Array.isArray(input.seedAnchors) || input.seedAnchors.length!==required.length) {
    throw new Error('checkpoint context has the wrong seed anchor count');
  }
  const seedAnchors=input.seedAnchors.map((raw,index)=>{
    exact(raw,seedFields,`seedAnchors[${index}]`);
    const anchor={height:uint(raw.height,64),block:hash(raw.block,`seedAnchors[${index}].block`)};
    if(anchor.height!==required[index]) throw new Error('checkpoint context has the wrong seed height');
    const projected=recentHeaders.find(header=>header.height===anchor.height);
    if(projected && projected.block!==anchor.block) throw new Error('seed anchor disagrees with recent header');
    return anchor;
  });

  const encoded=new Uint8Array(CHECKPOINT_CONTEXT_BYTES);
  encoded.set(new TextEncoder().encode(CHECKPOINT_CONTEXT_MAGIC),0);
  writeUint(encoded,8,BigInt(CHECKPOINT_CONTEXT_VERSION),2);
  writeUint(encoded,10,checkpointHeight,8);
  writeHash(encoded,18,checkpointBlock);
  writeUint(encoded,50,maxSpan,4);
  writeHash(encoded,54,economicStateRoot);
  let cursor=86;
  for(const header of recentHeaders) {
    writeUint(encoded,cursor,header.height,8);
    writeHash(encoded,cursor+8,header.block);
    writeUint(encoded,cursor+40,header.timestamp,8);
    cursor+=48;
  }
  encoded[cursor]=seedAnchors.length;
  cursor+=1;
  for(let index=0;index<CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS;++index) {
    const anchor=seedAnchors[index];
    if(anchor) {
      writeUint(encoded,cursor,anchor.height,8);
      writeHash(encoded,cursor+8,anchor.block);
    }
    cursor+=40;
  }
  if(cursor!==CHECKPOINT_CONTEXT_BYTES) throw new Error('checkpoint context encoder length mismatch');
  return {checkpointHeight,checkpointBlock,maxSpan,economicStateRoot,recentHeaders,seedAnchors,
    encoded:hexlify(encoded),contextHash:keccak256(encoded)};
}
