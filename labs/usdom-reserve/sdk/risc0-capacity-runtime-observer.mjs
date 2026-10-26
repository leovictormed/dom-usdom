import {createHash} from 'node:crypto';
import {getAddress,keccak256} from 'ethers';
import {validateRiscZeroMainnetReference} from './risc0-verifier-reference.mjs';

const sourcePattern=/^[a-z][a-z0-9-]{0,31}$/;

function fail(message) { throw new Error(message); }

function sourceIdentity(value,index) {
  if(!value || typeof value!=='object' || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort())!==JSON.stringify(['sourceId','url'])) {
    fail(`capacity source ${index} must contain exact fields`);
  }
  if(typeof value.sourceId!=='string' || !sourcePattern.test(value.sourceId)) {
    fail(`capacity source ${index} ID is invalid`);
  }
  let parsed;
  try { parsed=new URL(value.url); } catch { fail(`capacity source ${index} URL is invalid`); }
  if(parsed.protocol!=='https:' || parsed.username!=='' || parsed.password!==''
      || parsed.hash!=='' || parsed.hostname.length===0) {
    fail(`capacity source ${index} must use a credential-free HTTPS URL`);
  }
  return {sourceId:value.sourceId,url:parsed.href,
    endpointSha256:createHash('sha256').update(parsed.href).digest('hex')};
}

function block(value,label) {
  if(!value || typeof value!=='object' || Array.isArray(value)
      || typeof value.number!=='string' || !/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/.test(value.number)
      || BigInt(value.number)===0n || typeof value.hash!=='string'
      || !/^0x[0-9a-fA-F]{64}$/.test(value.hash)
      || value.hash.toLowerCase()==='0x'+'00'.repeat(32)) {
    fail(`${label} is not a canonical Ethereum block`);
  }
  return {number:BigInt(value.number),hash:value.hash.toLowerCase()};
}

function runtime(value,label) {
  if(typeof value!=='string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(value)
      || value.length>2+128*1024*2) fail(`${label} is not bounded EVM bytecode`);
  return value.toLowerCase();
}

/**
 * Collect the exact pinned direct-verifier runtime at one block that every
 * source already regards as finalized. Sources are transport redundancy for a
 * local capacity check; they are not promoted to production operators.
 */
export async function observePinnedRiscZeroRuntime({reference,sources,rpc}) {
  const trusted=validateRiscZeroMainnetReference(reference);
  if(!Array.isArray(sources) || sources.length<2 || sources.length>4) {
    fail('two to four capacity runtime sources are required');
  }
  if(typeof rpc!=='function') fail('capacity runtime observer requires an RPC function');
  const identities=sources.map(sourceIdentity);
  if(JSON.stringify(identities.map(value=>value.sourceId))
      !==JSON.stringify([...identities.map(value=>value.sourceId)].sort())
      || new Set(identities.map(value=>value.sourceId)).size!==identities.length
      || new Set(identities.map(value=>value.url)).size!==identities.length
      || new Set(identities.map(value=>value.endpointSha256)).size!==identities.length) {
    fail('capacity sources must be ordered and distinct');
  }
  const heads=await Promise.all(identities.map(async source=>{
    const [chainId,finalized]=await Promise.all([
      rpc({source,method:'eth_chainId',params:[]}),
      rpc({source,method:'eth_getBlockByNumber',params:['finalized',false]}),
    ]);
    if(chainId!=='0x1') fail(`capacity source ${source.sourceId} is not Ethereum mainnet`);
    return {source,finalized:block(finalized,`capacity source ${source.sourceId} finalized head`)};
  }));
  const commonNumber=heads.map(value=>value.finalized.number).reduce(
    (left,right)=>left<right?left:right,
  );
  const commonTag='0x'+commonNumber.toString(16);
  const observations=await Promise.all(heads.map(async({source})=>{
    const [commonBlock,code]=await Promise.all([
      rpc({source,method:'eth_getBlockByNumber',params:[commonTag,false]}),
      rpc({source,method:'eth_getCode',params:[trusted.verifier_address,commonTag]}),
    ]);
    const observedBlock=block(commonBlock,`capacity source ${source.sourceId} common block`);
    if(observedBlock.number!==commonNumber) fail('capacity source returned the wrong common block');
    return {source,block:observedBlock,code:runtime(code,`capacity source ${source.sourceId} runtime`)};
  }));
  if(new Set(observations.map(value=>value.block.hash)).size!==1
      || new Set(observations.map(value=>value.code)).size!==1) {
    fail('capacity sources disagree on the finalized block or verifier runtime');
  }
  const code=observations[0].code;
  const codeHash=keccak256(code);
  if(codeHash.toLowerCase()!==trusted.observed_runtime_code_hash.toLowerCase()) {
    fail('observed direct verifier runtime differs from the reviewed pin');
  }
  return Object.freeze({
    ethereumChainId:'1',riscZeroVerifier:getAddress(trusted.verifier_address),
    runtimeCode:code,runtimeCodeHash:codeHash.toLowerCase(),
    finalizedBlockNumber:commonNumber.toString(),
    finalizedBlockHash:observations[0].block.hash,
    sourceIds:Object.freeze(identities.map(value=>value.sourceId)),
    endpointSha256:Object.freeze(identities.map(value=>value.endpointSha256)),
  });
}
