import {Contract,keccak256,toUtf8Bytes} from 'ethers';
import {isIP} from 'node:net';
import {validateRiscZeroMainnetReference} from './risc0-verifier-reference.mjs';
import {validateRiscZeroHealthSourceCatalog} from './risc0-health-source-catalog.mjs';
import {BoundedMainnetPreflightProvider} from './mainnet-preflight-rpc.mjs';

const directAbi=['function SELECTOR() view returns (bytes4)','function VERSION() view returns (string)'];
const stopAbi=['function paused() view returns (bool)','function verifier() view returns (address)'];
const ETHEREUM_MAINNET_GENESIS=
  '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3';

function fail(message) { throw new Error(message); }

function exactObject(value,keys,label) {
  if(!value || typeof value!=='object' || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    fail(`${label} must contain exact fields`);
  }
  return value;
}

const codeHash=async(provider,address,blockTag)=>
  keccak256(await provider.send('eth_getCode',[address,blockTag]));

async function healthState(provider,trusted,finalizedTag) {
  const callOptions={blockTag:finalizedTag};
  const direct=new Contract(trusted.verifier_address,directAbi,provider);
  const stop=new Contract(trusted.emergency_stop_wrapper_address,stopAbi,provider);
  const [directCodeHash,selector,version,stopCodeHash,paused,verifier]=await Promise.all([
    codeHash(provider,trusted.verifier_address,finalizedTag),direct.SELECTOR(callOptions),
    direct.VERSION(callOptions),codeHash(provider,trusted.emergency_stop_wrapper_address,finalizedTag),
    stop.paused(callOptions),stop.verifier(callOptions),
  ]);
  return {riscZeroVerifier:{address:trusted.verifier_address,codeHash:directCodeHash,selector,version},
    riscZeroEmergencyStop:{address:trusted.emergency_stop_wrapper_address,codeHash:stopCodeHash,
      paused,verifier}};
}

export async function observeRiscZeroMainnetHealth({reference,provider}) {
  const trusted=validateRiscZeroMainnetReference(reference);
  if(!provider || typeof provider.send!=='function'
      ||typeof provider.pinFinalizedSnapshot!=='function') {
    fail('health observer requires a bounded snapshot-pinning RPC provider');
  }
  const [chainId,genesis,finalized]=await Promise.all([
    provider.send('eth_chainId',[]).then(BigInt),
    provider.send('eth_getBlockByNumber',['0x0',false]),
    provider.send('eth_getBlockByNumber',['finalized',false]),
  ]);
  if(chainId!==1n||genesis?.number!=='0x0'
      ||String(genesis?.hash??'').toLowerCase()!==ETHEREUM_MAINNET_GENESIS) {
    fail('RPC is not canonical Ethereum mainnet');
  }
  if(!finalized?.hash || !/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/.test(finalized.number??'')
      ||!/^0x[0-9a-fA-F]{64}$/.test(finalized.hash)) {
    fail('RPC did not return a canonical finalized block');
  }
  const {tag:finalizedTag}=provider.pinFinalizedSnapshot(finalized.number,finalized.hash);
  const before=await healthState(provider,trusted,finalizedTag);
  const [snapshotAfter,after]=await Promise.all([
    provider.send('eth_getBlockByNumber',[finalizedTag,false]),healthState(provider,trusted,finalizedTag),
  ]);
  if(snapshotAfter?.hash!==finalized.hash||JSON.stringify(before)!==JSON.stringify(after)) {
    fail('RISC Zero finalized health snapshot changed during collection');
  }
  return {chainId:chainId.toString(),genesisBlockHash:ETHEREUM_MAINNET_GENESIS,
    finalizedBlockNumber:BigInt(finalized.number).toString(),
    finalizedBlockHash:finalized.hash,snapshotBlockHashAfter:snapshotAfter?.hash??null,
    ...before};
}

export function reconcileRiscZeroHealthSources(sources) {
  if(!Array.isArray(sources)||sources.length<2||sources.length>4) {
    fail('two to four RISC Zero health source observations are required');
  }
  const canonical=sources.map(source=>JSON.stringify(source.observation));
  if(canonical.some(value=>value!==canonical[0])) {
    fail('cataloged RPCs disagree on the finalized RISC Zero health snapshot');
  }
  return sources;
}

export function riscZeroRpcEndpointHash(url) {
  let parsed;
  try { parsed=new URL(url); } catch { fail('RISC Zero health RPC endpoint must be a canonical HTTPS origin'); }
  if(typeof url!=='string'||url.length<8||url.length>4096||parsed.protocol!=='https:'
      ||parsed.username||parsed.password||parsed.search||parsed.hash||parsed.pathname!=='/'
      ||parsed.hostname.endsWith('.')||parsed.hostname==='localhost'
      ||parsed.hostname.endsWith('.localhost')||parsed.hostname.endsWith('.local')
      ||isIP(parsed.hostname)!==0||!parsed.hostname.includes('.')) {
    fail('RISC Zero health RPC endpoint must be a canonical HTTPS origin');
  }
  return keccak256(toUtf8Bytes(parsed.origin.toLowerCase()));
}

export async function collectRiscZeroHealthSources({reference,catalog,endpoints,
  providerFactory=url=>new BoundedMainnetPreflightProvider(url),
  observer=observeRiscZeroMainnetHealth}) {
  const approved=validateRiscZeroHealthSourceCatalog(catalog);
  if(!Array.isArray(endpoints) || endpoints.length!==approved.sources.length) {
    fail('one RPC endpoint is required for every approved health source');
  }
  const byId=new Map();
  for(let index=0;index<endpoints.length;index++) {
    const endpoint=exactObject(endpoints[index],['sourceId','url'],`RPC endpoint ${index}`);
    if(typeof endpoint.sourceId!=='string' || byId.has(endpoint.sourceId)) {
      fail('RPC endpoint source identities must be present and distinct');
    }
    byId.set(endpoint.sourceId,endpoint.url);
  }
  const resolved=approved.sources.map(identity=>{
    const url=byId.get(identity.sourceId);
    if(typeof url!=='string' || riscZeroRpcEndpointHash(url)!==identity.endpointHash) {
      fail(`RPC endpoint does not match approved source ${identity.sourceId}`);
    }
    return {identity,url};
  });
  const observations=await Promise.all(resolved.map(async({identity,url})=>{
    const provider=providerFactory(url,identity);
    try {
      const observation=await observer({reference,provider});
      return {...identity,observation};
    } catch(error) {
      const redacted=String(error?.message??error).split(url).join('[redacted RPC URL]');
      throw new Error(`health source ${identity.sourceId} failed: ${redacted}`);
    } finally {
      if(typeof provider?.destroy==='function') await provider.destroy();
    }
  }));
  return reconcileRiscZeroHealthSources(observations);
}
