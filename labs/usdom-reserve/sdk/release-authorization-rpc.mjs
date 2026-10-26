import {getAddress,keccak256} from 'ethers';
import {collectReleaseAuthorizationApproval} from './release-authorization.mjs';
import {collectNativeAttestationApprovals} from './native-release-attestation.mjs';
import {BoundedMainnetPreflightProvider,matchMainnetPreflightRpcSources}
  from './mainnet-preflight-rpc.mjs';
import {rpcConsensusEvidence} from './rpc-consensus-evidence.mjs';

function fail(message) { throw new Error(message); }
function canonical(value) {
  if(Array.isArray(value)) return value.map(canonical);
  if(value&&typeof value==='object') return Object.fromEntries(
    Object.keys(value).sort().map(key=>[key,canonical(value[key])]),
  );
  return value;
}
function same(values) {
  const first=JSON.stringify(canonical(values[0]));
  return values.every(value=>JSON.stringify(canonical(value))===first);
}
async function anchor(provider,releaseConfig) {
  const [chainId,finalized]=await Promise.all([
    provider.send('eth_chainId',[]),provider.send('eth_getBlockByNumber',['finalized',false]),
  ]);
  if(BigInt(chainId).toString()!==releaseConfig.ethereumChainId||!finalized?.hash
      ||!/^0x[0-9a-fA-F]{64}$/.test(finalized.hash)||!/^0x[0-9a-fA-F]+$/.test(finalized.number??'')
      ||!/^0x[0-9a-fA-F]+$/.test(finalized.timestamp??'')) fail('RPC finalized anchor is invalid');
  const governance=getAddress(releaseConfig.governance),tag=finalized.number;
  const code=await provider.send('eth_getCode',[governance,tag]);
  if(!/^0x(?:[0-9a-fA-F]{2})+$/.test(code??'')) fail('finalized governance code is invalid');
  const codeHash=keccak256(code);
  if(codeHash.toLowerCase()!==String(releaseConfig.governanceCodeHash).toLowerCase()) {
    fail('finalized governance runtime differs from release');
  }
  const [blockAfter,codeAfter]=await Promise.all([
    provider.send('eth_getBlockByNumber',[tag,false]),provider.send('eth_getCode',[governance,tag]),
  ]);
  if(blockAfter?.hash?.toLowerCase()!==finalized.hash.toLowerCase()
      ||String(codeAfter).toLowerCase()!==String(code).toLowerCase()) {
    fail('finalized authorization anchor changed during collection');
  }
  return {blockNumber:BigInt(tag).toString(),blockHash:finalized.hash.toLowerCase(),
    blockTimestamp:BigInt(finalized.timestamp).toString(),governance,governanceCodeHash:codeHash.toLowerCase()};
}

export function resolveReleaseAuthorizationRpcSources({catalog,runtimeSources}) {
  return matchMainnetPreflightRpcSources(catalog,runtimeSources);
}

export async function withReleaseAuthorizationProviders(sources,operation) {
  if(!Array.isArray(sources)||sources.length<2||sources.length>5) fail('two to five RPC sources are required');
  const providers=sources.map(source=>new BoundedMainnetPreflightProvider(source.url));
  try { return await operation(providers); }
  catch(error) {
    let message=String(error?.message??error);
    for(const source of sources) message=message.split(source.url).join('[redacted RPC URL]');
    throw new Error(message);
  } finally { for(const provider of providers) provider.destroy(); }
}

export async function collectReleaseAuthorizationAnchor({providers,releaseConfig,sources}) {
  if(!Array.isArray(providers)||providers.length<2||providers.length>5) fail('two to five providers are required');
  if(!Array.isArray(sources)||sources.length!==providers.length) fail('RPC source identities must match providers');
  const anchors=await Promise.all(providers.map(provider=>anchor(provider,releaseConfig)));
  if(!same(anchors)) fail('cataloged RPCs disagree on the finalized authorization anchor');
  return {...anchors[0],rpcConsensus:rpcConsensusEvidence(sources)};
}

export function validateReleaseSigningNetworkObservation({authorized,observed}={}) {
  if(!authorized||!observed) fail('authorized and observed finalized anchors are required');
  let authorizedBlock,observedBlock;
  try {
    authorizedBlock=BigInt(authorized.blockNumber);
    observedBlock=BigInt(observed.blockNumber);
  } catch { fail('finalized anchor block number is invalid'); }
  if(getAddress(authorized.governance)!==getAddress(observed.governance)
      ||String(authorized.governanceCodeHash).toLowerCase()
        !==String(observed.governanceCodeHash).toLowerCase()
      ||!same([authorized.rpcConsensus,observed.rpcConsensus])
      ||observedBlock<authorizedBlock) {
    fail('current finalized governance observation differs from signing authorization');
  }
  return {governance:getAddress(observed.governance),blockNumber:observedBlock.toString()};
}

export async function collectReleaseAuthorizationApprovalConsensus({providers,releaseConfig,
  authorization,sources}) {
  if(!Array.isArray(providers)||providers.length<2||providers.length>5) fail('two to five providers are required');
  if(!Array.isArray(sources)||sources.length!==providers.length) fail('RPC source identities must match providers');
  const observations=await Promise.all(providers.map(async provider=>{
    const before=await collectReleaseAuthorizationApproval({provider,releaseConfig,authorization});
    if(before.finalizedBlockHash!==before.snapshotBlockHashAfter
        ||before.governanceCodeHash.toLowerCase()!==releaseConfig.governanceCodeHash.toLowerCase()
        ||before.approvals?.releaseAuthorization?.valid!==true) {
      fail('finalized EIP-1271 observation is invalid or unstable');
    }
    const after=await collectReleaseAuthorizationApproval({provider,releaseConfig,authorization});
    if(!same([before,after])) fail('finalized EIP-1271 observation changed during collection');
    return before;
  }));
  if(!same(observations)) fail('cataloged RPCs disagree on finalized EIP-1271 authorization');
  return {...observations[0],rpcConsensus:rpcConsensusEvidence(sources)};
}

export async function collectNativeAttestationApprovalConsensus({providers,releaseConfig,
  attestations,sources}) {
  if(!Array.isArray(providers)||providers.length<2||providers.length>5) fail('two to five providers are required');
  if(!Array.isArray(sources)||sources.length!==providers.length) fail('RPC source identities must match providers');
  const names=Object.keys(attestations??{});
  if(names.length===0) fail('native attestations are required');
  const observations=await Promise.all(providers.map(async provider=>{
    const before=await collectNativeAttestationApprovals({provider,releaseConfig,attestations});
    if(before.finalizedBlockHash!==before.snapshotBlockHashAfter
        ||before.governanceCodeHash.toLowerCase()!==releaseConfig.governanceCodeHash.toLowerCase()
        ||names.some(name=>before.approvals?.[name]?.valid!==true)) {
      fail('finalized native EIP-1271 observation is invalid or unstable');
    }
    const after=await collectNativeAttestationApprovals({provider,releaseConfig,attestations});
    if(!same([before,after])) fail('finalized native EIP-1271 observation changed during collection');
    return before;
  }));
  if(!same(observations)) fail('cataloged RPCs disagree on finalized native EIP-1271 attestations');
  return {...observations[0],rpcConsensus:rpcConsensusEvidence(sources)};
}
