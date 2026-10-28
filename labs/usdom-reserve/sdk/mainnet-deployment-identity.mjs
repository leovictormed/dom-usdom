import {createHash} from 'node:crypto';
import {getAddress,getCreateAddress,keccak256,toUtf8Bytes} from 'ethers';
import {rpcConsensusEvidence,validateRpcConsensusEvidence} from './rpc-consensus-evidence.mjs';

const roles=Object.freeze([
  {name:'finalizedBurnVerifier',deployerField:'verifierDeployer',nonceField:'verifierDeployerNonce',
    addressField:'verifier'},
  {name:'checkpointVerifier',deployerField:'checkpointVerifierDeployer',
    nonceField:'checkpointVerifierDeployerNonce',addressField:'checkpointVerifier'},
  {name:'checkpointRegistry',deployerField:'checkpointRegistryDeployer',
    nonceField:'checkpointRegistryDeployerNonce',addressField:'checkpointRegistry'},
  {name:'reserve',deployerField:'deployer',nonceField:'deployerNonce',addressField:'reserve'},
]);
const ETHEREUM_MAINNET_GENESIS_BLOCK_HASH=
  '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3';

function sha256Json(value) {
  return createHash('sha256').update(`${JSON.stringify(value,null,2)}\n`).digest('hex');
}
function observationHash(value) { return keccak256(toUtf8Bytes(JSON.stringify(value))); }
function setNullOrExact(target,field,value) {
  if(target[field]!==null&&target[field]!==value) {
    throw new Error(`${field} already differs from the derived deployment identity`);
  }
  target[field]=value;
}
function exactObject(value,keys,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    throw new Error(`${label} schema is invalid`);
  }
}
function decimalUint64(value,label) {
  if(typeof value!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(value)) {
    throw new Error(`${label} is not canonical uint64 decimal`);
  }
  const parsed=BigInt(value);
  if(parsed>2n**64n-1n) throw new Error(`${label} exceeds uint64`);
  return parsed;
}
function canonicalBlock(value,label) {
  if(typeof value==='string'&&/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(value)) return BigInt(value);
  return decimalUint64(value,label);
}

export function validateOrderedDeploymentChronology(deployments,{requireReceiptOrder=false}={}) {
  if(!Array.isArray(deployments)||deployments.length===0||deployments.length>roles.length) {
    throw new Error('deployment chronology is incomplete');
  }
  for(let index=0;index<deployments.length;index++) {
    const current=deployments[index];
    if(!current||current.name!==roles[index].name) {
      throw new Error('deployment chronology role order is invalid');
    }
    for(const [numberField,hashField] of [
      ['receiptBlockNumber','receiptBlockHash'],['finalizedBlockNumber','finalizedBlockHash'],
    ]) {
      if(current[numberField]===undefined) continue;
      const number=canonicalBlock(current[numberField],`${current.name} ${numberField}`);
      const hash=current[hashField];
      if(typeof hash!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(hash)) {
        throw new Error('deployment chronology block hash is invalid');
      }
      if(index===0||deployments[index-1][numberField]===undefined) continue;
      const previous=deployments[index-1];
      const previousNumber=canonicalBlock(previous[numberField],`${previous.name} ${numberField}`);
      if(number<previousNumber||(number===previousNumber
          &&hash.toLowerCase()!==previous[hashField].toLowerCase())) {
        throw new Error('deployment chronology is inconsistent with ordered nonces');
      }
    }
  }
  if(requireReceiptOrder) {
    for(let index=0;index<deployments.length;index++) {
      const current=deployments[index];
      const block=canonicalBlock(current.receiptBlockNumber,`${current.name} receipt block`);
      const transactionIndex=canonicalBlock(current.receiptTransactionIndex,
        `${current.name} receipt transaction index`);
      if(index===0) continue;
      const previous=deployments[index-1];
      const previousBlock=canonicalBlock(previous.receiptBlockNumber,
        `${previous.name} receipt block`);
      const previousTransactionIndex=canonicalBlock(previous.receiptTransactionIndex,
        `${previous.name} receipt transaction index`);
      if(block<previousBlock||(block===previousBlock&&transactionIndex<=previousTransactionIndex)) {
        throw new Error('deployment receipt chronology is inconsistent with ordered nonces');
      }
    }
  }
  return deployments;
}

export function validateMainnetDeploymentTopology(releaseConfig,{deployments}={}) {
  const plans=roles.map((role,index)=>{
    const from=getAddress(releaseConfig?.[role.deployerField]);
    if(BigInt(from)===0n) throw new Error('deployment account must not be zero');
    const nonce=decimalUint64(releaseConfig?.[role.nonceField],`${role.name} nonce`);
    const expectedContract=getAddress(releaseConfig?.[role.addressField]);
    if(BigInt(expectedContract)===0n
        ||getCreateAddress({from,nonce})!==expectedContract) {
      throw new Error(`${role.name} CREATE address differs from deployment topology`);
    }
    return {name:role.name,from,nonce,expectedContract,index};
  });
  const base=plans[0];
  for(const plan of plans) {
    if(plan.from!==base.from||plan.nonce!==base.nonce+BigInt(plan.index)) {
      throw new Error('deployment topology requires one deployer and four consecutive ordered nonces');
    }
  }
  if(deployments!==undefined) {
    const normalized=deployments.map((deployment,index)=>({name:roles[index].name,
      receiptBlockNumber:deployment?.receiptBlockNumber??deployment?.blockNumber,
      receiptBlockHash:deployment?.receiptBlockHash??deployment?.blockHash,
      finalizedBlockNumber:deployment?.finalizedBlockNumber,
      finalizedBlockHash:deployment?.finalizedBlockHash}));
    validateOrderedDeploymentChronology(normalized);
  }
  return plans;
}

export function deriveMainnetDeploymentIdentity({releaseConfig,deployer,baseNonce}) {
  if(!releaseConfig||typeof releaseConfig!=='object'||Array.isArray(releaseConfig)
      ||releaseConfig.productionReady!==false||releaseConfig.realFundsAuthorized!==false
      ||releaseConfig.ethereumChainId!=='1'||releaseConfig.deploymentMethod!=='CREATE') {
    throw new Error('deployment identity requires the unapproved mainnet CREATE template');
  }
  const address=getAddress(deployer);
  if(BigInt(address)===0n) throw new Error('deployment account must not be zero');
  let nonce;
  try { nonce=decimalUint64(baseNonce,'deployment base nonce'); }
  catch { throw new Error('deployment base nonce is outside uint64 bounds'); }
  if(nonce>2n**64n-4n) throw new Error('deployment base nonce is outside uint64 bounds');
  const result={...releaseConfig};
  const plans=roles.map((role,index)=>{
    const roleNonce=nonce+BigInt(index);
    const expectedContract=getCreateAddress({from:address,nonce:roleNonce});
    setNullOrExact(result,role.deployerField,address);
    setNullOrExact(result,role.nonceField,roleNonce.toString());
    setNullOrExact(result,role.addressField,expectedContract);
    return {name:role.name,from:address,nonce:roleNonce.toString(),expectedContract};
  });
  const configuredOwners=['governanceOwners','guardianOwners','checkpointGuardianOwners']
    .flatMap(field=>Array.isArray(releaseConfig[field])?releaseConfig[field]:[]);
  const identities=[address,...plans.map(plan=>plan.expectedContract),releaseConfig.token,
    releaseConfig.governance,releaseConfig.guardian,releaseConfig.checkpointGuardian,
    ...configuredOwners]
    .filter(value=>typeof value==='string').map(getAddress);
  if(new Set(identities).size!==identities.length) {
    throw new Error('deployment identity collides with a configured role or contract');
  }
  return {configuration:result,plans};
}

export async function observeMainnetDeploymentIdentity({releaseConfig,deployer,providers,sourceIds,
  sourceOriginCommitments}={}) {
  if(!Array.isArray(providers)||providers.length<2||providers.length>5
      ||new Set(providers).size!==providers.length) {
    throw new Error('two to five independent provider objects are required');
  }
  if(sourceIds===undefined) sourceIds=providers.map((_,index)=>`rpc-${index+1}`);
  if(!Array.isArray(sourceIds)||sourceIds.length!==providers.length
      ||sourceIds.some(value=>typeof value!=='string'||!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(value))
      ||new Set(sourceIds).size!==sourceIds.length) throw new Error('provider source identities are invalid');
  if(!Array.isArray(sourceOriginCommitments)||sourceOriginCommitments.length!==providers.length
      ||sourceOriginCommitments.some(value=>typeof value!=='string'
        ||!/^0x[0-9a-f]{64}$/.test(value)||BigInt(value)===0n)
      ||new Set(sourceOriginCommitments).size!==sourceOriginCommitments.length) {
    throw new Error('provider origin commitments are invalid');
  }
  const address=getAddress(deployer);
  const observations=[];
  for(let index=0;index<providers.length;index++) {
    const provider=providers[index];
    let network,genesis,finalized,finalizedNonce,pendingNonce,deployerCode;
    try {
      network=await provider.getNetwork();
      [genesis,finalized]=await Promise.all([provider.getBlock(0),provider.getBlock('finalized')]);
      if(!genesis||genesis.number!==0
          ||genesis.hash?.toLowerCase()!==ETHEREUM_MAINNET_GENESIS_BLOCK_HASH) {
        throw new Error('invalid Ethereum mainnet genesis');
      }
      if(!finalized||!Number.isSafeInteger(finalized.number)||finalized.number<0
          ||typeof finalized.hash!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(finalized.hash)) {
        throw new Error('invalid finalized block');
      }
      if(typeof provider.pinFinalizedSnapshot==='function') {
        provider.pinFinalizedSnapshot(finalized.number,finalized.hash,{allowPendingNonce:true});
      }
      [finalizedNonce,pendingNonce,deployerCode]=await Promise.all([
        provider.getTransactionCount(address,finalized.number),
        provider.getTransactionCount(address,'pending'),
        provider.getCode(address,finalized.number),
      ]);
    } catch {
      throw new Error(`RPC ${index+1} deployment-identity observation failed`);
    }
    if(network.chainId!==1n) throw new Error(`RPC ${index+1} is not Ethereum mainnet`);
    if(!Number.isSafeInteger(finalizedNonce)||finalizedNonce<0
        ||!Number.isSafeInteger(pendingNonce)||pendingNonce<0
        ||finalizedNonce!==pendingNonce||deployerCode!=='0x') {
      throw new Error(`RPC ${index+1} reports a busy nonce or non-EOA deployer`);
    }
    observations.push({source:sourceIds[index],originKeccak256:sourceOriginCommitments[index],
      genesisBlockHash:genesis.hash.toLowerCase(),
      finalizedBlockNumber:String(finalized.number),finalizedBlockHash:finalized.hash.toLowerCase(),
      finalizedNonce:String(finalizedNonce),pendingNonce:String(pendingNonce)});
  }
  if(observations.some(value=>value.finalizedNonce!==observations[0].finalizedNonce
      ||value.finalizedBlockNumber!==observations[0].finalizedBlockNumber
      ||value.finalizedBlockHash!==observations[0].finalizedBlockHash)) {
    throw new Error('deployment finalized snapshot or nonce disagrees across RPC sources');
  }
  const derived=deriveMainnetDeploymentIdentity({releaseConfig,deployer:address,
    baseNonce:observations[0].finalizedNonce});
  for(let index=0;index<providers.length;index++) {
    const provider=providers[index],block=Number(observations[index].finalizedBlockNumber);
    let codes,nonces,rechecked;
    try {
      [codes,nonces]=await Promise.all([
        Promise.all(derived.plans.map(plan=>provider.getCode(plan.expectedContract,block))),
        Promise.all(derived.plans.map(plan=>provider.getTransactionCount(plan.expectedContract,block))),
      ]);
      const fixed=await Promise.all([
        provider.getBlock(block),provider.getTransactionCount(address,block),
        provider.getTransactionCount(address,'pending'),provider.getCode(address,block),
      ]);
      const [plannedCodes,plannedNonces]=await Promise.all([
        Promise.all(derived.plans.map(plan=>provider.getCode(plan.expectedContract,block))),
        Promise.all(derived.plans.map(plan=>provider.getTransactionCount(plan.expectedContract,block))),
      ]);
      const [snapshot,finalizedNonce,pendingNonce,deployerCode]=fixed;
      rechecked={snapshot,finalizedNonce,pendingNonce,deployerCode,plannedCodes,plannedNonces};
    } catch {
      throw new Error(`RPC ${index+1} CREATE-address observation failed`);
    }
    if(codes.some(code=>code!=='0x')||nonces.some(nonce=>nonce!==0)) {
      throw new Error(`RPC ${index+1} reports an occupied CREATE address`);
    }
    if(!rechecked.snapshot||rechecked.snapshot.hash?.toLowerCase()!==observations[index].finalizedBlockHash
        ||rechecked.finalizedNonce!==Number(observations[index].finalizedNonce)
        ||rechecked.pendingNonce!==Number(observations[index].pendingNonce)
        ||rechecked.deployerCode!=='0x'||rechecked.plannedCodes.some(code=>code!=='0x')
        ||rechecked.plannedNonces.some(nonce=>nonce!==0)) {
      throw new Error(`RPC ${index+1} deployment-identity snapshot changed during observation`);
    }
  }
  const rpcConsensus=rpcConsensusEvidence(observations.map(value=>({sourceId:value.source,
    originKeccak256:value.originKeccak256})));
  const observation={schema:'usdom-mainnet-deployment-identity-observation-v1',chainId:'1',
    deployer:address,baseNonce:observations[0].finalizedNonce,plans:derived.plans,
    rpcConsensus,rpcObservations:observations,releaseConfigBefore:structuredClone(releaseConfig),
    releaseConfigBeforeSha256:sha256Json(releaseConfig),
    releaseConfigAfter:structuredClone(derived.configuration),
    releaseConfigAfterSha256:sha256Json(derived.configuration)};
  return {
    configuration:derived.configuration,
    observation:{...observation,observationHash:observationHash(observation)},
  };
}

export function validateMainnetDeploymentIdentityObservation({observation,releaseConfigAfter}={}) {
  const expected=['schema','chainId','deployer','baseNonce','plans','rpcConsensus','rpcObservations',
    'releaseConfigBefore','releaseConfigBeforeSha256','releaseConfigAfter','releaseConfigAfterSha256',
    'observationHash'];
  if(!observation||JSON.stringify(Object.keys(observation).sort())!==JSON.stringify(expected.sort())
      ||observation.schema!=='usdom-mainnet-deployment-identity-observation-v1'
      ||observation.chainId!=='1'||!Array.isArray(observation.rpcObservations)) {
    throw new Error('deployment identity observation schema is invalid');
  }
  const hash=observation?.observationHash,body={...observation}; delete body.observationHash;
  if(observationHash(body)!==hash) throw new Error('deployment identity observation hash mismatch');
  validateRpcConsensusEvidence(observation.rpcConsensus);
  if(observation.rpcObservations.length<2||observation.rpcObservations.length>5) {
    throw new Error('deployment identity RPC observation count is invalid');
  }
  const seenSources=new Set(),seenOrigins=new Set();
  for(const [index,value] of observation.rpcObservations.entries()) {
    exactObject(value,['source','originKeccak256','genesisBlockHash','finalizedBlockNumber','finalizedBlockHash',
      'finalizedNonce','pendingNonce'],`deployment identity RPC observation ${index}`);
    if(typeof value.source!=='string'||!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(value.source)
        ||seenSources.has(value.source)||typeof value.originKeccak256!=='string'
        ||!/^0x[0-9a-f]{64}$/.test(value.originKeccak256)||BigInt(value.originKeccak256)===0n
        ||seenOrigins.has(value.originKeccak256)
        ||value.genesisBlockHash!==ETHEREUM_MAINNET_GENESIS_BLOCK_HASH
        ||!/^0x[0-9a-f]{64}$/.test(value.finalizedBlockHash)) {
      throw new Error(`deployment identity RPC observation ${index} identity is invalid`);
    }
    decimalUint64(value.finalizedBlockNumber,`RPC observation ${index} finalized block`);
    decimalUint64(value.finalizedNonce,`RPC observation ${index} finalized nonce`);
    decimalUint64(value.pendingNonce,`RPC observation ${index} pending nonce`);
    seenSources.add(value.source); seenOrigins.add(value.originKeccak256);
  }
  const releaseConfigBefore=observation.releaseConfigBefore;
  if(sha256Json(releaseConfigBefore)!==observation.releaseConfigBeforeSha256
      ||sha256Json(observation.releaseConfigAfter)!==observation.releaseConfigAfterSha256) {
    throw new Error('deployment identity configuration SHA mismatch');
  }
  const derived=deriveMainnetDeploymentIdentity({releaseConfig:releaseConfigBefore,
    deployer:observation.deployer,baseNonce:observation.baseNonce});
  if(JSON.stringify(derived.configuration)!==JSON.stringify(observation.releaseConfigAfter)
      ||JSON.stringify(derived.plans)!==JSON.stringify(observation.plans)) {
    throw new Error('deployment identity CREATE plan mismatch');
  }
  for(const field of ['ethereumChainId','deploymentMethod','verifierDeployer','verifierDeployerNonce',
    'verifier','checkpointVerifierDeployer','checkpointVerifierDeployerNonce','checkpointVerifier',
    'checkpointRegistryDeployer','checkpointRegistryDeployerNonce','checkpointRegistry','deployer',
    'deployerNonce','reserve']) {
    if(releaseConfigAfter!==undefined&&releaseConfigAfter?.[field]!==observation.releaseConfigAfter[field]) {
      throw new Error(`deployment identity configured ${field} mismatch`);
    }
  }
  const sources=observation.rpcObservations.map(value=>({sourceId:value.source,
    originKeccak256:value.originKeccak256}));
  if(observation.rpcObservations.some(value=>value.finalizedNonce!==observation.baseNonce
      ||value.pendingNonce!==observation.baseNonce
      ||value.genesisBlockHash!==observation.rpcObservations[0].genesisBlockHash
      ||value.finalizedBlockNumber!==observation.rpcObservations[0].finalizedBlockNumber
      ||value.finalizedBlockHash!==observation.rpcObservations[0].finalizedBlockHash)) {
    throw new Error('deployment identity RPC nonce mismatch');
  }
  if(JSON.stringify(rpcConsensusEvidence(sources))!==JSON.stringify(observation.rpcConsensus)) {
    throw new Error('deployment identity RPC catalog mismatch');
  }
  return observation;
}
