import {keccak256,toUtf8Bytes} from 'ethers';
import {isIP} from 'node:net';

export const FINALIZED_DEPOSIT_SOURCE_CATALOG_SCHEMA='usdom-finalized-deposit-source-catalog-v1';

function fail(message) { throw new Error(message); }
function origin(url,label) {
  if(typeof url!=='string'||url.length<10||url.length>4096) fail(`${label} URL is invalid`);
  let parsed;
  try { parsed=new URL(url); } catch { fail(`${label} URL is invalid`); }
  if(parsed.protocol!=='https:'||parsed.username||parsed.password||parsed.hash) {
    fail(`${label} URL must use HTTPS without userinfo or fragment`);
  }
  const hostname=parsed.hostname.toLowerCase();
  const unbracketed=hostname.startsWith('[')&&hostname.endsWith(']')?hostname.slice(1,-1):hostname;
  if(hostname.endsWith('.')||hostname==='localhost'||hostname.endsWith('.localhost')
      ||hostname.endsWith('.local')||isIP(unbracketed)!==0||!hostname.includes('.')) {
    fail(`${label} URL must use a canonical public DNS hostname`);
  }
  return parsed.origin.toLowerCase();
}
function hashOrigin(value) { return keccak256(toUtf8Bytes(value)); }
function operatorId(value) {
  if(typeof value!=='string'||!/^[-a-z0-9_]{3,64}$/.test(value)) fail('operatorId is invalid');
  return value;
}
function hash(value,label) {
  if(typeof value!=='string'||!/^0x[0-9a-f]{64}$/.test(value)) fail(`${label} is invalid`);
  return value;
}

export function validateFinalizedDepositSourceCatalog(catalog) {
  if(!catalog||![Object.prototype,null].includes(Object.getPrototypeOf(catalog))
      ||Object.keys(catalog).sort().join(',')!=='schema,sources'
      ||catalog.schema!==FINALIZED_DEPOSIT_SOURCE_CATALOG_SCHEMA
      ||!Array.isArray(catalog.sources)||catalog.sources.length<2||catalog.sources.length>5) {
    fail('finalized-deposit source catalog is invalid');
  }
  let previous=''; const operators=new Set(),execution=new Set(),beacon=new Set();
  for(const item of catalog.sources) {
    if(!item||![Object.prototype,null].includes(Object.getPrototypeOf(item))
        ||Object.keys(item).sort().join(',')!=='beaconOriginKeccak256,executionOriginKeccak256,operatorId') {
      fail('finalized-deposit catalog entry is invalid');
    }
    operatorId(item.operatorId); hash(item.executionOriginKeccak256,'execution origin hash');
    hash(item.beaconOriginKeccak256,'Beacon origin hash');
    if(item.operatorId<=previous||operators.has(item.operatorId)
        ||execution.has(item.executionOriginKeccak256)||beacon.has(item.beaconOriginKeccak256)) {
      fail('finalized-deposit catalog sources must be sorted and independent');
    }
    previous=item.operatorId; operators.add(item.operatorId);
    execution.add(item.executionOriginKeccak256); beacon.add(item.beaconOriginKeccak256);
  }
  return catalog;
}

export function finalizedDepositSourceSetCommitment(catalog) {
  validateFinalizedDepositSourceCatalog(catalog);
  return keccak256(toUtf8Bytes(
    `USDOM_FINALIZED_DEPOSIT_RPC_SOURCES_V1\n${catalog.sources.map(source=>
      `${source.operatorId}\u0000${source.executionOriginKeccak256}\u0000${source.beaconOriginKeccak256}`
    ).join('\n')}`));
}

export function buildFinalizedDepositSourceCatalog(runtimeSources) {
  if(!Array.isArray(runtimeSources)) fail('runtime finalized-deposit sources must be an array');
  const executionHostnames=[],beaconHostnames=[];
  const sources=runtimeSources.map(item=>{
    if(!item||![Object.prototype,null].includes(Object.getPrototypeOf(item))
        ||Object.keys(item).sort().join(',')!=='beaconUrl,executionUrl,operatorId') {
      fail('runtime finalized-deposit source schema is invalid');
    }
    const execution=new URL(item.executionUrl),beacon=new URL(item.beaconUrl);
    executionHostnames.push(execution.hostname.toLowerCase());
    beaconHostnames.push(beacon.hostname.toLowerCase());
    return {operatorId:operatorId(item.operatorId),
      executionOriginKeccak256:hashOrigin(origin(item.executionUrl,'execution')),
      beaconOriginKeccak256:hashOrigin(origin(item.beaconUrl,'Beacon'))};
  }).sort((a,b)=>a.operatorId<b.operatorId?-1:a.operatorId>b.operatorId?1:0);
  if(new Set(executionHostnames).size!==executionHostnames.length
      ||new Set(beaconHostnames).size!==beaconHostnames.length) {
    fail('finalized-deposit sources must use independent execution and Beacon hostnames');
  }
  return validateFinalizedDepositSourceCatalog({schema:FINALIZED_DEPOSIT_SOURCE_CATALOG_SCHEMA,sources});
}

export function matchFinalizedDepositSourceCatalog(catalog,runtimeSources) {
  validateFinalizedDepositSourceCatalog(catalog);
  const built=buildFinalizedDepositSourceCatalog(runtimeSources);
  if(JSON.stringify(built)!==JSON.stringify(catalog)) fail('runtime finalized-deposit sources do not match catalog');
  const byId=new Map(runtimeSources.map(item=>[item.operatorId,item]));
  return catalog.sources.map(({operatorId})=>{
    const item=byId.get(operatorId);
    origin(item.executionUrl,'execution'); origin(item.beaconUrl,'Beacon');
    return {operatorId,executionUrl:item.executionUrl,beaconUrl:item.beaconUrl};
  });
}

export function reconcileFinalizedDepositObservations(observations) {
  if(!Array.isArray(observations)||observations.length<2||observations.length>5) {
    fail('two to five finalized-deposit observations are required');
  }
  const first=JSON.stringify(observations[0]);
  if(observations.some(value=>JSON.stringify(value)!==first)) {
    fail('cataloged finalized-deposit sources disagree');
  }
  return observations[0];
}
