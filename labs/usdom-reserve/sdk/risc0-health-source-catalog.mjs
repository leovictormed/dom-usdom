import {keccak256,toUtf8Bytes} from 'ethers';

export const RISC0_HEALTH_SOURCE_CATALOG_SCHEMA='usdom-risc0-health-source-catalog/v2';

const hashPattern=/^0x[0-9a-fA-F]{64}$/;
const zeroHash='0x'+'00'.repeat(32);

function fail(message) { throw new Error(message); }

function exactObject(value,keys,label) {
  if(!value || typeof value!=='object' || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    fail(`${label} must contain exact fields`);
  }
  return value;
}

function identity(value,index) {
  exactObject(value,['sourceId','operatorId','providerId','infrastructureId','endpointHash'],
    `health source ${index}`);
  for(const [field,label] of [['sourceId','source'],['operatorId','operator'],
    ['providerId','provider'],['infrastructureId','infrastructure']]) {
    if(typeof value[field]!=='string' || !/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(value[field])) {
      fail(`health source ${index} ${label} identity is invalid`);
    }
  }
  if(typeof value.endpointHash!=='string' || !hashPattern.test(value.endpointHash)
      || value.endpointHash.toLowerCase()===zeroHash) {
    fail(`health source ${index} endpoint hash must be a nonzero bytes32`);
  }
  return {sourceId:value.sourceId,operatorId:value.operatorId,providerId:value.providerId,
    infrastructureId:value.infrastructureId,
    endpointHash:value.endpointHash.toLowerCase()};
}

function body(value) {
  if(value.schema!==RISC0_HEALTH_SOURCE_CATALOG_SCHEMA) fail('health source catalog schema mismatch');
  if(value.ethereumChainId!=='1') fail('health source catalog must target Ethereum mainnet');
  if(!Array.isArray(value.sources) || value.sources.length<2 || value.sources.length>4) {
    fail('health source catalog requires two to four sources');
  }
  const sources=value.sources.map(identity);
  if(JSON.stringify(sources)!==JSON.stringify([...sources].sort(
    (left,right)=>left.sourceId.localeCompare(right.sourceId)))) {
    fail('health source catalog must be sorted by source identity');
  }
  for(const [field,label] of [['sourceId','source identities'],['operatorId','operator identities'],
    ['providerId','provider identities'],['infrastructureId','infrastructure identities'],
    ['endpointHash','endpoint hashes']]) {
    if(new Set(sources.map(source=>source[field])).size!==sources.length) {
      fail(`health source catalog ${label} must be distinct`);
    }
  }
  return {schema:RISC0_HEALTH_SOURCE_CATALOG_SCHEMA,ethereumChainId:'1',sources};
}

export function riscZeroHealthSourceCatalogHash(value) {
  return keccak256(toUtf8Bytes(JSON.stringify(body(value))));
}

export function createRiscZeroHealthSourceCatalog({sources}) {
  const value={schema:RISC0_HEALTH_SOURCE_CATALOG_SCHEMA,ethereumChainId:'1',sources};
  return {...body(value),catalogHash:riscZeroHealthSourceCatalogHash(value)};
}

export function validateRiscZeroHealthSourceCatalog(value) {
  exactObject(value,['schema','ethereumChainId','sources','catalogHash'],'health source catalog');
  const normalized=body(value);
  if(typeof value.catalogHash!=='string' || !hashPattern.test(value.catalogHash)
      || value.catalogHash.toLowerCase()!==riscZeroHealthSourceCatalogHash(normalized)) {
    fail('health source catalog hash mismatch');
  }
  return {...normalized,catalogHash:value.catalogHash.toLowerCase()};
}
