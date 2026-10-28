import {createHash} from 'node:crypto';
import {keccak256} from 'ethers';

const contracts=Object.freeze([
  'USDOMProofReserve','DOMCheckpointRegistry',
  'DOMFinalizedBurnRiscZeroVerifier','DOMCheckpointRiscZeroVerifier',
]);

function stable(value) {
  if(Array.isArray(value)) return value.map(stable);
  if(value&&typeof value==='object') return Object.fromEntries(
    Object.keys(value).sort().map(key=>[key,stable(value[key])]));
  return value;
}
const sha=value=>createHash('sha256').update(
  typeof value==='string'?value:JSON.stringify(stable(value))).digest('hex');
function object(value,label) {
  if(typeof value!=='string'||!/^0x[0-9a-f]*$/.test(value)||value.length%2) {
    throw new Error(`${label} is malformed`);
  }
  return value;
}

export const PRODUCTION_SOLIDITY_CONTRACTS=contracts;

export function solidityArtifactFingerprint(artifact,label='artifact') {
  if(!artifact||typeof artifact!=='object'||Array.isArray(artifact)) throw new Error(`${label} is malformed`);
  if(!Array.isArray(artifact.abi)||!artifact.storageLayout
      ||!Array.isArray(artifact.storageLayout.storage)||!artifact.storageLayout.types) {
    throw new Error(`${label} lacks ABI or storage layout`);
  }
  const sources=artifact.metadata?.sources;
  if(!sources||typeof sources!=='object'||Array.isArray(sources)||!Object.keys(sources).length) {
    throw new Error(`${label} lacks source hashes`);
  }
  const sourceHashes=Object.fromEntries(Object.entries(sources).sort(([a],[b])=>a.localeCompare(b)).map(
    ([name,value])=>{
      if(!/^0x[0-9a-f]{64}$/.test(value?.keccak256??'')) throw new Error(`${label} source hash is malformed`);
      return [name,value.keccak256];
    }));
  const initcode=object(artifact.bytecode?.object,`${label} initcode`);
  const runtime=object(artifact.deployedBytecode?.object,`${label} runtime`);
  return Object.freeze({
    initcodeKeccak256:keccak256(initcode),runtimeKeccak256:keccak256(runtime),
    abiSha256:sha(artifact.abi),storageLayoutSha256:sha(artifact.storageLayout),
    sourceHashesSha256:sha(sourceHashes),sourceHashes,
  });
}

export function assertSolidityBuildsEqual(first,second) {
  for(const contract of contracts) {
    if(JSON.stringify(first?.[contract])!==JSON.stringify(second?.[contract])) {
      throw new Error(`isolated Solidity builds differ: ${contract}`);
    }
  }
  return true;
}
