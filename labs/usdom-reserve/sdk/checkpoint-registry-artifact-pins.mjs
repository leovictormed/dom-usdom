import {createHash} from 'node:crypto';
import {parseStrictJsonBytes} from './strict-json.mjs';

const bytes32=/^0x[0-9a-f]{64}$/;
const sha=/^[0-9a-f]{64}$/;
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());

export function buildCheckpointRegistryArtifactPins({binding,artifactSha256,releaseConfigSha256}) {
  const report={schema:'usdom-checkpoint-registry-artifact-pins/v1',
    artifactPath:'out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json',artifactSha256,
    releaseConfigPath:'config/proof-reserve.unconfigured.json',releaseConfigSha256,
    runtimeCodeHash:binding.runtimeCodeHash.toLowerCase(),runtimeSize:binding.runtimeSize,
    initcodeHash:binding.initcodeHash.toLowerCase(),initcodeSize:binding.initcodeSize,
    checkpointRegistryConfigHash:binding.checkpointRegistryConfigHash.toLowerCase(),
    compilerVersion:binding.compilerVersion,sourceCount:binding.sourceCount};
  validateCheckpointRegistryArtifactPins(report);
  return Object.freeze(report);
}

export function validateCheckpointRegistryArtifactPins(value,{reportBytes,binding,artifactBytes,releaseConfigBytes,artifactSha256,releaseConfigSha256}={}) {
  const keys=['schema','artifactPath','artifactSha256','releaseConfigPath','releaseConfigSha256',
    'runtimeCodeHash','runtimeSize','initcodeHash','initcodeSize','checkpointRegistryConfigHash',
    'compilerVersion','sourceCount'];
  if(!exact(value,keys)||value.schema!=='usdom-checkpoint-registry-artifact-pins/v1'
      ||value.artifactPath!=='out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json'
      ||value.releaseConfigPath!=='config/proof-reserve.unconfigured.json'
      ||!sha.test(value.artifactSha256)||!sha.test(value.releaseConfigSha256)
      ||!bytes32.test(value.runtimeCodeHash)||!bytes32.test(value.initcodeHash)
      ||!bytes32.test(value.checkpointRegistryConfigHash)
      ||!Number.isSafeInteger(value.runtimeSize)||value.runtimeSize<=0
      ||!Number.isSafeInteger(value.initcodeSize)||value.initcodeSize<=0
      ||typeof value.compilerVersion!=='string'||!Number.isSafeInteger(value.sourceCount)||value.sourceCount<=0) {
    throw new Error('checkpoint registry artifact pins report is invalid');
  }
  if(binding&&(value.runtimeCodeHash!==binding.runtimeCodeHash.toLowerCase()
      ||value.initcodeHash!==binding.initcodeHash.toLowerCase()
      ||value.checkpointRegistryConfigHash!==binding.checkpointRegistryConfigHash.toLowerCase()
      ||value.runtimeSize!==binding.runtimeSize||value.initcodeSize!==binding.initcodeSize
      ||value.compilerVersion!==binding.compilerVersion||value.sourceCount!==binding.sourceCount)) {
    throw new Error('checkpoint registry artifact pins differ from current compiled binding');
  }
  if(reportBytes!==undefined) {
    if(!Buffer.isBuffer(reportBytes)) throw new Error('checkpoint registry report authority bytes are invalid');
    const parsed=parseStrictJsonBytes(reportBytes,{label:'checkpoint registry artifact pins report',maxBytes:64*1024,maxDepth:8});
    if(JSON.stringify(parsed)!==JSON.stringify(value)) throw new Error('checkpoint registry report differs from authority bytes');
  }
  if(artifactBytes!==undefined&&!Buffer.isBuffer(artifactBytes)) throw new Error('checkpoint registry artifact authority bytes are invalid');
  if(releaseConfigBytes!==undefined&&!Buffer.isBuffer(releaseConfigBytes)) throw new Error('checkpoint registry release authority bytes are invalid');
  const currentArtifactSha256=artifactBytes===undefined?artifactSha256:checkpointRegistryPinsSha256(artifactBytes);
  const currentReleaseSha256=releaseConfigBytes===undefined?releaseConfigSha256:checkpointRegistryPinsSha256(releaseConfigBytes);
  if(currentArtifactSha256&&value.artifactSha256!==currentArtifactSha256) throw new Error('checkpoint registry artifact bytes changed');
  if(currentReleaseSha256&&value.releaseConfigSha256!==currentReleaseSha256) throw new Error('checkpoint registry release config bytes changed');
  return value;
}

export const checkpointRegistryPinsSha256=bytes=>createHash('sha256').update(bytes).digest('hex');
