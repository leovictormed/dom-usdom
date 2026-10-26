import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {materializeProductionSolidityPins} from '../sdk/production-solidity-pins.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const releasePath='config/proof-reserve.unconfigured.json';
const reservePath='contracts/USDOMProofReserve.sol';
const registryPath='contracts/DOMCheckpointRegistry.sol';

try {
  if(process.argv.length!==2) throw new Error('this fixed materializer accepts no arguments');
  const [releaseBytes,reserveBytes,registryBytes]=await Promise.all([
    readDirectProjectFile(root,releasePath),readDirectProjectFile(root,reservePath),
    readDirectProjectFile(root,registryPath),
  ]);
  const releaseConfig=parseStrictJson(releaseBytes.toString('utf8'),{label:releasePath});
  const result=materializeProductionSolidityPins({releaseConfig,
    reserveSource:reserveBytes.toString('utf8'),checkpointRegistrySource:registryBytes.toString('utf8')});
  for(const [relative,previous] of [[releasePath,releaseBytes],[reservePath,reserveBytes],[registryPath,registryBytes]]) {
    const current=await readDirectProjectFile(root,relative,{minimum:previous.length,maximum:previous.length});
    if(!current.equals(previous)) throw new Error(`pin input changed during preparation: ${relative}`);
  }
  const sha256=value=>createHash('sha256').update(value).digest('hex');
  process.stdout.write(JSON.stringify({...result,inputSha256:{
    releaseConfig:sha256(releaseBytes),reserveSource:sha256(reserveBytes),
    checkpointRegistrySource:sha256(registryBytes),
  }})+'\n');
} catch(error) {
  writeReleaseFailure('prepare-production-solidity-pins',error);
  process.exitCode=1;
}
