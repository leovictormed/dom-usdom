import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {collectEthereumCheckpointConsensus} from '../sdk/ethereum-checkpoint-consensus.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const endpointValues=[];
function takeEndpoint(name){const value=process.env[name];delete process.env[name];if(value) endpointValues.push(value);return value}

try {
  if(process.argv.length!==2) throw new Error('this fixed collector accepts no arguments');
  const sources=[1,2,3].map(index=>({
    operatorId:process.env[`ETHEREUM_BEACON_OPERATOR_ID_${index}`],
    url:takeEndpoint(`ETHEREUM_BEACON_API_URL_${index}`),
  }));
  const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
  const relative='config/ethereum-checkpoint-source-catalog.unconfigured.json';
  const before=await readDirectProjectFile(root,relative,{minimum:2,maximum:16*1024});
  const catalog=parseStrictJson(before.toString('utf8'),{label:relative,maxBytes:16*1024,maxDepth:6});
  const result=await collectEthereumCheckpointConsensus({sources,catalog});
  const after=await readDirectProjectFile(root,relative,{minimum:before.length,maximum:before.length});
  if(!after.equals(before)) throw new Error('Ethereum checkpoint source catalog changed during collection');
  process.stdout.write(JSON.stringify(result,null,2)+'\n');
} catch(error) {
  writeReleaseFailure('collect-ethereum-checkpoint-consensus',error);
  process.exitCode=1;
}
