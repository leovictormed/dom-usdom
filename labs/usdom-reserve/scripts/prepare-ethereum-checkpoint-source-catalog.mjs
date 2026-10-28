import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {buildEthereumCheckpointSourceCatalog} from '../sdk/ethereum-checkpoint-consensus.mjs';

const endpointValues=[];
function takeEndpoint(name){const value=process.env[name];delete process.env[name];if(value) endpointValues.push(value);return value}
function redactEndpoints(error){
  let message=error instanceof Error?error.message:String(error);
  for(const endpoint of endpointValues.toSorted((a,b)=>b.length-a.length)) {
    if(endpoint) message=message.replaceAll(endpoint,'[redacted endpoint]');
  }
  return new Error(message);
}

try {
  if(process.argv.length!==2) throw new Error('this fixed source-catalog preparer accepts no arguments');
  const sources=[1,2,3].map(index=>({operatorId:process.env[`ETHEREUM_BEACON_OPERATOR_ID_${index}`],
    url:takeEndpoint(`ETHEREUM_BEACON_API_URL_${index}`)}));
  process.stdout.write(JSON.stringify(buildEthereumCheckpointSourceCatalog(sources),null,2)+'\n');
} catch(error) {
  writeReleaseFailure('prepare-ethereum-checkpoint-source-catalog',redactEndpoints(error));
  process.exitCode=1;
}
