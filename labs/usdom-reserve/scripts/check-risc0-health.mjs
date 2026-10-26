import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {assessRiscZeroMainnetHealth} from '../sdk/risc0-health.mjs';
import {collectRiscZeroHealthSources} from '../sdk/risc0-health-observer.mjs';
import {validateRiscZeroHealthSourceCatalog} from '../sdk/risc0-health-source-catalog.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const envNames=Array.from({length:4},(_,index)=>`USDOM_RISC0_RPC_URL_${index+1}`);
const urls=envNames.map(name=>process.env[name]??null);

if(process.argv.length!==2) {
  console.error('Usage: USDOM_RISC0_RPC_URL_1=... USDOM_RISC0_RPC_URL_2=... node scripts/check-risc0-health.mjs');
  process.exitCode=2;
} else {
  try {
    const [referenceBytes,catalogBytes]=await Promise.all([
      readDirectProjectFile(root,'config/risc0-ethereum-mainnet-v3.json',{
        maximum:4*1024*1024,label:'RISC Zero reference',
      }),readDirectProjectFile(root,'evidence/risc0-health-sources.json',{
        maximum:4*1024*1024,label:'RISC Zero source catalog'}),
    ]);
    const reference=parseStrictJson(referenceBytes.toString('utf8'),
      {label:'config/risc0-ethereum-mainnet-v3.json'});
    const catalog=validateRiscZeroHealthSourceCatalog(parseStrictJson(catalogBytes.toString('utf8'),
      {label:'evidence/risc0-health-sources.json'}));
    if(urls.slice(0,catalog.sources.length).some(url=>url===null)
        ||urls.slice(catalog.sources.length).some(url=>url!==null)) {
      throw new Error(`exactly ${catalog.sources.length} catalog-ordered RPC URLs are required`);
    }
    const endpoints=catalog.sources.map((source,index)=>({sourceId:source.sourceId,url:urls[index]}));
    const observed=await collectRiscZeroHealthSources({reference,catalog,endpoints});
    const sources=observed.map(source=>({...source,
      report:assessRiscZeroMainnetHealth({reference,observation:source.observation})}));
    const healthy=sources.every(source=>source.report.healthy);
    const [currentReferenceBytes,currentCatalogBytes]=await Promise.all([
      readDirectProjectFile(root,'config/risc0-ethereum-mainnet-v3.json',{
        minimum:referenceBytes.length,maximum:referenceBytes.length,label:'RISC Zero reference',
      }),
      readDirectProjectFile(root,'evidence/risc0-health-sources.json',{
        minimum:catalogBytes.length,maximum:catalogBytes.length,label:'RISC Zero source catalog',
      }),
    ]);
    if(!currentReferenceBytes.equals(referenceBytes)||!currentCatalogBytes.equals(catalogBytes)) {
      throw new Error('RISC Zero health inputs changed during observation');
    }
    console.log(JSON.stringify({schema:'usdom-risc0-health-multi-source-report/v1',healthy,
      catalogHash:catalog.catalogHash,sources},null,2));
    if(!healthy) process.exitCode=1;
  } catch(error) {
    writeReleaseFailure('check-risc0-health',error);
    process.exitCode=2;
  }
}
