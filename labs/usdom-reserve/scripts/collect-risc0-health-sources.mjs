import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {collectRiscZeroHealthSources} from '../sdk/risc0-health-observer.mjs';
import {validateRiscZeroHealthSourceCatalog} from '../sdk/risc0-health-source-catalog.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const catalogPath='evidence/risc0-health-sources.json';
const referencePath='config/risc0-ethereum-mainnet-v3.json';
const envNames=Array.from({length:4},(_,index)=>`USDOM_RISC0_RPC_URL_${index+1}`);
const urls=envNames.map(name=>process.env[name]??null);

if(process.argv.length!==2) {
  console.error('Usage: USDOM_RISC0_RPC_URL_1=... USDOM_RISC0_RPC_URL_2=... npm run observe:risc0-upstream-sources');
  process.exitCode=2;
} else {
  try {
    const [catalogBytes,referenceBytes]=await Promise.all([
      readDirectProjectFile(root,catalogPath,{maximum:4*1024*1024,label:'RISC Zero source catalog'}),
      readDirectProjectFile(root,referencePath,{maximum:4*1024*1024,label:'RISC Zero reference'}),
    ]);
    const catalogRaw=catalogBytes.toString('utf8');
    const referenceRaw=referenceBytes.toString('utf8');
    const catalog=validateRiscZeroHealthSourceCatalog(parseStrictJson(catalogRaw,{label:catalogPath}));
    const reference=parseStrictJson(referenceRaw,{label:referencePath});
    if(urls.slice(0,catalog.sources.length).some(url=>url===null)
        || urls.slice(catalog.sources.length).some(url=>url!==null)) {
      throw new Error(`exactly ${catalog.sources.length} catalog-ordered RPC URL environment variables are required`);
    }
    const endpoints=catalog.sources.map((source,index)=>({sourceId:source.sourceId,url:urls[index]}));
    const sources=await collectRiscZeroHealthSources({reference,catalog,endpoints});
    const [currentCatalogBytes,currentReferenceBytes]=await Promise.all([
      readDirectProjectFile(root,catalogPath,{
        minimum:catalogBytes.length,maximum:catalogBytes.length,label:'RISC Zero source catalog',
      }),
      readDirectProjectFile(root,referencePath,{
        minimum:referenceBytes.length,maximum:referenceBytes.length,label:'RISC Zero reference',
      }),
    ]);
    if(!currentCatalogBytes.equals(catalogBytes)||!currentReferenceBytes.equals(referenceBytes)) {
      throw new Error('RISC Zero health inputs changed during observation');
    }
    console.log(JSON.stringify({schema:'usdom-risc0-health-source-observations/v1',
      catalogHash:catalog.catalogHash,sources},null,2));
  } catch(error) {
    writeReleaseFailure('collect-risc0-health-sources',error);
    process.exitCode=1;
  }
}
