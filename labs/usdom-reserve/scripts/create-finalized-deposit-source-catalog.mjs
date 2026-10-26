import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {buildFinalizedDepositSourceCatalog} from '../sdk/finalized-deposit-source-catalog.mjs';
import {writeFileDurable} from '../sdk/durable-private-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const target=path.join(root,'config','finalized-deposit-source-catalog.json');
let runtime=[];
const runtimeJson=process.env.USDOM_FINALIZED_DEPOSIT_SOURCES??'';
delete process.env.USDOM_FINALIZED_DEPOSIT_SOURCES;
try {
  runtime=parseStrictJson(runtimeJson,{
    label:'USDOM_FINALIZED_DEPOSIT_SOURCES',maxBytes:64*1024,maxDepth:8});
  const catalog=buildFinalizedDepositSourceCatalog(runtime);
  await writeFileDurable(target,Buffer.from(`${JSON.stringify(catalog,null,2)}\n`),{
    maximum:64*1024,mode:0o644,replace:false,
  });
  console.log(JSON.stringify({status:'created',path:path.relative(root,target),sources:catalog.sources.length}));
} catch(error) {
    writeReleaseFailure('create-finalized-deposit-source-catalog',error); process.exitCode=1;
}
