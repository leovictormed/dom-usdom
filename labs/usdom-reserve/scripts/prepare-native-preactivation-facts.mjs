import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {assembleNativePreActivationFacts} from '../sdk/native-preactivation-facts.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const relative='config/native-preactivation-policy.unconfigured.json';
try {
  if(process.argv.length!==2) throw new Error('this fixed native-fact assembler accepts no arguments');
  const before=await readDirectProjectFile(root,relative,{minimum:2,maximum:16*1024});
  const chunks=[];
  let size=0;
  for await(const chunk of process.stdin) {
    size+=chunk.length;
    if(size>16*1024) throw new Error('DOM anchor input exceeds 16 KiB');
    chunks.push(chunk);
  }
  const anchor=parseStrictJson(Buffer.concat(chunks,size).toString('utf8'),
    {label:'authenticated DOM pre-activation anchor',maxBytes:16*1024,maxDepth:4});
  const policy=parseStrictJson(before.toString('utf8'),{label:relative,maxBytes:16*1024,maxDepth:4});
  const facts=assembleNativePreActivationFacts({anchor,policy});
  const after=await readDirectProjectFile(root,relative,{minimum:before.length,maximum:before.length});
  if(!after.equals(before)) throw new Error('pre-activation policy changed during assembly');
  process.stdout.write(JSON.stringify(facts,null,2)+'\n');
} catch(error) {
  writeReleaseFailure('prepare-native-preactivation-facts',error);
  process.exitCode=1;
}
