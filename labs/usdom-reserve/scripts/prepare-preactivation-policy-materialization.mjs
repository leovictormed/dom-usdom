import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {materializePreActivationPolicy} from '../sdk/preactivation-policy.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const inputs=['config/proof-reserve.unconfigured.json','evidence/native-preactivation/dom-anchor.json',
  'evidence/native-preactivation/ethereum-checkpoint-consensus.json',
  'config/native-preactivation-policy.unconfigured.json'];
try {
  if(process.argv.length!==2) throw new Error('this fixed policy materializer accepts no arguments');
  const snapshots=new Map();
  for(const relative of inputs) snapshots.set(relative,await readDirectProjectFile(root,relative,
    {minimum:2,maximum:256*1024}));
  const parsed=Object.fromEntries([...snapshots].map(([name,bytes])=>[name,
    parseStrictJson(bytes.toString('utf8'),{label:name,maxBytes:256*1024,maxDepth:16})]));
  const policy=materializePreActivationPolicy({releaseConfig:parsed[inputs[0]],anchor:parsed[inputs[1]],
    checkpointConsensus:parsed[inputs[2]]});
  const current=parsed[inputs[3]];
  for(const [field,value] of Object.entries(policy)) {
    if(current[field]!==null&&current[field]!==value) throw new Error(`${field} already differs`);
  }
  if(Object.keys(current).length!==Object.keys(policy).length
      ||Object.keys(policy).some(field=>!(field in current))) throw new Error('policy target schema differs');
  for(const [relative,before] of snapshots) {
    const after=await readDirectProjectFile(root,relative,{minimum:before.length,maximum:before.length});
    if(!after.equals(before)) throw new Error(`policy materialization input changed: ${relative}`);
  }
  process.stdout.write(JSON.stringify(policy,null,2)+'\n');
} catch(error) {
  writeReleaseFailure('prepare-preactivation-policy-materialization',error);
  process.exitCode=1;
}
