#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {materializeLimitedMainnetPolicy} from '../sdk/limited-mainnet-policy.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

try {
  if(process.argv.length!==2) throw new Error('this fixed command accepts no arguments');
  const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
  const relative='config/proof-reserve.unconfigured.json';
  const before=await readDirectProjectFile(root,relative,{exactMode:0o644,maximum:1024*1024});
  const release=parseStrictJson(before.toString('utf8'),{label:'proof-reserve release config'});
  const result=materializeLimitedMainnetPolicy(release);
  const current=await readDirectProjectFile(root,relative,{
    minimum:before.length,maximum:before.length,exactMode:0o644,
  });
  if(!current.equals(before)) throw new Error('release configuration changed during materialization');
  process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-limited-mainnet-policy-materialization',error);
  process.exitCode=1;
}
