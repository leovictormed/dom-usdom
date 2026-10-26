#!/usr/bin/env node
import path from 'node:path';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {productionImplementationClaimFailures} from '../sdk/production-implementation-claims.mjs';

const root=path.resolve(import.meta.dirname,'..');
const source=(await readDirectProjectFile(root,'config/production-requirements.json',{
  minimum:1,maximum:2*1024*1024,label:'production requirements',
})).toString('utf8');
const requirements=parseStrictJson(source,{label:'production requirements',maxBytes:2*1024*1024,maxDepth:16});
const failures=productionImplementationClaimFailures(requirements,{requireClaims:true});
if(failures.length!==0) {
  for(const failure of failures) {
    const suffix=failure.dependencies.length===0?'':`: ${failure.dependencies.join(', ')}`;
    console.error(`${failure.claim}: ${failure.reason}${suffix}`);
  }
  process.exitCode=1;
} else {
  console.log('PASS: broad production implementation claims are backed by concrete implementation facts');
}
