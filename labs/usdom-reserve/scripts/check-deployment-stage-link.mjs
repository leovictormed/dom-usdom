#!/usr/bin/env node
import path from 'node:path';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateDeploymentStageLink} from '../sdk/deployment-evidence.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
try {
  if(process.argv.length!==6||process.argv.slice(2).some(value=>!path.isAbsolute(value))) {
    throw new Error('usage: RAW RECEIPT COMPLETION ANCHOR');
  }
  const labels=['raw validation','receipt','completion','fee anchor'];
  const values=await Promise.all(process.argv.slice(2).map((target,index)=>
    readDirectFile(target,{minimum:2,maximum:64*1024,exactMode:0o600,label:labels[index]})));
  validateDeploymentStageLink({raw:parseStrictJsonBytes(values[0],{label:labels[0],maxDepth:4}),
    receipt:parseStrictJsonBytes(values[1],{label:labels[1],maxDepth:4}),
    completion:parseStrictJsonBytes(values[2],{label:labels[2],maxDepth:4}),
    anchor:parseStrictJsonBytes(values[3],{label:labels[3],maxDepth:4})});
} catch(error) { writeReleaseFailure('check-deployment-stage-link',error); process.exitCode=1; }
