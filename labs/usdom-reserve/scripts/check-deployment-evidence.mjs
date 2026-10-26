#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {validateDeploymentEvidence,validateDeploymentFeeAnchor,validateDeploymentRawEvidence,
  validateDeploymentReceiptEvidence}
  from '../sdk/deployment-evidence.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

try {
  if((process.argv.length!==3&&process.argv.length!==4)||!path.isAbsolute(process.argv[2])
      ||(process.argv[3]!==undefined&&!['completion','raw','receipt','anchor'].includes(process.argv[3]))) {
    throw new Error('usage: check-deployment-evidence.mjs ABSOLUTE_PATH [completion|raw|receipt|anchor]');
  }
  const bytes=await readDirectFile(process.argv[2],{minimum:2,maximum:64*1024,exactMode:0o600,
    label:'deployment evidence'});
  const value=parseStrictJsonBytes(bytes,{label:'deployment evidence',maxDepth:4});
  const validator=process.argv[3]==='raw'?validateDeploymentRawEvidence
    :process.argv[3]==='receipt'?validateDeploymentReceiptEvidence
    :process.argv[3]==='anchor'?validateDeploymentFeeAnchor:validateDeploymentEvidence;
  validator(value);
} catch(error) {
  writeReleaseFailure('check-deployment-evidence',error);
  process.exitCode=1;
}
