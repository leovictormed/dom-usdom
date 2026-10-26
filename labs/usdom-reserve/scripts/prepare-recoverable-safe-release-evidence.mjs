#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {buildRecoverableSafeControlReleaseEvidence} from '../sdk/safe-control-release-evidence.mjs';

async function strictFile(path,label) {
  if(typeof path!=='string'||path.length===0) throw new Error(`${label} path is required`);
  const bytes=await readDirectFile(path,{minimum:1,maximum:4*1024*1024,label});
  try { return parseStrictJson(bytes.toString('utf8'),
    {label,maxBytes:4*1024*1024,maxDepth:48}); }
  finally { bytes.fill(0); }
}

try {
  const result=buildRecoverableSafeControlReleaseEvidence({
    packageDocument:await strictFile(process.env.USDOM_SAFE_PACKAGE,'recoverable Safe package'),
    baselineSnapshot:await strictFile(process.env.USDOM_SAFE_BASELINE,'Safe baseline'),
    recoveryReport:await strictFile(process.env.USDOM_SAFE_RECOVERY_REPORT,'Safe recovery report'),
  });
  process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-recoverable-safe-release-evidence',error);
  process.exitCode=1;
}
