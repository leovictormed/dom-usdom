#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {assembleRecoverableSafeRecoveryTransactions} from '../sdk/safe-control-recovery-plan.mjs';

async function strictFile(path,label) {
  if(typeof path!=='string'||path.length===0) throw new Error(`${label} path is required`);
  const bytes=await readDirectFile(path,{minimum:1,maximum:2*1024*1024,label});
  try { return parseStrictJson(bytes.toString('utf8'),
    {label,maxBytes:2*1024*1024,maxDepth:32}); }
  finally { bytes.fill(0); }
}

try {
  const result=assembleRecoverableSafeRecoveryTransactions({
    plan:await strictFile(process.env.USDOM_SAFE_RECOVERY_PLAN,'Safe recovery plan'),
    signatures:await strictFile(process.env.USDOM_SAFE_RECOVERY_SIGNATURES,'Safe recovery signatures'),
  });
  process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
} catch(error) {
  writeReleaseFailure('assemble-recoverable-safe-recovery',error);
  process.exitCode=1;
}
