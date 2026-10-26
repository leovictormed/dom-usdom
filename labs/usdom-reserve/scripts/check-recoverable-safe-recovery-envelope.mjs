#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {validateRecoverableSafeRecoveryEnvelope} from '../sdk/safe-control-recovery-envelope.mjs';

async function strictFile(path,label) {
  if(typeof path!=='string'||path.length===0) throw new Error(`${label} path is required`);
  const bytes=await readDirectFile(path,{minimum:1,maximum:2*1024*1024,label});
  try { return parseStrictJson(bytes.toString('utf8'),
    {label,maxBytes:2*1024*1024,maxDepth:32}); }
  finally { bytes.fill(0); }
}

try {
  const plan=await strictFile(process.env.USDOM_SAFE_RECOVERY_PLAN,'Safe recovery plan');
  const transactions=await strictFile(
    process.env.USDOM_SAFE_RECOVERY_TRANSACTIONS,'Safe recovery transaction package',
  );
  const envelope=await strictFile(
    process.env.USDOM_SAFE_RECOVERY_ENVELOPE,'Safe recovery envelope',
  );
  validateRecoverableSafeRecoveryEnvelope(plan,transactions,envelope);
  process.stdout.write(`${envelope.envelopeHash}\n`);
} catch(error) {
  writeReleaseFailure('check-recoverable-safe-recovery-envelope',error);
  process.exitCode=1;
}
