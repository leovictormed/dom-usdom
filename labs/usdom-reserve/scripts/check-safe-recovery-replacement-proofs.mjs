#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {validateSafeRecoveryReplacementProofs}
  from '../sdk/safe-recovery-replacement-proofs.mjs';
async function load(path,label){
  if(typeof path!=='string'||path.length===0) fail(`${label} path is required`);
  const bytes=await readDirectFile(path,{minimum:2,maximum:2*1024*1024,
    exactMode:0o600,label});
  try { return parseStrictJson(bytes.toString('utf8'),{label,maxBytes:2*1024*1024,maxDepth:32}); }
  finally { bytes.fill(0); }
}

try {
  const plan=await load(process.env.USDOM_SAFE_RECOVERY_PLAN,'Safe recovery plan');
  const bundle=await load(process.env.USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS,'Safe recovery replacement proofs');
  process.stdout.write(`${JSON.stringify(validateSafeRecoveryReplacementProofs(plan,bundle))}\n`);
} catch(error) {
  writeReleaseFailure('check-safe-recovery-replacement-proofs',error);
  process.exitCode=1;
}
