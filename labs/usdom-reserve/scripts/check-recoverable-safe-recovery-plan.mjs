#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {validateRecoverableSafeRecoveryPlan} from '../sdk/safe-control-recovery-plan.mjs';

try {
  const path=process.env.USDOM_SAFE_RECOVERY_PLAN;
  if(typeof path!=='string'||path.length===0) throw new Error('USDOM_SAFE_RECOVERY_PLAN is required');
  const plan=parseStrictJson((await readDirectFile(path,{
    minimum:1,maximum:2*1024*1024,label:'Safe recovery plan',
  })).toString('utf8'),{
    label:'Safe recovery plan',maxBytes:2*1024*1024,maxDepth:32,
  });
  validateRecoverableSafeRecoveryPlan(plan);
  process.stdout.write(`${plan.planHash}\n`);
} catch(error) {
  writeReleaseFailure('check-recoverable-safe-recovery-plan',error);
  process.exitCode=1;
}
