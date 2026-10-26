#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {validateRecoverableSafeControlReleaseEvidence} from '../sdk/safe-control-release-evidence.mjs';

try {
  const path=process.env.USDOM_SAFE_RELEASE_EVIDENCE_BUNDLE;
  if(typeof path!=='string'||path.length===0) throw new Error('bundle path is required');
  const bundle=parseStrictJson((await readDirectFile(path,{
    minimum:1,maximum:4*1024*1024,label:'Safe release-evidence bundle',
  })).toString('utf8'),{
    label:'Safe release-evidence bundle',maxBytes:4*1024*1024,maxDepth:48,
  });
  validateRecoverableSafeControlReleaseEvidence(bundle);
  process.stdout.write(`${bundle.bundleHash}\n`);
} catch(error) {
  writeReleaseFailure('check-recoverable-safe-release-evidence',error);
  process.exitCode=1;
}
