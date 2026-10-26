#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readFileSync} from 'node:fs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {RECOVERABLE_SAFE_CONTROL_SCHEMA,SAFE_CONTROL_SPECS} from '../sdk/safe-control-deployment.mjs';
import {_safeControlObservationInternals} from '../sdk/safe-control-observation.mjs';

if(process.argv.length!==3) process.exit(64);
try {
  const value=parseStrictJsonBytes(readFileSync(process.argv[2]),{
    label:'Safe control package',maxBytes:4*1024*1024,maxDepth:32});
  if(value?.schema!==RECOVERABLE_SAFE_CONTROL_SCHEMA||value.ethereumChainId!=='1'
      ||value.threshold!=='2'||!Array.isArray(value.controls)||value.controls.length!==3
      ||JSON.stringify(value.controls.map(control=>control?.role))
        !==JSON.stringify(SAFE_CONTROL_SPECS.map(spec=>spec.role))) {
    throw new Error('Safe control package identity is invalid');
  }
  process.stdout.write(`${_safeControlObservationInternals.documentHash(value)}\n`);
} catch(error) { writeReleaseFailure('hash-safe-control-package',error); process.exitCode=1; }
