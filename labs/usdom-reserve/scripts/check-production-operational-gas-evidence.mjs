#!/usr/bin/env node
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {
  validateProductionOperationalGasEvidence,
  validateProductionOperationalGasJob,
} from '../sdk/production-operational-gas-evidence.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';

try {
  if(process.argv.length!==4) {
    throw new Error('usage: check-production-operational-gas-evidence.mjs JOB REPORT');
  }
  const [jobBytes,reportBytes]=await Promise.all(process.argv.slice(2).map((file,index)=>
    readDirectFile(file,{
      minimum:1,
      maximum:4*1024*1024,
      exactMode:0o600,
      label:index?'operational gas evidence':'operational gas job',
    })));
  const job=validateProductionOperationalGasJob(parseStrictJsonBytes(jobBytes,{
    label:'operational gas job',
    maxDepth:16,
  }));
  validateProductionOperationalGasEvidence(parseStrictJsonBytes(reportBytes,{
    label:'operational gas evidence',
    maxDepth:32,
  }),job);
  process.stdout.write('production operational gas evidence: valid\n');
} catch(error) {
  writeReleaseFailure('check-production-operational-gas-evidence',error);
  process.exitCode=1;
}
