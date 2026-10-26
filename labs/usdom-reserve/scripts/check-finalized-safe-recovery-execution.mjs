#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import process from 'node:process';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateFinalizedSafeRecoveryExecution} from '../sdk/safe-control-recovery-execution.mjs';

async function read(file,label) {
  if(typeof file!=='string'||!path.isAbsolute(file)) throw new Error(`${label} path is invalid`);
  const bytes=await readDirectFile(file,{minimum:2,maximum:2*1024*1024,exactMode:0o600,label});
  return parseStrictJsonBytes(bytes,{label,maxBytes:2*1024*1024,maxDepth:32});
}
try {
  if(process.argv.length!==4||!['governance','reserveGuardian','checkpointGuardian'].includes(process.argv[3])) {
    throw new Error('usage: EXECUTION_FILE ROLE');
  }
  const [plan,transactionPackage,execution]=await Promise.all([
    read(process.env.USDOM_SAFE_RECOVERY_PLAN,'Safe recovery plan'),
    read(process.env.USDOM_SAFE_RECOVERY_TRANSACTIONS,'Safe recovery transaction package'),
    read(process.argv[2],'finalized Safe recovery execution'),
  ]);
  validateFinalizedSafeRecoveryExecution({plan,transactionPackage,execution});
  if(execution.role!==process.argv[3]) throw new Error('finalized execution role mismatch');
} catch(error) {
  writeReleaseFailure('check-finalized-safe-recovery-execution',error);
  process.exitCode=1;
}
