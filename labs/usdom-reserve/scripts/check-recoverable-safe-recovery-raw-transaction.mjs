#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {validateRecoverableSafeRecoveryRawTransaction} from '../sdk/safe-control-recovery-execution.mjs';
import {parseSafeRecoveryRawTransactionBytes} from '../sdk/safe-recovery-text-evidence.mjs';

async function strictJsonFile(path,label) {
  if(typeof path!=='string'||path.length===0) throw new Error(`${label} path is required`);
  const bytes=await readDirectFile(path,{
    minimum:1,maximum:2*1024*1024,label,
  });
  try {
    let json;
    try { json=new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
    catch { throw new Error(`${label} contains invalid UTF-8`); }
    return parseStrictJson(json,{label,maxBytes:2*1024*1024,maxDepth:32});
  } finally { bytes.fill(0); }
}

async function strictRawFile(path) {
  if(typeof path!=='string'||path.length===0) throw new Error('raw transaction path is required');
  const bytes=await readDirectFile(path,{
    minimum:1,maximum:128*1024,exactMode:0o600,label:'raw transaction',
  });
  try { return parseSafeRecoveryRawTransactionBytes(bytes); }
  finally { bytes.fill(0); }
}

try {
  const envelopePlan=await strictJsonFile(
    process.env.USDOM_SAFE_RECOVERY_ENVELOPE,'Safe recovery envelope',
  );
  const result=validateRecoverableSafeRecoveryRawTransaction({
    plan:await strictJsonFile(process.env.USDOM_SAFE_RECOVERY_PLAN,'Safe recovery plan'),
    transactionPackage:await strictJsonFile(
      process.env.USDOM_SAFE_RECOVERY_TRANSACTIONS,'Safe recovery transaction package',
    ),
    envelopePlan,
    role:envelopePlan.role,
    rawTransaction:await strictRawFile(process.env.USDOM_SAFE_RECOVERY_RAW_TRANSACTION),
    relayerOwner:envelopePlan.relayerOwner,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch(error) {
  writeReleaseFailure('check-recoverable-safe-recovery-raw-transaction',error);
  process.exitCode=1;
}
