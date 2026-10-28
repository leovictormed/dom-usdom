#!/usr/bin/env node
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {pilotDepositGateSafeTypedData} from '../sdk/pilot-deposit-gate.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
try {
 if(process.argv.length!==3) throw new Error('private pilot gate plan path required');
 const plan=parseStrictJsonBytes(await readDirectFile(process.argv[2],{minimum:2,maximum:2*1024*1024,
  exactMode:0o600,label:'private pilot gate plan'}),{label:'private pilot gate plan'});
 process.stdout.write(`${JSON.stringify({schema:'usdom-onekey-eip712-signing/v1',digest:plan.safeTxHash,
  typedData:pilotDepositGateSafeTypedData(plan)})}\n`);
} catch(error) {writeReleaseFailure('prepare-pilot-gate-onekey-envelope',error);process.exitCode=1;}
