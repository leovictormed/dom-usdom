#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs'; import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {assemblePilotDepositGateTransaction} from '../sdk/pilot-deposit-gate.mjs';
try {
 if(process.argv.length!==9) throw new Error('usage: assemble-pilot-deposit-gate-transaction PLAN SNAPSHOT AUTHORIZATION_STATE RELEASE SAFE SIGNATURE_A SIGNATURE_B');
 const values=await Promise.all(process.argv.slice(2).map(value=>readDirectFile(value,{minimum:2,maximum:8*1024*1024,exactMode:0o600})));
 const [plan,snapshot,authorizationState,releaseConfig,safePackage,...signatures]=values.map((value,index)=>parseStrictJsonBytes(value,{label:`pilot gate assembly input ${index}`}));
 process.stdout.write(JSON.stringify(assemblePilotDepositGateTransaction({plan,snapshot,authorizationState,releaseConfig,safePackage,signatures}),null,2)+'\n');
} catch(error) { writeReleaseFailure('assemble-pilot-deposit-gate-transaction',error); process.exitCode=1; }
