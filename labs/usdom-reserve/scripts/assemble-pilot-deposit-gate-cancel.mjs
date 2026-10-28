#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs'; import {parseStrictJsonBytes} from '../sdk/strict-json.mjs'; import {assemblePilotGateCancelTransaction} from '../sdk/pilot-deposit-gate-cancel.mjs';
try{if(process.argv.length!==6)throw new Error('usage: assemble cancel PLAN SIG1 SIG2');const [plan,...signatures]=(await Promise.all(process.argv.slice(2).map(p=>readDirectFile(p,{minimum:2,maximum:8*1024*1024,exactMode:0o600})))).map((v,i)=>parseStrictJsonBytes(v,{label:`cancel assembly ${i}`}));process.stdout.write(JSON.stringify(assemblePilotGateCancelTransaction({plan,signatures}),null,2)+'\n');}catch(e){writeReleaseFailure('assemble-pilot-deposit-gate-cancel',e);process.exitCode=1;}
