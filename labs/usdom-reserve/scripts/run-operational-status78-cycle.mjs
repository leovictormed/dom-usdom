#!/usr/bin/env node
import {existsSync,lstatSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import {runStatus78Cycle} from '../sdk/status78-cycle.mjs';
const [profile,arg,...rest]=process.argv.slice(2);
if(rest.length || !profile) process.exit(64);
const evidence=process.env.USDOM_CONTROL_EVIDENCE_DIRECTORY;
if(!evidence || !path.isAbsolute(evidence)) process.exit(64);
const regular=p=>{try{const s=lstatSync(p);return s.isFile()&&!s.isSymbolicLink()&&s.nlink===1}catch{return false}};
const absent=p=>!existsSync(p);
const npm=(name,args=[])=>['npm',['run','--silent',name,'--',...args]];
let executor, candidates=[];
const operational=flow=>['bash',['scripts/sign-operational-gas-relayer.sh',flow]];
const candidate=(flow,envelope,input,raw,done,signer=operational(flow))=>({flow,envelope:path.join(evidence,envelope),input:path.join(evidence,input),raw:path.join(evidence,raw),done:path.join(evidence,done),signer});
switch(profile){
case 'safe-deployment':
 if(arg!==undefined) process.exit(64); executor=npm('execute:safe-control-deployment');
 for(const role of ['governance','reserveGuardian','checkpointGuardian','usdtCustody']) candidates.push(candidate(`safe-deployment:${role}`,`safe-deployment-${role}-relayer-envelope.json`,`safe-deployment-${role}-relayer-input.json`,`safe-deployment-${role}-raw.txt`,`safe-deployment-${role}-receipt.json`)); break;
case 'contract-deployment':
 if(!/^[0-3]$/.test(arg??'')) process.exit(64); executor=npm('execute:mainnet-deployment',[arg]); candidates=[candidate(`contract-deployment:${arg}`,`contract-deployment-${arg}-relayer-envelope.json`,`contract-deployment-${arg}-relayer-input.json`,`contract-deployment-${arg}-relayer-external-raw.txt`,`contract-deployment-${arg}-receipt.json`,['bash',['scripts/sign-mainnet-deployment-gas-relayer.sh',arg]])]; break;
case 'recovery':
 if(arg!==undefined) process.exit(64); executor=npm('execute:recoverable-safe-recovery');
 for(const role of ['governance','reserveGuardian','checkpointGuardian']) candidates.push(candidate(`recovery:${role}`,`${role}-recovery-envelope.json`,`${role}-recovery-relayer-input.json`,`${role}-recovery-raw-transaction.txt`,`${role}-finalized-execution.json`)); break;
case 'recovery-v3':
 if(arg!==undefined) process.exit(64); executor=['bash',['scripts/prepare-safe-recovery-roster-v3-prebroadcast.sh']];
 for(let step=0;step<12;step++) candidates.push(candidate(`recovery-v3:${step}`,`recovery-v3-step-${step}-relayer-envelope.json`,`recovery-v3-step-${step}-relayer-input.json`,`recovery-v3-step-${step}-relayer-raw.txt`,`recovery-v3-step-${step}-journal.json`)); break;
case 'reserve-resume':
 if(arg!==undefined) process.exit(64); executor=npm('execute:reserve-resume');
 for(const step of ['schedule','execute']) candidates.push(candidate(`reserve-resume:${step}`,`reserve-resume-${step}-relayer-envelope.json`,`reserve-resume-${step}-relayer-input.json`,`reserve-resume-${step}-relayer-raw.txt`,`reserve-resume-${step}-finalized.json`)); break;
case 'pilot-gate':
 if(arg!==undefined) process.exit(64); executor=npm('execute:pilot-deposit-gate'); candidates=[candidate('pilot-gate:execute','pilot-deposit-gate-relayer-envelope.json','pilot-deposit-gate-transaction.json','pilot-deposit-gate-raw.txt','pilot-deposit-gate-finalized.json')]; break;
case 'pilot-gate-cancel':
 if(arg!==undefined) process.exit(64); executor=npm('execute:pilot-deposit-gate-cancel'); candidates=[candidate('pilot-gate:cancel','pilot-deposit-gate-cancel-relayer-envelope.json','pilot-deposit-gate-cancel-transaction.json','pilot-deposit-gate-cancel-raw.txt','pilot-deposit-gate-cancel-finalized.json')]; break;
case 'pilot-gate-clear':
 if(arg!==undefined) process.exit(64); executor=npm('execute:expired-pilot-gate-clear'); candidates=[candidate('pilot-gate:clear','pilot-deposit-gate-clear-relayer-envelope.json','pilot-deposit-gate-clear-transaction.json','pilot-deposit-gate-clear-raw.txt','pilot-deposit-gate-clear-finalized.json')]; break;
case 'deposit':
 if(arg!==undefined) process.exit(64); executor=['bash',['scripts/execute-closed-mainnet-deposit.sh']];
 for(const step of ['approve','deposit']) candidates.push(candidate(`safe-deposit:${step}`,`safe-deposit-${step}-relayer-envelope.json`,`safe-deposit-${step}-relayer-input.json`,`safe-deposit-${step}-relayer-raw.txt`,`safe-deposit-${step}-finalized.json`)); break;
case 'redemption':
 if(arg!==undefined) process.exit(64); executor=npm('execute:closed-mainnet-redemption');
 for(const index of ['0','1']) candidates.push(candidate(`redemption:${index}`,`closed-redemption-${index}-relayer-envelope.json`,`closed-redemption-${index}-relayer-input.json`,`closed-redemption-${index}-raw.txt`,`closed-redemption-${index}-finality.json`)); break;
default: process.exit(64);
}
const run=([file,args])=>{const r=spawnSync(file,args,{cwd:process.cwd(),env:process.env,stdio:'inherit'});if(r.error)throw r.error;return r.status??80};
const status=await runStatus78Cycle({runExecutor:()=>run(executor),resolveSigner:()=>{const ready=candidates.filter(c=>regular(c.envelope)&&regular(c.input)&&absent(c.raw)&&absent(c.done));if(ready.length===0)return null;if(ready.length!==1)throw new Error('multiple status78 signer envelopes are simultaneously eligible');return ready[0].flow;},runSigner:flow=>{const c=candidates.find(x=>x.flow===flow);if(!c)throw new Error('unresolved signer flow');return run(c.signer);}}).catch(e=>{console.error(`status78 cycle failed closed: ${e.message}`);return 80});
process.exit(status);
