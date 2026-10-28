import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {runStatus78Cycle} from '../../sdk/status78-cycle.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');

test('78 invokes exactly one resolved signer and resumes executor to success',async()=>{
 const events=[]; const statuses=[78,0];
 const status=await runStatus78Cycle({runExecutor:async()=>{events.push('execute');return statuses.shift()},resolveSigner:async()=>{events.push('resolve');return 'redemption:0'},runSigner:async flow=>{events.push(`sign:${flow}`);return 0}});
 assert.equal(status,0); assert.deepEqual(events,['execute','resolve','sign:redemption:0','execute']);
});

test('80 is terminal and never resolves, signs or retries',async()=>{
 const events=[];
 const status=await runStatus78Cycle({runExecutor:async()=>{events.push('execute');return 80},resolveSigner:async()=>{events.push('resolve');return 'pilot-gate:execute'},runSigner:async()=>{events.push('sign');return 0}});
 assert.equal(status,80); assert.deepEqual(events,['execute']);
});

test('78 without a uniquely ready signer remains 78 and does not retry blindly',async()=>{
 const events=[];
 const status=await runStatus78Cycle({runExecutor:async()=>{events.push('execute');return 78},resolveSigner:async()=>{events.push('resolve');return null},runSigner:async()=>{events.push('sign');return 0}});
 assert.equal(status,78); assert.deepEqual(events,['execute','resolve']);
});

test('signer failure and bounded repeated 78 fail closed without publication',async()=>{
 let executions=0;
 assert.equal(await runStatus78Cycle({runExecutor:async()=>{executions++;return 78},resolveSigner:async()=> 'deposit:approve',runSigner:async()=>80}),80);
 assert.equal(executions,1);
 executions=0;
 assert.equal(await runStatus78Cycle({maxCycles:3,runExecutor:async()=>{executions++;return 78},resolveSigner:async()=> 'deposit:approve',runSigner:async()=>0}),80);
 assert.equal(executions,3);
});

test('phase generator covers every production 78 family with fixed profiles',async()=>{
 const runner=await readFile(path.join(root,'scripts/run-operational-status78-cycle.mjs'),'utf8');
 const core=await readFile(path.join(root,'sdk/status78-cycle.mjs'),'utf8');
 const generator=await readFile(path.join(root,'scripts/generate-closed-mainnet-phase-command.sh'),'utf8');
 for(const profile of ['safe-deployment','contract-deployment','recovery','reserve-resume','pilot-gate','pilot-gate-cancel','pilot-gate-clear','deposit','redemption']) assert.match(runner,new RegExp(`case '${profile}'`));
 for(const command of ['safe-deployment','contract-deployment "\\$index"','reserve-resume','pilot-gate','pilot-gate-cancel','pilot-gate-clear','deposit','redemption']) assert.match(generator,new RegExp(`run-operational-status78-cycle\\.mjs ${command}`));
 assert.match(runner,/ready\.length!==1/); assert.match(core,/status===0 \|\| status===80/);
 const dispatcher=await readFile(path.join(root,'scripts/sign-operational-gas-relayer.sh'),'utf8');
 assert.match(dispatcher,/safe-deposit:approve\|safe-deposit:deposit\)[\s\S]*relayer_role=pilot-gate/);
 assert.match(dispatcher,/safe-deployment:governance\|safe-deployment:reserveGuardian[\s\S]*relayer_role=safe-deployment/);
 assert.match(dispatcher,/pilot-gate:cancel\)[\s\S]*relayer_role=pilot-gate/);
 assert.match(dispatcher,/pilot-gate:clear\)[\s\S]*relayer_role=pilot-gate/);
 assert.doesNotMatch(dispatcher,/default_keystore/);
 assert.equal(spawnSync('bash',['-n',path.join(root,'scripts/generate-closed-mainnet-phase-command.sh')]).status,0);
});
