import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
const root=new URL('../..',import.meta.url).pathname;
const generator=readFileSync(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
test('phase generator has no Ledger production route and binds modern boundaries',()=>{
 assert.doesNotMatch(generator,/--ledger|wallet address|wallet sign|prepare-ledger|assemble-ledger|Ledger signing/iu);
 for(const marker of ['USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG','USDOM_ONEKEY_IOS_ONBOARDING_EVIDENCE_DIRECTORY','execute-safe-recovery-roster-v3-step.sh','run-operational-status78-cycle.mjs safe-deployment','run-operational-status78-cycle.mjs contract-deployment']) assert.ok(generator.includes(marker),marker);
});
test('every generated phase is Ledger-free and syntactically closed',()=>{
 const phases=['migrate-safe-owners-hardware-secret','prepare-safe-controls','execute-safe-controls-deployment-secret','prepare-safe-recovery-secret','execute-safe-recovery-secret','execute-mainnet-deployment-secret','authorize-pilot-funds-secret'];
 for(const phase of phases){const r=spawnSync('/usr/bin/bash',['scripts/generate-closed-mainnet-phase-command.sh',phase],{cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});assert.equal(r.status,0,`${phase}: ${r.stderr}`);assert.doesNotMatch(r.stdout,/--ledger|wallet address|wallet sign|prepare-ledger|assemble-ledger/iu,phase);const syntax=spawnSync('/usr/bin/bash',['-n'],{encoding:'utf8',input:r.stdout,env:{PATH:'/usr/bin:/bin'}});assert.equal(syntax.status,0,phase);}
});
test('production boundary checker no longer emits legacy Ledger path code',()=>{
 const checker=readFileSync(new URL('../../scripts/check-onekey-production-boundary.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(checker,/LEDGER_PRODUCTION_PATH/u);
 assert.match(checker,/PROHIBITED_HARDWARE_PATH/u);
});
