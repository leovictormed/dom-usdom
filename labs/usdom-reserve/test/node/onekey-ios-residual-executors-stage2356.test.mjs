import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import test from 'node:test';
const root=path.resolve(import.meta.dirname,'../..');
const source=name=>readFileSync(path.join(root,'scripts',name),'utf8');
const names=['execute-pilot-deposit-gate.sh','execute-pilot-deposit-gate-cancel.sh','sign-checkpoint-bootstrap-ratification.sh'];

test('all three residual phase executors use resumable iPhone WalletConnect EIP-712',()=>{
 for(const name of names){const s=source(name);assert.match(s,/prepare-onekey-ios-walletconnect-request\.mjs/,name);assert.match(s,/check-onekey-ios-walletconnect-request\.mjs/,name);assert.match(s,/sign-onekey-ios-walletconnect-typed-data\.mjs/,name);assert.match(s,/extract-onekey-ios-walletconnect-signature\.mjs/,name);assert.doesNotMatch(s,/legacy desktop signer disabled|sign-onekey-mainnet-(?:typed-data|transaction)\.mjs/,name);assert.match(s,/status|STATUS/,name);}
});

test('phase generator retains cancel and checkpoint ratification as concrete mobile phases',()=>{const generator=source('generate-closed-mainnet-phase-command.sh');assert.match(generator,/run-operational-status78-cycle\.mjs pilot-gate-cancel/);assert.match(generator,/sign:checkpoint-bootstrap-ratification/);const pkg=JSON.parse(readFileSync(path.join(root,'package.json')));for(const command of ['execute:pilot-deposit-gate','execute:pilot-deposit-gate-cancel','sign:checkpoint-bootstrap-ratification'])assert.equal(typeof pkg.scripts[command],'string',command);});

test('WalletConnect request and response are create-once lifecycle artifacts',()=>{for(const name of names){const s=source(name);assert.match(s,/if (?:test|\[\[) ! -e "?\$[A-Z_]*REQUEST|if test ! -e "\$request"/,name);assert.match(s,/if (?:test|\[\[) ! -e "?\$[A-Z_]*RESPONSE|if test ! -e "\$response"/,name);}});
