import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync,chmodSync} from 'node:fs';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {checkOneKeyElectronBlePolicy,readOneKeyElectronBlePolicy,
 oneKeyElectronBlePolicyMaximumBytes} from '../../sdk/onekey-electron-ble-handoff-policy.mjs';

const authority=JSON.parse(readFileSync(new URL(
 '../../config/onekey-electron-ble-handoff-policy.unconfigured.json',import.meta.url),'utf8'));
const clone=()=>structuredClone(authority);
const rejected=policy=>assert.throws(()=>checkOneKeyElectronBlePolicy(policy),/fail-closed authority/u);

test('future Electron BLE handoff authority is complete and remains unapproved',()=>{
 assert.deepEqual(checkOneKeyElectronBlePolicy(authority),{
  ok:true,status:'unconfigured',hardwareSigningApproved:false});
});

test('Electron renderer hardening cannot be weakened',()=>{
 for(const mutate of [
  p=>{p.browserWindow.contextIsolation=false;},p=>{p.browserWindow.nodeIntegration=true;},
  p=>{p.browserWindow.sandbox=false;},p=>{p.browserWindow.productionDevTools=true;},
  p=>{p.browserWindow.navigation=true;},p=>{p.browserWindow.popups=true;},
  p=>{p.contentSecurityPolicy=p.contentSecurityPolicy.replace("connect-src 'none'","connect-src https:");},
 ]) { const policy=clone(); mutate(policy); rejected(policy); }
});

test('preload and IPC envelopes are exact and integrity-bound',()=>{
 for(const mutate of [
  p=>{p.preloadAllowlist.push('broadcast');},p=>{p.ipc.requestFields.pop();},
  p=>{p.ipc.responseFields.push('debug');},p=>{p.ipc.exactSchemas=false;},
  p=>{p.ipc.nonceRequired=false;},p=>{p.ipc.payloadHashRequired=false;},
  p=>{p.ipc.requestHashRequired=false;},p=>{p.ipc.resultHashRequired=false;},
 ]) { const policy=clone(); mutate(policy); rejected(policy); }
});

test('durable output, secrets and transport remain fail-closed',()=>{
 for(const mutate of [
  p=>{p.durableOutput.mode='0644';},p=>{p.durableOutput.createOnce=false;},
  p=>{p.durableOutput.overwrite=true;},p=>{p.forbiddenCapabilities.splice(0,1);},
  p=>{p.transport.allowed.push('usb');},p=>{p.transport.forbiddenFallbacks.splice(2,1);},
  p=>{p.hardwareSigningApproved=true;},
 ]) { const policy=clone(); mutate(policy); rejected(policy); }
});

test('policy reader rejects duplicate keys at top level and nested objects',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'onekey-electron-policy-'));
 try {
  for(const payload of [
   '{"schema":"a","schema":"b"}',
   '{"browserWindow":{"sandbox":true,"sandbox":false}}',
  ]) {
   const path=join(directory,'policy.json');
   writeFileSync(path,payload,{mode:0o600}); chmodSync(path,0o600);
   await assert.rejects(readOneKeyElectronBlePolicy(path),/duplicate object key/u);
  }
 } finally { await rm(directory,{recursive:true,force:true}); }
});

test('policy reader rejects unsafe mode and oversized input',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'onekey-electron-policy-'));
 const path=join(directory,'policy.json');
 try {
  writeFileSync(path,'{}',{mode:0o644}); chmodSync(path,0o644);
  await assert.rejects(readOneKeyElectronBlePolicy(path),/mode|safe direct regular file/u);
  writeFileSync(path,' '.repeat(oneKeyElectronBlePolicyMaximumBytes+1),{mode:0o600});
  chmodSync(path,0o600);
  await assert.rejects(readOneKeyElectronBlePolicy(path),
   /size|maximum|large|bounds|safe direct regular file/u);
 } finally { await rm(directory,{recursive:true,force:true}); }
});
