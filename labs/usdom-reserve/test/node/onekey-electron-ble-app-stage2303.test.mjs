import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';

const root=new URL('../../',import.meta.url);
test('Electron BLE shell checker binds every local artifact and keeps gates closed',()=>{
 const result=spawnSync(process.execPath,['scripts/check-onekey-electron-ble-app.mjs'],{cwd:root,encoding:'utf8'});
 assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/gates closed/);
 const authority=JSON.parse(readFileSync(new URL('../../config/onekey-electron-ble-app-authority.json',import.meta.url)));
 assert.deepEqual(authority.gates,{nativeBleAdapterApproved:true,electronRuntimeApproved:false,
  rendererBundleApproved:true,physicalCeremonyApproved:false,productionTransportApproved:false});
});

test('launch command exits closed before importing an unapproved Electron runtime',()=>{
 const result=spawnSync(process.execPath,['scripts/launch-onekey-electron-ble-ceremony.mjs'],{cwd:root,encoding:'utf8'});
 assert.equal(result.status,78);assert.match(result.stderr,/BLOCKED/);
});

test('source excludes USB, hwk alpha, network and privileged renderer settings',()=>{
 const files=['main.mjs','preload.mjs','renderer.mjs','native-adapter.mjs'].map(name=>
  readFileSync(new URL(`../../electron/onekey-ble/${name}`,import.meta.url),'utf8')).join('\n');
 assert.doesNotMatch(files,/hd-transport-usb|hwk-desktop|nodeIntegration:\s*true|contextIsolation:\s*false|https?:\/\//u);
 assert.match(files,/nativeBleAdapterApproved=true/);
 assert.match(files,/session\.fromPartition/u);assert.doesNotMatch(files,/session\.defaultSession/u);
 assert.match(files,/deviceId!==policy\.expectedDeviceId/u);
 assert.match(files,/approvedFirmwareVersions\.includes\(firmware\)/u);
 assert.match(files,/api\.cancel\(connectId\)/u);assert.match(files,/finally \{await dispose\(\);\}/u);
});
