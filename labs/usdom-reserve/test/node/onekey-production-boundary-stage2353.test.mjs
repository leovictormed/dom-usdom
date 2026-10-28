import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {auditOneKeyProductionBoundary} from '../../sdk/onekey-production-boundary.mjs';
const root=resolve(import.meta.dirname,'../..');
const read=path=>JSON.parse(readFileSync(resolve(root,path)));
const inventory=read('config/onekey-production-script-inventory.json');
const legacy=read('config/onekey-legacy-lab-inventory.json');
const critical=read('config/rebuild-v3-critical-source-inventory.json');

test('Electron BLE files remain a non-executable laboratory outside the critical production inventory',()=>{
 assert.equal(legacy.classification,'laboratory-legacy-non-production');
 assert.equal(legacy.productionExecutable,false);
 assert.equal(legacy.productionRoute,'onekey-ios-walletconnect-eip712-only');
 assert.ok(legacy.paths.includes('electron/onekey-ble/renderer.bundle.mjs'));
 for(const path of legacy.paths)assert.equal(critical.criticalSources.includes(path),false,path);
});

test('every inventoried production script is free of Electron and desktop BLE legacy references',()=>{
 const sources=Object.fromEntries(inventory.scripts.map(path=>[path,readFileSync(resolve(root,path),'utf8')]));
 const report=auditOneKeyProductionBoundary({inventory,allScriptPaths:Object.keys(sources),readSource:path=>sources[path]});
 assert.deepEqual(report.violations,[]);
});

test('boundary rejects all legacy reference spellings in a productive executor',()=>{
 for(const source of ['electron/onekey-ble/main.mjs','onekey-electron-ble-app','openApprovedOneKeyBluetooth from onekey-bluetooth-factory','transport=desktop-web-ble','sign-onekey-mainnet-typed-data.mjs']){
  const report=auditOneKeyProductionBoundary({inventory:{schema:1,scripts:['scripts/execute.sh']},readSource:()=>source});
  assert.deepEqual(report.violations,[{path:'scripts/execute.sh',line:1,reason:'legacy-electron-ble-reference'}]);
 }
});
