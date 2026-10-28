import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';

const root=new URL('../../',import.meta.url);
test('renderer bundle is byte reproducible and every forbidden SDK edge resolves to the blocker',()=>{
 const run=spawnSync(process.execPath,['scripts/check-onekey-electron-ble-bundle.mjs'],{cwd:root,encoding:'utf8'});
 assert.equal(run.status,0,run.stderr);assert.match(run.stdout,/reproducible/u);
 const meta=JSON.parse(readFileSync(new URL('../../electron/onekey-ble/renderer.bundle.meta.json',import.meta.url)));
 const forbidden=new Set(['@onekeyfe/hd-transport-http','@onekeyfe/hd-transport-emulator',
  '@onekeyfe/hd-transport-lowlevel','@onekeyfe/hd-transport-usb','axios']);
 const edges=Object.values(meta.inputs).flatMap(value=>value.imports??[]).filter(edge=>forbidden.has(edge.original));
 assert.equal(new Set(edges.map(edge=>edge.original)).size,forbidden.size);
 assert.ok(edges.every(edge=>edge.path==='electron/onekey-ble/blocked-module.mjs'));
 assert.ok(Object.values(meta.outputs).every(output=>(output.imports??[]).length===0));
});

test('Electron package is pinned but executable and Linux production gates remain closed',()=>{
 const authority=JSON.parse(readFileSync(new URL('../../config/onekey-electron-ble-app-authority.json',import.meta.url)));
 assert.equal(authority.electronRuntimePackage.version,'44.10.0');
 assert.equal(authority.electronRuntimePackage.executableSha256,null);
 assert.equal(authority.electronRuntimePackage.installedExecutableVerified,false);
 assert.equal(authority.gates.rendererBundleApproved,true);
 assert.equal(authority.gates.electronRuntimeApproved,false);
 assert.equal(authority.gates.productionTransportApproved,false);
});
