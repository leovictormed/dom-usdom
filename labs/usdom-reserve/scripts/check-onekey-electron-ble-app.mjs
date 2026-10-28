#!/usr/bin/env node
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const root=resolve(import.meta.dirname,'..');
const authority=parseStrictJson(readFileSync(resolve(root,'config/onekey-electron-ble-app-authority.json'),'utf8'),{label:'OneKey Electron BLE app authority'});
const packageJson=parseStrictJson(readFileSync(resolve(root,'package.json'),'utf8'),{label:'package.json'});
const packageLock=parseStrictJson(readFileSync(resolve(root,'package-lock.json'),'utf8'),{label:'package-lock.json',maxBytes:8*1024*1024});
if(authority.schema!=='usdom-onekey-electron-ble-app-authority-v1'||authority.hardwareSigningApproved!==false
 ||authority.runtimeTransport!=='desktop-web-ble'||authority.gates?.nativeBleAdapterApproved!==true
 ||authority.gates?.rendererBundleApproved!==true||authority.gates?.electronRuntimeApproved!==false
 ||authority.gates?.productionTransportApproved!==false
 ||authority.gates?.physicalCeremonyApproved!==false||authority.approvedFirmwareVersions?.length!==0
 ||authority.runtimeLauncher?.electronExecutable!==null||authority.runtimeLauncher?.electronExecutableSha256!==null
 ||authority.runtimeLauncher?.mainPath!=='electron/onekey-ble/main.mjs') throw new Error('OneKey Electron BLE app gate is inconsistent');
for(const [path,expected] of Object.entries(authority.artifacts??{})) {
 const actual=createHash('sha256').update(readFileSync(resolve(root,path))).digest('hex');
 if(actual!==expected) throw new Error(`OneKey Electron BLE artifact drift: ${path}`);
}
if(authority.runtimeLauncher.mainSha256!==authority.artifacts[authority.runtimeLauncher.mainPath]) {
 throw new Error('OneKey Electron main launcher hash is not bound to the artifact authority');
}
for(const [name,pin] of [['electron',authority.electronRuntimePackage],['esbuild',authority.rendererBuild]]) {
 if(packageJson.devDependencies?.[name]!==pin.version)throw new Error(`${name} dev dependency pin drift`);
 const locked=packageLock.packages?.[`node_modules/${name}`];
 if(locked?.version!==pin.version||locked?.integrity!==pin.integrity||locked?.license!=='MIT')throw new Error(`${name} lock authority drift`);
}
const platform=packageLock.packages?.[`node_modules/${authority.rendererBuild.platformPackage}`];
if(platform?.version!==authority.rendererBuild.platformVersion||platform?.integrity!==authority.rendererBuild.platformIntegrity) {
 throw new Error('esbuild platform binary authority drift');
}
if(authority.electronRuntimePackage.executableSha256!==null
  ||authority.electronRuntimePackage.installedExecutableVerified!==false)throw new Error('Electron executable gate is not closed');
const renderer=readFileSync(resolve(root,'electron/onekey-ble/renderer.mjs'),'utf8');
for(const forbidden of authority.rendererBundle.forbiddenModules) {
 if(renderer.includes(forbidden)) throw new Error(`forbidden renderer import: ${forbidden}`);
}
const main=readFileSync(resolve(root,'electron/onekey-ble/main.mjs'),'utf8');
for(const forbidden of ['fetch(','http://','https://','nodeIntegration:true','contextIsolation:false','sandbox:false']) {
 if(main.includes(forbidden)) throw new Error(`unsafe Electron main source: ${forbidden}`);
}
process.stdout.write('PASS: OneKey Electron BLE shell and minimal Noble adapter pinned; bundle/runtime/firmware/physical gates closed\n');
