#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {buildOneKeyBleRenderer} from './build-onekey-electron-ble-renderer.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const root=resolve(import.meta.dirname,'..'),blocked='electron/onekey-ble/blocked-module.mjs';
const forbidden=['@onekeyfe/hd-transport-http','@onekeyfe/hd-transport-emulator',
 '@onekeyfe/hd-transport-lowlevel','@onekeyfe/hd-transport-usb','usb','axios','http','https','net','tls'];
const meta=parseStrictJson(readFileSync(resolve(root,'electron/onekey-ble/renderer.bundle.meta.json'),'utf8'),
 {label:'OneKey renderer metafile',maxBytes:1024*1024});
for(const input of Object.keys(meta.inputs)) if(forbidden.some(name=>input===`node_modules/${name}`||input.startsWith(`node_modules/${name}/`))) {
 throw new Error(`forbidden executable renderer input: ${input}`);
}
const aliases=new Set();
for(const value of Object.values(meta.inputs)) for(const edge of value.imports??[]) {
 if(forbidden.includes(edge.original)){if(edge.path!==blocked)throw new Error(`forbidden import not fail-closed: ${edge.original}`);aliases.add(edge.original);}
}
for(const required of ['@onekeyfe/hd-transport-http','@onekeyfe/hd-transport-emulator','@onekeyfe/hd-transport-lowlevel',
 '@onekeyfe/hd-transport-usb','axios']) if(!aliases.has(required)) throw new Error(`missing fail-closed alias evidence: ${required}`);
for(const output of Object.values(meta.outputs)) if((output.imports??[]).length) throw new Error('renderer bundle retains external imports');
const first=await buildOneKeyBleRenderer({write:false}),second=await buildOneKeyBleRenderer({write:false});
const expected=readFileSync(resolve(root,'electron/onekey-ble/renderer.bundle.mjs'));
const one=Buffer.from(first.result.outputFiles[0].contents),two=Buffer.from(second.result.outputFiles[0].contents);
if(!one.equals(two)||!one.equals(expected))throw new Error('OneKey renderer bundle is not reproducible');
if(JSON.stringify(first.normalized)!==JSON.stringify(meta))throw new Error('OneKey renderer metafile drift');
process.stdout.write('PASS: OneKey BLE renderer bundle reproducible; forbidden transports/network aliases fail closed\n');
