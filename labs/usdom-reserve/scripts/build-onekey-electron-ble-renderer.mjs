#!/usr/bin/env node
import {build} from 'esbuild';
import {writeFileSync} from 'node:fs';
import {resolve} from 'node:path';

const root=resolve(import.meta.dirname,'..');
const blocked=resolve(root,'electron/onekey-ble/blocked-module.mjs');
const forbidden=['@onekeyfe/hd-transport-http','@onekeyfe/hd-transport-emulator',
 '@onekeyfe/hd-transport-lowlevel','@onekeyfe/hd-transport-usb','usb','axios','http','https','net','tls'];
export async function buildOneKeyBleRenderer({write=true}={}) {
const result=await build({entryPoints:[resolve(root,'electron/onekey-ble/renderer.mjs')],
 outfile:resolve(root,'electron/onekey-ble/renderer.bundle.mjs'),bundle:true,platform:'browser',format:'esm',
 target:['chrome142'],metafile:true,write:true,legalComments:'none',charset:'utf8',treeShaking:true,
 logLevel:'silent',write,plugins:[{name:'usdom-deny-non-ble',setup(api){
  api.onResolve({filter:/.*/},args=>forbidden.includes(args.path)?{path:blocked}:null);
 }}]});
const normalized={inputs:Object.fromEntries(Object.entries(result.metafile.inputs).sort()),
 outputs:Object.fromEntries(Object.entries(result.metafile.outputs).sort())};
if(write) writeFileSync(resolve(root,'electron/onekey-ble/renderer.bundle.meta.json'),`${JSON.stringify(normalized,null,2)}\n`,{mode:0o644});
return {result,normalized};
}
if(process.argv[1]===new URL(import.meta.url).pathname) await buildOneKeyBleRenderer();
