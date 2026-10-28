#!/usr/bin/env node
import {readFileSync,readdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {auditOneKeyProductionBoundary} from '../sdk/onekey-production-boundary.mjs';

const root=resolve(new URL('..',import.meta.url).pathname);
const inventory=JSON.parse(readFileSync(resolve(root,
 'config/onekey-production-script-inventory.json'),'utf8'));
const legacy=JSON.parse(readFileSync(resolve(root,
 'config/onekey-legacy-lab-inventory.json'),'utf8'));
if(legacy.schema!=='usdom-onekey-legacy-lab-inventory-v1'||legacy.productionExecutable!==false
 ||legacy.classification!=='laboratory-legacy-non-production'
 ||!Array.isArray(legacy.paths)||legacy.paths.length===0
 ||new Set(legacy.paths).size!==legacy.paths.length) throw new Error('invalid OneKey legacy lab inventory');
const allScriptPaths=readdirSync(resolve(root,'scripts'),{withFileTypes:true})
 .filter(entry=>entry.isFile()&&/\.(?:sh|mjs)$/u.test(entry.name))
 .map(entry=>`scripts/${entry.name}`).sort();
const result=auditOneKeyProductionBoundary({inventory,
 allScriptPaths,readSource:path=>readFileSync(resolve(root,path),'utf8')});
if(!result.ok) {
 for(const violation of result.violations) {
  process.stderr.write(`PROHIBITED_HARDWARE_PATH ${violation.path}:${violation.line}\n`);
 }
 process.exit(1);
}
process.stdout.write(`PASS: ${result.checked} inventoried OneKey production scripts; `
 +`${result.discovered} scripts discovered without prohibited hardware options\n`);
