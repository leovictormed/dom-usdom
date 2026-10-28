#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {auditOneKeySdkDependencyAuthority} from '../sdk/onekey-sdk-dependency-authority.mjs';

const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const read=(path,label)=>parseStrictJson(readFileSync(resolve(root,path),'utf8'),{label,maxBytes:8*1024*1024});
const auditPath=process.argv[2];
const result=auditOneKeySdkDependencyAuthority({
 authority:read('config/onekey-sdk-dependency-authority.json','OneKey dependency authority'),
 packageJson:read('package.json','package.json'),
 packageLock:read('package-lock.json','package-lock.json'),
 auditReport:auditPath?parseStrictJson(readFileSync(auditPath,'utf8'),{label:'npm audit report'}):undefined,
});
if(!result.ok) {
 for(const violation of result.violations) process.stderr.write(`${violation.reason}: ${violation.detail}\n`);
 process.exit(1);
}
process.stdout.write(`PASS: ${result.packages} OneKey/runtime dependency artifacts pinned; audit zero; hardware gate closed\n`);
