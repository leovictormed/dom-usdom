#!/usr/bin/env node
import {readdirSync,readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const self=fileURLToPath(import.meta.url),root=path.resolve(path.dirname(self),'..');
const fail=message=>{throw new Error(message);};
const read=relative=>readFileSync(path.join(root,relative),'utf8');
const foundry=read('foundry.toml');
for(const line of ['remappings = ["@openzeppelin/contracts/=vendor/openzeppelin-contracts-5.6.1/"]','solc_version = "0.8.37"','evm_version = "cancun"','optimizer = true','optimizer_runs = 1','via_ir = true','bytecode_hash = "none"','ast = true']) if(!foundry.includes(line)) fail(`Foundry release setting missing: ${line}`);
if((foundry.match(/@openzeppelin\/contracts\//g)??[]).length!==1||foundry.includes('openzeppelin-contracts-5.0.2')) fail('OpenZeppelin remapping is ambiguous');
if(JSON.parse(read('vendor/openzeppelin-contracts-5.6.1/package.json')).version!=='5.6.1') fail('selected OpenZeppelin vendor identity drifted');
for(const base of ['contracts','sdk','scripts','test']) { const stack=[path.join(root,base)]; while(stack.length) { const current=stack.pop(); for(const entry of readdirSync(current,{withFileTypes:true})) { const target=path.join(current,entry.name); if(entry.isDirectory()) stack.push(target); else if(entry.isFile()&&target!==self&&readFileSync(target).includes(Buffer.from('openzeppelin-contracts-5.0.2'))) fail(`retired OpenZeppelin tree is referenced by pilot code: ${path.relative(root,target)}`); } } }
for(const name of ['reserve','checkpoint-registry','verifier','checkpoint-verifier']) { const value=read(`sdk/${name}-reproducible-build-report.mjs`); for(const flag of ['--offline','--no-auto-detect','--use <sha256-pinned-solc-0.8.37>','--evm-version cancun','--optimize','--optimizer-runs 1','--via-ir','--force','--out <isolated>','--cache-path <isolated>','-D warnings']) if(!value.includes(flag)) fail(`${name} reproducible command lacks ${flag}`); if(value.includes('--optimizer-runs 200')) fail(`${name} records stale optimizer settings`); }
const generator=read('scripts/generate-closed-mainnet-phase-command.sh');
for(const line of generator.split('\n').filter(line=>/\bcargo (?:test|build|run)\b/.test(line))) if(!line.includes('--locked')||!line.includes('--offline')) fail(`unlocked/online Cargo invocation: ${line.trim()}`);
if(!generator.includes('npm ci --offline --ignore-scripts --audit=false')) fail('offline npm lockfile install is absent');
for(const executable of ['node','npm','forge','cargo']) if(!generator.includes(`test "\\$(command -v ${executable})" =`)) fail(`${executable} path is not pinned`);
if(!generator.includes('node scripts/check-mainnet-toolchain.mjs')) fail('tool binary hash checker is absent');
console.log('PASS: pilot build settings, dependency selection and toolchain bindings are unambiguous');
