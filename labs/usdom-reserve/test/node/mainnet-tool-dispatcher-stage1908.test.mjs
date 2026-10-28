import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,chmodSync,readFileSync,existsSync,mkdirSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const dispatcher=path.join(root,'scripts/mainnet-tool-dispatcher');
const run=(args,env={})=>spawnSync(dispatcher,args,{cwd:root,encoding:'utf8',env:{...process.env,...env}});
test('all package scripts and chained segments use the static authenticated dispatcher',()=>{
 const result=run(['node','scripts/check-package-tool-dispatch-policy.mjs']);
 assert.equal(result.status,0,result.stderr); assert.match(result.stdout,/PASS: 169 package scripts/);
});
test('PATH shims cannot replace bash, node, python3, forge, or npm',()=>{
 const directory=mkdtempSync(path.join(tmpdir(),'usdom-dispatch-shims-'));
 for(const name of ['bash','node','python3','forge','npm']){const target=path.join(directory,name);writeFileSync(target,'#!/bin/sh\necho USDOM_PATH_SHIM_EXECUTED >&2\nexit 97\n');chmodSync(target,0o700);}
 const cases=[
  [['bash','test/fixtures/dispatcher-ok.sh'],/dispatcher-bash-ok/],
  [['node','--version'],/^v24\.19\.0/mu],
  [['python3','scripts/source-manifest.py','--self-test'],/PASS: source manifest/],
  [['forge','--version'],/forge Version: 1\.8\.5/mu],
  [['npm','--version'],/^11\.17\.0/mu],
 ];
 for(const [args,expected] of cases){const result=run(args,{PATH:directory,BASH_ENV:path.join(directory,'bash'),NODE_OPTIONS:'--require=/outside'});assert.equal(result.status,0,`${args[0]}: ${result.stderr}`);assert.doesNotMatch(result.stderr,/USDOM_PATH_SHIM_EXECUTED/);assert.match(result.stdout,expected);}
});
test('nested scripts resolve the entire authenticated toolchain through the private FD PATH',()=>{
 const directory=mkdtempSync(path.join(tmpdir(),'usdom-internal-shims-'));
 for(const name of ['bash','node','npm','python3','forge','cast','rustc','cargo','solc','jq']){const target=path.join(directory,name);writeFileSync(target,'#!/bin/sh\necho USDOM_INTERNAL_PATH_SHIM_EXECUTED >&2\nexit 96\n');chmodSync(target,0o700);}
 const result=run(['bash','test/fixtures/dispatcher-internal-tools.sh'],{PATH:directory});
 assert.equal(result.status,0,result.stderr);assert.doesNotMatch(result.stderr,/USDOM_INTERNAL_PATH_SHIM_EXECUTED/);
 for(const expected of ['v24.19.0','11.17.0','Python 3.12.3','forge Version: 1.8.5','cast Version: 1.8.5','rustc 1.98.0','cargo 1.98.0','Version: 0.8.37','jq-1.7'])assert.ok(result.stdout.includes(expected),expected);
});
test('interpreted scripts outside the repository are rejected',()=>{
 const outside=path.join(mkdtempSync(path.join(tmpdir(),'usdom-dispatch-outside-')),'attack.mjs');writeFileSync(outside,'process.exit(0)\n');
 const result=run(['node',outside]);assert.equal(result.status,70);assert.match(result.stderr,/script escapes repository/);
});
test('dispatcher is statically linked and byte-bound',()=>{
 const binary=readFileSync(dispatcher);assert.equal(binary.subarray(0,4).toString('hex'),'7f454c46');assert.equal(binary.includes(Buffer.from('/lib64/ld-linux')),false);
});
test('environment sanitation precedes every execution route including repo-exec',()=>{
 const source=readFileSync(path.join(root,'scripts/mainnet-tool-dispatcher.c'),'utf8');
 const main=source.slice(source.indexOf('int main('));
 assert.ok(main.indexOf('sanitize_environment();')<main.indexOf('if(!strcmp(tool,"repo-exec"))'));
 assert.equal((source.match(/sanitize_environment\(\);/gu)||[]).length,1);
});
test('Python user-site startup code cannot cross the dispatcher boundary',()=>{
 const directory=mkdtempSync(path.join(tmpdir(),'usdom-python-user-site-'));
 const site=path.join(directory,'lib/python3.12/site-packages');mkdirSync(site,{recursive:true});
 const marker=path.join(directory,'executed');
 writeFileSync(path.join(site,'sitecustomize.py'),`from pathlib import Path\nPath(${JSON.stringify(marker)}).write_text('executed')\n`);
 const result=run(['python3','scripts/source-manifest.py','--self-test'],{PYTHONUSERBASE:directory,PYTHONNOUSERSITE:'0',PYTHONSAFEPATH:'0'});
 assert.equal(result.status,0,result.stderr);assert.equal(existsSync(marker),false);
});
test('Cargo, Rust and dynamic-loader injection variables are removed',()=>{
 const poison={};
 for(const name of ['CARGO_HOME','CARGO_TARGET_DIR','CARGO_BUILD_RUSTC','CARGO_BUILD_RUSTC_WRAPPER','CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_TARGET','CARGO_ENCODED_RUSTFLAGS','CARGO_NET_GIT_FETCH_WITH_CLI','RUSTC','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTFLAGS','RUSTDOC','RUSTDOCFLAGS','LD_PRELOAD','LD_LIBRARY_PATH','LD_AUDIT'])poison[name]='/attacker';
 const result=run(['bash','test/fixtures/dispatcher-clean-env.sh'],poison);
 assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/dispatcher-clean-env-ok/);
});
