import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,mkdtemp,readFile,readdir,rm,symlink,writeFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {tmpdir} from 'node:os';
import path from 'node:path';

const script=new URL('../../scripts/remove-private-directory-durable.mjs',import.meta.url);
const node='/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node';
const run=target=>new Promise(resolve=>{
  const child=spawn(node,[script.pathname,target],{stdio:['ignore','pipe','pipe']});
  let stderr=''; child.stderr.on('data',chunk=>stderr+=chunk);
  child.on('close',code=>resolve({code,stderr}));
});

test('private directory removal recovers SIGKILL tombstones and concurrent starts',async t=>{
  const parent=await mkdtemp(path.join(tmpdir(),'usdom-private-purge-'));
  t.after(()=>rm(parent,{recursive:true,force:true}));
  const target=path.join(parent,'observed-state');
  const staleInvalid=path.join(parent,'.observed-state.invalid.'+'11'.repeat(12));
  const stalePurge=path.join(parent,'.observed-state.purge.'+'22'.repeat(12));
  for(const directory of [target,staleInvalid,stalePurge]) {
    await mkdir(directory,{mode:0o700});
    await writeFile(path.join(directory,'secret'),'sensitive',{mode:0o600});
  }
  const results=await Promise.all([run(target),run(target)]);
  assert(results.every(result=>result.code===0),JSON.stringify(results));
  assert.deepEqual(await readdir(parent),[]);
});

test('private directory removal fails closed on an indirect orphan tombstone',async t=>{
  const parent=await mkdtemp(path.join(tmpdir(),'usdom-private-purge-link-'));
  t.after(()=>rm(parent,{recursive:true,force:true}));
  const outside=await mkdtemp(path.join(tmpdir(),'usdom-private-purge-victim-'));
  t.after(()=>rm(outside,{recursive:true,force:true}));
  await writeFile(path.join(outside,'keep'),'untouched');
  const tombstone=path.join(parent,'.observed-state.invalid.'+'33'.repeat(12));
  await symlink(outside,tombstone);
  const result=await run(path.join(parent,'observed-state'));
  assert.notEqual(result.code,0); assert.match(result.stderr,/tombstone is unsafe/);
  assert.equal(await readFile(path.join(outside,'keep'),'utf8'),'untouched');
});
