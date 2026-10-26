import assert from 'node:assert/strict';
import {chmod,link,mkdtemp,rm,truncate,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {assertExecutableUnchanged,snapshotExecutable,snapshotExecutablePath} from '../../sdk/stable-executable.mjs';

test('pins one executable by absolute resolved path, inode and content hash',async t=>{
 const directory=await mkdtemp(path.join(os.tmpdir(),'usdom-executable-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 const executable=path.join(directory,'forge');await writeFile(executable,'#!/bin/sh\nexit 0\n');await chmod(executable,0o700);
 const snapshot=await snapshotExecutable('forge',{pathValue:`relative:${directory}`});
 assert.equal(snapshot.path,executable);assert.match(snapshot.sha256,/^[0-9a-f]{64}$/);
 assert.equal(await assertExecutableUnchanged(snapshot),true);
 await writeFile(executable,'#!/bin/sh\nexit 1\n');await chmod(executable,0o700);
 await assert.rejects(assertExecutableUnchanged(snapshot),/changed during materialization/);
});

test('rejects relative-only PATH and invalid executable names',async()=>{
 await assert.rejects(snapshotExecutable('forge',{pathValue:'relative'}),/absolute PATH/);
 await assert.rejects(snapshotExecutable('../forge',{pathValue:'/bin'}),/name is invalid/);
});

test('rejects writable and hard-linked executable installations',async t=>{
 const directory=await mkdtemp(path.join(os.tmpdir(),'usdom-unsafe-executable-'));
 t.after(()=>rm(directory,{recursive:true,force:true}));
 const executable=path.join(directory,'forge');await writeFile(executable,'binary');await chmod(executable,0o722);
 await assert.rejects(snapshotExecutable('forge',{pathValue:directory}),/safely owned/);
 await chmod(executable,0o700);await link(executable,path.join(directory,'forge-copy'));
 await assert.rejects(snapshotExecutable('forge',{pathValue:directory}),/safely owned/);
});

test('rejects writable parent directories and oversized executable input before reading it',async t=>{
 const directory=await mkdtemp(path.join(os.tmpdir(),'usdom-executable-boundary-'));
 t.after(()=>rm(directory,{recursive:true,force:true}));
 const executable=path.join(directory,'forge');await writeFile(executable,'binary');await chmod(executable,0o700);
 await chmod(directory,0o777);
 await assert.rejects(snapshotExecutable('forge',{pathValue:directory}),/immutable directory/);
 await chmod(directory,0o700);await truncate(executable,512*1024*1024+1);
 await assert.rejects(snapshotExecutable('forge',{pathValue:directory}),/immutable executable/);
});

test('absolute executable snapshot applies the same identity boundary',async t=>{
 const directory=await mkdtemp(path.join(os.tmpdir(),'usdom-executable-path-'));
 t.after(()=>rm(directory,{recursive:true,force:true}));
 const executable=path.join(directory,'verifier');
 await writeFile(executable,'#!/bin/sh\nexit 0\n');await chmod(executable,0o700);
 const snapshot=await snapshotExecutablePath(executable);
 assert.equal(snapshot.path,executable);assert.equal(await assertExecutableUnchanged(snapshot),true);
 await writeFile(executable,'#!/bin/sh\nexit 1\n');await chmod(executable,0o700);
 await assert.rejects(assertExecutableUnchanged(snapshot),/changed during materialization/);
 await assert.rejects(snapshotExecutablePath('verifier'),/must be absolute/);
});
