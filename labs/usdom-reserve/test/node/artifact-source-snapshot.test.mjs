import assert from 'node:assert/strict';
import {mkdir,mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {keccak256} from 'ethers';
import {assertArtifactSourcesUnchanged,snapshotArtifactSources}
  from '../../sdk/artifact-source-snapshot.mjs';

test('binds every compiler metadata source and detects later mutation',async t=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'usdom-artifact-sources-'));t.after(()=>rm(root,{recursive:true,force:true}));
 await mkdir(path.join(root,'contracts'));const source=Buffer.from('contract A {}\n');
 await writeFile(path.join(root,'contracts/A.sol'),source);
 const artifact=Buffer.from(JSON.stringify({metadata:{sources:{'contracts/A.sol':{keccak256:keccak256(source)}}}}));
 const snapshot=await snapshotArtifactSources(root,artifact);
 assert.equal(await assertArtifactSourcesUnchanged(root,snapshot),true);
 await writeFile(path.join(root,'contracts/A.sol'),'contract B {}\n');
 await assert.rejects(assertArtifactSourcesUnchanged(root,snapshot),/changed during materialization/);
});

test('rejects source bytes that disagree with artifact metadata',async t=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'usdom-artifact-sources-'));t.after(()=>rm(root,{recursive:true,force:true}));
 await writeFile(path.join(root,'A.sol'),'a');
 const artifact=Buffer.from(JSON.stringify({metadata:{sources:{'A.sol':{keccak256:keccak256(Buffer.from('b'))}}}}));
 await assert.rejects(snapshotArtifactSources(root,artifact),/differs from compiler metadata/);
});

test('rejects ambiguous artifact JSON bytes before source authority',async t=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'usdom-artifact-sources-'));t.after(()=>rm(root,{recursive:true,force:true}));
 for(const bytes of [
  Buffer.from('{"metadata":{"sources":{}},"\\u006detadata":{"sources":{"A.sol":{"keccak256":"0x'+'00'.repeat(32)+'"}}}}'),
  Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
 ]) await assert.rejects(snapshotArtifactSources(root,bytes),/duplicate (?:object )?key|invalid UTF-8/);
});

test('artifact authority uses byte-strict JSON boundary',async()=>{
 const source=await readFile(new URL('../../sdk/artifact-source-snapshot.mjs',import.meta.url),'utf8');
 assert.match(source,/parseStrictJsonBytes\(artifactBytes/);
 assert.doesNotMatch(source,/artifactBytes\.toString\(['"]utf8['"]\)/);
});
