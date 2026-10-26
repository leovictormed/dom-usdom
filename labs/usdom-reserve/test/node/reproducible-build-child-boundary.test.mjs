import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {runPinnedExecutable} from '../../sdk/pinned-executable-child.mjs';

const scripts=['reserve','verifier','checkpoint-registry','checkpoint-verifier'];

test('all reproducible Forge builds use the bounded pinned-child boundary',async()=>{
  for(const name of scripts) {
    const source=await readFile(new URL(
      `../../scripts/prepare-${name}-reproducible-build-report.mjs`,import.meta.url),'utf8');
    assert.equal((source.match(/runPinnedExecutable\(forge,/g)??[]).length,1,name);
    assert.match(source,/maxBuffer:64\*1024\*1024/);
    assert.match(source,/timeout:10\*60\*1000/);
    assert.match(source,/productionFoundryBuildArguments\(/);
    assert.match(source,/reproducibleFoundryChildEnvironment\(process\.env,configHome\)/);
    assert.match(source,/snapshotProductionSolc\(process\.env\)/);
    assert.match(source,/assertExecutableUnchanged\(solc\)/);
    assert.match(source,/compilerExecutableSha256:solc\.sha256/);
    assert.doesNotMatch(source,/execFileAsync|execFile\(|forgePath/);
    assert.match(source,/isolatedBuild\('isolated-build-a'[\s\S]*,forge,solc\)/);
    assert.match(source,/isolatedBuild\('isolated-build-b'[\s\S]*,forge,solc\)/);
  }
});

test('pinned child rejects absent resource bounds before execution',async()=>{
  await assert.rejects(runPinnedExecutable(Object.freeze({path:'/invalid'}),[],{}),
    /pinned child bounds are invalid/);
  await assert.rejects(runPinnedExecutable(Object.freeze({path:'/invalid'}),[],
    {maxBuffer:1,timeout:0}),/pinned child bounds are invalid/);
});
