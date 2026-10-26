import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const scripts=[
  '../../scripts/materialize-finalized-burn-release-evidence.mjs',
  '../../scripts/materialize-checkpoint-capacity-release-evidence.mjs',
];

test('release evidence materializers pin and bound every Git inspection',async()=>{
  for(const relative of scripts) {
    const source=await readFile(new URL(relative,import.meta.url),'utf8');
    const capture=source.slice(source.indexOf('async function captureGit('),
      source.indexOf('\n}\n\nasync function assertSourceBoundary',source.indexOf('async function captureGit('))+2);
    assert.match(source,/const gitExecutable=await snapshotExecutable\('git'\)/);
    assert.match(source,/runPinnedExecutable\(gitExecutable,args,/);
    assert.match(source,/maxBuffer:maximum,timeout:30_000/);
    assert.match(source,/result\.stderr\.length!==0/);
    assert.match(source,/new TextDecoder\('utf-8',\{fatal:true\}\)\.decode\(result\.stdout\)/);
    assert.doesNotMatch(capture,/spawn\('git'|execFile|\.toString\('utf8'\)/);
  }
});
