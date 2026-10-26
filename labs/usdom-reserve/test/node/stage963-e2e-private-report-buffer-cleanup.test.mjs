import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const scripts=[
  'run-finalized-burn-release-e2e.mjs',
  'run-checkpoint-capacity-e2e.mjs',
  'run-finalized-burn-capacity-e2e.mjs',
];

test('E2E private report hash reads erase their Buffer immediately',async()=>{
  for(const name of scripts) {
    const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
    assert.match(source,/async function privateFileSha[\s\S]*finally \{ bytes\.fill\(0\); \}/,name);
    assert.equal((source.match(/await privateFileSha\(/g)||[]).length,1,name);
    assert.doesNotMatch(source,/rawSha\(await readDirectFile\(/,name);
  }
});
