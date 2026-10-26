import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {pinnedAnvil} from './helpers/pinned-anvil.mjs';

test('local EVM tests authenticate the exact Anvil binary without ambient PATH',async()=>{
  assert.equal(await pinnedAnvil(),'/home/leonardov/.foundry/bin/anvil');
  for(const relative of [
    './helpers/evm.mjs','./evm.test.mjs','./finalized-burn-evm-integration.test.mjs',
  ]) {
    const source=await readFile(new URL(relative,import.meta.url),'utf8');
    assert.match(source,/await pinnedAnvil\(\)/);
    assert.doesNotMatch(source,/USDOM_ANVIL|\?\?\s*['"]anvil['"]/);
  }
});
