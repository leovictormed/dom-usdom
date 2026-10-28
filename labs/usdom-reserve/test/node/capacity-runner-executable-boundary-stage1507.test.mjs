import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const scripts=await Promise.all([
  'run-checkpoint-capacity-e2e.mjs','run-finalized-burn-capacity-e2e.mjs',
].map(async name=>[name,await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8')]));

test('capacity runners authenticate fixed executables and reject ambient Anvil',()=>{
  for(const [name,source] of scripts) {
    assert.match(source,/snapshotExecutablePath/);
    assert.match(source,/assertExecutableUnchanged/);
    assert.match(source,/const CARGO='\/home\/leonardov\/\.rustup\/toolchains\/stable-x86_64-unknown-linux-gnu\/bin\/cargo'/);
    assert.match(source,/const ANVIL='\/home\/leonardov\/\.foundry\/bin\/anvil'/);
    assert.match(source,/Object\.hasOwn\(process\.env,'USDOM_ANVIL'\)/);
    assert.doesNotMatch(source,/process\.env\.USDOM_ANVIL\?\?|runCommand\('cargo'|spawn\('anvil'/,name);
  }
});

test('capacity subprocesses are bounded process groups and reattested',()=>{
  for(const [name,source] of scripts) {
    assert.match(source,/detached:true/);
    assert.match(source,/12\*60\*60\*1000/);
    assert.match(source,/process\.kill\(-child\.pid,'SIGKILL'\)/);
    assert.match(source,/await assertExecutableUnchanged\(executable\)/);
    assert.match(source,/await assertExecutableUnchanged\(anvil\)/);
    assert.match(source,/TIME,\[\s*'-v','-o',[\s\S]*CARGO/);
  }
});
