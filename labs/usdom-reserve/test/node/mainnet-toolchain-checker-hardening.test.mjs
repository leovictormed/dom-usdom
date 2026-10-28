import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const checker=new URL('../../scripts/check-mainnet-toolchain.mjs',import.meta.url);

test('mainnet toolchain checker authenticates bytes, versions and final executable identity',async()=>{
  const source=await readFile(checker,'utf8');
  assert.match(source,/readDirectProjectFile\(root,'config\/mainnet-toolchain-lock\.json'/);
  assert.match(source,/parseStrictJsonBytes\(lockBytes/);
  assert.match(source,/snapshotExecutablePath\(tool\.path\)/);
  assert.match(source,/snapshot\.path!==tool\.realpath\|\|snapshot\.sha256!==tool\.sha256/);
  assert.match(source,/runPinnedExecutable\(snapshot,policy\.args/);
  assert.match(source,/version\.includes\(policy\.version\)/);
  assert.match(source,/seenTools\.has\(tool\.name\)/);
  assert.match(source,/seenFiles\.has\(file\.path\)/);
  assert.match(source,/Promise\.all\(snapshots\.map\(assertExecutableUnchanged\)\)/);
  assert.doesNotMatch(source,/\breadFileSync\b|\brealpathSync\b|\bstatSync\b|parseStrictJson\(/);
});

test('mainnet toolchain checker uses a closed file and tool inventory',async()=>{
  const source=await readFile(checker,'utf8');
  for(const tool of ['bash','node','npm','forge','cast','rustc','cargo','python3','jq']) {
    assert.match(source,new RegExp(`\\['${tool}',\\{args:`));
  }
  for(const file of ['package-lock.json','../../Cargo.lock','foundry.toml']) {
    assert.ok(source.includes(`['${file}',`));
  }
  assert.match(source,/lock\.executables\.length!==toolPolicies\.size/);
  assert.match(source,/lock\.files\.length!==lockedFiles\.size/);
  assert.match(source,/readDirectProjectFile\(repositoryRoot,lockedFiles\.get\(file\.path\)/);
});

test('checker and repository agree on the exact pinned Rust selector',async()=>{
  const [source,selector]=await Promise.all([
    readFile(checker,'utf8'),
    readFile(new URL('../../../../rust-toolchain.toml',import.meta.url),'utf8'),
  ]);
  const expected='[toolchain]\nchannel = "1.98.0"\ncomponents = ["rustfmt", "clippy"]\n';
  assert.equal(selector,expected);
  assert.match(source,/const expectedRustToolchain=Buffer\.from\(/);
  assert.ok(source.includes(`'[toolchain]\\nchannel = "1.98.0"\\ncomponents = ["rustfmt", "clippy"]\\n'`));
  assert.match(source,/rustToolchain\.equals\(expectedRustToolchain\)/);
  assert.doesNotMatch(source,/channel = \\"stable\\"|\.includes\('channel/);
});

test('the closed file inventory hashes the exact current release inputs',async()=>{
  const lock=JSON.parse(await readFile(
    new URL('../../config/mainnet-toolchain-lock.json',import.meta.url),'utf8'));
  const targets=new Map([
    ['package-lock.json',new URL('../../package-lock.json',import.meta.url)],
    ['containers/risc0-snarkjs/package-lock.json',
      new URL('../../containers/risc0-snarkjs/package-lock.json',import.meta.url)],
    ['../../Cargo.lock',new URL('../../../../Cargo.lock',import.meta.url)],
    ['foundry.toml',new URL('../../foundry.toml',import.meta.url)],
    ['scripts/mainnet-tool-dispatcher',new URL('../../scripts/mainnet-tool-dispatcher',import.meta.url)],
  ]);
  assert.equal(lock.files.length,targets.size);
  for(const entry of lock.files) {
    assert.ok(targets.has(entry.path),entry.path);
    const digest=createHash('sha256').update(await readFile(targets.get(entry.path))).digest('hex');
    assert.equal(entry.sha256,digest,entry.path);
  }
});
