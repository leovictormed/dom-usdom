import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

test('solc lock materializer replaces exact authenticated prior bytes through durable CAS',async()=>{
  const source=await readFile(new URL(
    '../../scripts/materialize-solc-toolchain-lock.mjs',import.meta.url),'utf8');
  assert.match(source,/replaceLockedParentFileDurable/);
  assert.match(source,/expectedPreviousSha256:sha\(before\)/);
  assert.match(source,/expectedParentDevice:String\(directoryIdentity\.dev\)/);
  assert.match(source,/expectedParentInode:String\(directoryIdentity\.ino\)/);
  assert.match(source,/expectedMode:0o600/);
  assert.match(source,/durableReplacementFailureExitCode\(error\)/);
  assert.doesNotMatch(source,/renameSync\(/);
});
