import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const source=await readFile(new URL(
  '../../scripts/materialize-finalized-burn-capacity-release-evidence.mjs',import.meta.url),'utf8');

test('finalized-burn capacity aggregate uses authenticated compare-and-swap',()=>{
  for(const value of [
    'replaceLockedParentFileDurable','expectedPreviousSha256:sha256(evidenceBytes)',
    'expectedSha256:sha256(updatedBytes)','expectedMode:0o600',
    'expectedParentDevice:String(parentMetadata.dev)','expectedParentInode:String(parentMetadata.ino)',
    'metadataInspectorSha256:pythonExecutable.sha256',
    'process.exitCode=durableReplacementFailureExitCode(error)',
  ]) assert.match(source,new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  assert.doesNotMatch(source,/writePrivateFileDurable\(path\.join\(root,'config\/mainnet-release-evidence/);
  assert.ok(source.indexOf('writePrivateFileDurableNew(path.join(root,relative),bytes)')
    <source.indexOf('replaceLockedParentFileDurable({target'));
  assert.ok(source.indexOf('replaceLockedParentFileDurable({target')
    <source.indexOf("process.stdout.write(`${JSON.stringify({status:'materialized'"));
});
