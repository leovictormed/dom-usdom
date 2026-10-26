import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const source=await readFile(new URL(
  '../../scripts/prepare-authenticated-checkpoint-submission.mjs',import.meta.url),'utf8');

test('checkpoint submission package is private, immutable and release-bound through write',()=>{
  assert.match(source,/mkdir\(outputDirectory,\{recursive:true,mode:0o700\}\)/);
  assert.ok(source.includes('(metadata.mode&0o077)!==0'));
  assert.match(source,/writePrivateFileDurableNew\(outputPath,bytes/);
  assert.match(source,/removePrivateFileDurableIfExists\(outputPath\)/);
  assert.doesNotMatch(source,/writePrivateFileDurable\(outputPath,bytes/);
  assert.match(source,/authenticated checkpoint submission inputs changed during preparation/);
  assert.match(source,/usdom-checkpoint-submission\./);
  assert.match(source,/privateInputReplica\(authenticatedInputs\)/);
  assert.match(source,/privateMode:true,minimum:1/);
  assert.match(source,/installed\.equals\(output\)/);
  assert.match(source,/packageSha256=createHash\('sha256'\)\.update\(installed\)/);
  assert.match(source,/currentInputs\.some\(\(bytes,index\)=>!bytes\.equals\(authenticatedInputs\[index\]\)\)/);
  assert.ok(source.indexOf('privateInputReplica(authenticatedInputs)')
    <source.lastIndexOf('buildAuthenticatedCheckpointSubmission'));
  assert.ok(source.indexOf('removePrivateFileDurableIfExists(outputPath)')
    <source.indexOf('const configurationInputs='));
  assert.ok(source.indexOf('currentInputs.some')<source.indexOf('await atomicWrite(output)'));
  assert.ok(source.indexOf('await atomicWrite(output)')<source.indexOf('installed.equals(output)'));
  for(const input of ['statementPath','proofIndexPath','sealPath']) {
    assert.ok(source.lastIndexOf(`readDirectProjectFile(root,${input})`)
      >source.indexOf('const currentInputs='),input);
  }
});
