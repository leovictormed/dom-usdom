import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const source=await readFile(new URL(
  '../../scripts/prepare-authenticated-finalized-burn-submission.mjs',import.meta.url),'utf8');

test('finalized-burn submission is private, immutable and bound through persistence',()=>{
  assert.match(source,/mkdir\(outputDirectory,\{recursive:true,mode:0o700\}\)/);
  assert.ok(source.includes('(metadata.mode&0o077)!==0'));
  assert.match(source,/writePrivateFileDurableNew\(outputPath,bytes/);
  assert.match(source,/removePrivateFileDurableIfExists\(outputPath\)/);
  assert.doesNotMatch(source,/writePrivateFileDurable\(outputPath,bytes/);
  assert.match(source,/authenticated finalized-burn submission inputs changed during preparation/);
  assert.match(source,/usdom-finalized-burn-submission\./);
  assert.match(source,/privateInputReplica\(authenticatedInputs\)/);
  assert.match(source,/privateMode:true,minimum:1/);
  assert.match(source,/installed\.equals\(output\)/);
  assert.match(source,/packageSha256=createHash\('sha256'\)\.update\(installed\)/);
  assert.ok(source.indexOf('privateInputReplica(authenticatedInputs)')
    <source.lastIndexOf('buildAuthenticatedFinalizedBurnSubmission'));
  assert.ok(source.indexOf('removePrivateFileDurableIfExists(outputPath)')
    <source.indexOf('const authenticatedInputs='));
  assert.ok(source.indexOf('currentInputs.some')<source.indexOf('await atomicWrite(output)'));
  assert.ok(source.indexOf('await atomicWrite(output)')<source.indexOf('installed.equals(output)'));
  assert.match(source,/currentInputs\.some\(\(bytes,index\)=>!bytes\.equals\(authenticatedInputs\[index\]\)\)/);
  for(const input of ['sourceIndexPath','sourceInputPath','receiptIndexPath','proofIndexPath','sealPath']) {
    assert.ok(source.lastIndexOf(`readDirectProjectFile(root,${input})`)
      >source.indexOf('const currentInputs='),input);
  }
});
