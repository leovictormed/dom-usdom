import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const source=await readFile(new URL(
  '../../scripts/check-recoverable-safe-recovery-target.mjs',import.meta.url),'utf8');

test('Safe target preflight erases all eight private captures including partial batches',()=>{
  assert.equal((source.match(/readPrivateInput\(/g)||[]).length,9);
  assert.equal((source.match(/readDirectFile\(/g)||[]).length,1);
  assert.match(source,/async function readPrivateInput[\s\S]*privateInputBytes\.push\(bytes\);[\s\S]*return bytes;/);
  assert.match(source,/finally \{\n  for\(const bytes of privateInputBytes\) bytes\.fill\(0\);\n\}/);
});
