import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const source=await readFile(new URL(
  '../../scripts/prepare-native-release-attestation-requests.mjs',import.meta.url),'utf8');

test('native attestation request erases all six wallet evidence captures',()=>{
  assert.equal((source.match(/readPrivateWalletEvidence\(/g)||[]).length,7);
  assert.match(source,/async function readPrivateWalletEvidence[\s\S]*privateWalletEvidenceBytes\.push\(bytes\)/);
  assert.match(source,/finally \{\n  for\(const bytes of privateWalletEvidenceBytes\) bytes\.fill\(0\);\n\}/);
  assert.equal((source.match(/readDirectFile\(/g)||[]).length,1,
    'wallet evidence must enter only through the erasing capture helper');
});
