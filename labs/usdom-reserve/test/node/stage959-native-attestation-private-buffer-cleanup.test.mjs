import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const source=await readFile(new URL(
  '../../scripts/prepare-native-release-attestation-requests.mjs',import.meta.url),'utf8');

test('native attestation request erases both snapshots of all seven private wallet artifacts',()=>{
  // One helper declaration plus seven initial reads and seven TOCTOU re-reads.
  assert.equal((source.match(/readPrivateWalletEvidence\(/g)||[]).length,15);
  for(const path of ['publicIdentityPath','tpmEvidencePath','recoveryEvidencePath',
    'privacyInstallationPath','privacyTranscriptPath','privacyVerifyingKeyPath',
    'privacyManifestPath']) {
    assert.equal((source.match(new RegExp(`readPrivateWalletEvidence\\(${path}`, 'g'))||[]).length,2,
      `${path} must be captured and erased for both snapshots`);
  }
  assert.match(source,/async function readPrivateWalletEvidence[\s\S]*privateWalletEvidenceBytes\.push\(bytes\)/);
  assert.match(source,/finally \{\n  for\(const bytes of privateWalletEvidenceBytes\) bytes\.fill\(0\);\n\}/);
  assert.equal((source.match(/readDirectFile\(/g)||[]).length,1,
    'wallet evidence must enter only through the erasing capture helper');
});
