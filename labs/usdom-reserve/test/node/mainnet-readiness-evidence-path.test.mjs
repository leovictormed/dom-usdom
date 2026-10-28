import assert from 'node:assert/strict';
import test from 'node:test';
import {isCanonicalReleaseEvidenceDocumentPath}
  from '../../sdk/mainnet-readiness.mjs';

test('release evidence references stay inside the evidence authority root',()=>{
  for(const value of [
    'evidence/reports/security.json',
    'evidence/native-runtime-manifest.json',
  ]) assert.equal(isCanonicalReleaseEvidenceDocumentPath(value),true,value);

  for(const value of [
    'README.md','config/production-requirements.json','contracts/USDOMProofReserve.sol',
    'evidence','evidence/../README.md','evidence//report.json','./evidence/report.json',
    '/evidence/report.json','evidence\\report.json','evidence/report.json\0suffix',
    'evidence/report\nforged.json','evidence/report\tforged.json','evidence/report 2.json',
    'evidence/réport.json','evidence/рeport.json','evidence/.hidden.json',
    'evidence/_report.json','evidence/Report.json','evidence/reports/SECURITY.json','out/arbitrary.json',
  ]) assert.equal(isCanonicalReleaseEvidenceDocumentPath(value),false,String(value));
});

test('only the four source-bound Foundry artifacts may live outside evidence',()=>{
  for(const value of [
    'out/USDOMProofReserve.sol/USDOMProofReserve.json',
    'out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json',
    'out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json',
    'out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json',
  ]) assert.equal(isCanonicalReleaseEvidenceDocumentPath(value),true,value);

  for(const value of [
    'out/USDOMProofReserve.sol/metadata.json',
    'out/USDOMReserve.sol/USDOMReserve.json',
    'out/DOMCheckpointRegistry.sol/../USDOMProofReserve.sol/USDOMProofReserve.json',
  ]) assert.equal(isCanonicalReleaseEvidenceDocumentPath(value),false,value);
});

test('release evidence path components fit the portable filesystem name bound',()=>{
  assert.equal(isCanonicalReleaseEvidenceDocumentPath(`evidence/${'a'.repeat(255)}`),true);
  assert.equal(isCanonicalReleaseEvidenceDocumentPath(`evidence/${'a'.repeat(256)}`),false);
  assert.equal(isCanonicalReleaseEvidenceDocumentPath(
    `evidence/${'a'.repeat(255)}/${'b'.repeat(255)}`),true);
});

test('release evidence pathname reserves the terminating PATH_MAX byte',()=>{
  const pathWithLength=target=>{
    let value='evidence';
    while(value.length<target) {
      const componentLength=Math.min(255,target-value.length-1);
      assert.ok(componentLength>0);
      value+=`/${'a'.repeat(componentLength)}`;
    }
    return value;
  };
  const maximum=pathWithLength(4095);
  const tooLong=pathWithLength(4096);
  assert.equal(maximum.length,4095);
  assert.equal(tooLong.length,4096);
  assert.equal(isCanonicalReleaseEvidenceDocumentPath(maximum),true);
  assert.equal(isCanonicalReleaseEvidenceDocumentPath(tooLong),false);
});
