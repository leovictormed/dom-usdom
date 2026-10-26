import test from 'node:test';
import assert from 'node:assert/strict';
import {validateSafeRecoveryEvidenceBundleShape}
  from '../../sdk/safe-recovery-evidence-bundle.mjs';

const sha=character=>character.repeat(64);
const hash=character=>`0x${character.repeat(64)}`;
const valid={schema:'usdom-safe-recovery-evidence-bundle/v1',ethereumChainId:'1',
  packageDocumentSha256:sha('1'),packageHash:hash('2'),baselineDocumentSha256:sha('3'),
  planDocumentSha256:sha('4'),transactionPackageDocumentSha256:sha('5'),rpcCatalogSha256:sha('6'),
  executions:['governance','reserveGuardian','checkpointGuardian'].map((role,index)=>({
    role,documentSha256:sha(String(index+7)),transactionHash:hash(String(index+1)),
  })),reportDocumentSha256:sha('a'),recoveryHash:hash('b')};

test('Safe recovery aggregate evidence has one exact canonical shape',()=>{
  assert.equal(validateSafeRecoveryEvidenceBundleShape(valid),valid);
});

test('Safe recovery aggregate evidence rejects schema and binding mutations',()=>{
  for(const mutate of [
    value=>{value.extra=true;},value=>{delete value.planDocumentSha256;},
    value=>{value.ethereumChainId=1;},value=>{value.rpcCatalogSha256='0x'+sha('6');},
    value=>{value.executions[0].extra=true;},value=>{delete value.executions[0].documentSha256;},
    value=>{value.executions[0].role='reserveGuardian';},
    value=>{value.executions[1].transactionHash=value.executions[1].transactionHash.toUpperCase();},
    value=>{value.executions.pop();},
  ]) {
    const changed=structuredClone(valid); mutate(changed);
    assert.throws(()=>validateSafeRecoveryEvidenceBundleShape(changed));
  }
});
