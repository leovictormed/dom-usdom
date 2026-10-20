import test from 'node:test';
import assert from 'node:assert/strict';
import {
  PINNED_RISC0_MAINNET_V3,
  validateRiscZeroMainnetReference,
} from '../../sdk/risc0-verifier-reference.mjs';

test('reviewed RISC Zero mainnet reference pins the direct immutable verifier',()=>{
  const result=validateRiscZeroMainnetReference({...PINNED_RISC0_MAINNET_V3});
  assert.equal(result.chain_id,'1');
  assert.equal(result.verifier_contract_kind,'direct-immutable-verifier');
  assert.notEqual(result.verifier_address,result.router_address);
  assert.notEqual(result.verifier_address,result.emergency_stop_wrapper_address);
});

test('RISC Zero mainnet reference rejects every changed, missing or extra field',()=>{
  for(const field of Object.keys(PINNED_RISC0_MAINNET_V3)) {
    const changed={...PINNED_RISC0_MAINNET_V3,[field]:`${PINNED_RISC0_MAINNET_V3[field]}-changed`};
    assert.throws(()=>validateRiscZeroMainnetReference(changed),field);
  }
  const missing={...PINNED_RISC0_MAINNET_V3};
  delete missing.verifier_address;
  assert.throws(()=>validateRiscZeroMainnetReference(missing),/exact/);
  assert.throws(()=>validateRiscZeroMainnetReference({...PINNED_RISC0_MAINNET_V3,extra:true}),/exact/);
});
