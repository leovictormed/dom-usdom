import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

import {
  productionImplementationClaims,
  productionImplementationClaimFailures,
} from '../../sdk/production-implementation-claims.mjs';

const requirements=JSON.parse(await readFile(
  new URL('../../config/production-requirements.json',import.meta.url),'utf8'));

test('every asserted broad implementation claim has concrete implementation support',()=>{
  assert.deepEqual(productionImplementationClaimFailures(requirements),[]);
  assert.equal(requirements.production_finalized_burn_verifier_implemented,true,
    'UDFINL04 cannot be claimed complete before its rebuilt guest and positive receipt exist');
  for(const dependency of [
    'production_finalized_burn_guest_compiled',
    'production_finalized_burn_guest_reproducibly_compiled',
  ]) assert.equal(requirements[dependency],true);
  assert.equal(requirements.production_finalized_burn_guest_positive_raw_witness_executed,true);
  assert.equal(requirements.production_finalized_burn_risc0_evm_receipt_verifier_implemented,false,
    'implementation closure must not claim that a non-development receipt was verified');
  assert.equal(requirements.proof_reserve_proxy_storage_configuration_covered,true,
    'Safe proxy implementation and mutable policy coverage must remain recorded');
});

test('every broad implementation claim rejects each missing dependency',()=>{
  for(const [claim,dependencies] of Object.entries(productionImplementationClaims)) {
    for(const dependency of dependencies) {
      const mutated=structuredClone(requirements);
      mutated[claim]=true;
      for(const required of dependencies) mutated[required]=true;
      mutated[dependency]=false;
      const failures=productionImplementationClaimFailures(mutated);
      assert.deepEqual(failures.find(failure=>failure.claim===claim),
        {claim,reason:'dependency_not_true',dependencies:[dependency]},
        `${claim} must depend on ${dependency}`);
    }
  }
});

test('finalized-burn implementation closure requires the current v4 evidence schema',()=>{
  const dependencies=productionImplementationClaims.production_finalized_burn_verifier_implemented;
  assert(dependencies.includes('production_finalized_burn_e2e_report_v4_enforced'));
  assert(!dependencies.includes('production_finalized_burn_e2e_report_v3_enforced'),
    'retired v3 evidence must not remain an impossible release dependency');
});

test('the release checker can require all broad implementation claims explicitly',()=>{
  for(const claim of Object.keys(productionImplementationClaims)) {
    const mutated=structuredClone(requirements);
    mutated[claim]=false;
    assert(productionImplementationClaimFailures(mutated,{requireClaims:true}).some(
      failure=>failure.claim===claim && failure.reason==='claim_not_true'));
  }
  assert.throws(()=>productionImplementationClaimFailures(null),/must be an object/);
});
