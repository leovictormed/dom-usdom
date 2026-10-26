import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {validateCheckpointEconomicCoverage} from '../../sdk/checkpoint-economic-coverage.mjs';

const sources={
  library:await readFile(new URL(
    '../../../../crates/dom-usdom-checkpoint-program/src/lib.rs',import.meta.url),'utf8'),
  chunks:await readFile(new URL(
    '../../../../crates/dom-usdom-checkpoint-program/src/economic_chunks.rs',import.meta.url),'utf8'),
  portable:await readFile(new URL(
    '../../../../crates/dom-usdom-checkpoint-program/src/portable.rs',import.meta.url),'utf8'),
};

test('recursive economic witnesses cover the consensus weight domain and RandomX fields are header-derived',()=>{
  assert.deepEqual(validateCheckpointEconomicCoverage(sources),[]);
});

test('coverage, recursive binding and header derivation mutations fail closed',()=>{
  const mutations=[
    ['library','.div_ceil(MAX_ECONOMIC_CHUNK_KEYS) + 1','.div_ceil(MAX_ECONOMIC_CHUNK_KEYS)'],
    ['chunks','total > dom_core::MAX_BLOCK_WEIGHT','false'],
    ['chunks','while cursor < total {','if cursor < total {'],
    ['chunks','if proving_state != expected_final {','if false {'],
    ['portable','claim.package_commitment','[0; 32]'],
    ['portable','claim.previous_roots != economic_roots','false'],
    ['portable','risc0_zkvm::guest::env::verify(','Ok::<(), core::convert::Infallible>('],
    ['library','block_height: header.height.0,','block_height: 1,'],
    ['library','randomx_hash: *header.pow.randomx_hash.as_bytes(),','randomx_hash: [0; 32],'],
  ];
  for(const [key,before,after] of mutations) {
    assert(sources[key].includes(before),`mutation anchor missing: ${before}`);
    const mutated={...sources,[key]:sources[key].replaceAll(before,after)};
    assert.notDeepEqual(validateCheckpointEconomicCoverage(mutated),[],before);
  }
});
