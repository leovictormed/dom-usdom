import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {validateCheckpointRecursiveAuthority} from '../../sdk/checkpoint-recursive-authority.mjs';

const sources={
  aggregateGuest:await readFile(new URL('../../../../crates/dom-usdom-randomx-aggregate-risc0-guest/src/main.rs',import.meta.url),'utf8'),
  segmentGuest:await readFile(new URL('../../../../crates/dom-usdom-checkpoint-segment-risc0-guest/src/main.rs',import.meta.url),'utf8'),
  outerGuest:await readFile(new URL('../../../../crates/dom-usdom-checkpoint-outer-risc0-guest/src/main.rs',import.meta.url),'utf8'),
  outerProgram:await readFile(new URL('../../../../crates/dom-usdom-checkpoint-program/src/outer.rs',import.meta.url),'utf8'),
};

test('recursive guests preserve component, segment and outer authority boundaries',()=>{
  assert.deepEqual(validateCheckpointRecursiveAuthority(sources),[]);
});

test('recursive authority substitutions fail closed',()=>{
  const mutations=[
    ['aggregateGuest','env::commit_slice(&aggregate.commitment()','env::commit_slice(&transition.commitment()'],
    ['segmentGuest','env::commit_slice(&executed.transition_commitment())','env::commit_slice(&[0; 32])'],
    ['segmentGuest','verify_checkpoint_segment_randomx_bindings_in_guest(executed.randomx_bindings())','Ok::<(), core::convert::Infallible>(())'],
    ['outerGuest','validate_checkpoint_outer_chain_v6(&statement, &chain, &policy, &opening, SEGMENT_IMAGE_ID)','validate_checkpoint_outer_chain_v6(&statement, &chain, &policy, &opening, [0; 32])'],
    ['outerGuest','env::commit_slice(&executed.statement_hash())','env::commit_slice(&[0; 32])'],
    ['outerProgram','transition.previous != current','false'],
    ['outerProgram','current.block_hash != public.confirmation_block','false'],
    ['outerProgram','risc0_zkvm::guest::env::verify(','Ok::<(), core::convert::Infallible>('],
  ];
  for(const [key,before,after] of mutations) {
    assert(sources[key].includes(before),`mutation anchor missing: ${before}`);
    const mutated={...sources,[key]:sources[key].replaceAll(before,after)};
    assert.notDeepEqual(validateCheckpointRecursiveAuthority(mutated),[],before);
  }
});
