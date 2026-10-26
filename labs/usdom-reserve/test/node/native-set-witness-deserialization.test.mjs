import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {validateNativeSetWitnessDeserialization} from '../../sdk/native-set-witness-deserialization.mjs';

const source=await readFile(new URL('../../../../crates/dom-usdom-state/src/lib.rs',import.meta.url),'utf8');

test('native set witness uses a bounded cursor and adversarial corpus',()=>{
  assert.deepEqual(validateNativeSetWitnessDeserialization(source),[]);
});

test('cursor, nested length and truncation mutations fail closed',()=>{
  const mutations=[
    ['            .checked_add(length)','            .wrapping_add(length)'],
    ['let mut reader = SetWitnessReader::new(bytes);','let mut reader = SetWitnessReader::new(&bytes[..10]);'],
    ['length == 0 || length > MAX_SPARSE_PROOF_BYTES','length == 0'],
    ['if !reader.is_empty() {','if false {'],
    ['for end in 0..bytes.len() {','for end in 0..0 {'],
    ['oversized_first_proof[10..12]','oversized_first_proof[10..10]'],
  ];
  for(const [before,after] of mutations) {
    assert(source.includes(before),`mutation anchor missing: ${before}`);
    assert.notDeepEqual(validateNativeSetWitnessDeserialization(source.replaceAll(before,after)),[],before);
  }
});
