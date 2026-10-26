import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const root = new URL('../../../../', import.meta.url);
const read = (path) => readFileSync(new URL(path, root), 'utf8');
const program = read('crates/dom-usdom-checkpoint-program/src/lib.rs');
const portable = read('crates/dom-usdom-checkpoint-program/src/portable.rs');
const outer = read('crates/dom-usdom-checkpoint-program/src/outer.rs');
const state = read('crates/dom-usdom-state/src/lib.rs');
const source = read('crates/dom-usdom-checkpoint-program/src/source.rs');
const persisted = read('crates/dom-chain/src/native_usdom_v4.rs');

assert.match(program, /CHECKPOINT_SEGMENT_TRANSITION_MAGIC[^\n]+UDCSTN03/);
assert.match(program, /CHECKPOINT_SEGMENT_TRANSITION_VERSION: u16 = 3/);
assert.match(program, /CHECKPOINT_SEGMENT_TRANSITION_PREFIX_BYTES: usize = 108/);
assert.doesNotMatch(program, /CHECKPOINT_SEGMENT_TRANSITION_MAGIC[^\n]+UDCSTN02/);
assert.match(program, /for magic in \[b"UDCSTN01", b"UDCSTN02"\]/);
for (const [field, offset] of [
  ['previous_total_issued', '44\\.\\.60'],
  ['previous_total_burned', '60\\.\\.76'],
  ['new_total_issued', '76\\.\\.92'],
  ['new_total_burned', '92\\.\\.108'],
]) {
  assert.match(program, new RegExp(`bytes\\[${offset}\\]\\.copy_from_slice\\(&self\\.${field}\\.to_be_bytes\\(\\)\\)`));
  assert.match(program, new RegExp(`${field}: u128::from_be_bytes`));
}
assert.match(state, /previous_total_issued: previous\.total_issued/);
assert.match(state, /new_total_burned: next\.total_burned/);
assert.match(state, /bytes\.extend_from_slice\(&previous\.total_issued\.to_be_bytes\(\)\)/);
assert.match(portable, /receipt\.previous_total_issued != authenticated_total_issued/);
assert.match(portable, /receipt\.new_total_burned != next_native_state\.total_burned/);
assert.match(portable, /authenticated_total_issued != transition\.new_total_issued/);
assert.match(outer, /transition\.previous_total_issued != current_total_issued/);
assert.match(outer, /current_total_burned = transition\.new_total_burned/);
assert.match(outer, /target_totals[\s\S]*current_total_issued, current_total_burned/);
assert.match(outer, /target_total_issued: u128/);
assert.match(outer, /target_total_burned: u128/);
assert.match(source, /transition_statement_with_totals\([\s\S]*previous_native_state\.total_issued/);
assert.match(source, /transition_statement_with_totals\([\s\S]*segment_native_state\.total_issued/);
assert.match(persisted, /USDOM_V2_PERSISTENCE_VERSION: u16 = 2/);
assert.match(persisted, /previous_total_issued: u128::from_be_bytes/);
assert.match(persisted, /self\.receipt\.new_total_burned != self\.next_state\.total_burned/);
console.log('checkpoint segment economic adjacency stage1023: ok');
