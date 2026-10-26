import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const statePath = new URL('../../../../labs/usdom-ethereum-finality/src/state.rs', import.meta.url);
const receiptsPath = new URL('../../../../labs/usdom-ethereum-finality/src/receipts.rs', import.meta.url);
const cargoPath = new URL('../../../../Cargo.toml', import.meta.url);
const [state, receipts, cargo] = await Promise.all([
  readFile(statePath, 'utf8'),
  readFile(receiptsPath, 'utf8'),
  readFile(cargoPath, 'utf8'),
]);
const productionState = state.split('\n#[cfg(test)]')[0];

test('all untrusted Ethereum MPT proofs are prevalidated before alloy-trie', () => {
  assert.match(cargo, /\[profile\.release\][\s\S]*?panic\s*=\s*"abort"/);
  assert.match(productionState, /fn validate_inline_node_shape/);
  assert.match(productionState, /noncanonical inline extension child in MPT/);
  const helper = productionState.slice(productionState.indexOf('pub(crate) fn verify_mpt_proof'), productionState.indexOf('impl HistoricalCapellaClient'));
  assert.ok(helper.indexOf('validate_inline_node_shape(&node)?') < helper.indexOf('verify_proof('));
  assert.equal([...productionState.matchAll(/\bverify_proof\(/g)].length, 1, 'only the prevalidated helper may call alloy-trie');
  assert.equal([...productionState.matchAll(/\bverify_mpt_proof\(/g)].length, 3, 'helper plus account and storage verification');
  assert.equal([...receipts.matchAll(/\bverify_mpt_proof\(/g)].length, 1, 'receipt inclusion uses the same guard');
  assert.doesNotMatch(receipts, /\bverify_proof\(/);
});

test('protection does not rely on catch_unwind under panic abort', () => {
  assert.doesNotMatch(productionState, /catch_unwind|AssertUnwindSafe/);
  assert.match(productionState, /TrieNode::decode\(&mut child_bytes\)/);
  assert.match(productionState, /matches!\(&child, TrieNode::Branch\(_\)\)/);
  assert.match(state, /fn inline_extension_to_leaf_is_rejected_before_dependency_abort\(\)/);
});
