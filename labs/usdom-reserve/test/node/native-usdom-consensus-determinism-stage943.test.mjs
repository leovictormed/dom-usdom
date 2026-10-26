import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../../../../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");

test("native state roots and storage deltas use canonical ordered collections", async () => {
  const state = await read("crates/dom-usdom-state/src/lib.rs");
  assert.match(state, /note_commitments: BTreeSet/);
  assert.match(state, /consumed_deposits: BTreeMap/);
  assert.match(state, /burns: BTreeMap/);
  assert.match(state, /let keys: BTreeSet<Vec<u8>>/);
  assert.match(state, /transition_batch_root\(self\.domain, &commitments\)/);
  assert.doesNotMatch(state.split("#[cfg(test)]")[0], /thread_rng|SystemTime|\bf32\b|\bf64\b/);
});

test("parallel proof verification restores canonical envelope order before state transition", async () => {
  const native = await read("crates/dom-chain/src/native_usdom_v4.rs");
  assert.match(native, /entries\s*\.par_iter\(\)/);
  assert.match(native, /\.collect::<Vec<_>>\(\)/);
  assert.match(native, /for \(index, entry\) in entries\.iter\(\)\.enumerate\(\)/);
  assert.match(native, /private_results\[index\]\.take\(\)/);
  assert.match(native, /apply_batch\([\s\S]*&verified\.transitions/);
});

test("consensus context is header, network and schedule bound", async () => {
  const [native, chain] = await Promise.all([
    read("crates/dom-chain/src/native_usdom_v4.rs"),
    read("crates/dom-chain/src/chain_state.rs"),
  ]);
  assert.match(chain, /ValidationContext \{\s*current_height: header\.height,\s*chain_id: \*chain_id\.as_bytes\(\),\s*now,/);
  assert.match(native, /block_timestamp: block\.header\.timestamp\.0/);
  assert.match(native, /schedule\.network_magic\(\) != network_magic/);
  assert.match(native, /package\.to_bytes\(\)\?\.as_slice\(\) != bytes/);
});
