import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../../../../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");

test("native USDOM burn authority is bound to a finalized checkpoint state", async () => {
  const source = await read("crates/dom-usdom-finalized-burn-program/src/lib.rs");
  assert.match(source, /state_root == Hash256::ZERO \|\| !burn_witness\.verify\(state_root\)/);
  assert.match(source, /consensus\.height != dom_height/);
  assert.match(source, /consensus\.block\.as_slice\(\) != &record\[9\.\.41\]/);
  assert.match(source, /consensus\.state_root != \*state_root\.as_bytes\(\)/);
  assert.match(source, /finalized\.block_number < event_execution_block/);
  assert.match(source, /finalized\.beacon_slot < event_beacon_slot/);
});

test("all native USDOM reorg paths enforce the durable checkpoint floor", async () => {
  const source = await read("crates/dom-chain/src/chain_state.rs");
  const calls = source.match(/ethereum_checkpoint_poc::check_reorg\(/g) ?? [];
  assert.ok(calls.length >= 3, `expected ordinary, v1 and v2 reorg guards; found ${calls.length}`);
  assert.match(source, /native USDOM v2 reorg crosses below activation/);
  assert.match(source, /rewind_persisted_usdom_v2_state_to_ancestor/);
  assert.match(source, /apply_reorg_with_consensus_state_and_sidecar_changes/);
});

test("startup and history retention fail closed around the checkpoint barrier", async () => {
  const [chain, checkpoint, native] = await Promise.all([
    read("crates/dom-chain/src/chain_state.rs"),
    read("crates/dom-chain/src/ethereum_checkpoint_poc.rs"),
    read("crates/dom-chain/src/native_usdom_v4.rs"),
  ]);
  assert.ok((chain.match(/ensure_restart_floor\(/g) ?? []).length >= 3);
  assert.match(checkpoint, /ancestor_height < checkpoint\.height/);
  assert.match(checkpoint, /get_hash_at_height\(checkpoint\.height\)/);
  assert.match(native, /let maximum_prunable = rolling_floor\.min\(checkpoint_predecessor\)/);
  assert.match(native, /cursor < schedule\.first_v2_height\(\)/);
  assert.match(native, /The compact burn archive and the checkpoint block record remain available/);
});
