import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../../../../", import.meta.url);
const [native, state, wallet] = await Promise.all([
  readFile(new URL("crates/dom-chain/src/native_usdom_v4.rs", root), "utf8"),
  readFile(new URL("crates/dom-usdom-state/src/lib.rs", root), "utf8"),
  readFile(new URL("crates/dom-usdom-wallet/src/snapshot.rs", root), "utf8"),
]);

test("block and mining admission have exact proof and memory budgets", () => {
  for (const rule of [
    /MAX_CHECKPOINTS_PER_ENVELOPE: usize = 1/,
    /MAX_ISSUANCES_PER_ENVELOPE: usize = 4/,
    /MAX_PRIVATE_SPENDS_PER_ENVELOPE: usize = 16/,
    /MAX_USDOM_V4_MINING_CANDIDATES: usize = 16/,
    /MAX_USDOM_V4_MINING_CANDIDATE_BYTES: usize = 16 \* 1024 \* 1024/,
  ]) assert.match(native, rule);
});

test("counted envelope and witness vectors prove minimum bytes before allocation", () => {
  assert.match(native, /USDOM_V4_ENVELOPE_HEADER_BYTES[\s\S]{0,240}count\.checked_mul\(5\)/);
  assert.match(native, /truncated native USDOM v4 proof entries[\s\S]{0,120}Vec::with_capacity\(count\)/);
  assert.match(native, /USDOM_V2_WITNESS_BUNDLE_HEADER_BYTES[\s\S]{0,240}count\.checked_mul\(5\)/);
  assert.match(native, /truncated native USDOM v2 execution witnesses[\s\S]{0,120}Vec::with_capacity\(count\)/);
});

test("state wallet and prover inputs bind note/path/depth and byte counts", () => {
  for (const rule of [
    /MAX_INPUT_NULLIFIERS: usize = 2/,
    /MAX_OUTPUT_NOTES: usize = 2/,
    /MAX_SET_EFFECTS_PER_TRANSITION: usize = 6/,
    /MAX_BURN_INCLUSION_SIBLINGS: usize = 64/,
    /MAX_TRANSITIONS_PER_BATCH: usize = 1_024/,
  ]) assert.match(state, rule);
  assert.match(wallet, /MAX_SNAPSHOT_BYTES: usize = 64 \* 1024 \* 1024/);
  assert.match(wallet, /MAX_SNAPSHOT_ITEMS: usize = 1_000_000/);
  assert.equal((wallet.match(/reader\.require_records\(/g) ?? []).length, 7);
  assert.match(native, /MAX_NATIVE_BURN_BLOCK_PROVER_INPUT_BYTES/);
});
