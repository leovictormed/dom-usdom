import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("../../../../crates/dom-chain/src/native_usdom_v4.rs", import.meta.url), "utf8");

test("native envelope applies deterministic count and byte budgets before crypto", () => {
  assert.match(source, /const MAX_CHECKPOINTS_PER_ENVELOPE: usize = 1/);
  assert.match(source, /const MAX_ISSUANCES_PER_ENVELOPE: usize = 4/);
  assert.match(source, /const MAX_PRIVATE_SPENDS_PER_ENVELOPE: usize = 16/);
  assert.match(source, /MAX_USDOM_V4_ENVELOPE_BYTES: usize = dom_core::MAX_BLOCK_SERIALIZED_SIZE \/ 2/);
  const validation = source.indexOf("validate_envelope_entries(entries)?;");
  const parallel = source.indexOf(".par_iter()", validation);
  assert.ok(validation >= 0 && parallel > validation);
});

test("exact repeated expensive proofs fail in cheap canonical prevalidation", () => {
  assert.match(source, /let mut unique_entries = BTreeSet::new\(\)/);
  assert.match(source, /unique_entries\.insert\(\(entry\.kind\.discriminator\(\), entry\.payload\.as_slice\(\)\)\)/);
  const duplicate = source.indexOf("duplicate native USDOM v4 proof entry");
  const verifier = source.indexOf("fn verify_envelope_transitions");
  assert.ok(duplicate >= 0 && duplicate < verifier);
  assert.match(source, /let duplicate_spend = UsdomV4ProofEnvelope/);
});

test("parallel verification work is bounded and rejoined by canonical slot", () => {
  assert.match(source, /if private_spends > 1/);
  assert.match(source, /private_spends > MAX_PRIVATE_SPENDS_PER_ENVELOPE/);
  assert.match(source, /\.collect::<Vec<_>>\(\)/);
  assert.match(source, /private_results\[index\]\.take\(\)/);
});
