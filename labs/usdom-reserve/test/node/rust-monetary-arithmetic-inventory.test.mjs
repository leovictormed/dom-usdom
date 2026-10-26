import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repo = path.resolve(import.meta.dirname, "../../../..");
const crates = path.join(repo, "crates");

function rustSources() {
  const pending = fs.readdirSync(crates, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith("dom-usdom-"))
    .map((entry) => path.join(crates, entry.name));
  const result = [];
  while (pending.length) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (entry.name === "tests" || entry.name === "target") continue;
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(absolute);
      else if (entry.isFile() && entry.name.endsWith(".rs")) result.push(absolute);
    }
  }
  return result.sort();
}

function production(file) {
  return fs.readFileSync(file, "utf8").split(/#\[cfg\(test\)\]\s*\nmod tests?\s*\{/u, 1)[0];
}

function count(source, needle) {
  return source.split(needle).length - 1;
}

test("all USDOM Rust arithmetic boundaries remain inventoried", () => {
  const files = rustSources();
  assert.equal(files.length, 59);
  const source = files.map(production).join("\n");
  assert.deepEqual({
    checkedAdd: count(source, ".checked_add("),
    checkedSub: count(source, ".checked_sub("),
    checkedMul: count(source, ".checked_mul("),
    saturatingAdd: count(source, ".saturating_add("),
    saturatingSub: count(source, ".saturating_sub("),
    tryInto: count(source, ".try_into()"),
    asU64: count(source, " as u64"),
    asU32: count(source, " as u32"),
    asUsize: count(source, " as usize"),
  }, {
    checkedAdd: 157,
    checkedSub: 34,
    checkedMul: 17,
    saturatingAdd: 9,
    saturatingSub: 10,
    tryInto: 203,
    asU64: 68,
    asU32: 14,
    asUsize: 57,
  });
});

test("native issuance and burn totals are checked and supply conserving", () => {
  const state = production(path.join(crates, "dom-usdom-state/src/lib.rs"));
  assert.match(state, /total_issued\s*\.checked_add\(u128::from\(value\.amount\)\)\s*\.ok_or\(UsdomStateError::MonetaryOverflow\)/u);
  assert.match(state, /total_burned\s*\.checked_add\(u128::from\(value\.record\.amount\)\)\s*\.ok_or\(UsdomStateError::MonetaryOverflow\)/u);
  assert.match(state, /if next_burned > self\.total_issued\s*\{\s*return Err\(UsdomStateError::BurnExceedsSupply\)/u);
  assert.match(state, /computed_issued != total_issued \|\| computed_burned != total_burned/u);
  assert.match(state, /value\.total_burned <= value\.total_issued/u);
  assert.match(state, /pub fn outstanding\(&self\) -> u128[\s\S]*self\.total_issued - self\.total_burned/u);
});

test("private circuit constrains u64 values and exact conservation", () => {
  const circuit = production(path.join(crates, "dom-usdom-privacy/src/circuit.rs"));
  assert.match(circuit, /UInt64::new_witness\(cs, \|\| Ok\(value\)\)/u);
  assert.match(circuit, /\(output_sum \+ burn_amount\)\.enforce_equal\(&input_sum\)\?/u);
  assert.match(circuit, /enabled\.enforce_equal\(&Boolean::TRUE\)\?/u);
  assert.match(circuit, /public_nullifiers\[slot\]\.conditional_enforce_equal/u);
});

test("duplicates, ordering and wallet selection fail closed", () => {
  const state = production(path.join(crates, "dom-usdom-state/src/lib.rs"));
  assert.match(state, /if !strictly_sorted\(nullifiers\)\s*\{\s*return Err\(UsdomStateError::NonCanonicalOrder\)/u);
  assert.match(state, /!transition_unique\.insert\(\*nullifier\)\s*\|\| self\.nullifiers\.contains\(nullifier\)/u);
  assert.match(state, /!transition_unique\.insert\(\*note\)\s*\|\| self\.note_commitments\.contains\(note\)/u);

  const builders = production(path.join(crates, "dom-usdom-wallet/src/builder.rs"))
    + production(path.join(crates, "dom-usdom-wallet/src/burn_builder.rs"));
  assert.equal(count(builders, "sum.checked_add(value)"), 2);
  assert.equal(count(builders, ".checked_sub(amount)"), 2);

  const wallet = production(path.join(crates, "dom-usdom-wallet/src/lib.rs"));
  assert.match(wallet, /pub fn available_balance\(&self\) -> u128[\s\S]*map\(\|note\| u128::from\(note\.received\.opening\.value\)\)/u);
});
