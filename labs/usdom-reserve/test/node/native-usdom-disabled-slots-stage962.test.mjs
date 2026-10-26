import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("../../../../crates/dom-usdom-privacy/src/circuit.rs", import.meta.url), "utf8");

test("disabled input fields and path are all constrained to zero", () => {
  for (const rule of [
    /origin\.conditional_enforce_equal\(&FpVar::zero\(\), &disabled\)/,
    /value\.conditional_enforce_equal\(&FpVar::zero\(\), &disabled\)/,
    /leaf_index_field\.conditional_enforce_equal\(&FpVar::zero\(\), &disabled\)/,
    /secret\.conditional_enforce_equal\(&FpVar::zero\(\), &disabled\)/,
    /rho\.conditional_enforce_equal\(&FpVar::zero\(\), &disabled\)/,
    /sibling\.conditional_enforce_equal\(&FpVar::zero\(\), &disabled\)/,
    /public_nullifiers\[slot\]\.conditional_enforce_equal\(&FpVar::zero\(\), &disabled\)/,
  ]) assert.match(source, rule);
});

test("disabled outputs and optional memo have unique representation", () => {
  assert.match(source, /for field in \[&value, &owner, &rho\][\s\S]{0,160}conditional_enforce_equal\(&FpVar::zero\(\), &disabled\)/);
  assert.match(source, /public_outputs\[slot\]\.conditional_enforce_equal\(&FpVar::zero\(\), &disabled\)/);
  assert.match(source, /memo\.is_eq\(&FpVar::zero\(\)\)\?[\s\S]{0,100}any_output\.clone\(\)\.not\(\)/);
  assert.match(source, /enabled\.clone\(\) & previous_output_enabled\.not\(\)/);
});

test("mutation regressions cover nine disabled fields and optional branches", () => {
  assert.match(source, /for mutation in 0\.\.9/);
  assert.match(source, /disabled_slots_have_one_canonical_zero_witness/);
  assert.match(source, /optional_outputs_are_left_packed_and_memo_presence_is_canonical/);
});
