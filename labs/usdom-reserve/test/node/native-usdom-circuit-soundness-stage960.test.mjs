import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("../../../../crates/dom-usdom-privacy/src/circuit.rs", import.meta.url), "utf8");

test("all nine public fields are allocated directly in frozen verifier order", () => {
  assert.match(source, /pub fn public_inputs\(self\) -> \[Fr; 9\]/);
  assert.equal((source.match(/FpVar::new_input/g) ?? []).length, 7);
  assert.match(source, /let burn_amount = input_u64/);
  assert.match(source, /assert_eq!\(cs\.num_instance_variables\(\), 10\)/);
});

test("membership ownership nullifier outputs ranges and conservation are constrained", () => {
  for (const rule of [
    /hash\(cs\.clone\(\), OWNER_DOMAIN/,
    /NULLIFIER_DOMAIN/,
    /node\.conditional_enforce_equal\(&anchor, &enabled\)/,
    /high_bit\.enforce_equal\(&Boolean::FALSE\)/,
    /commitment\.conditional_enforce_equal\(&public_outputs\[slot\], &enabled\)/,
    /\(output_sum \+ burn_amount\)\.enforce_equal\(&input_sum\)/,
    /effect\.is_eq\(&FpVar::zero\(\)\)\?\.enforce_equal\(&is_transfer\)/,
    /memo\.is_eq\(&FpVar::zero\(\)\)\?\s*\.enforce_equal\(&any_output\.clone\(\)\.not\(\)\)/,
  ]) assert.match(source, rule);
});

test("disabled witness slots are fully canonicalized", () => {
  assert.match(source, /origin\.conditional_enforce_equal\(&FpVar::zero\(\), &disabled\)/);
  assert.match(source, /sibling\.conditional_enforce_equal\(&FpVar::zero\(\), &disabled\)/);
  assert.match(source, /field\.conditional_enforce_equal\(&FpVar::zero\(\), &disabled\)/);
  assert.match(source, /disabled_slots_have_one_canonical_zero_witness/);
});
