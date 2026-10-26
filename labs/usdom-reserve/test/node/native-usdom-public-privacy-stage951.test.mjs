import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../../../../", import.meta.url);
const [state, wallet, burn] = await Promise.all([
  readFile(new URL("crates/dom-usdom-state/src/lib.rs", root), "utf8"),
  readFile(new URL("crates/dom-usdom-wallet/src/lib.rs", root), "utf8"),
  readFile(new URL("crates/dom-usdom-wallet/src/burn_builder.rs", root), "utf8"),
]);

test("private transfer projection exposes commitments and nullifiers, not value or recipient", () => {
  const commitment = state.indexOf("pub fn consensus_commitment(&self)");
  const start = state.indexOf("Self::Transfer {", commitment);
  const end = state.indexOf("Self::Burn {", start);
  const transfer = state.slice(start, end);
  assert.match(transfer, /encode_note_anchor/);
  assert.match(transfer, /encode_hash_list\(&mut bytes, nullifiers\)/);
  assert.match(transfer, /encode_hash_list\(&mut bytes, output_notes\)/);
  assert.match(transfer, /memo_commitment/);
  assert.doesNotMatch(transfer, /recipient|amount|deposit_id|encrypted_memo/);
});

test("wallet memo uses fresh authenticated encryption bound to output identity", () => {
  assert.match(wallet, /EphemeralSecret::random_from_rng/);
  assert.match(wallet, /rng\.fill_bytes\(&mut nonce\)/);
  assert.match(wallet, /XChaCha20Poly1305/);
  assert.match(wallet, /aad: &context/);
  assert.match(wallet, /plaintext\.extend_from_slice\(&output\.value\.to_be_bytes\(\)\)/);
  assert.match(wallet, /plaintext\.extend_from_slice\(&output\.rho\.to_bytes\(\)\)/);
});

test("burn payout is explicitly public while change and request randomness remain fresh", () => {
  assert.match(state, /pub struct BurnRecord[\s\S]{0,300}pub request_id: \[u8; 32\][\s\S]{0,180}pub amount: u64[\s\S]{0,180}pub recipient: \[u8; 20\]/);
  assert.match(burn, /rng\.fill_bytes\(&mut value\)/);
  assert.match(burn, /rho: random_scalar\(rng\)/);
  assert.match(burn, /inputs\.sort_by_key\(\|\(nullifier, _, _\)\| nullifier\.to_bytes\(\)\)/);
});
