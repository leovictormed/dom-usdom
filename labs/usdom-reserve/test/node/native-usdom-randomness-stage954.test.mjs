import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../../../../", import.meta.url);
const [wallet, builder, burn, authority, keystore] = await Promise.all([
  readFile(new URL("crates/dom-usdom-wallet/src/lib.rs", root), "utf8"),
  readFile(new URL("crates/dom-usdom-wallet/src/builder.rs", root), "utf8"),
  readFile(new URL("crates/dom-usdom-wallet/src/burn_builder.rs", root), "utf8"),
  readFile(new URL("crates/dom-usdom-wallet/src/tpm2_authority.rs", root), "utf8"),
  readFile(new URL("crates/dom-usdom-wallet/src/tpm2_keystore.rs", root), "utf8"),
]);

test("production generators require CryptoRng and reject zero or biased scalars", () => {
  assert.ok((wallet.match(/R: RngCore \+ CryptoRng/g) ?? []).length >= 3);
  assert.match(wallet, /if bytes\.iter\(\)\.any\(\|byte\| \*byte != 0\)/);
  assert.match(wallet, /Scalar::from_bytes\(\*candidate\)[\s\S]{0,100}!value\.is_zero\(\)/);
  assert.match(builder, /pub\(super\) fn random_scalar<R: RngCore \+ CryptoRng>/);
  assert.match(builder, /Scalar::from_bytes\(\*bytes\)[\s\S]{0,100}!value\.is_zero\(\)/);
  assert.match(burn, /const REQUEST_IDENTIFIER_ATTEMPTS: usize = 128/);
});

test("memo and recovery derivations are role chain and context separated", () => {
  assert.match(wallet, /RECOVERY_OWNER_INFO/);
  assert.match(wallet, /RECOVERY_SCAN_INFO/);
  assert.match(wallet, /info\.extend_from_slice\(&chain_bytes\)/);
  assert.match(wallet, /Hkdf::<Sha256>::new\(Some\(MEMO_KEY_SALT\), shared\)/);
  assert.match(wallet, /context\.extend_from_slice\(&commitment\.to_bytes\(\)\)/);
  assert.match(wallet, /context\.push\(output_index\)/);
});

test("TPM credential generators propagate OS CSPRNG failure", () => {
  for (const source of [authority, keystore]) {
    assert.match(source, /OsRng[\s\S]{0,80}\.try_fill_bytes/);
    assert.match(source, /Tpm2SealAuthorityError::RandomnessUnavailable/);
  }
  assert.doesNotMatch(authority.split("#[cfg(test)]")[0], /OsRng\.fill_bytes/);
  assert.doesNotMatch(keystore.split("#[cfg(test)]")[0], /OsRng\.fill_bytes/);
});
