import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../../../../", import.meta.url);
const [crypto, snapshot, wallet, authority, keystore] = await Promise.all([
  readFile(new URL("crates/dom-wallet-crypto/src/lib.rs", root), "utf8"),
  readFile(new URL("crates/dom-usdom-wallet/src/snapshot.rs", root), "utf8"),
  readFile(new URL("crates/dom-usdom-wallet/src/lib.rs", root), "utf8"),
  readFile(new URL("crates/dom-usdom-wallet/src/tpm2_authority.rs", root), "utf8"),
  readFile(new URL("crates/dom-usdom-wallet/src/tpm2_keystore.rs", root), "utf8"),
]);

test("wallet envelopes pin KDF/version and fail closed on OS entropy", () => {
  assert.match(crypto, /m_cost_kib: 65536[\s\S]{0,80}t_cost: 3[\s\S]{0,80}parallelism: 1/);
  assert.match(crypto, /Algorithm::Argon2id, Version::V0x13/);
  assert.match(crypto, /OsRng[\s\S]{0,100}try_fill_bytes\(&mut salt\)/);
  assert.match(crypto, /try_fill_bytes\(&mut nonce_bytes\)/);
  assert.match(crypto, /EnvelopeError::RandomnessUnavailable/);
  assert.doesNotMatch(crypto.split("#[cfg(test)]")[0], /thread_rng\(\)\.fill_bytes/);
});

test("snapshot rollback authority binds generation digest chain and predecessor", () => {
  assert.match(snapshot, /generation != seal\.generation/);
  assert.match(snapshot, /value\.checked_add\(1\) == Some\(generation\)/);
  assert.match(snapshot, /seal_for\(&current\)\? != previous/);
  assert.match(snapshot, /save_envelope_bytes[\s\S]{0,180}ENVELOPE_VERSION/);
  assert.match(snapshot, /WalletSecrets::from_bytes\(chain, owner_secret, scan_secret\)/);
});

test("recovery and TPM records reject downgrade substitution and overwrite", () => {
  assert.match(wallet, /RECOVERY_ENVELOPE_VERSION: u16 = 1/);
  assert.match(wallet, /stored_chain != expected_chain/);
  assert.match(wallet, /save_envelope_bytes_noclobber/);
  assert.match(authority, /CREDENTIAL_ENVELOPE_VERSION: u16 = 1/);
  assert.match(keystore, /RECORD_VERSION: u16 = 1/);
  assert.match(keystore, /bytes\[14\.\.46\] != expected_binding\.as_bytes\(\)/);
});
