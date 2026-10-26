import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const privacy = new URL('../../../../crates/dom-usdom-privacy/src/verifier.rs', import.meta.url);
const prover = new URL('../../../../crates/dom-usdom-prover/src/lib.rs', import.meta.url);
const circuit = new URL('../../../../crates/dom-usdom-privacy/src/circuit.rs', import.meta.url);
const policy = new URL('../../../../crates/dom-usdom-privacy/src/lib.rs', import.meta.url);
const config = new URL('../../../../crates/dom-node/src/native_usdom_config.rs', import.meta.url);

const sources = await Promise.all([privacy, prover, circuit, policy, config].map((path) => readFile(path, 'utf8')));

function checkedCompressedDecodes(source) {
  return [...source.matchAll(/deserialize_with_mode\([\s\S]{0,180}?Compress::Yes,[\s\S]{0,80}?Validate::Yes/g)].length;
}

test('Groth16 authority bytes use checked compressed decoding and canonical round trips', () => {
  const [verifierSource, proverSource] = sources;
  assert.equal(checkedCompressedDecodes(verifierSource), 2, 'VK and proof must be checked');
  assert.equal(checkedCompressedDecodes(proverSource), 1, 'proving key must be checked');
  assert.match(verifierSource, /if canonical != bytes/);
  assert.match(verifierSource, /if canonical\.as_slice\(\) != proof_bytes/);
  assert.match(proverSource, /if canonical != bytes/);
  for (const mutation of [
    verifierSource.replaceAll('Validate::Yes', 'Validate::No'),
    verifierSource.replace('if canonical.as_slice() != proof_bytes', 'if false'),
    proverSource.replace('Validate::Yes', 'Validate::No'),
  ]) {
    assert.ok(checkedCompressedDecodes(mutation) < 2 || !mutation.includes('if canonical.as_slice() != proof_bytes'));
  }
});

test('frozen statement order, count and circuit policy are committed', () => {
  const [verifierSource, , circuitSource, policySource] = sources;
  assert.match(verifierSource, /const PUBLIC_INPUTS: usize = 9;/);
  assert.match(verifierSource, /gamma_abc_g1\.len\(\) != PUBLIC_INPUTS \+ 1/);
  assert.match(circuitSource, /pub fn public_inputs\(self\) -> \[Fr; 9\]/);
  for (const field of ['self.chain.0', 'self.anchor.0', 'self.nullifiers[0].0', 'self.nullifiers[1].0', 'self.output_notes[0].0', 'self.output_notes[1].0', 'Fr::from(self.burn_amount)', 'self.effect.0', 'self.memo.0']) {
    assert.ok(circuitSource.includes(field), `missing public input ${field}`);
  }
  assert.match(policySource, /direct-public:chain,anchor,nf0,nf1,out0,out1,burn,effect,memo/);
  assert.match(verifierSource, /identity\.extend_from_slice\(privacy_policy_hash\(\)\.as_bytes\(\)\)/);
});

test('startup binds exact VK bytes to versioned manifest and bridge/network identity', () => {
  const [, , , , configSource] = sources;
  assert.match(configSource, /LEGACY_SCHEMA_VERSION \| CANDIDATE_V2_SCHEMA_VERSION/);
  assert.match(configSource, /spend_verifying_key_sha256/);
  assert.match(configSource, /spend_verifier\.config_hash\(\)\.as_bytes\(\) != &bridge\.privacy_verifier_config_hash/);
  assert.match(configSource, /bridge\.ethereum_chain_id != expected_ethereum_chain_id/);
  assert.match(configSource, /bridge\.dom_domain/);
});
