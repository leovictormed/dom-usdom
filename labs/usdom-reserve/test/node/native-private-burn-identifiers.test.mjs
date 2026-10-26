import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

import {validateNativePrivateBurnIdentifiers}
  from '../../sdk/native-private-burn-identifiers.mjs';

const sources={
  walletBurnBuilder:await readFile(new URL(
    '../../../../crates/dom-usdom-wallet/src/burn_builder.rs',import.meta.url),'utf8'),
  privacy:await readFile(new URL(
    '../../../../crates/dom-usdom-privacy/src/lib.rs',import.meta.url),'utf8'),
  state:await readFile(new URL(
    '../../../../crates/dom-usdom-state/src/lib.rs',import.meta.url),'utf8'),
};

test('private burn identifiers are collision-resistant and proof/consensus bound',()=>{
  assert.deepEqual(validateNativePrivateBurnIdentifiers(sources),[]);
});

test('each identifier security boundary rejects a source mutation',()=>{
  const mutations=[
    ['walletBurnBuilder','where\n    R: RngCore + CryptoRng,\n    I: IntoIterator<Item = [u8; 32]>,',
      'where\n    R: RngCore,\n    I: IntoIterator<Item = [u8; 32]>,'],
    ['walletBurnBuilder','const REQUEST_IDENTIFIER_ATTEMPTS: usize = 128;',
      'const REQUEST_IDENTIFIER_ATTEMPTS: usize = 0;'],
    ['walletBurnBuilder','value != [0; 32] && value != burn_id && !existing.contains(&value)',
      'value != [0; 32]'],
    ['walletBurnBuilder','.map(|pending| pending.record.request_id)',
      '.map(|_| [0; 32])'],
    ['walletBurnBuilder','statement_nullifiers[slot] = nullifier;',
      'statement_nullifiers[slot] = Scalar::ZERO;'],
    ['privacy','&[self.chain, owner_secret, self.commitment()?]',
      '&[self.chain, owner_secret]'],
    ['state','&value.nullifiers,','&[],'],
    ['state','if self.burn_request_ids.contains(&value.record.request_id)',
      'if false'],
  ];
  for(const [key,before,after] of mutations) {
    assert(sources[key].includes(before),`mutation anchor missing: ${before}`);
    const mutated={...sources,[key]:sources[key].replaceAll(before,after)};
    assert.notDeepEqual(validateNativePrivateBurnIdentifiers(mutated),[],before);
  }
});
