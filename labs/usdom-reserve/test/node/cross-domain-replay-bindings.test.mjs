import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

import {validateCrossDomainReplayBindings}
  from '../../sdk/cross-domain-replay-bindings.mjs';

const read = relative => readFile(new URL(relative, import.meta.url), 'utf8');
const sources = {
  reserveContract: await read('../../contracts/USDOMProofReserve.sol'),
  checkpointContract: await read('../../contracts/DOMCheckpointRegistry.sol'),
  preactivationPolicy: await read('../../sdk/preactivation-policy.mjs'),
  checkpointStatement: await read('../../../../crates/dom-usdom-checkpoint-statement/src/lib.rs'),
  nativeState: await read('../../../../crates/dom-usdom-state/src/lib.rs'),
  nativeChain: await read('../../../../crates/dom-chain/src/native_usdom_v4.rs'),
  finalizedBurnProgram: await read('../../../../crates/dom-usdom-finalized-burn-program/src/lib.rs'),
  depositFinality: await read('../../../usdom-ethereum-finality/src/deposits.rs'),
  proofReserveSdk: await read('../../sdk/proof-reserve.mjs'),
  checkpointRegistrySdk: await read('../../sdk/checkpoint-registry.mjs'),
};

test('cross-domain and cross-deployment replay bindings remain complete', () => {
  assert.deepEqual(validateCrossDomainReplayBindings(sources), []);
});

test('the replay gate detects removal of each independently required boundary', () => {
  const mutations = [
    ['reserveContract', 'block.chainid, address(this), funder, salt', 'funder, salt'],
    ['preactivationPolicy', ',address checkpointRegistry)', ')'],
    ['checkpointContract', 'NATIVE_STATE_VERSION,\n            TRANSITION_BATCH_VERSION,', ''],
    ['depositFinality', 'event.emitter() == policy.reserve', 'true'],
    ['nativeState', 'self.consumed_deposits.contains_key(&value.deposit_id)', 'false'],
    ['finalizedBurnProgram', 'burn.reserve != state.reserve', 'false'],
    ['proofReserveSdk', 'BurnIntent(bytes32 burnId,bytes32 requestId,address recipient',
      'BurnIntent(bytes32 requestId,bytes32 burnId,address recipient'],
    ['checkpointStatement', 'encoded[608..640].copy_from_slice(&value.ethereum_chain_id);',
      'encoded[608..640].copy_from_slice(&value.checkpoint_config_hash);'],
  ];
  for (const [name, before, after] of mutations) {
    assert.ok(sources[name].includes(before), `missing mutation anchor: ${before}`);
    const mutated = {...sources, [name]: sources[name].replace(before, after)};
    assert.notDeepEqual(validateCrossDomainReplayBindings(mutated), [], before);
  }
});
