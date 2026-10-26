import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const nodeManifestUrl=new URL('../../../../crates/dom-node/Cargo.toml',import.meta.url);
const walletManifestUrl=new URL('../../../../crates/dom-usdom-wallet/Cargo.toml',import.meta.url);
const requirementsUrl=new URL('../../config/production-requirements.json',import.meta.url);
const readinessUrl=new URL('../../sdk/mainnet-readiness.mjs',import.meta.url);
const buildBurnUrl=new URL(
  '../../../../crates/dom-node/src/bin/dom-usdom-build-private-burn.rs',import.meta.url);
const submitBurnUrl=new URL(
  '../../../../crates/dom-node/src/bin/dom-usdom-submit-private-burn.rs',import.meta.url);
const registerDepositUrl=new URL(
  '../../../../crates/dom-node/src/bin/dom-usdom-register-finalized-deposit.rs',import.meta.url);
const nodeHandleUrl=new URL('../../../../crates/dom-node/src/node_handle.rs',import.meta.url);
const rpcUrl=new URL('../../../../crates/dom-rpc/src/lib.rs',import.meta.url);

const [nodeManifest,walletManifest,requirements,readiness,buildBurn,submitBurn,registerDeposit,
  nodeHandle,rpc]=
  await Promise.all([
    readFile(nodeManifestUrl,'utf8'),
    readFile(walletManifestUrl,'utf8'),
    readFile(requirementsUrl,'utf8').then(JSON.parse),
    readFile(readinessUrl,'utf8'),
    readFile(buildBurnUrl,'utf8'),
    readFile(submitBurnUrl,'utf8'),
    readFile(registerDepositUrl,'utf8'),
    readFile(nodeHandleUrl,'utf8'),
    readFile(rpcUrl,'utf8'),
  ]);

test('validating node and offline operator features bind the native wallet without loading the prover into ordinary validation',()=>{
  assert.match(nodeManifest,/native-usdom-v4-poc\s*=\s*\[[\s\S]*?"dep:dom-usdom-wallet"[\s\S]*?\]/);
  assert.match(nodeManifest,/usdom-wallet-operator\s*=\s*\[[\s\S]*?"native-usdom-v4-poc"[\s\S]*?"dep:dom-usdom-prover"[\s\S]*?"dom-usdom-wallet\/tpm2-seal-authority"[\s\S]*?\]/);
  assert.match(nodeManifest,/dom-usdom-wallet\s*=\s*\{[^\n]*optional\s*=\s*true[^\n]*features\s*=\s*\["rpc-client"\]/);
  assert.match(nodeManifest,/dom-usdom-prover\s*=\s*\{[^\n]*optional\s*=\s*true/);
  assert.doesNotMatch(
    nodeManifest.match(/native-usdom-v4-poc\s*=\s*\[[\s\S]*?\]/)?.[0]??'',
    /dom-usdom-prover/,
    'ordinary validating nodes must not load the proving key implementation',
  );
});

test('dom-node owns the proof-backed private burn and authenticated wallet lifecycle binaries',()=>{
  for(const name of [
    'dom-usdom-build-private-burn',
    'dom-usdom-submit-private-burn',
    'dom-usdom-bootstrap-tpm-wallet-authority',
    'dom-usdom-wallet-tpm-keystore',
    'dom-usdom-recover-wallet-at-checkpoint',
  ]) {
    const escaped=name.replaceAll('-','\\-');
    assert.match(nodeManifest,new RegExp(
      `name\\s*=\\s*"${escaped}"[\\s\\S]*?required-features\\s*=\\s*\\["usdom-wallet-operator"\\]`));
  }
  for(const name of [
    'dom-usdom-register-finalized-deposit',
    'dom-usdom-observe-finalized-deposit',
  ]) {
    const escaped=name.replaceAll('-','\\-');
    assert.match(nodeManifest,new RegExp(
      `name\\s*=\\s*"${escaped}"[\\s\\S]*?required-features\\s*=\\s*\\["native-usdom-v4-poc"\\]`));
  }

  assert.match(buildBurn,/use dom_usdom_prover::SpendProver;/);
  assert.match(buildBurn,/use dom_usdom_wallet::[\s\S]*?WalletState/);
  assert.match(buildBurn,/SpendProver::from_bytes\(/);
  assert.match(buildBurn,/\.build_private_burn\(/);
  assert.match(submitBurn,/use dom_usdom_wallet::/);
  assert.match(submitBurn,/UsdomRpcClient::from_token_file\(/);
  assert.match(submitBurn,/\.submit_pending_private_burn\(/);
  assert.match(registerDeposit,/use dom_usdom_wallet::/);
  assert.match(registerDeposit,/WalletState::new_empty\(/);
  assert.match(registerDeposit,/\.register_expected_deposit\(/);

  assert.match(nodeHandle,/fn submit_usdom_v4_private_burn_v1\(/);
  assert.match(nodeHandle,/inspect_private_burn_outputs\(&payload\)/);
  assert.match(nodeHandle,/submit_native_usdom_v4_mining_envelope\(/);
  assert.match(nodeHandle,/fn scan_usdom_v4_history_v1\(/);
  assert.match(nodeHandle,/load_authenticated_usdom_v4_history_block\(/);
  assert.match(rpc,/"\/usdom\/v4\/burn\/submit\/v1"/);
  assert.match(rpc,/"\/usdom\/v4\/history\/scan\/v1"/);
});

test('wallet crate directly binds proof construction and exposes RPC only through its explicit feature',()=>{
  assert.match(walletManifest,/dom-usdom-prover\s*=\s*\{\s*path\s*=\s*"\.\.\/dom-usdom-prover"\s*\}/);
  assert.match(walletManifest,/rpc-client\s*=\s*\[[\s\S]*?"dep:dom-usdom-rpc-protocol"[\s\S]*?"dep:reqwest"[\s\S]*?\]/);
  assert.equal(requirements.native_private_prover_linked_into_node,true);
  assert.equal(requirements.native_private_wallet_node_dependency,true);
  assert.match(readiness,/const closedMainnetRequirements = \[[\s\S]*?'native_private_prover_linked_into_node'/);
  assert.match(readiness,/const closedMainnetRequirements = \[[\s\S]*?'native_private_wallet_node_dependency'/);
  assert.equal(
    requirements.native_private_offline_prover_scope,
    'feature_gated_dom_node_operator_binaries_excluded_from_validating_runtime',
  );
});
