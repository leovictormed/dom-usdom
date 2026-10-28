import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const script=new URL('../../scripts/sign-recoverable-safe-recovery.sh',import.meta.url);
const releaseScript=new URL('../../scripts/sign-release-authorizations.sh',import.meta.url);
const deploymentExecutor=new URL('../../scripts/execute-mainnet-deployment.sh',import.meta.url);
const recoveryExecutor=new URL('../../scripts/execute-recoverable-safe-recovery.sh',import.meta.url);

test('Safe recovery uses only the bounded OneKey iOS EIP-712 signer',async()=>{
  const source=await readFile(script,'utf8');
  assert.match(source,/command in cast jq node[\s\S]* timeout;/);
  assert.match(source,/timeout_bin=\$\(realpath "\$\(command -v timeout\)"\)/);
  assert.match(source,/timeout_identity=\$\(stat -Lc '%d:%i:%s:%Y:%Z'/);
  assert.match(source,/timeout_sha256=\$\(sha256_file "\$timeout_bin"\)/);
  assert.match(source,/assert_timeout_unchanged\(\) \{/);
  assert.match(source,/sign-onekey-ios-walletconnect-typed-data\.mjs/);
  assert.match(source,/prepare-onekey-ios-walletconnect-request\.mjs/);
  assert.match(source,/read-onekey-ios-walletconnect-signature\.mjs/);
  assert.match(source,/--kill-after=10s 330s "\$node_bin"/);
  assert.doesNotMatch(source,/--ledger|wallet address|wallet sign/i);
  assert.doesNotMatch(source,/eth_sendTransaction|eth_signTransaction/);
});

test('mainnet deployment no longer contains a Ledger identity path',async()=>{
  const source=await readFile(deploymentExecutor,'utf8');
  assert.match(source,/contract-deployment-\$index-relayer-external-raw\.txt/);
  assert.doesNotMatch(source,/sign-onekey-mainnet-transaction/);
  assert.match(source,/deployment_broadcast_state=signed-unresolved/);
  assert.doesNotMatch(source,/wallet address --ledger|wallet sign|--ledger/i);
});

test('Safe recovery executor has no hardware signing channel',async()=>{
  const source=await readFile(recoveryExecutor,'utf8');
  assert.doesNotMatch(source,/--ledger|wallet address|wallet sign|run_bounded_ledger_address/i);
  assert.match(source,/check-safe-recovery-relayer-policy\.mjs/);
  assert.match(source,/RAW externa do relayer ausente/);
});

test('release and native authorization uses the bounded iPhone WalletConnect EIP-712 boundary',async()=>{
  const source=await readFile(releaseScript,'utf8');
  assert.match(source,/timeout_bin=\$\(realpath "\$\(command -v timeout\)"\)/);
  assert.match(source,/sign-onekey-ios-walletconnect-typed-data\.mjs/);
  assert.match(source,/--kill-after=15s 330s/);
  assert.match(source,/assemble-onekey-safe-signatures\.mjs/);
  assert.match(source,/onekey-governance-owner-\$\(\(index \+ 1\)\)-physical-account\.json/);
  assert.doesNotMatch(source,/openApprovedOneKeyBluetooth|onekey-governance-owner-.*-identity\.json/);
  assert.doesNotMatch(source,/--ledger|wallet sign|wallet address|cast_bin/i);
});
