import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const root=path.resolve(import.meta.dirname,'../..');
const load=name=>readFile(path.join(root,'scripts',name),'utf8');

test('native wallet and recovery drill bound build and credential binaries',async()=>{
  const [wallet,drill]=await Promise.all([
    load('prepare-native-receiving-wallet.sh'),load('drill-closed-mainnet-wallet-recovery.sh'),
  ]);
  assert.match(wallet,/timeout --signal=TERM --kill-after=30s 3600s "\$CARGO_BIN" build/);
  assert.match(wallet,/timeout --signal=TERM --kill-after=5s 300s "\$\{COMMAND\[@\]\}"/);
  assert.match(drill,/timeout --signal=TERM --kill-after=30s 3600s "\$CARGO_BIN" build/);
  assert.match(drill,/run_pinned_timeout --signal=TERM --kill-after=5s 300s "\$FD_EXEC" "\$REPOSITORY_ROOT"/);
  assert.match(drill,/"target\/release\/dom-usdom-wallet-tpm-keystore" "\$keystore_binary_sha256" -- unlock/);
  assert.match(drill,/"target\/release\/dom-usdom-recover-wallet-at-checkpoint" "\$recovery_binary_sha256" --/);
});

test('TPM authority and keystore provisioning bound children and terminate on signals',async()=>{
  const [bootstrap,provision]=await Promise.all([
    load('bootstrap-closed-mainnet-tpm-authority.sh'),
    load('provision-closed-mainnet-tpm-keystore.sh'),
  ]);
  for(const source of [bootstrap,provision]) {
    assert.match(source,/timeout --signal=TERM --kill-after=30s 3600s cargo build/);
  }
  assert.match(bootstrap,/timeout --signal=TERM --kill-after=5s 300s "\$keystore_binary" unlock/);
  assert.match(bootstrap,/timeout --signal=TERM --kill-after=5s 300s "\$bootstrap_binary"/);
  assert.match(provision,/timeout --signal=TERM --kill-after=5s 300s "\$keystore_binary" provision/);
  for(const [signal,status] of [['HUP','129'],['INT','130'],['TERM','143']]) {
    assert.match(provision,new RegExp(`trap 'cleanup ${status}' ${signal}`));
  }
  assert.match(provision,/cleanup\(\) \{[\s\S]*local status=\$\{1:-\$\?\}[\s\S]*trap - EXIT HUP INT TERM[\s\S]*exit "\$status"/);
  assert.doesNotMatch(provision,/trap cleanup EXIT HUP INT TERM/);
});
