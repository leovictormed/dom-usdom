import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('preactivation sync policy uses bounded descriptor-bound capture',async()=>{
  const source=await readFile(new URL(
    '../../../../crates/dom-node/src/bin/dom-usdom-export-preactivation-anchor.rs',
    import.meta.url),'utf8');
  const loader=/fn load_sync_policy[\s\S]*?\n\}/.exec(source)?.[0]??'';
  assert.match(loader,/dom_wallet_crypto::read_captured_bytes\(path, 16 \* 1024\)/);
  assert.doesNotMatch(loader,/std::fs::read|File::open|read_to_end/);
  assert.doesNotMatch(loader,/path\.display\(\)/,
    'filesystem errors must not disclose the operator path');
});

test('other public-network USDOM loaders remain on the shared captured reader',async()=>{
  const names=[
    'dom-usdom-observe-finalized-deposit.rs',
    'dom-usdom-recover-wallet-at-checkpoint.rs',
    'dom-usdom-register-finalized-deposit.rs',
    'dom-usdom-build-private-burn.rs',
  ];
  for(const name of names) {
    const source=await readFile(new URL(
      `../../../../crates/dom-node/src/bin/${name}`,import.meta.url),'utf8');
    assert.match(source,/dom_wallet_crypto::read_(?:captured|private)_bytes/ ,name);
  }
});
