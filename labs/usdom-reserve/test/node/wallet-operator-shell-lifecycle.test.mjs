import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const root=path.resolve(import.meta.dirname,'../..');
const load=name=>readFile(path.join(root,'scripts',name),'utf8');

test('wallet operator builds and runtime binaries have group deadlines',async()=>{
  const rows=[
    ['observe-finalized-deposit-wallet.sh','observer'],
    ['register-finalized-deposit-wallet.sh','register'],
    ['submit-closed-mainnet-private-burn.sh','submit'],
  ];
  for(const [name,binary] of rows) {
    const source=await load(name);
    assert.match(source,/command in [^\n]* timeout;/,name);
    assert.match(source,/timeout --signal=TERM --kill-after=30s 3600s "\$CARGO_BIN" build/,name);
    assert.match(source,/timeout --signal=TERM --kill-after=5s 300s "\$keystore_binary" unlock/,name);
    assert.match(source,new RegExp(`timeout --signal=TERM --kill-after=5s 300s "\\$${binary}_binary"`),name);
    assert.doesNotMatch(source,/(?:^|\s)&\s*(?:#.*)?$/m,name);
  }
});

test('finalized-deposit witness Cargo process has a hard group deadline',async()=>{
  const source=await load('build-finalized-deposit-witness.sh');
  assert.match(source,/command in [^\n]* timeout;/);
  assert.match(source,/timeout --signal=TERM --kill-after=30s 3600s cargo run --quiet --release --locked/);
  assert.doesNotMatch(source,/(?:^|\s)&\s*(?:#.*)?$/m);
});
