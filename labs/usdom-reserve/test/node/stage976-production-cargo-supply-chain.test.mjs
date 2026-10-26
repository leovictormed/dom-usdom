import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const root=new URL('../../../../',import.meta.url);
const read=relative=>readFile(new URL(relative,root),'utf8');

test('production ceremony is frozen and cannot fetch from the network',async()=>{
  const source=await read('labs/usdom-reserve/scripts/run-closed-mainnet-node.sh');
  assert.match(source,/"\$cargo_bin" build --quiet --release --frozen --no-default-features -p dom-node \\\n  --features native-usdom-v4-poc --bin dom-node/);
  assert.doesNotMatch(source,/"\$cargo_bin" build[^\n]*--locked/);
});

test('every remote Cargo.lock package has immutable source authority',async()=>{
  const lock=await read('Cargo.lock');
  assert.match(lock,/^version = 3$/m);
  const packages=lock.split('[[package]]').slice(1);
  let registry=0,git=0;
  for(const block of packages) {
    const source=/^source = "([^"]+)"$/m.exec(block)?.[1];
    if(!source) continue; // repository-local path dependency
    if(source.startsWith('registry+')) {
      registry++;
      assert.match(block,/^checksum = "[0-9a-f]{64}"$/m);
    } else if(source.startsWith('git+')) {
      git++;
      assert.match(source,/\?rev=[0-9a-f]{40}#[0-9a-f]{40}$/);
      const [,requested,resolved]=/\?rev=([0-9a-f]{40})#([0-9a-f]{40})$/.exec(source);
      assert.equal(resolved,requested);
    } else assert.fail(`unsupported Cargo source: ${source}`);
  }
  assert.ok(registry>400,`unexpected registry package count ${registry}`);
  assert.ok(git>0,`unexpected git package count ${git}`);
});

test('production graph git declarations use commit rev, never branch or tag',async()=>{
  for(const name of ['Cargo.toml','crates/dom-crypto/Cargo.toml']) {
    const source=await read(name);
    for(const line of source.split('\n').filter(line=>line.includes('git = '))) {
      assert.match(line,/rev = "[0-9a-f]{40}"/);
      assert.doesNotMatch(line,/branch\s*=|tag\s*=/);
    }
  }
});
