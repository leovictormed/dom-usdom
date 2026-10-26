import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const root=new URL('../../../../',import.meta.url);
const read=relative=>readFile(new URL(relative,root),'utf8');

test('production USDOM graph has explicit empty defaults and no unsafe normal dependency',async()=>{
  const manifests=[
    'crates/dom-node/Cargo.toml','crates/dom-chain/Cargo.toml',
    'crates/dom-usdom-state/Cargo.toml','crates/dom-usdom-wallet/Cargo.toml',
    'labs/usdom-ethereum-finality/Cargo.toml',
  ];
  for(const name of manifests) {
    const source=await read(name);
    assert.match(source,/\[features\]\s*\ndefault = \[\]/,name);
    let section='';
    for(const line of source.split('\n')) {
      const header=/^\[([^\]]+)\]$/.exec(line);
      if(header) { section=header[1]; continue; }
      if(!line.includes('unsafe-test-oracle')) continue;
      assert.ok(section==='features'||section.endsWith('dev-dependencies'),
        `${name}: unsafe oracle reachable from ${section}`);
    }
  }
});

test('all production proof hosts compile RISC0 with dev mode disabled',async()=>{
  for(const name of ['finalized-burn','checkpoint','randomx','economic']) {
    const source=await read(`crates/dom-usdom-${name}-proof-host/Cargo.toml`);
    assert.match(source,/\[features\]\s*\ndefault = \[\]/,name);
    assert.match(source,/risc0-zkvm = \{[^\n]*default-features = false[^\n]*"disable-dev-mode"/,name);
  }
});

test('closed-mainnet node build is package scoped with exact feature baseline',async()=>{
  const source=await read('labs/usdom-reserve/scripts/run-closed-mainnet-node.sh');
  assert.match(source,/"\$cargo_bin" build --quiet --release --frozen --no-default-features -p dom-node \\\n  --features native-usdom-v4-poc --bin dom-node/);
  assert.doesNotMatch(source,/"\$cargo_bin" build[^\n]*(?:--workspace|--all-targets)/);
});
