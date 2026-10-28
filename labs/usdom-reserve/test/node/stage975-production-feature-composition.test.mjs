import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const root=new URL('../../../../',import.meta.url);
const read=relative=>readFile(new URL(relative,root),'utf8');

test('production USDOM graph has explicit empty defaults and no unsafe normal dependency',async()=>{
  const manifests=[
    'crates/dom-node/Cargo.toml','crates/dom-chain/Cargo.toml',
    'crates/dom-store/Cargo.toml',
    'crates/dom-usdom-state/Cargo.toml','crates/dom-usdom-wallet/Cargo.toml',
    'crates/dom-usdom-finalized-burn-program/Cargo.toml',
    'labs/usdom-ethereum-finality/Cargo.toml',
  ];
  for(const name of manifests) {
    const source=await read(name);
    if(source.includes('[features]')) {
      assert.match(source,/\[features\]\s*\ndefault = \[\]/,name);
    }
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

test('test-only rate-limit environment knobs are absent from production code',async()=>{
  const source=await read('crates/dom-node/src/msg_rate_limit.rs');
  assert.match(source,/#\[cfg\(not\(test\)\)\]\s*\{\s*Self::default\(\)\s*\}/s);
  for(const helper of [
    'bounded_test_budget_override',
    'bounded_test_window_override',
    'parse_bounded_test_override',
  ]) {
    assert.match(source,new RegExp(`#\\[cfg\\(test\\)\\]\\s*fn ${helper}\\b`),helper);
  }
  const productionBranch=source.match(/#\[cfg\(not\(test\)\)\][\s\S]*?#\[cfg\(test\)\]/)?.[0] ?? '';
  assert.doesNotMatch(productionBranch,/DOM_TEST_/);
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

test('TPM operator builds are locked offline with explicit feature baseline',async()=>{
  for(const name of [
    'provision-closed-mainnet-tpm-keystore.sh',
    'bootstrap-closed-mainnet-tpm-authority.sh',
  ]) {
    const source=await read(`labs/usdom-reserve/scripts/${name}`);
    assert.match(source,/cargo build --quiet --release --locked --offline --no-default-features -p dom-node \\/,name);
    assert.doesNotMatch(source,/cargo build[^\n]*(?:--all-features|--workspace)/,name);
  }
});
